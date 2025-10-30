use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use anyhow::{Context as _, bail};
use http::{HeaderMap, Method};
use jsonpath_rust::query::js_path_process;
use path_tree::{Path, PathTree};
use serde::Serialize;
use tracing::{debug, debug_span, error_span, instrument, trace_span, warn, warn_span};

use crate::{
    engine::{
        context::{Context, ContextMethods},
        event_capture::EventCapture,
        hostname_filter::HostnameFilter,
        principal::Principal,
        report::Report,
        resource_capture::ResourceCapture,
        rule::{
            Rule, TransportRule,
            http::{BodyRules, HeaderRules},
        },
        template_renderer::{
            AGENT_CONTEXT, AgentContext, CaptureContext, RenderCapture, RenderCaptures as _,
        },
    },
    transport_parser::http::HttpRequestResponse,
};

#[derive(Debug)]
struct PerHostnameMethodRouteFilterRules {
    request_header: HeaderRules,
    request_body: BodyRules,
    response_header: HeaderRules,
    response_body: Option<BodyRules>,
    resource_capture: Vec<ResourceCapture>,
    event_capture: Vec<EventCapture>,
}

#[derive(Debug, Default)]
struct Routes {
    capture: PathTree<PerHostnameMethodRouteFilterRules>,
    ignore: Option<PathTree<()>>,
}

impl Routes {
    fn is_empty(&self) -> bool {
        self.capture.iter().next().is_none() && self.ignore.is_none()
    }
}

#[derive(Debug)]
struct Filter {
    hostnames: Vec<HostnameFilter>,
    routes_by_method: HashMap<Method, Routes>,
    routes_any_method: Routes,
    inputs: Arc<HashMap<String, String>>,
}

#[derive(Debug)]
pub(crate) struct HttpParser {
    filters: Vec<Filter>,
}

impl HttpParser {
    pub(crate) fn new(rules: &Vec<Rule>) -> Self {
        let mut filters = vec![];

        for Rule {
            hostnames,
            transport_rules,
            inputs,
        } in rules
        {
            let mut routes_by_method: HashMap<Method, Routes> = HashMap::new();
            let mut routes_any_method: Routes = Routes::default();

            for rule in transport_rules.iter().map(|rule| match rule {
                TransportRule::Http(rule) => rule,
            }) {
                fn add_routes(routes: &mut Routes, rule: &crate::engine::rule::http::Rule) {
                    if rule.request.routes.is_empty() {
                        let path_id = routes.capture.insert(
                            "/*",
                            PerHostnameMethodRouteFilterRules {
                                request_header: rule.request.header_rules.clone(),
                                request_body: rule.request.body_rules.clone(),
                                response_header: rule
                                    .response
                                    .as_ref()
                                    .map(|response| response.header_rules.clone())
                                    .unwrap_or_default(),
                                response_body: rule
                                    .response
                                    .as_ref()
                                    .map(|response| response.body_rules.clone()),
                                resource_capture: rule.resource_capture_rules.clone(),
                                event_capture: rule.event_capture_rules.clone(),
                            },
                        );
                        debug!(path_id, "Added /* route pattern to filter");
                    } else {
                        for route in &rule.request.routes {
                            let path_id = routes.capture.insert(
                                route,
                                PerHostnameMethodRouteFilterRules {
                                    request_header: rule.request.header_rules.clone(),
                                    request_body: rule.request.body_rules.clone(),
                                    response_header: rule
                                        .response
                                        .as_ref()
                                        .map(|response| response.header_rules.clone())
                                        .unwrap_or_default(),
                                    response_body: rule
                                        .response
                                        .as_ref()
                                        .map(|response| response.body_rules.clone()),
                                    resource_capture: rule.resource_capture_rules.clone(),
                                    event_capture: rule.event_capture_rules.clone(),
                                },
                            );
                            debug!(route, path_id, "Added route pattern to filter");
                        }
                    }

                    if !rule.request.ignore_routes.is_empty() {
                        let mut path_tree = PathTree::new();

                        for route in &rule.request.ignore_routes {
                            let _path_id = path_tree.insert(route, ());
                        }

                        routes.ignore = Some(path_tree);
                    }
                }

                if rule.request.methods.is_empty() {
                    add_routes(&mut routes_any_method, rule);
                } else {
                    for method in &rule.request.methods {
                        let routes = routes_by_method.entry(method.clone()).or_default();

                        add_routes(routes, rule);
                    }
                }
            }

            if !routes_by_method.is_empty() || !routes_any_method.is_empty() {
                filters.push(Filter {
                    hostnames: hostnames.clone(),
                    routes_by_method,
                    routes_any_method,
                    inputs: inputs.clone(),
                });
            }
        }

        Self { filters }
    }

    #[instrument(skip_all, fields(
        http_version = tracing::field::debug(message.version),
        hostname = tracing::field::debug(&message.tls_server_name),
        method = tracing::field::debug(message.request.method()),
        path = tracing::field::debug(message.request.uri().path()),
    ))]
    pub(crate) async fn parse_message(
        &self,
        message: HttpRequestResponse,
        context: &Context,
    ) -> Option<Report> {
        let filter_results = self
            .filters
            .iter()
            .enumerate()
            .filter_map(
                |(
                    index,
                    Filter {
                        hostnames,
                        routes_by_method,
                        routes_any_method,
                        inputs,
                    },
                )| {
                    let _filter_span = error_span!(
                        "filter",
                        filter = index,
                        hostnames = hostnames
                            .iter()
                            .map(|hostname| format!("{hostname}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                    .entered();

                    if !hostnames
                        .iter()
                        .any(|hostname| hostname.matches(&message.tls_server_name))
                    {
                        debug!("Request does not match hostname filters");
                        return None;
                    }

                    let routes = routes_by_method.get(&message.request.method().into());

                    let mut method_span = error_span!(
                        "method",
                        method = tracing::field::display(message.request.method())
                    )
                    .entered();

                    if let Some(((), route)) =
                        routes.and_then(|routes| routes.ignore.as_ref()).and_then(
                            |ignored_routes| ignored_routes.find(message.request.uri().path()),
                        )
                    {
                        debug!(?route, "Request matches ignored route pattern");
                        return None;
                    }

                    let filter_route = routes
                        .and_then(|routes| routes.capture.find(message.request.uri().path()))
                        .map(|(filter, route)| {
                            debug!("Request matches a route pattern");
                            (filter, route)
                        });

                    if filter_route.is_none() {
                        debug!("Request does not match any route patterns");
                    }

                    if filter_route.is_none() {
                        method_span.exit();
                        method_span = error_span!("method", method = "*").entered();
                    }

                    let filter_route = filter_route.or_else(|| {
                        if let Some(((), route)) =
                            routes_any_method
                                .ignore
                                .as_ref()
                                .and_then(|ignored_routes| {
                                    ignored_routes.find(message.request.uri().path())
                                })
                        {
                            debug!(?route, "Request matches ignored route pattern");
                            return None;
                        }

                        if let Some((filter, route)) =
                            routes_any_method.capture.find(message.request.uri().path())
                        {
                            debug!("Request matches a route pattern");
                            Some((filter, route))
                        } else {
                            debug!("Request does not match any route patterns");
                            None
                        }
                    });

                    let (filter, route) = filter_route?;

                    if !check_header_rules(message.request.headers(), &filter.request_header) {
                        debug!("Request headers do not match filter");
                        return None;
                    }

                    let request_body_captures =
                        match check_body_rules(&message.request.body().0, &filter.request_body) {
                            Ok(Some(captures)) => captures,
                            Ok(None) => {
                                debug!("Request body does not match filter");
                                return None;
                            }
                            Err(err) => {
                                warn!(?err, "Failed to evaluate request body");
                                return None;
                            }
                        };

                    if !check_header_rules(message.response.headers(), &filter.response_header) {
                        debug!("Response headers do not match filter");
                        return None;
                    }

                    let response_body_captures = match &filter.response_body {
                        Some(body_rules) => {
                            match check_body_rules(&message.response.body().0, body_rules) {
                                Ok(Some(captures)) => captures,
                                Ok(None) => {
                                    debug!("Response body does not match filter");
                                    return None;
                                }
                                Err(err) => {
                                    warn!(?err, "Failed to evaluate response body");
                                    return None;
                                }
                            }
                        }
                        None => HashMap::new(),
                    };

                    debug!("Request matches a filter");

                    method_span.exit();

                    Some((
                        inputs.as_ref(),
                        &filter.resource_capture,
                        &filter.event_capture,
                        route,
                        request_body_captures,
                        response_body_captures,
                    ))
                },
            )
            .collect::<Vec<_>>();

        if filter_results.is_empty() {
            debug!("No matching HTTP filters found");
            return None;
        }

        let mut report = Report::new();

        for (
            inputs,
            resource_capture_rules,
            event_capture_rules,
            path,
            request_body_captures,
            response_body_captures,
        ) in filter_results
        {
            let render_context = RenderContext::new(
                inputs,
                &message,
                &path,
                request_body_captures,
                response_body_captures,
            );

            let capture_context =
                message
                    .container_id
                    .as_ref()
                    .map(|container_id| CaptureContext {
                        context: context.clone(),
                        container_id: container_id.clone(),
                    });

            for rule in resource_capture_rules {
                match rule
                    .render_captures(&render_context, capture_context.as_ref())
                    .await
                {
                    Ok(resource_captures) => {
                        debug_span!(
                            "render",
                            render_context = tracing::field::debug(render_context.clone()),
                            resource_capture_rule = tracing::field::debug(rule)
                        )
                        .in_scope(|| debug!(?resource_captures, "Rendered resource captures"));
                        report.add_resource_captures(resource_captures);
                    }
                    Err(err) => {
                        warn_span!(
                            "render",
                            render_context = tracing::field::debug(render_context.clone()),
                            resource_capture_rule = tracing::field::debug(rule)
                        )
                        .in_scope(|| warn!(?err, "Failed to render resource capture"));
                    }
                }
            }

            let principals = context
                .lock()
                .await
                .principals(message.container_id.as_ref())
                .await;
            if principals.is_empty() {
                warn!(
                    "No principals found for container ID {:?}, skipping event capture",
                    message.container_id
                );
                return Some(report);
            }

            for rule in event_capture_rules {
                match render_event_capture(
                    rule,
                    &principals,
                    &render_context,
                    capture_context.as_ref(),
                )
                .await
                {
                    Ok(event_capture) => {
                        debug_span!(
                            "render",
                            render_context = tracing::field::debug(render_context.clone()),
                            event_capture_rule = tracing::field::debug(rule)
                        )
                        .in_scope(|| debug!(?event_capture, "Rendered event capture"));
                        report.add_event_capture(event_capture);
                    }
                    Err(err) => {
                        warn_span!(
                            "render",
                            render_context = tracing::field::debug(render_context.clone()),
                            event_capture_rule = tracing::field::debug(rule)
                        )
                        .in_scope(|| warn!(?err, "Failed to render event capture"));
                    }
                }
            }
        }

        Some(report)
    }
}

fn check_header_rules(headers: &HeaderMap, rules: &HeaderRules) -> bool {
    if rules.is_empty() {
        return true;
    }

    for (header, rule) in rules {
        let _header_span = error_span!("header rule", header).entered();

        let Some(Ok(header_value)) = headers.get(header).map(|value| value.to_str()) else {
            debug!("Header is missing or not UTF-8");
            return false;
        };

        let _header_value_span = trace_span!("header value", header_value).entered();

        if !rule.regex.is_match(header_value) {
            debug!(?rule.regex, "Header does not match regex");
            return false;
        }
    }

    true
}

fn check_body_rules(
    body: &Vec<u8>,
    rules: &BodyRules,
) -> anyhow::Result<Option<HashMap<String, Vec<serde_json::Value>>>> {
    if rules.is_empty() {
        return Ok(Some(HashMap::new()));
    }

    let body_json: serde_json::Value = match serde_json::from_slice(body.as_slice()) {
        Ok(body_json) => body_json,
        Err(err) => bail!("Body is not valid JSON: {err}"),
    };

    let mut captures = HashMap::new();

    for (rule_name, rule) in rules {
        let values = js_path_process(&rule.path, &body_json)
            .with_context(|| format!("Failed to process JSONPath for Body Rule {rule_name:?}"))?
            .into_iter()
            .filter_map(|val| {
                let value = val.val();

                if let Some(value_match) = &rule.value
                    && value != value_match
                {
                    return None;
                }

                Some(value.to_owned())
            })
            .collect::<Vec<_>>();

        if values.is_empty() {
            debug!(rule = ?rule_name, "Body Rule did not match any values");
            return Ok(None);
        }

        captures.insert(rule_name.to_owned(), values);
    }

    Ok(Some(captures))
}

#[instrument(level = "error", skip_all, fields(?rule_principal))]
async fn render_event_principal(
    render_context: &RenderContext<'_>,
    capture_context: Option<&CaptureContext>,
    rule_principal: &Principal,
) -> anyhow::Result<Principal> {
    let principal = rule_principal
        .render_capture(render_context, capture_context)
        .await?;

    if let Some(CaptureContext {
        context,
        container_id,
    }) = capture_context
    {
        let context = context.lock().await;

        debug!(container_id, ?principal.id, "Evaluating principal nesting within context DNS");

        let nested_principal_id = context
            .nest_resources_within_context_dns(&rule_principal.id, container_id, vec![principal.id])
            .await
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Expected only one principal to be nested"))?;

        debug!(
            container_id,
            ?nested_principal_id,
            "Result principal nesting within context DNS"
        );

        Ok(Principal {
            id: nested_principal_id,
            event: principal.event,
        })
    } else {
        Ok(principal)
    }
}

async fn render_event_capture(
    rule: &EventCapture,
    principals: &[Principal],
    render_context: &RenderContext<'_>,
    capture_context: Option<&CaptureContext>,
) -> anyhow::Result<EventCapture> {
    let mut events = vec![];

    for rule in &rule.events {
        let rule_events = rule
            .render_captures(render_context, capture_context)
            .await?;

        events.extend(rule_events);
    }

    if let Some(first_principal) = rule.principals.first() {
        let principal_futs = rule
            .principals
            .iter()
            .map(|rule_principal| {
                render_event_principal(render_context, capture_context, rule_principal)
            })
            .collect::<Vec<_>>();

        let rule_principals = futures::future::try_join_all(principal_futs)
            .await?
            .into_iter()
            .collect::<Vec<_>>();

        // If the first principal in this event capture rule has an event,
        // append specified principals to the agent context.
        //
        // E.g. a Secret Value may be the first principal, and it has an event
        // specified representing that the Secret Value is being used by the
        // context principal chain in order to access the resource(s) of the
        // event.
        //
        // Alternatively, if the first principal does not have an event, then
        // it the specified principal chain is considered to be the complete
        // chain, and is not appended to the agent context principal chain.
        let principals = if first_principal.event.is_some() {
            principals
                .iter()
                .cloned()
                .chain(rule_principals.into_iter())
                .collect()
        } else {
            rule_principals
        };

        Ok(EventCapture { principals, events })
    } else {
        // No principal chain is specified, so append it to the agent context
        // principal chain.
        Ok(EventCapture {
            principals: principals.to_vec(),
            events,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RenderContext<'a> {
    inputs: &'a HashMap<String, String>,
    agent: &'static AgentContext,
    tls_server_name: String,
    request: RequestRenderContext,
    response: ResponseRenderContext,
}

impl<'a> RenderContext<'a> {
    fn new(
        inputs: &'a HashMap<String, String>,
        message: &HttpRequestResponse,
        path: &Path,
        request_body_captures: HashMap<String, Vec<serde_json::Value>>,
        response_body_captures: HashMap<String, Vec<serde_json::Value>>,
    ) -> Self {
        Self {
            inputs,
            agent: &*AGENT_CONTEXT,
            tls_server_name: message.tls_server_name.clone(),
            request: RequestRenderContext::new(message, path, request_body_captures),
            response: ResponseRenderContext::new(message, response_body_captures),
        }
    }
}

fn headermap_to_hashmap(header_map: &HeaderMap) -> HashMap<String, Vec<String>> {
    header_map
        .iter()
        .fold(HashMap::new(), |mut headers, (name, value)| {
            match headers.entry(name.as_str().to_string()) {
                Entry::Vacant(entry) => {
                    entry.insert(vec![String::from_utf8_lossy(value.as_bytes()).to_string()]);
                }
                Entry::Occupied(mut entry) => {
                    entry
                        .get_mut()
                        .push(String::from_utf8_lossy(value.as_bytes()).to_string());
                }
            }

            headers
        })
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RequestRenderContext {
    method: String,
    path: HashMap<String, String>,
    headers: HashMap<String, Vec<String>>,
    body_captures: HashMap<String, Vec<serde_json::Value>>,
}

impl RequestRenderContext {
    fn new(
        message: &HttpRequestResponse,
        path: &Path,
        body_captures: HashMap<String, Vec<serde_json::Value>>,
    ) -> Self {
        Self {
            method: message.request.method().to_string(),
            path: path
                .params_iter()
                .map(|(param, value)| (param.to_owned(), value.to_owned()))
                .collect(),
            headers: headermap_to_hashmap(message.request.headers()),
            body_captures,
        }
    }
}

impl std::fmt::Debug for RequestRenderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestRenderContext")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &mask_confidential_headers(&self.headers))
            .field("body_captures", &self.body_captures)
            .finish()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ResponseRenderContext {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body_captures: HashMap<String, Vec<serde_json::Value>>,
}

impl ResponseRenderContext {
    fn new(
        message: &HttpRequestResponse,
        body_captures: HashMap<String, Vec<serde_json::Value>>,
    ) -> Self {
        Self {
            status: message.response.status().as_u16(),
            headers: headermap_to_hashmap(message.response.headers()),
            body_captures,
        }
    }
}

impl std::fmt::Debug for ResponseRenderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseRenderContext")
            .field("status", &self.status)
            .field("headers", &mask_confidential_headers(&self.headers))
            .field("body_captures", &self.body_captures)
            .finish()
    }
}

fn mask_confidential_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<&str, Vec<&str>> {
    headers
        .iter()
        .map(
            |(key, values)| match http::HeaderName::from_lowercase(key.as_bytes()).unwrap() {
                http::header::ACCEPT
                | http::header::ACCEPT_CHARSET
                | http::header::ACCEPT_ENCODING
                | http::header::ACCEPT_LANGUAGE
                | http::header::ACCEPT_RANGES
                | http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS
                | http::header::ACCESS_CONTROL_ALLOW_HEADERS
                | http::header::ACCESS_CONTROL_ALLOW_METHODS
                | http::header::ACCESS_CONTROL_ALLOW_ORIGIN
                | http::header::ACCESS_CONTROL_EXPOSE_HEADERS
                | http::header::ACCESS_CONTROL_REQUEST_HEADERS
                | http::header::ACCESS_CONTROL_REQUEST_METHOD
                | http::header::AGE
                | http::header::ALLOW
                | http::header::ALT_SVC
                | http::header::CACHE_CONTROL
                | http::header::CACHE_STATUS
                | http::header::CDN_CACHE_CONTROL
                | http::header::CONNECTION
                | http::header::CONTENT_DISPOSITION
                | http::header::CONTENT_ENCODING
                | http::header::CONTENT_LANGUAGE
                | http::header::CONTENT_LENGTH
                | http::header::CONTENT_RANGE
                | http::header::CONTENT_SECURITY_POLICY
                | http::header::CONTENT_SECURITY_POLICY_REPORT_ONLY
                | http::header::CONTENT_TYPE
                | http::header::DNT
                | http::header::DATE
                | http::header::ETAG
                | http::header::EXPECT
                | http::header::EXPIRES
                | http::header::FORWARDED
                | http::header::FROM
                | http::header::HOST
                | http::header::IF_MATCH
                | http::header::IF_MODIFIED_SINCE
                | http::header::IF_NONE_MATCH
                | http::header::IF_RANGE
                | http::header::IF_UNMODIFIED_SINCE
                | http::header::LAST_MODIFIED
                | http::header::MAX_FORWARDS
                | http::header::ORIGIN
                | http::header::PRAGMA
                | http::header::PROXY_AUTHENTICATE
                | http::header::PUBLIC_KEY_PINS
                | http::header::PUBLIC_KEY_PINS_REPORT_ONLY
                | http::header::RANGE
                | http::header::REFERRER_POLICY
                | http::header::REFRESH
                | http::header::RETRY_AFTER
                | http::header::SEC_WEBSOCKET_ACCEPT
                | http::header::SEC_WEBSOCKET_EXTENSIONS
                | http::header::SEC_WEBSOCKET_PROTOCOL
                | http::header::SEC_WEBSOCKET_VERSION
                | http::header::SERVER
                | http::header::STRICT_TRANSPORT_SECURITY
                | http::header::TE
                | http::header::TRAILER
                | http::header::TRANSFER_ENCODING
                | http::header::USER_AGENT
                | http::header::UPGRADE
                | http::header::UPGRADE_INSECURE_REQUESTS
                | http::header::VARY
                | http::header::VIA
                | http::header::WARNING
                | http::header::X_CONTENT_TYPE_OPTIONS
                | http::header::X_DNS_PREFETCH_CONTROL
                | http::header::X_FRAME_OPTIONS
                | http::header::X_XSS_PROTECTION => (
                    key.as_str(),
                    values.iter().map(std::string::String::as_str).collect(),
                ),
                _ => (key.as_str(), vec!["*****"; values.len()]),
            },
        )
        .collect()
}
