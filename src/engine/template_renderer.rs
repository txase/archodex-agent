use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use base64::Engine;
use minijinja::{Environment, syntax::SyntaxConfig};
use serde::Serialize;
use tracing::{debug, trace};

use crate::{Context, account_salted_hasher};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AgentContext {
    env: HashMap<String, String>,
}

pub(crate) static AGENT_CONTEXT: LazyLock<AgentContext> = LazyLock::new(|| AgentContext {
    env: std::env::vars().collect(),
});

struct MiniJinjaCache<'a> {
    env: Environment<'a>,
}

impl MiniJinjaCache<'_> {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let mut env = Environment::empty();

        env.set_syntax(
            SyntaxConfig::builder()
                .variable_delimiters("{", "}")
                .build()
                .unwrap(),
        );

        env.add_function("trace", |state: &minijinja::State| {
            let mut context = HashMap::new();

            for name in state.known_variables() {
                let value = state.lookup(&name).unwrap_or_default();
                context.insert(name.to_string(), value);
            }

            trace!("{context:#?}");

            Ok(context)
        });

        env.add_filter("trace", |value: &minijinja::Value| {
            trace!("{value:#?}");

            value.clone()
        });

        env.add_filter(
            "render",
            |state: &minijinja::State, value: minijinja::Value, template: &str| {
                let mut context = HashMap::new();

                for name in state.known_variables() {
                    let value = state.lookup(&name).unwrap_or_default();
                    context.insert(name.to_string(), value);
                }

                context.insert("Value".to_string(), value);

                match state.env().get_template(template) {
                    Ok(template) => template.render(context),
                    Err(_) => state.env().render_str(template, context),
                }
            },
        );

        // Add a filter to parse HTTP Authorization headers.
        //
        // This filter takes a string or a sequence of strings representing an
        // HTTP Authorzation header value. If the passed value is a sequence of
        // strings, this filter evaluates only the first value in the sequence.
        //
        // The filter returns an object with the following structure:
        // ```json
        // {
        //   "Basic": {
        //     "Username": "username" | undefined,
        //     "Password": "password" | undefined
        //   },
        //   "Bearer": {
        //     "Token": "token" | undefined
        //   }
        // }
        env.add_filter("parse_http_auth", |authorization: &minijinja::Value| {
            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            struct HttpAuthBasic {
                username: Option<String>,
                password: Option<String>,
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            struct HttpAuthBearer {
                token: Option<String>,
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            struct HttpAuth {
                basic: HttpAuthBasic,
                bearer: HttpAuthBearer,
            }

            static AUTH_RE: LazyLock<regex::Regex> =
                LazyLock::new(|| regex::Regex::new(r"^(?P<scheme>\S+)\s+(?P<value>\S+)$").unwrap());

            let authorization = match authorization.kind() {
                minijinja::value::ValueKind::String => {
                    authorization.as_str().ok_or_else(|| {
                        trace!(?authorization, "Invalid HTTP Authorization Value: Value is not a string");
                        minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            "Invalid HTTP Authorization Value: Value is not a string",
                        )
                    })?
                    .to_string()
                }
                minijinja::value::ValueKind::Seq => {
                    authorization
                        .get_item_by_index(0).map_err(|err| {
                            trace!(?authorization, ?err, "Failed to get first HTTP Authorization value from sequence");
                            minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                format!("Failed to get first HTTP Authorization value from sequence: {err:?}"),
                            )
                        })?
                        .as_str().ok_or_else(|| {
                        trace!(?authorization, "Invalid HTTP Authorization Value: Value is not a string");
                        minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            "Invalid HTTP Authorization Value: Value is not a string",
                        )
                    })?
                    .to_string()
                }
                kind => {
                    return Err(minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        format!("Invalid HTTP Authorization header type {kind}"),
                    ))
                }
            };

            let captures = AUTH_RE.captures(&authorization).ok_or_else(|| {
                minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    "Invalid HTTP Authorization header",
                )
            })?;

            let scheme = captures
                .name("scheme")
                .ok_or_else(|| {
                    minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        "Invalid HTTP Authorization header",
                    )
                })?
                .as_str()
                .to_lowercase();

            let value = captures
                .name("value")
                .ok_or_else(|| {
                    minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        "Invalid HTTP Authorization header",
                    )
                })?
                .as_str();

            match scheme.as_str() {
                "basic" => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|_| {
                            minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                "Failed to decode Basic Authentication header base64 string",
                            )
                        })?;

                    let decoded = String::from_utf8(decoded).map_err(|_| {
                        minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            "Failed to decode Basic Authentication header base64 string",
                        )
                    })?;

                    let mut parts = decoded.split(':');
                    let username = parts
                        .next()
                        .ok_or_else(|| {
                            minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                "Invalid Basic Authentication header",
                            )
                        })?
                        .to_string();
                    let password = parts
                        .next()
                        .ok_or_else(|| {
                            minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                "Invalid Basic Authentication header",
                            )
                        })?
                        .to_string();

                    if parts.next().is_some() {
                        return Err(minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            "Invalid Basic Authentication header",
                        ));
                    }

                    Ok(minijinja::Value::from_serialize(HttpAuth {
                        basic: HttpAuthBasic {
                            username: Some(username),
                            password: Some(password),
                        },
                        bearer: HttpAuthBearer { token: None },
                    }))
                }
                "bearer" => Ok(minijinja::Value::from_serialize(HttpAuth {
                    basic: HttpAuthBasic {
                        username: None,
                        password: None,
                    },
                    bearer: HttpAuthBearer {
                        token: Some(value.to_string()),
                    },
                })),
                scheme => Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("Unsupported HTTP Authorization scheme: {scheme}"),
                )),
            }
        });

        // Hash a secret value for secure storage or comparison.
        //
        // This filter takes a string or a sequence of strings and produces a hash of each value.
        // The hash uses a salted algorithm to ensure security and consistency.
        //
        // ### Examples
        //
        // In a template:
        // ```
        // {{ "my_password" | secret_value_hash }}
        // {{ ["password1", "password2"] | secret_value_hash }}
        // ```
        env.add_filter("secret_value_hash", |value: &minijinja::Value| {
            use minijinja::value::ValueKind;

            fn hash_value(value: &str) -> Result<String, minijinja::Error> {
                if value.is_empty() {
                    return Err(minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        "Cannot hash empty Secret Value",
                    ));
                }

                let hash = account_salted_hasher::hash(value.as_bytes()).map_err(|err| {
                    minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, err.to_string())
                })?;

                Ok(format!("{hash:064x}"))
            }

            match value.kind() {
                ValueKind::String => {
                    let value = value.as_str().ok_or_else(|| {
                        trace!(?value, "Invalid Secret Value: Value is not a string");
                        minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            "Invalid Secret Value: Value is not a string",
                        )
                    })?;

                    Ok(vec![hash_value(value)?])
                }
                ValueKind::Seq | ValueKind::Iterable => Ok(value
                    .try_iter()?
                    .map(|value| {
                        let value = value.as_str().ok_or_else(|| {
                            trace!(
                                ?value,
                                "Invalid Secret Value: A value in the sequence is not a string",
                            );
                            minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                "Invalid Secret Value: A value in the sequence is not a string",
                            )
                        })?;

                        hash_value(value)
                    })
                    .collect::<Result<Vec<String>, _>>()?),
                kind => {
                    trace!(
                        %kind,
                        "Invalid Secret Value: Value is not a string or sequence",
                    );
                    Err(minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        "Invalid Secret Value: Value is not a string or sequence",
                    ))
                }
            }
        });

        Self { env }
    }

    pub(crate) fn has_template(&self, template: &str) -> bool {
        self.env.get_template(template).is_ok()
    }

    pub(crate) fn add_template(&mut self, template: &str) -> Result<(), minijinja::Error> {
        static RENDER_TEMPLATE_SINGLE_QUOTE_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r#"render\s*\(\s*[']([^()"']*)[']\s*\)"#).unwrap());
        static RENDER_TEMPLATE_DOUBLE_QUOTE_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r#"render\s*\(\s*["]([^()"']*)["]\s*\)"#).unwrap());

        if !self.has_template(template) {
            let static_template = Box::leak(Box::new(template.to_string()));

            self.env.add_template(static_template, static_template)?;

            // Attempt to add subtemplates. This will miss complicated cases
            // with escaped quoting or further function calls, but should catch
            // most cases.

            if let Some(captures) = RENDER_TEMPLATE_SINGLE_QUOTE_RE.captures(template) {
                // Skip the first capture group, which is the entire match
                for capture in captures.iter().skip(1).flatten() {
                    let template = capture.as_str();
                    if let Err(err) = self.add_template(template) {
                        debug!(template, ?err, "Failed to add render subtemplate");
                    }
                }
            }
            if let Some(captures) = RENDER_TEMPLATE_DOUBLE_QUOTE_RE.captures(template) {
                // Skip the first capture group, which is the entire match
                for capture in captures.iter().skip(1).flatten() {
                    let template = capture.as_str();
                    if let Err(err) = self.add_template(template) {
                        debug!(template, ?err, "Failed to add render subtemplate");
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn render<C: Serialize>(
        &self,
        template: &str,
        context: C,
    ) -> Result<String, minijinja::Error> {
        let template = self.env.get_template(template)?;

        template.render(context)
    }
}

static MINI_JINJA_CACHE: LazyLock<RwLock<MiniJinjaCache>> =
    LazyLock::new(|| RwLock::new(MiniJinjaCache::new()));

fn template_renderer_cache() -> RwLockReadGuard<'static, MiniJinjaCache<'static>> {
    MINI_JINJA_CACHE
        .read()
        .expect("Failed to acquire read lock for MiniJinja cache")
}

fn template_renderer_cache_mut() -> RwLockWriteGuard<'static, MiniJinjaCache<'static>> {
    MINI_JINJA_CACHE
        .write()
        .expect("Failed to acquire write lock for MiniJinja cache")
}

pub(crate) fn add_template(template: &str) -> Result<(), minijinja::Error> {
    template_renderer_cache_mut().add_template(template)
}

pub(crate) fn render<C: Serialize>(
    template: &str,
    context: &C,
) -> Result<String, minijinja::Error> {
    let cache = template_renderer_cache();

    if cache.has_template(template) {
        cache.render(template, context)
    } else {
        drop(cache);

        add_template(template)?;

        template_renderer_cache().render(template, context)
    }
}

pub(crate) fn render_non_empty<C: Serialize>(
    template: &str,
    context: &C,
) -> Result<String, minijinja::Error> {
    let rendered = render(template, context)?;

    if rendered.is_empty() {
        Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Rendered template is empty",
        ))
    } else {
        Ok(rendered)
    }
}

pub(crate) struct CaptureContext {
    pub(crate) context: Context,
    pub(crate) container_id: String,
}

pub(crate) trait RenderCapture: Sized {
    async fn render_capture<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Self>;
}

pub(crate) trait RenderCaptures: Sized {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>>;
}
