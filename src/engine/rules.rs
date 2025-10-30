use std::{
    collections::{HashMap, hash_map::Entry},
    mem::MaybeUninit,
};

use tokio::{
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tracing::{debug, instrument, trace};

use crate::{
    engine::{debug_server_name_filter::DebugServerNameFilter, hostname_filter::HostnameFilter},
    ssl_instrumenter::libssl_bpf::types,
    transport_parser::TransportEvent,
};

use super::{config, context::Context, parser::http::HttpParser, report::Report, rule::Rule};

#[derive(Debug)]
pub(crate) struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    pub(crate) fn new(rules: config::Rules) -> anyhow::Result<Self> {
        let rules = rules
            .into_iter()
            .map(Rule::try_from)
            .collect::<anyhow::Result<Vec<Rule>>>()?;

        for (index, rule) in rules.iter().enumerate() {
            debug!(index, rule = tracing::field::debug(rule), "Parsed rule");
        }

        Ok(Self { rules })
    }

    #[instrument]
    pub(crate) fn server_name_filters(&self) -> Vec<types::server_name_filter> {
        let mut filters_map: HashMap<HostnameFilter, Option<Vec<String>>> = HashMap::new();
        for rule in &self.rules {
            for hostname in &rule.hostnames {
                match hostname {
                    HostnameFilter::Equals(_) | HostnameFilter::Suffix(_) => {
                        filters_map.insert(hostname.to_owned(), None);
                    }
                    HostnameFilter::SuffixAndPrefixes((suffix, prefixes)) => {
                        match filters_map.entry(HostnameFilter::Suffix(suffix.to_owned())) {
                            Entry::Occupied(mut entry) => {
                                if let Some(cur) = entry.get_mut() {
                                    cur.extend(prefixes.to_owned());
                                }
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(Some(prefixes.to_owned()));
                            }
                        }
                    }
                }
            }
        }

        let mut filters_map = filters_map.into_iter().collect::<Vec<_>>();
        filters_map.sort_by(|(a, _), (b, _)| a.cmp(b));

        debug!(?filters_map, "Server name filter list");

        let mut filters = vec![];

        for entry in filters_map {
            match entry {
                (HostnameFilter::Equals(hostname), _) => {
                    let mut filter = types::server_name_filter {
                        r#type: types::filter_type::EQUALS as u8,
                        test_len: u8::try_from(hostname.len())
                            .expect("hostname length must be less than 256 bytes"),
                        more_prefix_tests: MaybeUninit::new(false),
                        ..Default::default()
                    };
                    filter.test[..hostname.len()].copy_from_slice(hostname.as_bytes());
                    filters.push(filter);
                }
                (HostnameFilter::Suffix(suffix), None) => {
                    let mut filter = types::server_name_filter {
                        r#type: types::filter_type::SUFFIX as u8,
                        test_len: u8::try_from(suffix.len())
                            .expect("hostname suffix length must be less than 256 bytes"),
                        more_prefix_tests: MaybeUninit::new(false),
                        ..Default::default()
                    };
                    filter.test[..suffix.len()].copy_from_slice(suffix.as_bytes());
                    filters.push(filter);
                }
                (HostnameFilter::Suffix(suffix), Some(prefixes)) => {
                    let mut filter = types::server_name_filter {
                        r#type: types::filter_type::SUFFIX as u8,
                        test_len: u8::try_from(suffix.len())
                            .expect("hostname suffix length must be less than 256 bytes"),
                        more_prefix_tests: MaybeUninit::new(true),
                        ..Default::default()
                    };
                    filter.test[..suffix.len()].copy_from_slice(suffix.as_bytes());
                    filters.push(filter);

                    for prefix in &prefixes[..prefixes.len() - 1] {
                        let mut filter = types::server_name_filter {
                            r#type: types::filter_type::PREFIX as u8,
                            test_len: u8::try_from(prefix.len())
                                .expect("hostname prefix length must be less than 256 bytes"),
                            more_prefix_tests: MaybeUninit::new(true),
                            ..Default::default()
                        };
                        filter.test[..prefix.len()].copy_from_slice(prefix.as_bytes());
                        filters.push(filter);
                    }

                    let prefix = prefixes.last().unwrap();

                    let mut filter = types::server_name_filter {
                        r#type: types::filter_type::PREFIX as u8,
                        test_len: u8::try_from(prefix.len())
                            .expect("hostname prefix length must be less than 256 bytes"),
                        more_prefix_tests: MaybeUninit::new(false),
                        ..Default::default()
                    };
                    filter.test[..prefix.len()].copy_from_slice(prefix.as_bytes());
                    filters.push(filter);
                }
                (HostnameFilter::SuffixAndPrefixes(_), _) => unreachable!(),
            }
        }

        debug!(
            filters = ?filters
                .iter()
                .map(Into::<DebugServerNameFilter>::into)
                .collect::<Vec<_>>(),
            "Aggregated server name filters"
        );

        filters
    }

    #[instrument(skip_all)]
    pub(crate) fn message_parser(
        &self,
        mut transport_event_receiver: UnboundedReceiver<TransportEvent>,
        context: Context,
    ) -> UnboundedReceiver<Report> {
        let (mut report_sender, report_receiver) = unbounded_channel();

        let http_parser = HttpParser::new(&self.rules);

        spawn(async move {
            while let Some(event) = transport_event_receiver.recv().await {
                handle_transport_event(event, &http_parser, &context, &mut report_sender).await;
            }
        });

        report_receiver
    }
}

#[instrument(skip(http_parser, report_sender), level = "trace")]
async fn handle_transport_event(
    event: TransportEvent,
    http_parser: &HttpParser,
    context: &Context,
    report_sender: &mut UnboundedSender<Report>,
) {
    trace!("Handling transport event");

    let report = match event {
        TransportEvent::Http(message) => http_parser.parse_message(message, context).await,
    };

    if let Some(report) = report {
        report_sender
            .send(report)
            .expect("Failed to send ResourceEvent");
    }
}
