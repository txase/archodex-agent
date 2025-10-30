use anyhow::{anyhow, bail, ensure};
use url::{ParseError, Url};

use crate::ssl_instrumenter::libssl_bpf::types;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum HostnameFilter {
    Equals(String),
    Suffix(String),
    SuffixAndPrefixes((String, Vec<String>)),
}

impl TryFrom<String> for HostnameFilter {
    type Error = anyhow::Error;

    fn try_from(value: String) -> anyhow::Result<Self> {
        use regex::Regex;
        use std::sync::LazyLock;

        static MULTI_WILDCARD_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"\*.*\*").unwrap());
        static PREFIXES_SUFFIX_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^(?P<prefix>[^*]+\.)\*(?P<suffix>\.[^*]+)$").unwrap());

        let hostname = value.trim();
        let url = Url::parse(hostname);

        let hostname = if let Ok(url) = &url {
            url.host_str()
                .ok_or_else(|| anyhow!("No hostname in hostname filter URL {hostname:?}"))?
        } else if let Err(ParseError::RelativeUrlWithoutBase) = url {
            hostname
        } else {
            bail!("Invalid hostname filter URL {hostname:?}: {url:?}");
        };

        if hostname.is_empty() {
            bail!("Empty hostname in hostnames list {value:?}");
        }

        if MULTI_WILDCARD_RE.is_match(hostname) {
            bail!("Invalid multi-wildcard hostname {hostname:?} in hostnames list ({hostname:?})");
        }

        if let Some(suffix) = hostname.strip_prefix("*.") {
            let suffix = format!(".{suffix}");
            ensure!(
                suffix.len() < u8::MAX as usize,
                "Hostname suffix {suffix:?} is too long"
            );
            Ok(HostnameFilter::Suffix(suffix))
        } else if let Some(captures) = PREFIXES_SUFFIX_RE.captures(hostname) {
            let suffix = captures.name("suffix").unwrap().as_str().to_owned();
            ensure!(
                suffix.len() < u8::MAX as usize,
                "Hostname suffix {suffix:?} is too long"
            );

            let prefix = captures.name("prefix").unwrap().as_str().to_owned();
            ensure!(
                prefix.len() < u8::MAX as usize,
                "Hostname prefix {prefix:?} is too long"
            );

            Ok(HostnameFilter::SuffixAndPrefixes((suffix, vec![prefix])))
        } else {
            ensure!(
                hostname.len() < u8::MAX as usize,
                "Hostname {hostname:?} is too long"
            );
            Ok(HostnameFilter::Equals(hostname.to_owned()))
        }
    }
}

impl HostnameFilter {
    pub(crate) fn matches(&self, hostname: &str) -> bool {
        use HostnameFilter::{Equals, Suffix, SuffixAndPrefixes};

        match self {
            Equals(filter) => hostname == filter,
            Suffix(suffix) => hostname.ends_with(suffix),
            SuffixAndPrefixes((suffix, prefixes)) => {
                hostname.ends_with(suffix)
                    && prefixes.iter().any(|prefix| hostname.starts_with(prefix))
            }
        }
    }
}

impl PartialOrd for HostnameFilter {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HostnameFilter {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use HostnameFilter::{Equals, Suffix, SuffixAndPrefixes};
        use std::cmp::Ordering::{Greater, Less};

        match (self, other) {
            (Equals(a), Equals(b))
            | (Suffix(a), Suffix(b))
            | (SuffixAndPrefixes((a, _)), SuffixAndPrefixes((b, _))) => a.cmp(b),
            (Equals(_), _) => Greater,
            (_, Equals(_)) => Less,
            (Suffix(_), _) => Greater,
            (_, Suffix(_)) => Less,
        }
    }
}

impl std::fmt::Display for HostnameFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use HostnameFilter::{Equals, Suffix, SuffixAndPrefixes};

        match self {
            Equals(filter) => write!(f, "{filter}"),
            Suffix(suffix) => write!(f, "*{suffix}"),
            SuffixAndPrefixes((suffix, prefixes)) => {
                write!(f, "{{{}}}*{suffix}", prefixes.join(","))
            }
        }
    }
}

impl TryFrom<u8> for types::filter_type {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        const NONE: u8 = types::filter_type::NO_FILTER as u8;
        const EQUALS: u8 = types::filter_type::EQUALS as u8;
        const SUFFIX: u8 = types::filter_type::SUFFIX as u8;
        const PREFIX: u8 = types::filter_type::PREFIX as u8;

        match value {
            NONE => Ok(types::filter_type::NO_FILTER),
            EQUALS => Ok(types::filter_type::EQUALS),
            SUFFIX => Ok(types::filter_type::SUFFIX),
            PREFIX => Ok(types::filter_type::PREFIX),
            _ => bail!("Invalid filter type {value}"),
        }
    }
}

impl std::fmt::Display for types::filter_type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use types::filter_type::{EQUALS, NO_FILTER, PREFIX, SUFFIX};

        match self {
            NO_FILTER => write!(f, "NO_FILTER"),
            EQUALS => write!(f, "EQUALS"),
            SUFFIX => write!(f, "SUFFIX"),
            PREFIX => write!(f, "PREFIX"),
        }
    }
}
