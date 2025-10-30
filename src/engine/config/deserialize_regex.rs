use regex::Regex;
use serde::Deserializer;

pub(crate) fn deserialize_regex<'de, D>(deserializer: D) -> Result<Regex, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = Regex;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a regex string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Regex, E>
        where
            E: serde::de::Error,
        {
            Regex::new(value).map_err(|err| {
                E::invalid_value(
                    serde::de::Unexpected::Str(value),
                    &format!("a valid regex: {err}").as_str(),
                )
            })
        }
    }

    deserializer.deserialize_str(Visitor)
}
