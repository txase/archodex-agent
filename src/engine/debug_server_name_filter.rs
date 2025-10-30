use crate::ssl_instrumenter::libssl_bpf::types;

pub(crate) struct DebugServerNameFilter<'a> {
    inner: &'a types::server_name_filter,
}

impl<'a> From<&'a types::server_name_filter> for DebugServerNameFilter<'a> {
    fn from(value: &'a types::server_name_filter) -> Self {
        Self { inner: value }
    }
}

impl std::fmt::Debug for DebugServerNameFilter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter = self.inner;
        let r#type: types::filter_type = filter.r#type.try_into().unwrap();

        f.debug_struct("server_name_filter")
            .field("type", &r#type.to_string())
            .field(
                "test",
                &std::str::from_utf8(&filter.test[..filter.test_len as usize])
                    .expect("non-UTF-8 server_name_filter test"),
            )
            .field("test_len", &filter.test_len)
            .field("more_prefix_tests", unsafe {
                filter.more_prefix_tests.assume_init_ref()
            })
            .finish()
    }
}
