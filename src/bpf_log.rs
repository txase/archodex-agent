macro_rules! bpf_log_module_get_level {
    ($module_name:literal) => {
        {
            const TARGET: &str = concat!(env!("CARGO_CRATE_NAME"), "::ebpf::", $module_name);

            if tracing::event_enabled!(target: TARGET, ::tracing::Level::TRACE) {
                types::LogLevel::LOG_LEVEL_TRACE
            } else if tracing::event_enabled!(target: TARGET, ::tracing::Level::DEBUG) {
                types::LogLevel::LOG_LEVEL_DEBUG
            } else if tracing::event_enabled!(target: TARGET, ::tracing::Level::INFO) {
                types::LogLevel::LOG_LEVEL_INFO
            } else if tracing::event_enabled!(target: TARGET, ::tracing::Level::WARN) {
                types::LogLevel::LOG_LEVEL_WARN
            } else {
                types::LogLevel::LOG_LEVEL_ERROR
            }
        }
    }
}

macro_rules! bpf_log_impls {
    () => {
        impl From<u32> for LogModule {
            fn from(value: u32) -> Self {
                unsafe { std::mem::transmute(value) }
            }
        }

        impl From<u32> for LogLevel {
            fn from(value: u32) -> Self {
                unsafe { std::mem::transmute(value) }
            }
        }

        impl From<LogLevel> for tracing::Level {
            fn from(value: LogLevel) -> Self {
                use tracing::Level;

                match value {
                    LogLevel::LOG_LEVEL_ERROR => Level::ERROR,
                    LogLevel::LOG_LEVEL_WARN => Level::WARN,
                    LogLevel::LOG_LEVEL_INFO => Level::INFO,
                    LogLevel::LOG_LEVEL_DEBUG => Level::DEBUG,
                    LogLevel::LOG_LEVEL_TRACE => Level::TRACE,
                }
            }
        }
    };
}

pub(crate) use bpf_log_impls;
pub(crate) use bpf_log_module_get_level;
