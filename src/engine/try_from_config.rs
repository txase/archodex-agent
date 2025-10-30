pub(crate) trait TryFromConfig<C>: Sized {
    fn try_from_config(value: C) -> anyhow::Result<Self>;
}
