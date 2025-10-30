use std::sync::OnceLock;

use anyhow::anyhow;
use sha2::{Digest, Sha256, digest::crypto_common};
use tracing::warn;

use crate::report_api_key;

static SALTED_HASHER: OnceLock<Sha256> = OnceLock::new();

pub(crate) fn init(provided_salt_value: Option<&String>) -> anyhow::Result<()> {
    let account_salt = if let Some(salt) = report_api_key::account_salt() {
        salt.to_owned()
    } else if let Some(salt) = provided_salt_value {
        hex::decode(salt)
            .map_err(|_| anyhow!("Failed to decode provided salt value as a hex string"))?
            .try_into()
            .map_err(|_| anyhow!("Provided salt value must be a 32-byte hex string"))?
    } else {
        warn!(
            "Secret Values are being hashed with a random salt because no Archodex API Key was provided."
        );

        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| anyhow!("Failed to generate random salt"))?;

        salt
    };

    let mut hasher = Sha256::new();
    hasher.update(account_salt);
    SALTED_HASHER
        .set(hasher.clone())
        .map_err(|_| anyhow!("Unexpected error: Account salted hasher already initialized"))
}

fn new() -> anyhow::Result<Sha256> {
    if let Some(hasher) = SALTED_HASHER.get() {
        Ok(hasher.clone())
    } else {
        Err(anyhow!(
            "Unexpected error: Account salt not set before generating first hasher"
        ))
    }
}

/// Hash a slice of bytes with the account salt
///
///
pub(crate) fn hash(value: &[u8]) -> anyhow::Result<crypto_common::Output<Sha256>> {
    let mut hasher: Sha256 = new()?;
    hasher.update(value);
    Ok(hasher.finalize())
}
