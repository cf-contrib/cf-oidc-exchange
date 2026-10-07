//! Where the person's ID token is kept between runs: the OS keychain.

use anyhow::{Context, Result};

use super::BrokerUrl;

/// The keychain service ID tokens are stored under, one per broker URL.
const SERVICE: &str = "cf-sts";

/// Store keeps the person's ID token between runs, under the broker's URL.
pub trait Store {
    /// Returns the ID token stored for `broker`, if any.
    fn load(&self, broker: &BrokerUrl) -> Result<Option<String>>;
    /// Stores `id_token` for `broker`, replacing any.
    fn save(&self, broker: &BrokerUrl, id_token: &str) -> Result<()>;
    /// Removes the ID token stored for `broker`, and returns whether there was one.
    fn delete(&self, broker: &BrokerUrl) -> Result<bool>;
}

/// The OS keychain: Keychain on macOS, the Secret Service on Linux, Credential
/// Manager on Windows.
pub struct Keychain;

impl Keychain {
    fn entry(broker: &BrokerUrl) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, broker.as_str()).context("the OS keychain failed")
    }
}

impl Store for Keychain {
    fn load(&self, broker: &BrokerUrl) -> Result<Option<String>> {
        match Self::entry(broker)?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err).context("the OS keychain failed"),
        }
    }

    fn save(&self, broker: &BrokerUrl, id_token: &str) -> Result<()> {
        Self::entry(broker)?
            .set_password(id_token)
            .context("the OS keychain failed")
    }

    fn delete(&self, broker: &BrokerUrl) -> Result<bool> {
        match Self::entry(broker)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(err).context("the OS keychain failed"),
        }
    }
}
