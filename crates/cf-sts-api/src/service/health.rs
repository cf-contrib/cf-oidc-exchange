//! The broker's readiness check, for `/health/ready`.
//!
//! [`SecretsCheck`] reads the secrets an exchange reads: the Cloudflare token,
//! and the signing key if one is bound, imported as the broker would sign
//! with it. A secret that's bound but can't be read, say one Secrets Store
//! won't hand over, then shows up as `503` on the probe, with why in the log,
//! not only as a `500` on the first exchange.
//!
//! It doesn't call Cloudflare's API to verify the token: the endpoint is
//! public, and anyone probing it would spend the token's rate limit.

use std::sync::Arc;

use cf_sts_sdk::v1::{HealthCheck, HealthCheckError};
use tracing::error;
use worker::send::SendFuture;

use super::{config::Config, handler::signing_key};

/// Reads the secrets every exchange needs.
pub struct SecretsCheck {
    config: Arc<Config>,
}

impl SecretsCheck {
    /// A check over the Worker's configuration, shared with the handlers.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Reads the Cloudflare token, then the signing key if one is bound.
    async fn read(&self) -> Result<(), String> {
        self.config
            .cloudflare()
            .client()
            .await
            .map_err(|err| err.to_string())?;
        signing_key(&self.config)
            .await
            .map_err(|err| err.error_description)?;
        Ok(())
    }
}

impl HealthCheck for SecretsCheck {
    // Secrets Store futures aren't `Send`: they hold JavaScript values. A
    // Worker is single-threaded, so the check runs in a `SendFuture`, as the
    // handlers do.
    fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send {
        SendFuture::new(async move {
            self.read().await.map_err(|why| {
                error!(event = "unready", message = %why);
                why.into()
            })
        })
    }
}
