//! The OpenID Provider people sign in at: its endpoints from OpenID Connect
//! Discovery, the link to its authorization endpoint, and the code redeemed at
//! its token endpoint for the ID token.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use url::Url;

use super::{Authorization, challenge};

/// Every request to the provider gives up after this.
const TIMEOUT: Duration = Duration::from_secs(30);

/// What the sign-in asks for: an ID token saying who the person is.
pub const SCOPES: &str = "openid email profile";

/// Provider is an OpenID Provider's endpoints, from its Discovery document.
#[derive(Debug, Deserialize)]
pub struct Provider {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    #[serde(skip)]
    http: reqwest::Client,
}

impl Provider {
    /// Reads the Discovery document of `issuer`, which must name it.
    pub async fn discover(issuer: &str) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(TIMEOUT).build()?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let mut provider: Self = async {
            http.get(&url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await
        }
        .await
        .with_context(|| format!("can't read {url}"))?;
        if provider.issuer != issuer {
            bail!(
                "can't read {url}: it names another issuer, {}",
                provider.issuer
            );
        }
        provider.http = http;
        Ok(provider)
    }

    /// Returns the link the person signs in at.
    pub fn link(&self, sign_in: &Authorization) -> String {
        let mut link = self.authorization_endpoint.clone();
        link.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &sign_in.client_id)
            .append_pair("redirect_uri", &sign_in.redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", &sign_in.state)
            .append_pair("nonce", &sign_in.nonce)
            .append_pair("code_challenge", &challenge(&sign_in.verifier))
            .append_pair("code_challenge_method", "S256");
        link.to_string()
    }

    /// Redeems the authorization `code` for the ID token, with the PKCE
    /// verifier in place of a client secret.
    pub async fn redeem(&self, sign_in: &Authorization, code: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Reply {
            id_token: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &sign_in.redirect_uri),
            ("client_id", &sign_in.client_id),
            ("code_verifier", &sign_in.verifier),
        ];
        let response = self
            .http
            .post(self.token_endpoint.clone())
            .form(&form)
            .send()
            .await
            .context("the provider's token endpoint failed")?;
        let status = response.status();
        let reply: Reply = response
            .json()
            .await
            .map_err(|_| anyhow!("the provider's token endpoint answered {status}"))?;
        match (reply.id_token, reply.error) {
            (Some(id_token), None) if status.is_success() => Ok(id_token),
            (_, Some(error)) => {
                let description = reply.error_description.unwrap_or_default();
                bail!("the provider refused the sign-in ({error}): {description}")
            }
            _ => bail!("the provider's token endpoint answered {status} with no ID token"),
        }
    }
}
