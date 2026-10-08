//! Signing in: OpenID Connect with a public client, PKCE (RFC 7636) and a
//! loopback redirect (RFC 8252). The identity provider's endpoints from its
//! Discovery document, one sign-in's secrets, the redirect the browser comes
//! back to, and the checks the ID token has to pass. And staying signed in:
//! where the provider issues refresh tokens, a new ID token for one, with no
//! browser.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

use super::{Identity, Login};

/// Every request to the provider gives up after this.
const TIMEOUT: Duration = Duration::from_secs(30);

/// What the sign-in asks for: an ID token saying who the person is.
pub const SCOPES: &str = "openid email profile";

/// What it asks for too where the provider refreshes: a refresh token.
pub const OFFLINE_ACCESS: &str = "offline_access";

/// Provider is an OpenID Provider's endpoints, from its Discovery document.
#[derive(Debug, Deserialize)]
pub struct Provider {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    /// Whether it refreshes: `refresh_token` (RFC 8414), or Cloudflare
    /// Access's `refresh_tokens`, listed only where the application allows it.
    #[serde(default)]
    grant_types_supported: Vec<String>,
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

    /// Returns true if the provider issues refresh tokens. Asking one that
    /// doesn't for `offline_access` fails the sign-in, as Access does.
    pub fn issues_refresh_tokens(&self) -> bool {
        self.grant_types_supported
            .iter()
            .any(|grant| grant == "refresh_token" || grant == "refresh_tokens")
    }

    /// Returns the scopes the sign-in asks for: `offline_access` too where
    /// the provider refreshes.
    pub fn scopes(&self) -> String {
        if self.issues_refresh_tokens() {
            format!("{SCOPES} {OFFLINE_ACCESS}")
        } else {
            SCOPES.to_string()
        }
    }

    /// Returns the link the person signs in at.
    pub fn link(&self, sign_in: &Authorization) -> String {
        let mut link = self.authorization_endpoint.clone();
        link.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &sign_in.client_id)
            .append_pair("redirect_uri", &sign_in.redirect_uri)
            .append_pair("scope", &self.scopes())
            .append_pair("state", &sign_in.state)
            .append_pair("nonce", &sign_in.nonce)
            .append_pair("code_challenge", &challenge(&sign_in.verifier))
            .append_pair("code_challenge_method", "S256");
        link.to_string()
    }

    /// Redeems the authorization `code` for the ID token, with the PKCE
    /// verifier in place of a client secret.
    pub async fn redeem(&self, sign_in: &Authorization, code: &str) -> Result<Login> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &sign_in.redirect_uri),
            ("client_id", &sign_in.client_id),
            ("code_verifier", &sign_in.verifier),
        ];
        self.token(&form, "sign-in").await
    }

    /// Trades `refresh_token` for a new login, as the public client
    /// `client_id`: no secret, as the sign-in had none. Its refresh token is a
    /// new one where the provider rotates them, and none where it doesn't.
    pub async fn refresh(&self, client_id: &str, refresh_token: &str) -> Result<Login> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        self.token(&form, "refresh").await
    }

    /// Posts `form` to the token endpoint, and returns the login it answers
    /// with: its ID token, and a refresh token where it issues them. `what` is
    /// what the provider refused, if it did.
    async fn token(&self, form: &[(&str, &str)], what: &str) -> Result<Login> {
        #[derive(Deserialize)]
        struct Reply {
            id_token: Option<String>,
            refresh_token: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }
        let response = self
            .http
            .post(self.token_endpoint.clone())
            .form(form)
            .send()
            .await
            .context("the provider's token endpoint failed")?;
        let status = response.status();
        let reply: Reply = response
            .json()
            .await
            .map_err(|_| anyhow!("the provider's token endpoint answered {status}"))?;
        match (reply.id_token, reply.error) {
            (Some(id_token), None) if status.is_success() => Ok(Login {
                id_token,
                refresh_token: reply.refresh_token.filter(|token| !token.is_empty()),
            }),
            (_, Some(error)) => {
                let description = reply.error_description.unwrap_or_default();
                bail!("the provider refused the {what} ({error}): {description}")
            }
            _ => bail!("the provider's token endpoint answered {status} with no ID token"),
        }
    }
}

/// Checks a refreshed ID token, from `issuer` for `client_id`: as a sign-in's
/// is checked, but without a nonce, which only a sign-in sends (OpenID Connect
/// Core §12.2).
pub fn check_refreshed_id_token(identity: &Identity, issuer: &str, client_id: &str) -> Result<()> {
    let claims = identity.claims();
    if claims.iss != issuer {
        bail!("the provider's refreshed ID token is from {}", claims.iss);
    }
    if !identity.is_for(client_id) {
        bail!("the provider's refreshed ID token is for another client");
    }
    if identity.is_expired() {
        bail!("the provider's refreshed ID token has already expired");
    }
    Ok(())
}

/// Authorization is what one sign-in sends the provider, and checks its ID
/// token against.
pub struct Authorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub verifier: String,
    pub state: String,
    pub nonce: String,
}

impl Authorization {
    /// Returns a sign-in as `client_id`, redirected to `redirect_uri`, with a
    /// fresh PKCE verifier, state and nonce.
    pub fn new(client_id: &str, redirect_uri: &str) -> Result<Self> {
        Ok(Self {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            verifier: random()?,
            state: random()?,
            nonce: random()?,
        })
    }

    /// Checks the ID token this sign-in ended in, from `issuer`: that it's
    /// from it, for this client and this sign-in, and not yet expired (OpenID
    /// Connect Core §3.1.3.7). Its signature isn't: it came straight from the
    /// token endpoint over TLS, as item 6 allows, and the broker verifies it on
    /// every exchange anyway.
    pub fn check(&self, identity: &Identity, issuer: &str) -> Result<()> {
        let claims = identity.claims();
        if claims.iss != issuer {
            bail!("the provider's ID token is from {}", claims.iss);
        }
        if !identity.is_for(&self.client_id) {
            bail!("the provider's ID token is for another client");
        }
        if claims.nonce.as_deref() != Some(self.nonce.as_str()) {
            bail!("the provider's ID token isn't for this sign-in");
        }
        if identity.is_expired() {
            bail!("the provider's ID token has already expired");
        }
        Ok(())
    }
}

/// Returns 32 random bytes, base64url: a PKCE verifier (RFC 7636 §4.1), a
/// state or a nonce.
fn random() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("no randomness from the OS: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the PKCE `S256` challenge for `verifier` (RFC 7636 §4.2).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Waits for the provider's redirect to the loopback, and returns its code.
/// A request that isn't it, including one with another sign-in's `state`, is
/// answered and ignored: a page on another site can reach the loopback too.
pub async fn callback(listener: &TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("the sign-in's loopback failed")?;
        let Some(target) = request_target(&mut stream).await else {
            continue;
        };
        let Some(query) = target.strip_prefix("/callback?") else {
            respond(&mut stream, "404 Not Found", "Not found.").await;
            continue;
        };
        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        if params.get("state").map(String::as_str) != Some(state) {
            let message = "This isn't the sign-in cloudflare-sts started.";
            respond(&mut stream, "400 Bad Request", message).await;
            continue;
        }
        if let Some(error) = params.get("error") {
            let description = params.get("error_description").map_or("", String::as_str);
            let message = "The sign-in failed. cloudflare-sts says why.";
            respond(&mut stream, "200 OK", message).await;
            bail!("the provider refused the sign-in ({error}): {description}");
        }
        let Some(code) = params.get("code") else {
            respond(&mut stream, "400 Bad Request", "The sign-in had no code.").await;
            continue;
        };
        let message = "Signed in. You can close this tab.";
        respond(&mut stream, "200 OK", message).await;
        return Ok(code.clone());
    }
}

/// Returns the target of an HTTP `GET`, from its request line.
async fn request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0; 8192];
    let mut read = 0;
    while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") && read < buf.len() {
        match stream.read(&mut buf[read..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    let head = String::from_utf8_lossy(&buf[..read]);
    let mut line = head.lines().next()?.split(' ');
    match (line.next(), line.next()) {
        (Some("GET"), Some(target)) => Some(target.to_string()),
        _ => None,
    }
}

/// Answers the browser with a page saying `message`.
async fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><title>cloudflare-sts</title><p style=\"font-family:sans-serif\">{message}</p>\n"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    // The browser may be gone already: the sign-in still counts.
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::sts::stub::jwt;

    #[test]
    fn checks_the_id_token_is_from_the_issuer_for_this_client_and_sign_in() {
        let sign_in = Authorization::new("abc", "http://127.0.0.1:8250/callback").unwrap();
        let issuer = "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/abc";
        let token = |overrides: Value| {
            let mut claims = json!({
                "iss": issuer,
                "sub": "user-0001",
                "aud": ["abc"],
                "nonce": sign_in.nonce,
                "exp": chrono::Utc::now().timestamp() + 3600,
            });
            for (key, value) in overrides.as_object().unwrap() {
                claims[key] = value.clone();
            }
            Identity::parse(jwt(claims)).unwrap()
        };
        sign_in.check(&token(json!({})), issuer).unwrap();
        for (overrides, said) in [
            (
                json!({ "iss": "https://other.example.com" }),
                "is from https://other.example.com",
            ),
            (json!({ "aud": "other" }), "is for another client"),
            (
                json!({ "nonce": "another-sign-ins" }),
                "isn't for this sign-in",
            ),
            (json!({ "nonce": null }), "isn't for this sign-in"),
            (json!({ "exp": 1_790_000_000 }), "has already expired"),
        ] {
            let err = sign_in
                .check(&token(overrides.clone()), issuer)
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("the provider's ID token {said}"),
                "{overrides}"
            );
        }
    }

    #[test]
    fn makes_the_pkce_challenge_rfc_7636_does() {
        // RFC 7636, Appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let verifier = random().unwrap();
        assert_eq!(verifier.len(), 43);
        assert_ne!(verifier, random().unwrap());
    }

    #[tokio::test]
    async fn ignores_requests_that_arent_this_sign_ins_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let waiting = tokio::spawn(async move { callback(&listener, "the-state").await });

        let client = reqwest::Client::new();
        let get = |path: &str| client.get(format!("{base}{path}")).send();
        assert_eq!(get("/favicon.ico").await.unwrap().status(), 404);
        let forged = get("/callback?code=forged&state=other").await.unwrap();
        assert_eq!(forged.status(), 400);
        let real = get("/callback?code=the-code&state=the-state")
            .await
            .unwrap();
        assert_eq!(real.status(), 200);

        assert_eq!(waiting.await.unwrap().unwrap(), "the-code");
    }
}
