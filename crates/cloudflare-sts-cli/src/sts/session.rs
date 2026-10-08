//! The stored login: the person's ID token and what its claims say, the
//! refresh token that renews it where the provider issues one, the OS
//! keychain they're kept in between runs, and when the login expires.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::{Broker, BrokerUrl, Provider, check_refreshed, hinted};

/// The keychain service ID tokens are stored under, one per broker URL.
const SERVICE: &str = "cloudflare-sts";

/// The keychain service refresh tokens are stored under: an entry of their
/// own, so an ID token's is as it always was, and neither outgrows what a
/// keychain entry holds.
const REFRESH_SERVICE: &str = "cloudflare-sts-refresh";

/// How close to expiring an ID token is renewed, where it can be: soon enough
/// that it hasn't expired by the time the broker reads it.
const RENEW_AHEAD: i64 = 60;

/// Login is what `login` keeps: the ID token, and the refresh token that
/// renews it, where the provider issues one.
pub struct Login {
    pub id_token: String,
    pub refresh_token: Option<String>,
}

/// Store keeps the person's login between runs, under the broker's URL.
pub trait Store {
    /// Returns the login stored for `broker`, if any.
    fn load(&self, broker: &BrokerUrl) -> Result<Option<Login>>;
    /// Stores `login` for `broker`, replacing any.
    fn save(&self, broker: &BrokerUrl, login: &Login) -> Result<()>;
    /// Removes the login stored for `broker`, and returns whether there was one.
    fn delete(&self, broker: &BrokerUrl) -> Result<bool>;
}

/// The OS keychain: Keychain on macOS, the Secret Service on Linux, Credential
/// Manager on Windows.
pub struct Keychain;

impl Keychain {
    fn entry(service: &str, broker: &BrokerUrl) -> Result<keyring::Entry> {
        keyring::Entry::new(service, broker.as_str()).context("the OS keychain failed")
    }

    fn get(service: &str, broker: &BrokerUrl) -> Result<Option<String>> {
        match Self::entry(service, broker)?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err).context("the OS keychain failed"),
        }
    }

    fn remove(service: &str, broker: &BrokerUrl) -> Result<bool> {
        match Self::entry(service, broker)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(err).context("the OS keychain failed"),
        }
    }
}

impl Store for Keychain {
    fn load(&self, broker: &BrokerUrl) -> Result<Option<Login>> {
        let Some(id_token) = Self::get(SERVICE, broker)? else {
            return Ok(None);
        };
        let refresh_token = Self::get(REFRESH_SERVICE, broker)?;
        Ok(Some(Login {
            id_token,
            refresh_token,
        }))
    }

    fn save(&self, broker: &BrokerUrl, login: &Login) -> Result<()> {
        Self::entry(SERVICE, broker)?
            .set_password(&login.id_token)
            .context("the OS keychain failed")?;
        match &login.refresh_token {
            Some(token) => Self::entry(REFRESH_SERVICE, broker)?
                .set_password(token)
                .context("the OS keychain failed"),
            // A login without one renews nothing: an older one's goes.
            None => Self::remove(REFRESH_SERVICE, broker).map(|_| ()),
        }
    }

    fn delete(&self, broker: &BrokerUrl) -> Result<bool> {
        let id_token = Self::remove(SERVICE, broker)?;
        let refresh_token = Self::remove(REFRESH_SERVICE, broker)?;
        Ok(id_token || refresh_token)
    }
}

/// Identity is a person's ID token, and what its claims say about it.
///
/// The claims are read, not verified: the broker verifies the token on every
/// exchange, and the CLI only shows who it's for, and refuses an expired one
/// before asking.
pub struct Identity {
    token: String,
    claims: Claims,
}

/// The ID token claims the CLI reads.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Unix time in seconds.
    pub exp: i64,
    /// A string or a list of them.
    #[serde(default)]
    pub aud: Value,
    #[serde(default)]
    pub nonce: Option<String>,
}

impl Identity {
    /// Reads the claims of `token`, a JWT.
    pub fn parse(token: String) -> Result<Self> {
        let invalid = || {
            hinted(
                "the stored login isn't an ID token",
                "run 'cloudflare-sts login'",
            )
        };
        let payload = token.split('.').nth(1).ok_or_else(invalid)?;
        let json = URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?;
        let claims = serde_json::from_slice(&json).map_err(|_| invalid())?;
        Ok(Self { token, claims })
    }

    /// Returns the ID token, to exchange.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns its claims.
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Returns who it's for: the email, or else the subject.
    pub fn who(&self) -> &str {
        self.claims.email.as_deref().unwrap_or(&self.claims.sub)
    }

    /// Returns true once it has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_within(0)
    }

    /// Returns true if it has expired, or will within `seconds`.
    pub fn expires_within(&self, seconds: i64) -> bool {
        self.claims.exp <= Utc::now().timestamp() + seconds
    }

    /// Returns true if its `aud` names `client_id`.
    pub fn is_for(&self, client_id: &str) -> bool {
        match &self.claims.aud {
            Value::String(aud) => aud == client_id,
            Value::Array(auds) => auds.iter().any(|aud| aud == client_id),
            _ => false,
        }
    }
}

/// Returns the login stored for `broker`, expired or not: its identity, and
/// the refresh token that renews it, if there is one.
pub fn stored(store: &dyn Store, broker: &BrokerUrl) -> Result<(Identity, Option<String>)> {
    let Some(login) = store.load(broker)? else {
        return Err(hinted(
            format!("not signed in to {broker}"),
            "run 'cloudflare-sts login'",
        ));
    };
    Ok((Identity::parse(login.id_token)?, login.refresh_token))
}

/// Returns the login stored for `broker`, to exchange. One that has expired,
/// or is about to, is renewed with its refresh token where it has one, with no
/// browser; one that can't be is refused before asking the broker, since only
/// `login` may open a browser.
pub async fn current(store: &dyn Store, broker: &Broker) -> Result<Identity> {
    let (identity, refresh_token) = stored(store, broker.url())?;
    let Some(refresh_token) = refresh_token.filter(|_| identity.expires_within(RENEW_AHEAD)) else {
        if identity.is_expired() {
            return Err(expired(identity.claims.exp));
        }
        return Ok(identity);
    };
    match renew(store, broker, &identity, &refresh_token).await {
        Ok(renewed) => Ok(renewed),
        // Not yet expired, it still does, this once.
        Err(_) if !identity.is_expired() => Ok(identity),
        Err(err) => Err(anyhow!(
            "your login expired at {}, and renewing it failed ({err:#}); run 'cloudflare-sts login'",
            rfc3339(identity.claims.exp)
        )),
    }
}

/// Trades `refresh_token` for a new login from the provider that issued
/// `identity`, checks its ID token, and stores it, with the refresh token the
/// provider sent, or else this one.
async fn renew(
    store: &dyn Store,
    broker: &Broker,
    identity: &Identity,
    refresh_token: &str,
) -> Result<Identity> {
    let issuer = &identity.claims.iss;
    let client_id = broker.client_id(issuer).await?;
    let provider = Provider::discover(issuer).await?;
    let mut login = provider.refresh(&client_id, refresh_token).await?;
    let renewed = Identity::parse(login.id_token.clone())?;
    check_refreshed(&renewed, issuer, &client_id)?;
    // A provider that doesn't rotate them keeps taking this one.
    login
        .refresh_token
        .get_or_insert_with(|| refresh_token.to_string());
    store.save(broker.url(), &login)?;
    Ok(renewed)
}

/// Returns the error for a login that expired at `exp`.
pub fn expired(exp: i64) -> anyhow::Error {
    anyhow!(
        "your login expired at {}; run 'cloudflare-sts login'",
        rfc3339(exp)
    )
}

/// Returns Unix seconds as the broker and the action show them, e.g.
/// `2026-09-28T12:15:00Z`.
pub fn rfc3339(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

/// Returns how long until `exp`, roughly: `7h12m`, `5m`, `30s`.
pub fn until(exp: i64) -> String {
    let left = (exp - Utc::now().timestamp()).max(0);
    match (left / 3600, left % 3600 / 60) {
        (0, 0) => format!("{left}s"),
        (0, minutes) => format!("{minutes}m"),
        (hours, minutes) => format!("{hours}h{minutes}m"),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::json;

    use super::*;
    use crate::sts::stub::{Memory, jwt};

    fn broker() -> BrokerUrl {
        BrokerUrl::parse(Some("https://cloudflare-sts-api.example.com")).unwrap()
    }

    #[test]
    fn reads_who_its_for_and_until_when() {
        let exp = Utc::now().timestamp() + 3 * 3600 + 120;
        let identity = Identity::parse(jwt(json!({
            "iss": "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/abc",
            "sub": "user-0001",
            "email": "alice@example.com",
            "aud": ["abc"],
            "exp": exp,
        })))
        .unwrap();
        assert_eq!(identity.who(), "alice@example.com");
        assert!(identity.is_for("abc") && !identity.is_for("other"));
        assert!(!identity.is_expired());
        assert!(until(exp).starts_with("3h"), "{}", until(exp));

        let subject_only = Identity::parse(jwt(
            json!({ "iss": "i", "sub": "user-0001", "aud": "abc", "exp": exp }),
        ))
        .unwrap();
        assert_eq!(subject_only.who(), "user-0001");
        assert!(subject_only.is_for("abc"));
    }

    #[test]
    fn refuses_what_isnt_an_id_token() {
        for token in [
            "",
            "abc",
            "a.!!!.c",
            &jwt(json!({ "sub": "no iss or exp" })),
        ] {
            assert!(Identity::parse(token.to_string()).is_err(), "{token}");
        }
    }

    #[tokio::test]
    async fn says_to_sign_in_when_theres_no_login_or_it_has_expired() {
        let store = Memory::default();
        let broker = Broker::new(&broker());
        let err = current(&store, &broker).await.err().unwrap().to_string();
        assert_eq!(
            err,
            "not signed in to https://cloudflare-sts-api.example.com\n  hint: run 'cloudflare-sts login'"
        );

        let token = jwt(json!({ "iss": "i", "sub": "s", "exp": 1_790_000_000 }));
        let login = Login {
            id_token: token,
            refresh_token: None,
        };
        store.save(broker.url(), &login).unwrap();
        // Shown by whoami, but never exchanged: with no refresh token, it
        // can't be renewed either.
        assert!(stored(&store, broker.url()).is_ok());
        let err = current(&store, &broker).await.err().unwrap().to_string();
        assert_eq!(
            err,
            "your login expired at 2026-09-21T14:13:20Z; run 'cloudflare-sts login'"
        );
    }

    #[test]
    fn formats_times_as_the_broker_does() {
        assert_eq!(rfc3339(1_790_597_700), "2026-09-28T12:15:00Z");
    }

    #[test]
    fn says_roughly_how_long_until() {
        let now = Utc::now().timestamp();
        assert_eq!(until(now + 30), "30s");
        assert_eq!(until(now + 5 * 60 + 30), "5m");
        assert!(until(now + 3 * 3600 + 120).starts_with("3h"));
        assert_eq!(until(now - 10), "0s");
    }
}
