use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::{BrokerUrl, hinted};

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
        let invalid = || hinted("the stored login isn't an ID token", "run 'cf-sts login'");
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
        self.claims.exp <= Utc::now().timestamp()
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

/// Returns the login stored for `broker`, expired or not.
pub fn stored(store: &dyn Store, broker: &BrokerUrl) -> Result<Identity> {
    let Some(token) = store.load(broker)? else {
        return Err(hinted(
            format!("not signed in to {broker}"),
            "run 'cf-sts login'",
        ));
    };
    Identity::parse(token)
}

/// Returns the login stored for `broker`, to exchange: refused before asking
/// the broker when it has expired, since only `login` may open a browser.
pub fn current(store: &dyn Store, broker: &BrokerUrl) -> Result<Identity> {
    let identity = stored(store, broker)?;
    if identity.is_expired() {
        return Err(expired(identity.claims.exp));
    }
    Ok(identity)
}

/// Returns the error for a login that expired at `exp`.
pub fn expired(exp: i64) -> anyhow::Error {
    anyhow!("your login expired at {}; run 'cf-sts login'", rfc3339(exp))
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
pub mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use serde_json::json;

    use super::*;

    /// Memory keeps logins in memory, for the tests.
    #[derive(Default)]
    pub struct Memory(RefCell<HashMap<String, String>>);

    impl Store for Memory {
        fn load(&self, broker: &BrokerUrl) -> Result<Option<String>> {
            Ok(self.0.borrow().get(broker.as_str()).cloned())
        }

        fn save(&self, broker: &BrokerUrl, id_token: &str) -> Result<()> {
            self.0
                .borrow_mut()
                .insert(broker.to_string(), id_token.to_string());
            Ok(())
        }

        fn delete(&self, broker: &BrokerUrl) -> Result<bool> {
            Ok(self.0.borrow_mut().remove(broker.as_str()).is_some())
        }
    }

    /// Returns an unsigned JWT with `claims`: the CLI never checks the signature.
    pub fn jwt(claims: Value) -> String {
        let encode = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
        format!(
            "{}.{}.signature",
            encode(json!({ "alg": "RS256" })),
            encode(claims)
        )
    }

    fn broker() -> BrokerUrl {
        BrokerUrl::parse(Some("https://cf-sts.example.com")).unwrap()
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

    #[test]
    fn says_to_sign_in_when_theres_no_login_or_it_has_expired() {
        let store = Memory::default();
        let err = current(&store, &broker()).err().unwrap().to_string();
        assert_eq!(
            err,
            "not signed in to https://cf-sts.example.com\n  hint: run 'cf-sts login'"
        );

        let token = jwt(json!({ "iss": "i", "sub": "s", "exp": 1_790_000_000 }));
        store.save(&broker(), &token).unwrap();
        // Shown by whoami, but never exchanged.
        assert!(stored(&store, &broker()).is_ok());
        let err = current(&store, &broker()).err().unwrap().to_string();
        assert_eq!(
            err,
            "your login expired at 2026-09-21T14:13:20Z; run 'cf-sts login'"
        );
    }

    #[test]
    fn formats_times_as_the_broker_does() {
        assert_eq!(rfc3339(1_790_597_700), "2026-09-28T12:15:00Z");
    }
}
