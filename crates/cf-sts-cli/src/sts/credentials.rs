//! What the broker granted, checked as the action checks it, and the
//! environment it becomes.

use anyhow::{Result, anyhow};
use cf_sts_sdk::v1::{BucketCredentials, TokenExchangeResponse};

use super::rfc3339;

/// Every variable `exec` sets, as the action exports them. The child gets
/// exactly those the profile grants: the rest are removed, so a token left in
/// the caller's shell can't stand in for a missing one.
pub const VARIABLES: [&str; 9] = [
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_R2_ACCESS_KEY_ID",
    "CLOUDFLARE_R2_SECRET_ACCESS_KEY",
    "CLOUDFLARE_R2_SESSION_TOKEN",
    "CLOUDFLARE_R2_ENDPOINT",
    "CLOUDFLARE_R2_BUCKET",
    "CLOUDFLARE_R2_PREFIXES",
    "CLOUDFLARE_R2_PREFIX",
];

/// Credentials are what the exchange granted, checked as the action checks
/// them.
#[derive(Debug)]
pub struct Credentials {
    pub profile: String,
    pub account_id: String,
    pub token: Option<Token>,
    pub bucket: Option<BucketCredentials>,
}

/// Token is a Cloudflare API token the broker minted, to revoke.
#[derive(Debug)]
pub struct Token {
    pub value: String,
    pub id: String,
    /// Unix time in seconds.
    pub expires_at: i64,
}

impl TryFrom<TokenExchangeResponse> for Credentials {
    type Error = anyhow::Error;

    fn try_from(response: TokenExchangeResponse) -> Result<Self> {
        let invalid = |what: &str| anyhow!("the broker returned an invalid response: {what}");
        let present = |value: Option<String>| value.filter(|v| !v.is_empty());

        // Cloudflare credentials always name the account. A token for
        // another service's audience doesn't, and isn't for `exec`.
        let account_id =
            present(response.account_id).ok_or_else(|| invalid("missing account_id"))?;
        let token = match (present(response.access_token), present(response.token_id)) {
            (Some(value), Some(id)) => Some(Token {
                value,
                id,
                expires_at: response.expires_at,
            }),
            (None, None) => None,
            _ => return Err(invalid("missing access_token or token_id")),
        };
        if let Some(bucket) = &response.bucket {
            let fields = [
                ("name", &bucket.name),
                ("access_key_id", &bucket.access_key_id),
                ("secret_access_key", &bucket.secret_access_key),
                ("session_token", &bucket.session_token),
                ("endpoint", &bucket.endpoint),
            ];
            if let Some((field, _)) = fields.iter().find(|(_, value)| value.is_empty()) {
                return Err(invalid(&format!("missing bucket.{field}")));
            }
        }
        if token.is_none() && response.bucket.is_none() {
            return Err(invalid("missing token and bucket"));
        }
        Ok(Self {
            profile: response.profile,
            account_id,
            token,
            bucket: response.bucket,
        })
    }
}

impl Credentials {
    /// Returns the child's environment, under the action's names.
    pub fn variables(&self) -> Vec<(&'static str, String)> {
        let mut vars = vec![("CLOUDFLARE_ACCOUNT_ID", self.account_id.clone())];
        if let Some(token) = &self.token {
            vars.push(("CLOUDFLARE_API_TOKEN", token.value.clone()));
        }
        if let Some(b) = &self.bucket {
            let prefixes = serde_json::to_string(&b.prefixes).unwrap_or_else(|_| "[]".into());
            // Only meaningful for exactly one prefix; the list has them all.
            let prefix = match b.prefixes.as_slice() {
                [prefix] => prefix.clone(),
                _ => String::new(),
            };
            vars.extend([
                ("CLOUDFLARE_R2_ACCESS_KEY_ID", b.access_key_id.clone()),
                (
                    "CLOUDFLARE_R2_SECRET_ACCESS_KEY",
                    b.secret_access_key.clone(),
                ),
                ("CLOUDFLARE_R2_SESSION_TOKEN", b.session_token.clone()),
                ("CLOUDFLARE_R2_ENDPOINT", b.endpoint.clone()),
                ("CLOUDFLARE_R2_BUCKET", b.name.clone()),
                ("CLOUDFLARE_R2_PREFIXES", prefixes),
                ("CLOUDFLARE_R2_PREFIX", prefix),
            ]);
        }
        vars
    }

    /// Returns what was granted, worded as the action logs it. None of it is
    /// secret.
    pub fn granted(&self) -> Vec<String> {
        let mut lines = vec![];
        if let Some(token) = &self.token {
            lines.push(format!(
                "minted token {} (profile {}, expires {})",
                token.id,
                self.profile,
                rfc3339(token.expires_at)
            ));
        }
        if let Some(b) = &self.bucket {
            let scope = if b.prefixes.is_empty() {
                String::new()
            } else {
                format!(" under {}", b.prefixes.join(", "))
            };
            lines.push(format!(
                "issued R2 credentials for bucket {}{scope} (profile {}, expires {})",
                b.name,
                self.profile,
                expires_on(b)
            ));
        }
        lines
    }
}

/// Returns when R2 credentials expire, as the broker shows it.
pub fn expires_on(bucket: &BucketCredentials) -> String {
    bucket.expires_on.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::sts::stub;

    pub fn credentials(overrides: Value) -> Result<Credentials> {
        let mut body = json!({
            "access_token": "t",
            "token_id": "id",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 900,
            "expires_at": 1_790_597_700,
            "account_id": "0123456789abcdef0123456789abcdef",
            "profile": "example-org/app:tofu-plan",
            "bucket": stub::bucket(),
        });
        for (key, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                body.as_object_mut().unwrap().remove(key);
            } else {
                body[key] = value.clone();
            }
        }
        Credentials::try_from(serde_json::from_value::<TokenExchangeResponse>(body).unwrap())
    }

    #[test]
    fn refuses_a_response_the_action_would_refuse() {
        assert!(credentials(json!({})).is_ok());
        assert!(credentials(json!({ "access_token": null, "token_id": null })).is_ok());
        for (overrides, said) in [
            (json!({ "account_id": null }), "missing account_id"),
            (
                json!({ "token_id": null }),
                "missing access_token or token_id",
            ),
            (
                json!({ "access_token": null, "token_id": null, "bucket": null }),
                "missing token and bucket",
            ),
        ] {
            let err = credentials(overrides).unwrap_err().to_string();
            assert!(err.ends_with(said), "{err}");
        }
    }

    #[test]
    fn says_what_was_granted_as_the_action_does() {
        assert_eq!(
            credentials(json!({})).unwrap().granted(),
            [
                "minted token id (profile example-org/app:tofu-plan, expires 2026-09-28T12:15:00Z)",
                "issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ (profile example-org/app:tofu-plan, expires 2026-09-28T12:15:00Z)",
            ]
        );
    }
}
