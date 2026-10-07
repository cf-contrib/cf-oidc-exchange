use std::{fmt, future::Future, time::Duration};

use anyhow::{Result, anyhow, bail};
use cf_sts_sdk::v1::{
    ApiError, ApiOpError, ErrorCode, ExchangeTokenApiError, HttpClient, Login, MetadataApiError,
    TokenExchangeRequest, TokenExchangeRequestGrantType as GrantType,
    TokenExchangeRequestSubjectTokenType as SubjectTokenType, TokenExchangeResponse,
    TokenRevocationRequest, TokenRevocationRequestTokenTypeHint as TokenTypeHint,
};

use super::hinted;

/// Every request to the broker gives up after this, as the action's do.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The broker's URL: its origin, `https://`, or plain `http://` on a loopback
/// host for local development, because the ID token travels in the request.
/// It's also what the login is stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerUrl(String);

impl BrokerUrl {
    /// Parses `--url` or `CF_STS_CLI_URL`, which every command needs: there's
    /// no config file.
    pub fn parse(value: Option<&str>) -> Result<Self> {
        let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            bail!("no broker URL; pass --url or set CF_STS_CLI_URL");
        };
        let url =
            url::Url::parse(value).map_err(|_| anyhow!("--url is not a valid URL: {value}"))?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => bail!("--url must use https: {value}"),
        }
        Ok(Self(url.origin().ascii_serialization()))
    }

    /// Returns the origin, e.g. `https://cf-sts.example.com`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BrokerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The broker's API, over the SDK's client, with its errors made into
/// messages a person can act on.
pub struct Broker {
    url: BrokerUrl,
    client: HttpClient,
}

impl Broker {
    /// Returns a client for the broker at `url`.
    pub fn new(url: &BrokerUrl) -> Self {
        Self {
            url: url.clone(),
            client: HttpClient::new().with_base_url(url.as_str()),
        }
    }

    /// Returns the broker's URL.
    pub fn url(&self) -> &BrokerUrl {
        &self.url
    }

    /// Exchanges the person's ID token for what `profile`, or the one profile
    /// that matches, grants. Not retried: minting isn't idempotent.
    pub async fn exchange(
        &self,
        id_token: &str,
        profile: Option<String>,
        ttl: Option<String>,
    ) -> Result<TokenExchangeResponse> {
        let request = TokenExchangeRequest {
            grant_type: GrantType::UrnIetfParamsOauthGrantTypeTokenExchange,
            subject_token: id_token.to_string(),
            subject_token_type: SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken,
            audience: None,
            requested_token_type: None,
            profile,
            ttl,
        };
        self.call("/oauth/token", self.client.exchange_token(request))
            .await?
            .map_err(|err| self.refused(err))
    }

    /// Revokes a token the exchange minted. The broker answers `200` whether
    /// it was revoked now or was already gone.
    pub async fn revoke(&self, token: &str) -> Result<()> {
        let request = TokenRevocationRequest {
            token: token.to_string(),
            token_type_hint: Some(TokenTypeHint::AccessToken),
        };
        self.call("/oauth/revoke", self.client.revoke_token(request))
            .await?
            .map_err(|err| match err {
                ApiOpError::Api(api) => anyhow!("the broker answered {}", api.status),
                ApiOpError::Transport(err) => anyhow!(err),
            })
    }

    /// Returns where people sign in, from the broker's metadata.
    pub async fn login(&self) -> Result<Login> {
        let path = "/.well-known/oauth-authorization-server";
        let metadata = self.call(path, self.client.metadata()).await?.map_err(
            |err: ApiOpError<MetadataApiError>| match err {
                ApiOpError::Api(api) => self.answered(path, &api),
                ApiOpError::Transport(err) => self.unreachable(&err),
            },
        )?;
        metadata.login.ok_or_else(|| {
            hinted(
                format!("the broker at {} names no login", self.url),
                "its policy's login names the provider people sign in with",
            )
        })
    }

    /// Awaits `request`, giving up after [`TIMEOUT`].
    async fn call<T>(&self, path: &str, request: impl Future<Output = T>) -> Result<T> {
        tokio::time::timeout(TIMEOUT, request).await.map_err(|_| {
            anyhow!(
                "the broker at {} didn't answer {path} within {}s",
                self.url,
                TIMEOUT.as_secs()
            )
        })
    }

    /// Returns why an exchange failed, and what to do about it.
    fn refused(&self, err: ApiOpError<ExchangeTokenApiError>) -> anyhow::Error {
        let api = match err {
            ApiOpError::Transport(err) => return self.unreachable(&err),
            ApiOpError::Api(api) => api,
        };
        let said = match &api.typed {
            Some(
                ExchangeTokenApiError::Status400(said)
                | ExchangeTokenApiError::Status500(said)
                | ExchangeTokenApiError::Status503(said),
            ) => said,
            None => return self.answered("/oauth/token", &api),
        };
        let (code, description) = (&said.error, said.error_description.as_str());
        let message = if api.status == 400 {
            format!("the broker refused the exchange ({code}): {description}")
        } else {
            format!("the broker failed ({code}): {description}")
        };
        match hint(code, description) {
            Some(hint) => hinted(message, hint),
            None => anyhow!(message),
        }
    }

    /// Returns the error for a response that isn't one of the broker's OAuth
    /// errors: most likely `--url` points at something else.
    fn answered<E>(&self, path: &str, api: &ApiError<E>) -> anyhow::Error {
        let message = format!(
            "the broker at {} answered {path} with {}",
            self.url, api.status
        );
        if api.status == 404 {
            hinted(
                message,
                "check --url or CF_STS_CLI_URL: it should be the broker's URL",
            )
        } else {
            anyhow!(message)
        }
    }

    fn unreachable(&self, err: &impl fmt::Display) -> anyhow::Error {
        anyhow!("can't reach the broker at {}: {err}", self.url)
    }
}

/// Returns what to do about the errors a person usually runs into, by the
/// broker's OAuth error code and description.
fn hint(code: &ErrorCode, description: &str) -> Option<&'static str> {
    match code {
        ErrorCode::InvalidRequest if description.contains("isn't for provider") => {
            Some("your login is for people: ask for a profile for its provider, not one for CI")
        }
        ErrorCode::InvalidRequest if description.ends_with(": name one") => {
            Some("pass --profile or set CF_STS_CLI_PROFILE")
        }
        ErrorCode::InvalidRequest if description.starts_with("no provider is for issuer") => {
            Some("this broker doesn't take your login; run 'cf-sts login' with its URL")
        }
        ErrorCode::ServerError => Some("the broker is misconfigured; its logs say why"),
        ErrorCode::TemporarilyUnavailable => {
            Some("Cloudflare or your identity provider failed; try again")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::sts::stub::{self, Stub};

    #[test]
    fn takes_the_origin_of_an_https_or_loopback_url() {
        let parse = |value| BrokerUrl::parse(Some(value)).map(|url| url.0);
        assert_eq!(
            parse("https://cf-sts.example.com/").unwrap(),
            "https://cf-sts.example.com"
        );
        assert_eq!(
            parse(" https://cf-sts.example.com:8443/x ").unwrap(),
            "https://cf-sts.example.com:8443"
        );
        assert_eq!(
            parse("http://127.0.0.1:8790").unwrap(),
            "http://127.0.0.1:8790"
        );
        for (value, said) in [
            ("http://cf-sts.example.com", "must use https"),
            ("ftp://127.0.0.1", "must use https"),
            ("cf-sts.example.com", "is not a valid URL"),
        ] {
            let err = parse(value).unwrap_err().to_string();
            assert!(err.contains(said), "{value}: {err}");
        }
    }

    #[test]
    fn needs_a_url_and_says_where_it_comes_from() {
        for value in [None, Some(""), Some("  ")] {
            assert_eq!(
                BrokerUrl::parse(value).unwrap_err().to_string(),
                "no broker URL; pass --url or set CF_STS_CLI_URL"
            );
        }
    }

    #[test]
    fn hints_at_what_to_do_about_the_usual_refusals() {
        let hinted = |code, description| hint(&code, description).unwrap_or_default();
        assert!(
            hinted(
                ErrorCode::InvalidRequest,
                "profile example-org/app:ci.apply isn't for provider com.cloudflare.access"
            )
            .contains("not one for CI")
        );
        assert!(
            hinted(
                ErrorCode::InvalidRequest,
                "profiles a, b all match the token: name one"
            )
            .contains("--profile")
        );
        assert!(hinted(ErrorCode::TemporarilyUnavailable, "").contains("try again"));
        assert_eq!(
            hint(&ErrorCode::InvalidRequest, "no profile matches the token"),
            None
        );
    }

    #[tokio::test]
    async fn says_what_the_broker_refused_and_why() {
        let stub = Stub::start().await;
        stub.refuse(
            400,
            json!({ "error": "invalid_request", "error_description": "profile example-org/app:ci.apply isn't for provider access" }),
        );
        let err = Broker::new(&stub.url())
            .exchange("id-token", Some("example-org/app:ci.apply".into()), None)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "the broker refused the exchange (invalid_request): profile example-org/app:ci.apply isn't for provider access\n  hint: your login is for people: ask for a profile for its provider, not one for CI"
        );
    }

    #[tokio::test]
    async fn says_when_the_url_isnt_a_broker() {
        let stub = Stub::start().await;
        stub.refuse(404, json!("not found"));
        let err = Broker::new(&stub.url())
            .exchange("id-token", None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("answered /oauth/token with 404\n  hint: check --url"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn sends_the_id_token_profile_and_ttl() {
        let stub = Stub::start().await;
        Broker::new(&stub.url())
            .exchange("id-token", Some("tofu-plan".into()), Some("30m".into()))
            .await
            .unwrap();
        let form = stub.exchanges().pop().unwrap();
        assert_eq!(form["subject_token"], "id-token");
        assert_eq!(
            form["subject_token_type"],
            "urn:ietf:params:oauth:token-type:id_token"
        );
        assert_eq!(form["profile"], "tofu-plan");
        assert_eq!(form["ttl"], "30m");
        assert!(!form.contains_key("audience"));
    }

    #[tokio::test]
    async fn reads_where_people_sign_in_from_the_metadata() {
        let stub = Stub::start().await;
        let login = Broker::new(&stub.url()).login().await.unwrap();
        assert_eq!(login.issuer, stub.issuer());
        assert_eq!(login.client_id, stub::CLIENT_ID);

        stub.without_login();
        let err = Broker::new(&stub.url())
            .login()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("names no login\n  hint:"), "{err}");
    }
}
