//! The tests' stand-ins: a broker, as the action tests' stub is, and the
//! identity provider its metadata names, at `/idp`, served from the test
//! process; a keychain in memory; and unsigned ID tokens. All tokens and IDs
//! are made up.

use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::Result;
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::{BrokerUrl, Login, Store};

/// Memory keeps logins in memory, for the tests.
#[derive(Default)]
pub struct Memory(RefCell<HashMap<String, (String, Option<String>)>>);

impl Store for Memory {
    fn load(&self, broker: &BrokerUrl) -> Result<Option<Login>> {
        Ok(self
            .0
            .borrow()
            .get(broker.as_str())
            .map(|(id_token, refresh_token)| Login {
                id_token: id_token.clone(),
                refresh_token: refresh_token.clone(),
            }))
    }

    fn save(&self, broker: &BrokerUrl, login: &Login) -> Result<()> {
        self.0.borrow_mut().insert(
            broker.to_string(),
            (login.id_token.clone(), login.refresh_token.clone()),
        );
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

/// The identity provider's client ID, which the broker's metadata names.
pub const CLIENT_ID: &str = "stub-client-id";

type Fields = HashMap<String, String>;

/// A broker and identity provider on a loopback port, and what they were
/// asked.
pub struct Stub {
    base: String,
    state: Arc<Mutex<World>>,
}

struct World {
    base: String,
    /// What the exchange answers, or the status and body it refuses with.
    response: Value,
    refusal: Option<(u16, Value)>,
    exchanges: Vec<Fields>,
    revoked: Vec<String>,
    /// The names of the identity providers the metadata lists. All are the
    /// one at `/idp`.
    identity_providers: Vec<String>,
    deny: bool,
    /// Claims set on the provider's ID tokens, over its own.
    claims: Value,
    authorize: Fields,
    token: Fields,
    /// Whether the provider issues refresh tokens, as its Discovery document
    /// says; whether it refuses them; the one it takes now, which each
    /// renewal replaces; and the forms renewals sent.
    refreshes: bool,
    refuse_refresh: bool,
    refresh_token: String,
    renewals: Vec<Fields>,
}

/// R2 credentials, as the broker returns them.
pub fn bucket() -> Value {
    json!({
        "name": "org-terraform-state",
        "access_key_id": "stub-r2-access-key-id",
        "secret_access_key": "stub-r2-secret-access-key",
        "session_token": "stub-r2-session-token",
        "prefixes": ["github.com/example-org/app/"],
        "endpoint": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
        "expires_on": "2026-09-28T12:15:00Z",
    })
}

impl Stub {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(World {
            base: base.clone(),
            response: json!({
                "access_token": "stub-cloudflare-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 900,
                "expires_at": 1_790_597_700,
                "token_id": "stub-token-id",
                "account_id": "0123456789abcdef0123456789abcdef",
                "profile": "example-org/app:tofu-plan",
                "bucket": bucket(),
            }),
            refusal: None,
            exchanges: vec![],
            revoked: vec![],
            identity_providers: vec!["access".into()],
            deny: false,
            claims: json!({}),
            authorize: Fields::new(),
            token: Fields::new(),
            refreshes: true,
            refuse_refresh: false,
            refresh_token: "stub-refresh-token-0".into(),
            renewals: vec![],
        }));
        let router = Router::new()
            .route("/oauth/token", post(exchange))
            .route("/oauth/revoke", post(revoke))
            .route("/.well-known/oauth-authorization-server", get(metadata))
            .route("/idp/.well-known/openid-configuration", get(discovery))
            .route("/idp/authorize", get(authorize))
            .route("/idp/token", post(token))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { base, state }
    }

    fn world(&self) -> MutexGuard<'_, World> {
        self.state.lock().unwrap()
    }

    /// Returns the broker's URL, as given on the command line.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn url(&self) -> BrokerUrl {
        BrokerUrl::parse(Some(&self.base)).unwrap()
    }

    /// The identity provider's issuer.
    pub fn issuer(&self) -> String {
        format!("{}/idp", self.base)
    }

    pub fn respond(&self, response: Value) {
        self.world().response = response;
    }

    pub fn response(&self) -> Value {
        self.world().response.clone()
    }

    pub fn refuse(&self, status: u16, body: Value) {
        self.world().refusal = Some((status, body));
    }

    /// The forms the exchange was sent.
    pub fn exchanges(&self) -> Vec<Fields> {
        self.world().exchanges.clone()
    }

    pub fn revoked(&self) -> Vec<String> {
        self.world().revoked.clone()
    }

    /// The metadata lists these identity providers.
    pub fn identity_providers(&self, names: &[&str]) {
        self.world().identity_providers = names.iter().map(|n| n.to_string()).collect();
    }

    /// The provider sends the person back with `access_denied`.
    pub fn deny_sign_in(&self) {
        self.world().deny = true;
    }

    /// Sets `claims` on the provider's ID tokens.
    pub fn claims(&self, claims: Value) {
        self.world().claims = claims;
    }

    /// What the sign-in sent the provider: the authorization request's query,
    /// and the token request's form.
    pub fn sign_in(&self) -> (Fields, Fields) {
        let world = self.world();
        (world.authorize.clone(), world.token.clone())
    }

    /// The provider issues no refresh tokens, and its Discovery document
    /// doesn't list them.
    pub fn no_refresh(&self) {
        self.world().refreshes = false;
    }

    /// The provider refuses refresh tokens, as once they've expired.
    pub fn refuse_refresh(&self) {
        self.world().refuse_refresh = true;
    }

    /// The refresh token the provider takes now.
    pub fn refresh_token(&self) -> String {
        self.world().refresh_token.clone()
    }

    /// The forms renewals sent the provider.
    pub fn renewals(&self) -> Vec<Fields> {
        self.world().renewals.clone()
    }
}

type Shared = State<Arc<Mutex<World>>>;

async fn exchange(State(state): Shared, Form(form): Form<Fields>) -> Response {
    let mut world = state.lock().unwrap();
    world.exchanges.push(form);
    match &world.refusal {
        Some((status, body)) => {
            (StatusCode::from_u16(*status).unwrap(), Json(body.clone())).into_response()
        }
        None => Json(world.response.clone()).into_response(),
    }
}

async fn revoke(State(state): Shared, Form(form): Form<Fields>) -> StatusCode {
    let mut world = state.lock().unwrap();
    world.revoked.push(form["token"].clone());
    StatusCode::OK
}

async fn metadata(State(state): Shared) -> Json<Value> {
    let world = state.lock().unwrap();
    let base = &world.base;
    let mut metadata = json!({
        "issuer": base,
        "jwks_uri": format!("{base}/.well-known/jwks"),
        "token_endpoint": format!("{base}/oauth/token"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": [],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
    });
    if !world.identity_providers.is_empty() {
        let providers: Vec<Value> = world
            .identity_providers
            .iter()
            .map(|name| json!({ "name": name, "issuer": format!("{base}/idp"), "client_id": CLIENT_ID }))
            .collect();
        metadata["identity_providers"] = json!(providers);
    }
    Json(metadata)
}

async fn discovery(State(state): Shared) -> Json<Value> {
    let world = state.lock().unwrap();
    let base = &world.base;
    // As Cloudflare Access lists them, per application.
    let mut grants = vec!["authorization_code_with_pkce"];
    if world.refreshes {
        grants.push("refresh_tokens");
    }
    Json(json!({
        "issuer": format!("{base}/idp"),
        "authorization_endpoint": format!("{base}/idp/authorize"),
        "token_endpoint": format!("{base}/idp/token"),
        "grant_types_supported": grants,
    }))
}

/// Signs the person in at once, and sends them back to the redirect URI.
async fn authorize(State(state): Shared, Query(query): Query<Fields>) -> Response {
    let mut world = state.lock().unwrap();
    let mut back = url::Url::parse(&query["redirect_uri"]).unwrap();
    if world.deny {
        back.query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("error_description", "not an account member");
    } else {
        back.query_pairs_mut().append_pair("code", "stub-code");
    }
    back.query_pairs_mut().append_pair("state", &query["state"]);
    world.authorize = query;
    (StatusCode::FOUND, [(header::LOCATION, back.to_string())]).into_response()
}

/// An ID token for the code, with the nonce the authorization request sent,
/// and a refresh token if it asked for offline_access. Or, for a refresh
/// token, a new ID token without a nonce and a new refresh token: Access
/// rotates them.
async fn token(State(state): Shared, Form(form): Form<Fields>) -> Response {
    let mut world = state.lock().unwrap();
    let renewal = form.get("grant_type").map(String::as_str) == Some("refresh_token");
    let mut claims = json!({
        "iss": format!("{}/idp", world.base),
        "sub": "user-0001",
        "email": "alice@example.com",
        "aud": CLIENT_ID,
        "exp": chrono::Utc::now().timestamp() + 3600,
    });
    if !renewal {
        claims["nonce"] = json!(world.authorize.get("nonce"));
    }
    for (key, value) in world.claims.as_object().unwrap() {
        claims[key] = value.clone();
    }
    let mut reply = json!({ "id_token": jwt(claims), "token_type": "Bearer", "access_token": "stub-access-token" });

    if renewal {
        let taken = form.get("refresh_token") == Some(&world.refresh_token);
        world.renewals.push(form);
        if world.refuse_refresh || !taken {
            let refusal = json!({ "error": "invalid_grant", "error_description": "the refresh token has expired" });
            return (StatusCode::BAD_REQUEST, Json(refusal)).into_response();
        }
        let next = world.renewals.len();
        world.refresh_token = format!("stub-refresh-token-{next}");
        reply["refresh_token"] = json!(world.refresh_token);
        return Json(reply).into_response();
    }

    let offline = world
        .authorize
        .get("scope")
        .is_some_and(|scope| scope.split(' ').any(|s| s == "offline_access"));
    if world.refreshes && offline {
        reply["refresh_token"] = json!(world.refresh_token);
    }
    world.token = form;
    Json(reply).into_response()
}
