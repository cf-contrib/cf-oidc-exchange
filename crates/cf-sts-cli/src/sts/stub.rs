//! The tests' stand-ins, served from the test process: a broker, as the action
//! tests' stub is, and the identity provider its metadata names, at `/idp`.
//! All tokens and IDs are made up.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use super::{BrokerUrl, identity::tests::jwt};

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
    login: bool,
    deny: bool,
    /// Claims set on the provider's ID tokens, over its own.
    claims: Value,
    authorize: Fields,
    token: Fields,
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
            login: true,
            deny: false,
            claims: json!({}),
            authorize: Fields::new(),
            token: Fields::new(),
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

    /// The metadata names no login.
    pub fn without_login(&self) {
        self.world().login = false;
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
    if world.login {
        metadata["login"] = json!({ "issuer": format!("{base}/idp"), "client_id": CLIENT_ID });
    }
    Json(metadata)
}

async fn discovery(State(state): Shared) -> Json<Value> {
    let base = state.lock().unwrap().base.clone();
    Json(json!({
        "issuer": format!("{base}/idp"),
        "authorization_endpoint": format!("{base}/idp/authorize"),
        "token_endpoint": format!("{base}/idp/token"),
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

/// An ID token for the code, with the nonce the authorization request sent.
async fn token(State(state): Shared, Form(form): Form<Fields>) -> Json<Value> {
    let mut world = state.lock().unwrap();
    let mut claims = json!({
        "iss": format!("{}/idp", world.base),
        "sub": "user-0001",
        "email": "alice@example.com",
        "aud": CLIENT_ID,
        "exp": chrono::Utc::now().timestamp() + 3600,
        "nonce": world.authorize.get("nonce"),
    });
    for (key, value) in world.claims.as_object().unwrap() {
        claims[key] = value.clone();
    }
    world.token = form;
    Json(
        json!({ "id_token": jwt(claims), "token_type": "Bearer", "access_token": "stub-access-token" }),
    )
}
