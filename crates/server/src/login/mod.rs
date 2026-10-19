//! Who may use the dashboard.
//!
//! Three modes, picked in `[login]`:
//! - `none`: no sign-in; for loopback or a network that is trusted as a whole.
//! - `proxy`: an authenticating proxy in front (oauth2-proxy, an ingress with
//!   single sign-on) vouches for the user, by passing along a token the
//!   server verifies, or by identity headers from a trusted address.
//! - `oidc`: the server signs users in itself, with the authorization code
//!   flow and PKCE, and keeps them signed in with a session cookie.
//!
//! In both of the latter, [`require`] guards everything but the sign-in
//! flow's own routes and `/healthz`, and `[login.allow]` narrows down who gets in.

mod config;
mod keys;
mod oidc;
mod proxy;

pub use config::{Allow, LoginConfig, Mode, OidcConfig, ProxyConfig, ProxyTrust};

use anyhow::Context;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Where the identity provider sends users back to.
pub const CALLBACK_PATH: &str = "/auth/callback";
const LOGIN_PATH: &str = "/auth/login";
const LOGOUT_PATH: &str = "/auth/logout";
const SIGNED_OUT_PATH: &str = "/auth/signed-out";

/// A signed-in user, available to handlers as an [`Extension`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Stable ID from the identity provider (`sub`), or the proxy's user
    /// header.
    pub subject: String,
    pub email: Option<String>,
    /// Whether the provider vouches for `email`. Only verified addresses
    /// count for `[login.allow]`: some providers let users put any address
    /// into their profile.
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl Allow {
    fn is_open(&self) -> bool {
        self.emails.is_empty() && self.domains.is_empty() && self.groups.is_empty()
    }

    pub fn permits(&self, user: &User) -> bool {
        if self.is_open() {
            return true;
        }
        let email = user
            .email
            .as_deref()
            .filter(|_| user.email_verified)
            .map(str::to_ascii_lowercase);
        let by_email = email.as_deref().is_some_and(|email| {
            self.emails.iter().any(|e| e.eq_ignore_ascii_case(email))
                || email.rsplit_once('@').is_some_and(|(_, domain)| {
                    self.domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
                })
        });
        by_email || user.groups.iter().any(|g| self.groups.contains(g))
    }
}

/// Claims of ID and access tokens that make up a [`User`].
#[derive(Debug, Deserialize)]
struct IdentityClaims {
    sub: String,
    email: Option<String>,
    /// A boolean, or `"true"` with some providers.
    email_verified: Option<serde_json::Value>,
    name: Option<String>,
    preferred_username: Option<String>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

impl IdentityClaims {
    fn into_user(mut self, groups_claim: &str) -> User {
        // Groups are a list, or a single string with some providers.
        let groups = match self.other.remove(groups_claim) {
            Some(serde_json::Value::Array(items)) => items
                .into_iter()
                .filter_map(|g| g.as_str().map(str::to_owned))
                .collect(),
            Some(serde_json::Value::String(group)) => vec![group],
            _ => Vec::new(),
        };
        User {
            subject: self.sub,
            email_verified: self.email.is_some()
                && match &self.email_verified {
                    Some(serde_json::Value::Bool(verified)) => *verified,
                    Some(serde_json::Value::String(verified)) => {
                        verified.eq_ignore_ascii_case("true")
                    }
                    _ => false,
                },
            email: self.email,
            name: self.name.or(self.preferred_username),
            groups,
        }
    }
}

enum Method {
    None,
    Proxy(Box<proxy::Proxy>),
    Oidc(Box<oidc::Oidc>),
}

pub struct Login {
    method: Method,
    allow: Allow,
}

impl Login {
    /// No sign-in at all.
    pub fn none() -> Self {
        Self {
            method: Method::None,
            allow: Allow::default(),
        }
    }

    /// Fetches the identity provider's discovery document, if any, so a
    /// broken configuration fails at start-up. `env` looks up environment
    /// variables.
    pub async fn from_config(
        config: &LoginConfig,
        env: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!(
                "github-security-dashboard/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        let groups_claim = config.groups_claim.as_deref().unwrap_or("groups");
        let method = match config.mode {
            Mode::None => Method::None,
            Mode::Proxy => {
                let proxy = config.proxy.as_ref().context("[login.proxy] missing")?;
                Method::Proxy(Box::new(
                    proxy::Proxy::new(proxy, http, groups_claim).await?,
                ))
            }
            Mode::Oidc => {
                let oidc = config.oidc.as_ref().context("[login.oidc] missing")?;
                Method::Oidc(Box::new(
                    oidc::Oidc::new(oidc, http, groups_claim, &config.allow.groups, env).await?,
                ))
            }
        };
        Ok(Self {
            method,
            allow: config.allow.clone(),
        })
    }

    pub fn mode(&self) -> Mode {
        match self.method {
            Method::None => Mode::None,
            Method::Proxy(_) => Mode::Proxy,
            Method::Oidc(_) => Mode::Oidc,
        }
    }

    /// `/auth/*` and `/api/me`. The routes still need [`require`] in front.
    pub fn router(self: &Arc<Self>) -> Router {
        let router = Router::new().route("/api/me", get(me));
        let router = match self.method {
            Method::Oidc(_) => router
                .route(LOGIN_PATH, get(oidc::login))
                .route(CALLBACK_PATH, get(oidc::callback))
                .route(LOGOUT_PATH, post(oidc::logout))
                .route(SIGNED_OUT_PATH, get(oidc::signed_out)),
            _ => router,
        };
        router.with_state(Arc::clone(self))
    }
}

/// Paths everyone may reach: the sign-in flow itself, and liveness probes.
/// Exact matches only; paths aren't normalized, so a prefix would also let
/// `/auth/../api/summary` through to the UI fallback.
fn is_public(path: &str) -> bool {
    [
        LOGIN_PATH,
        CALLBACK_PATH,
        LOGOUT_PATH,
        SIGNED_OUT_PATH,
        "/healthz",
    ]
    .contains(&path)
}

/// Lets signed-in, allowed users through, with their [`User`] attached.
/// Others get 401 (API requests, or with a proxy) or are sent to sign in
/// (page loads with `oidc`); signed-in users the allow-list doesn't cover
/// get 403.
pub async fn require(
    State(login): State<Arc<Login>>,
    mut request: Request,
    next: Next,
) -> Response {
    if matches!(login.method, Method::None) || is_public(request.uri().path()) {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let user = match &login.method {
        Method::None => unreachable!("handled above"),
        Method::Proxy(proxy) => proxy.authenticate(request.headers(), peer).await,
        Method::Oidc(oidc) => oidc.authenticate(request.headers()),
    };
    let Some(user) = user else {
        return unauthenticated(&login, &request);
    };
    if !login.allow.permits(&user) {
        tracing::warn!(user = %user.subject, "signed-in user not allowed");
        return forbidden();
    }
    request.extensions_mut().insert(user);
    next.run(request).await
}

fn unauthenticated(login: &Login, request: &Request) -> Response {
    let path = request.uri().path();
    let can_sign_in = matches!(login.method, Method::Oidc(_));
    if can_sign_in && !path.starts_with("/api/") {
        let target = request.uri().path_and_query().map_or("/", |p| p.as_str());
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", target)
            .finish();
        return Redirect::to(&format!("{LOGIN_PATH}?{query}")).into_response();
    }
    let body = Json(serde_json::json!({
        "error": "unauthenticated",
        "login": can_sign_in.then_some(LOGIN_PATH),
    }));
    let mut response = (StatusCode::UNAUTHORIZED, body).into_response();
    let challenge = if can_sign_in { "Cookie" } else { "Bearer" };
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        challenge.parse().expect("static header"),
    );
    response
}

fn forbidden() -> Response {
    let body = Json(serde_json::json!({ "error": "not allowed" }));
    (StatusCode::FORBIDDEN, body).into_response()
}

#[derive(Serialize)]
struct Me {
    mode: &'static str,
    user: Option<User>,
    /// Where to send the browser to sign out; `oidc` signs out with
    /// `POST /auth/logout` instead.
    sign_out_url: Option<String>,
}

async fn me(State(login): State<Arc<Login>>, user: Option<Extension<User>>) -> Json<Me> {
    let sign_out_url = match &login.method {
        Method::Proxy(proxy) => proxy.sign_out_url().map(str::to_owned),
        _ => None,
    };
    Json(Me {
        mode: login.mode().as_str(),
        user: user.map(|Extension(user)| user),
        sign_out_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    fn user(email: Option<&str>, groups: &[&str]) -> User {
        User {
            subject: "u".into(),
            email: email.map(str::to_owned),
            email_verified: true,
            name: None,
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn empty_allow_list_admits_everyone() {
        check!(Allow::default().permits(&user(None, &[])));
    }

    #[test]
    fn allow_list_matches_emails_domains_and_groups() {
        let allow = Allow {
            emails: vec!["Alice@Example.org".into()],
            domains: vec!["corp.example".into()],
            groups: vec!["security".into()],
        };
        check!(allow.permits(&user(Some("alice@example.org"), &[])));
        check!(allow.permits(&user(Some("bob@CORP.example"), &[])));
        check!(allow.permits(&user(None, &["security"])));
        check!(!allow.permits(&user(Some("bob@example.org"), &["devs"])));
        check!(!allow.permits(&user(Some("bob@evil.corp.example.net"), &[])));
        check!(!allow.permits(&user(None, &[])));

        let mut unverified = user(Some("alice@example.org"), &[]);
        unverified.email_verified = false;
        check!(
            !allow.permits(&unverified),
            "unverified addresses prove nothing"
        );
    }

    #[test]
    fn claims_become_users() {
        let claims: IdentityClaims = serde_json::from_value(serde_json::json!({
            "sub": "123", "email": "a@b.c", "email_verified": true,
            "preferred_username": "alice", "roles": ["admin", "dev"], "exp": 1
        }))
        .unwrap();
        let user = claims.into_user("roles");
        check!(user.subject == "123");
        check!(user.email.as_deref() == Some("a@b.c"));
        check!(user.email_verified);
        check!(user.name.as_deref() == Some("alice"));
        check!(user.groups == ["admin", "dev"]);

        let unverified: IdentityClaims = serde_json::from_value(serde_json::json!({
            "sub": "123", "email": "a@b.c", "email_verified": false, "groups": "one"
        }))
        .unwrap();
        let user = unverified.into_user("groups");
        check!(!user.email_verified);
        check!(user.groups == ["one"]);

        for (claim, verified) in [
            (serde_json::json!("true"), true),
            (serde_json::json!("True"), true),
            (serde_json::json!("yes"), false),
            (serde_json::Value::Null, false),
        ] {
            let claims: IdentityClaims = serde_json::from_value(serde_json::json!({
                "sub": "1", "email": "a@b.c", "email_verified": claim
            }))
            .unwrap();
            check!(claims.into_user("groups").email_verified == verified);
        }
        let silent: IdentityClaims =
            serde_json::from_value(serde_json::json!({ "sub": "1", "email": "a@b.c" })).unwrap();
        check!(
            !silent.into_user("groups").email_verified,
            "no claim, no verification"
        );
    }

    #[test]
    fn only_the_sign_in_flow_and_probes_are_public() {
        check!(is_public("/auth/callback"));
        check!(is_public("/healthz"));
        check!(!is_public("/api/summary"));
        check!(!is_public("/"));
        check!(!is_public("/authx"));
        check!(!is_public("/auth/"));
        check!(!is_public("/auth/../api/summary"));
    }
}
