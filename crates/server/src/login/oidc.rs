//! Sign-in with OpenID Connect: the authorization code flow with PKCE, as
//! OAuth 2.1 has it, and a signed session cookie afterwards.
//!
//! 1. `GET /auth/login` remembers a random state, nonce and PKCE verifier in
//!    a short-lived signed cookie and sends the browser to the provider.
//! 2. `GET /auth/callback` checks the state against the cookie, redeems the
//!    code with the verifier, verifies the ID token (signature, issuer,
//!    audience, nonce) and sets the session cookie.
//!
//! Session and sign-in cookies are HS256 JWTs with distinct audiences, so
//! neither passes for the other, nor for a live-update token.

use super::keys::{KeySet, Metadata};
use super::{IdentityClaims, LOGIN_PATH, Login, Method, User};
use anyhow::{Context, bail};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use gh::Secret;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

const SESSION_COOKIE: &str = "dashboard-session";
const SESSION_AUDIENCE: &str = "dashboard-session";
const SIGN_IN_COOKIE: &str = "dashboard-sign-in";
const SIGN_IN_AUDIENCE: &str = "dashboard-sign-in";
/// Time to get through the provider's sign-in page.
const SIGN_IN_TTL: Duration = Duration::from_secs(10 * 60);

pub struct Oidc {
    client_id: String,
    client_secret: Option<Secret>,
    redirect_url: Url,
    scopes: String,
    metadata: Metadata,
    keys: KeySet,
    http: reqwest::Client,
    encoding: EncodingKey,
    decoding: DecodingKey,
    session_ttl: Duration,
    /// `https` redirect URL: cookies get `Secure` and the `__Host-` prefix.
    secure: bool,
    groups_claim: String,
    /// Groups the allow-list asks about; the only ones worth keeping in
    /// the session cookie, which has to stay small.
    relevant_groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(flatten)]
    user: User,
}

#[derive(Serialize, Deserialize)]
struct SignInClaims {
    aud: String,
    exp: i64,
    state: String,
    nonce: String,
    verifier: String,
    return_to: String,
}

#[derive(Deserialize)]
struct IdToken {
    nonce: Option<String>,
    azp: Option<String>,
    #[serde(flatten)]
    identity: IdentityClaims,
}

fn random() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS provides randomness");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `target` if it is a path on this server, `/` otherwise, so the sign-in
/// can't be abused to redirect elsewhere.
fn local_path(target: Option<&str>) -> String {
    match target {
        Some(t)
            if t.starts_with('/')
                && !t.starts_with("//")
                && !t.starts_with("/\\")
                && !t.starts_with("/auth/")
                && !t.chars().any(char::is_control) =>
        {
            t.to_owned()
        }
        _ => "/".to_owned(),
    }
}

fn text(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

impl Oidc {
    pub async fn new(
        config: &super::OidcConfig,
        http: reqwest::Client,
        groups_claim: &str,
        relevant_groups: &[String],
        env: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let client_secret = match &config.client_secret_env {
            Some(var) => Some(Secret::new(
                env(var)
                    .filter(|s| !s.trim().is_empty())
                    .with_context(|| format!("environment variable {var} is not set"))?
                    .trim(),
            )),
            None => None,
        };
        let key = match &config.session_key_env {
            Some(var) => env(var)
                .filter(|k| k.len() >= 32)
                .with_context(|| {
                    format!(
                        "environment variable {var} must hold a session key of at least 32 bytes"
                    )
                })?
                .into_bytes(),
            None => random().into_bytes(),
        };
        let metadata = Metadata::discover(&http, &config.issuer).await?;
        let secure = match config.redirect_url.scheme() {
            "https" => true,
            "http" => false,
            other => bail!("[login.oidc] redirect_url has unsupported scheme {other:?}"),
        };
        Ok(Self {
            client_id: config.client_id.clone(),
            client_secret,
            redirect_url: config.redirect_url.clone(),
            scopes: config.scopes.join(" "),
            keys: KeySet::new(http.clone(), &metadata.jwks_uri),
            metadata,
            http,
            encoding: EncodingKey::from_secret(&key),
            decoding: DecodingKey::from_secret(&key),
            session_ttl: config.session_ttl,
            secure,
            groups_claim: groups_claim.to_owned(),
            relevant_groups: relevant_groups.to_vec(),
        })
    }

    fn cookie_name(&self, base: &str) -> String {
        if self.secure {
            format!("__Host-{base}")
        } else {
            base.to_owned()
        }
    }

    fn cookie(&self, base: &str, value: &str, max_age: Duration) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}",
            self.cookie_name(base),
            max_age.as_secs()
        )
        .parse()
        .expect("cookie values are base64 and JWTs")
    }

    fn read_cookie<'a>(&self, headers: &'a HeaderMap, base: &str) -> Option<&'a str> {
        let name = self.cookie_name(base);
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(n, _)| *n == name)
            .map(|(_, value)| value)
    }

    fn sign<T: Serialize>(&self, claims: &T) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &self.encoding)
            .expect("HS256 signing doesn't fail")
    }

    fn read_signed<T: for<'de> Deserialize<'de>>(&self, token: &str, audience: &str) -> Option<T> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        validation.set_audience(&[audience]);
        validation.required_spec_claims = ["exp", "aud"].map(String::from).into();
        jsonwebtoken::decode::<T>(token, &self.decoding, &validation)
            .ok()
            .map(|data| data.claims)
    }

    /// The user of a valid session cookie.
    pub fn authenticate(&self, headers: &HeaderMap) -> Option<User> {
        let token = self.read_cookie(headers, SESSION_COOKIE)?;
        self.read_signed::<SessionClaims>(token, SESSION_AUDIENCE)
            .map(|claims| claims.user)
    }

    fn start(&self, return_to: Option<&str>) -> Response {
        let claims = SignInClaims {
            aud: SIGN_IN_AUDIENCE.into(),
            exp: Utc::now().timestamp() + SIGN_IN_TTL.as_secs() as i64,
            state: random(),
            nonce: random(),
            verifier: random(),
            return_to: local_path(return_to),
        };
        let mut authorize = match Url::parse(&self.metadata.authorization_endpoint) {
            Ok(url) => url,
            Err(e) => {
                tracing::error!(error = %e, "provider has an invalid authorization_endpoint");
                return text(StatusCode::BAD_GATEWAY, "sign-in is misconfigured");
            }
        };
        authorize
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", self.redirect_url.as_str())
            .append_pair("scope", &self.scopes)
            .append_pair("state", &claims.state)
            .append_pair("nonce", &claims.nonce)
            .append_pair("code_challenge", &pkce_challenge(&claims.verifier))
            .append_pair("code_challenge_method", "S256");
        let cookie = self.cookie(SIGN_IN_COOKIE, &self.sign(&claims), SIGN_IN_TTL);
        let mut response = Redirect::to(authorize.as_str()).into_response();
        response.headers_mut().append(header::SET_COOKIE, cookie);
        response
    }

    /// Redeems `code` and verifies the ID token it comes with.
    async fn redeem(&self, code: &str, sign_in: &SignInClaims) -> anyhow::Result<User> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_verifier", &sign_in.verifier),
        ];
        let mut request = self
            .http
            .post(&self.metadata.token_endpoint)
            .header(header::ACCEPT, "application/json");
        match &self.client_secret {
            // client_secret_basic, the default: both parts form-encoded.
            Some(secret) => {
                let encode = |s: &str| {
                    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
                };
                request =
                    request.basic_auth(encode(&self.client_id), Some(encode(secret.expose())));
            }
            None => form.push(("client_id", &self.client_id)),
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let response = request.form(&form).send().await?;
        let status = response.status();
        if !status.is_success() {
            // The body names the OAuth error, never a secret.
            let body = response.text().await.unwrap_or_default();
            bail!("token endpoint answered {status}: {body}");
        }
        let tokens: TokenResponse = response.json().await.context("parsing token response")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.metadata.issuer]);
        validation.set_audience(&[&self.client_id]);
        validation.required_spec_claims = ["exp", "iss", "aud", "sub"].map(String::from).into();
        let id: IdToken = self
            .keys
            .verify(&tokens.id_token, &validation)
            .await
            .map_err(|e| anyhow::anyhow!("ID token rejected: {e:?}"))?;
        if id.nonce.as_deref() != Some(sign_in.nonce.as_str()) {
            bail!("ID token rejected: nonce mismatch");
        }
        if id.azp.as_deref().is_some_and(|azp| azp != self.client_id) {
            bail!("ID token rejected: issued to another party");
        }
        let mut user = id.identity.into_user(&self.groups_claim);
        user.groups.retain(|g| self.relevant_groups.contains(g));
        Ok(user)
    }

    fn session(&self, user: User) -> HeaderValue {
        let now = Utc::now().timestamp();
        let claims = SessionClaims {
            aud: SESSION_AUDIENCE.into(),
            iat: now,
            exp: now + self.session_ttl.as_secs() as i64,
            user,
        };
        self.cookie(SESSION_COOKIE, &self.sign(&claims), self.session_ttl)
    }

    fn clear(&self, base: &str) -> HeaderValue {
        self.cookie(base, "", Duration::ZERO)
    }
}

fn oidc(login: &Login) -> Option<&Oidc> {
    match &login.method {
        Method::Oidc(oidc) => Some(oidc),
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct LoginQuery {
    return_to: Option<String>,
}

pub async fn login(State(login): State<Arc<Login>>, Query(query): Query<LoginQuery>) -> Response {
    match oidc(&login) {
        Some(oidc) => oidc.start(query.return_to.as_deref()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(login): State<Arc<Login>>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(oidc) = oidc(&login) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(error) = &query.error {
        tracing::warn!(%error, "identity provider refused the sign-in");
        return text(
            StatusCode::FORBIDDEN,
            "The identity provider refused the sign-in.",
        );
    }
    let sign_in = oidc
        .read_cookie(&headers, SIGN_IN_COOKIE)
        .and_then(|token| oidc.read_signed::<SignInClaims>(token, SIGN_IN_AUDIENCE));
    let (Some(sign_in), Some(code), Some(state)) = (sign_in, &query.code, &query.state) else {
        return text(
            StatusCode::BAD_REQUEST,
            "Sign-in expired or was started elsewhere. Please try again.",
        );
    };
    if *state != sign_in.state {
        return text(
            StatusCode::BAD_REQUEST,
            "Sign-in expired or was started elsewhere. Please try again.",
        );
    }
    let user = match oidc.redeem(code, &sign_in).await {
        Ok(user) => user,
        Err(e) => {
            tracing::warn!(error = %e, "sign-in failed");
            return text(StatusCode::BAD_GATEWAY, "Sign-in failed.");
        }
    };
    let mut response = if login.allow.permits(&user) {
        tracing::info!(user = %user.subject, "signed in");
        let mut response = Redirect::to(&sign_in.return_to).into_response();
        response
            .headers_mut()
            .append(header::SET_COOKIE, oidc.session(user));
        response
    } else {
        tracing::warn!(user = %user.subject, "signed-in user not allowed");
        text(
            StatusCode::FORBIDDEN,
            "You are signed in, but not allowed to use this dashboard.",
        )
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, oidc.clear(SIGN_IN_COOKIE));
    response
}

/// Ends the session here; the provider's own session lives on, so signing
/// in again may not ask for credentials.
pub async fn logout(State(login): State<Arc<Login>>) -> Response {
    let Some(oidc) = oidc(&login) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = Json(serde_json::json!({ "redirect": "/auth/signed-out" })).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, oidc.clear(SESSION_COOKIE));
    response
}

pub async fn signed_out() -> Html<String> {
    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Signed out</title>\
         <p>You are signed out of the security dashboard. <a href=\"{LOGIN_PATH}\">Sign in again</a></p>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // Appendix B.
        check!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn return_targets_stay_on_this_server() {
        check!(local_path(Some("/repo/acme/api?tab=alerts")) == "/repo/acme/api?tab=alerts");
        for bad in [
            None,
            Some(""),
            Some("https://evil.example"),
            Some("//evil.example"),
            Some("/\\evil.example"),
            Some("/auth/login"),
            Some("/a\r\nSet-Cookie: x"),
        ] {
            check!(local_path(bad) == "/", "{bad:?}");
        }
    }

    #[test]
    fn random_values_are_long_and_distinct() {
        check!(random().len() == 43);
        check!(random() != random());
    }
}
