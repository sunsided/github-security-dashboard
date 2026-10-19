//! Sign-in by an authenticating proxy in front of the server.

use super::config::{ProxyConfig, ProxyTrust};
use super::keys::{KeySet, Metadata};
use super::{IdentityClaims, User};
use anyhow::Context;
use axum::http::{HeaderMap, HeaderName};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::Value;
use std::net::IpAddr;

/// Clock skew allowed on `exp` and `nbf` of tokens checked by the mesh.
const LEEWAY_SECS: i64 = 60;

pub struct Proxy {
    trust: Trust,
    /// Empty: any peer.
    trusted_proxies: Vec<IpNet>,
    sign_out_url: Option<String>,
}

enum Trust {
    Token {
        header: HeaderName,
        keys: KeySet,
        validation: Box<Validation>,
        groups_claim: String,
    },
    Headers {
        user: HeaderName,
        email: HeaderName,
        groups: HeaderName,
    },
    /// Verified by the mesh already; see [`Unverified`].
    Istio {
        header: HeaderName,
        /// `header` holds only the payload, not a whole JWT.
        payload_only: bool,
        claims: Unverified,
        groups_claim: String,
    },
}

/// Checks on a token whose signature someone else verified: that it is
/// well-formed, unexpired, and from the expected issuer for the expected
/// audience, if those are configured. Nothing here stops a forged token;
/// that is the mesh's job.
struct Unverified {
    issuers: Vec<String>,
    audiences: Vec<String>,
}

impl Unverified {
    /// The claims of `raw`, a whole JWT or (`payload_only`) its payload.
    fn claims(&self, raw: &str, payload_only: bool, now: i64) -> Option<Value> {
        let payload = if payload_only {
            raw
        } else {
            // Header, payload, signature; the header must name an algorithm
            // the library knows, which also rules out `none`.
            jsonwebtoken::decode_header(raw).ok()?;
            let mut parts = raw.split('.');
            let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
            if parts.next().is_some() {
                return None;
            }
            payload
        };
        // Istio's payload header is base64url; accept plain base64 as well.
        let payload = payload.trim_end_matches('=');
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| STANDARD_NO_PAD.decode(payload))
            .ok()?;
        let claims: Value = serde_json::from_slice(&bytes).ok()?;

        let exp = claims.get("exp")?.as_i64()?;
        if exp + LEEWAY_SECS <= now {
            return None;
        }
        if let Some(nbf) = claims.get("nbf")
            && nbf.as_i64()? > now + LEEWAY_SECS
        {
            return None;
        }
        if !self.issuers.is_empty() {
            let iss = claims.get("iss")?.as_str()?;
            if !self.issuers.iter().any(|i| i == iss) {
                return None;
            }
        }
        if !self.audiences.is_empty() {
            let accepted = |aud: &str| self.audiences.iter().any(|a| a == aud);
            let matches = match claims.get("aud")? {
                Value::String(aud) => accepted(aud),
                Value::Array(auds) => auds.iter().filter_map(Value::as_str).any(accepted),
                _ => false,
            };
            if !matches {
                return None;
            }
        }
        Some(claims)
    }
}

/// `raw` without a `Bearer ` prefix.
fn strip_bearer(raw: &str) -> &str {
    match raw.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
        _ => raw,
    }
}

fn header_name(name: &str) -> anyhow::Result<HeaderName> {
    HeaderName::try_from(name).with_context(|| format!("invalid header name {name:?}"))
}

impl Proxy {
    pub async fn new(
        config: &ProxyConfig,
        http: reqwest::Client,
        groups_claim: &str,
    ) -> anyhow::Result<Self> {
        let trust = match config.trust {
            ProxyTrust::Token => {
                let issuer = config
                    .issuer
                    .as_deref()
                    .context("[login.proxy] issuer missing")?;
                let (issuer, jwks_url) = match &config.jwks_url {
                    Some(url) => (issuer.to_owned(), url.clone()),
                    None => {
                        let metadata = Metadata::discover(&http, issuer).await?;
                        (metadata.issuer, metadata.jwks_uri)
                    }
                };
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_issuer(&[issuer]);
                validation.set_audience(&config.audiences);
                validation.required_spec_claims =
                    ["exp", "iss", "aud", "sub"].map(String::from).into();
                Trust::Token {
                    header: header_name(&config.token_header)?,
                    keys: KeySet::new(http, jwks_url),
                    validation: Box::new(validation),
                    groups_claim: groups_claim.to_owned(),
                }
            }
            ProxyTrust::Headers => Trust::Headers {
                user: header_name(&config.user_header)?,
                email: header_name(&config.email_header)?,
                groups: header_name(&config.groups_header)?,
            },
            ProxyTrust::Istio => {
                tracing::warn!(
                    "[login.proxy] trust = \"istio\": token signatures are not checked here; \
                     Istio must verify them and require a valid token on every request"
                );
                Trust::Istio {
                    header: header_name(
                        config
                            .payload_header
                            .as_deref()
                            .unwrap_or(&config.token_header),
                    )?,
                    payload_only: config.payload_header.is_some(),
                    claims: Unverified {
                        issuers: config.issuer.iter().cloned().collect(),
                        audiences: config.audiences.clone(),
                    },
                    groups_claim: groups_claim.to_owned(),
                }
            }
        };
        Ok(Self {
            trust,
            trusted_proxies: config.trusted_proxies.clone(),
            sign_out_url: config.sign_out_url.clone(),
        })
    }

    pub fn sign_out_url(&self) -> Option<&str> {
        self.sign_out_url.as_deref()
    }

    /// `peer` is the address the request came from, if known.
    pub async fn authenticate(&self, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<User> {
        if !self.trusted_proxies.is_empty() {
            let trusted =
                peer.is_some_and(|ip| self.trusted_proxies.iter().any(|n| n.contains(&ip)));
            if !trusted {
                tracing::warn!(?peer, "request from outside trusted_proxies");
                return None;
            }
        }
        let value = |name: &HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
        };
        match &self.trust {
            Trust::Token {
                header,
                keys,
                validation,
                groups_claim,
            } => {
                let token = strip_bearer(value(header)?);
                let claims: IdentityClaims = keys
                    .verify(token, validation)
                    .await
                    .inspect_err(|e| tracing::debug!(?e, "rejected forwarded token"))
                    .ok()?;
                Some(claims.into_user(groups_claim))
            }
            Trust::Headers {
                user,
                email,
                groups,
            } => {
                let email = value(email).map(str::to_owned);
                Some(User {
                    subject: value(user).map(str::to_owned).or_else(|| email.clone())?,
                    // The proxy vouches for it, as for the rest.
                    email_verified: email.is_some(),
                    email,
                    name: None,
                    groups: value(groups)
                        .map(|g| {
                            g.split(',')
                                .map(str::trim)
                                .filter(|g| !g.is_empty())
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            }
            Trust::Istio {
                header,
                payload_only,
                claims,
                groups_claim,
            } => {
                let raw = strip_bearer(value(header)?);
                let now = chrono::Utc::now().timestamp();
                let Some(claims) = claims.claims(raw, *payload_only, now) else {
                    tracing::debug!("rejected token passed on by Istio");
                    return None;
                };
                let claims: IdentityClaims = serde_json::from_value(claims).ok()?;
                Some(claims.into_user(groups_claim))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    async fn headers_proxy(trusted: &[&str]) -> Proxy {
        let config = ProxyConfig {
            trust: ProxyTrust::Headers,
            trusted_proxies: trusted.iter().map(|n| n.parse().unwrap()).collect(),
            ..ProxyConfig::default()
        };
        Proxy::new(&config, reqwest::Client::new(), "groups")
            .await
            .unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[tokio::test]
    async fn identity_headers_count_only_from_trusted_peers() {
        let proxy = headers_proxy(&["10.0.0.0/8"]).await;
        let request = headers(&[
            ("x-forwarded-user", "alice"),
            ("x-forwarded-email", "alice@example.org"),
            ("x-forwarded-groups", "security, devs,"),
        ]);

        let user = proxy
            .authenticate(&request, Some("10.1.2.3".parse().unwrap()))
            .await
            .unwrap();
        check!(user.subject == "alice");
        check!(user.email.as_deref() == Some("alice@example.org"));
        check!(user.groups == ["security", "devs"]);

        check!(
            proxy
                .authenticate(&request, Some("192.168.0.1".parse().unwrap()))
                .await
                == None
        );
        check!(
            proxy.authenticate(&request, None).await == None,
            "unknown peer"
        );
    }

    fn encode(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    /// A JWT with a signature nobody checks.
    fn jwt(claims: &Value) -> String {
        let header = encode(&serde_json::json!({ "alg": "RS256", "typ": "JWT" }));
        format!("{header}.{}.bm90LWEtc2lnbmF0dXJl", encode(claims))
    }

    fn claims(exp: i64) -> Value {
        serde_json::json!({ "iss": "https://idp", "aud": ["dash"], "sub": "u1", "exp": exp })
    }

    #[test]
    fn unverified_tokens_still_need_form_and_expiry() {
        let open = Unverified {
            issuers: Vec::new(),
            audiences: Vec::new(),
        };
        let now = 1_000_000;
        check!(open.claims(&jwt(&claims(now + 300)), false, now).is_some());
        check!(
            open.claims(&encode(&claims(now + 300)), true, now)
                .is_some()
        );
        check!(
            open.claims(&jwt(&claims(now - 300)), false, now).is_none(),
            "expired"
        );
        check!(
            open.claims(&jwt(&serde_json::json!({ "sub": "u1" })), false, now)
                .is_none(),
            "no exp"
        );

        let mut early = claims(now + 300);
        early["nbf"] = (now + 600).into();
        check!(
            open.claims(&jwt(&early), false, now).is_none(),
            "not yet valid"
        );

        let none_alg = format!(
            "{}.{}.",
            encode(&serde_json::json!({ "alg": "none" })),
            encode(&claims(now + 300))
        );
        for garbage in [
            "not-a-token",
            "a.b.c",
            none_alg.as_str(),
            &format!("{}.extra", jwt(&claims(now + 300))),
        ] {
            check!(open.claims(garbage, false, now).is_none(), "{garbage}");
        }
        check!(open.claims("%%%", true, now).is_none());
    }

    #[test]
    fn unverified_tokens_match_issuer_and_audience_if_configured() {
        let strict = Unverified {
            issuers: vec!["https://idp".into()],
            audiences: vec!["dash".into()],
        };
        let now = 1_000_000;
        check!(
            strict
                .claims(&jwt(&claims(now + 300)), false, now)
                .is_some()
        );

        let mut other_issuer = claims(now + 300);
        other_issuer["iss"] = "https://elsewhere".into();
        check!(strict.claims(&jwt(&other_issuer), false, now).is_none());

        let mut other_audience = claims(now + 300);
        other_audience["aud"] = "someone-else".into();
        check!(strict.claims(&jwt(&other_audience), false, now).is_none());
    }

    #[tokio::test]
    async fn istio_reads_whole_tokens_or_payload_headers() {
        let exp = chrono::Utc::now().timestamp() + 300;
        let config = ProxyConfig {
            trust: ProxyTrust::Istio,
            ..ProxyConfig::default()
        };
        let proxy = Proxy::new(&config, reqwest::Client::new(), "groups")
            .await
            .unwrap();
        let bearer = format!("Bearer {}", jwt(&claims(exp)));
        let user = proxy
            .authenticate(&headers(&[("authorization", &bearer)]), None)
            .await
            .unwrap();
        check!(user.subject == "u1");

        let config = ProxyConfig {
            trust: ProxyTrust::Istio,
            payload_header: Some("x-jwt-payload".into()),
            ..ProxyConfig::default()
        };
        let proxy = Proxy::new(&config, reqwest::Client::new(), "groups")
            .await
            .unwrap();
        let payload = encode(&claims(exp));
        check!(
            proxy
                .authenticate(&headers(&[("x-jwt-payload", &payload)]), None)
                .await
                .is_some()
        );
        check!(
            proxy
                .authenticate(&headers(&[("authorization", &bearer)]), None)
                .await
                .is_none(),
            "only the payload header counts"
        );
    }

    #[tokio::test]
    async fn identity_headers_need_a_user_or_email() {
        let proxy = headers_proxy(&["127.0.0.1/32"]).await;
        let peer = Some("127.0.0.1".parse().unwrap());
        check!(proxy.authenticate(&HeaderMap::new(), peer).await == None);
        let by_email = proxy
            .authenticate(&headers(&[("x-forwarded-email", "bob@example.org")]), peer)
            .await
            .unwrap();
        check!(by_email.subject == "bob@example.org");
    }
}
