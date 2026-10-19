//! Sign-in by an authenticating proxy in front of the server.

use super::config::{ProxyConfig, ProxyTrust};
use super::keys::{KeySet, Metadata};
use super::{IdentityClaims, User};
use anyhow::Context;
use axum::http::{HeaderMap, HeaderName};
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, Validation};
use std::net::IpAddr;

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
                let raw = value(header)?;
                let token = match raw.split_once(' ') {
                    Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
                    _ => raw,
                };
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
