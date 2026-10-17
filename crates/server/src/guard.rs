//! Request guards for an API without authentication.
//!
//! Binding to loopback alone does not keep browsers out: a page on another
//! site can rebind its DNS name to 127.0.0.1 and read the API (DNS
//! rebinding), or fire cross-site POSTs at it (CSRF).

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Header required on state-changing requests. Browsers only send custom
/// headers cross-site after a CORS preflight, which this server never grants.
pub const CSRF_HEADER: &str = "x-dashboard-request";

/// Hostnames (without port) the server answers to.
#[derive(Debug, Clone)]
pub struct AllowedHosts(Arc<[String]>);

impl AllowedHosts {
    /// Loopback names plus `extra`, compared case-insensitively.
    pub fn new(extra: &[String]) -> Self {
        let hosts = ["localhost", "127.0.0.1", "[::1]"]
            .into_iter()
            .map(str::to_owned)
            .chain(extra.iter().map(|h| h.to_ascii_lowercase()))
            .collect();
        Self(hosts)
    }

    fn allows(&self, headers: &HeaderMap) -> bool {
        let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
            return false;
        };
        self.allows_host(host)
    }

    /// `host` as in a Host header or an origin: a name, optionally with port.
    pub fn allows_host(&self, host: &str) -> bool {
        let name = strip_port(host).to_ascii_lowercase();
        self.0.contains(&name)
    }
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // [::1]:8080
        return host.find(']').map_or(host, |end| &host[..=end]);
    }
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

pub async fn check(State(allowed): State<AllowedHosts>, request: Request, next: Next) -> Response {
    if !allowed.allows(request.headers()) {
        tracing::warn!(host = ?request.headers().get(header::HOST), "rejected request for unknown host");
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if !safe && !request.headers().contains_key(CSRF_HEADER) {
        return (StatusCode::FORBIDDEN, "missing request header").into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use axum::http::HeaderValue;

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn allows_loopback_and_configured_hosts() {
        let allowed = AllowedHosts::new(&["Dashboard.Internal".into()]);
        for ok in [
            "localhost:8080",
            "127.0.0.1",
            "[::1]:8080",
            "dashboard.internal:443",
        ] {
            check!(allowed.allows(&host(ok)), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:8080",
            "localhost.evil.example",
            "[::2]",
        ] {
            check!(!allowed.allows(&host(bad)), "{bad}");
        }
        check!(!allowed.allows(&HeaderMap::new()), "missing Host");
    }
}
