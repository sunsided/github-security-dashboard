//! Persistence for the GitHub security dashboard.
//!
//! The application only talks to the [`Store`] trait. Backends are selected by
//! URL scheme at runtime and compiled in via cargo features.

mod api;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use std::sync::Arc;

pub use api::*;

/// Opens the backend matching `url` and applies pending migrations.
///
/// Supported schemes: `sqlite:` (feature `sqlite`).
pub async fn connect(url: &str) -> Result<Arc<dyn Store>> {
    #[cfg(feature = "sqlite")]
    if url.starts_with("sqlite:") {
        return Ok(Arc::new(sqlite::SqliteStore::connect(url).await?));
    }

    Err(StoreError::UnsupportedUrl(redact(url)))
}

/// Strips credentials from a connection URL before it ends up in an error.
fn redact(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}://***{}", &url[..scheme_end], &url[at..])
        }
        _ => url.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_hides_credentials() {
        assert_eq!(
            redact("postgres://user:secret@db:5432/x"),
            "postgres://***@db:5432/x"
        );
        assert_eq!(redact("mysql://db/x"), "mysql://db/x");
    }
}
