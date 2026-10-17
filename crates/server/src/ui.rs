//! Serves the SvelteKit build from `web/build`.
//!
//! Release builds embed the files; debug builds read them from disk, so a
//! `yarn build` shows up without recompiling the server.

use axum::http::{StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/build"]
#[allow_missing = true]
struct Assets;

const NOT_BUILT: &str = "<!doctype html><title>UI not built</title>\
<p>The web UI has not been built. Run <code>task web:build</code>, \
or use <code>task dev</code> for the Vite dev server.</p>";

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if let Some(file) = (!path.is_empty()).then(|| Assets::get(path)).flatten() {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        // SvelteKit fingerprints everything under _app/immutable.
        let cache = if path.starts_with("_app/immutable/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                (header::CACHE_CONTROL, cache),
            ],
            file.data,
        )
            .into_response();
    }

    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Client-side routing: unknown paths get the SPA shell.
    match Assets::get("200.html") {
        Some(index) => ([(header::CACHE_CONTROL, "no-cache")], Html(index.data)).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, Html(NOT_BUILT)).into_response(),
    }
}
