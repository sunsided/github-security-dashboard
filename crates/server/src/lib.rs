//! Dashboard server: collector scheduler, JSON API and embedded UI.

pub mod api;
pub mod config;
pub mod scheduler;
mod ui;

use axum::Router;
use tower_http::trace::TraceLayer;

pub fn app(state: api::AppState) -> Router {
    api::router(state)
        .fallback(ui::serve)
        .layer(TraceLayer::new_for_http())
}
