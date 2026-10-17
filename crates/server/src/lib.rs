//! Dashboard server: collector scheduler, JSON API and embedded UI.

pub mod api;
pub mod config;
pub mod guard;
pub mod insights;
pub mod realtime;
pub mod scheduler;
mod ui;

use axum::Router;
use axum::middleware::from_fn_with_state;
use tower_http::trace::TraceLayer;

pub fn app(state: api::AppState, allowed_hosts: guard::AllowedHosts) -> Router {
    api::router(state)
        .fallback(ui::serve)
        .layer(from_fn_with_state(allowed_hosts, guard::check))
        .layer(TraceLayer::new_for_http())
}
