//! Dashboard server: collector scheduler, JSON API and embedded UI.

pub mod api;
pub mod config;
pub mod guard;
pub mod insights;
pub mod login;
pub mod realtime;
pub mod scheduler;
mod ui;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

pub fn app(
    state: api::AppState,
    allowed_hosts: guard::AllowedHosts,
    login: Arc<login::Login>,
) -> Router {
    api::router(state)
        .merge(login.router())
        .route(guard::HEALTH_PATH, get(|| async { "ok" }))
        .fallback(ui::serve)
        .layer(from_fn_with_state(login, login::require))
        .layer(from_fn_with_state(allowed_hosts, guard::check))
        .layer(TraceLayer::new_for_http())
}
