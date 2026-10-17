//! JSON API under `/api`.

use crate::config::Scoring;
use crate::scheduler::Scheduler;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use gh::{GitHub, RateLimit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use store::{
    Alert, AlertEvent, AlertFilter, EventFilter, RepoFilter, RepoKind, RepoOverview, RepoSource,
    Run, SeverityCounts, Snapshot, Store,
};

/// Repositories without a commit for this long count as stale.
const STALE_AFTER_DAYS: i64 = 180;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub github: Arc<GitHub>,
    pub scheduler: Arc<Scheduler>,
    pub scoring: Scoring,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/summary", get(summary))
        .route("/api/repos", get(list_repos))
        .route("/api/repos/{owner}/{name}", get(get_repo))
        .route("/api/runs", get(list_runs))
        .route("/api/events", get(list_events))
        .route("/api/refresh", post(refresh))
        .with_state(state)
}

struct ApiError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self.0, "request failed");
        let body = Json(serde_json::json!({ "error": "internal error" }));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Serialize)]
struct RepoView {
    #[serde(flatten)]
    repo: RepoOverview,
    /// Whole days since the last commit on the default branch.
    days_since_commit: Option<i64>,
    stale: bool,
    /// Weighted sum of open alerts; see [`Scoring`].
    risk_score: i64,
}

impl RepoView {
    fn new(repo: RepoOverview, now: DateTime<Utc>, scoring: &Scoring) -> Self {
        let days_since_commit = repo
            .latest
            .as_ref()
            .and_then(|s| s.stats.last_commit_at)
            .map(|t| (now - t).num_days());
        Self {
            stale: days_since_commit.is_some_and(|d| d >= STALE_AFTER_DAYS),
            days_since_commit,
            risk_score: scoring.score(&repo.open_alerts),
            repo,
        }
    }
}

#[derive(Deserialize)]
struct RepoQuery {
    owner: Option<String>,
    kind: Option<RepoKind>,
    #[serde(default)]
    include_archived: bool,
}

async fn list_repos(
    State(state): State<AppState>,
    Query(query): Query<RepoQuery>,
) -> ApiResult<Vec<RepoView>> {
    let filter = RepoFilter {
        owner: query.owner,
        kind: query.kind,
        include_archived: query.include_archived,
    };
    let now = Utc::now();
    let repos = state.store.list_repos(&filter).await?;
    Ok(Json(
        repos
            .into_iter()
            .map(|r| RepoView::new(r, now, &state.scoring))
            .collect(),
    ))
}

#[derive(Serialize)]
struct RepoDetail {
    #[serde(flatten)]
    repo: RepoView,
    history: Vec<Snapshot>,
    /// Open alerts first, then closed ones, most severe first.
    alerts: Vec<Alert>,
    sources: Vec<RepoSource>,
    events: Vec<AlertEvent>,
}

async fn get_repo(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let Some(repo) = state.store.get_repo(&owner, &name).await? else {
        let body = Json(serde_json::json!({ "error": "repository not tracked" }));
        return Ok((StatusCode::NOT_FOUND, body).into_response());
    };
    let history = state.store.snapshot_history(repo.id, 90).await?;
    let alerts = state
        .store
        .list_alerts(repo.id, &AlertFilter::default())
        .await?;
    let sources = state.store.source_statuses(repo.id).await?;
    let events = state
        .store
        .alert_events(&EventFilter {
            repo: Some(repo.id),
            since: None,
            limit: 100,
        })
        .await?;
    let detail = RepoDetail {
        repo: RepoView::new(repo, Utc::now(), &state.scoring),
        history,
        alerts,
        sources,
        events,
    };
    Ok(Json(detail).into_response())
}

#[derive(Deserialize)]
struct RunsQuery {
    #[serde(default = "default_runs_limit")]
    limit: u32,
}

fn default_runs_limit() -> u32 {
    20
}

async fn list_runs(
    State(state): State<AppState>,
    Query(query): Query<RunsQuery>,
) -> ApiResult<Vec<Run>> {
    Ok(Json(state.store.list_runs(query.limit.min(200)).await?))
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<DateTime<Utc>>,
    #[serde(default = "default_events_limit")]
    limit: u32,
}

fn default_events_limit() -> u32 {
    100
}

/// Alert changes across all repositories, most recent first.
async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Vec<AlertEvent>> {
    let filter = EventFilter {
        repo: None,
        since: query.since,
        limit: query.limit.min(1000),
    };
    Ok(Json(state.store.alert_events(&filter).await?))
}

#[derive(Serialize)]
struct Summary {
    repos: usize,
    stale_repos: usize,
    open_issues: i64,
    open_prs: i64,
    stale_after_days: i64,
    open_alerts: SeverityCounts,
    repos_with_alerts: usize,
    collecting: bool,
    last_run: Option<Run>,
    rate_limits: HashMap<String, RateLimit>,
}

async fn summary(State(state): State<AppState>) -> ApiResult<Summary> {
    let now = Utc::now();
    let repos: Vec<RepoView> = state
        .store
        .list_repos(&RepoFilter::default())
        .await?
        .into_iter()
        .map(|r| RepoView::new(r, now, &state.scoring))
        .collect();
    let mut open_alerts = SeverityCounts::default();
    for r in &repos {
        let c = r.repo.open_alerts;
        open_alerts.critical += c.critical;
        open_alerts.high += c.high;
        open_alerts.medium += c.medium;
        open_alerts.low += c.low;
    }
    let latest = || repos.iter().filter_map(|r| r.repo.latest.as_ref());

    Ok(Json(Summary {
        repos: repos.len(),
        stale_repos: repos.iter().filter(|r| r.stale).count(),
        open_issues: latest().map(|s| s.stats.open_issues).sum(),
        open_prs: latest().map(|s| s.stats.open_prs).sum(),
        stale_after_days: STALE_AFTER_DAYS,
        open_alerts,
        repos_with_alerts: repos
            .iter()
            .filter(|r| r.repo.open_alerts.total() > 0)
            .count(),
        collecting: state.scheduler.is_running(),
        last_run: state.store.list_runs(1).await?.into_iter().next(),
        rate_limits: state.github.rate_limits(),
    }))
}

async fn refresh(State(state): State<AppState>) -> impl IntoResponse {
    state.scheduler.request_run();
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "requested": true })),
    )
}
