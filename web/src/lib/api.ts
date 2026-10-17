// Types mirror the JSON produced by crates/server/src/api.rs.

export type RepoKind = 'org' | 'user' | 'external';
export type RunStatus = 'running' | 'succeeded' | 'partial' | 'failed';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AlertSource = 'dependabot' | 'code_scanning' | 'secret_scanning' | 'osv';
export type AlertState = 'open' | 'fixed' | 'dismissed' | 'gone';
export type EventKind = 'opened' | 'reopened' | 'severity_changed' | 'fixed' | 'dismissed' | 'gone';
export type SourceStatus = 'ok' | 'unavailable' | 'skipped' | 'error';

/** Most severe first. */
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export const SOURCE_LABELS: Record<AlertSource, string> = {
	dependabot: 'Dependabot',
	code_scanning: 'Code scanning',
	secret_scanning: 'Secret scanning',
	osv: 'OSV estimate'
};

/** Alert numbers are GitHub's own, except for OSV estimates (internal keys). */
export const hasAlertNumber = (source: AlertSource) => source !== 'osv';

export type SeverityCounts = Record<Severity, number>;

export interface Snapshot {
	run_id: number;
	taken_at: string;
	open_issues: number;
	open_prs: number;
	contributors: number | null;
	commits: number | null;
	tags: number;
	releases: number;
	stars: number;
	forks: number;
	pushed_at: string | null;
	last_commit_at: string | null;
}

export interface Repo {
	id: number;
	owner: string;
	name: string;
	kind: RepoKind;
	url: string;
	description: string | null;
	archived: boolean;
	fork: boolean;
	private: boolean;
	language: string | null;
	default_branch: string | null;
	last_seen_run: number;
	latest: Snapshot | null;
	open_alerts: SeverityCounts;
	days_since_commit: number | null;
	stale: boolean;
	risk_score: number;
	/** Seen in the latest finished run; otherwise the data is as of `last_seen_run`. */
	refreshed: boolean;
}

export interface Alert {
	id: number;
	repo_id: number;
	source: AlertSource;
	number: number;
	state: AlertState;
	severity: Severity;
	title: string;
	location: string | null;
	html_url: string;
	created_at: string;
	closed_at: string | null;
	estimated: boolean;
	first_seen_run: number;
	last_seen_run: number;
}

export interface AlertEvent {
	id: number;
	alert_id: number;
	run_id: number;
	at: string;
	kind: EventKind;
	old: string | null;
	new: string | null;
	/** Alert already existed when its source was first collected. */
	baseline: boolean;
	owner: string;
	repo: string;
	source: AlertSource;
	number: number;
	title: string;
}

export interface RepoSource {
	source: AlertSource;
	status: SourceStatus;
	message: string | null;
	checked_at: string;
	first_collected_run: number | null;
}

export interface RepoDetail extends Repo {
	history: Snapshot[];
	alerts: Alert[];
	sources: RepoSource[];
	events: AlertEvent[];
}

export interface Run {
	id: number;
	started_at: string;
	finished_at: string | null;
	status: RunStatus;
	rate_limit_remaining: number | null;
	errors: string[];
}

export interface RateLimit {
	limit: number;
	remaining: number;
	reset: string;
}

export interface Summary {
	repos: number;
	stale_repos: number;
	open_issues: number;
	open_prs: number;
	stale_after_days: number;
	open_alerts: SeverityCounts;
	repos_with_alerts: number;
	/** Repositories missing from the latest run, left out of the totals. */
	not_refreshed: number;
	/** How the server authenticates, e.g. "GitHub App". */
	auth: string;
	collecting: boolean;
	last_run: Run | null;
	rate_limits: Record<string, RateLimit>;
}

type Fetch = typeof fetch;

async function getJson<T>(fetch: Fetch, path: string): Promise<T> {
	const response = await fetch(path, { headers: { accept: 'application/json' } });
	if (!response.ok) {
		throw new Error(`${path}: ${response.status} ${response.statusText}`);
	}
	return response.json() as Promise<T>;
}

export const getSummary = (fetch: Fetch) => getJson<Summary>(fetch, '/api/summary');

export const getRepos = (fetch: Fetch) =>
	getJson<Repo[]>(fetch, '/api/repos?include_archived=true');

/** `null` if the repository is not tracked. */
export async function getRepo(
	fetch: Fetch,
	owner: string,
	name: string
): Promise<RepoDetail | null> {
	const path = `/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
	const response = await fetch(path, { headers: { accept: 'application/json' } });
	if (response.status === 404) return null;
	if (!response.ok) {
		throw new Error(`${path}: ${response.status} ${response.statusText}`);
	}
	return response.json() as Promise<RepoDetail>;
}

export const getEvents = (fetch: Fetch, limit = 200, includeBaseline = false) =>
	getJson<AlertEvent[]>(
		fetch,
		`/api/events?limit=${limit}${includeBaseline ? '&include_baseline=true' : ''}`
	);

export const getRuns = (fetch: Fetch, limit = 50) =>
	getJson<Run[]>(fetch, `/api/runs?limit=${limit}`);

/** Asks the server for a collector run as soon as possible. */
export async function requestRefresh(): Promise<void> {
	const response = await fetch('/api/refresh', {
		method: 'POST',
		// Required by the server's CSRF guard (see crates/server/src/guard.rs).
		headers: { 'x-dashboard-request': '1' }
	});
	if (!response.ok) {
		throw new Error(`refresh: ${response.status} ${response.statusText}`);
	}
}
