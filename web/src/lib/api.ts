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

/**
 * Sends the browser to sign in when the server says nobody is (any more).
 * Only with `[login] mode = "oidc"`; behind a proxy, the proxy does that.
 */
export async function signInIfNeeded(response: Response): Promise<void> {
	if (response.status !== 401) return;
	const body = (await response
		.clone()
		.json()
		.catch(() => null)) as { login?: string | null } | null;
	if (body?.login) {
		const target = location.pathname + location.search;
		location.assign(`${body.login}?return_to=${encodeURIComponent(target)}`);
	}
}

async function get(fetch: Fetch, path: string): Promise<Response> {
	const response = await fetch(path, { headers: { accept: 'application/json' } });
	await signInIfNeeded(response);
	return response;
}

async function getJson<T>(fetch: Fetch, path: string): Promise<T> {
	const response = await get(fetch, path);
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
	const response = await get(fetch, path);
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

export interface Delivery {
	id: number;
	target: string;
	attempted_at: string;
	first_event_id: number;
	last_event_id: number;
	/** 0 for a day without news (recorded, nothing sent). */
	events: number;
	succeeded: boolean;
	error: string | null;
}

/** Recent digest deliveries; `null` while the digest is disabled. */
export async function getDeliveries(fetch: Fetch): Promise<Delivery[] | null> {
	const response = await get(fetch, '/api/digest/deliveries');
	if (response.status === 404) return null;
	if (!response.ok) {
		throw new Error(`/api/digest/deliveries: ${response.status} ${response.statusText}`);
	}
	return response.json() as Promise<Delivery[]>;
}

export interface Bucket {
	key: string;
	counts: SeverityCounts;
	total: number;
	repo_ids: number[];
}

export interface IssueRepository {
	id: number;
	owner: string;
	name: string;
	alerts: { source: AlertSource; number: number; url: string; estimated: boolean }[];
}

export interface Issue {
	ids: string[];
	title: string;
	severity: Severity;
	sources: AlertSource[];
	estimated_only: boolean;
	repositories: IssueRepository[];
}

export interface Insights {
	by_source: Bucket[];
	by_ecosystem: Bucket[];
	by_owner: Bucket[];
	by_age: Bucket[];
	widespread: Issue[];
}

export const getInsights = (fetch: Fetch) => getJson<Insights>(fetch, '/api/insights');

/** Asks the server for a collector run as soon as possible. */
export async function requestRefresh(): Promise<void> {
	const response = await fetch('/api/refresh', {
		method: 'POST',
		// Required by the server's CSRF guard (see crates/server/src/guard.rs).
		headers: { 'x-dashboard-request': '1' }
	});
	await signInIfNeeded(response);
	if (!response.ok) {
		throw new Error(`refresh: ${response.status} ${response.statusText}`);
	}
}

// Mirrors crates/server/src/login/mod.rs.

export type LoginMode = 'none' | 'proxy' | 'oidc';

export interface User {
	subject: string;
	email: string | null;
	/** Only verified addresses count for the server's allow-list. */
	email_verified: boolean;
	name: string | null;
	groups?: string[];
}

export interface Me {
	mode: LoginMode;
	/** `null` without sign-in. */
	user: User | null;
	/** The proxy's sign-out endpoint, if configured. */
	sign_out_url: string | null;
}

export const getMe = (fetch: Fetch) => getJson<Me>(fetch, '/api/me');

/** Whether `signOut` can do anything for this kind of sign-in. */
export const canSignOut = (me: Me) => me.mode === 'oidc' || me.sign_out_url !== null;

export async function signOut(me: Me): Promise<void> {
	if (me.mode !== 'oidc') {
		if (me.sign_out_url) location.assign(me.sign_out_url);
		return;
	}
	const response = await fetch('/auth/logout', {
		method: 'POST',
		headers: { 'x-dashboard-request': '1' }
	});
	if (!response.ok) {
		throw new Error(`sign out: ${response.status} ${response.statusText}`);
	}
	const body = (await response.json()) as { redirect: string };
	location.assign(body.redirect);
}
