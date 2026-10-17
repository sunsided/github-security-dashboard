// Types mirror the JSON produced by crates/server/src/api.rs.

export type RepoKind = 'org' | 'user' | 'external';
export type RunStatus = 'running' | 'succeeded' | 'partial' | 'failed';

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
	days_since_commit: number | null;
	stale: boolean;
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
