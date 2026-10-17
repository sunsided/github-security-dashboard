<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { requestRefresh, type Repo, type RepoKind } from '#lib/api.js';
	import ActivityBadge from '#lib/components/ActivityBadge.svelte';
	import StatTile from '#lib/components/StatTile.svelte';
	import { activity, formatCount, formatDateTime } from '#lib/format.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	type SortKey =
		| 'name'
		| 'open_issues'
		| 'open_prs'
		| 'contributors'
		| 'commits'
		| 'tags'
		| 'releases'
		| 'days_since_commit';

	const columns: { key: SortKey; label: string; numeric: boolean }[] = [
		{ key: 'name', label: 'Repository', numeric: false },
		{ key: 'open_issues', label: 'Issues', numeric: true },
		{ key: 'open_prs', label: 'PRs', numeric: true },
		{ key: 'contributors', label: 'Contributors', numeric: true },
		{ key: 'commits', label: 'Commits', numeric: true },
		{ key: 'tags', label: 'Tags', numeric: true },
		{ key: 'releases', label: 'Releases', numeric: true },
		{ key: 'days_since_commit', label: 'Last commit', numeric: true }
	];

	let sortKey = $state<SortKey>('open_issues');
	let descending = $state(true);
	let search = $state('');
	let owner = $state('');
	let kind = $state<RepoKind | ''>('');
	let showArchived = $state(false);
	let refreshing = $state(false);
	let refreshError = $state<string | null>(null);

	const owners = $derived([...new Set(data.repos.map((r) => r.owner))].sort());

	function sortValue(repo: Repo, key: SortKey): number | string | null {
		switch (key) {
			case 'name':
				return `${repo.owner}/${repo.name}`.toLowerCase();
			case 'days_since_commit':
				return repo.days_since_commit;
			default:
				return repo.latest?.[key] ?? null;
		}
	}

	const visible = $derived.by(() => {
		const needle = search.trim().toLowerCase();
		const rows = data.repos.filter(
			(r) =>
				(showArchived || !r.archived) &&
				(!owner || r.owner === owner) &&
				(!kind || r.kind === kind) &&
				(!needle || `${r.owner}/${r.name}`.toLowerCase().includes(needle))
		);
		const direction = descending ? -1 : 1;
		return rows.sort((a, b) => {
			const x = sortValue(a, sortKey);
			const y = sortValue(b, sortKey);
			// Missing values sort last in either direction.
			if (x === y) return 0;
			if (x === null) return 1;
			if (y === null) return -1;
			return (x < y ? -1 : 1) * direction;
		});
	});

	function sortBy(key: SortKey) {
		if (sortKey === key) {
			descending = !descending;
		} else {
			sortKey = key;
			descending = key !== 'name';
		}
	}

	async function refresh() {
		refreshing = true;
		refreshError = null;
		try {
			await requestRefresh();
			// Poll until the server reports the run as finished.
			do {
				await new Promise((resolve) => setTimeout(resolve, 2500));
				await invalidateAll();
			} while (data.summary.collecting);
		} catch (e) {
			refreshError = e instanceof Error ? e.message : String(e);
		} finally {
			refreshing = false;
		}
	}

	const lastRun = $derived(data.summary.last_run);
	const graphql = $derived(data.summary.rate_limits['graphql']);
</script>

<section class="heading">
	<div>
		<h1>Repositories</h1>
		<p class="meta">
			{#if lastRun}
				Last run {formatDateTime(lastRun.finished_at ?? lastRun.started_at)} ·
				<a href={resolve('/runs')}>{lastRun.status}</a>
				{#if lastRun.errors.length > 0}
					with {lastRun.errors.length} error{lastRun.errors.length === 1 ? '' : 's'}
				{/if}
			{:else}
				No collector run yet.
			{/if}
		</p>
	</div>
	<div class="actions">
		{#if refreshError}
			<span class="error" role="alert">{refreshError}</span>
		{/if}
		<button onclick={refresh} disabled={refreshing || data.summary.collecting}>
			{refreshing || data.summary.collecting ? 'Collecting…' : 'Refresh now'}
		</button>
	</div>
</section>

<section class="tiles" aria-label="Summary">
	<StatTile label="Tracked repositories" value={formatCount(data.summary.repos)} />
	<StatTile label="Open issues" value={formatCount(data.summary.open_issues)} />
	<StatTile label="Open pull requests" value={formatCount(data.summary.open_prs)} />
	<StatTile
		label="Stale repositories"
		value={formatCount(data.summary.stale_repos)}
		hint="no commit for {data.summary.stale_after_days} days"
	/>
	{#if graphql}
		<StatTile
			label="GraphQL quota left"
			value={formatCount(graphql.remaining)}
			hint="of {formatCount(graphql.limit)}, resets {formatDateTime(graphql.reset)}"
		/>
	{/if}
</section>

<section class="filters" aria-label="Filters">
	<input
		type="search"
		placeholder="Filter by name"
		bind:value={search}
		aria-label="Filter by name"
	/>
	<select bind:value={owner} aria-label="Owner">
		<option value="">All owners</option>
		{#each owners as name (name)}
			<option value={name}>{name}</option>
		{/each}
	</select>
	<select bind:value={kind} aria-label="Kind">
		<option value="">All kinds</option>
		<option value="org">Organization</option>
		<option value="user">User</option>
		<option value="external">External</option>
	</select>
	<label>
		<input type="checkbox" bind:checked={showArchived} />
		Show archived
	</label>
	<span class="count">{visible.length} of {data.repos.length}</span>
</section>

<div class="table-wrap">
	<table>
		<thead>
			<tr>
				{#each columns as column (column.key)}
					<th
						class:numeric={column.numeric}
						aria-sort={sortKey === column.key
							? descending
								? 'descending'
								: 'ascending'
							: undefined}
					>
						<button onclick={() => sortBy(column.key)}>
							{column.label}
							<span class="arrow" aria-hidden="true">
								{sortKey === column.key ? (descending ? '↓' : '↑') : ''}
							</span>
						</button>
					</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#each visible as repo (repo.id)}
				<tr class:archived={repo.archived}>
					<td>
						<!-- External link to GitHub, not an app route. -->
						<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
						<a href={repo.url} target="_blank" rel="noreferrer">
							<span class="owner">{repo.owner}/</span>{repo.name}
						</a>
						<span class="tags">
							{#if repo.kind === 'external'}<span class="tag">external</span>{/if}
							{#if repo.archived}<span class="tag">archived</span>{/if}
							{#if repo.fork}<span class="tag">fork</span>{/if}
							{#if repo.private}<span class="tag">private</span>{/if}
						</span>
					</td>
					<td class="numeric tabular">{formatCount(repo.latest?.open_issues)}</td>
					<td class="numeric tabular">{formatCount(repo.latest?.open_prs)}</td>
					<td class="numeric tabular">{formatCount(repo.latest?.contributors)}</td>
					<td class="numeric tabular">{formatCount(repo.latest?.commits)}</td>
					<td class="numeric tabular">{formatCount(repo.latest?.tags)}</td>
					<td class="numeric tabular">{formatCount(repo.latest?.releases)}</td>
					<td class="numeric">
						<ActivityBadge
							activity={activity(repo.days_since_commit, data.summary.stale_after_days)}
							days={repo.days_since_commit}
						/>
					</td>
				</tr>
			{:else}
				<tr>
					<td class="empty" colspan={columns.length}>
						{data.repos.length === 0
							? 'Nothing collected yet. Check the runs page if this persists.'
							: 'No repository matches the filters.'}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<style>
	.heading {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		gap: 1rem;
		flex-wrap: wrap;
	}

	h1 {
		margin: 0;
		font-size: 1.4rem;
	}

	.meta {
		margin: 0.25rem 0 0;
		color: var(--ink-secondary);
	}

	.actions {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.error {
		color: var(--critical);
	}

	.actions button {
		padding: 0.45rem 0.9rem;
		border: 1px solid var(--accent);
		border-radius: var(--radius);
		background: var(--accent);
		color: var(--surface-raised);
		cursor: pointer;
	}

	.actions button:disabled {
		opacity: 0.6;
		cursor: progress;
	}

	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
		gap: 0.75rem;
		margin: 1.25rem 0;
	}

	.filters {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.6rem;
		margin-bottom: 0.75rem;
	}

	.filters input[type='search'],
	.filters select {
		padding: 0.4rem 0.55rem;
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface-raised);
		color: var(--ink);
		font: inherit;
	}

	.filters label {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		color: var(--ink-secondary);
	}

	.count {
		margin-left: auto;
		color: var(--ink-muted);
		font-size: 0.85rem;
	}

	.table-wrap {
		overflow-x: auto;
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface-raised);
	}

	table {
		width: 100%;
		border-collapse: collapse;
	}

	th,
	td {
		padding: 0.5rem 0.75rem;
		text-align: left;
		border-bottom: 1px solid var(--border);
	}

	tbody tr:last-child td {
		border-bottom: none;
	}

	tbody tr:hover {
		background: var(--surface-sunken);
	}

	th {
		position: sticky;
		top: 0;
		background: var(--surface-raised);
		font-weight: 500;
		white-space: nowrap;
	}

	th button {
		all: unset;
		cursor: pointer;
		color: var(--ink-secondary);
		font-size: 0.85rem;
	}

	th button:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	th[aria-sort] button {
		color: var(--ink);
	}

	.arrow {
		display: inline-block;
		width: 0.8em;
	}

	.numeric {
		text-align: right;
	}

	td a {
		color: var(--ink);
		text-decoration: none;
	}

	td a:hover {
		text-decoration: underline;
	}

	.owner {
		color: var(--ink-muted);
	}

	.tags {
		margin-left: 0.4rem;
	}

	.tag {
		display: inline-block;
		margin-right: 0.25rem;
		padding: 0 0.35rem;
		border: 1px solid var(--border);
		border-radius: 3px;
		color: var(--ink-muted);
		font-size: 0.75rem;
	}

	.archived td {
		color: var(--ink-muted);
	}

	.empty {
		text-align: center;
		color: var(--ink-muted);
		padding: 2rem;
	}
</style>
