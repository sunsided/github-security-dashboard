<script lang="ts">
	import { resolve } from '$app/paths';
	import {
		SEVERITIES,
		SOURCE_LABELS,
		hasAlertNumber,
		type AlertSource,
		type RepoSource,
		type SourceStatus
	} from '#lib/api.js';
	import EventList from '#lib/components/EventList.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import StatTile from '#lib/components/StatTile.svelte';
	import { formatAge, formatCount, formatDate, formatDateTime } from '#lib/format.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let showClosed = $state(false);

	const repo = $derived(data.repo);
	const alerts = $derived(repo ? repo.alerts.filter((a) => showClosed || a.state === 'open') : []);
	const openCount = $derived(repo ? repo.alerts.filter((a) => a.state === 'open').length : 0);
	const closedCount = $derived(repo ? repo.alerts.length - openCount : 0);

	// Archived repositories are skipped by the collector unless configured
	// otherwise (collector.alerts.skip_archived).
	const alertsFrozen = $derived(
		repo?.sources.some((s) => s.status === 'skipped' && s.message === 'archived') ?? false
	);

	const sourceOrder: AlertSource[] = ['dependabot', 'code_scanning', 'secret_scanning', 'osv'];
	const sources = $derived(
		sourceOrder
			.map((source) => ({
				source,
				status: repo?.sources.find((s) => s.source === source) as RepoSource | undefined
			}))
			// Estimates only run for some repositories; don't list them as pending elsewhere.
			.filter(({ source, status }) => source !== 'osv' || status)
	);

	const statusText: Record<SourceStatus, string> = {
		ok: 'collected',
		unavailable: 'not available',
		skipped: 'skipped',
		error: 'failed'
	};
	const statusGlyph: Record<SourceStatus, string> = {
		ok: '✓',
		unavailable: '–',
		skipped: '–',
		error: '✕'
	};
</script>

<svelte:head>
	<title>{data.owner}/{data.name} · Security dashboard</title>
</svelte:head>

<p class="back"><a href={resolve('/')}>← Repositories</a></p>

{#if !repo}
	<h1>{data.owner}/{data.name}</h1>
	<p class="muted">This repository is not tracked.</p>
{:else}
	<header class="repo-head">
		<h1>
			<span class="owner">{repo.owner}/</span>{repo.name}
		</h1>
		<!-- External link to GitHub, not an app route. -->
		<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
		<a href={repo.url} target="_blank" rel="noreferrer">Open on GitHub ↗</a>
	</header>
	<p class="meta">
		{#if repo.description}{repo.description} ·{/if}
		{repo.kind}{#if repo.private}, private{/if}{#if repo.fork}, fork{/if}{#if repo.archived},
			archived{/if}
		{#if repo.language}· {repo.language}{/if}
		{#if repo.default_branch}· default branch <code>{repo.default_branch}</code>{/if}
	</p>

	{#if !repo.refreshed}
		<p class="notice" role="status">
			<strong>Not refreshed.</strong> The latest collector run did not see this repository, so
			everything below is as of run #{repo.last_seen_run}{#if repo.latest}
				({formatDateTime(repo.latest.taken_at)}){/if}. The token may have lost access, or the
			repository was deleted, renamed or transferred.
		</p>
	{/if}
	{#if repo.archived}
		<p class="notice" role="status">
			<strong>Archived on GitHub.</strong>
			{#if alertsFrozen}
				Statistics are still updated, but alerts are no longer collected for archived repositories,
				so the alerts below show their state from before it was archived.
			{:else}
				It is read-only; alerts can no longer be fixed here.
			{/if}
		</p>
	{/if}

	<section class="tiles" aria-label="Summary">
		<StatTile label="Risk score" value={formatCount(repo.risk_score)} />
		<StatTile
			label="Open alerts"
			value={formatCount(openCount)}
			hint={SEVERITIES.map((s) => `${repo.open_alerts[s]} ${s}`).join(' · ')}
		/>
		<StatTile label="Open issues" value={formatCount(repo.latest?.open_issues)} />
		<StatTile label="Open pull requests" value={formatCount(repo.latest?.open_prs)} />
		<StatTile
			label="Contributors"
			value={formatCount(repo.latest?.contributors)}
			hint="{formatCount(repo.latest?.commits)} commits"
		/>
		<StatTile
			label="Last commit"
			value={repo.days_since_commit == null ? '—' : formatAge(repo.days_since_commit)}
			hint={repo.days_since_commit == null
				? 'no commits'
				: `${formatDate(repo.latest?.last_commit_at)}${repo.stale ? ' · stale' : ''}`}
		/>
	</section>

	<section aria-labelledby="sources-heading">
		<h2 id="sources-heading">Alert sources</h2>
		<ul class="sources">
			{#each sources as { source, status } (source)}
				<li class={status?.status ?? 'unchecked'}>
					<span class="glyph" aria-hidden="true">
						{status ? statusGlyph[status.status] : '?'}
					</span>
					<span class="name">{SOURCE_LABELS[source]}</span>
					<span class="state">{status ? statusText[status.status] : 'not checked yet'}</span>
					{#if status?.message}
						<span class="message">{status.message}</span>
					{/if}
				</li>
			{/each}
		</ul>
	</section>

	<section aria-labelledby="alerts-heading">
		<div class="section-head">
			<h2 id="alerts-heading">Alerts</h2>
			{#if closedCount > 0}
				<label>
					<input type="checkbox" bind:checked={showClosed} />
					Include {closedCount} closed
				</label>
			{/if}
		</div>
		{#if alerts.length === 0}
			<p class="muted">No open alerts.</p>
		{:else}
			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Severity</th>
							<th>Alert</th>
							<th class="location-col">Location</th>
							<th>Opened</th>
							<th>State</th>
						</tr>
					</thead>
					<tbody>
						{#each alerts as alert (alert.id)}
							<tr class:closed={alert.state !== 'open'}>
								<td><SeverityBadge severity={alert.severity} /></td>
								<td>
									<span class="source"
										>{SOURCE_LABELS[alert.source]}{#if hasAlertNumber(alert.source)}
											#{alert.number}{/if}</span
									>
									<!-- External link to GitHub, not an app route. -->
									<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
									<a href={alert.html_url} target="_blank" rel="noreferrer">{alert.title}</a>
									{#if alert.estimated}<span class="tag">estimated</span>{/if}
									{#if alert.location}<span class="location-inline">{alert.location}</span>{/if}
								</td>
								<td class="location location-col">{alert.location ?? '—'}</td>
								<td class="nowrap">{formatDate(alert.created_at)}</td>
								<td class="nowrap">
									{alert.state}
									{#if alert.closed_at}
										<span class="muted">{formatDate(alert.closed_at)}</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<section aria-labelledby="history-heading">
		<h2 id="history-heading">History</h2>
		<EventList events={repo.events} />
		{#if repo.latest}
			<p class="muted small">
				Last collected {formatDateTime(repo.latest.taken_at)} in run #{repo.latest.run_id}.
			</p>
		{/if}
	</section>
{/if}

<style>
	.back {
		margin: 0 0 0.75rem;
	}

	.back a {
		color: var(--ink-secondary);
		text-decoration: none;
	}

	.repo-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 1rem;
		flex-wrap: wrap;
	}

	h1 {
		margin: 0;
		font-size: 1.4rem;
		overflow-wrap: anywhere;
	}

	h2 {
		font-size: 1.05rem;
		margin: 1.75rem 0 0.6rem;
	}

	.owner {
		color: var(--ink-muted);
		font-weight: normal;
	}

	.meta {
		margin: 0.3rem 0 0;
		color: var(--ink-secondary);
	}

	.muted {
		color: var(--ink-muted);
	}

	.notice {
		margin: 1rem 0 0;
		padding: 0.6rem 0.9rem;
		border: 1px solid var(--border);
		border-left: 4px solid var(--warning);
		border-radius: var(--radius);
		background: var(--surface-raised);
		color: var(--ink-secondary);
	}

	.notice strong {
		color: var(--ink);
	}

	.small {
		font-size: 0.85rem;
	}

	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 0.75rem;
		margin-top: 1.25rem;
	}

	.sources {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: 0.35rem;
	}

	.sources li {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem 0.6rem;
		align-items: baseline;
	}

	.sources .glyph {
		width: 1rem;
		text-align: center;
		color: var(--ink-muted);
	}

	.sources .ok .glyph {
		color: var(--good);
	}

	.sources .error .glyph {
		color: var(--critical);
	}

	.sources .name {
		font-weight: 500;
		min-width: 8.5rem;
	}

	.sources .state {
		color: var(--ink-secondary);
	}

	.sources .message {
		color: var(--ink-muted);
		font-size: 0.85rem;
	}

	.section-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 1rem;
	}

	.section-head label {
		display: inline-flex;
		gap: 0.35rem;
		color: var(--ink-secondary);
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
		vertical-align: baseline;
	}

	th {
		font-weight: 500;
		font-size: 0.85rem;
		color: var(--ink-secondary);
	}

	tbody tr:last-child td {
		border-bottom: none;
	}

	.source {
		display: block;
		font-size: 0.8rem;
		color: var(--ink-muted);
	}

	td a {
		color: var(--ink);
	}

	.location,
	.location-inline {
		color: var(--ink-secondary);
		font-size: 0.9rem;
		overflow-wrap: break-word;
	}

	.location-inline {
		display: none;
	}

	/* Narrow screens: the location moves under the title instead of
	   squeezing a column that would break paths mid-word. */
	@media (max-width: 640px) {
		.location-col {
			display: none;
		}

		.location-inline {
			display: block;
			margin-top: 0.15rem;
			font-size: 0.8rem;
		}
	}

	.nowrap {
		white-space: nowrap;
	}

	.closed td {
		color: var(--ink-muted);
	}

	.tag {
		margin-left: 0.35rem;
		padding: 0 0.35rem;
		border: 1px solid var(--border);
		border-radius: 3px;
		color: var(--ink-muted);
		font-size: 0.75rem;
	}
</style>
