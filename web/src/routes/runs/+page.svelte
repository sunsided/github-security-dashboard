<script lang="ts">
	import type { RunStatus } from '#lib/api.js';
	import { formatCount, formatDateTime, formatDuration } from '#lib/format.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const glyphs: Record<RunStatus, string> = {
		running: '…',
		succeeded: '✓',
		partial: '!',
		failed: '✕'
	};
</script>

<svelte:head>
	<title>Runs · Security dashboard</title>
</svelte:head>

<h1>Collector runs</h1>

{#if data.runs.length === 0}
	<p class="muted">No runs yet.</p>
{:else}
	<ol class="runs">
		{#each data.runs as run (run.id)}
			<li>
				<div class="row">
					<span class="status {run.status}">
						<span aria-hidden="true">{glyphs[run.status]}</span>
						{run.status}
					</span>
					<span>#{run.id}</span>
					<span>{formatDateTime(run.started_at)}</span>
					<span class="muted">took {formatDuration(run.started_at, run.finished_at)}</span>
					{#if run.rate_limit_remaining != null}
						<span class="muted tabular">{formatCount(run.rate_limit_remaining)} requests left</span>
					{/if}
				</div>
				{#if run.errors.length > 0}
					<details>
						<summary>{run.errors.length} error{run.errors.length === 1 ? '' : 's'}</summary>
						<ul>
							{#each run.errors as error, i (i)}
								<li><code>{error}</code></li>
							{/each}
						</ul>
					</details>
				{/if}
			</li>
		{/each}
	</ol>
{/if}

{#if data.deliveries}
	<h2>Digest deliveries</h2>
	{#if data.deliveries.length === 0}
		<p class="muted">No digest has been due yet.</p>
	{:else}
		<ol class="runs">
			{#each data.deliveries as delivery (delivery.id)}
				<li>
					<div class="row">
						<span class="status {delivery.succeeded ? 'succeeded' : 'failed'}">
							<span aria-hidden="true">{delivery.succeeded ? '✓' : '✕'}</span>
							{delivery.succeeded ? (delivery.events > 0 ? 'sent' : 'quiet') : 'failed'}
						</span>
						<span>{delivery.target}</span>
						<span>{formatDateTime(delivery.attempted_at)}</span>
						<span class="muted tabular">
							{delivery.events > 0
								? `${formatCount(delivery.events)} event${delivery.events === 1 ? '' : 's'}`
								: 'nothing new'}
						</span>
					</div>
					{#if delivery.error}
						<p class="error-line"><code>{delivery.error}</code></p>
					{/if}
				</li>
			{/each}
		</ol>
	{/if}
{/if}

<style>
	h1 {
		margin: 0 0 1rem;
		font-size: 1.4rem;
	}

	h2 {
		margin: 2rem 0 0.75rem;
		font-size: 1.1rem;
	}

	.error-line {
		margin: 0.35rem 0 0;
		color: var(--ink-secondary);
	}

	.muted {
		color: var(--ink-muted);
	}

	.runs {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface-raised);
	}

	.runs > li {
		padding: 0.6rem 0.9rem;
		border-bottom: 1px solid var(--border);
	}

	.runs > li:last-child {
		border-bottom: none;
	}

	.row {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem 1.25rem;
		align-items: baseline;
	}

	.status {
		display: inline-flex;
		gap: 0.35rem;
		min-width: 6.5rem;
		font-weight: 500;
	}

	.succeeded span {
		color: var(--good);
	}

	.partial span {
		color: var(--warning);
	}

	.failed span {
		color: var(--critical);
	}

	details {
		margin-top: 0.4rem;
		color: var(--ink-secondary);
	}

	summary {
		cursor: pointer;
	}

	code {
		font-size: 0.85rem;
		overflow-wrap: anywhere;
	}
</style>
