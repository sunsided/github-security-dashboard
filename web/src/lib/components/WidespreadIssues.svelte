<script lang="ts">
	import { resolve } from '$app/paths';
	import { SOURCE_LABELS, hasAlertNumber, type Issue } from '#lib/api.js';
	import SeverityBadge from './SeverityBadge.svelte';

	interface Props {
		issues: Issue[];
		/** First ID of the issue the table is filtered by, if any. */
		selected?: string | null;
		onselect?: (issue: Issue) => void;
	}

	let { issues, selected = null, onselect }: Props = $props();

	let expanded = $state<string | null>(null);
</script>

<section class="widespread" aria-labelledby="widespread-heading">
	<h3 id="widespread-heading">Most widespread</h3>
	{#if issues.length === 0}
		<p class="empty">No issue has open alerts in more than one repository.</p>
	{:else}
		<ol>
			{#each issues as issue, i (issue.ids[0])}
				<li class:selected={selected === issue.ids[0]}>
					<span class="rank tabular" aria-hidden="true">{i + 1}</span>
					<div class="body">
						<div class="headline">
							<SeverityBadge severity={issue.severity} />
							<span class="title">{issue.title}</span>
							{#if issue.estimated_only}<span class="tag">estimated</span>{/if}
						</div>
						<div class="meta">
							<span class="ids">{issue.ids.join(' · ')}</span>
							<span class="sources">{issue.sources.map((s) => SOURCE_LABELS[s]).join(', ')}</span>
						</div>
						{#if expanded === issue.ids[0]}
							<ul class="repos">
								{#each issue.repositories as repo (repo.id)}
									<li>
										<a
											href={resolve('/repo/[owner]/[name]', { owner: repo.owner, name: repo.name })}
											>{repo.owner}/{repo.name}</a
										>
										{#each repo.alerts as alert (alert.url)}
											<!-- External link to the alert on GitHub / OSV. -->
											<!-- eslint-disable svelte/no-navigation-without-resolve -->
											<a class="alert" href={alert.url} target="_blank" rel="noreferrer">
												{SOURCE_LABELS[alert.source]}{#if hasAlertNumber(alert.source)}
													#{alert.number}{/if} ↗</a
											>
											<!-- eslint-enable svelte/no-navigation-without-resolve -->
										{/each}
									</li>
								{/each}
							</ul>
						{/if}
					</div>
					<div class="actions">
						<button
							class="count"
							aria-pressed={selected === issue.ids[0]}
							title="Show these repositories in the table"
							onclick={() => onselect?.(issue)}
						>
							<span class="tabular">{issue.repositories.length}</span> repositories
						</button>
						<button
							class="expand"
							aria-expanded={expanded === issue.ids[0]}
							onclick={() => (expanded = expanded === issue.ids[0] ? null : issue.ids[0])}
						>
							{expanded === issue.ids[0] ? 'Hide' : 'Show'} repositories
						</button>
					</div>
				</li>
			{/each}
		</ol>
	{/if}
</section>

<style>
	.widespread {
		padding: 0.8rem 0.9rem;
		background: var(--surface-raised);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	h3 {
		margin: 0 0 0.5rem;
		font-size: 1rem;
	}

	.empty {
		margin: 0;
		color: var(--ink-muted);
	}

	ol {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	ol > li {
		display: grid;
		grid-template-columns: 1.5rem 1fr auto;
		gap: 0.6rem;
		align-items: start;
		padding: 0.5rem 0.35rem;
		border-bottom: 1px solid var(--border);
	}

	ol > li:last-child {
		border-bottom: none;
	}

	ol > li.selected {
		background: var(--surface-sunken);
		box-shadow: inset 3px 0 0 var(--accent);
	}

	.rank {
		color: var(--ink-muted);
		text-align: right;
	}

	.body {
		min-width: 0;
	}

	.headline {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.25rem 0.6rem;
	}

	.title {
		overflow-wrap: anywhere;
	}

	.meta {
		display: flex;
		flex-wrap: wrap;
		gap: 0.2rem 0.8rem;
		margin-top: 0.15rem;
		font-size: 0.8rem;
		color: var(--ink-muted);
	}

	.ids {
		overflow-wrap: anywhere;
	}

	.tag {
		padding: 0 0.35rem;
		border: 1px solid var(--border);
		border-radius: 3px;
		color: var(--ink-muted);
		font-size: 0.75rem;
	}

	.repos {
		margin: 0.4rem 0 0;
		padding-left: 1rem;
		font-size: 0.85rem;
		display: grid;
		gap: 0.2rem;
	}

	.repos a {
		color: var(--ink);
	}

	.repos .alert {
		margin-left: 0.5rem;
		color: var(--ink-muted);
		font-size: 0.8rem;
	}

	.actions {
		display: grid;
		justify-items: end;
		gap: 0.2rem;
	}

	.actions button {
		all: unset;
		cursor: pointer;
		font-size: 0.8rem;
		white-space: nowrap;
	}

	.count {
		color: var(--ink);
		font-weight: 500;
	}

	.count[aria-pressed='true'] {
		color: var(--accent);
	}

	.expand {
		color: var(--accent);
	}

	.actions button:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	@media (max-width: 640px) {
		ol > li {
			grid-template-columns: 1.5rem 1fr;
		}

		.actions {
			grid-column: 2;
			justify-items: start;
			display: flex;
			gap: 1rem;
		}
	}
</style>
