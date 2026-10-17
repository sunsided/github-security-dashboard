<script lang="ts">
	import { SEVERITIES, type Bucket } from '#lib/api.js';
	import { formatCount } from '#lib/format.js';
	import { SEVERITY_GLYPHS } from './SeverityBadge.svelte';

	interface Props {
		title: string;
		buckets: Bucket[];
		/** Display name of a bucket key. */
		label?: (key: string) => string;
		/** Key of the bucket the table is filtered by, if any. */
		selected?: string | null;
		onselect?: (bucket: Bucket) => void;
		/** Shown when there are no buckets. */
		empty?: string;
	}

	let {
		title,
		buckets,
		label = (key) => key,
		selected = null,
		onselect,
		empty = 'No open alerts.'
	}: Props = $props();

	const max = $derived(Math.max(1, ...buckets.map((b) => b.total)));

	/** Wide enough that every severity present stays visible, even when the
	 * bucket is tiny next to the largest one: 4px per segment plus gaps. */
	function minWidth(bucket: Bucket): string {
		const segments = SEVERITIES.filter((s) => bucket.counts[s] > 0).length;
		return `${segments * 4 + Math.max(0, segments - 1) * 2}px`;
	}
	let hovered = $state<string | null>(null);
	let showTable = $state(false);
</script>

<figure class="chart">
	<figcaption>{title}</figcaption>
	{#if buckets.length === 0}
		<p class="empty">{empty}</p>
	{:else}
		<ol class="rows">
			{#each buckets as bucket (bucket.key)}
				<li>
					<button
						class="row"
						class:selected={selected === bucket.key}
						aria-pressed={selected === bucket.key}
						onclick={() => onselect?.(bucket)}
						onpointerenter={() => (hovered = bucket.key)}
						onpointerleave={() => (hovered = null)}
						onfocus={() => (hovered = bucket.key)}
						onblur={() => (hovered = null)}
					>
						<span class="label">{label(bucket.key)}</span>
						<span class="track">
							<span
								class="bar"
								style:width="{(bucket.total / max) * 100}%"
								style:min-width={minWidth(bucket)}
							>
								{#each SEVERITIES as severity (severity)}
									{#if bucket.counts[severity] > 0}
										<span class="segment {severity}" style:flex-grow={bucket.counts[severity]}
										></span>
									{/if}
								{/each}
							</span>
						</span>
						<span class="value tabular">{formatCount(bucket.total)}</span>
					</button>
					{#if hovered === bucket.key}
						<div class="tooltip" role="tooltip">
							{#each SEVERITIES as severity (severity)}
								{#if bucket.counts[severity] > 0}
									<span class="tip-row">
										<span class="key {severity}" aria-hidden="true"></span>
										<strong class="tabular">{formatCount(bucket.counts[severity])}</strong>
										{severity}
									</span>
								{/if}
							{/each}
							<span class="tip-row muted">
								in {bucket.repo_ids.length} repositor{bucket.repo_ids.length === 1 ? 'y' : 'ies'}
							</span>
						</div>
					{/if}
				</li>
			{/each}
		</ol>
		<button class="table-toggle" onclick={() => (showTable = !showTable)} aria-expanded={showTable}>
			{showTable ? 'Hide table' : 'Show as table'}
		</button>
		{#if showTable}
			<table>
				<thead>
					<tr>
						<th scope="col">{title}</th>
						{#each SEVERITIES as severity (severity)}
							<th scope="col" class="num">
								<span aria-hidden="true">{SEVERITY_GLYPHS[severity]}</span>
								{severity}
							</th>
						{/each}
						<th scope="col" class="num">total</th>
						<th scope="col" class="num">repos</th>
					</tr>
				</thead>
				<tbody>
					{#each buckets as bucket (bucket.key)}
						<tr>
							<th scope="row">{label(bucket.key)}</th>
							{#each SEVERITIES as severity (severity)}
								<td class="num tabular">{formatCount(bucket.counts[severity])}</td>
							{/each}
							<td class="num tabular">{formatCount(bucket.total)}</td>
							<td class="num tabular">{formatCount(bucket.repo_ids.length)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	{/if}
</figure>

<style>
	.chart {
		margin: 0;
		padding: 0.8rem 0.9rem;
		background: var(--surface-raised);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		min-width: 0;
	}

	figcaption {
		font-weight: 600;
		margin-bottom: 0.5rem;
	}

	.empty {
		color: var(--ink-muted);
		margin: 0;
	}

	.rows {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: 0.15rem;
	}

	li {
		position: relative;
	}

	.row {
		all: unset;
		box-sizing: border-box;
		display: grid;
		grid-template-columns: minmax(5rem, 8.5rem) 1fr 3rem;
		align-items: center;
		gap: 0.6rem;
		width: 100%;
		/* Hit target taller than the bar. */
		padding: 0.3rem 0.35rem;
		border-radius: 4px;
		cursor: pointer;
	}

	.row:hover,
	.row:focus-visible {
		background: var(--surface-sunken);
	}

	.row:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 1px;
	}

	.row.selected {
		background: var(--surface-sunken);
		box-shadow: inset 3px 0 0 var(--accent);
	}

	.label {
		color: var(--ink-secondary);
		font-size: 0.85rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.track {
		display: block;
		min-width: 0;
	}

	.bar {
		display: flex;
		gap: 2px;
		height: 14px;
		/* Square at the baseline, rounded at the data end. */
		border-radius: 0 4px 4px 0;
		overflow: hidden;
	}

	.segment {
		display: block;
		flex-basis: 0;
		min-width: 4px;
	}

	.critical {
		background: var(--critical);
	}

	.high {
		background: var(--serious);
	}

	.medium {
		background: var(--warning);
	}

	.low {
		background: var(--ink-muted);
	}

	.value {
		text-align: right;
		font-size: 0.85rem;
		color: var(--ink);
	}

	.tooltip {
		position: absolute;
		z-index: 2;
		left: 9rem;
		top: 100%;
		display: grid;
		gap: 0.15rem;
		padding: 0.45rem 0.6rem;
		background: var(--surface-raised);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		box-shadow: 0 4px 12px rgb(0 0 0 / 0.12);
		font-size: 0.8rem;
		pointer-events: none;
		white-space: nowrap;
	}

	.tip-row {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.key {
		width: 10px;
		height: 3px;
		border-radius: 2px;
	}

	.muted {
		color: var(--ink-muted);
	}

	.table-toggle {
		all: unset;
		margin-top: 0.4rem;
		font-size: 0.8rem;
		color: var(--accent);
		cursor: pointer;
	}

	.table-toggle:focus-visible {
		outline: 2px solid var(--accent);
	}

	table {
		width: 100%;
		margin-top: 0.4rem;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	th,
	td {
		padding: 0.25rem 0.35rem;
		border-bottom: 1px solid var(--border);
		text-align: left;
		font-weight: normal;
	}

	thead th {
		color: var(--ink-secondary);
	}

	.num {
		text-align: right;
	}
</style>
