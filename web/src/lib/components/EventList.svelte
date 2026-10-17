<script lang="ts">
	import { resolve } from '$app/paths';
	import { SOURCE_LABELS, type AlertEvent, type EventKind } from '#lib/api.js';
	import { describeEvent, formatDateTime } from '#lib/format.js';

	interface Props {
		events: AlertEvent[];
		/** Show which repository each event belongs to. */
		showRepo?: boolean;
	}

	let { events, showRepo = false }: Props = $props();

	// Good news, bad news, and everything else get distinct glyphs.
	const glyphs: Record<EventKind, string> = {
		opened: '+',
		reopened: '+',
		severity_changed: '±',
		fixed: '✓',
		dismissed: '–',
		gone: '–'
	};
</script>

{#if events.length === 0}
	<p class="empty">No alert changes recorded yet.</p>
{:else}
	<ol class="events">
		{#each events as event (event.id)}
			<li class={event.kind}>
				<span class="glyph" aria-hidden="true">{glyphs[event.kind]}</span>
				<span class="when">{formatDateTime(event.at)}</span>
				<span class="what">
					{#if showRepo}
						<a href={resolve('/repo/[owner]/[name]', { owner: event.owner, name: event.repo })}>
							{event.owner}/{event.repo}</a
						>:
					{/if}
					{SOURCE_LABELS[event.source]} #{event.number}
					<span class="title">{event.title}</span>
				</span>
				<span class="change">{describeEvent(event.kind, event.old, event.new)}</span>
			</li>
		{/each}
	</ol>
{/if}

<style>
	.empty {
		color: var(--ink-muted);
	}

	.events {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface-raised);
	}

	li {
		display: grid;
		grid-template-columns: 1.2rem 11rem 1fr auto;
		gap: 0.75rem;
		align-items: baseline;
		padding: 0.45rem 0.8rem;
		border-bottom: 1px solid var(--border);
	}

	li:last-child {
		border-bottom: none;
	}

	.glyph {
		text-align: center;
		font-weight: 600;
		color: var(--ink-muted);
	}

	.opened .glyph,
	.reopened .glyph {
		color: var(--critical);
	}

	.fixed .glyph {
		color: var(--good);
	}

	.when {
		color: var(--ink-muted);
		font-size: 0.85rem;
		white-space: nowrap;
	}

	.what {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.title {
		color: var(--ink-secondary);
		margin-left: 0.3rem;
	}

	.change {
		white-space: nowrap;
		color: var(--ink-secondary);
	}

	a {
		color: var(--ink);
	}

	@media (max-width: 640px) {
		li {
			grid-template-columns: 1.2rem 1fr;
		}

		.what,
		.change {
			grid-column: 2;
		}
	}
</style>
