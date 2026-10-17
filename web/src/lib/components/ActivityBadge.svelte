<script lang="ts">
	import { formatAge, type Activity } from '#lib/format.js';

	interface Props {
		activity: Activity;
		days: number | null;
	}

	let { activity, days }: Props = $props();

	// Status colors never carry meaning alone: each state has its own glyph.
	const glyphs: Record<Activity, string> = {
		active: '●',
		quiet: '◐',
		stale: '○',
		empty: '–'
	};
</script>

<span class="badge {activity}" title={activity}>
	<span class="glyph" aria-hidden="true">{glyphs[activity]}</span>
	<span class="text">{activity === 'empty' ? 'no commits' : formatAge(days)}</span>
	<span class="visually-hidden">({activity})</span>
</span>

<style>
	.badge {
		display: inline-flex;
		align-items: baseline;
		gap: 0.35rem;
		white-space: nowrap;
	}

	.glyph {
		font-size: 0.8em;
	}

	.active .glyph {
		color: var(--good);
	}

	.quiet .glyph {
		color: var(--warning);
	}

	.stale .glyph {
		color: var(--serious);
	}

	.empty .glyph,
	.empty .text {
		color: var(--ink-muted);
	}

	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
</style>
