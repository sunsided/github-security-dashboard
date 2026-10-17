<script lang="ts" module>
	import type { Severity } from '#lib/api.js';

	// Shape and label carry the severity; color only reinforces it.
	export const SEVERITY_GLYPHS: Record<Severity, string> = {
		critical: '◆',
		high: '▲',
		medium: '■',
		low: '●'
	};
</script>

<script lang="ts">
	interface Props {
		severity: Severity;
		/** Shows a number instead of the label, e.g. in table cells. */
		count?: number;
	}

	let { severity, count }: Props = $props();
</script>

{#if count === undefined}
	<span class="badge {severity}">
		<span class="glyph" aria-hidden="true">{SEVERITY_GLYPHS[severity]}</span>
		{severity}
	</span>
{:else if count === 0}
	<span class="zero" aria-label="no {severity} alerts">·</span>
{:else}
	<span class="badge {severity}" title="{count} {severity}">
		<span class="glyph" aria-hidden="true">{SEVERITY_GLYPHS[severity]}</span>
		<span class="tabular">{count}</span>
	</span>
{/if}

<style>
	.badge {
		display: inline-flex;
		align-items: baseline;
		gap: 0.3rem;
		white-space: nowrap;
	}

	.glyph {
		font-size: 0.75em;
	}

	.critical .glyph {
		color: var(--critical);
	}

	.high .glyph {
		color: var(--serious);
	}

	.medium .glyph {
		color: var(--warning);
	}

	.low .glyph {
		color: var(--ink-muted);
	}

	.zero {
		color: var(--ink-muted);
	}
</style>
