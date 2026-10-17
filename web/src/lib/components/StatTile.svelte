<script lang="ts">
	interface Props {
		label: string;
		value: string;
		hint?: string;
	}

	let { label, value, hint }: Props = $props();
</script>

<div class="tile">
	<div class="label">{label}</div>
	<div class="value">{value}</div>
	{#if hint}
		<div class="hint">{hint}</div>
	{/if}
</div>

<style>
	.tile {
		padding: 0.9rem 1rem;
		background: var(--surface-raised);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		min-width: 0;
	}

	.label {
		color: var(--ink-secondary);
		font-size: 0.85rem;
	}

	.value {
		font-size: 1.75rem;
		font-weight: 600;
		line-height: 1.2;
		margin-top: 0.15rem;
	}

	.hint {
		color: var(--ink-muted);
		font-size: 0.8rem;
		margin-top: 0.15rem;
	}
</style>
