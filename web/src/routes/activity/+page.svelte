<script lang="ts">
	import EventList from '#lib/components/EventList.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>Activity · Security dashboard</title>
</svelte:head>

<h1>Alert activity</h1>
<p class="intro">
	Every change the collector has observed, newest first. This log is append-only; entries are never
	edited or removed.
</p>

<EventList events={data.events} showRepo />

<style>
	h1 {
		margin: 0;
		font-size: 1.4rem;
	}

	.intro {
		margin: 0.25rem 0 1rem;
		color: var(--ink-secondary);
	}
</style>
