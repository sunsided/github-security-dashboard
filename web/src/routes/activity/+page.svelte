<script lang="ts">
	import EventList from '#lib/components/EventList.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let includeFirstSeen = $state(false);
</script>

<svelte:head>
	<title>Activity · Security dashboard</title>
</svelte:head>

<div class="head">
	<div>
		<h1>Alert activity</h1>
		<p class="intro">
			Every change the collector has observed, newest first. This log is append-only; entries are
			never edited or removed.
		</p>
	</div>
	<label>
		<input type="checkbox" bind:checked={includeFirstSeen} />
		Include alerts that already existed when first collected
	</label>
</div>

<EventList
	events={includeFirstSeen ? data.all : data.news}
	showRepo
	empty={includeFirstSeen
		? 'No alert changes recorded yet.'
		: 'Nothing has changed since alerts were first collected.'}
/>

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		gap: 1rem;
		flex-wrap: wrap;
		margin-bottom: 1rem;
	}

	h1 {
		margin: 0;
		font-size: 1.4rem;
	}

	.intro {
		margin: 0.25rem 0 0;
		color: var(--ink-secondary);
	}

	label {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		color: var(--ink-secondary);
	}
</style>
