<script lang="ts">
	import favicon from '#lib/assets/favicon.svg';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const links = [
		{ route: '/', label: 'Repositories' },
		{ route: '/activity', label: 'Activity' },
		{ route: '/runs', label: 'Runs' }
	] as const;
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Security dashboard</title>
</svelte:head>

<header>
	<a class="brand" href={resolve('/')}>Security dashboard</a>
	<nav>
		{#each links as link (link.route)}
			<a
				href={resolve(link.route)}
				aria-current={page.url.pathname === resolve(link.route) ? 'page' : undefined}
			>
				{link.label}
			</a>
		{/each}
	</nav>
</header>

<main>
	{@render children()}
</main>

<style>
	:global {
		:root {
			color-scheme: light dark;
			--surface: #fcfcfb;
			--surface-raised: #ffffff;
			--surface-sunken: #f2f2ef;
			--border: #e2e1dc;
			--ink: #1a1a19;
			--ink-secondary: #52514c;
			--ink-muted: #7a7972;
			--accent: #2a5bd7;
			--good: #0ca30c;
			--warning: #fab219;
			--serious: #ec835a;
			--critical: #d03b3b;
			--radius: 6px;
			font-family:
				system-ui,
				-apple-system,
				'Segoe UI',
				Roboto,
				sans-serif;
			font-size: 15px;
			line-height: 1.45;
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--surface: #1a1a19;
				--surface-raised: #232322;
				--surface-sunken: #141413;
				--border: #353533;
				--ink: #ecebe6;
				--ink-secondary: #b5b4ad;
				--ink-muted: #8a8982;
				--accent: #7ea2f5;
			}
		}

		body {
			margin: 0;
			background: var(--surface);
			color: var(--ink);
		}

		a {
			color: var(--accent);
		}

		button {
			font: inherit;
		}

		.tabular {
			font-variant-numeric: tabular-nums;
		}
	}

	header {
		display: flex;
		align-items: baseline;
		gap: 2rem;
		padding: 0.9rem 1.5rem;
		border-bottom: 1px solid var(--border);
		background: var(--surface-raised);
	}

	.brand {
		font-weight: 600;
		color: var(--ink);
		text-decoration: none;
	}

	nav {
		display: flex;
		gap: 1.25rem;
	}

	nav a {
		color: var(--ink-secondary);
		text-decoration: none;
		padding-bottom: 2px;
		border-bottom: 2px solid transparent;
	}

	nav a[aria-current='page'] {
		color: var(--ink);
		border-bottom-color: var(--accent);
	}

	main {
		max-width: 1400px;
		margin: 0 auto;
		padding: 1.5rem;
	}

	@media (max-width: 640px) {
		header {
			padding: 0.75rem 1rem;
			gap: 1rem;
		}

		main {
			padding: 1rem;
		}
	}
</style>
