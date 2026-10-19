import { defineConfig } from 'vitest/config';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

// The Rust server; `yarn dev` proxies /api there.
const API = process.env.DASHBOARD_API ?? 'http://127.0.0.1:8080';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// Served by the Rust server as a single-page app; 200.html is the shell.
			adapter: adapter({ fallback: '200.html' })
		})
	],
	server: {
		// ws: the live-update socket at /api/realtime goes through the proxy too.
		// /auth: sign-in with [login] mode = "oidc".
		proxy: { '/api': { target: API, ws: true }, '/auth': { target: API } }
	},
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'unit',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			}
		]
	}
});
