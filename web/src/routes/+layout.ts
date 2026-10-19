import { getMe } from '#lib/api.js';
import type { LayoutLoad } from './$types';

// Client-rendered only: all data comes from the local JSON API.
export const ssr = false;
export const prerender = false;

export const load: LayoutLoad = async ({ fetch }) => ({ me: await getMe(fetch) });
