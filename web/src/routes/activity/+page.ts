import { getEvents } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [news, all] = await Promise.all([getEvents(fetch, 300), getEvents(fetch, 300, true)]);
	return { news, all };
};
