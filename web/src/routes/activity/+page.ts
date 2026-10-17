import { getEvents } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => ({ events: await getEvents(fetch, 300) });
