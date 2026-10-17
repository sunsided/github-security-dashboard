import { getRepos, getSummary } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [summary, repos] = await Promise.all([getSummary(fetch), getRepos(fetch)]);
	return { summary, repos };
};
