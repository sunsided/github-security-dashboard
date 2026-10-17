import { getInsights, getRepos, getSummary } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [summary, repos, insights] = await Promise.all([
		getSummary(fetch),
		getRepos(fetch),
		getInsights(fetch)
	]);
	return { summary, repos, insights };
};
