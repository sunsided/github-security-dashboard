import { getRepo } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => ({
	owner: params.owner,
	name: params.name,
	repo: await getRepo(fetch, params.owner, params.name)
});
