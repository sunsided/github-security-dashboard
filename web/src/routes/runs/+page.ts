import { getDeliveries, getRuns } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [runs, deliveries] = await Promise.all([getRuns(fetch), getDeliveries(fetch)]);
	return { runs, deliveries };
};
