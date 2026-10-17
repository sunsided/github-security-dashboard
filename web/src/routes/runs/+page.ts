import { getRuns } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => ({ runs: await getRuns(fetch) });
