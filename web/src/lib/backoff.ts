/** Delay before reconnect attempt `attempt` (0-based): doubling from 1 s up
 * to 30 s, with up to 20 % jitter so many tabs don't reconnect in lockstep.
 * `random` is injectable for tests. */
export function reconnectDelay(attempt: number, random: () => number = Math.random): number {
	const base = Math.min(30_000, 1000 * 2 ** Math.max(0, attempt));
	return Math.round(base * (1 - 0.2 * random()));
}

/** When to refresh a token that expires at `expiresAt`: 30 s before, but not
 * sooner than 1 s from `now` (all in milliseconds). */
export function refreshDelay(expiresAt: number, now: number): number {
	return Math.max(1000, expiresAt - now - 30_000);
}
