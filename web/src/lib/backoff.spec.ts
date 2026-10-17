import { describe, expect, it } from 'vitest';
import { reconnectDelay, refreshDelay } from './backoff';

describe('reconnectDelay', () => {
	it('doubles up to thirty seconds', () => {
		const none = () => 0;
		expect([0, 1, 2, 3, 4, 5, 6].map((a) => reconnectDelay(a, none))).toEqual([
			1000, 2000, 4000, 8000, 16000, 30000, 30000
		]);
	});

	it('jitters by at most a fifth', () => {
		expect(reconnectDelay(3, () => 1)).toBe(6400);
		expect(reconnectDelay(3, () => 0.5)).toBe(7200);
	});
});

describe('refreshDelay', () => {
	it('refreshes thirty seconds before expiry, never right away', () => {
		expect(refreshDelay(300_000, 0)).toBe(270_000);
		expect(refreshDelay(10_000, 0)).toBe(1000);
	});
});
