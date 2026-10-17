import { describe, expect, it } from 'vitest';
import { activity, describeEvent, formatAge, formatCount, formatDuration } from './format';

describe('formatCount', () => {
	it('keeps small numbers exact and compacts large ones', () => {
		expect(formatCount(1284)).toBe('1,284');
		expect(formatCount(12_900)).toBe('12.9K');
		expect(formatCount(4_200_000)).toBe('4.2M');
		expect(formatCount(null)).toBe('—');
	});
});

describe('formatAge', () => {
	it('uses the largest fitting unit', () => {
		expect(formatAge(0)).toBe('today');
		expect(formatAge(1)).toBe('1 day');
		expect(formatAge(15)).toBe('2 weeks');
		expect(formatAge(400)).toBe('1 year');
		expect(formatAge(800)).toBe('2 years');
		expect(formatAge(null)).toBe('—');
	});
});

describe('activity', () => {
	it('buckets by days since the last commit', () => {
		expect(activity(3, 180)).toBe('active');
		expect(activity(90, 180)).toBe('quiet');
		expect(activity(180, 180)).toBe('stale');
		expect(activity(null, 180)).toBe('empty');
	});
});

describe('formatDuration', () => {
	it('switches to minutes after two minutes', () => {
		expect(formatDuration('2026-10-17T12:00:00Z', '2026-10-17T12:00:42Z')).toBe('42 s');
		expect(formatDuration('2026-10-17T12:00:00Z', '2026-10-17T12:05:00Z')).toBe('5 min');
		expect(formatDuration('2026-10-17T12:00:00Z', null)).toBe('—');
	});
});

describe('describeEvent', () => {
	it('names the transition', () => {
		expect(describeEvent('opened', null, 'high')).toBe('opened as high');
		expect(describeEvent('severity_changed', 'high', 'critical')).toBe('severity high → critical');
		expect(describeEvent('reopened', 'dismissed', 'open')).toBe('reopened (was dismissed)');
		expect(describeEvent('fixed', 'open', 'fixed')).toBe('fixed');
		expect(describeEvent('gone', 'open', 'gone')).toBe('no longer on GitHub');
	});
});
