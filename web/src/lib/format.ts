const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
const plain = new Intl.NumberFormat('en');

/** 1,284 below ten thousand, 12.9K / 4.2M above. */
export function formatCount(value: number | null | undefined): string {
	if (value == null) return '—';
	return Math.abs(value) < 10_000 ? plain.format(value) : compact.format(value);
}

/** "today", "1 day", "3 weeks", "2 years" — coarse on purpose. */
export function formatAge(days: number | null | undefined): string {
	if (days == null) return '—';
	if (days < 1) return 'today';
	const units: [number, string][] = [
		[365, 'year'],
		[30, 'month'],
		[7, 'week'],
		[1, 'day']
	];
	for (const [size, unit] of units) {
		if (days >= size) {
			const n = Math.floor(days / size);
			return `${n} ${unit}${n === 1 ? '' : 's'}`;
		}
	}
	return 'today';
}

export type Activity = 'active' | 'quiet' | 'stale' | 'empty';

/** Buckets days since the last commit; `staleAfter` comes from the server. */
export function activity(days: number | null | undefined, staleAfter: number): Activity {
	if (days == null) return 'empty';
	if (days >= staleAfter) return 'stale';
	if (days >= 90) return 'quiet';
	return 'active';
}

export function formatDateTime(iso: string | null | undefined): string {
	if (!iso) return '—';
	return new Date(iso).toLocaleString(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short'
	});
}

/** Duration between two ISO timestamps, e.g. "42 s" or "3 min". */
export function formatDuration(from: string, to: string | null): string {
	if (!to) return '—';
	const seconds = Math.round((Date.parse(to) - Date.parse(from)) / 1000);
	return seconds < 120 ? `${seconds} s` : `${Math.round(seconds / 60)} min`;
}
