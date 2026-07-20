/** Deterministic date formatting (UTC, fixed layout) shared by server render
 *  and client hydration so both always produce identical markup. */

function pad(n: number): string {
	return String(n).padStart(2, '0');
}

export function formatDate(iso: string | null | undefined): string {
	if (!iso) return 'Never';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return 'Never';
	return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function formatDateTime(iso: string | null | undefined): string {
	if (!iso) return 'Never';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return 'Never';
	return `${formatDate(iso)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

export function formatDateTimeSeconds(iso: string | null | undefined): string {
	if (!iso) return 'Never';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return 'Never';
	return `${formatDateTime(iso)}:${pad(d.getUTCSeconds())}`;
}

export function humanize(value: string): string {
	return value.replaceAll('_', ' ');
}
