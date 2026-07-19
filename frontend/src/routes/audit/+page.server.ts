import { apiJson } from '$lib/server/api';
import type { AuditPage } from '$lib/types';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const params = new URLSearchParams();
	for (const key of ['page', 'action', 'actor', 'date_from', 'date_to']) {
		const value = event.url.searchParams.get(key);
		if (value) params.set(key, value);
	}
	const qs = params.toString();
	const audit = await apiJson<AuditPage>(event, `/api/v1/audit${qs ? `?${qs}` : ''}`);
	return {
		audit,
		filters: {
			action: event.url.searchParams.get('action') ?? '',
			actor: event.url.searchParams.get('actor') ?? '',
			date_from: event.url.searchParams.get('date_from') ?? '',
			date_to: event.url.searchParams.get('date_to') ?? ''
		},
		title: 'Audit Log'
	};
};
