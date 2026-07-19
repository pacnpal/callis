import { apiJson } from '$lib/server/api';
import type { Dashboard } from '$lib/types';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const dashboard = await apiJson<Dashboard>(event, '/api/v1/dashboard');
	return { dashboard, title: 'Dashboard' };
};
