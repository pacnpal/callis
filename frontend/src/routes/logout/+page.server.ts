import { redirect } from '@sveltejs/kit';
import { apiFetch } from '$lib/server/api';
import type { Actions, PageServerLoad } from './$types';

// Logout is POST-only; a GET just bounces to the login page.
export const load: PageServerLoad = async () => {
	redirect(303, '/login');
};

export const actions: Actions = {
	default: async (event) => {
		await apiFetch(event, '/api/v1/auth/logout', { method: 'POST' });
		redirect(303, '/login');
	}
};
