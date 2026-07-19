import { fail, redirect } from '@sveltejs/kit';
import { apiAttempt, apiFetch } from '$lib/server/api';
import type { Session, TOTPSetup } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const response = await apiFetch(event, '/api/v1/setup/totp');
	if (response.status === 401) redirect(303, '/login');
	if (response.status === 404) redirect(303, '/login'); // wizard already finished
	if (response.status === 409) redirect(303, '/dashboard'); // already enrolled
	if (!response.ok) redirect(303, '/setup');
	const totp = (await response.json()) as TOTPSetup;
	return { totp, title: 'Authenticator Setup' };
};

export const actions: Actions = {
	default: async (event) => {
		const form = await event.request.formData();
		const result = await apiAttempt<Session>(event, '/api/v1/setup/totp/verify', {
			method: 'POST',
			body: { totp_code: String(form.get('totp_code') ?? '') }
		});
		if (!result.ok) {
			if (result.status === 409) redirect(303, '/dashboard');
			return fail(result.status, { error: result.detail });
		}
		redirect(303, '/dashboard');
	}
};
