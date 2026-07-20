import { fail, redirect } from '@sveltejs/kit';
import { apiAttempt, apiFetch } from '$lib/server/api';
import type { Enroll, TOTPSetup } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const response = await apiFetch(event, '/api/v1/auth/totp/setup');
	if (response.status === 401) redirect(303, '/login');
	if (response.status === 409) redirect(303, '/dashboard'); // already enrolled
	if (!response.ok) redirect(303, '/login');
	const totp = (await response.json()) as TOTPSetup;
	return { totp, title: 'Authenticator Setup' };
};

export const actions: Actions = {
	default: async (event) => {
		const form = await event.request.formData();
		const result = await apiAttempt<Enroll>(event, '/api/v1/auth/totp/verify', {
			method: 'POST',
			body: { totp_code: String(form.get('totp_code') ?? '') }
		});
		if (!result.ok) {
			if (result.status === 409) redirect(303, '/dashboard');
			return fail(result.status, { error: result.detail });
		}
		// Show the one-time recovery codes before continuing to the dashboard.
		event.setHeaders({ 'cache-control': 'no-store' });
		return { recoveryCodes: result.data.recovery_codes };
	}
};
