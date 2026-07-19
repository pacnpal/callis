import { fail, redirect } from '@sveltejs/kit';
import { apiAttempt } from '$lib/server/api';
import type { Session } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { user } = await parent();
	if (user?.totp_enrolled) {
		redirect(303, '/dashboard');
	}
	return { title: 'Login' };
};

export const actions: Actions = {
	default: async (event) => {
		const form = await event.request.formData();
		const result = await apiAttempt<Session>(event, '/api/v1/auth/login', {
			method: 'POST',
			body: {
				username: String(form.get('username') ?? ''),
				password: String(form.get('password') ?? ''),
				totp_code: String(form.get('totp_code') ?? '')
			}
		});
		if (!result.ok) {
			return fail(result.status, { error: result.detail });
		}
		redirect(303, result.data.user.totp_enrolled ? '/dashboard' : '/totp/setup');
	}
};
