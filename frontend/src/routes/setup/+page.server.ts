import { fail, redirect } from '@sveltejs/kit';
import { apiAttempt } from '$lib/server/api';
import type { Session } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { meta } = await parent();
	if (!meta.setup_needed) {
		redirect(303, '/login');
	}
	return { title: 'Setup' };
};

export const actions: Actions = {
	default: async (event) => {
		const form = await event.request.formData();
		const username = String(form.get('username') ?? '');
		const display_name = String(form.get('display_name') ?? '');
		const result = await apiAttempt<Session>(event, '/api/v1/setup', {
			method: 'POST',
			body: {
				username,
				password: String(form.get('password') ?? ''),
				password_confirm: String(form.get('password_confirm') ?? ''),
				display_name
			}
		});
		if (!result.ok) {
			return fail(result.status, { error: result.detail, username, display_name });
		}
		redirect(303, '/setup/totp');
	}
};
