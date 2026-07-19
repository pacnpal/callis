import { fail } from '@sveltejs/kit';
import { apiAttempt, apiJson } from '$lib/server/api';
import type { Settings } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const settings = await apiJson<Settings>(event, '/api/v1/settings');
	return { settings, title: 'Settings' };
};

export const actions: Actions = {
	default: async (event) => {
		const form = await event.request.formData();
		// Forward every submitted field verbatim; the API owns validation,
		// clamping, and revert-on-empty semantics.
		const body: Record<string, string> = {};
		for (const [key, value] of form.entries()) {
			if (typeof value === 'string') body[key] = value;
		}
		const result = await apiAttempt<Settings>(event, '/api/v1/settings', {
			method: 'PUT',
			body
		});
		if (!result.ok) {
			return fail(result.status, { error: result.detail });
		}
		return { success: 'Settings saved.', settings: result.data };
	}
};
