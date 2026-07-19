import { fail } from '@sveltejs/kit';
import { apiAttempt, apiJson } from '$lib/server/api';
import type { Sessions } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const sessions = await apiJson<Sessions>(event, '/api/v1/sessions');
	return { sessions, title: 'Sessions' };
};

export const actions: Actions = {
	terminate: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(
			event,
			`/api/v1/sessions/${encodeURIComponent(id)}/terminate`,
			{ method: 'POST' }
		);
		if (!result.ok) {
			const detail =
				result.detail === 'session_process_not_found'
					? 'Could not locate the session process. The record was left open — ' +
						'in-container termination requires the unified deployment; the session ' +
						'will close when it disconnects.'
					: result.detail;
			return fail(result.status, { error: detail });
		}
		return {};
	}
};
