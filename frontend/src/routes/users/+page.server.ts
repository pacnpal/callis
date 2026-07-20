import { fail } from '@sveltejs/kit';
import { apiAttempt, apiJson } from '$lib/server/api';
import type { UserListItem } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
	const users = await apiJson<UserListItem[]>(event, '/api/v1/users');
	return { users, title: 'Users' };
};

export const actions: Actions = {
	create: async (event) => {
		const form = await event.request.formData();
		const username = String(form.get('username') ?? '');
		const display_name = String(form.get('display_name') ?? '');
		const email = String(form.get('email') ?? '');
		const role = String(form.get('role') ?? 'readonly');
		const result = await apiAttempt(event, '/api/v1/users', {
			method: 'POST',
			body: {
				username,
				display_name,
				email,
				password: String(form.get('password') ?? ''),
				role
			}
		});
		if (!result.ok) {
			return fail(result.status, {
				error: result.detail,
				values: { username, display_name, email, role }
			});
		}
		return { created: true };
	},
	activate: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(event, `/api/v1/users/${encodeURIComponent(id)}/activate`, {
			method: 'POST'
		});
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	deactivate: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(event, `/api/v1/users/${encodeURIComponent(id)}/deactivate`, {
			method: 'POST'
		});
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	delete: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(event, `/api/v1/users/${encodeURIComponent(id)}`, {
			method: 'DELETE'
		});
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	}
};
