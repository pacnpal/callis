import { fail } from '@sveltejs/kit';
import { apiAttempt, apiFetch, apiJson } from '$lib/server/api';
import type { Host, UserListItem } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

interface DeployKey {
	public_key: string;
}

export const load: PageServerLoad = async (event) => {
	const { user } = await event.parent();
	const hosts = await apiJson<Host[]>(event, '/api/v1/hosts');

	// Admin-only extras: assignable users + the server deploy key. Fetched
	// concurrently; non-admins never trigger these requests.
	let allUsers: { id: string; username: string }[] = [];
	let deployKey = '';
	if (user?.role === 'admin') {
		const [usersResponse, keyResponse] = await Promise.all([
			apiFetch(event, '/api/v1/users'),
			apiFetch(event, '/api/v1/hosts/deploy-key')
		]);
		if (usersResponse.ok) {
			const users = (await usersResponse.json()) as UserListItem[];
			allUsers = users
				.filter((u) => u.is_active)
				.map((u) => ({ id: u.id, username: u.username }))
				.sort((a, b) => a.username.localeCompare(b.username));
		}
		if (keyResponse.ok) {
			deployKey = ((await keyResponse.json()) as DeployKey).public_key;
		}
	}

	return { hosts, allUsers, deployKey, title: 'Hosts' };
};

export const actions: Actions = {
	create: async (event) => {
		const form = await event.request.formData();
		const label = String(form.get('label') ?? '');
		const hostname = String(form.get('hostname') ?? '');
		const description = String(form.get('description') ?? '');
		const port = Number(form.get('port') ?? 22);
		const result = await apiAttempt(event, '/api/v1/hosts', {
			method: 'POST',
			body: { label, hostname, port: Number.isFinite(port) ? port : 22, description }
		});
		if (!result.ok) {
			return fail(result.status, {
				error: result.detail,
				values: { label, hostname, port: String(form.get('port') ?? '22'), description }
			});
		}
		return { created: true };
	},
	deactivate: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(event, `/api/v1/hosts/${encodeURIComponent(id)}/deactivate`, {
			method: 'POST'
		});
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	delete: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const result = await apiAttempt(event, `/api/v1/hosts/${encodeURIComponent(id)}`, {
			method: 'DELETE'
		});
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	assign: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const userId = String(form.get('target_user_id') ?? '');
		if (!userId) return {};
		const result = await apiAttempt(
			event,
			`/api/v1/hosts/${encodeURIComponent(id)}/assign/${encodeURIComponent(userId)}`,
			{ method: 'POST' }
		);
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	unassign: async (event) => {
		const form = await event.request.formData();
		const id = String(form.get('id') ?? '');
		const userId = String(form.get('target_user_id') ?? '');
		const result = await apiAttempt(
			event,
			`/api/v1/hosts/${encodeURIComponent(id)}/unassign/${encodeURIComponent(userId)}`,
			{ method: 'POST' }
		);
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	}
};
