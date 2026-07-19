import { fail } from '@sveltejs/kit';
import { apiAttempt, apiJson } from '$lib/server/api';
import type { SSHKey, UserDetail } from '$lib/types';
import type { Actions, PageServerLoad } from './$types';

interface GeneratedKey {
	private_key: string;
	key: SSHKey;
}

export const load: PageServerLoad = async (event) => {
	const detail = await apiJson<UserDetail>(
		event,
		`/api/v1/users/${encodeURIComponent(event.params.id)}`
	);
	return { detail, title: detail.user.display_name };
};

export const actions: Actions = {
	uploadKey: async (event) => {
		const form = await event.request.formData();
		const label = String(form.get('label') ?? '');
		const public_key = String(form.get('public_key') ?? '');
		const result = await apiAttempt<SSHKey>(
			event,
			`/api/v1/users/${encodeURIComponent(event.params.id)}/keys`,
			{ method: 'POST', body: { label, public_key } }
		);
		if (!result.ok) {
			return fail(result.status, { uploadError: result.detail, label, public_key });
		}
		return { uploaded: true };
	},
	generateKey: async (event) => {
		const form = await event.request.formData();
		const result = await apiAttempt<GeneratedKey>(
			event,
			`/api/v1/users/${encodeURIComponent(event.params.id)}/keys/generate`,
			{ method: 'POST', body: { label: String(form.get('label') ?? '') } }
		);
		if (!result.ok) {
			return fail(result.status, { generateError: result.detail });
		}
		// The private key exists only in this one response — it is never
		// persisted server-side and disappears when the page re-renders.
		return { generated: result.data };
	},
	revokeKey: async (event) => {
		const form = await event.request.formData();
		const keyId = String(form.get('key_id') ?? '');
		const result = await apiAttempt(
			event,
			`/api/v1/users/${encodeURIComponent(event.params.id)}/keys/${encodeURIComponent(keyId)}/revoke`,
			{ method: 'POST' }
		);
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	},
	changeRole: async (event) => {
		const form = await event.request.formData();
		const result = await apiAttempt(
			event,
			`/api/v1/users/${encodeURIComponent(event.params.id)}/role`,
			{ method: 'PUT', body: { role: String(form.get('role') ?? '') } }
		);
		if (!result.ok) return fail(result.status, { error: result.detail });
		return {};
	}
};
