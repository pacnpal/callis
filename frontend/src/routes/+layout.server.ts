import { redirect } from '@sveltejs/kit';
import { apiFetch, apiJson } from '$lib/server/api';
import type { Meta, Session, User } from '$lib/types';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async (event) => {
	const meta = await apiJson<Meta>(event, '/api/v1/meta');
	const path = event.url.pathname;

	// First-run: everything funnels into the setup wizard (server-side, the
	// SetupGuard middleware enforces the same rule on every API endpoint).
	if (meta.setup_needed && !path.startsWith('/setup')) {
		redirect(303, '/setup');
	}

	// Resolve the session, if any. /auth/me returns the user even before TOTP
	// enrollment completes; per-page loads enforce enrollment via the API.
	let user: User | null = null;
	const response = await apiFetch(event, '/api/v1/auth/me');
	if (response.ok) {
		user = ((await response.json()) as Session).user;
	}

	return { meta, user };
};
