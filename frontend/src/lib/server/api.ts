/** Server-side client for the FastAPI JSON API (the single source of truth).
 *
 *  Every page load and form action goes through here. The client:
 *   - forwards the browser's session cookie to the API,
 *   - forwards the real client address chain (X-Forwarded-For) so rate
 *     limiting and audit-log source IPs keep working behind the SSR server,
 *   - captures Set-Cookie headers from API responses (session refresh,
 *     login, logout) into event.locals for replay onto the final response,
 *   - translates auth errors into SvelteKit redirects.
 */

import { env } from '$env/dynamic/private';
import { error, redirect, type RequestEvent } from '@sveltejs/kit';

const API_ORIGIN = () => env.CALLIS_API_ORIGIN ?? 'http://127.0.0.1:8000';

export interface ApiError {
	status: number;
	detail: string;
}

/** Whether the deployment declares a trusted TLS proxy in front of the SSR
 *  server (same switch the API uses for its TRUSTED_PROXIES handling). */
const behindTrustedProxy = () => (env.HTTPS_ENABLED ?? '').toLowerCase() === 'true';

function clientAddressChain(event: RequestEvent): string {
	let addr = '';
	try {
		addr = event.getClientAddress();
	} catch {
		// Prerendering or unavailable socket — leave empty.
	}
	// Only propagate the browser-supplied X-Forwarded-For chain when a front
	// proxy is explicitly declared; otherwise a direct client (including one
	// connecting over a loopback SSH tunnel, which the API trusts as a hop)
	// could spoof its address to skew rate limiting and audit source IPs.
	const incoming = behindTrustedProxy()
		? event.request.headers.get('x-forwarded-for')
		: null;
	return [incoming, addr].filter(Boolean).join(', ');
}

export async function apiFetch(
	event: RequestEvent,
	path: string,
	init: { method?: string; body?: unknown } = {}
): Promise<Response> {
	const headers: Record<string, string> = {
		accept: 'application/json'
	};
	const cookie = event.request.headers.get('cookie');
	if (cookie) headers['cookie'] = cookie;
	const xff = clientAddressChain(event);
	if (xff) headers['x-forwarded-for'] = xff;
	// Pass through the TLS proxy's protocol hint only when a front proxy is
	// declared; a direct client's header is untrusted.
	const proto = behindTrustedProxy()
		? event.request.headers.get('x-forwarded-proto')
		: null;
	if (proto) headers['x-forwarded-proto'] = proto;

	let body: string | undefined;
	if (init.body !== undefined) {
		headers['content-type'] = 'application/json';
		body = JSON.stringify(init.body);
	}

	const response = await fetch(`${API_ORIGIN()}${path}`, {
		method: init.method ?? 'GET',
		headers,
		body,
		redirect: 'manual',
		// The API lives on loopback and answers in milliseconds; bound the
		// request so a stalled backend fails fast instead of hanging the page.
		signal: AbortSignal.timeout(30_000)
	});

	// Replay session cookie mutations (refresh/login/logout) onto our response.
	const setCookies = response.headers.getSetCookie?.() ?? [];
	if (setCookies.length > 0) {
		event.locals.setCookies = [...(event.locals.setCookies ?? []), ...setCookies];
	}

	return response;
}

async function detailOf(response: Response): Promise<string> {
	try {
		const data = await response.clone().json();
		if (typeof data?.detail === 'string') return data.detail;
		return JSON.stringify(data?.detail ?? data);
	} catch {
		return response.statusText || `HTTP ${response.status}`;
	}
}

/** GET/POST JSON and translate auth failures into navigation.
 *
 *  Used by page loads: 401 → /login, TOTP-pending 403 → /totp/setup,
 *  first-run 409 → /setup. Anything else unexpected becomes an error page.
 */
export async function apiJson<T>(
	event: RequestEvent,
	path: string,
	init: { method?: string; body?: unknown } = {}
): Promise<T> {
	const response = await apiFetch(event, path, init);
	if (response.ok) {
		return (await response.json()) as T;
	}
	const detail = await detailOf(response);
	if (response.status === 401 && detail === 'authentication_required') {
		redirect(303, '/login');
	}
	if (response.status === 403 && detail === 'totp_enrollment_required') {
		redirect(303, '/totp/setup');
	}
	if (response.status === 409 && detail === 'setup_required') {
		redirect(303, '/setup');
	}
	error(response.status, { message: detail });
}

/** For form actions: returns either parsed data or a structured failure the
 *  action can surface with fail(status, { error }). Auth redirects still fire. */
export async function apiAttempt<T>(
	event: RequestEvent,
	path: string,
	init: { method?: string; body?: unknown } = {}
): Promise<{ ok: true; data: T } | { ok: false; status: number; detail: string }> {
	const response = await apiFetch(event, path, init);
	if (response.ok) {
		const data =
			response.status === 204 ? (undefined as T) : ((await response.json()) as T);
		return { ok: true, data };
	}
	const detail = await detailOf(response);
	if (response.status === 401 && detail === 'authentication_required') {
		redirect(303, '/login');
	}
	if (response.status === 403 && detail === 'totp_enrollment_required') {
		redirect(303, '/totp/setup');
	}
	if (response.status === 409 && detail === 'setup_required') {
		redirect(303, '/setup');
	}
	if (response.status === 429) {
		return { ok: false, status: 429, detail: 'Too many attempts. Please wait and try again.' };
	}
	return { ok: false, status: response.status, detail };
}
