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

/** Parse an IPv4/IPv6 address to a big-integer value + width, or null. */
function parseIp(raw: string): { value: bigint; bits: number } | null {
	let ip = raw.trim();
	const zone = ip.indexOf('%');
	if (zone !== -1) ip = ip.slice(0, zone);
	if (!ip) return null;
	if (!ip.includes(':')) {
		const parts = ip.split('.');
		if (parts.length !== 4) return null;
		let value = 0n;
		for (const p of parts) {
			if (!/^\d{1,3}$/.test(p)) return null;
			const n = Number(p);
			if (n > 255) return null;
			value = (value << 8n) | BigInt(n);
		}
		return { value, bits: 32 };
	}
	// IPv6 — fold any trailing embedded IPv4 (e.g. ::ffff:1.2.3.4) into hextets.
	if (ip.includes('.')) {
		const idx = ip.lastIndexOf(':');
		if (idx === -1) return null;
		const v4 = parseIp(ip.slice(idx + 1));
		if (!v4 || v4.bits !== 32) return null;
		const hi = ((v4.value >> 16n) & 0xffffn).toString(16);
		const lo = (v4.value & 0xffffn).toString(16);
		ip = ip.slice(0, idx + 1) + hi + ':' + lo;
	}
	const halves = ip.split('::');
	if (halves.length > 2) return null;
	const toGroups = (s: string) => (s === '' ? [] : s.split(':'));
	const head = toGroups(halves[0]);
	const tail = halves.length === 2 ? toGroups(halves[1]) : null;
	let groups: string[];
	if (tail === null) {
		groups = head;
	} else {
		const missing = 8 - head.length - tail.length;
		if (missing < 0) return null;
		groups = [...head, ...Array(missing).fill('0'), ...tail];
	}
	if (groups.length !== 8) return null;
	let value = 0n;
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		value = (value << 16n) | BigInt(parseInt(g, 16));
	}
	return { value, bits: 128 };
}

/** True if `peer` falls within the IP or CIDR `token` (same address family). */
function ipInToken(peer: string, token: string): boolean {
	const slash = token.indexOf('/');
	const net = parseIp(slash === -1 ? token : token.slice(0, slash));
	const addr = parseIp(peer);
	if (!net || !addr || net.bits !== addr.bits) return false;
	const prefix = slash === -1 ? addr.bits : Number(token.slice(slash + 1));
	if (!Number.isInteger(prefix) || prefix < 0 || prefix > addr.bits) return false;
	if (prefix === 0) return true;
	const shift = BigInt(addr.bits - prefix);
	return addr.value >> shift === net.value >> shift;
}

/** Whether the direct peer that connected to the SSR is a declared trusted
 *  proxy. Only then may we believe its X-Forwarded-* headers. A client that
 *  reaches the web port directly (bypassing the reverse proxy) is NOT trusted,
 *  so it cannot spoof X-Forwarded-For to forge audit IPs or dodge rate limits.
 *  Mirrors the API's TRUSTED_PROXIES allow-list, plus loopback. */
function proxyPeerTrusted(event: RequestEvent): boolean {
	if (!behindTrustedProxy()) return false;
	let peer = '';
	try {
		peer = event.getClientAddress();
	} catch {
		return false;
	}
	if (!peer) return false;
	const tokens = (env.TRUSTED_PROXIES ?? '')
		.split(',')
		.map((t) => t.trim())
		.filter((t) => t && t !== '*');
	return ['127.0.0.1', '::1', ...tokens].some((t) => ipInToken(peer, t));
}

function clientAddressChain(event: RequestEvent, peerTrusted: boolean): string {
	let addr = '';
	try {
		addr = event.getClientAddress();
	} catch {
		// Prerendering or unavailable socket — leave empty.
	}
	// Only propagate the browser-supplied X-Forwarded-For chain when the direct
	// peer is a declared trusted proxy; otherwise a direct client (including one
	// connecting over a loopback SSH tunnel, which the API trusts as a hop)
	// could spoof its address to skew rate limiting and audit source IPs.
	const incoming = peerTrusted ? event.request.headers.get('x-forwarded-for') : null;
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
	const peerTrusted = proxyPeerTrusted(event);
	const xff = clientAddressChain(event, peerTrusted);
	if (xff) headers['x-forwarded-for'] = xff;
	// Pass through the TLS proxy's protocol hint only when the direct peer is a
	// declared trusted proxy; a direct client's header is untrusted.
	const proto = peerTrusted ? event.request.headers.get('x-forwarded-proto') : null;
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
