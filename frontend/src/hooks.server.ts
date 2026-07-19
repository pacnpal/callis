import { env } from '$env/dynamic/private';
import type { Handle } from '@sveltejs/kit';

const API_ORIGIN = () => env.CALLIS_API_ORIGIN ?? 'http://127.0.0.1:8000';

/** Paths served by the FastAPI backend but reachable on the public port —
 *  the CLI installer flow (`curl .../install.sh | sh`) and health checks. */
const PROXY_PATHS = new Set(['/install.sh', '/callis.sh', '/health']);

const FORM_CONTENT_TYPES = new Set([
	'application/x-www-form-urlencoded',
	'multipart/form-data',
	'text/plain'
]);

/** CSRF origin check, protocol-agnostic (kit.csrf.checkOrigin is disabled —
 *  it compares full origins, and the derived protocol is unreliable without a
 *  fixed ORIGIN env, which a zero-config LAN deployment doesn't have).
 *  Browsers always send Origin on cross-site and same-site POSTs, so requiring
 *  the Origin host to equal the Host header blocks cross-site form posts. */
function csrfForbidden(request: Request): boolean {
	if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return false;
	const contentType = (request.headers.get('content-type') ?? '')
		.split(';')[0]
		.trim()
		.toLowerCase();
	if (!FORM_CONTENT_TYPES.has(contentType)) return false;
	const origin = request.headers.get('origin');
	if (!origin) return true;
	try {
		return new URL(origin).host !== request.headers.get('host');
	} catch {
		return true;
	}
}

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.setCookies = [];

	if (csrfForbidden(event.request)) {
		return new Response('Cross-site form submissions are forbidden', { status: 403 });
	}

	// Transparent pass-through for backend-owned plain-text endpoints.
	if (PROXY_PATHS.has(event.url.pathname)) {
		const upstream = await fetch(`${API_ORIGIN()}${event.url.pathname}`, {
			headers: { accept: '*/*' },
			redirect: 'manual'
		});
		const headers = new Headers();
		for (const name of ['content-type', 'cache-control']) {
			const value = upstream.headers.get(name);
			if (value) headers.set(name, value);
		}
		return new Response(await upstream.arrayBuffer(), {
			status: upstream.status,
			headers
		});
	}

	const response = await resolve(event);

	// Replay any session-cookie mutations captured from API calls this request.
	for (const cookie of event.locals.setCookies) {
		response.headers.append('set-cookie', cookie);
	}

	// Security headers (CSP itself comes from kit.csp in svelte.config.js).
	response.headers.set('X-Frame-Options', 'DENY');
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('Referrer-Policy', 'no-referrer');
	if ((env.HTTPS_ENABLED ?? '').toLowerCase() === 'true') {
		response.headers.set(
			'Strict-Transport-Security',
			'max-age=31536000; includeSubDomains'
		);
	}

	return response;
};
