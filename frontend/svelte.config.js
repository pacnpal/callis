import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({ out: 'build' }),
		// Kit's built-in check compares the full origin including protocol, but
		// adapter-node assumes https when ORIGIN is unset — which breaks the
		// zero-config plain-HTTP LAN deployment. hooks.server.ts implements an
		// equivalent host-based origin check instead (see csrfGuard), on top of
		// the SameSite=Strict session cookie.
		csrf: { checkOrigin: false },
		// Strict CSP: SvelteKit hashes its own inline hydration scripts; all
		// other assets (Pico CSS, theme.js, app styles) are bundled locally,
		// so nothing outside 'self' is ever loaded. No CDNs.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				'style-src': ['self'],
				'img-src': ['self', 'data:'],
				'font-src': ['self'],
				'connect-src': ['self'],
				'frame-ancestors': ['none'],
				'base-uri': ['self'],
				'form-action': ['self']
			}
		}
	}
};

export default config;
