// See https://svelte.dev/docs/kit/types#app.d.ts
declare global {
	namespace App {
		interface Locals {
			/** Raw Set-Cookie headers captured from API responses during this
			 *  request; replayed onto the final response in hooks.server.ts so
			 *  the API stays the single source of truth for cookie attributes. */
			setCookies: string[];
		}
		interface Error {
			message: string;
		}
	}
}

// Pico CSS styles dialog close buttons via [rel="prev"]; the attribute is
// non-standard on <button>, so teach Svelte's typings about it.
declare module 'svelte/elements' {
	interface HTMLButtonAttributes {
		rel?: string;
	}
}

export {};
