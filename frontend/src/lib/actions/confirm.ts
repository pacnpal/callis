import type { Action } from 'svelte/action';

/** `use:confirm={'message'}` — ask before submitting a form (destructive
 *  actions). Without JS the form still submits; parity with the previous
 *  htmx-based hx-confirm behavior, which also required JS. */
export const confirm: Action<HTMLFormElement, string> = (form, message) => {
	function onSubmit(event: SubmitEvent) {
		if (!window.confirm(message)) {
			event.preventDefault();
			event.stopImmediatePropagation();
		}
	}
	// Capture phase so the check runs before use:enhance's submit handler.
	form.addEventListener('submit', onSubmit, true);
	return {
		destroy() {
			form.removeEventListener('submit', onSubmit, true);
		}
	};
};
