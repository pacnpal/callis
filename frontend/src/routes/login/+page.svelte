<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/state';
	import type { ActionData } from './$types';

	let { form }: { form: ActionData } = $props();

	const motd = $derived(page.data.meta.motd);
</script>

<article class="auth-card">
	<header>
		<h2>Sign In</h2>
		<p class="text-muted">Callis &mdash; SSH bastion host</p>
	</header>
	{#if motd}
		<div class="flash flash-info motd" role="status">{motd}</div>
	{/if}
	{#if form?.error}
		<div class="flash flash-error" role="alert">{form.error}</div>
	{/if}
	<form method="post" use:enhance>
		<label for="username">Username</label>
		<input type="text" id="username" name="username" required autocomplete="username" />

		<label for="password">Password</label>
		<input
			type="password"
			id="password"
			name="password"
			required
			autocomplete="current-password"
		/>

		<label for="totp_code">Authenticator Code</label>
		<input
			type="text"
			id="totp_code"
			name="totp_code"
			autocomplete="one-time-code"
			placeholder="6-digit code"
			pattern="[0-9]{'{'}6{'}'}|[A-Za-z0-9 \-]{'{'}10,14{'}'}"
			maxlength="14"
			aria-describedby="totp_code_help"
		/>
		<p id="totp_code_help" class="helper-text">
			Enter the code from your authenticator app, or a recovery code if you lost your device.
			Leave blank on your first login &mdash; you will set up two-factor authentication next.
		</p>

		<button type="submit">Sign In</button>
	</form>
</article>
