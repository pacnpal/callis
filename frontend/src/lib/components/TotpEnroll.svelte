<script lang="ts">
	import { enhance } from '$app/forms';
	import type { TOTPSetup } from '$lib/types';

	let {
		totp,
		buttonLabel = 'Verify & Enable 2FA',
		error = null
	}: {
		totp: TOTPSetup;
		buttonLabel?: string;
		error?: string | null;
	} = $props();
</script>

<article class="setup-card">
	<header>
		<h2>Set Up Two-Factor Authentication</h2>
		<p>
			Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.), then
			enter the 6-digit code to confirm.
		</p>
	</header>

	{#if error}
		<div class="flash flash-error" role="alert">{error}</div>
	{/if}

	<div class="totp-qr">
		<img src={`data:image/png;base64,${totp.qr_png_b64}`} alt="Authenticator QR Code" />
	</div>

	<details>
		<summary>Manual entry</summary>
		<p>If you cannot scan the QR code, enter this secret manually:</p>
		<pre class="totp-secret">{totp.secret}</pre>
	</details>

	<form method="post" class="totp-form" use:enhance>
		<label for="totp_code">Enter 6-digit code from your authenticator</label>
		<input
			type="text"
			id="totp_code"
			name="totp_code"
			required
			autocomplete="one-time-code"
			inputmode="numeric"
			pattern="[0-9]{'{'}6{'}'}"
			maxlength="6"
			placeholder="000000"
		/>
		<button type="submit">{buttonLabel}</button>
	</form>
</article>
