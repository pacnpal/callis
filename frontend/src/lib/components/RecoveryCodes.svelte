<script lang="ts">
	import CopyButton from '$lib/components/CopyButton.svelte';

	let {
		codes,
		heading = 'Recovery Codes',
		continueHref = '/dashboard'
	}: {
		codes: string[];
		heading?: string;
		continueHref?: string | null;
	} = $props();

	const text = $derived(codes.join('\n'));

	function download() {
		const blob = new Blob([text + '\n'], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'callis-recovery-codes.txt';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		setTimeout(() => URL.revokeObjectURL(url), 0);
	}
</script>

<article class="setup-card">
	<header>
		<h2>{heading}</h2>
		<p>
			Each code can be used <strong>once</strong> in place of an authenticator code if the
			authenticator device is lost. Any previously issued codes are now invalid.
		</p>
	</header>

	<div class="flash flash-error" role="alert">
		Save these codes now — they will <strong>never be shown again</strong>.
	</div>

	<div class="ssh-config-actions">
		<CopyButton {text} />
		<button type="button" class="outline btn-sm" onclick={download}>Download</button>
	</div>
	<pre class="ssh-config recovery-codes">{text}</pre>

	<p class="text-small text-muted">
		To use a code, enter it in the "Authenticator Code" field on the login page instead of a
		6-digit code.
	</p>

	{#if continueHref}
		<a href={continueHref} role="button">I have saved my codes — continue</a>
	{/if}
</article>
