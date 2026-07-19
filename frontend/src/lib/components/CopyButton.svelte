<script lang="ts">
	let {
		text,
		label = 'Copy'
	}: {
		text: string;
		label?: string;
	} = $props();

	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;

	function fallbackCopy() {
		const ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.opacity = '0';
		document.body.appendChild(ta);
		ta.select();
		try {
			if (document.execCommand('copy')) onSuccess();
		} catch {
			// leave button label unchanged on failure
		}
		document.body.removeChild(ta);
	}

	function onSuccess() {
		copied = true;
		clearTimeout(timer);
		timer = setTimeout(() => (copied = false), 2000);
	}

	function copy() {
		// navigator.clipboard requires a secure context; fall back to
		// execCommand('copy') for plain-HTTP LAN deployments.
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(onSuccess).catch(fallbackCopy);
		} else {
			fallbackCopy();
		}
	}
</script>

<button type="button" class="outline btn-sm" onclick={copy}>
	{copied ? 'Copied!' : label}
</button>
