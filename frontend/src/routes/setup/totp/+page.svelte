<script lang="ts">
	import RecoveryCodes from '$lib/components/RecoveryCodes.svelte';
	import TotpEnroll from '$lib/components/TotpEnroll.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const recoveryCodes = $derived(
		form && 'recoveryCodes' in form ? (form.recoveryCodes ?? null) : null
	);
</script>

{#if recoveryCodes}
	<RecoveryCodes codes={recoveryCodes} />
{:else}
	<TotpEnroll
		totp={data.totp}
		buttonLabel="Verify & Complete Setup"
		error={form && 'error' in form ? (form.error ?? null) : null}
	/>
{/if}
