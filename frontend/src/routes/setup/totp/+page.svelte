<script lang="ts">
	import TotpEnroll from '$lib/components/TotpEnroll.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<TotpEnroll totp={data.totp} buttonLabel="Verify & Complete Setup" error={form?.error ?? null} />
