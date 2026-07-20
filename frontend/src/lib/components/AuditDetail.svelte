<script lang="ts">
	import { humanize } from '$lib/format';
	import type { AuditEntry } from '$lib/types';

	let { detail }: { detail: AuditEntry['detail'] } = $props();

	const isMapping = $derived(
		detail !== null && typeof detail === 'object' && !Array.isArray(detail)
	);
</script>

{#if detail}
	{#if isMapping}
		{#each Object.entries(detail as Record<string, unknown>) as [key, value], i (key)}
			{#if i > 0}&nbsp;&middot;&nbsp;{/if}<span class="detail-key">{humanize(key)}:</span>
			{String(value)}
		{/each}
	{:else}
		{JSON.stringify(detail)}
	{/if}
{/if}
