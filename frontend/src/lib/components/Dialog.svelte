<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		open = $bindable(false),
		children
	}: {
		title: string;
		open?: boolean;
		children: Snippet;
	} = $props();

	let el: HTMLDialogElement | undefined = $state();

	$effect(() => {
		if (!el) return;
		if (open && !el.open) el.showModal();
		if (!open && el.open) el.close();
	});
</script>

<dialog bind:this={el} onclose={() => (open = false)}>
	<article>
		<header>
			<button type="button" aria-label="Close" rel="prev" onclick={() => (open = false)}></button>
			<h3>{title}</h3>
		</header>
		{@render children()}
	</article>
</dialog>
