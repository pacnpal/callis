<script lang="ts">
	import '@picocss/pico/css/pico.min.css';
	import '$lib/styles/app.css';
	import { page } from '$app/state';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import type { LayoutData } from './$types';
	import type { Snippet } from 'svelte';

	let { data, children }: { data: LayoutData; children: Snippet } = $props();

	const user = $derived(data.user);
	const meta = $derived(data.meta);
</script>

<svelte:head>
	<title>{page.data.title ? `${page.data.title} - ` : ''}{meta.instance_name}</title>
</svelte:head>

<nav class="container-fluid">
	<ul>
		<li><a href="/dashboard" class="brand">{meta.instance_name}</a></li>
	</ul>
	<ul>
		{#if user}
			{#if user.totp_enrolled}
				<li><a href="/dashboard">Dashboard</a></li>
				{#if user.role === 'admin'}
					<li><a href="/users">Users</a></li>
				{/if}
				<li><a href="/users/{user.id}">My Profile</a></li>
				<li><a href="/hosts">Hosts</a></li>
				<li><a href="/audit">Audit Log</a></li>
				{#if user.role === 'admin'}
					<li><a href="/settings">Settings</a></li>
				{/if}
			{/if}
			<li>
				<form method="post" action="/logout" class="nav-form">
					<button type="submit" class="outline secondary nav-btn">Logout</button>
				</form>
			</li>
		{/if}
		<li>
			<ThemeToggle />
		</li>
	</ul>
</nav>

<main class="container">
	{@render children()}
</main>

<footer class="container callis-footer">
	<small class="text-muted">Callis v{meta.version} &mdash; SSH Bastion Host</small>
	<a href="https://github.com/pacnpal/callis" class="github-link" aria-label="View on GitHub">
		<svg height="20" width="20" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" /></svg>
	</a>
</footer>
