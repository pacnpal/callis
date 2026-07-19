<script lang="ts">
	import { onMount } from 'svelte';
	import { enhance } from '$app/forms';
	import { invalidateAll } from '$app/navigation';
	import { page } from '$app/state';
	import { formatDateTime } from '$lib/format';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const me = $derived(page.data.user!);
	const isAdmin = $derived(me.role === 'admin');
	const errorMsg = $derived(form && 'error' in form && form.error ? form.error : null);

	// Live view: refresh the session tables every 10 seconds.
	onMount(() => {
		const timer = setInterval(() => invalidateAll(), 10_000);
		return () => clearInterval(timer);
	});
</script>

<h2>SSH Sessions</h2>

<p class="text-muted">
	Live view of connections through the bastion, tracked from the sshd log. The tables refresh
	automatically every 10 seconds.
</p>

{#if errorMsg}
	<div class="flash flash-error" role="alert">{errorMsg}</div>
{/if}

<h3>Active <span class="badge badge-active">{data.sessions.active.length}</span></h3>
{#if data.sessions.active.length > 0}
	<figure>
		<table>
			<thead>
				<tr>
					<th>User</th>
					<th>Source</th>
					<th>Connected Since</th>
					<th>Key Fingerprint</th>
					{#if isAdmin}
						<th>Actions</th>
					{/if}
				</tr>
			</thead>
			<tbody>
				{#each data.sessions.active as s (s.id)}
					<tr>
						<td>{s.username}</td>
						<td><code class="text-small">{s.source_ip}:{s.source_port}</code></td>
						<td class="text-small">{formatDateTime(s.started_at)}</td>
						<td><code class="text-small">{s.key_fingerprint ?? '—'}</code></td>
						{#if isAdmin}
							<td>
								<form
									method="post"
									action="?/terminate"
									use:enhance={({ cancel }) => {
										if (
											!window.confirm(
												`Terminate this SSH session for ${s.username}? The connection will be dropped immediately.`
											)
										)
											cancel();
									}}
								>
									<input type="hidden" name="id" value={s.id} />
									<button type="submit" class="outline contrast btn-sm">Terminate</button>
								</form>
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>
	</figure>
{:else}
	<p class="text-muted">No active SSH sessions.</p>
{/if}

<h3>Recently Closed</h3>
{#if data.sessions.recent.length > 0}
	<figure>
		<table>
			<thead>
				<tr>
					<th>User</th>
					<th>Source</th>
					<th>Connected</th>
					<th>Disconnected</th>
					<th>Reason</th>
				</tr>
			</thead>
			<tbody>
				{#each data.sessions.recent as s (s.id)}
					<tr>
						<td>{s.username}</td>
						<td><code class="text-small">{s.source_ip}:{s.source_port}</code></td>
						<td class="text-small">{formatDateTime(s.started_at)}</td>
						<td class="text-small">{s.ended_at ? formatDateTime(s.ended_at) : '—'}</td>
						<td>
							<span class="badge {s.close_reason === 'terminated' ? 'badge-inactive' : ''}">
								{(s.close_reason ?? 'disconnected').replace('_', ' ')}
							</span>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</figure>
{:else}
	<p class="text-muted">
		No closed sessions recorded yet. Sessions appear here once users connect through the bastion.
	</p>
{/if}
