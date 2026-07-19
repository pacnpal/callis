<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/state';
	import CopyButton from '$lib/components/CopyButton.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import type { Host } from '$lib/types';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const me = $derived(page.data.user!);
	const meta = $derived(page.data.meta);
	const isAdmin = $derived(me.role === 'admin');
	const errorMsg = $derived(form && 'error' in form && form.error ? form.error : null);
	const createFailed = $derived(!!(form && 'values' in form && form.values));

	let addHostOpen = $state(false);

	$effect(() => {
		if (form && 'values' in form && form.values) addHostOpen = true;
		if (form && 'created' in form && form.created) addHostOpen = false;
	});

	function sshConfigBlock(host: Host): string {
		return `Host ${host.alias}\n    HostName ${host.hostname}\n    Port ${host.port}\n    ProxyJump ${me.username}@${meta.ssh_host}:${meta.ssh_port}`;
	}

	function assignableUsers(host: Host) {
		const assigned = new Set(host.assigned_users.map((u) => u.id));
		return data.allUsers.filter((u) => !assigned.has(u.id));
	}

	function autoSubmit(event: Event) {
		const select = event.currentTarget as HTMLSelectElement;
		if (select.value) select.form?.requestSubmit();
	}
</script>

<div class="page-header">
	<h2>Jump Targets</h2>
	{#if isAdmin}
		<button onclick={() => (addHostOpen = true)}>Add Host</button>
	{/if}
</div>

<p class="text-muted">
	Hosts are internal servers you connect to through Callis. Each host gets an
	<strong>alias</strong> — a short name auto-generated from its label — that you use in your SSH
	config and with <code>ssh callis resolve &lt;alias&gt;</code>.
</p>

{#if errorMsg && !createFailed}
	<div class="flash flash-error" role="alert">{errorMsg}</div>
{/if}

{#if isAdmin}
	<Dialog title="Add Host" bind:open={addHostOpen}>
		{#if errorMsg && createFailed}
			<div class="flash flash-error" role="alert">{errorMsg}</div>
		{/if}
		<form method="post" action="?/create" use:enhance>
			<label for="label">Label</label>
			<input
				type="text"
				id="label"
				name="label"
				required
				placeholder="e.g. Production Web Server"
				value={(form && 'values' in form && form.values?.label) || ''}
				aria-describedby="host_label_help"
			/>
			<p id="host_label_help" class="helper-text">
				A friendly name for this host. It will be converted into an SSH alias automatically
				(e.g. "Production Web Server" → <code>production-web-server</code>). This alias is used
				in your SSH config and with <code>ssh callis resolve &lt;alias&gt;</code>.
			</p>

			<label for="hostname">Hostname / IP</label>
			<input
				type="text"
				id="hostname"
				name="hostname"
				required
				placeholder="192.168.1.50 or server.internal"
				value={(form && 'values' in form && form.values?.hostname) || ''}
				aria-describedby="hostname_help"
			/>
			<p id="hostname_help" class="helper-text">
				The internal address reachable from the Callis server. This is never exposed publicly.
			</p>

			<label for="port">SSH Port</label>
			<input
				type="number"
				id="port"
				name="port"
				value={(form && 'values' in form && form.values?.port) || '22'}
				min="1"
				max="65535"
			/>

			<label for="description">Description</label>
			<textarea
				id="description"
				name="description"
				rows="2"
				placeholder="Optional — purpose, environment, notes"
				value={(form && 'values' in form && form.values?.description) || ''}
			></textarea>

			<button type="submit">Add Host</button>
		</form>
	</Dialog>
{/if}

<figure>
	<table>
		<thead>
			<tr>
				<th>Label</th>
				<th>Alias</th>
				<th>Hostname</th>
				<th>Port</th>
				<th>Status</th>
				<th>Assigned Users</th>
				<th>SSH Config</th>
				{#if isAdmin}
					<th>Actions</th>
				{/if}
			</tr>
		</thead>
		<tbody>
			{#each data.hosts as host (host.id)}
				<tr>
					<td>{host.label}</td>
					<td class="alias-col">{host.alias}</td>
					<td><code>{host.hostname}</code></td>
					<td>{host.port}</td>
					<td>
						{#if host.is_active}
							<span class="badge badge-active">Active</span>
						{:else}
							<span class="badge badge-inactive">Inactive</span>
						{/if}
					</td>
					<td>
						{#each host.assigned_users as u (u.id)}
							<span class="badge">
								{u.username}
								{#if isAdmin}
									<form
										method="post"
										action="?/unassign"
										class="assign-form"
										use:enhance={({ cancel }) => {
											if (!window.confirm(`Unassign ${u.username}?`)) cancel();
										}}
									>
										<input type="hidden" name="id" value={host.id} />
										<input type="hidden" name="target_user_id" value={u.id} />
										<button type="submit" class="unassign-btn" aria-label="Unassign {u.username}">
											&times;
										</button>
									</form>
								{/if}
							</span>
						{:else}
							<span class="text-muted text-small">None</span>
						{/each}
						{#if isAdmin && host.is_active && assignableUsers(host).length > 0}
							<form method="post" action="?/assign" class="assign-form" use:enhance>
								<input type="hidden" name="id" value={host.id} />
								<select
									name="target_user_id"
									class="assign-select"
									aria-label="Assign user to {host.label}"
									onchange={autoSubmit}
								>
									<option value="">+ Assign</option>
									{#each assignableUsers(host) as u (u.id)}
										<option value={u.id}>{u.username}</option>
									{/each}
								</select>
								<noscript><button type="submit" class="assign-go outline">Go</button></noscript>
							</form>
						{/if}
					</td>
					<td>
						<details>
							<summary class="text-small">Show</summary>
							<pre class="ssh-config">{sshConfigBlock(host)}</pre>
						</details>
					</td>
					{#if isAdmin}
						<td class="actions">
							{#if host.is_active}
								<form method="post" action="?/deactivate" use:enhance>
									<input type="hidden" name="id" value={host.id} />
									<button type="submit" class="outline secondary">Deactivate</button>
								</form>
							{/if}
							<form
								method="post"
								action="?/delete"
								use:enhance={({ cancel }) => {
									if (!window.confirm(`Delete host ${host.label}? This cannot be undone.`)) cancel();
								}}
							>
								<input type="hidden" name="id" value={host.id} />
								<button type="submit" class="outline contrast">Delete</button>
							</form>
						</td>
					{/if}
				</tr>
			{/each}
		</tbody>
	</table>
</figure>

{#if data.hosts.length === 0}
	<p class="text-muted">
		No hosts configured yet.
		{#if isAdmin}
			Click <strong>Add Host</strong> above to register your first internal server. Once added,
			assign users so they can connect through the bastion.
		{:else}
			Ask an administrator to add hosts and assign you to them.
		{/if}
	</p>
{/if}

{#if isAdmin && data.deployKey}
	<hr />
	<div class="page-header">
		<h3>Callis Server Key</h3>
	</div>
	<p class="text-muted">
		Add this public key to each target host's <code>~/.ssh/authorized_keys</code> (or the
		relevant system user's authorized_keys) to allow Callis to authenticate when connecting
		directly to that host. This key is unique to this Callis instance.
	</p>
	<div class="ssh-config-actions">
		<CopyButton text={data.deployKey} />
	</div>
	<pre class="ssh-config">{data.deployKey}</pre>
	<p class="text-small text-muted">
		On each target host, open <code>~/.ssh/authorized_keys</code> in a text editor and paste the
		copied key above on its own line.
	</p>
{/if}
