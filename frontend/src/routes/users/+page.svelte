<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/state';
	import { confirm } from '$lib/actions/confirm';
	import Dialog from '$lib/components/Dialog.svelte';
	import { formatDate } from '$lib/format';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const me = $derived(page.data.user!);
	const errorMsg = $derived(form && 'error' in form && form.error ? form.error : null);
	const createFailed = $derived(!!(form && 'values' in form && form.values));
	let addUserOpen = $state(false);

	// Reopen the dialog when a create attempt failed so the error is visible;
	// close it after a successful create.
	$effect(() => {
		if (form && 'values' in form && form.values) addUserOpen = true;
		if (form && 'created' in form && form.created) addUserOpen = false;
	});
</script>

<div class="page-header">
	<h2>Users</h2>
	<button onclick={() => (addUserOpen = true)}>Add User</button>
</div>

<p class="text-muted">
	Manage who can access the bastion. Users need to set up an authenticator app before they can
	access the web UI. SSH access requires at least one SSH key and the appropriate host assignment.
</p>

{#if errorMsg && !createFailed}
	<div class="flash flash-error" role="alert">{errorMsg}</div>
{/if}

<Dialog title="Create User" bind:open={addUserOpen}>
	{#if errorMsg && createFailed}
		<div class="flash flash-error" role="alert">{errorMsg}</div>
	{/if}
	<form method="post" action="?/create" use:enhance>
		<label for="username">Username</label>
		<input
			type="text"
			id="username"
			name="username"
			required
			pattern="[a-z][a-z0-9_\-]{'{'}0,31{'}'}"
			title="Lowercase letters, numbers, hyphens, underscores. Must start with a letter. Max 32 chars."
			placeholder="johndoe"
			value={(form && 'values' in form && form.values?.username) || ''}
			aria-describedby="username_help"
		/>
		<p id="username_help" class="helper-text">
			This becomes their SSH login name. Lowercase letters, numbers, hyphens, and underscores
			only.
		</p>

		<label for="display_name">Display Name</label>
		<input
			type="text"
			id="display_name"
			name="display_name"
			placeholder="John Doe"
			value={(form && 'values' in form && form.values?.display_name) || ''}
		/>

		<label for="email">Email</label>
		<input
			type="email"
			id="email"
			name="email"
			placeholder="john@example.com"
			value={(form && 'values' in form && form.values?.email) || ''}
		/>

		<label for="password">Password</label>
		<input
			type="password"
			id="password"
			name="password"
			required
			minlength="8"
			aria-describedby="password_help"
		/>
		<p id="password_help" class="helper-text">
			Minimum 8 characters. The user will set up their authenticator app on first login.
		</p>

		<label for="role">Role</label>
		<select id="role" name="role">
			<option value="readonly">Read Only (view dashboard, hosts, audit, and manage own keys/profile)</option>
			<option value="operator">Operator (same access as read only: view dashboard, hosts, audit, and manage own keys/profile)</option>
			<option value="admin">Admin (all operator access, plus manage users)</option>
		</select>

		<button type="submit">Create User</button>
	</form>
</Dialog>

<figure>
	<table>
		<thead>
			<tr>
				<th>Username</th>
				<th>Display Name</th>
				<th>Role</th>
				<th>Status</th>
				<th>Keys</th>
				<th>Created</th>
				<th>Actions</th>
			</tr>
		</thead>
		<tbody>
			{#each data.users as u (u.id)}
				<tr>
					<td><a href="/users/{u.id}">{u.username}</a></td>
					<td>{u.display_name}</td>
					<td><span class="badge badge-{u.role}">{u.role}</span></td>
					<td>
						{#if u.is_active}
							<span class="badge badge-active">Active</span>
						{:else}
							<span class="badge badge-inactive">Inactive</span>
						{/if}
					</td>
					<td>{u.key_count}</td>
					<td class="text-small">{formatDate(u.created_at)}</td>
					<td class="actions">
						{#if u.id !== me.id}
							{#if u.is_active}
								<form method="post" action="?/deactivate" use:enhance>
									<input type="hidden" name="id" value={u.id} />
									<button type="submit" class="outline secondary">Deactivate</button>
								</form>
							{:else}
								<form method="post" action="?/activate" use:enhance>
									<input type="hidden" name="id" value={u.id} />
									<button type="submit" class="outline">Activate</button>
								</form>
							{/if}
							<form
								method="post"
								action="?/delete"
								use:confirm={`Delete user ${u.username}? This cannot be undone.`}
								use:enhance
							>
								<input type="hidden" name="id" value={u.id} />
								<button type="submit" class="outline contrast">Delete</button>
							</form>
						{:else}
							<span class="text-muted text-small">(you)</span>
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</figure>
