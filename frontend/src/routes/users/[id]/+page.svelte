<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/state';
	import CopyButton from '$lib/components/CopyButton.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import SshConfigSection from '$lib/components/SshConfigSection.svelte';
	import { formatDate, formatDateTime } from '$lib/format';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const me = $derived(page.data.user!);
	const target = $derived(data.detail.user);
	const generated = $derived(form && 'generated' in form ? form.generated : null);

	let generateOpen = $state(false);

	$effect(() => {
		// Keep the dialog open to show either the generated key or the error.
		if (form && ('generated' in form || 'generateError' in form)) generateOpen = true;
	});

	function downloadKey(text: string) {
		const blob = new Blob([text], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'id_ed25519';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		setTimeout(() => URL.revokeObjectURL(url), 0);
	}
</script>

<h2>{target.display_name}</h2>

{#if form && 'error' in form && form.error}
	<div class="flash flash-error" role="alert">{form.error}</div>
{/if}

<div class="grid">
	<div>
		<dl>
			<dt>Username</dt>
			<dd>{target.username}</dd>
			<dt>Email</dt>
			<dd>{target.email || 'Not set'}</dd>
			<dt>Role</dt>
			<dd>
				<span class="badge badge-{target.role}">{target.role}</span>
				{#if me.role === 'admin' && target.id !== me.id}
					<form method="post" action="?/changeRole" class="role-change-form" use:enhance>
						<select name="role" aria-label="Change role">
							{#each data.detail.roles as r (r)}
								<option value={r} selected={target.role === r}>{r}</option>
							{/each}
						</select>
						<button type="submit" class="outline btn-sm">Change Role</button>
					</form>
				{/if}
			</dd>
		</dl>
	</div>
	<div>
		<dl>
			<dt>Status</dt>
			<dd>
				{#if target.is_active}
					<span class="badge badge-active">Active</span>
				{:else}
					<span class="badge badge-inactive">Inactive</span>
				{/if}
			</dd>
			<dt>Authenticator App</dt>
			<dd>{target.totp_enrolled ? 'Enrolled' : 'Not enrolled'}</dd>
			<dt>Created</dt>
			<dd>{formatDateTime(target.created_at)}</dd>
			<dt>Last Login</dt>
			<dd>{formatDateTime(target.last_login_at)}</dd>
		</dl>
	</div>
</div>

<hr />

<div class="page-header">
	<h3>SSH Keys</h3>
	{#if target.is_active}
		<button type="button" class="outline btn-sm" onclick={() => (generateOpen = true)}>
			Generate Key
		</button>
	{/if}
</div>

{#if target.is_active}
	<form method="post" action="?/uploadKey" class="key-upload-form" use:enhance>
		<div class="grid">
			<div>
				<label for="label">Key Label</label>
				<input
					type="text"
					id="label"
					name="label"
					required
					placeholder="e.g. Work Laptop"
					value={(form && 'label' in form && form.label) || ''}
					aria-describedby="key_label_help"
				/>
				<p id="key_label_help" class="helper-text">
					A name to identify this key (e.g. the device it belongs to).
				</p>
			</div>
		</div>
		<label for="public_key">Public Key</label>
		<textarea
			id="public_key"
			name="public_key"
			required
			rows="3"
			placeholder="ssh-ed25519 &lt;public-key&gt; comment"
			aria-describedby="public_key_help"
			value={(form && 'public_key' in form && form.public_key) || ''}
		></textarea>
		<p id="public_key_help" class="helper-text">
			Paste the contents of your <code>.pub</code> file. Accepted types:
			<strong>Ed25519</strong> (recommended) or <strong>RSA 4096-bit+</strong>. Generate one
			with: <code>ssh-keygen -t ed25519</code>
		</p>
		<p aria-live="polite" role="alert" class="text-error">
			{(form && 'uploadError' in form && form.uploadError) || ''}
		</p>
		<button type="submit">Upload Key</button>
	</form>
{:else}
	<p class="text-muted">Key management is disabled for inactive users.</p>
{/if}

{#if data.detail.keys.length > 0}
	<figure>
		<table>
			<thead>
				<tr>
					<th>Label</th>
					<th>Type</th>
					<th>Fingerprint</th>
					<th>Added</th>
					<th>Last Used</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each data.detail.keys as key (key.id)}
					<tr>
						<td>{key.label}</td>
						<td><code>{key.key_type}</code></td>
						<td><code class="text-small">{key.fingerprint}</code></td>
						<td class="text-small">{formatDate(key.created_at)}</td>
						<td class="text-small">{formatDateTime(key.last_used_at)}</td>
						<td>
							<form
								method="post"
								action="?/revokeKey"
								use:enhance={({ cancel }) => {
									if (!window.confirm('Revoke this key? SSH access using this key will be denied immediately.')) cancel();
								}}
							>
								<input type="hidden" name="key_id" value={key.id} />
								<button type="submit" class="outline secondary btn-sm">Revoke</button>
							</form>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</figure>
{:else}
	<p class="text-muted">No active SSH keys. Upload one above to enable SSH access.</p>
{/if}

<hr />

<div class="page-header">
	<h3>SSH Config</h3>
</div>

<div class="ssh-config-section">
	<SshConfigSection
		username={target.username}
		sshHost={data.detail.ssh_host}
		sshPort={data.detail.ssh_port}
		assignedHosts={data.detail.assigned_hosts}
	/>
</div>

<Dialog title="Generate SSH Key" bind:open={generateOpen}>
	{#if generated}
		<div class="generated-key-display">
			<div class="flash flash-error" role="alert">
				<strong>⚠ Save this private key now.</strong> Copy or download it before closing this
				dialog.
			</div>
			<p class="text-small text-muted">
				<strong>Label:</strong> {generated.key.label} &mdash; <strong>Type:</strong>
				<code>{generated.key.key_type}</code> &mdash; <strong>Fingerprint:</strong>
				<code>{generated.key.fingerprint}</code>
			</p>
			<div class="ssh-config-actions">
				<CopyButton text={generated.private_key} />
				<button
					type="button"
					class="outline btn-sm"
					onclick={() => downloadKey(generated!.private_key)}
				>
					Download
				</button>
			</div>
			<pre class="ssh-config">{generated.private_key}</pre>
			<p class="text-small text-muted">
				Save this file as <code>~/.ssh/id_ed25519</code> (or a name of your choice) and set its
				permissions: <code>chmod 600 ~/.ssh/id_ed25519</code>. Update your SSH config's
				<code>IdentityFile</code> to point to the file you saved.
			</p>
			<button type="button" class="secondary" onclick={() => (generateOpen = false)}>
				I've saved my key &mdash; Close
			</button>
		</div>
	{:else}
		<p class="text-small text-muted">
			A new Ed25519 key pair will be generated. Copy or download the private key immediately
			&mdash; it cannot be recovered after this session.
		</p>
		<form method="post" action="?/generateKey" use:enhance>
			<label for="gen-label">Key Label</label>
			<input
				type="text"
				id="gen-label"
				name="label"
				placeholder="e.g. Work Laptop"
				aria-describedby="gen_label_help"
			/>
			<p id="gen_label_help" class="helper-text">
				A name to identify this key (e.g. the device it belongs to). Leave blank for a default
				name.
			</p>
			<p aria-live="polite" role="alert" class="text-error">
				{(form && 'generateError' in form && form.generateError) || ''}
			</p>
			<button type="submit">Generate Key</button>
		</form>
	{/if}
</Dialog>
