/** Typed mirror of the FastAPI /api/v1 response schemas (api/schemas.py).
 *  The backend is the single source of truth; these types only describe it. */

export interface User {
	id: string;
	username: string;
	display_name: string;
	email: string | null;
	role: 'admin' | 'operator' | 'readonly';
	is_active: boolean;
	totp_enrolled: boolean;
	created_at: string;
	last_login_at: string | null;
}

export interface UserListItem extends User {
	key_count: number;
}

export interface UserRef {
	id: string;
	username: string;
}

export interface SSHKey {
	id: string;
	label: string;
	key_type: string;
	fingerprint: string;
	is_active: boolean;
	created_at: string;
	last_used_at: string | null;
}

export interface Host {
	id: string;
	label: string;
	alias: string;
	hostname: string;
	port: number;
	description: string | null;
	is_active: boolean;
	created_at: string;
	assigned_users: UserRef[];
}

export interface AuditEntry {
	id: string;
	timestamp: string;
	action: string;
	actor_username: string | null;
	target_type: string | null;
	target_id: string | null;
	source_ip: string | null;
	detail: Record<string, unknown> | unknown[] | string | null;
}

export interface AuditPage {
	entries: AuditEntry[];
	page: number;
	total_pages: number;
	total: number;
	actions: string[];
	users: UserRef[];
}

export interface Meta {
	instance_name: string;
	version: string;
	motd: string;
	ssh_host: string;
	ssh_port: number;
	base_url: string;
	setup_needed: boolean;
}

export interface UserDetail {
	user: User;
	keys: SSHKey[];
	assigned_hosts: Host[];
	ssh_host: string;
	ssh_port: number;
	roles: string[];
}

export interface Dashboard {
	active_users: number;
	active_hosts: number;
	user_key_count: number;
	recent_audit: AuditEntry[];
	ssh_host: string;
	ssh_port: number;
}

export interface SettingField {
	key: string;
	label: string;
	help: string;
	type: 'str' | 'text' | 'int' | 'choice';
	value: string | number;
	group: string;
	choices: string[] | null;
	min: number | null;
	max: number | null;
	readonly: boolean;
}

export interface Settings {
	fields: SettingField[];
	installer_url: string;
}

export interface TOTPSetup {
	qr_png_b64: string;
	secret: string;
}

export interface Session {
	user: User;
}
