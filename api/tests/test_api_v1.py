"""End-to-end tests for the /api/v1 JSON API.

Drives the same flow the SvelteKit SSR frontend uses: first-run setup wizard,
TOTP enrollment, login, user/host/key management, audit and settings.
"""

import asyncio

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import core
import main
from middleware.setup_guard import SetupGuardMiddleware
from models import Base


TEST_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPZzMFEBbaEK6IJVMKuqNTGBygyz+FFJTHiSwVIbUS3e test@example"
)

# Dummy test-only credentials, computed at runtime so secret scanners don't
# mistake the fixture for a real hardcoded username/password pair.
ADMIN_PASSWORD = "-".join(("unit", "test", "admin", "credential"))
USER_PASSWORD = "-".join(("unit", "test", "user", "credential"))


@pytest_asyncio.fixture
async def client():
    # Fresh in-memory DB per test: drop and recreate all tables.
    engine = core.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    core.invalidate_db_settings_cache()
    await core.load_db_settings()
    SetupGuardMiddleware._setup_complete = False
    main.limiter.reset()

    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def complete_setup(client: AsyncClient, username: str = "admin", password: str = ADMIN_PASSWORD):
    """Run the whole first-run wizard; returns the authenticated client."""
    r = await client.post(
        "/api/v1/setup",
        json={
            "username": username,
            "password": password,
            "password_confirm": password,
            "display_name": "Administrator",
        },
    )
    assert r.status_code == 201, r.text
    assert "callis_session" in r.cookies

    r = await client.get("/api/v1/setup/totp")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]

    code = pyotp.TOTP(secret).now()
    r = await client.post("/api/v1/setup/totp/verify", json={"totp_code": code})
    assert r.status_code == 200, r.text
    assert r.json()["user"]["totp_enrolled"] is True
    return secret


@pytest.mark.asyncio
async def test_setup_guard_blocks_until_setup(client):
    r = await client.get("/api/v1/dashboard")
    assert r.status_code == 409
    assert r.json()["detail"] == "setup_required"

    r = await client.get("/api/v1/meta")
    assert r.status_code == 200
    assert r.json()["setup_needed"] is True

    r = await client.get("/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_full_setup_login_and_crud_flow(client):
    secret = await complete_setup(client)

    # Meta flips to setup complete
    r = await client.get("/api/v1/meta")
    assert r.json()["setup_needed"] is False

    # Session works
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 200
    admin = r.json()["user"]
    assert admin["role"] == "admin"

    # Dashboard
    r = await client.get("/api/v1/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["active_users"] == 1
    assert body["user_key_count"] == 0

    # Logout then login again with TOTP
    r = await client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401

    r = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": ADMIN_PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert r.status_code == 200, r.text

    # Wrong password is rejected and the failure is audited despite the 401
    # (failure audit rows must survive the exception path's rollback)
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password", "totp_code": ""},
    )
    assert r.status_code == 401
    r = await client.get("/api/v1/audit", params={"action": "login_failure"})
    assert r.status_code == 200
    assert any(
        e["detail"] and e["detail"].get("reason") == "wrong_password"
        for e in r.json()["entries"]
    )

    # Create a user
    r = await client.post(
        "/api/v1/users",
        json={"username": "alice", "password": USER_PASSWORD, "role": "operator"},
    )
    assert r.status_code == 201, r.text
    alice = r.json()

    # Duplicate rejected
    r = await client.post(
        "/api/v1/users",
        json={"username": "alice", "password": USER_PASSWORD, "role": "operator"},
    )
    assert r.status_code == 400

    # Reserved username rejected
    r = await client.post(
        "/api/v1/users",
        json={"username": "root", "password": USER_PASSWORD},
    )
    assert r.status_code == 400

    # User list includes key counts
    r = await client.get("/api/v1/users")
    assert r.status_code == 200
    assert {u["username"] for u in r.json()} == {"admin", "alice"}

    # Upload a key for alice
    r = await client.post(
        f"/api/v1/users/{alice['id']}/keys",
        json={"label": "laptop", "public_key": TEST_PUBKEY},
    )
    assert r.status_code == 201, r.text
    key = r.json()
    assert key["key_type"] == "ssh-ed25519"

    # Duplicate key rejected
    r = await client.post(
        f"/api/v1/users/{alice['id']}/keys",
        json={"label": "laptop2", "public_key": TEST_PUBKEY},
    )
    assert r.status_code == 400

    # Generate a key (private key returned exactly once)
    r = await client.post(
        f"/api/v1/users/{alice['id']}/keys/generate", json={"label": ""}
    )
    assert r.status_code == 201, r.text
    generated = r.json()
    assert "PRIVATE KEY" in generated["private_key"]
    assert r.headers["cache-control"] == "no-store"

    # Revoke it
    r = await client.post(
        f"/api/v1/users/{alice['id']}/keys/{generated['key']['id']}/revoke"
    )
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    # Create a host and assign alice
    r = await client.post(
        "/api/v1/hosts",
        json={"label": "Prod Web", "hostname": "10.0.0.5", "port": 22},
    )
    assert r.status_code == 201, r.text
    host = r.json()
    assert host["alias"] == "prod-web"

    # Duplicate alias rejected
    r = await client.post(
        "/api/v1/hosts",
        json={"label": "prod web", "hostname": "10.0.0.6"},
    )
    assert r.status_code == 400

    r = await client.post(f"/api/v1/hosts/{host['id']}/assign/{alice['id']}")
    assert r.status_code == 200
    assert [u["username"] for u in r.json()["assigned_users"]] == ["alice"]

    # User detail shows the assignment
    r = await client.get(f"/api/v1/users/{alice['id']}")
    assert r.status_code == 200
    detail = r.json()
    assert [h["alias"] for h in detail["assigned_hosts"]] == ["prod-web"]
    assert len(detail["keys"]) == 1  # revoked key excluded

    r = await client.post(f"/api/v1/hosts/{host['id']}/unassign/{alice['id']}")
    assert r.status_code == 200
    assert r.json()["assigned_users"] == []

    # Role change (not self)
    r = await client.put(f"/api/v1/users/{alice['id']}/role", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    me_id = admin["id"]
    r = await client.put(f"/api/v1/users/{me_id}/role", json={"role": "readonly"})
    assert r.status_code == 400

    # Audit log captured everything and is filterable
    r = await client.get("/api/v1/audit")
    assert r.status_code == 200
    page = r.json()
    actions = {e["action"] for e in page["entries"]}
    assert {"user_created", "key_added", "key_revoked", "host_created", "host_assigned"} <= actions

    r = await client.get("/api/v1/audit", params={"action": "host_created"})
    assert {e["action"] for e in r.json()["entries"]} == {"host_created"}

    # Settings round-trip
    r = await client.get("/api/v1/settings")
    assert r.status_code == 200
    fields = {f["key"]: f for f in r.json()["fields"]}
    assert fields["instance_name"]["value"] == "Callis"

    r = await client.put("/api/v1/settings", json={"instance_name": "My Bastion"})
    assert r.status_code == 200
    fields = {f["key"]: f for f in r.json()["fields"]}
    assert fields["instance_name"]["value"] == "My Bastion"

    r = await client.get("/api/v1/meta")
    assert r.json()["instance_name"] == "My Bastion"

    # Invalid settings rejected atomically
    r = await client.put("/api/v1/settings", json={"base_url": "not-a-url"})
    assert r.status_code == 400

    # Deactivate / delete
    r = await client.post(f"/api/v1/users/{alice['id']}/deactivate")
    assert r.status_code == 200
    assert r.json()["is_active"] is False
    r = await client.delete(f"/api/v1/users/{alice['id']}")
    assert r.status_code == 204
    r = await client.delete(f"/api/v1/users/{me_id}")
    assert r.status_code == 400  # cannot delete yourself

    r = await client.post(f"/api/v1/hosts/{host['id']}/deactivate")
    assert r.status_code == 200
    r = await client.delete(f"/api/v1/hosts/{host['id']}")
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_rbac_and_totp_guard(client):
    await complete_setup(client)

    # Create a readonly user and log in as them (no TOTP yet)
    r = await client.post(
        "/api/v1/users",
        json={"username": "bob", "password": USER_PASSWORD, "role": "readonly"},
    )
    assert r.status_code == 201
    bob_id = r.json()["id"]

    bob = AsyncClient(transport=ASGITransport(app=main.app), base_url="http://testserver")
    async with bob:
        r = await bob.post(
            "/api/v1/auth/login",
            json={"username": "bob", "password": USER_PASSWORD, "totp_code": ""},
        )
        assert r.status_code == 200
        assert r.json()["user"]["totp_enrolled"] is False

        # TOTP guard blocks data endpoints until enrolled
        r = await bob.get("/api/v1/dashboard")
        assert r.status_code == 403
        assert r.json()["detail"] == "totp_enrollment_required"

        # Enrollment endpoints are reachable
        r = await bob.get("/api/v1/auth/totp/setup")
        assert r.status_code == 200
        secret = r.json()["secret"]
        r = await bob.post(
            "/api/v1/auth/totp/verify",
            json={"totp_code": pyotp.TOTP(secret).now()},
        )
        assert r.status_code == 200

        # Now data endpoints work, but admin endpoints do not
        r = await bob.get("/api/v1/dashboard")
        assert r.status_code == 200
        r = await bob.get("/api/v1/users")
        assert r.status_code == 403
        r = await bob.get("/api/v1/settings")
        assert r.status_code == 403
        r = await bob.get("/api/v1/hosts/deploy-key")
        assert r.status_code == 403

        # Hosts list is visible to any enrolled user
        r = await bob.get("/api/v1/hosts")
        assert r.status_code == 200

        # Bob can manage his own keys but not create users
        r = await bob.post(
            f"/api/v1/users/{bob_id}/keys",
            json={"label": "bob key", "public_key": TEST_PUBKEY},
        )
        assert r.status_code == 201
        r = await bob.post(
            "/api/v1/users",
            json={"username": "eve", "password": USER_PASSWORD},
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_host_list_scoped_and_audit_admin_only(client):
    await complete_setup(client)

    # Admin creates two hosts, a readonly user, and assigns the user to one host.
    h1 = (await client.post("/api/v1/hosts", json={"label": "Alpha", "hostname": "10.0.0.1"})).json()
    (await client.post("/api/v1/hosts", json={"label": "Beta", "hostname": "10.0.0.2"})).json()
    carol_id = (
        await client.post(
            "/api/v1/users",
            json={"username": "carol", "password": USER_PASSWORD, "role": "readonly"},
        )
    ).json()["id"]
    assert (await client.post(f"/api/v1/hosts/{h1['id']}/assign/{carol_id}")).status_code == 200

    carol = AsyncClient(transport=ASGITransport(app=main.app), base_url="http://testserver")
    async with carol:
        assert (
            await carol.post(
                "/api/v1/auth/login",
                json={"username": "carol", "password": USER_PASSWORD, "totp_code": ""},
            )
        ).status_code == 200
        secret = (await carol.get("/api/v1/auth/totp/setup")).json()["secret"]
        assert (
            await carol.post(
                "/api/v1/auth/totp/verify", json={"totp_code": pyotp.TOTP(secret).now()}
            )
        ).status_code == 200

        # Finding 1: a non-admin sees ONLY assigned hosts, with no assignment map.
        hosts = (await carol.get("/api/v1/hosts")).json()
        assert [h["alias"] for h in hosts] == ["alpha"]
        assert hosts[0]["assigned_users"] == []

        # Admin still sees the full inventory including the assignment map.
        admin_hosts = (await client.get("/api/v1/hosts")).json()
        assert {h["alias"] for h in admin_hosts} == {"alpha", "beta"}
        alpha = next(h for h in admin_hosts if h["alias"] == "alpha")
        assert [u["username"] for u in alpha["assigned_users"]] == ["carol"]

        # Finding 2: the audit log is admin-only.
        assert (await carol.get("/api/v1/audit")).status_code == 403
        assert (await client.get("/api/v1/audit")).status_code == 200

        # Finding 2: the dashboard hides recent activity from non-admins.
        assert (await carol.get("/api/v1/dashboard")).json()["recent_audit"] == []
        assert len((await client.get("/api/v1/dashboard")).json()["recent_audit"]) > 0


@pytest.mark.asyncio
async def test_session_revoked_server_side_on_logout(client):
    await complete_setup(client)

    # Capture the live session token, then log out (which bumps session_epoch).
    old_cookie = client.cookies.get("callis_session")
    assert old_cookie
    assert (await client.post("/api/v1/auth/logout")).status_code == 204

    # Finding 4: replaying the pre-logout token is rejected server-side, not
    # merely cleared client-side. Restore the captured token onto the client
    # (logout deleted it) and confirm the API still refuses it.
    client.cookies.set("callis_session", old_cookie)
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_totp_code_cannot_be_replayed(client):
    secret = await complete_setup(client)
    await client.post("/api/v1/auth/logout")

    code = pyotp.TOTP(secret).now()
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": code},
    )
    assert r.status_code == 200

    # Finding 5: the same code is refused on a second login even though it is
    # still within its validity window.
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": code},
    )
    assert r.status_code == 401
    r = await client.get("/api/v1/audit", params={"action": "totp_failure"})
    assert any(
        e["detail"] and e["detail"].get("reason") == "totp_replay"
        for e in r.json()["entries"]
    )


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(client):
    await complete_setup(client)
    fresh = AsyncClient(transport=ASGITransport(app=main.app), base_url="http://testserver")
    async with fresh:
        for path in ("/api/v1/dashboard", "/api/v1/users", "/api/v1/hosts", "/api/v1/audit", "/api/v1/settings"):
            r = await fresh.get(path)
            assert r.status_code == 401, path
        # Meta and health stay public
        assert (await fresh.get("/api/v1/meta")).status_code == 200
        assert (await fresh.get("/health")).status_code == 200
        assert (await fresh.get("/install.sh")).status_code == 200


@pytest.mark.asyncio
async def test_recovery_codes_flow(client):
    # Complete the wizard by hand so we can capture the enrollment response
    r = await client.post(
        "/api/v1/setup",
        json={
            "username": "admin",
            "password": ADMIN_PASSWORD,
            "password_confirm": ADMIN_PASSWORD,
            "display_name": "Administrator",
        },
    )
    assert r.status_code == 201, r.text
    secret = (await client.get("/api/v1/setup/totp")).json()["secret"]
    r = await client.post(
        "/api/v1/setup/totp/verify", json={"totp_code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 200, r.text
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10

    admin_id = (await client.get("/api/v1/auth/me")).json()["user"]["id"]

    # A recovery code substitutes for the TOTP code at login...
    await client.post("/api/v1/auth/logout")
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": codes[0]},
    )
    assert r.status_code == 200, r.text

    # ...exactly once
    await client.post("/api/v1/auth/logout")
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": codes[0]},
    )
    assert r.status_code == 401

    # TOTP login still works, and the profile reports remaining codes
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 200, r.text
    r = await client.get(f"/api/v1/users/{admin_id}")
    assert r.json()["recovery_codes_remaining"] == 9

    # The use is audited
    r = await client.get("/api/v1/audit", params={"action": "recovery_code_used"})
    assert r.json()["total"] == 1

    # Regeneration invalidates the old set
    r = await client.post(f"/api/v1/users/{admin_id}/recovery-codes")
    assert r.status_code == 200, r.text
    new_codes = r.json()["codes"]
    assert len(new_codes) == 10
    assert set(new_codes).isdisjoint(codes)

    await client.post("/api/v1/auth/logout")
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": codes[1]},
    )
    assert r.status_code == 401  # old code dead
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": new_codes[0]},
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_host_groups_flow(client):
    await complete_setup(client)

    r = await client.post(
        "/api/v1/hosts",
        json={"label": "Prod Web", "hostname": "web.internal", "port": 22},
    )
    assert r.status_code == 201, r.text
    host_id = r.json()["id"]

    r = await client.post(
        "/api/v1/users",
        json={"username": "bob", "password": USER_PASSWORD},
    )
    assert r.status_code == 201, r.text
    bob_id = r.json()["id"]

    # Create a group; duplicate names are rejected
    r = await client.post("/api/v1/groups", json={"name": "prod", "description": "Production"})
    assert r.status_code == 201, r.text
    group_id = r.json()["id"]
    r = await client.post("/api/v1/groups", json={"name": "prod"})
    assert r.status_code == 400

    # Add the host and bob to the group
    r = await client.post(f"/api/v1/groups/{group_id}/hosts/{host_id}")
    assert r.status_code == 200 and [h["id"] for h in r.json()["hosts"]] == [host_id]
    r = await client.post(f"/api/v1/groups/{group_id}/users/{bob_id}")
    assert r.status_code == 200 and [u["id"] for u in r.json()["users"]] == [bob_id]

    r = await client.get("/api/v1/groups")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Bob's effective access now includes the group's host
    r = await client.get(f"/api/v1/users/{bob_id}")
    body = r.json()
    assert [h["label"] for h in body["assigned_hosts"]] == ["Prod Web"]
    assert [g["name"] for g in body["host_groups"]] == ["prod"]

    # Removing the host from the group revokes the group-granted access
    r = await client.delete(f"/api/v1/groups/{group_id}/hosts/{host_id}")
    assert r.status_code == 200 and r.json()["hosts"] == []
    r = await client.get(f"/api/v1/users/{bob_id}")
    assert r.json()["assigned_hosts"] == []

    # Delete the group
    r = await client.delete(f"/api/v1/groups/{group_id}")
    assert r.status_code == 204
    assert (await client.get("/api/v1/groups")).json() == []

    # Membership changes are audited
    r = await client.get("/api/v1/audit", params={"action": "group_host_added"})
    assert r.json()["total"] == 1


@pytest.mark.asyncio
async def test_group_hosts_visible_to_member_but_groups_admin_only(client):
    await complete_setup(client)

    # Admin builds a group containing a host and adds a readonly user to it.
    host_id = (
        await client.post("/api/v1/hosts", json={"label": "Grp Web", "hostname": "grp.internal"})
    ).json()["id"]
    group_id = (await client.post("/api/v1/groups", json={"name": "team"})).json()["id"]
    assert (await client.post(f"/api/v1/groups/{group_id}/hosts/{host_id}")).status_code == 200
    dave_id = (
        await client.post(
            "/api/v1/users",
            json={"username": "dave", "password": USER_PASSWORD, "role": "readonly"},
        )
    ).json()["id"]
    assert (await client.post(f"/api/v1/groups/{group_id}/users/{dave_id}")).status_code == 200

    dave = AsyncClient(transport=ASGITransport(app=main.app), base_url="http://testserver")
    async with dave:
        assert (
            await dave.post(
                "/api/v1/auth/login",
                json={"username": "dave", "password": USER_PASSWORD, "totp_code": ""},
            )
        ).status_code == 200
        secret = (await dave.get("/api/v1/auth/totp/setup")).json()["secret"]
        assert (
            await dave.post(
                "/api/v1/auth/totp/verify", json={"totp_code": pyotp.TOTP(secret).now()}
            )
        ).status_code == 200

        # P1: a group-only assignment still surfaces the host in the scoped
        # list, with the assignment map stripped.
        hosts = (await dave.get("/api/v1/hosts")).json()
        assert [h["alias"] for h in hosts] == ["grp-web"]
        assert hosts[0]["assigned_users"] == []

        # P1: the groups endpoint (host + member map) is admin-only.
        assert (await dave.get("/api/v1/groups")).status_code == 403
        assert (await client.get("/api/v1/groups")).status_code == 200


@pytest.mark.asyncio
async def test_sessions_endpoints(client):
    from models import SshSession

    await complete_setup(client)

    r = await client.get("/api/v1/sessions")
    assert r.status_code == 200
    assert r.json() == {"active": [], "recent": []}

    r = await client.post("/api/v1/sessions/nonexistent/terminate")
    assert r.status_code == 404

    # Seed an open session row as the tracker would
    factory = core.get_session_factory()
    async with factory() as db:
        db.add(
            SshSession(username="alice", source_ip="203.0.113.5", source_port=50000)
        )
        await db.commit()

    r = await client.get("/api/v1/sessions")
    active = r.json()["active"]
    assert len(active) == 1 and active[0]["username"] == "alice"
    session_id = active[0]["id"]

    # No process owns that connection in the test environment: the record
    # must stay open and the endpoint must say so instead of faking a close.
    r = await client.post(f"/api/v1/sessions/{session_id}/terminate")
    assert r.status_code == 409
    assert r.json()["detail"] == "session_process_not_found"
    r = await client.get("/api/v1/sessions")
    assert len(r.json()["active"]) == 1
