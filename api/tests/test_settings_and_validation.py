from core import (
    CONFIGURABLE_SETTINGS,
    RESERVED_USERNAMES,
    USERNAME_RE,
    get_effective_settings,
    slugify,
)


def test_slugify_basic():
    assert slugify("Production Web Server") == "production-web-server"
    assert slugify("  Mac Mini  ") == "mac-mini"
    assert slugify("a__b!!c") == "a-b-c"
    assert slugify("---") == "host"
    assert slugify("") == "host"


def test_username_regex():
    for good in ("alice", "a", "bob-2", "web_ops", "a" + "b" * 31):
        assert USERNAME_RE.match(good), good
    for bad in ("Alice", "1abc", "-abc", "", "a" * 33, "bob smith", "bob$"):
        assert not USERNAME_RE.match(bad), bad


def test_reserved_usernames_include_system_accounts():
    assert "root" in RESERVED_USERNAMES
    assert "sshd" in RESERVED_USERNAMES


def test_effective_settings_defaults():
    result = get_effective_settings({})
    assert result["instance_name"] == "Callis"
    assert result["max_keys_per_user"] == 5
    # env-var values expressed in minutes for the UI
    assert result["session_idle_timeout"] == 30
    assert result["session_max_lifetime"] == 480


def test_effective_settings_db_override():
    result = get_effective_settings({"instance_name": "My Bastion", "max_keys_per_user": "10"})
    assert result["instance_name"] == "My Bastion"
    assert result["max_keys_per_user"] == 10


def test_effective_settings_ignores_invalid_int_override():
    result = get_effective_settings({"max_keys_per_user": "not-a-number"})
    assert result["max_keys_per_user"] == 5


def test_effective_settings_ignores_readonly_override():
    result = get_effective_settings({"ssh_port": "9999"})
    assert result["ssh_port"] == 2222


def test_every_setting_has_required_metadata():
    for key, meta in CONFIGURABLE_SETTINGS.items():
        assert meta["type"] in {"str", "text", "int", "choice"}, key
        assert meta["label"], key
        assert meta["group"], key
        assert "default" in meta, key
        if meta["type"] == "choice":
            assert meta.get("choices"), key
