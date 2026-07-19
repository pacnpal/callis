import base64
import struct

import pytest

from core import generate_ssh_keypair, parse_ssh_public_key


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _make_rsa_key_blob(bits: int) -> str:
    """Synthesize an ssh-rsa wire-format public key with a modulus of `bits` bits."""
    e = (65537).to_bytes(3, "big")
    n = ((1 << (bits - 1)) | 1).to_bytes((bits + 7) // 8, "big")
    blob = _ssh_string(b"ssh-rsa") + _ssh_string(e) + _ssh_string(n)
    return f"ssh-rsa {base64.b64encode(blob).decode()}"


def test_generated_ed25519_key_parses():
    _, public_key = generate_ssh_keypair(comment="alice")
    info = parse_ssh_public_key(public_key)
    assert info["key_type"] == "ssh-ed25519"
    assert info["fingerprint"].startswith("SHA256:")
    assert info["public_key_text"].endswith(" alice")


def test_comment_is_preserved_and_normalized():
    _, public_key = generate_ssh_keypair()
    parsed = parse_ssh_public_key(public_key + "   my   laptop  ")
    assert parsed["public_key_text"].endswith(" my laptop")
    assert "\n" not in parsed["public_key_text"]


def test_rsa_4096_accepted():
    info = parse_ssh_public_key(_make_rsa_key_blob(4096))
    assert info["key_type"] == "ssh-rsa"


def test_rsa_2048_rejected():
    with pytest.raises(ValueError, match="4096"):
        parse_ssh_public_key(_make_rsa_key_blob(2048))


def test_ecdsa_rejected():
    blob = _ssh_string(b"ecdsa-sha2-nistp256") + _ssh_string(b"nistp256")
    key = f"ecdsa-sha2-nistp256 {base64.b64encode(blob).decode()}"
    with pytest.raises(ValueError, match="not allowed"):
        parse_ssh_public_key(key)


def test_type_mismatch_rejected():
    # Header claims ed25519 but the blob embeds ssh-rsa
    blob = _ssh_string(b"ssh-rsa") + _ssh_string(b"\x01\x00\x01")
    key = f"ssh-ed25519 {base64.b64encode(blob).decode()}"
    with pytest.raises(ValueError, match="mismatch"):
        parse_ssh_public_key(key)


def test_control_characters_rejected():
    _, public_key = generate_ssh_keypair()
    with pytest.raises(ValueError, match="control characters"):
        parse_ssh_public_key(public_key + "\ninjected")


def test_invalid_base64_rejected():
    with pytest.raises(ValueError, match="base64"):
        parse_ssh_public_key("ssh-ed25519 not-valid-base64!!!")


def test_missing_parts_rejected():
    with pytest.raises(ValueError, match="Invalid SSH public key"):
        parse_ssh_public_key("ssh-ed25519")


def test_generate_keypair_rejects_control_chars_in_comment():
    with pytest.raises(ValueError, match="control characters"):
        generate_ssh_keypair(comment="evil\ncomment")
