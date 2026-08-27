"""`pirewall.api.auth`: password hashing, sessions, Admin PC IP restriction (spec §29)."""

from datetime import UTC, datetime, timedelta

import pytest

from pirewall.api.auth import (
    Authenticator,
    SessionStore,
    enforce_admin_pc_ip,
    hash_password,
    verify_password,
)
from pirewall.core.exceptions import AuthenticationError

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_hash_password_produces_a_verifiable_hash() -> None:
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed) is True


def test_verify_password_rejects_wrong_password() -> None:
    hashed = hash_password("correct horse battery staple")
    assert verify_password("wrong password", hashed) is False


def test_verify_password_rejects_malformed_hash() -> None:
    assert verify_password("anything", "not-a-valid-hash-format") is False


def test_hash_password_never_produces_the_same_hash_twice() -> None:
    """Different random salts each time — hashes are never stored/compared as plaintext."""
    first = hash_password("same password")
    second = hash_password("same password")
    assert first != second
    assert verify_password("same password", first)
    assert verify_password("same password", second)


def test_hash_password_output_does_not_contain_the_plaintext() -> None:
    password = "unmistakable-plaintext-marker"
    hashed = hash_password(password)
    assert password not in hashed


def test_session_store_create_and_validate() -> None:
    store = SessionStore(token_expiry_seconds=3600)
    session = store.create("admin", NOW)
    assert store.validate(session.token, NOW) == session


def test_session_store_expired_token_is_rejected() -> None:
    store = SessionStore(token_expiry_seconds=60)
    session = store.create("admin", NOW)
    assert store.validate(session.token, NOW + timedelta(seconds=61)) is None


def test_session_store_unknown_token_is_rejected() -> None:
    store = SessionStore(token_expiry_seconds=3600)
    assert store.validate("nonexistent-token", NOW) is None


def test_session_store_invalidate() -> None:
    store = SessionStore(token_expiry_seconds=3600)
    session = store.create("admin", NOW)
    store.invalidate(session.token)
    assert store.validate(session.token, NOW) is None


def test_authenticator_login_success() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    session = authenticator.login("admin", "secret", NOW)
    assert session.username == "admin"


def test_authenticator_login_wrong_password_raises() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    with pytest.raises(AuthenticationError):
        authenticator.login("admin", "wrong", NOW)


def test_authenticator_login_wrong_username_raises() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    with pytest.raises(AuthenticationError):
        authenticator.login("not-admin", "secret", NOW)


def test_authenticator_authenticate_valid_token() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    session = authenticator.login("admin", "secret", NOW)
    assert authenticator.authenticate(session.token, NOW).username == "admin"


def test_authenticator_authenticate_invalid_token_raises() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    with pytest.raises(AuthenticationError):
        authenticator.authenticate("bogus", NOW)


def test_authenticator_logout_invalidates_session() -> None:
    authenticator = Authenticator("admin", hash_password("secret"), SessionStore(3600))
    session = authenticator.login("admin", "secret", NOW)
    authenticator.logout(session.token)
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(session.token, NOW)


def test_enforce_admin_pc_ip_allows_configured_ip() -> None:
    enforce_admin_pc_ip("192.168.1.50", "192.168.1.50", restrict=True)  # must not raise


def test_enforce_admin_pc_ip_rejects_other_ip() -> None:
    with pytest.raises(AuthenticationError):
        enforce_admin_pc_ip("203.0.113.9", "192.168.1.50", restrict=True)


def test_enforce_admin_pc_ip_rejects_missing_client_host() -> None:
    with pytest.raises(AuthenticationError):
        enforce_admin_pc_ip(None, "192.168.1.50", restrict=True)


def test_enforce_admin_pc_ip_skipped_when_restriction_disabled() -> None:
    enforce_admin_pc_ip("203.0.113.9", "192.168.1.50", restrict=False)  # must not raise
