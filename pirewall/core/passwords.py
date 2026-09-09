"""Password hashing shared by every process that verifies a credential.

Extracted from `pirewall.api.auth` when the captive portal (ADDENDUM_3.md
C3) became a second consumer: pirewall-api verifies the single admin's
password, pirewall-core verifies portal users' passwords on their behalf,
and `scripts/deployment/` hashes new passwords at provisioning time. One
implementation, imported by all three — CLAUDE.md's "one canonical module"
rule applied to credential handling rather than feature extraction.

Lives under `pirewall.core` because dependencies flow one direction and
`core` has no backward dependents: `api`, `portal`, and `scripts` may all
import it, and it imports nothing of theirs.

Algorithm: stdlib `hashlib.scrypt` (N=2**14, r=8, p=1, 16-byte random
salt, 32-byte key), not bcrypt/argon2 — see `docs/ARCHITECTURE.md` for why
that avoids a dependency outside CLAUDE.md's allowed list.
"""

import hashlib
import hmac
import secrets

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_LENGTH = 32


def hash_password(password: str) -> str:
    """Hash `password` with scrypt and a fresh random salt. Returns `"<salt_hex>$<hash_hex>"`."""
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_LENGTH
    )
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time-compare `password` against a hash produced by `hash_password`.

    Returns `False` rather than raising on a malformed `stored_hash`: a
    corrupted or hand-edited credential must fail authentication, not take
    the process down.
    """
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    if not expected:
        return False
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


def generate_password(length: int = 16) -> str:
    """A URL-safe random password for provisioning a portal account (ADDENDUM_3.md C3).

    Returned in the clear exactly once, to be shown to the admin and never
    stored — only its `hash_password` output is persisted.
    """
    if length < 8:
        raise ValueError("generated passwords must be at least 8 characters")
    return secrets.token_urlsafe(length)[:length]
