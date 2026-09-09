"""`PortalUserStore`: the on-disk LAN user accounts (ADDENDUM_3.md C3).

Owned and written by **pirewall-core only**. The portal process never opens
this file; it asks core to verify a credential over the portal RPC socket.
That keeps a single writer — no two-process race over the file, and
allowlist-driven provisioning stays automatically consistent with what the
portal will accept.

The file is JSON at `portal.user_store_path` (default
`/var/lib/pirewall/portal_users.json`), mode `0600`. It is meant to be
hand-editable, as the operator asked: it is plain JSON, one object per
user, and `scripts/deployment/portal_users.py` is the supported way to edit
it without hand-writing a scrypt hash.

Writes go through a temp-file-then-`os.replace` so a crash or a full disk
can never leave a truncated user file behind — the same
write-validated-then-rename discipline `scripts/deployment/configure.py`
uses for the config.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.portal import PortalUser
from pirewall.core.passwords import hash_password, verify_password

_FILE_MODE = 0o600
_DIR_MODE = 0o700


class PortalUserStore:
    """Load/save `PortalUser` records, keyed by username.

    Loads eagerly at construction so a malformed store is a startup failure
    with a clear message rather than a mid-session authentication error.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._users: dict[str, PortalUser] = {}
        self.reload()

    @property
    def path(self) -> Path:
        return self._path

    def reload(self) -> None:
        """Re-read the file. A missing file is an empty store, not an error."""
        if not self._path.is_file():
            self._users = {}
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"could not read portal user store {self._path}: {exc}") from exc
        if not isinstance(raw, list):
            raise ConfigurationError(f"portal user store {self._path} must contain a JSON list of users")
        users: dict[str, PortalUser] = {}
        for item in raw:  # pyright: ignore[reportUnknownVariableType]
            user = PortalUser.model_validate(item)
            users[user.username] = user
        self._users = users

    def list_users(self) -> list[PortalUser]:
        """Every account, username-sorted for a stable control-panel ordering."""
        return sorted(self._users.values(), key=lambda user: user.username)

    def get(self, username: str) -> PortalUser | None:
        return self._users.get(username)

    def has_demo_accounts(self) -> bool:
        """True while any seeded demo account survives (drives the startup warning + login banner)."""
        return any(user.is_demo for user in self._users.values())

    def verify(self, username: str, password: str) -> bool:
        """Verify a credential without revealing whether the username exists.

        An unknown username still runs a full scrypt derivation against a
        dummy hash, so the response time does not distinguish "no such user"
        from "wrong password".
        """
        user = self._users.get(username)
        if user is None:
            verify_password(password, _TIMING_DECOY)
            return False
        return verify_password(password, user.password_hash)

    def add(
        self,
        username: str,
        password: str,
        created_at: datetime,
        created_by: str,
        note: str = "",
        is_demo: bool = False,
    ) -> PortalUser:
        """Create an account and persist it. Raises `ConfigurationError` if it already exists."""
        if username in self._users:
            raise ConfigurationError(f"portal user {username!r} already exists")
        user = PortalUser(
            username=username,
            password_hash=hash_password(password),
            created_at=created_at,
            created_by=created_by,
            note=note,
            is_demo=is_demo,
        )
        self._users[username] = user
        self._persist()
        return user

    def set_password(self, username: str, password: str) -> PortalUser:
        """Replace one account's password. Raises `ConfigurationError` if it doesn't exist."""
        user = self._users.get(username)
        if user is None:
            raise ConfigurationError(f"portal user {username!r} does not exist")
        # Rotating a demo account's password takes it out of demo status:
        # the warning is about the *documented* credentials, not the name.
        updated = user.model_copy(update={"password_hash": hash_password(password), "is_demo": False})
        self._users[username] = updated
        self._persist()
        return updated

    def remove(self, username: str) -> bool:
        """Delete an account. Returns False if it wasn't there."""
        if self._users.pop(username, None) is None:
            return False
        self._persist()
        return True

    def _persist(self) -> None:
        payload = [user.model_dump(mode="json") for user in self.list_users()]
        parent = self._path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            # Temp file in the destination directory so `os.replace` is a
            # same-filesystem atomic rename rather than a copy.
            handle, staging = tempfile.mkstemp(dir=parent, prefix=".portal_users-", suffix=".json")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump(payload, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                os.chmod(staging, _FILE_MODE)
                os.replace(staging, self._path)
            except BaseException:
                Path(staging).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise ConfigurationError(f"could not write portal user store {self._path}: {exc}") from exc


# A real scrypt hash of an unguessable value, used only to equalize timing
# for unknown usernames in `verify`. Never matches any password a caller
# could supply, because nothing knows the input it was derived from.
_TIMING_DECOY = hash_password(os.urandom(32).hex())
