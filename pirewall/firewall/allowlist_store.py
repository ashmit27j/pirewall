"""`AllowlistStore`: on-disk persistence for runtime-added allowlist entries (KNOWN_ISSUES.md #10).

`POST /api/v1/allowlist` used to mutate `FirewallManager`'s in-memory list
only — `config.firewall.allowlist` is re-read at startup, so every entry
added through the control panel was silently lost on the next restart, for
the mechanism that is supposed to outrank every adaptive rule
unconditionally (ADDENDUM.md A2).

Fixed the same way `pirewall.portal.store.PortalUserStore` already solved
an identical problem (ADDENDUM_3.md C3): a separate state file that the
config *seeds* rather than owns, written by exactly one process. This
keeps `pirewall-api` from needing write access to `config/local_config.toml`
(A4's whole point) — `FirewallManager`, which lives in `pirewall-core`, is
the only thing that ever opens this file. `config.firewall.allowlist`
stays the static, deployment-declared seed; entries added at runtime (via
the control panel or API) live here instead, and `FirewallManager` unions
both at startup.

Same write discipline as `PortalUserStore`: temp-file-then-`os.replace`,
so a crash or a full disk can never leave a truncated file behind.
"""

import json
import os
import tempfile
from pathlib import Path

from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.allowlist import AllowlistEntry

_FILE_MODE = 0o600
_DIR_MODE = 0o700


class AllowlistStore:
    """Load/save runtime-added `AllowlistEntry` records, keyed by id.

    Loads eagerly at construction so a malformed store is a startup
    failure with a clear message rather than a mid-session surprise.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._entries: dict[str, AllowlistEntry] = {}
        self.reload()

    @property
    def path(self) -> Path:
        return self._path

    def reload(self) -> None:
        """Re-read the file. A missing file is an empty store, not an error."""
        if not self._path.is_file():
            self._entries = {}
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"could not read allowlist store {self._path}: {exc}") from exc
        if not isinstance(raw, list):
            raise ConfigurationError(f"allowlist store {self._path} must contain a JSON list of entries")
        entries: dict[str, AllowlistEntry] = {}
        for item in raw:  # pyright: ignore[reportUnknownVariableType]
            entry = AllowlistEntry.model_validate(item)
            entries[entry.id] = entry
        self._entries = entries

    def list_entries(self) -> list[AllowlistEntry]:
        """Every persisted entry, id-sorted for a stable ordering."""
        return sorted(self._entries.values(), key=lambda entry: entry.id)

    def add(self, entry: AllowlistEntry) -> None:
        """Persist one entry. Overwrites any existing entry with the same id."""
        self._entries[entry.id] = entry
        self._persist()

    def remove(self, entry_id: str) -> bool:
        """Delete a persisted entry. Returns `False` if it wasn't there (e.g. a config-seeded entry)."""
        if self._entries.pop(entry_id, None) is None:
            return False
        self._persist()
        return True

    def _persist(self) -> None:
        payload = [entry.model_dump(mode="json") for entry in self.list_entries()]
        parent = self._path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            # Temp file in the destination directory so `os.replace` is a
            # same-filesystem atomic rename rather than a copy.
            handle, staging = tempfile.mkstemp(dir=parent, prefix=".allowlist-", suffix=".json")
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
            raise ConfigurationError(f"could not write allowlist store {self._path}: {exc}") from exc
