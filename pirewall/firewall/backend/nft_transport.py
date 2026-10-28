"""How `NftablesSetBackend` reaches the kernel: libnftables, or `nft -j -f -` (CLAUDE.md v2 dependencies).

Both transports take one nft JSON document (`{"nftables": [...]}`), run it
as **one transaction**, and return the parsed JSON output (list commands) or
an empty dict. Neither ever builds nft syntax from strings (spec §20).

* `LibNftablesTransport`: `python3-nftables`, ctypes over the system
  libnftables. Median 0.36 ms per set update in the sandbox
  (`docs/v2/v2/RESULTS.md` finding 9, env=sandbox). The Debian package
  installs into the system dist-packages; phase 16's
  `install_nftables_pth.sh` makes it importable from the uv venv.
* `SubprocessTransport`: `nft -j -f -`, one process per batch. Median 10 ms
  (sandbox), still far faster than the A3 rate cap needs. `shell=False`,
  JSON on stdin.

`select_transport()` prefers libnftables and falls back to the subprocess.
Preflight (phase 16) reports which one is in use through `kind`.

Linux-only and needs CAP_NET_ADMIN; Environment-dependent outside the
netns tier.
"""

import importlib
import json
import subprocess
import time
from collections.abc import Mapping
from typing import Any, Protocol, cast

from pirewall.core.enums import NftTransportKind
from pirewall.core.exceptions import FirewallError

_NFT_BINARY = "nft"
_TIMEOUT_SECONDS = 10


class NftTransport(Protocol):
    """Runs one nft JSON document as one transaction."""

    @property
    def kind(self) -> NftTransportKind:
        """Which transport this is."""
        ...

    def run(self, document: Mapping[str, object]) -> dict[str, object]:
        """Run `document`; return its parsed JSON output ({} when it prints nothing). Raises FirewallError."""
        ...


class SubprocessTransport:
    """`nft -j -f -` with the JSON document on stdin."""

    def __init__(self, binary: str = _NFT_BINARY) -> None:
        self._binary = binary

    @property
    def kind(self) -> NftTransportKind:
        return NftTransportKind.SUBPROCESS

    def run(self, document: Mapping[str, object]) -> dict[str, object]:
        try:
            result = subprocess.run(
                [self._binary, "-j", "-f", "-"],
                input=json.dumps(document),
                capture_output=True,
                text=True,
                check=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise FirewallError(f"'{self._binary}' binary not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError(f"nft command timed out: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            raise FirewallError(f"nft command failed: {exc.stderr.strip()}") from exc
        return _parse(result.stdout)


class LibNftablesTransport:
    """`python3-nftables`. Construction fails with `FirewallError` if the module cannot be imported."""

    def __init__(self) -> None:
        try:
            module = importlib.import_module("nftables")
        except ImportError as exc:
            raise FirewallError(f"python3-nftables is not importable: {exc}") from exc
        # Any: `python3-nftables` ships no type information (a ctypes wrapper).
        self._nft: Any = module.Nftables()
        self._nft.set_json_output(True)

    @property
    def kind(self) -> NftTransportKind:
        return NftTransportKind.LIBNFTABLES

    def run(self, document: Mapping[str, object]) -> dict[str, object]:
        rc, output, error = cast("tuple[int, object, str]", self._nft.json_cmd(dict(document)))
        if rc != 0:
            raise FirewallError(f"nft command failed: {str(error).strip()}")
        if isinstance(output, dict):
            return cast("dict[str, object]", output)
        return {}


class MeteredTransport:
    """Wraps a transport with call/failure/latency counters (phase 13: "a transport property and metrics")."""

    def __init__(self, inner: NftTransport) -> None:
        self._inner = inner
        self.calls = 0
        self.failures = 0
        self.total_seconds = 0.0

    @property
    def kind(self) -> NftTransportKind:
        return self._inner.kind

    def run(self, document: Mapping[str, object]) -> dict[str, object]:
        started = time.perf_counter()
        self.calls += 1
        try:
            return self._inner.run(document)
        except FirewallError:
            self.failures += 1
            raise
        finally:
            self.total_seconds += time.perf_counter() - started


def select_transport(prefer: NftTransportKind | None = None) -> NftTransport:
    """libnftables when importable (or when asked for), otherwise the subprocess fallback.

    `prefer=SUBPROCESS` forces the fallback. `prefer=LIBNFTABLES` raises if
    the module is missing rather than falling back silently.
    """
    if prefer is NftTransportKind.SUBPROCESS:
        return SubprocessTransport()
    try:
        return LibNftablesTransport()
    except FirewallError:
        if prefer is NftTransportKind.LIBNFTABLES:
            raise
        return SubprocessTransport()


def _parse(stdout: str) -> dict[str, object]:
    if not stdout.strip():
        return {}
    try:
        parsed: object = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise FirewallError(f"nft returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise FirewallError("nft returned JSON that is not an object")
    return cast("dict[str, object]", parsed)
