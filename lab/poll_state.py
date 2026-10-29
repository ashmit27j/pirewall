"""Poll pirewall-core's state over its RPC socket, read-only, as JSON lines (PLAN_FINAL §5).

    sudo -u <a member of pirewall-ipc> uv run python lab/poll_state.py --out FILE.jsonl \\
        [--socket /run/pirewall/core.sock] [--interval 1.0] [--duration S] [--api-url https://127.0.0.1:8443]

Each line is one poll: `{"t": wall seconds, "rules": [...], "events": [new events],
"offenders": [...], "guard_modes": {...}, "engine": {...}, "bindings": n,
"api_latency_ms": float | null, "errors": [...]}`.

**Read-only by construction.** `ReadOnlyCore` exposes only the read
operations (rules, events, offenders, bindings, guard modes, engine stats)
and holds the client privately; nothing here can approve, remove, flip a
guard, panic or kill-switch. It talks to core as a member of
`pirewall-ipc` and never imports `pirewall.firewall.backend` or
`pirewall.capture` (`tests/unit/test_lab_import_graph.py`). The four v2
reads are served from core's snapshots, never under its RPC lock (V2_CONTRACTS §9).

`--api-url` also times an unauthenticated `GET /api/v1/health` each poll,
for the admin API p95 during an attack (G1). The certificate is not
verified: it is the Pi's own self-signed loopback certificate.
"""

import argparse
import json
import ssl
import sys
import time
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/poll_state.py`

from lab.manifest import Json

__all__ = ["CoreReader", "Poller", "ReadOnlyCore", "rule_record", "sets_empty"]

DEFAULT_SOCKET: Final = "/run/pirewall/core.sock"


class CoreReader(Protocol):
    """The reads a poll makes. `ReadOnlyCore` adapts the real client; tests pass a fake."""

    def rules(self) -> list[dict[str, Json]]: ...
    def events(self) -> list[dict[str, Json]]: ...
    def offenders(self) -> list[dict[str, Json]]: ...
    def bindings(self) -> int: ...
    def guard_modes(self) -> dict[str, Json]: ...
    def engine(self) -> dict[str, Json]: ...


def rule_record(rule: object) -> dict[str, Json]:
    """A rule as the compact record a poll keeps."""
    from pirewall.core.models.rule import FirewallRule

    assert isinstance(rule, FirewallRule)
    return {
        "id": rule.id,
        "action": rule.action.value,
        "status": rule.status.value,
        "ip": None if rule.target is None else str(rule.target.ip),
        "mac": None if rule.target is None or rule.target.mac is None else str(rule.target.mac),
        "source": str(rule.source),
        "created_at": rule.created_at.isoformat(),
    }


class ReadOnlyCore:
    """The read-only face of `UnixSocketRpcClient`. The client itself is never exposed."""

    def __init__(self, socket_path: str, timeout_seconds: float = 2.0) -> None:
        from pirewall.ipc.client import UnixSocketRpcClient

        self.__client = UnixSocketRpcClient(socket_path, timeout_seconds=timeout_seconds)

    def rules(self) -> list[dict[str, Json]]:
        """Every rule core holds, compactly."""
        return [rule_record(rule) for rule in self.__client.list_rules()]

    def events(self) -> list[dict[str, Json]]:
        """Core's bounded event history."""
        return [json.loads(event.model_dump_json()) for event in self.__client.list_events()]

    def offenders(self) -> list[dict[str, Json]]:
        """The last `@offenders` poll."""
        return [json.loads(entry.model_dump_json()) for entry in self.__client.list_offenders()]

    def bindings(self) -> int:
        """How many bindings core holds (the list itself names household devices; not recorded)."""
        return len(self.__client.list_bindings())

    def guard_modes(self) -> dict[str, Json]:
        """The three guard modes as read from the kernel."""
        return json.loads(self.__client.get_guard_modes().model_dump_json())

    def engine(self) -> dict[str, Json]:
        """Capture-engine counters."""
        return json.loads(self.__client.get_engine_stats().model_dump_json())


_LIVE: Final = frozenset({"active", "pending_approval"})
_ENFORCING: Final = frozenset({"rate_limit", "block"})


def sets_empty(reader: CoreReader) -> bool:
    """No live RATE_LIMIT/BLOCK rule and no offender, per one read of core.

    What "the adaptive sets are empty" means for the campaign cooldown and
    the preflight: core's own view, read-only, never `nft list`.
    """
    live = [
        rule for rule in reader.rules() if rule.get("action") in _ENFORCING and rule.get("status") in _LIVE
    ]
    return not live and not reader.offenders()


def api_latency_ms(url: str, timeout: float = 2.0) -> float | None:
    """Milliseconds for `GET <url>/api/v1/health`, or None if it failed."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the Pi's own loopback certificate, lab measurement only
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(
            url.rstrip("/") + "/api/v1/health", timeout=timeout, context=context
        ) as reply:
            reply.read()
    except OSError:
        return None
    return (time.perf_counter() - started) * 1000.0


class Poller:
    """One poll at a time; remembers which events it has already written."""

    def __init__(
        self, reader: CoreReader, api_url: str | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self._reader = reader
        self._api_url = api_url
        self._clock = clock
        self._seen: set[str] = set()

    def poll(self) -> dict[str, Json]:
        """One record. Never raises: a failed read is listed under `errors`."""
        record: dict[str, Json] = {"t": self._clock()}
        errors: list[Json] = []
        reads: tuple[tuple[str, Callable[[], Json]], ...] = (
            ("rules", lambda: list[Json](self._reader.rules())),
            ("offenders", lambda: list[Json](self._reader.offenders())),
            ("bindings", self._reader.bindings),
            ("guard_modes", lambda: dict[str, Json](self._reader.guard_modes())),
            ("engine", lambda: dict[str, Json](self._reader.engine())),
        )
        for name, read in reads:
            try:
                record[name] = read()
            except Exception as exc:  # the poller outlives a core restart; record and carry on
                record[name] = None
                errors.append(f"{name}: {exc}")
        try:
            fresh = [event for event in self._reader.events() if str(event.get("id")) not in self._seen]
            self._seen.update(str(event.get("id")) for event in fresh)
            record["events"] = list[Json](fresh)
        except Exception as exc:
            record["events"] = []
            errors.append(f"events: {exc}")
        record["api_latency_ms"] = api_latency_ms(self._api_url) if self._api_url else None
        record["errors"] = errors
        return record


def run(
    poller: Poller,
    out: Path,
    interval: float,
    duration: float | None,
    should_stop: Callable[[], bool] = lambda: False,
) -> int:
    """Append polls to `out` every `interval` s until `duration` passes or `should_stop()`."""
    started = time.monotonic()
    count = 0
    with out.open("a", encoding="utf-8") as stream:
        while not should_stop() and (duration is None or time.monotonic() - started < duration):
            tick = time.monotonic()
            stream.write(json.dumps(poller.poll(), default=str) + "\n")
            stream.flush()
            count += 1
            time.sleep(max(0.0, interval - (time.monotonic() - tick)))
    return count


def main(argv: Sequence[str] | None = None) -> int:
    """Poll until `--duration` or Ctrl-C."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument("--api-url", default=None)
    args = parser.parse_args(argv)
    try:
        count = run(Poller(ReadOnlyCore(args.socket), args.api_url), args.out, args.interval, args.duration)
    except KeyboardInterrupt:
        return 0
    print(f"{count} polls -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
