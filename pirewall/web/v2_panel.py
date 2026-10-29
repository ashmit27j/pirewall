"""The control panel's v2 section: guard modes, panic, offenders, bindings, engine (phase 16).

Same rules as `pirewall.web.render`: every dynamic value goes through
`html.escape`, and values reach JS only through `data-` attributes read at
click time, never by interpolation into script source. The actions call the
JSON API (`pirewall.api.routes.guards`), which enforces everything that
matters: a session, the Admin PC, the password again for an ENFORCE flip,
and the typed confirmation for panic. This module only renders.
"""

import html
from dataclasses import dataclass, field

from pirewall.core.enums import GuardMode, GuardName
from pirewall.core.models.identity import Binding
from pirewall.ipc.protocol_v2 import EngineStats, GuardModes, OffenderEntry


@dataclass(frozen=True, slots=True)
class V2PanelState:
    """What the dashboard fetched for the v2 section. `None` + an error means that part failed."""

    guards: GuardModes | None = None
    guards_error: str | None = None
    offenders: tuple[OffenderEntry, ...] = ()
    bindings: tuple[Binding, ...] = ()
    engine: EngineStats | None = None
    errors: tuple[str, ...] = field(default_factory=tuple[str, ...])


_GUARD_HELP: dict[GuardName, str] = {
    GuardName.RAW: (
        "anti-spoof and per-MAC flood meters at LAN ingress (enforces only once bindings are seeded)"
    ),
    GuardName.INPUT: "traffic to the Pi itself: DNS, portal concurrency, closed-port scans",
    GuardName.FORWARD: (
        "traffic through the Pi to the Internet (stays observe until the G5 benign check)"
    ),
}

V2_SCRIPT = """<script>
function v2Post(url, body) {
  return fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
  }).then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); });
}
function v2SetGuard(button) {
  const guard = button.dataset.guard;
  const mode = button.dataset.mode;
  const body = {mode: mode};
  if (mode === "enforce") {
    const field = document.getElementById("guard-password-" + guard);
    if (!field || !field.value) { alert("Enter the admin password to switch a guard to enforce."); return; }
    body.password = field.value;
  } else if (!confirm("Switch the " + guard + " guard to observe? It will stop dropping traffic.")) {
    return;
  }
  v2Post("/api/v1/guards/" + encodeURIComponent(guard), body).then(function (res) {
    if (!res.ok) { alert("Failed: " + (res.data.detail || "unknown error")); return; }
    location.reload();
  }).catch(function (e) { alert("Request failed: " + e); });
}
function v2Panic() {
  const typed = prompt("PANIC deletes pirewall's v2 tables: every static guard, the anti-spoof " +
    "bindings and the adaptive sets. pirewall_base and the portal gate stay. Restoring needs " +
    "pirewall-start on the Pi.\\n\\nType panic to continue.");
  if (typed !== "panic") { return; }
  v2Post("/api/v1/firewall/panic", {confirm: "panic"}).then(function (res) {
    if (!res.ok) { alert("Failed: " + (res.data.detail || "unknown error")); return; }
    alert("Deleted: " + res.data.deleted_tables.join(", ") + "\\n\\nRestore on the Pi with:\\n" +
          res.data.restore_command);
    location.reload();
  }).catch(function (e) { alert("Request failed: " + e); });
}
document.addEventListener("click", function (event) {
  const guardButton = event.target.closest("button[data-guard]");
  if (guardButton) { v2SetGuard(guardButton); return; }
  if (event.target.closest("button[data-panic]")) { v2Panic(); }
});
</script>"""


def _e(value: object) -> str:
    return html.escape(str(value))


def _guard_row(guard: GuardName, mode: GuardMode) -> str:
    other = GuardMode.OBSERVE if mode is GuardMode.ENFORCE else GuardMode.ENFORCE
    badge = "badge-active" if mode is GuardMode.ENFORCE else "badge-shadow"
    password = ""
    if other is GuardMode.ENFORCE:
        password = (
            f'<input id="guard-password-{_e(guard.value)}" type="password" '
            'placeholder="admin password" autocomplete="current-password"> '
        )
    button = (
        f'<button type="button" data-guard="{_e(guard.value)}" data-mode="{_e(other.value)}">'
        f"Switch to {_e(other.value)}</button>"
    )
    return (
        f"<tr><td>{_e(guard.value)}</td><td><span class=\"badge {badge}\">{_e(mode.value)}</span></td>"
        f"<td>{_e(_GUARD_HELP[guard])}</td><td>{password}{button}</td></tr>"
    )


def _guards_table(state: V2PanelState) -> str:
    if state.guards is None:
        reason = state.guards_error or "guard modes unavailable"
        return f'<p class="error">Guard modes unavailable: {_e(reason)}</p>'
    modes = {
        GuardName.RAW: state.guards.raw,
        GuardName.INPUT: state.guards.input,
        GuardName.FORWARD: state.guards.forward,
    }
    rows = "".join(_guard_row(guard, modes[guard]) for guard in GuardName)
    return f"""
    <table>
      <tr><th>Guard</th><th>Mode</th><th>Covers</th><th></th></tr>
      {rows}
    </table>
    <p class="hint">Read back from the kernel at {_e(state.guards.read_at)}. Observe still counts
    and records offenders but drops nothing. Switching to enforce asks for the admin password again;
    every flip is an audit event. The kill switch sets every guard to observe.</p>
    """


def _offenders_table(offenders: tuple[OffenderEntry, ...]) -> str:
    rows = "".join(
        f"<tr><td>{_e(o.last_seen)}</td><td>{_e(o.mac)}</td><td>{_e(o.code.name)}</td>"
        f"<td>{_e(o.guard.value)}</td><td>{_e(o.guard_mode.value)}</td><td>{o.sustained_polls}</td></tr>"
        for o in offenders
    )
    empty = (
        '<tr><td colspan="6">No offenders published. The kernel offender poller arrives with the '
        "v2 policy engine (phase 17); until then this list stays empty.</td></tr>"
    )
    return f"""
    <table>
      <tr><th>Last seen</th><th>MAC</th><th>Code</th><th>Guard</th><th>Guard mode</th><th>Polls</th></tr>
      {rows or empty}
    </table>
    """


def _bindings_table(bindings: tuple[Binding, ...]) -> str:
    rows = "".join(
        f"<tr><td>{_e(b.ip)}</td><td>{_e(b.mac)}</td><td>{_e(b.source.value)}</td>"
        f"<td>{_e(b.expires_at) if b.expires_at is not None else '&mdash;'}</td></tr>"
        for b in sorted(bindings, key=lambda binding: int(binding.ip))
    )
    return f"""
    <table>
      <tr><th>IP</th><th>MAC</th><th>Source</th><th>Lease expires</th></tr>
      {rows or '<tr><td colspan="4">No bindings. Portal sign-in and anti-spoof need them.</td></tr>'}
    </table>
    """


def _engine_table(engine: EngineStats | None) -> str:
    if engine is None:
        return "<p>No engine counters published yet.</p>"
    cells = (
        ("Backend", engine.backend),
        ("Packet ring available", engine.has_packet_ring),
        ("Frames seen", engine.frames_seen),
        ("Kernel drops", engine.kernel_drops),
        ("Flows shed", engine.flows_shed),
        ("New-flow signals shed", engine.new_flow_signals_shed),
        ("Native panics caught", engine.panics_caught),
        ("Read at", engine.read_at),
    )
    rows = "".join(f"<tr><th>{_e(label)}</th><td>{_e(value)}</td></tr>" for label, value in cells)
    return f"<table>{rows}</table>"


def render_v2_section(state: V2PanelState) -> str:
    """The v2 panel body: guards (with toggles), panic, offenders, bindings, engine counters."""
    errors = "".join(f'<p class="error">{_e(error)}</p>' for error in state.errors)
    return f"""
    {errors}
    <h3>Static guards (ADDENDUM_4.md D2)</h3>
    {_guards_table(state)}
    <p><button type="button" class="kill-switch" data-panic="1">
      Panic: remove pirewall's v2 tables</button></p>
    <p class="hint">Panic deletes inet pirewall_adaptive, inet pirewall_static and arp
    pirewall_static_arp, and nothing else; the base ruleset and the portal gate stay. It asks you to
    type <code>panic</code>. Restore by re-running <code>sudo scripts/deployment/pirewall-start</code>
    on the Pi.</p>
    <h3>Kernel offenders</h3>
    {_offenders_table(state.offenders)}
    <h3>IP&harr;MAC bindings (ADDENDUM_4.md D3)</h3>
    {_bindings_table(state.bindings)}
    <h3>Capture engine</h3>
    {_engine_table(state.engine)}
    {V2_SCRIPT}
    """
