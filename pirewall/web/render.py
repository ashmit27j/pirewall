"""Server-rendered control panel pages (spec §30).

Plain HTML + CSS + minimal vanilla JS (`fetch()` for actions) — no
frontend framework, and no templating library (`html.escape` on every
piece of dynamic content instead; see `docs/ARCHITECTURE.md`).

**Escaping is per-context, and `html.escape` only covers one of them.** It
is correct for element text and for attribute *values*, but not for a value
landing inside a JS string literal in an inline handler: the HTML parser
decodes `&#x27;` back to `'` before the JS engine parses the attribute, so
an escaped quote still terminates the string. Dynamic values therefore
reach JS through `data-` attributes read at click time (`_action_button`
plus the delegated listener in `_SCRIPT`), never by interpolation into
`onclick` source. Ids are additionally `urllib.parse.quote`d, since they
are being built into a URL path.

Read-only
except for the actions already exposed by the JSON API (spec §30, §45) —
this module never executes anything itself, it only renders links/forms
that call the same authenticated API endpoints a script could.
"""

import html
from collections.abc import Iterable
from urllib.parse import quote

from pirewall.core.enums import RuleStatus
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.portal import PortalSession, PortalUser
from pirewall.core.models.rule import FirewallRule
from pirewall.core.models.status import StatusResult
from pirewall.core.models.threat import ThreatAssessment

_STYLE = """<style>
body { font-family: system-ui, sans-serif; margin: 2rem; background: #f7f7f8; color: #1a1a1a; }
h1, h2, h3 { margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1rem; background: #fff; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
th { background: #eee; }
.badge { padding: 0.1rem 0.5rem; border-radius: 0.3rem; font-size: 0.8rem; color: #fff; }
.badge-shadow { background: #6c757d; }
.badge-active { background: #198754; }
.badge-pending { background: #fd7e14; }
.badge-rejected, .badge-removed, .badge-disabled { background: #adb5bd; }
.kill-switch { background: #b02a37; color: #fff; border: none; padding: 0.6rem 1.2rem; font-size: 1rem;
  border-radius: 0.3rem; cursor: pointer; }
.error { color: #b02a37; }
.hint { font-size: 0.8rem; color: #5c6b7a; margin: 0.4rem 0 0; }
form.inline { display: inline; }
.page-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
.help-btn { background: #0d6efd; color: #fff; border: none; border-radius: 0.3rem; padding: 0.5rem 1rem;
  font-size: 0.9rem; cursor: pointer; }
.panel { margin-bottom: 1.5rem; }
.panel-toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
.panel-toolbar h2 { margin: 0; }
.panel-controls button { background: #fff; border: 1px solid #ccc; border-radius: 0.3rem;
  padding: 0.15rem 0.55rem; margin-left: 0.35rem; font-size: 0.8rem; cursor: pointer; }
.panel-controls button:hover { background: #eee; }
.panel-body[hidden] { display: none; }
dialog { max-width: 46rem; width: 90%; border-radius: 0.5rem; border: 1px solid #ccc;
  padding: 1.5rem 1.75rem; }
dialog::backdrop { background: rgba(0, 0, 0, 0.45); }
dialog table { font-size: 0.85rem; }
.dialog-close { float: right; background: #adb5bd; color: #fff; border: none; border-radius: 0.3rem;
  padding: 0.3rem 0.8rem; cursor: pointer; }
</style>"""

_SCRIPT = """<script>
async function pirewallCall(method, url, body) {
  const opts = {method: method};
  if (body !== undefined) {
    opts.headers = {"Content-Type": "application/json"};
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  if (!res.ok) { alert("Action failed: " + res.status); return; }
  location.reload();
}
function confirmKillSwitch() {
  if (confirm("This immediately reverts to SHADOW mode and removes every active adaptive rule. Continue?")) {
    pirewallCall("POST", "/api/v1/firewall/kill-switch");
  }
}
function addAllowlistEntry(event) {
  event.preventDefault();
  const form = event.target;
  const body = {target: form.target.value, reason: form.reason.value};
  if (form.port.value) body.port = parseInt(form.port.value, 10);
  if (form.protocol.value) body.protocol = form.protocol.value;
  if (form.portal_username.value) body.portal_username = form.portal_username.value;
  // A generated portal password comes back exactly once and is never
  // stored in the clear, so it has to be shown before the page reloads.
  fetch("/api/v1/allowlist", {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
  }).then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
    .then(function (res) {
      if (!res.ok) { alert("Failed: " + (res.data.detail || "unknown error")); return; }
      if (res.data.portal_password) {
        alert("Portal account created.\\n\\nUsername: " + res.data.portal_username +
              "\\nPassword: " + res.data.portal_password +
              "\\n\\nThis password is shown once and is not stored in readable form. " +
              "Write it down now.");
      }
      location.reload();
    }).catch(function (e) { alert("Request failed: " + e); });
}
function addPortalUser(event) {
  event.preventDefault();
  const form = event.target;
  const body = {username: form.username.value, note: form.note.value};
  if (form.password.value) body.password = form.password.value;
  fetch("/api/v1/portal/users", {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
  }).then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
    .then(function (res) {
      if (!res.ok) { alert("Failed: " + (res.data.detail || "unknown error")); return; }
      if (res.data.generated_password) {
        alert("Portal account created.\\n\\nUsername: " + res.data.user.username +
              "\\nPassword: " + res.data.generated_password +
              "\\n\\nThis password is shown once and is not stored in readable form. " +
              "Write it down now.");
      }
      location.reload();
    }).catch(function (e) { alert("Request failed: " + e); });
}
function togglePanel(id) {
  const body = document.getElementById("panel-body-" + id);
  const btn = document.querySelector('button[data-toggle="' + id + '"]');
  if (!body) return;
  body.hidden = !body.hidden;
  if (btn) btn.textContent = body.hidden ? "\\u25b8 Expand" : "\\u25be Collapse";
}
function csvField(text) {
  const value = (text || "").trim();
  return /[",\\n]/.test(value) ? '"' + value.replace(/"/g, '""') + '"' : value;
}
function exportPanel(id) {
  const body = document.getElementById("panel-body-" + id);
  const table = body ? body.querySelector("table") : null;
  if (!table) return;
  const csv = Array.from(table.querySelectorAll("tr"))
    .filter(function (row) { return !row.hidden; })
    .map(function (row) {
      return Array.from(row.children).map(function (cell) { return csvField(cell.textContent); }).join(",");
    })
    .join("\\n");
  const blob = new Blob([csv], {type: "text/csv"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "pirewall-" + id + "-" + new Date().toISOString().slice(0, 19).replace(/:/g, "-") + ".csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}
// "Clear view" never deletes anything on pirewall-core: it records a
// per-browser cutoff timestamp in localStorage and hides rows at or before
// it (compared against each row's first, Time, cell). Security event/audit
// history must stay recoverable server-side even after an operator clears
// their own view of it (spec-adjacent to A1's shadow-log audit trail).
function clearedCutoffKey(id) {
  return "pirewall-cleared-" + id;
}
function applyClearedCutoff(id) {
  const cutoffRaw = localStorage.getItem(clearedCutoffKey(id));
  if (!cutoffRaw) return;
  const cutoff = Date.parse(cutoffRaw);
  const body = document.getElementById("panel-body-" + id);
  const table = body ? body.querySelector("table") : null;
  if (!table) return;
  Array.from(table.querySelectorAll("tr")).forEach(function (row) {
    const firstCell = row.children[0];
    if (!firstCell || firstCell.tagName === "TH") return;
    const rowTime = Date.parse(firstCell.textContent.trim());
    if (!isNaN(rowTime) && rowTime <= cutoff) row.hidden = true;
  });
}
function clearPanelView(id) {
  if (!confirm("Hide rows currently visible in this section? This only affects your browser " +
    "\\u2014 nothing is deleted on pirewall-core, and reopening after new activity will show new rows.")) {
    return;
  }
  localStorage.setItem(clearedCutoffKey(id), new Date().toISOString());
  applyClearedCutoff(id);
}
// Rule/allowlist ids reach JS through data- attributes read at click time,
// never interpolated into an inline handler's JS source. html.escape() is
// correct for HTML attribute values but NOT for JS string literals: the
// parser decodes &#x27; back to ' before the JS engine sees the attribute,
// so an id containing a quote would break out of the string and execute.
// Delegated listener, so it also covers rows added by a future re-render.
document.addEventListener("click", function (event) {
  const actionButton = event.target.closest("button[data-action]");
  if (actionButton) { pirewallCall(actionButton.dataset.method, actionButton.dataset.action); return; }
  const toggleButton = event.target.closest("button[data-toggle]");
  if (toggleButton) { togglePanel(toggleButton.dataset.toggle); return; }
  const exportButton = event.target.closest("button[data-export]");
  if (exportButton) { exportPanel(exportButton.dataset.export); return; }
  const clearButton = event.target.closest("button[data-clear]");
  if (clearButton) { clearPanelView(clearButton.dataset.clear); return; }
});
document.querySelectorAll("[data-panel]").forEach(function (panel) {
  applyClearedCutoff(panel.dataset.panel);
});
</script>"""


def _e(value: object) -> str:
    return html.escape(str(value))


def _page(title: str, body: str) -> str:
    # Explicit charset, not left to `HTMLResponse`'s default header: the page emits raw
    # non-ASCII characters (em dashes, arrows) that mojibake under any transport that
    # doesn't send charset=utf-8 (e.g. a bare static file server) without this.
    head = f'<meta charset="utf-8"><title>{_e(title)}</title>{_STYLE}'
    return f"<!doctype html><html><head>{head}</head><body>{body}{_SCRIPT}</body></html>"


_LOGIN_SCRIPT = """<script>
async function pirewallLogin(event) {
  event.preventDefault();
  const form = event.target;
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: form.username.value, password: form.password.value}),
  });
  if (!res.ok) {
    document.getElementById("login-error").textContent = "Login failed (" + res.status + ")";
    return;
  }
  location.href = "/control-panel";
}
</script>"""


def render_login_page() -> str:
    body = f"""
    <h1>pirewall control panel</h1>
    <p class="error" id="login-error"></p>
    <form onsubmit="pirewallLogin(event)">
      <p><label>Username <input name="username" required autofocus></label></p>
      <p><label>Password <input name="password" type="password" required></label></p>
      <p><button type="submit">Log in</button></p>
    </form>
    {_LOGIN_SCRIPT}
    """
    return _page("pirewall — login", body)


def render_core_unavailable_page(detail: str) -> str:
    """The control panel when `pirewall-core` can't be reached (ADDENDUM.md A6, spec §26).

    A6's whole argument for the A4 process split is that pirewall-api
    survives a pirewall-core crash-loop and can therefore *report* it. That
    only holds if an unreachable core renders this instead of a 500.

    Deliberately states the enforcement consequence rather than just the
    error: with core down, no adaptive rule is being evaluated, and what
    the network is left with is whatever static base ruleset was loaded at
    deploy time (`deploy/firewall/`) — which under the default
    `failure.mode = "fail_open"` means traffic keeps flowing unfiltered.
    """
    body = f"""
    <h1>pirewall control panel</h1>
    <h2 class="error">pirewall-core is unreachable</h2>
    <p class="error">{_e(detail)}</p>
    <p>
      The control panel process is running, but it cannot reach
      <code>pirewall-core</code> over its local socket. While core is down
      <strong>no adaptive rule is being evaluated</strong>: enforcement is
      whatever the static base ruleset from <code>deploy/firewall/</code>
      already installed. With the default <code>failure.mode =
      "fail_open"</code> that means traffic continues to flow unfiltered.
    </p>
    <p>
      Check <code>systemctl status pirewall-core</code> on the Pi. A unit
      left in <code>failed</code> state means the crash-loop limit tripped
      (ADDENDUM.md A6); see <code>docs/DEPLOYMENT.md</code>.
    </p>
    """
    return _page("pirewall — core unreachable", body)


def _status_badge(status: RuleStatus) -> str:
    css_class = {
        RuleStatus.ACTIVE: "badge-active",
        RuleStatus.SHADOWED: "badge-shadow",
        RuleStatus.PENDING_APPROVAL: "badge-pending",
    }.get(status, "badge-rejected")
    return f'<span class="badge {css_class}">{_e(status.value)}</span>'


def _render_system_section(status: StatusResult) -> str:
    return f"""
    <table>
      <tr><th>pirewall-core status</th><td>reachable, uptime {status.uptime_seconds:.0f}s</td></tr>
      <tr><th>Enforcement mode</th><td>{_e(status.enforcement_mode.value)}</td></tr>
      <tr><th>Failure mode</th><td>{_e(status.failure_mode.value)}</td></tr>
      <tr><th>Active rules</th><td>{status.active_rule_count}</td></tr>
      <tr><th>Pending approvals</th><td>{status.pending_approval_count}</td></tr>
      <tr><th>Tracked flows (recent)</th><td>{status.tracked_flow_count}</td></tr>
      <tr><th>LightGBM loaded</th><td>{status.lightgbm_loaded}</td></tr>
      <tr><th>Isolation Forest loaded</th><td>{status.isolation_forest_loaded}</td></tr>
    </table>
    <button class="kill-switch" onclick="confirmKillSwitch()">Emergency kill-switch</button>
    """


def _render_threats_section(threats: Iterable[ThreatAssessment]) -> str:
    rows = "".join(
        f"<tr><td>{_e(t.assessed_at)}</td><td>{_e(t.source_ip)}</td><td>{_e(t.threat_level.value)}</td>"
        f"<td>{t.threat_score:.1f}</td><td>{_e(t.explanation)}</td></tr>"
        for t in threats
    )
    return f"""
    <table>
      <tr><th>Time</th><th>Source</th><th>Level</th><th>Score</th><th>Explanation</th></tr>
      {rows or '<tr><td colspan="5">No recent threat assessments.</td></tr>'}
    </table>
    """


def _render_network_section(capture_stats: CaptureStatistics | None) -> str:
    if capture_stats is None:
        row = '<tr><td colspan="4">No capture statistics reported yet.</td></tr>'
    else:
        row = (
            f"<tr><td>{_e(capture_stats.interface)}</td><td>{capture_stats.packets_seen}</td>"
            f"<td>{capture_stats.packets_dropped}</td><td>{capture_stats.packets_malformed}</td></tr>"
        )
    return f"""
    <table>
      <tr><th>Interface</th><th>Packets seen</th><th>Packets dropped</th><th>Packets malformed</th></tr>
      {row}
    </table>
    """


def _detection_evidence_summary(record: DetectionRecord) -> str:
    parts: list[str] = []
    if record.known_evidence is not None:
        parts.append(f"known: {_e(record.known_evidence.predicted_class)}")
    if record.anomaly_evidence is not None:
        parts.append(f"anomaly: {record.anomaly_evidence.anomaly_score:.2f}")
    if record.protocol_signature_evidence is not None:
        parts.append(f"protocol: {_e(record.protocol_signature_evidence.signature)}")
    return ", ".join(parts) or "&mdash;"


def _render_detections_section(detections: Iterable[DetectionRecord]) -> str:
    rows = "".join(
        f"<tr><td>{_e(d.recorded_at)}</td><td>{_e(d.flow_id[:8])}</td><td>{_detection_evidence_summary(d)}</td></tr>"
        for d in detections
    )
    return f"""
    <table>
      <tr><th>Time</th><th>Flow</th><th>Evidence</th></tr>
      {rows or '<tr><td colspan="3">No detections recorded yet.</td></tr>'}
    </table>
    """


def _render_firewall_section(rules: list[FirewallRule]) -> str:
    rows = "".join(
        f"<tr><td>{_e(rule.id[:8])}</td><td>{_e(rule.action.value)}</td>"
        f"<td>{_e(rule.source)} -&gt; {_e(rule.destination)}</td>"
        f"<td>{_status_badge(rule.status)}</td><td>{_e(rule.expires_at)}</td><td>{_e(rule.reason)}</td>"
        f"<td>{_rule_actions(rule)}</td></tr>"
        for rule in rules
    )
    return f"""
    <table>
      <tr><th>ID</th><th>Action</th><th>Source -&gt; Destination</th><th>Status</th>
          <th>Expires</th><th>Reason</th><th>Actions</th></tr>
      {rows or '<tr><td colspan="7">No rules yet.</td></tr>'}
    </table>
    """


def _action_button(label: str, method: str, url: str) -> str:
    """An action button whose target URL travels in `data-` attributes, not inline JS.

    Attribute values are the one context `html.escape` is actually correct
    for. Interpolating the same value into an inline `onclick`'s JS source
    is not safe even escaped — see the delegated listener in `_SCRIPT`.
    """
    return f'<button data-method="{_e(method)}" data-action="{_e(url)}">{_e(label)}</button>'


def _rule_actions(rule: FirewallRule) -> str:
    base = f"/api/v1/rules/{quote(rule.id, safe='')}"
    if rule.status is RuleStatus.PENDING_APPROVAL:
        return (
            _action_button("Approve", "POST", f"{base}/approve")
            + " "
            + _action_button("Reject", "POST", f"{base}/reject")
        )
    if rule.status is RuleStatus.ACTIVE:
        return (
            _action_button("Disable", "POST", f"{base}/disable")
            + " "
            + _action_button("Remove", "POST", f"{base}/remove")
        )
    return ""


def _render_shadow_log_section(rules: list[FirewallRule]) -> str:
    shadowed = [rule for rule in rules if rule.status is RuleStatus.SHADOWED]
    rows = "".join(
        f"<tr><td>{_e(rule.created_at)}</td><td>{_e(rule.action.value)}</td>"
        f"<td>{_e(rule.source)} -&gt; {_e(rule.destination)}</td><td>{_e(rule.reason)}</td></tr>"
        for rule in shadowed
    )
    return f"""
    <table>
      <tr><th>Time</th><th>Would-be action</th><th>Source -&gt; Destination</th><th>Reason</th></tr>
      {rows or '<tr><td colspan="4">Nothing shadowed yet.</td></tr>'}
    </table>
    """


def _allowlist_row(entry: AllowlistEntry) -> str:
    port = _e(entry.port) if entry.port is not None else "&mdash;"
    protocol = _e(entry.protocol.value) if entry.protocol is not None else "&mdash;"
    remove_button = _action_button("Remove", "DELETE", f"/api/v1/allowlist/{quote(entry.id, safe='')}")
    return (
        f"<tr><td>{_e(entry.target)}</td><td>{port}</td><td>{protocol}</td>"
        f"<td>{_e(entry.reason)}</td><td>{_e(entry.created_by)}</td><td>{remove_button}</td></tr>"
    )


def _render_allowlist_section(allowlist: list[AllowlistEntry]) -> str:
    rows = "".join(_allowlist_row(entry) for entry in allowlist)
    return f"""
    <table>
      <tr><th>Target</th><th>Port</th><th>Protocol</th><th>Reason</th><th>Added by</th><th></th></tr>
      {rows or '<tr><td colspan="6">Allowlist is empty.</td></tr>'}
    </table>
    <form onsubmit="addAllowlistEntry(event)">
      <input name="target" placeholder="192.168.1.50/32" required>
      <input name="port" placeholder="port (optional)">
      <input name="protocol" placeholder="tcp/udp/icmp (optional)">
      <input name="reason" placeholder="reason" required>
      <input name="portal_username" placeholder="portal username (optional)">
      <button type="submit">Add</button>
    </form>
    <p class="hint">Filling in a portal username also creates a captive-portal
    account for this entry and shows its generated password once. Leave it empty
    for devices that cannot sign in \u2014 a gateway, a printer, a server.</p>
    """


def _portal_user_row(user: PortalUser) -> str:
    demo = '<span class="badge badge-pending">DEMO</span>' if user.is_demo else "&mdash;"
    username = quote(user.username, safe="")
    return (
        f"<tr><td>{_e(user.username)}</td><td>{_e(user.created_at)}</td>"
        f"<td>{_e(user.created_by)}</td><td>{demo}</td><td>{_e(user.note)}</td>"
        f"<td>{_action_button('Reset password', 'POST', f'/api/v1/portal/users/{username}/password')} "
        f"{_action_button('Delete', 'DELETE', f'/api/v1/portal/users/{username}')}</td></tr>"
    )


def _render_portal_users_section(users: list[PortalUser]) -> str:
    rows = "".join(_portal_user_row(user) for user in users)
    warning = ""
    if any(user.is_demo for user in users):
        warning = (
            '<p class="hint error"><strong>Demo accounts are active.</strong> '
            "Their passwords are published in docs/SETUP.md. Delete them before this network "
            "carries real traffic.</p>"
        )
    return f"""
    {warning}
    <table>
      <tr><th>Username</th><th>Created</th><th>Created by</th><th>Demo</th><th>Note</th><th></th></tr>
      {rows or '<tr><td colspan="6">No portal accounts yet.</td></tr>'}
    </table>
    <form onsubmit="addPortalUser(event)">
      <input name="username" placeholder="username" required>
      <input name="password" type="password" placeholder="password (blank = generate one)">
      <input name="note" placeholder="note (optional)">
      <button type="submit">Create account</button>
    </form>
    """


def _portal_session_row(session: PortalSession) -> str:
    disconnect = _action_button(
        "Disconnect", "POST", f"/api/v1/portal/sessions/{quote(str(session.client_ip), safe='')}/logout"
    )
    return (
        f"<tr><td>{_e(session.username)}</td><td>{_e(session.client_ip)}</td>"
        f"<td>{_e(session.issued_at)}</td><td>{_e(session.expires_at)}</td>"
        f"<td>{disconnect}</td></tr>"
    )


def _render_portal_sessions_section(sessions: list[PortalSession]) -> str:
    rows = "".join(_portal_session_row(session) for session in sessions)
    return f"""
    <table>
      <tr><th>User</th><th>Device</th><th>Signed in</th><th>Expires</th><th></th></tr>
      {rows or '<tr><td colspan="5">No clients are signed in.</td></tr>'}
    </table>
    <p class="hint">Sessions expire in the kernel: each signed-in device is an
    nftables set element carrying its own timeout, so sign-out needs no timer here.
    Disconnecting removes that element immediately.</p>
    """


def _event_row(event: SecurityEvent) -> str:
    return (
        f"<tr><td>{_e(event.timestamp)}</td><td>{_e(event.severity.value)}</td>"
        f"<td>{_e(event.event_type.value)}</td><td>{_e(event.subsystem)}</td>"
        f"<td>{_e(event.reason or '')}</td></tr>"
    )


def _render_events_section(events: Iterable[SecurityEvent]) -> str:
    rows = "".join(_event_row(event) for event in events)
    return f"""
    <table>
      <tr><th>Time</th><th>Severity</th><th>Type</th><th>Subsystem</th><th>Reason</th></tr>
      {rows or '<tr><td colspan="5">No events recorded yet.</td></tr>'}
    </table>
    """


def _render_ml_section(models: Iterable[ModelMetadata]) -> str:
    rows = "".join(
        f"<tr><td>{_e(m.model_type.value)}</td><td>{_e(m.model_version)}</td>"
        f"<td>{_e(m.feature_schema_version)}</td><td>{m.is_placeholder}</td></tr>"
        for m in models
    )
    return f"""
    <table>
      <tr><th>Model</th><th>Version</th><th>Feature schema</th><th>Placeholder?</th></tr>
      {rows or '<tr><td colspan="4">No models loaded.</td></tr>'}
    </table>
    """


def _panel(section_id: str, title: str, html_block: str, *, loggy: bool) -> str:
    """Wrap a rendered section in a collapsible panel with export/clear-view controls.

    The heading lives in the toolbar, outside the collapsible body, so a
    collapsed panel still shows which section it is rather than disappearing
    into an unlabeled control strip.

    `loggy` gates the "Clear view" control to sections that are genuinely
    append-only logs with a Time-first column (Detections/Threats/Shadow
    log/Events) — clearing a state table like Firewall/Allowlist wouldn't
    mean anything, since those rows aren't chronological history.
    """
    controls = (
        f'<button type="button" data-toggle="{_e(section_id)}">&#x25be; Collapse</button>'
        f'<button type="button" data-export="{_e(section_id)}">Export CSV</button>'
    )
    if loggy:
        controls += f'<button type="button" data-clear="{_e(section_id)}">Clear view</button>'
    return (
        f'<div class="panel" data-panel="{_e(section_id)}">'
        f'<div class="panel-toolbar"><h2>{_e(title)}</h2><div class="panel-controls">{controls}</div></div>'
        f'<div class="panel-body" id="panel-body-{_e(section_id)}">{html_block}</div>'
        f"</div>"
    )


_HELP_SECTIONS: tuple[tuple[str, str], ...] = (
    ("System", "Core process health: uptime, current enforcement/failure mode, active and pending-approval "
     "rule counts, tracked flows, whether the ML models are loaded, and the emergency kill-switch."),
    ("Network", "Live packet-capture counters for the configured interface: packets seen, dropped, and "
     "malformed. Dropped/malformed rising steadily can mean capture is falling behind."),
    ("Detections", "Raw per-flow evidence from the detectors (known-attack classification, anomaly score, "
     "protocol signature) before it is combined into a threat assessment."),
    ("Threats", "Detections combined into a per-flow threat score, level, and plain-language explanation."),
    ("Firewall", "Every rule pirewall knows about, active or pending. Approve/Reject pending rules; "
     "Disable/Remove active ones."),
    ("Shadow log", "What pirewall would have enforced had it been in ACTIVE mode (ADDENDUM.md A1). Review "
     "this before ever leaving SHADOW mode."),
    ("Allowlist", "Targets that are never adaptively blocked, regardless of threat score (ADDENDUM.md A2). "
     "Add your admin PC, printers, or other trusted devices here."),
    ("Events", "The security event stream: warnings, blocks, and errors across every subsystem."),
    ("ML", "Which model files are loaded, their versions, feature-schema version, and whether a model is a "
     "placeholder rather than trained on real data."),
)

_HELP_SCENARIOS: tuple[tuple[str, str], ...] = (
    ("A rule is waiting for approval", "Firewall section → find the row with an orange Pending badge → "
     "Approve or Reject."),
    ("You want to permanently trust a device (admin PC, printer, etc.)", "Allowlist section → fill in the "
     "target IP/CIDR, optional port/protocol, and a reason → Add."),
    ("You need to stop all adaptive enforcement immediately", "System section → red \"Emergency "
     "kill-switch\" button. Reverts to SHADOW mode and removes every active adaptive rule (ADDENDUM.md A8)."),
    ("You want to see what pirewall would block before turning enforcement on", "Shadow log section — "
     "SHADOWED rows show what would have happened in ACTIVE mode."),
    ("A deployed rule turns out to be wrong", "Firewall section → find the ACTIVE row → Disable "
     "(temporary, reversible) or Remove (permanent)."),
    ("A table is getting long and hard to scan", "Click ▾ Collapse on that section's toolbar to hide it, "
     "or Clear view to hide the rows you've already reviewed (browser-only, nothing is deleted)."),
    ("You want to save or share a table for later review", "Click Export CSV on that section's toolbar to "
     "download its currently visible rows."),
    ("The page shows \"pirewall-core is unreachable\"", "pirewall-core itself is down; the control panel "
     "process is still up and reporting it (ADDENDUM.md A6). Check `systemctl status pirewall-core` on "
     "the Pi."),
)


def _help_button() -> str:
    onclick = "document.getElementById('help-dialog').showModal()"
    return f'<button type="button" class="help-btn" onclick="{onclick}">ⓘ Help</button>'


def _help_dialog() -> str:
    section_rows = "".join(
        f"<tr><td>{_e(name)}</td><td>{_e(desc)}</td></tr>" for name, desc in _HELP_SECTIONS
    )
    scenario_rows = "".join(
        f"<tr><td>{_e(scenario)}</td><td>{_e(action)}</td></tr>" for scenario, action in _HELP_SCENARIOS
    )
    return f"""
    <dialog id="help-dialog">
      <button type="button" class="dialog-close" onclick="document.getElementById('help-dialog').close()">
        Close</button>
      <h2>Dashboard help</h2>
      <h3>What each section shows</h3>
      <table>
        <tr><th>Section</th><th>What it shows</th></tr>
        {section_rows}
      </table>
      <h3>Common scenarios</h3>
      <table>
        <tr><th>If you want to&hellip;</th><th>Do this</th></tr>
        {scenario_rows}
      </table>
    </dialog>
    """


def _portal_panels(
    users: list[PortalUser] | None, sessions: list[PortalSession] | None
) -> str:
    """The two captive-portal panels, or nothing when the portal is disabled.

    `None` (rather than an empty list) means pirewall-core reported the
    portal as disabled, which is different from "enabled with nobody signed
    in" — so the panels are omitted entirely rather than shown empty and
    implying a portal that is not there.
    """
    if users is None and sessions is None:
        return ""
    return _panel(
        "portal-sessions",
        "Portal — signed-in devices (ADDENDUM_3.md C1)",
        _render_portal_sessions_section(sessions or []),
        loggy=False,
    ) + _panel(
        "portal-users",
        "Portal — LAN user accounts (ADDENDUM_3.md C3)",
        _render_portal_users_section(users or []),
        loggy=False,
    )


def render_dashboard(
    status: StatusResult,
    rules: list[FirewallRule],
    events: list[SecurityEvent],
    threats: list[ThreatAssessment],
    models: list[ModelMetadata],
    allowlist: list[AllowlistEntry],
    capture_stats: CaptureStatistics | None,
    detections: list[DetectionRecord],
    portal_users: list[PortalUser] | None = None,
    portal_sessions: list[PortalSession] | None = None,
) -> str:
    """Render the full control panel (spec §30's sections, plus the addendum additions)."""
    body = (
        f'<div class="page-header"><h1>pirewall control panel</h1>{_help_button()}</div>'
        + _panel("system", "System", _render_system_section(status), loggy=False)
        + _panel("network", "Network", _render_network_section(capture_stats), loggy=False)
        + _panel("detections", "Detections", _render_detections_section(detections), loggy=True)
        + _panel("threats", "Threats", _render_threats_section(threats), loggy=True)
        + _panel(
            "firewall", "Firewall — active & adaptive rules", _render_firewall_section(rules), loggy=False
        )
        + _panel(
            "shadow-log",
            "Shadow log (ADDENDUM.md A1) — what would have happened",
            _render_shadow_log_section(rules),
            loggy=True,
        )
        + _panel(
            "allowlist",
            "Allowlist (ADDENDUM.md A2) — never adaptively blocked",
            _render_allowlist_section(allowlist),
            loggy=False,
        )
        + _portal_panels(portal_users, portal_sessions)
        + _panel("events", "Events", _render_events_section(events), loggy=True)
        + _panel("ml", "ML", _render_ml_section(models), loggy=False)
        + _help_dialog()
    )
    return _page("pirewall control panel", body)
