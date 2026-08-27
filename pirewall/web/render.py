"""Server-rendered control panel pages (spec §30).

Plain HTML + CSS + minimal vanilla JS (`fetch()` for actions) — no
frontend framework, and no templating library (`html.escape` on every
piece of dynamic content instead; see `docs/ARCHITECTURE.md`). Read-only
except for the actions already exposed by the JSON API (spec §30, §45) —
this module never executes anything itself, it only renders links/forms
that call the same authenticated API endpoints a script could.
"""

import html
from collections.abc import Iterable

from pirewall.core.enums import RuleStatus
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.rule import FirewallRule
from pirewall.core.models.status import StatusResult
from pirewall.core.models.threat import ThreatAssessment

_STYLE = """<style>
body { font-family: system-ui, sans-serif; margin: 2rem; background: #f7f7f8; color: #1a1a1a; }
h1, h2 { margin-top: 2rem; }
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
form.inline { display: inline; }
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
  pirewallCall("POST", "/api/v1/allowlist", body);
}
</script>"""


def _e(value: object) -> str:
    return html.escape(str(value))


def _page(title: str, body: str) -> str:
    head = f"<title>{_e(title)}</title>{_STYLE}"
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


def _status_badge(status: RuleStatus) -> str:
    css_class = {
        RuleStatus.ACTIVE: "badge-active",
        RuleStatus.SHADOWED: "badge-shadow",
        RuleStatus.PENDING_APPROVAL: "badge-pending",
    }.get(status, "badge-rejected")
    return f'<span class="badge {css_class}">{_e(status.value)}</span>'


def _render_system_section(status: StatusResult) -> str:
    return f"""
    <h2>System</h2>
    <table>
      <tr><th>pirewall-core status</th><td>running, uptime {status.uptime_seconds:.0f}s</td></tr>
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
    <h2>Threats</h2>
    <table>
      <tr><th>Time</th><th>Source</th><th>Level</th><th>Score</th><th>Explanation</th></tr>
      {rows or '<tr><td colspan="5">No recent threat assessments.</td></tr>'}
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
    <h2>Firewall — active &amp; adaptive rules</h2>
    <table>
      <tr><th>ID</th><th>Action</th><th>Source -&gt; Destination</th><th>Status</th>
          <th>Expires</th><th>Reason</th><th>Actions</th></tr>
      {rows or '<tr><td colspan="7">No rules yet.</td></tr>'}
    </table>
    """


def _rule_actions(rule: FirewallRule) -> str:
    rule_id = _e(rule.id)
    if rule.status is RuleStatus.PENDING_APPROVAL:
        return (
            f'<button onclick="pirewallCall(\'POST\', \'/api/v1/rules/{rule_id}/approve\')">Approve</button> '
            f'<button onclick="pirewallCall(\'POST\', \'/api/v1/rules/{rule_id}/reject\')">Reject</button>'
        )
    if rule.status is RuleStatus.ACTIVE:
        return (
            f'<button onclick="pirewallCall(\'POST\', \'/api/v1/rules/{rule_id}/disable\')">Disable</button> '
            f'<button onclick="pirewallCall(\'POST\', \'/api/v1/rules/{rule_id}/remove\')">Remove</button>'
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
    <h2>Shadow log (ADDENDUM.md A1) — what would have happened</h2>
    <table>
      <tr><th>Time</th><th>Would-be action</th><th>Source -&gt; Destination</th><th>Reason</th></tr>
      {rows or '<tr><td colspan="4">Nothing shadowed yet.</td></tr>'}
    </table>
    """


def _allowlist_row(entry: AllowlistEntry) -> str:
    port = _e(entry.port) if entry.port is not None else "&mdash;"
    protocol = _e(entry.protocol.value) if entry.protocol is not None else "&mdash;"
    remove_url = f"/api/v1/allowlist/{_e(entry.id)}"
    remove_button = f'<button onclick="pirewallCall(\'DELETE\', \'{remove_url}\')">Remove</button>'
    return (
        f"<tr><td>{_e(entry.target)}</td><td>{port}</td><td>{protocol}</td>"
        f"<td>{_e(entry.reason)}</td><td>{_e(entry.created_by)}</td><td>{remove_button}</td></tr>"
    )


def _render_allowlist_section(allowlist: list[AllowlistEntry]) -> str:
    rows = "".join(_allowlist_row(entry) for entry in allowlist)
    return f"""
    <h2>Allowlist (ADDENDUM.md A2) — never adaptively blocked</h2>
    <table>
      <tr><th>Target</th><th>Port</th><th>Protocol</th><th>Reason</th><th>Added by</th><th></th></tr>
      {rows or '<tr><td colspan="6">Allowlist is empty.</td></tr>'}
    </table>
    <form onsubmit="addAllowlistEntry(event)">
      <input name="target" placeholder="192.168.1.50/32" required>
      <input name="port" placeholder="port (optional)">
      <input name="protocol" placeholder="tcp/udp/icmp (optional)">
      <input name="reason" placeholder="reason" required>
      <button type="submit">Add</button>
    </form>
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
    <h2>Events</h2>
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
    <h2>ML</h2>
    <table>
      <tr><th>Model</th><th>Version</th><th>Feature schema</th><th>Placeholder?</th></tr>
      {rows or '<tr><td colspan="4">No models loaded.</td></tr>'}
    </table>
    """


def render_dashboard(
    status: StatusResult,
    rules: list[FirewallRule],
    events: list[SecurityEvent],
    threats: list[ThreatAssessment],
    models: list[ModelMetadata],
    allowlist: list[AllowlistEntry],
) -> str:
    """Render the full control panel (spec §30's sections, plus the addendum additions)."""
    body = (
        "<h1>pirewall control panel</h1>"
        + _render_system_section(status)
        + _render_threats_section(threats)
        + _render_firewall_section(rules)
        + _render_shadow_log_section(rules)
        + _render_allowlist_section(allowlist)
        + _render_events_section(events)
        + _render_ml_section(models)
    )
    return _page("pirewall control panel", body)
