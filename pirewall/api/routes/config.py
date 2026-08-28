"""`GET /api/v1/config` — a redacted, read-only view of the running configuration (spec §28).

Read-only in the strongest sense: there is no write counterpart anywhere in
the API. Changing pirewall's configuration is a deliberate, out-of-band
operation (edit the TOML, restart the unit), because a control panel that
could rewrite `firewall.enforcement_mode`, `admin.admin_pc_ip` or
`authentication.admin_password_hash` over HTTP would make a compromised
session equivalent to owning the firewall — exactly what spec §45 says must
not follow from a compromised control panel.

**Redaction is allowlist-shaped, not blocklist-shaped.** `_REDACTED_FIELDS`
names the `(section, field)` pairs whose *values* are replaced; every other
value is exposed as-is. That is the right way round here because the config
tree is a closed, reviewed set of fields — but it does mean any future
secret-bearing field must be added to that tuple, which is why the
accompanying test asserts the specific fields are absent from the response
rather than merely that the endpoint returns something.

What gets redacted, and why:

* `authentication.admin_password_hash` — a password hash is offline-crackable
  material; it is never shown, not even to an authenticated admin.
* `api.tls_key_path` / `api.tls_cert_path` — filesystem paths to TLS
  material are reconnaissance, not operational information.
* `integration.wazuh_host` / `integration.netdata_host` — internal hostnames
  of the Admin PC's monitoring stack.

Whether an integration is *enabled*, which port it targets, and every
threshold, mode, and network parameter stay visible: the point of this
endpoint is letting an operator confirm the Pi is running the configuration
they think it is.
"""

from typing import Any, cast

from fastapi import APIRouter

from pirewall.api.app import ConfigDep

router = APIRouter(prefix="/api/v1", tags=["read"])

_REDACTION_PLACEHOLDER = "***redacted***"

_REDACTED_FIELDS: tuple[tuple[str, str], ...] = (
    ("authentication", "admin_password_hash"),
    ("api", "tls_cert_path"),
    ("api", "tls_key_path"),
    ("integration", "wazuh_host"),
    ("integration", "netdata_host"),
)


def redact(dumped: dict[str, Any]) -> dict[str, Any]:
    """Replace every `_REDACTED_FIELDS` value in a dumped config with a placeholder.

    Only replaces fields that are actually present and not `None`, so an
    unset optional (e.g. `integration.wazuh_host` on a deployment with Wazuh
    disabled) still reads as `null` rather than as a redacted secret that
    does not exist.
    """
    for section_name, field_name in _REDACTED_FIELDS:
        section = dumped.get(section_name)
        if not isinstance(section, dict):
            continue
        # `cast` to `dict[str, Any]`: this walks an already-serialized
        # config tree, whose leaves are arbitrary JSON scalars by
        # construction, so `isinstance(section, dict)` can only narrow to
        # `dict[Unknown, Unknown]`. `model_dump(mode="json")` on a Pydantic
        # model guarantees str keys. The typed view of the same data is
        # `PirewallConfig` itself.
        typed_section = cast(dict[str, Any], section)
        if typed_section.get(field_name) is not None:
            typed_section[field_name] = _REDACTION_PLACEHOLDER
    return dumped


@router.get("/config")
def get_config(config: ConfigDep) -> dict[str, Any]:
    """Return the running configuration with secret-bearing fields redacted.

    Returns a plain dict rather than a Pydantic response model: this is a
    faithful dump of `PirewallConfig` with a handful of values replaced, and
    mirroring all fifteen config sections into a parallel response model
    would create a second schema to keep in sync for no added type safety —
    the authoritative typed view is `PirewallConfig`, one dependency away.
    """
    return redact(config.model_dump(mode="json"))
