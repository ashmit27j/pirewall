"""The startup rule for demo portal accounts (PLAN_FINAL §4.9, KNOWN_ISSUES.md #4).

The five seeded demo accounts have published passwords. In SHADOW mode
pirewall enforces nothing it decided, so the demo accounts are tolerated
there, with the existing startup warning, the login-page banner and the
control-panel notice. In ASSISTED or ACTIVE they would be live credentials
to a network pirewall is actually defending, so pirewall-core refuses to
start until they are removed (`portal_users remove-demo`) or the operator
says, in config, that they are wanted (`portal.allow_demo_accounts`).

Checked once, before pirewall-core touches any privileged resource
(`pirewall.main`). The enforcement mode cannot leave SHADOW at runtime
except through a config change and a restart (the kill switch only ever
moves it *to* SHADOW), so a startup check covers every way in.
"""

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EnforcementMode
from pirewall.core.exceptions import ConfigurationError
from pirewall.portal.store import PortalUserStore


def refuse_demo_accounts_when_enforcing(config: PirewallConfig) -> None:
    """Raise `ConfigurationError` if demo accounts exist while enforcing without an explicit opt-in.

    A disabled portal accepts no logins, so its accounts are inert and the
    store is not even opened. SHADOW is always allowed. A store that cannot
    be read is a `ConfigurationError` too, the same one pirewall-core would
    hit a moment later.
    """
    if not config.portal.enabled or config.portal.allow_demo_accounts:
        return
    if config.firewall.enforcement_mode is EnforcementMode.SHADOW:
        return
    demo = PortalUserStore(config.portal.user_store_path).demo_usernames()
    if not demo:
        return
    raise ConfigurationError(
        f"refusing to start in {config.firewall.enforcement_mode.value.upper()} mode: portal demo "
        f"account(s) {', '.join(demo)} still exist, and their passwords are public. Remove them with\n"
        "  python -m scripts.deployment.portal_users remove-demo\n"
        "or set portal.allow_demo_accounts = true to keep them deliberately "
        "(SHADOW mode starts either way)."
    )
