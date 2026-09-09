"""Captive-portal domain models (ADDENDUM_3.md C1-C4).

These describe the LAN-side authentication surface: who may use the
protected network (`PortalUser`), who currently is (`PortalSession`), and
what a given client should be told right now (`PortalClientState`).

Deliberately separate from the adaptive rule pipeline. A portal session is
*authorization to be forwarded at all*; an adaptive rule is *a threat
response layered on top*. A session never enters the `RuleStatus`
lifecycle, never consumes the ADDENDUM.md A3 rate cap, and is never
generated from ML output — see ADDENDUM_3.md C2 for the full argument.

IPv4-only, like every other model in the adaptive pipeline (ADDENDUM.md A5).
"""

from enum import StrEnum
from ipaddress import IPv4Address
from uuid import uuid4

from pydantic import AwareDatetime, Field

from pirewall.core.models.common import PirewallModel


class PortalClientStatus(StrEnum):
    """What the portal should show a client on its next keepalive poll."""

    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    BLOCKED = "blocked"


class PortalUser(PirewallModel):
    """A LAN user account, stored on the Pi with only a scrypt hash of the password.

    `is_demo` marks the seeded sample accounts documented in `docs/SETUP.md`.
    It exists so the running system can warn about them: pirewall-core emits
    a `SYSTEM_WARNING` at startup while any demo account survives, and the
    portal login page shows a banner. Deleting demo accounts is a
    production prerequisite, not a suggestion.
    """

    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password_hash: str = Field(min_length=1)
    created_at: AwareDatetime
    created_by: str = Field(min_length=1)
    note: str = Field(default="", max_length=200)
    is_demo: bool = False


class PortalSession(PirewallModel):
    """One authenticated LAN client, bound to the IP the login came from.

    The session is bound to `client_ip` rather than to the token alone
    because the token's whole purpose is to authorize *that address* for
    forwarding in the `pirewall_portal` nft set. A token replayed from a
    different address authorizes nothing and is rejected.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    token: str = Field(min_length=1)
    username: str = Field(min_length=1)
    client_ip: IPv4Address
    issued_at: AwareDatetime
    expires_at: AwareDatetime


class PortalClientState(PirewallModel):
    """The answer to one keepalive poll: what this client is, and what to tell them.

    `seconds_remaining` drives the countdown. It is computed server-side
    from `expires_at` on every poll, never from a clock in the browser, so
    a client cannot extend its own session by lying about the time.
    """

    status: PortalClientStatus
    username: str | None = None
    client_ip: IPv4Address
    seconds_remaining: int = Field(default=0, ge=0)
    expires_at: AwareDatetime | None = None
    message: str = Field(default="")
