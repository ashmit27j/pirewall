"""Request/response schemas specific to the API layer (spec §28).

Everything else (flows, rules, events, ...) is returned as the same
domain model `pirewall.ipc.client.BaseRpcClient` already gives us — no
need for a parallel, duplicate schema for read-only passthrough data.
"""

from datetime import datetime
from ipaddress import IPv4Network

from pydantic import BaseModel, ConfigDict, Field

from pirewall.core.enums import Protocol
from pirewall.core.models.portal import PortalUser


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    expires_at: datetime


class MessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str


class AllowlistCreateRequest(BaseModel):
    """Everything an admin supplies to create an `AllowlistEntry` — `id`/`created_at`/`created_by`
    are assigned server-side."""

    model_config = ConfigDict(extra="forbid")

    target: IPv4Network
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol | None = None
    reason: str = Field(min_length=1)

    # Optional captive-portal account provisioned alongside the entry
    # (ADDENDUM_3.md C3). An allowlist entry is a CIDR and a portal account
    # is a credential, so this is not one-to-one: a gateway or a printer
    # belongs on the allowlist and can never sign in. Left unset, nothing
    # is provisioned and behaviour is exactly as before.
    portal_username: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$"
    )


class AllowlistCreateResponse(BaseModel):
    """An created allowlist entry, plus the portal password if one was generated.

    `portal_password` is the only place a portal password ever appears in
    the clear, and it appears exactly once: it is not persisted, not logged,
    and not recoverable afterwards.
    """

    model_config = ConfigDict(extra="allow")

    portal_username: str | None = None
    portal_password: str | None = None


class PortalUserCreateRequest(BaseModel):
    """Create a portal account. An empty `password` means "generate one"."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str | None = Field(default=None, min_length=1)
    note: str = Field(default="", max_length=200)


class PortalUserResponse(BaseModel):
    """A portal account, plus the generated password when one was just generated."""

    model_config = ConfigDict(extra="forbid")

    user: PortalUser
    generated_password: str | None = None
