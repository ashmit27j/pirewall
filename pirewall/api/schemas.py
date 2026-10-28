"""Request/response schemas specific to the API layer (spec §28).

Everything else (flows, rules, events, ...) is returned as the same
domain model `pirewall.ipc.client.BaseRpcClient` already gives us — no
need for a parallel, duplicate schema for read-only passthrough data.
"""

from datetime import datetime
from ipaddress import IPv4Network

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from pirewall.core.enums import Protocol
from pirewall.core.models.common import UnicastMacAddress
from pirewall.core.models.portal import PortalUser

_HOST_PREFIX_LENGTH = 32


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
    are assigned server-side.

    Narrowed for v2 (PLAN_FINAL §4.9): the target is one device, a `/32`
    plus an optional MAC, never a range, because an allowlist entry outranks
    every adaptive rule (A2) and a range would exempt a whole segment. The
    reason is mandatory and non-blank, and the admin password must be
    supplied again (`password`); a session cookie alone cannot add one.

    Every check is a *field* validator on purpose: a 422 echoes the failing
    field's input, and a model-level validator's input is the whole body,
    password included.
    """

    model_config = ConfigDict(extra="forbid")

    target: IPv4Network
    mac: UnicastMacAddress | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol | None = None
    reason: str = Field(min_length=1)
    password: SecretStr = Field(min_length=1)

    # Optional captive-portal account provisioned alongside the entry
    # (ADDENDUM_3.md C3). An allowlist entry is a CIDR and a portal account
    # is a credential, so this is not one-to-one: a gateway or a printer
    # belongs on the allowlist and can never sign in. Left unset, nothing
    # is provisioned and behaviour is exactly as before.
    portal_username: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$"
    )

    @field_validator("target")
    @classmethod
    def _single_host(cls, value: IPv4Network) -> IPv4Network:
        if value.prefixlen != _HOST_PREFIX_LENGTH:
            raise ValueError("an allowlist entry must name one device: a /32, not a range")
        return value

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("a reason is required")
        return stripped


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
