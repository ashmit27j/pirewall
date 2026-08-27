"""Request/response schemas specific to the API layer (spec §28).

Everything else (flows, rules, events, ...) is returned as the same
domain model `pirewall.ipc.client.BaseRpcClient` already gives us — no
need for a parallel, duplicate schema for read-only passthrough data.
"""

from datetime import datetime
from ipaddress import IPv4Network

from pydantic import BaseModel, ConfigDict, Field

from pirewall.core.enums import Protocol


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
