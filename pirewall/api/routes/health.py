"""`GET /api/v1/health` — unauthenticated liveness probe for pirewall-api itself (spec §28)."""

from fastapi import APIRouter

from pirewall.api.schemas import MessageResponse

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health", response_model=MessageResponse)
def health() -> MessageResponse:
    """Liveness of the pirewall-api process only — not a check of pirewall-core. See `/status` for that."""
    return MessageResponse(message="ok")
