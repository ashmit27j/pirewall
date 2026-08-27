"""Firewall rule generation, validation, lifecycle management, and backend (Phase 6).

Deliberately does **not** re-export anything from `pirewall.firewall.backend`
here — only `pirewall.firewall.manager` (and tests) may import that
package directly (CLAUDE.md, enforced by
`tests/security/test_backend_isolation.py`). Re-exporting a backend class
from this `__init__.py` would let other code reach it via
`from pirewall.firewall import ...` without ever writing the literal
`pirewall.firewall.backend` import path that isolation check looks for.
"""

from pirewall.firewall.generator import generate_candidate_rule
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.manager import FirewallManager, RuleTransition, SubmissionResult
from pirewall.firewall.rate_limiter import RuleCreationRateLimiter
from pirewall.firewall.validator import ValidationOutcome, ValidationRejection, validate_candidate_rule

__all__ = [
    "FirewallBackend",
    "FirewallManager",
    "RuleCreationRateLimiter",
    "RuleTransition",
    "SubmissionResult",
    "ValidationOutcome",
    "ValidationRejection",
    "generate_candidate_rule",
    "validate_candidate_rule",
]
