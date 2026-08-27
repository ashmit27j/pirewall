"""Typed exception hierarchy for pirewall (spec §44).

Every subsystem raises one of these instead of letting a stdlib/third-party
exception (e.g. `tomllib.TOMLDecodeError`, a raw `ValueError`) leak across a
module boundary. Callers should never need to catch anything other than
`PirewallError` to handle "something in pirewall went wrong" generically,
while still being able to catch a specific subclass when they need to react
differently.
"""


class PirewallError(Exception):
    """Base class for every exception raised by pirewall's own code.

    Catching this (instead of `Exception`) at a subsystem boundary guarantees
    you're only swallowing errors pirewall itself defined and reasoned about,
    not e.g. a programming error like an `AttributeError`.
    """


class ConfigurationError(PirewallError):
    """Raised when configuration is missing, malformed, or fails validation.

    Covers TOML parse failures, missing required fields (especially
    security-relevant ones like the Admin PC IP or auth settings, which have
    no silent default), and values that fail their Pydantic constraints.
    """


class CaptureError(PirewallError):
    """Raised when the packet capture layer fails (socket setup, read, interface down)."""


class PacketParseError(PirewallError):
    """Raised when a captured packet cannot be parsed into `PacketMetadata`.

    A malformed or truncated packet raises this rather than propagating a
    raw struct-unpacking exception; callers decide whether to drop-and-log or
    escalate.
    """


class FlowError(PirewallError):
    """Raised on flow-table failures: key derivation, aggregation, or eviction errors."""


class FeatureExtractionError(PirewallError):
    """Raised when a `Flow` cannot be turned into a valid `FeatureVector`."""


class DatasetError(PirewallError):
    """Raised when a dataset adapter can't produce a canonical dataset from source data.

    Covers a missing required column (a structural schema mismatch — fail
    the whole file fast) and a dataset file that can't be found/read at all.
    A single row with an unparseable value is *not* this — see
    `pirewall.ml.preprocessing.common.DatasetLoadResult.skipped_rows`,
    which counts and reports those without aborting the whole load (spec
    §13: handle missing/invalid values explicitly, don't silently drop a
    feature the schema requires).
    """


class ModelLoadError(PirewallError):
    """Raised when an ML model artifact cannot be loaded or its metadata is invalid."""


class ModelInferenceError(PirewallError):
    """Raised when inference fails, including a runtime/model feature-schema mismatch (spec §15)."""


class ThreatAssessmentError(PirewallError):
    """Raised when combining evidence into a `ThreatAssessment` fails."""


class FirewallError(PirewallError):
    """Raised for firewall-subsystem failures: backend calls, manager transitions, deploys."""


class RuleValidationError(FirewallError):
    """Raised when a `CandidateRule` fails any stage of the validation chain (spec §24).

    A subclass of `FirewallError` rather than a direct `PirewallError`
    subclass because rule validation is part of the firewall subsystem, but
    it is distinguished so callers can specifically catch "this rule was
    rejected" without catching every other firewall failure mode.
    """


class AuthenticationError(PirewallError):
    """Raised on authentication/authorization failures in the API layer."""


class RpcError(PirewallError):
    """Raised when a pirewall-api <-> pirewall-core RPC call fails (ADDENDUM.md A4).

    Covers both transport failures (socket unavailable/timeout) and a
    well-formed error response from pirewall-core (e.g. "rule not found").
    """


class IntegrationError(PirewallError):
    """Raised when an external integration (Wazuh, Netdata) fails to send/receive data."""
