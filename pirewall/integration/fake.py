"""In-memory `WazuhTransport`/`NetdataTransport` fakes for tests (spec §39).

Let `WazuhForwarder`/`NetdataExporter` payload shaping be tested without any
real network I/O, following the same Protocol + Fake pattern as
`pirewall.capture.fake.FakePacketCapture` and
`pirewall.firewall.backend.fake.FakeFirewallBackend`.
"""

from pirewall.core.exceptions import IntegrationError


class FakeWazuhTransport:
    """In-memory `WazuhTransport`. Records every message sent, in order."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent_messages: list[str] = []
        self.fail = fail

    def send(self, message: str) -> None:
        if self.fail:
            raise IntegrationError("simulated Wazuh transport failure")
        self.sent_messages.append(message)


class FakeNetdataTransport:
    """In-memory `NetdataTransport`. Records every `(name, value)` pair sent, in order."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent_metrics: list[tuple[str, float]] = []
        self.fail = fail

    def send_metric(self, name: str, value: float) -> None:
        if self.fail:
            raise IntegrationError("simulated Netdata transport failure")
        self.sent_metrics.append((name, value))
