"""Test harness for building a full pirewall-api FastAPI app wired to an in-process core.

`TestHarness.get`/`post`/`delete` exist so no test file has to touch
`starlette.testclient.TestClient` directly: it overrides `httpx.Client` in
a way pyright can't fully resolve (its own default-argument sentinels
confuse overload matching), so raw member access on it comes back
partially `Unknown` under strict mode. These three methods are the one
place that's isolated.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from starlette.testclient import TestClient

from pirewall.api.app import create_app
from pirewall.config.models import PirewallConfig
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.loopback import LoopbackRpcClient
from pirewall.ipc.state import CoreStateStore
from tests.helpers.config import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, make_config

ADMIN_PC_IP = "192.168.1.50"


class Response:
    """A minimal, fully-typed view over `httpx.Response` for test assertions."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    @property
    def status_code(self) -> int:
        return cast(int, self._raw.status_code)

    def json(self) -> Any:
        return self._raw.json()

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._raw.cookies)


@dataclass
class TestHarness:
    client: TestClient
    manager: FirewallManager
    backend: FakeFirewallBackend
    state: CoreStateStore
    config: PirewallConfig

    def get(self, url: str, **kwargs: Any) -> Response:
        return Response(self.client.get(url, **kwargs))  # pyright: ignore[reportUnknownMemberType]

    def post(self, url: str, **kwargs: Any) -> Response:
        return Response(self.client.post(url, **kwargs))  # pyright: ignore[reportUnknownMemberType]

    def delete(self, url: str, **kwargs: Any) -> Response:
        return Response(self.client.delete(url, **kwargs))  # pyright: ignore[reportUnknownMemberType]


def make_harness(
    now: datetime,
    *,
    client_address: tuple[str, int] = (ADMIN_PC_IP, 12345),
    **config_overrides: dict[str, object],
) -> TestHarness:
    """Build a full app: FirewallManager + FakeFirewallBackend + CoreStateStore, wired via LoopbackRpcClient.

    `client_address` simulates the connecting IP FastAPI sees
    (`request.client.host`) — defaults to the configured Admin PC so tests
    opt in to simulating a *different* source when testing the restriction.
    """
    config = make_config(**config_overrides)
    backend = FakeFirewallBackend()
    manager = FirewallManager(config, backend)
    state = CoreStateStore(max_history=50, started_at=now)
    dispatcher = CoreRpcDispatcher(state, manager, config, now_fn=lambda: now)
    rpc_client = LoopbackRpcClient(dispatcher)
    app = create_app(config, rpc_client)
    test_client = TestClient(app, client=client_address)
    return TestHarness(client=test_client, manager=manager, backend=backend, state=state, config=config)


def login(
    harness: TestHarness, username: str = TEST_ADMIN_USERNAME, password: str = TEST_ADMIN_PASSWORD
) -> str:
    response = harness.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.json()
    token = response.json()["token"]
    assert isinstance(token, str)
    return token


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
