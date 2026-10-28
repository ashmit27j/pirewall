"""Portal sessions bound to `(ip, mac)` through core's binding table (ADDENDUM_4.md D3, C4; phase 14).

`PortalService` learns a client's MAC from `LeaseBindingTable`, never from
the HTTP request: no binding, no login; a session is ended when its address
is bound to another MAC; the kernel grant is the pair; and the block notice
follows a MAC-keyed block to the device's new address.
"""

import tempfile
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.core.bindings import LeaseBindingTable
from pirewall.core.enums import BindingSource, FirewallAction, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.identity import Binding
from pirewall.core.models.portal import PortalClientStatus
from pirewall.firewall import validator
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.local_addresses import LocalAddresses
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.portal_service import PortalLoginError, PortalService
from pirewall.portal.store import PortalUserStore
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PASSWORD = "correct-horse-battery"
CLIENT = IPv4Address("192.168.1.20")
CLIENT_MAC = "02:00:00:00:00:20"
OTHER_MAC = "02:00:00:00:00:99"


@pytest.fixture(autouse=True)
def no_host_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    empty = LocalAddresses(host=frozenset(), broadcast=frozenset())
    monkeypatch.setattr(validator, "cached_local_addresses", lambda: empty)


class _Rig:
    def __init__(self, *, v2: bool = False) -> None:
        self.now = NOW
        self.config = make_config(
            portal={"enabled": True, "session_timeout_seconds": 600},
            firewall={"enforcement_mode": "active"},
        )
        self.backend = FakeFirewallBackend()
        self.backend.set_clock(self.now)
        self.bindings = LeaseBindingTable()
        self.manager = FirewallManager(
            self.config,
            self.backend,
            set_backend=FakeSetBackend(lambda: self.now) if v2 else None,
            mac_resolver=self.bindings.resolve_mac,
        )
        store = PortalUserStore(Path(tempfile.mkdtemp()) / "users.json")
        store.add("alice", PASSWORD, self.now, "admin")
        self.events: list[SecurityEvent] = []
        self.service = PortalService(
            self.config, self.manager, store, self.events.append, lambda: self.now, bindings=self.bindings
        )

    def bind(self, *pairs: tuple[IPv4Address, str]) -> None:
        leases = [
            Binding(ip=ip, mac=mac, source=BindingSource.LEASE, expires_at=self.now + timedelta(hours=1))
            for ip, mac in pairs
        ]
        self.manager.sync_bindings(self.bindings.apply_leases(leases, self.now), self.now)

    def grants(self) -> frozenset[tuple[IPv4Address, str | None]]:
        return self.manager.authorized_portal_grants()

    def block(self, ip: IPv4Address) -> None:
        candidate = make_candidate(
            action=FirewallAction.BLOCK,
            source=f"{ip}/32",
            destination="203.0.113.9/32",
            created_at=self.now,
            expires_at=self.now + timedelta(seconds=300),
        )
        self.manager.register_decision(
            FirewallDecision.model_validate(
                {
                    "id": candidate.decision_id,
                    "threat_assessment_id": "a",
                    "action": candidate.action,
                    "threat_score": candidate.threat_score,
                    "threat_level": ThreatLevel.CRITICAL,
                    "reason": "test",
                    "decided_at": self.now,
                }
            )
        )
        assert self.manager.submit_candidate(candidate, self.now).rule is not None


def test_a_client_with_no_binding_cannot_log_in_and_is_told_why() -> None:
    rig = _Rig()
    with pytest.raises(PortalLoginError, match="lease"):
        rig.service.login("alice", PASSWORD, CLIENT)
    assert rig.grants() == frozenset()
    assert rig.service.list_sessions() == []


def test_a_bound_client_logs_in_and_the_grant_is_its_ip_mac_pair() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    assert session.client_mac == CLIENT_MAC
    assert rig.grants() == frozenset({(CLIENT, CLIENT_MAC)})
    state = rig.service.keepalive(session.token, CLIENT)
    assert state.status is PortalClientStatus.AUTHENTICATED


def test_a_session_ends_when_its_address_is_bound_to_another_mac() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    rig.bind((CLIENT, OTHER_MAC))
    state = rig.service.keepalive(session.token, CLIENT)
    assert state.status is PortalClientStatus.EXPIRED
    assert rig.grants() == frozenset(), "the pair grant is revoked with the session"
    assert rig.service.keepalive(session.token, CLIENT).status is PortalClientStatus.EXPIRED


def test_a_session_ends_when_its_binding_disappears() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    rig.bind()
    assert rig.service.keepalive(session.token, CLIENT).status is PortalClientStatus.EXPIRED


def test_logout_releases_the_pair() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    assert rig.service.logout(session.token, CLIENT) is True
    assert rig.grants() == frozenset()


def test_logout_from_a_different_device_is_refused_but_still_ends_the_session() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    rig.bind((CLIENT, OTHER_MAC))
    assert rig.service.logout(session.token, CLIENT) is False
    assert rig.grants() == frozenset()
    assert rig.service.list_sessions() == []


def test_reconcile_revokes_a_grant_whose_mac_no_session_holds() -> None:
    rig = _Rig()
    rig.bind((CLIENT, CLIENT_MAC))
    rig.service.login("alice", PASSWORD, CLIENT)
    rig.backend.authorize_portal_client(IPv4Address("192.168.1.21"), 600, OTHER_MAC)
    assert rig.service.reconcile() == 1
    assert rig.grants() == frozenset({(CLIENT, CLIENT_MAC)})


def test_a_mac_keyed_block_is_shown_to_the_device_at_its_new_address() -> None:
    """C4 by IP -> MAC: the notice finds the block after the device changes address."""
    rig = _Rig(v2=True)
    rig.bind((CLIENT, CLIENT_MAC))
    rig.block(CLIENT)
    moved = IPv4Address("192.168.1.40")
    rig.bind((moved, CLIENT_MAC))
    state = rig.service.keepalive(None, moved)
    assert state.status is PortalClientStatus.BLOCKED
    with pytest.raises(PortalLoginError, match="suspended"):
        rig.service.login("alice", PASSWORD, moved)


def test_the_device_that_inherits_a_blocked_address_can_log_in() -> None:
    rig = _Rig(v2=True)
    rig.bind((CLIENT, CLIENT_MAC))
    rig.block(CLIENT)
    rig.bind((CLIENT, OTHER_MAC))
    session = rig.service.login("alice", PASSWORD, CLIENT)
    assert session.client_mac == OTHER_MAC


def test_without_a_binding_table_the_portal_keeps_its_ip_only_behaviour() -> None:
    rig = _Rig()
    store = PortalUserStore(Path(tempfile.mkdtemp()) / "u.json")
    store.add("bob", PASSWORD, NOW, "admin")
    service = PortalService(rig.config, rig.manager, store, rig.events.append, lambda: rig.now)
    session = service.login("bob", PASSWORD, CLIENT)
    assert session.client_mac is None
    assert rig.grants() == frozenset({(CLIENT, None)})
    assert service.keepalive(session.token, CLIENT).status is PortalClientStatus.AUTHENTICATED
