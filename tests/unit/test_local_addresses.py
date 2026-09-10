"""`pirewall.firewall.local_addresses`: the host's own addresses, from `/proc/net/fib_trie`."""

from ipaddress import IPv4Address
from pathlib import Path

from pirewall.firewall.local_addresses import read_local_addresses

# A verbatim excerpt of a real Pi 4's /proc/net/fib_trie while routing
# between a LAN AP (wlan0), a WAN uplink (wlan1) and a wired admin link
# (eth0) — captured, not invented.
FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     +-- 0.0.0.0/4 2 0 2
        |-- 0.0.0.0
           /0 universe UNICAST
        +-- 10.253.156.0/24 2 0 1
           |-- 10.253.156.0
              /24 link UNICAST
           |-- 10.253.156.107
              /32 host LOCAL
           |-- 10.253.156.255
              /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 192.168.100.0/23 3 0 4
        +-- 192.168.100.0/31 1 0 0
           |-- 192.168.100.0
              /24 link UNICAST
           |-- 192.168.100.1
              /32 host LOCAL
        |-- 192.168.100.255
           /32 link BROADCAST
        +-- 192.168.101.0/31 1 0 0
           |-- 192.168.101.0
              /24 link UNICAST
           |-- 192.168.101.1
              /32 host LOCAL
        |-- 192.168.101.255
           /32 link BROADCAST
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "fib_trie"
    path.write_text(text, encoding="utf-8")
    return path


def test_every_local_address_is_found_including_the_dhcp_wan_lease(tmp_path: Path) -> None:
    result = read_local_addresses(_write(tmp_path, FIB_TRIE))

    assert IPv4Address("10.253.156.107") in result.host  # the WAN lease config never names
    assert IPv4Address("192.168.100.1") in result.host  # the LAN AP address
    assert IPv4Address("192.168.101.1") in result.host  # the wired admin address
    assert IPv4Address("127.0.0.1") in result.host


def test_broadcast_addresses_are_collected_separately(tmp_path: Path) -> None:
    result = read_local_addresses(_write(tmp_path, FIB_TRIE))

    assert IPv4Address("192.168.100.255") in result.broadcast
    assert IPv4Address("192.168.100.255") not in result.host


def test_link_unicast_prefixes_are_not_mistaken_for_host_addresses(tmp_path: Path) -> None:
    result = read_local_addresses(_write(tmp_path, FIB_TRIE))

    assert IPv4Address("192.168.100.0") not in result.host
    assert IPv4Address("10.253.156.0") not in result.host


def test_contains_covers_both_host_and_broadcast(tmp_path: Path) -> None:
    result = read_local_addresses(_write(tmp_path, FIB_TRIE))

    assert result.contains(IPv4Address("192.168.100.1")) is True
    assert result.contains(IPv4Address("192.168.100.255")) is True
    assert result.contains(IPv4Address("8.8.8.8")) is False


def test_a_missing_file_degrades_to_empty_rather_than_raising(tmp_path: Path) -> None:
    result = read_local_addresses(tmp_path / "does-not-exist")

    assert result.host == frozenset()
    assert result.broadcast == frozenset()


def test_unparseable_content_degrades_to_empty_rather_than_raising(tmp_path: Path) -> None:
    result = read_local_addresses(_write(tmp_path, "not a fib_trie at all\n|-- \n   host LOCAL\n"))

    assert result.host == frozenset()
    assert result.broadcast == frozenset()
