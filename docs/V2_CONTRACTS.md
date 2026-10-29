# V2 contracts

Frozen by phase 11, before any v2 implementation, so that phases 12–20 can
run in parallel git worktrees without diverging. The rules behind these
contracts are in `docs/ADDENDUM_4.md` (D1–D9). This file holds the exact
types, names, signatures and file ownership.

Every type below exists as a typed stub in the repository, so later phases
import it rather than redefine it. Where logic will eventually go, the stub
raises `NotImplementedError`. Tests in `tests/unit/test_v2_contracts.py`,
`tests/unit/test_config_v2_sections.py` and `tests/unit/test_migrate_config.py`
pin these contracts.

## 0. Change control

* **Adding** to a contract (a new enum member, an optional field, a new
  config key with a default) is allowed in the phase that needs it. It must
  update this file and the pinning tests in the same commit.
* **Changing or removing** anything here (a name, a type, a field's meaning,
  a signature) is not a phase's call. Stop and ask the human.
* The nft names are pinned to the templates by test. If a phase changes a
  template name, it must change `pirewall/core/nft_names.py` and this file in
  the same commit, or the test fails.

## 1. Vocabulary — `pirewall/core/enums.py`

| Enum | Values |
|---|---|
| `PipelineEngine` | `v1`, `v2` |
| `GuardName` | `raw`, `input`, `forward` (the `guard_verdict_<name>` chains) |
| `GuardMode` | `observe`, `enforce` |
| `BindingSource` | `lease`, `static` |
| `EnvTag` | `pi-live`, `pi-scripted`, `sandbox`, `mock` |
| `D1Detector` | `vertical_scan`, `horizontal_scan`, `failed_handshake`, `brute_force`, `slow_rate_dos`, `fan_in`, `new_mac_rate`, `new_lease_rate`, `portal_auth_failures` |

`FirewallAction`, `ThreatLevel` and `EnforcementMode` are reused unchanged.

## 2. MAC addresses — `pirewall/core/models/common.py`

* **`MacAddress`** is an `Annotated[str, …]`. It accepts six hex octets
  separated consistently by `:` or `-`, in any case, and normalises them to
  lowercase `aa:bb:cc:dd:ee:ff`. Everything else is refused: dotted Cisco
  form, bare 12-digit hex, mixed separators, whitespace, non-strings. Use it
  for observed frame fields, such as a flow's destination MAC, which may be
  broadcast.
* **`UnicastMacAddress`** is a `MacAddress` that can identify one device.
  It refuses any address with the I/G (group) bit set, which covers
  multicast and broadcast, and refuses `00:00:00:00:00:00`. Locally
  administered addresses are accepted. Every field that *names a device*
  uses this type.

## 3. Identity — `pirewall/core/models/identity.py`, `pirewall/core/binding_table.py`

```python
class RuleTarget(PirewallModel):
    ip: IPv4Address
    mac: UnicastMacAddress | None = None

class Binding(PirewallModel):
    ip: IPv4Address
    mac: UnicastMacAddress
    source: BindingSource
    expires_at: AwareDatetime | None = None   # required for LEASE, forbidden for STATIC

class BindingChange(PirewallModel):
    removed: tuple[Binding, ...] = ()          # applied first, same nft batch
    added: tuple[Binding, ...] = ()

class BindingTable(Protocol):
    def resolve_mac(self, ip: IPv4Address) -> MacAddress | None: ...
    def resolve_ip(self, mac: MacAddress) -> IPv4Address | None: ...
    def snapshot(self) -> tuple[Binding, ...]: ...
    def apply_leases(self, leases: Sequence[Binding], now: datetime) -> BindingChange: ...
```

Semantics:

* `apply_leases` receives the **full** current lease set. Entries whose
  expiry is not after `now` count as absent.
* A static binding always wins. A lease for an IP or MAC that a static
  entry names is ignored.
* A changed pair appears as the old pair in `removed` plus the new pair in
  `added`.
* `snapshot()` returns an immutable copy, so RPC handlers can serve it
  without holding core's RPC lock.
* The element timeout for a lease binding is `expires_at` plus
  `antispoof.grace_seconds`. Static bindings carry no timeout.
* The only writer of the kernel binding sets is
  `FirewallManager.sync_bindings` (phase 14). `BindingTable` holds no nft
  handle.

Phase 14 adds an optional `target: RuleTarget | None = None` to
`CandidateRule`/`FirewallRule` (`source`/`destination` stay, for v1), and an
optional `mac: UnicastMacAddress | None = None` to `AllowlistEntry`.

## 4. Evidence — `pirewall/core/models/evidence_v2.py`

Each variant has an `id` (a uuid4 by default) and a timezone-aware
timestamp.

| Variant | Fields | Ceiling on its own |
|---|---|---|
| `KernelGuardEvidence` | `code: OffenderCode`, `mac: UnicastMacAddress`, `guard: GuardName`, `guard_mode: GuardMode`, `sustained_polls: int ≥ 1`, `observed_at` | observe ⇒ MONITOR; enforce ⇒ RATE_LIMIT once `sustained_polls ≥ policy.sustained_polls` |
| `D1Evidence` | `detector: D1Detector`, `window_seconds: int > 0`, `value: float ≥ 0`, `threshold: float ≥ 0`, `mac: UnicastMacAddress \| None`, `observed_at` | per the policy table |
| `AnomalyEvidence` | **the existing v1 model**, reused unchanged (`pirewall/core/models/evidence.py`) | MONITOR |
| `ClassifierEvidence` | `flow_id`, `mac \| None`, `attack_probability`, `operating_threshold`, `is_attack` (= probability ≥ threshold), `family \| None`, `family_probability \| None` (set together), `model_version`, `feature_schema_version`, `generated_at` | MONITOR |

* `KernelGuardEvidence.guard` must be the guard that raises its `code`
  (§6). `guard_mode` is the mode **at poll time**.
* `D1Evidence.mac` is None only for aggregate detectors with no single
  source: global portal auth failures, and fan-in toward one destination.
  Such evidence cannot target a device on its own.
* `EvidenceV2` is the smart union of the four variants. They share no field
  set, so `extra="forbid"` disambiguates them.
* `evidence_id(evidence)` gives the string used in
  `PolicyDecision.evidence_ids`: the `id` for the three v2 variants, and
  `anomaly:<flow_id>` for the reused `AnomalyEvidence`, which has no id.
* **Producer ids (added by phase 17).** The producers set deterministic ids,
  so re-observing the same thing is the *same* evidence and can never
  escalate (D4): D1 uses
  `d1:<detector>:<scope>:<window>:<subject>:<floor(t / window)>` (scope
  `device | destination | account | global`); the kernel poller uses
  `k:<code>:<mac>:<episode start>:<guard mode>:<stage>`, where an episode is
  one unbroken run of polls and `stage` is `new`/`sustained` for an
  enforce-mode guard (crossing `policy.sustained_polls` is new evidence) and
  `observe` for an observe-mode one. Pinned by
  `tests/unit/test_d1_detectors.py::test_evidence_ids_are_stable_within_a_window_bucket`
  and `tests/unit/test_kernel_poller.py`.

## 5. Policy decision — `pirewall/core/models/policy.py`

```python
class PolicyDecision(PirewallModel):
    id: str                                    # uuid4 by default
    target: RuleTarget
    action: FirewallAction
    ttl_seconds: int | None                    # 1..3600; required iff RATE_LIMIT/BLOCK
    reasons: tuple[str, ...]                   # at least one
    evidence_ids: tuple[str, ...]              # at least one for RATE_LIMIT/BLOCK
    requires_approval: bool = False            # BLOCK only (A7)
    decided_at: AwareDatetime
    threat_level: ThreatLevel | None = None    # derived from action; filled if omitted, refused if inconsistent
```

`threat_level` is stored rather than computed so that a serialised decision
round-trips under `extra="forbid"`. The mapping
(`THREAT_LEVEL_BY_ACTION`) is the exact inverse of v1's level → action
ladder:

| Action | `threat_level` |
|---|---|
| ALLOW | low |
| MONITOR | medium |
| RATE_LIMIT | high |
| BLOCK | critical |

Constants: `MAX_ELEMENT_TTL_SECONDS = 3600` and
`ML_ONLY_ACTION_CEILING = MONITOR`.

**Left to phase 17, on purpose.** Which column a decision is computed from
while in SHADOW is policy-engine behaviour, not a type. A1 says the
pipeline runs in full and `FirewallManager` records SHADOWED. Phase 17
decides whether a SHADOW decision shows the ASSISTED or the ACTIVE
outcome, and documents its choice.

## 6. Offender codes — `pirewall/core/nft_names.py` `OffenderCode`

The integers come from the template's `update @offenders { ether saddr . N }`
rules, and the names from its header comment. `OFFENDER_GUARD` maps each
code to the guard whose verdict chain its rule jumps to. The test parses
both from the template.

| Code | Name | Template description | Guard | Meter set |
|---|---|---|---|---|
| 1 | `SYN_PPS` | syn pps | raw | `syn_meter` |
| 2 | `UDP_LOCAL_PPS` | udp pps (to the Pi) | raw | `udp_meter` |
| 3 | `ICMP_PPS` | icmp pps | raw | `icmp_meter` |
| 4 | `LOCAL_PPS` | total pps (to the Pi) | raw | `pps_meter` |
| 5 | `CLOSED_PORT` | closed-port hits on the Pi | input | `closed_meter` |
| 6 | `NEWCONN` | new-conn rate (forward) | forward | `newconn_meter` |
| 7 | `NEWCONN_DST` | new-conn rate per (mac, dst) | forward | `newconn_dst_meter` |
| 8 | `UDP_FWD` | udp pps per (mac, dst) (forward) | forward | `udp_fwd_meter` |
| 10 | `UNBOUND` | unbound-source traffic | raw | `unbound_meter` |
| 53 | `DNS_QPS` | dns qps to the Pi | input | `dns_meter` |
| 67 | `DHCP` | dhcp rate | raw | `dhcp_meter` |
| 8080 | `PORTAL_CONCURRENCY` | portal concurrency | input | `portal_conc` |

A code is not a port number, even where the value matches one.

## 7. nftables object names — `pirewall/core/nft_names.py`

Copied exactly from `docs/v2/v2/pirewall_static.nft.template` and
`pirewall_adaptive.nft.template`. The test also checks the copies phase 13
ports into `deploy/firewall/`, once they exist.

**Tables.**

| Family | Table | Constant |
|---|---|---|
| inet | `pirewall_static` | `STATIC_TABLE` |
| arp | `pirewall_static_arp` | `STATIC_ARP_TABLE` |
| inet | `pirewall_adaptive` | `ADAPTIVE_TABLE` |

`PANIC_TABLES` lists exactly these three, in deletion order: adaptive,
static, arp. `BASE_TABLE` (`pirewall_base`) and `PORTAL_TABLE`
(`pirewall_portal`) are named only so code can assert it never touches them.

**Lab table (added by phase 16).** `LAB_TABLE` (`inet pirewall_lab`) is
loaded only by `pirewall-start --lab-victim up` and deleted by `--lab-victim
down`. Core never reads or writes it, and it is not in `PANIC_TABLES`: it is
lab tooling, not enforcement. Its one rule sets `LAB_FORWARD_MARK`
(`0x00007077`) on LAN → victim forwards, and `pirewall_base`'s forward chain
accepts exactly that mark (an accept in a separate table cannot override
base's `policy drop`). Pinned by
`tests/unit/test_startup_helper.py::test_the_lab_ruleset_marks_only_lan_to_victim_traffic`
and `::test_the_base_template_accepts_exactly_the_lab_mark`.

**Chains.**

* **`pirewall_static`:** `prerouting_frag`, `prerouting_raw`,
  `input_guard`, `forward_guard`, `dhcp_gate`, `unbound`, `flood_meters`,
  `guard_verdict_raw`, `guard_verdict_input` and `guard_verdict_forward`.
  `GUARD_VERDICT_CHAINS` maps each `GuardName` to its verdict chain. Those
  are the only chains core may change (D1).
* **`pirewall_static_arp`:** `input`.
* **`pirewall_adaptive`:** `prerouting_adaptive`.

**Sets and their single writer.**

| Table | Set | Kind | Writer |
|---|---|---|---|
| static + arp | `bound4`, `macbind` | binding | `FirewallManager.sync_bindings` |
| static | `allow_bound` | allowlist copy | `FirewallManager` |
| static | `dhcp_meter`, `unbound_meter`, `syn_meter`, `udp_meter`, `icmp_meter`, `pps_meter`, `dns_meter`, `closed_meter`, `portal_conc`, `newconn_meter`, `newconn_dst_meter`, `udp_fwd_meter` | meter (`STATIC_METER_SETS`); membership is **not** evidence | kernel |
| static | `offenders` | evidence (`EVIDENCE_SET`) | kernel |
| static | `unbound_seen` | diagnostic: MAC+IP pairs that need a static binding | kernel |
| adaptive | `block_mac`, `block4`, `ratelimit_mac` | enforcement (`ADAPTIVE_ENFORCEMENT_SETS`); the kill switch flushes these | `FirewallManager` |
| adaptive | `allow_bound` | allowlist copy, same batch as static's | `FirewallManager` |
| adaptive | `infra4` | rendered from config at load | `pirewall-start` |
| adaptive | `rl_meter` | meter | kernel |

**Counters.**

* **static:** `c_ipv6`, `c_frag`, `c_bogon`, `c_rpf`, `c_spoof`,
  `c_bk_syn`, `c_bk_udp`, `c_bk_icmp`, `c_bk_unbound`, `c_bk_newconn` and
  `c_dns_bypass`, plus the per-guard `c_verdict_raw`, `c_verdict_input` and
  `c_verdict_forward` (`GUARD_VERDICT_COUNTERS`).
* **arp:** `c_arp_spoof`.
* **adaptive:** `c_block_mac`, `c_block4` and `c_ratelimit`.

**Names planned but not in the tested templates yet.** These are not in
`nft_names.py`. A phase that introduces one adds it to the template,
`nft_names.py`, this table and the pinning test together.

| Name | Planned by | Status |
|---|---|---|
| `pi_addrs` (set) | PLAN_FINAL §4.2, PLAN_v3 §6 step 4 | The template uses the literal `${PIREWALL_LAN_IP}` instead. Phase 13 decides. |
| `ratelimit4` (set) | phase 13 prompt | For IP-only RATE_LIMIT targets until phase 14 supplies MACs. |

## 8. Config — `pirewall/config/models.py`, `config/default_config.toml`

Every v2 section is optional and fully defaulted. A 1.x or 2.0 file still
loads unchanged, and no existing key was renamed or removed.
`scripts/deployment/migrate_config.py` writes the sections out explicitly.

| Section | Keys (defaults) |
|---|---|
| `[pipeline]` | `engine = "v1"` |
| `[guards]` | `raw_mode = "enforce"` (enforce **if seeded**), `input_mode = "enforce"`, `forward_mode = "observe"`, meter pairs `{rate, burst}` (table below), `portal_concurrency = 20`, set sizes |
| `[antispoof]` | `lease_file`: when unset, derived from `network.lan_interface` as `/var/lib/NetworkManager/dnsmasq-<lan_interface>.leases` (phase 14b; was a fixed `dnsmasq-wlan0.leases`, the same file for the default LAN), and an explicit value wins; `static = []` (`{ip, mac, reason}`; each IP and MAC once), `grace_seconds = 60`, `poll_seconds = 2.0` |
| `[policy]` | `rate_limit_ttl_seconds = 300`, `block_ttl_seconds = 300`, `escalation_ttl_multiplier = 2`, `max_ttl_seconds = 3600` (≤ 3600), `sustained_polls = 2` (≥ 2) |
| `[lab]` | `env_tag = "sandbox"`, `victim_netns = "labvictim"`, `victim_host_interface = "lab0"`, `victim_network = "10.250.0.0/30"` (must be a /30) |
| `[capture]` additions | `backend` also accepts `"replay"`, which needs `replay_path`. `replay_speed = "max"` (also `"realtime"` or `"<N>x"`). Phase 15 implements the replay (`pirewall/capture/replay.py`); core selects it from these settings from phase 16. Phase 15 adds `native_max_panics_per_minute = 5` (D6 fallback threshold). |
| `[flow]` addition (phase 15) | `connection_start_max_tracked = 100000`, the `ConnectionStartTracker` bound (§11). |
| `[policy]` additions (phase 17) | `table_path = "pirewall/policy/table.toml"` (the reviewable table, D4), `max_tracked_devices = 4096`, `max_evidence_ids_per_device = 256` (escalation memory bounds). |
| `[d1]` (phase 17) | `thresholds_path = "config/d1_thresholds.toml"`, `windows_seconds = [10, 60]` (must include both; 3600 optional), `max_tracked_macs = 4096`, `max_tracked_destinations = 4096`, `max_events_per_mac = 4096`, `max_tracked_accounts = 1024`, `evaluation_cooldown_seconds = 1.0`, `brute_force_ports = [22, 80, 443, 8080]` (+ the portal port), `brute_force_max_duration_seconds = 5.0`, `brute_force_size_tolerance = 0.25`, `failed_handshake_min_starts = 10`, `kernel_poll_interval_seconds = 1.0`, `set_fill_warning_ratio = 0.8`, `max_known_macs = 16384`. Thresholds themselves live in the thresholds file (§13). Older configs need no migration: the section is fully defaulted. |

**`[guards]` → template variable** (for `render_templates.py`, phase 13).
Each `{rate, burst}` pair renders into `<VAR>` and `<VAR>_BURST`. Rates are
per second, except DHCP, which is per minute.

| Config key | Template variables | Default |
|---|---|---|
| `dhcp_per_minute` | `DHCP_PER_MINUTE`, `DHCP_BURST` | 10 / 5 |
| `unbound` | `UNBOUND_PPS`, `UNBOUND_BURST` | 50 / 100 |
| `syn` | `SYN_PPS`, `SYN_BURST` | 200 / 400 |
| `icmp` | `ICMP_PPS`, `ICMP_BURST` | 50 / 100 |
| `udp_local` | `UDP_LOCAL_PPS`, `UDP_LOCAL_BURST` | 500 / 1000 |
| `local_pps` | `LOCAL_PPS`, `LOCAL_BURST` | 3000 / 6000 |
| `dns` | `DNS_QPS`, `DNS_BURST` | 100 / 300 |
| `closed_port` | `CLOSED_PPS`, `CLOSED_BURST` | 20 / 40 |
| `newconn` | `NEWCONN_PPS`, `NEWCONN_BURST` | 100 / 200 |
| `newconn_dst` | `NEWCONN_DST_PPS`, `NEWCONN_DST_BURST` | 50 / 100 |
| `udp_fwd` | `UDP_FWD_PPS`, `UDP_FWD_BURST` | 20000 / 40000 |
| `global_unbound` | `GLOBAL_UNBOUND_PPS`, `GLOBAL_UNBOUND_BURST` | 500 / 1000 |
| `global_syn` | `GLOBAL_SYN_PPS`, `GLOBAL_SYN_BURST` | 2000 / 4000 |
| `global_icmp` | `GLOBAL_ICMP_PPS`, `GLOBAL_ICMP_BURST` | 500 / 1000 |
| `global_udp_local` | `GLOBAL_UDP_LOCAL_PPS`, `GLOBAL_UDP_LOCAL_BURST` | 3000 / 6000 |
| `global_newconn` | `GLOBAL_NEWCONN_PPS`, `GLOBAL_NEWCONN_BURST` | 1000 / 2000 |
| `ratelimit` | `RATELIMIT_PPS`, `RATELIMIT_BURST` (adaptive template) | 20 / 40 |
| `portal_concurrency` | `PORTAL_CONCURRENCY` | 20 |
| `binding_set_size` | `BINDING_SIZE` | 1024 |
| `meter_set_size` | `METER_SIZE` | 256 |
| `pair_meter_set_size` | `PAIR_METER_SIZE` | 4096 |
| `offender_set_size` | `OFFENDER_SIZE` | 4096 |
| `adaptive_set_size` | `ADAPTIVE_SIZE` | 4096 |
| `raw_mode` / `input_mode` / `forward_mode` | `RAW_VERDICT` / `INPUT_VERDICT` / `FORWARD_VERDICT` (`drop` for enforce, empty for observe) | enforce / enforce / observe |

The defaults are the template's starting values (`docs/v2/v2/render.py`),
not calibrated values. A rate and its burst are one threshold, and are
fitted together.

**Model sidecar (added by phase 16).** `ModelMetadata.artifact_sha256`
(`pirewall/core/models/model_metadata.py`): optional lowercase-hex SHA-256 of
the artifact the sidecar describes. `pirewall-start` refuses when it is set
and does not match the file, and warns (recording the computed hash in the
manifest) when it is absent, as in every artifact trained before phase 16.
Pinned by `tests/unit/test_startup_helper.py::test_a_model_that_does_not_match_its_sidecar_hash_is_refused`
and `::test_a_matching_hash_passes_and_a_missing_one_only_warns`.

## 9. RPC — `pirewall/ipc/protocol_v2.py`

Six admin operations on `core.sock`, given as signatures only. Phase 16 added
them to `RpcOperation` (same string values), with handlers in
`CoreRpcDispatcher`; `tests/unit/test_v2_rpc.py::test_the_operation_names_are_the_frozen_contract`
pins the two lists to each other. **None of them is ever added to
`PortalRpcDispatcher`** (C1), pinned by
`::test_the_portal_dispatcher_has_none_of_the_v2_operations`.

```python
class CoreRpcV2(Protocol):
    def get_guard_modes(self) -> GuardModes: ...
    def set_guard_mode(self, guard: GuardName, mode: GuardMode, actor: str) -> GuardModes: ...
    def panic(self, actor: str) -> PanicResult: ...
    def list_offenders(self) -> tuple[OffenderEntry, ...]: ...
    def list_bindings(self) -> tuple[Binding, ...]: ...
    def get_engine_stats(self) -> EngineStats: ...
```

The result models are defined in the same module:

* `GuardModes{raw, input, forward, read_at}`
* `OffenderEntry{mac, code, guard, guard_mode, sustained_polls, first_seen, last_seen}`
* `EngineStats{backend: native|python|replay, has_packet_ring, frames_seen, kernel_drops, flows_shed, new_flow_signals_shed, panics_caught, read_at}`
* `PanicResult{deleted_tables, restore_command, actor, performed_at}`

**Rules:**

* The four read operations are served from snapshots that the poller and
  lease-sync threads publish, **never under core's single RPC lock**.
* `set_guard_mode(…, ENFORCE)` needs the admin password again at the API.
* Every `set_guard_mode` and `panic` call writes an audit event.
* `actor` is the authenticated admin username.

## 10. Native flow record additions (phase 14)

`native/src/parse.rs` → `FlowState` → `FlowRecord` and `NewFlowRecord`
gain:

```
src_mac: int   # 48-bit EUI-48 as an unsigned integer, octets big-endian
dst_mac: int
```

These are integers like the existing `src`/`dst` (IPv4 as `u32`), so the
record stays plain scalars. The Python side converts them to `MacAddress`
strings, and both the Python and native paths must produce identical values
(the parity test). For a frame, "src" means the Ethernet source of the
packet that opened the flow, which is the initiator's MAC. Python
`PacketMetadata` and `Flow` gain `source_mac`/`destination_mac:
MacAddress | None = None`, defaulted so that the dataset adapters stay
valid.

`typings/pirewall_native.pyi` gains the fields only when the extension
actually has them, in phase 14. Until then the stub must not claim them.

MAC is never a model feature. Phase 14 adds a test that `FEATURE_NAMES`
contains no MAC or OUI field.

**Phase 15 additions (D6).** The module exports `NativeEngineError` (a
`RuntimeError` subclass) and `HAS_PANIC_INJECTION`. Every `FlowEngine`
method and `PacketRing.poll` raise `NativeEngineError` on a caught panic.
`FlowEngine.panic_stats() -> (panics caught, open flows discarded)`. The
test-only `FlowEngine._arm_test_panic(site, count)` exists only in a build
with the `panic-injection` cargo feature, which maturin never enables.
`pirewall.flow.native` re-raises the error as
`pirewall.core.exceptions.NativeEngineError`.

## 11. Connection start — `pirewall/flow/connection_start.py`

D1 counts **connection starts**, not flow records. A record is a connection
start when both of these hold:

1. **Its initiator sent a SYN.** The record is TCP, and its opening packet
   was a SYN without ACK/RST (`Flow.opened_by_initiation`, native
   `FlowState.initiated`).
2. **It is the first record for its 5-tuple.** No earlier record for the
   same (source IP, destination IP, source port, destination port,
   protocol) has been observed.

A long connection that the active timeout splits into several records
therefore counts once. UDP and ICMP records are never connection starts;
those floods are the kernel meters' job.

"Earlier" is bounded. The tracker remembers at most `max_tracked` 5-tuples,
evicting the least recently seen. An evicted tuple seen again counts as a
new start, which errs toward over-counting and shows up in an eviction
counter.

`ConnectionStartTracker(max_tracked).observe(flow) -> bool`, with
`max_tracked` from `flow.connection_start_max_tracked`.
**Phase 15** implemented it (`pcap_to_flows.py` writes a `connection_start`
column), and **phase 17** imports the same class. There is one
definition: thresholds learned offline must mean the same thing live.

## 12. File ownership

**Integrator files.** Only the phase named may edit them, in this order.
Every other phase reaches them through their public API.

| File | Owner(s), in order | What each does there |
|---|---|---|
| `pirewall/firewall/manager.py` | **13**, then **14** | 13: set-backend path, `set_guard_mode`, kill switch, panic stub, reconcile. 14: `sync_bindings`, MAC targets, `blocking_rules_matching` by IP→MAC. |
| `pirewall/runtime/core.py` | **14**, then **16**, then **17** | 14: lease-sync thread and `BindingTable` wiring. 16: RPC snapshot wiring and replay capture selection (`--data-mode mock`). 17: K poller and the `engine = "v2"` pipeline. |
| `pirewall/ipc/dispatcher.py` | **16** | The six v2 operations. `pirewall/ipc/protocol.py`'s `RpcOperation` additions go with them. |

**Phase-owned paths.**

| Phase | Owns |
|---|---|
| 11 | `docs/ADDENDUM_4.md`, this file, the `CLAUDE.md` v2 section, the v2 config sections, `scripts/deployment/migrate_config.py`, the contract stubs (`pirewall/core/nft_names.py`, `binding_table.py`, `models/{identity,evidence_v2,policy}.py`, the v2 enums and MAC types, `pirewall/ipc/protocol_v2.py`, `pirewall/flow/connection_start.py`), and their tests |
| 12 | `pirewall/api/**`, `pirewall/portal/**`, `scripts/deployment/portal_users.py`, `scripts/deployment/make_certs.sh`, comments in `config/*` |
| 13 | `deploy/firewall/**`, `pirewall/firewall/backend/**`, `pirewall/firewall/validator.py`, new `pirewall/firewall/{sets,guards}.py`, `scripts/deployment/render_templates.py`, `tests/netns/**`, and `nft_names.py` additions (§7) |
| 14 | `native/src/{parse,flow,lib}.rs` (the MAC fields only), `typings/pirewall_native.pyi`, `pirewall/capture/**`, `pirewall/flow/**` (not `connection_start.py`), `pirewall/core/models/{packet,flow,rule,allowlist,portal}.py`, `pirewall/ipc/portal_service.py`, the portal set in `deploy/firewall/portal.nft.template`, `pirewall/firewall/validator.py` (MAC checks, after 13), `pirewall/portal/**` (MAC binding, after 12) |
| 15 | `native/**` (hardening, fuzz; rebased on 14's MAC fields), `pirewall/capture/replay.py`, `pirewall/capture/pcapio.py`, `pirewall/flow/connection_start.py`, `scripts/dataset/**`, `benchmarks/v2-native-pi/` |
| 16 | `scripts/deployment/pirewall-start`, `deploy/systemd/**`, `deploy/network/**`, `scripts/deployment/configure.py`, `scripts/deployment/install_nftables_pth.sh`, `docs/SETUP.md`, `setup-new-network.md`, the v2 API routes and control-panel panel (`pirewall/api/**` and `pirewall/web/**`, after 12) |
| 17 | `pirewall/policy/**`, `pirewall/detection_v2/**`, `pirewall/runtime/pipeline.py`, `pirewall/engine/**`, `scripts/train/fit_d1_thresholds.py`, `config/d1_thresholds.toml`, `deploy/wazuh/pirewall_decoder.xml` |
| 18–20 | **Prompts not yet written.** Tentatively, from PLAN_v3 §8: 18 `lab/**` (harness, data modes, aggregate); 19 ML datasets and training on schema 3.0.0; 20 docs reconciliation and paper tables. Their prompts confirm or replace this row. |

**Shared, additive only.**

* **`pirewall/config/models.py` and `config/default_config.toml`:** any phase
  may add fields or sections for its own scope, with defaults. None may
  rename or remove one (`extra="forbid"`). If a phase adds a key that older
  `local_config.toml` files need, it extends `migrate_config.py` too.
* **`pirewall/core/enums.py`:** members may be added, never renamed.
* **`docs/PROGRESS.md`:** every phase updates its own row and section.

**Known overlaps**, resolved by phase order, not by a split:

* Phase 12 and phase 14 both touch `pirewall/portal/**`. 14 starts after 12
  is merged, or rebases onto it.
* Phase 13 and phase 14 both touch `validator.py` and `manager.py`, in that
  order.
* Phase 15 runs in parallel with 13 but must not edit `runtime/core.py`. Its
  `ReplayCapture` is wired into capture selection by phase 16.

## 13. Phase-17 additions

All additive (§0). Each is pinned by the test named.

* **`SecurityEventType.POLICY_DECISION`** and optional `SecurityEvent`
  fields `mac`, `engine: PipelineEngine`, `policy_decision_id`,
  `evidence_ids` (default `()`), `requires_approval`. The Wazuh JSON carries
  them when set (`pirewall/integration/wazuh.py`), and
  `deploy/wazuh/pirewall_decoder.xml` matches them
  (`tests/unit/test_enums.py`, `tests/unit/test_wazuh_decoder.py`).
* **`SetBackend.read_counters(names, *, table, family) -> dict[str, int]`**:
  packet counts of named counters, missing ones omitted; implemented by
  `NftablesSetBackend` (one `list counter` each) and `FakeSetBackend`
  (with `record_offender`/`bump_counter` test hooks standing in for the
  kernel). `@offenders` keys list as `(mac, "<code>")`: nft prints the
  `inet_service` half as an integer (`tests/netns/test_kernel_data_plane.py::test_17_*`).
* **`FirewallManager` read-only kernel views**: `kernel_offenders()`,
  `kernel_counters(names)`, `kernel_set_fill(table, set_name)`. They only
  read; the kernel stays `@offenders`' only writer (`tests/unit/test_kernel_poller.py`).
* **`NetdataMetricsSnapshot.v2: V2Gauges | None`**: guard meter hits per
  poll (raw/input/forward), offenders, max set fill, kernel/D1 evidence and
  policy decision counts, D1 tracked MACs and evictions; exported as
  `pirewall.v2.<name>` (`tests/unit/test_v2_pipeline.py::test_the_netdata_snapshot_exports_v2_gauges`).
* **`list_offenders` (§9) is now populated**: under `pipeline.engine = "v2"` the kernel poller publishes each poll (`first_seen` = the episode start); under v1 it stays empty with `offenders_polled = false`.
* **`PortalService(on_login_failure=...)`**: told `(account, client_ip,
  client_mac, at)` of each wrong-password attempt, never the password.
* **The D1 thresholds file** (`pirewall/detection_v2/thresholds.py`):
  `version = 1`, `frozen`, `sha256` over the entries, `[provenance]`, and
  one `[[threshold]]` per `<detector>/<scope>/<window>` with `value`,
  `floor`, `ceiling` and, when fitted, `benign_p999`, `margin`, `samples`
  (`tests/unit/test_d1_thresholds.py`).
* **The policy table file** (`pirewall/policy/table.toml`): `version = 1`,
  `[d1] high/standard`, and one `[[row]]` per `EvidenceClass` with
  `shadow`/`assisted`/`active` cells and optional `escalate`
  (`tests/unit/test_policy_matrix.py`).
