//! The flow table: a port of `pirewall/flow/{state,aggregator,timeout}.py`.
//!
//! Same Welford accumulation in the same operation order, same microsecond
//! clock, same LRU eviction, same closure rules, same iteration order for
//! sweeps and snapshots — so a `Flow` built from this engine's output is
//! field-for-field identical to one the Python aggregator builds from the
//! same frames. That is what lets the native path replace the Python one
//! without reopening the training/runtime feature gap that feature schema
//! 2.0.0 closed: both are held to it by `tests/unit/test_native_parity.py`.

use std::collections::HashMap;

use crate::parse::{self, Packet, ParseError, Proto, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};

const NIL: usize = usize::MAX;
const LIMITED_BROADCAST: u32 = 0xFFFF_FFFF;

/// Online min/max/mean/std (Welford), identical to `RunningStats`.
#[derive(Clone, Copy, Debug)]
pub struct RunningStats {
    pub count: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl RunningStats {
    fn new() -> Self {
        Self { count: 0, mean: 0.0, m2: 0.0, min: f64::INFINITY, max: f64::NEG_INFINITY }
    }

    fn add(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (value - self.mean);
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    pub fn mean(&self) -> f64 {
        if self.count > 0 {
            self.mean
        } else {
            0.0
        }
    }

    pub fn std(&self) -> f64 {
        if self.count > 0 {
            (self.m2 / self.count as f64).sqrt()
        } else {
            0.0
        }
    }

    pub fn sample_std(&self) -> f64 {
        if self.count > 1 {
            (self.m2 / (self.count - 1) as f64).sqrt()
        } else {
            0.0
        }
    }

    pub fn min(&self) -> f64 {
        if self.count > 0 {
            self.min
        } else {
            0.0
        }
    }

    pub fn max(&self) -> f64 {
        if self.count > 0 {
            self.max
        } else {
            0.0
        }
    }
}

/// Direction-independent flow identity (`FlowKey`): endpoints sorted by
/// (address, port-or--1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    proto: Proto,
    a: (u32, i32),
    b: (u32, i32),
}

fn port_value(port: Option<u16>) -> i32 {
    port.map_or(-1, i32::from)
}

pub fn flow_key(src: u32, dst: u32, sport: Option<u16>, dport: Option<u16>, proto: Proto) -> FlowKey {
    let forward = (src, port_value(sport));
    let backward = (dst, port_value(dport));
    if backward < forward {
        FlowKey { proto, a: backward, b: forward }
    } else {
        FlowKey { proto, a: forward, b: backward }
    }
}

/// Mutable per-flow accumulator (`FlowState`).
#[derive(Clone, Debug)]
pub struct FlowState {
    pub proto: Proto,
    pub fwd_src: u32,
    pub fwd_sport: Option<u16>,
    pub fwd_dst: u32,
    pub fwd_dport: Option<u16>,
    /// Ethernet source/destination of the opening frame: the initiator's
    /// MAC, even when its IP source was spoofed (`Flow.source_mac`).
    pub fwd_src_mac: u64,
    pub fwd_dst_mac: u64,
    pub first_seen_us: i64,
    pub last_seen_us: i64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub fwd_packets: u64,
    pub bwd_packets: u64,
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    pub fwd_payload: u64,
    pub bwd_payload: u64,
    pub syn: u64,
    pub ack: u64,
    pub fin: u64,
    pub rst: u64,
    pub psh: u64,
    pub urg: u64,
    saw_fin_forward: bool,
    saw_fin_backward: bool,
    saw_rst: bool,
    /// `Flow.opened_by_initiation`: the opening packet was a TCP SYN without
    /// ACK/RST, or anything non-TCP.
    pub initiated: bool,
    pub packet_size: RunningStats,
    pub payload_size: RunningStats,
    pub inter_arrival: RunningStats,
    last_packet_us: Option<i64>,
}

impl FlowState {
    fn opening(packet: &Packet) -> Self {
        let mut state = Self {
            proto: packet.proto,
            fwd_src: packet.src,
            fwd_sport: packet.sport,
            fwd_dst: packet.dst,
            fwd_dport: packet.dport,
            fwd_src_mac: packet.src_mac,
            fwd_dst_mac: packet.dst_mac,
            first_seen_us: packet.ts_us,
            last_seen_us: packet.ts_us,
            packet_count: 0,
            byte_count: 0,
            fwd_packets: 0,
            bwd_packets: 0,
            fwd_bytes: 0,
            bwd_bytes: 0,
            fwd_payload: 0,
            bwd_payload: 0,
            syn: 0,
            ack: 0,
            fin: 0,
            rst: 0,
            psh: 0,
            urg: 0,
            saw_fin_forward: false,
            saw_fin_backward: false,
            saw_rst: false,
            initiated: match packet.tcp_flags {
                Some(flags) if packet.proto == Proto::Tcp => {
                    flags & TCP_SYN != 0 && flags & (TCP_ACK | TCP_RST) == 0
                }
                _ => true,
            },
            packet_size: RunningStats::new(),
            payload_size: RunningStats::new(),
            inter_arrival: RunningStats::new(),
            last_packet_us: None,
        };
        state.observe(packet);
        state
    }

    fn observe(&mut self, packet: &Packet) {
        let is_forward = packet.src == self.fwd_src && packet.sport == self.fwd_sport;
        if packet.ts_us > self.last_seen_us {
            self.last_seen_us = packet.ts_us;
        }
        let length = u64::from(packet.total_length);
        let payload = u64::from(packet.payload_length);
        self.packet_count += 1;
        self.byte_count += length;
        if is_forward {
            self.fwd_packets += 1;
            self.fwd_bytes += length;
            self.fwd_payload += payload;
        } else {
            self.bwd_packets += 1;
            self.bwd_bytes += length;
            self.bwd_payload += payload;
        }
        if let Some(flags) = packet.tcp_flags {
            let set = |bit: u8| u64::from(flags & bit != 0);
            self.syn += set(TCP_SYN);
            self.ack += set(TCP_ACK);
            self.fin += set(TCP_FIN);
            self.rst += set(TCP_RST);
            self.psh += set(TCP_PSH);
            self.urg += set(TCP_URG);
            if flags & TCP_FIN != 0 {
                if is_forward {
                    self.saw_fin_forward = true;
                } else {
                    self.saw_fin_backward = true;
                }
            }
            if flags & TCP_RST != 0 {
                self.saw_rst = true;
            }
        }
        self.packet_size.add(length as f64);
        self.payload_size.add(payload as f64);
        if let Some(previous) = self.last_packet_us {
            let delta = packet.ts_us - previous;
            if delta >= 0 {
                self.inter_arrival.add(delta as f64 / 1e6);
            }
        }
        self.last_packet_us = Some(packet.ts_us);
    }

    fn tcp_completed(&self) -> bool {
        self.proto == Proto::Tcp && (self.saw_rst || (self.saw_fin_forward && self.saw_fin_backward))
    }

    fn should_close(&self, now_us: i64, active_s: f64, inactive_s: f64) -> bool {
        self.tcp_completed()
            || (now_us - self.first_seen_us) as f64 / 1e6 >= active_s
            || (now_us - self.last_seen_us) as f64 / 1e6 >= inactive_s
    }
}

/// A newly opened flow, everything knowable from its first packet (`NewFlowSignal`).
#[derive(Clone, Copy, Debug)]
pub struct NewFlow {
    pub src: u32,
    pub dst: u32,
    pub src_mac: u64,
    pub dst_mac: u64,
    pub dport: Option<u16>,
    pub proto: Proto,
    pub ts_us: i64,
}

/// A TCP/443 payload worth handing to the TLS structural detectors.
#[derive(Clone, Debug)]
pub struct TlsCandidate {
    pub src: u32,
    pub dst: u32,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub ts_us: i64,
    pub payload: Vec<u8>,
}

/// One slow-connection cluster (`SlowConnectionCluster`).
pub struct SlowCluster {
    pub src: u32,
    pub dst: u32,
    pub count: usize,
    pub representative: FlowState,
}

struct Node {
    key: FlowKey,
    state: FlowState,
    prev: usize,
    next: usize,
}

/// Bounded LRU table: a slab of nodes threaded on a doubly-linked list,
/// oldest at `head`, indexed by key. Iterates oldest-first, exactly like
/// the Python `OrderedDict`.
struct LruTable {
    index: HashMap<FlowKey, usize>,
    nodes: Vec<Option<Node>>,
    free: Vec<usize>,
    head: usize,
    tail: usize,
    max: usize,
}

impl LruTable {
    fn new(max: usize) -> Self {
        Self { index: HashMap::new(), nodes: Vec::new(), free: Vec::new(), head: NIL, tail: NIL, max }
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn node(&self, slot: usize) -> &Node {
        self.nodes[slot].as_ref().expect("live slot")
    }

    fn node_mut(&mut self, slot: usize) -> &mut Node {
        self.nodes[slot].as_mut().expect("live slot")
    }

    fn unlink(&mut self, slot: usize) {
        let (prev, next) = {
            let n = self.node(slot);
            (n.prev, n.next)
        };
        if prev == NIL {
            self.head = next
        } else {
            self.node_mut(prev).next = next
        }
        if next == NIL {
            self.tail = prev
        } else {
            self.node_mut(next).prev = prev
        }
    }

    fn link_tail(&mut self, slot: usize) {
        let tail = self.tail;
        {
            let n = self.node_mut(slot);
            n.prev = tail;
            n.next = NIL;
        }
        if tail == NIL {
            self.head = slot
        } else {
            self.node_mut(tail).next = slot
        }
        self.tail = slot;
    }

    /// Look up and mark most-recently-used (`FlowTable.get`).
    fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowState> {
        let slot = *self.index.get(key)?;
        if self.tail != slot {
            self.unlink(slot);
            self.link_tail(slot);
        }
        Some(&mut self.node_mut(slot).state)
    }

    /// Insert a new flow, evicting the oldest if full (`FlowTable.insert`).
    fn insert(&mut self, key: FlowKey, state: FlowState) -> Option<FlowState> {
        let evicted = if self.len() >= self.max && self.head != NIL {
            let oldest = self.node(self.head).key;
            self.pop(&oldest)
        } else {
            None
        };
        let node = Node { key, state, prev: NIL, next: NIL };
        let slot = match self.free.pop() {
            Some(slot) => {
                self.nodes[slot] = Some(node);
                slot
            }
            None => {
                self.nodes.push(Some(node));
                self.nodes.len() - 1
            }
        };
        self.link_tail(slot);
        self.index.insert(key, slot);
        evicted
    }

    fn pop(&mut self, key: &FlowKey) -> Option<FlowState> {
        let slot = self.index.remove(key)?;
        self.unlink(slot);
        let node = self.nodes[slot].take().expect("live slot");
        self.free.push(slot);
        Some(node.state)
    }

    /// Slots oldest-first.
    fn slots(&self) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.len());
        let mut cursor = self.head;
        while cursor != NIL {
            out.push(cursor);
            cursor = self.node(cursor).next;
        }
        out
    }

    fn clear(&mut self) {
        self.index.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
    }
}

/// Parse + aggregate, with the TLS candidate hook — the whole per-packet path.
pub struct Engine {
    table: LruTable,
    active_s: f64,
    inactive_s: f64,
    protected: Option<(u32, u8)>,
    tls_port: u16,
    pub completed: Vec<FlowState>,
    pub new_flows: Vec<NewFlow>,
    pub tls: Vec<TlsCandidate>,
    pub packets_seen: u64,
    pub packets_malformed: u64,
    /// Per-drain caps: beyond these, completed flows / new-flow signals are
    /// counted and discarded here rather than handed to Python, where each
    /// would cost a domain-object conversion only to be dropped by the
    /// daemon's own bounded queues anyway (detection on a Pi handles a few
    /// hundred flows a second; a SYN flood completes tens of thousands).
    max_pending_completed: usize,
    max_pending_new_flows: usize,
    pub completed_shed: u64,
    pub new_flows_shed: u64,
}

fn in_prefix(address: u32, network: u32, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    address & mask == network & mask
}

impl Engine {
    pub fn new(
        active_s: f64,
        inactive_s: f64,
        max_flows: usize,
        protected: Option<(u32, u8)>,
        tls_port: u16,
    ) -> Self {
        Self {
            table: LruTable::new(max_flows),
            active_s,
            inactive_s,
            protected,
            tls_port,
            completed: Vec::new(),
            new_flows: Vec::new(),
            tls: Vec::new(),
            packets_seen: 0,
            packets_malformed: 0,
            max_pending_completed: usize::MAX,
            max_pending_new_flows: usize::MAX,
            completed_shed: 0,
            new_flows_shed: 0,
        }
    }

    /// Bound what accumulates between drains (see the field docs).
    pub fn set_pending_limits(&mut self, completed: usize, new_flows: usize) {
        self.max_pending_completed = completed;
        self.max_pending_new_flows = new_flows;
    }

    fn push_completed(&mut self, state: FlowState) {
        if self.completed.len() < self.max_pending_completed {
            self.completed.push(state);
        } else {
            self.completed_shed += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// `is_routable_unicast`: not unspecified, loopback, multicast,
    /// link-local, reserved (240/4, which includes 255.255.255.255), and not
    /// the protected network's own directed broadcast.
    fn routable(&self, address: u32) -> bool {
        if address == 0
            || in_prefix(address, 0x7F00_0000, 8)
            || in_prefix(address, 0xE000_0000, 4)
            || in_prefix(address, 0xA9FE_0000, 16)
            || in_prefix(address, 0xF000_0000, 4)
            || address == LIMITED_BROADCAST
        {
            return false;
        }
        match self.protected {
            Some((network, prefix)) if prefix < 31 => {
                let host_mask = u32::MAX >> u32::from(prefix);
                address != ((network & !host_mask) | host_mask)
            }
            _ => true,
        }
    }

    /// One captured frame through `capture_packets` + `FlowAggregator.process_packet`.
    pub fn feed(&mut self, raw: &[u8], ts_us: i64) {
        self.packets_seen += 1;
        let packet = match parse::parse(raw, ts_us) {
            Ok(packet) => packet,
            Err(ParseError::Malformed | ParseError::Unsupported) => {
                self.packets_malformed += 1;
                return;
            }
        };
        if packet.proto == Proto::Tcp
            && (packet.sport == Some(self.tls_port) || packet.dport == Some(self.tls_port))
            && packet.ipv4
        {
            self.offer_tls(raw, &packet);
        }
        if !packet.ipv4 || !self.routable(packet.src) || !self.routable(packet.dst) {
            return;
        }
        let key = flow_key(packet.src, packet.dst, packet.sport, packet.dport, packet.proto);
        let close = if let Some(state) = self.table.get_mut(&key) {
            state.observe(&packet);
            state.should_close(packet.ts_us, self.active_s, self.inactive_s)
        } else {
            let state = FlowState::opening(&packet);
            if !state.initiated {
                // A responder's flow: not a new connection (see `initiated`).
            } else if self.new_flows.len() < self.max_pending_new_flows {
                self.new_flows.push(NewFlow {
                    src: packet.src,
                    dst: packet.dst,
                    src_mac: packet.src_mac,
                    dst_mac: packet.dst_mac,
                    dport: packet.dport,
                    proto: packet.proto,
                    ts_us: packet.ts_us,
                });
            } else {
                self.new_flows_shed += 1;
            }
            let close = state.should_close(packet.ts_us, self.active_s, self.inactive_s);
            if let Some(evicted) = self.table.insert(key, state) {
                self.push_completed(evicted);
            }
            close
        };
        if close {
            if let Some(state) = self.table.pop(&key) {
                self.push_completed(state);
            }
        }
    }

    /// Only payloads the detectors could act on: a TLS heartbeat record
    /// (content type 24) or a handshake record carrying a ClientHello
    /// (content type 22, handshake type 1). `check_heartbleed`/`compute_ja3`
    /// return nothing for anything else, so filtering here changes no
    /// result — it just stops every HTTPS data segment crossing into Python.
    fn offer_tls(&mut self, raw: &[u8], packet: &Packet) {
        let Some(payload) = parse::tcp_payload(raw, packet) else { return };
        let interesting = matches!(payload, [24, ..] | [22, _, _, _, _, 1, ..]);
        if interesting {
            self.tls.push(TlsCandidate {
                src: packet.src,
                dst: packet.dst,
                sport: packet.sport,
                dport: packet.dport,
                ts_us: packet.ts_us,
                payload: payload.to_vec(),
            });
        }
    }

    /// `FlowAggregator.sweep_timeouts`.
    pub fn sweep(&mut self, now_us: i64) -> Vec<FlowState> {
        let closing: Vec<FlowKey> = self
            .table
            .slots()
            .into_iter()
            .map(|slot| self.table.node(slot))
            .filter(|node| node.state.should_close(now_us, self.active_s, self.inactive_s))
            .map(|node| node.key)
            .collect();
        closing.iter().filter_map(|key| self.table.pop(key)).collect()
    }

    /// `FlowAggregator.snapshot_slow_connection_clusters`.
    pub fn slow_clusters(
        &self,
        now_us: i64,
        min_duration_s: f64,
        max_bytes_per_s: f64,
        threshold: usize,
    ) -> Vec<SlowCluster> {
        let mut order: Vec<(u32, u32)> = Vec::new();
        let mut groups: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
        for slot in self.table.slots() {
            let state = &self.table.node(slot).state;
            let duration = (now_us - state.first_seen_us) as f64 / 1e6;
            if duration < min_duration_s {
                continue;
            }
            if state.byte_count as f64 / duration > max_bytes_per_s {
                continue;
            }
            let pair = (state.fwd_src, state.fwd_dst);
            groups
                .entry(pair)
                .or_insert_with(|| {
                    order.push(pair);
                    Vec::new()
                })
                .push(slot);
        }
        let mut clusters = Vec::new();
        for pair in order {
            let slots = &groups[&pair];
            if slots.len() < threshold {
                continue;
            }
            let mut representative = slots[0];
            for &slot in &slots[1..] {
                if self.table.node(slot).state.first_seen_us
                    < self.table.node(representative).state.first_seen_us
                {
                    representative = slot;
                }
            }
            clusters.push(SlowCluster {
                src: pair.0,
                dst: pair.1,
                count: slots.len(),
                representative: self.table.node(representative).state.clone(),
            });
        }
        clusters
    }

    /// `FlowAggregator.snapshot_open_flow_from`.
    pub fn snapshot_from(&self, src: u32) -> Option<FlowState> {
        let mut newest: Option<&FlowState> = None;
        for slot in self.table.slots() {
            let state = &self.table.node(slot).state;
            if state.fwd_src != src {
                continue;
            }
            if newest.is_none_or(|best| state.last_seen_us > best.last_seen_us) {
                newest = Some(state);
            }
        }
        newest.cloned()
    }

    /// `FlowAggregator.flush`.
    pub fn flush(&mut self) -> Vec<FlowState> {
        let out = self.table.slots().into_iter().map(|slot| self.table.node(slot).state.clone()).collect();
        self.table.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, payload: usize) -> Vec<u8> {
        let total = 40 + payload;
        let mut f = vec![0x02, 0, dst[0], dst[1], dst[2], dst[3], 0x02, 0, src[0], src[1], src[2], src[3]];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags, 4, 0, 0, 0, 0, 0]);
        f.extend(std::iter::repeat_n(0u8, payload));
        f
    }

    #[test]
    fn a_fin_closed_session_completes_with_both_directions_attributed() {
        let mut engine = Engine::new(120.0, 60.0, 1000, None, 443);
        let (c, s) = ([10, 0, 0, 5], [10, 0, 0, 10]);
        engine.feed(&frame(c, s, 5000, 80, TCP_SYN, 0), 0);
        engine.feed(&frame(s, c, 80, 5000, TCP_SYN | TCP_ACK, 0), 1_000);
        engine.feed(&frame(c, s, 5000, 80, TCP_FIN | TCP_ACK, 10), 2_000);
        engine.feed(&frame(s, c, 80, 5000, TCP_FIN | TCP_ACK, 0), 3_000);
        assert_eq!(engine.new_flows.len(), 1);
        assert_eq!(engine.completed.len(), 1);
        let flow = &engine.completed[0];
        assert_eq!((flow.fwd_packets, flow.bwd_packets), (2, 2));
        assert_eq!((flow.fwd_payload, flow.bwd_payload), (10, 0));
        assert_eq!(flow.inter_arrival.count, 3);
        assert_eq!(engine.len(), 0);
        // The initiator's MAC, from the opening frame, in both directions' record.
        assert_eq!(flow.fwd_src_mac, 0x0200_0A00_0005);
        assert_eq!(flow.fwd_dst_mac, 0x0200_0A00_000A);
        assert_eq!(engine.new_flows[0].src_mac, 0x0200_0A00_0005);
    }

    #[test]
    fn the_table_is_bounded_and_evicts_least_recently_used_first() {
        let mut engine = Engine::new(120.0, 60.0, 2, None, 443);
        let s = [10, 0, 0, 10];
        engine.feed(&frame([10, 0, 0, 1], s, 1, 80, TCP_SYN, 0), 0);
        engine.feed(&frame([10, 0, 0, 2], s, 2, 80, TCP_SYN, 0), 1);
        engine.feed(&frame([10, 0, 0, 1], s, 1, 80, TCP_ACK, 0), 2); // 10.0.0.1 is now MRU
        engine.feed(&frame([10, 0, 0, 3], s, 3, 80, TCP_SYN, 0), 3);
        assert_eq!(engine.len(), 2);
        assert_eq!(engine.completed.len(), 1);
        assert_eq!(engine.completed[0].fwd_src, u32::from_be_bytes([10, 0, 0, 2]));
    }

    #[test]
    fn non_unicast_and_protected_broadcast_never_become_flows() {
        let mut engine =
            Engine::new(120.0, 60.0, 10, Some((u32::from_be_bytes([192, 168, 100, 0]), 24)), 443);
        engine.feed(&frame([0, 0, 0, 0], [255, 255, 255, 255], 68, 67, 0, 0), 0);
        engine.feed(&frame([192, 168, 100, 5], [192, 168, 100, 255], 1, 2, 0, 0), 0);
        engine.feed(&frame([192, 168, 100, 5], [224, 0, 0, 251], 1, 2, 0, 0), 0);
        assert_eq!(engine.len(), 0);
        assert!(engine.new_flows.is_empty());
    }
}
