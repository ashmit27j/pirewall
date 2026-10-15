//! `pirewall_native`: the per-packet hot path, as an optional CPython extension.
//!
//! Python remains the system: detection, decisions, validation, enforcement,
//! the API — none of it lives here. This crate only replaces the three
//! stages that run once per *packet* rather than once per *flow* (capture,
//! header parsing, flow aggregation), because those are what the Pi could
//! not keep up with in Python (benchmarks/2026-09-10-attack-lab: 94% of a
//! 10k pkt/s SYN flood dropped). It produces exactly what the Python stages
//! produce — completed flows, new-flow signals, TLS candidate payloads — and
//! `pirewall.capture.native` turns those into the same domain objects.
//!
//! Locking discipline: every mutex here is only ever taken while the GIL is
//! released, and dropped before the GIL is re-acquired, so no thread can hold
//! one while waiting for the other.

mod flow;
mod parse;

#[cfg(target_os = "linux")]
mod capture;

use std::sync::Mutex;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use flow::{Engine, FlowState};

/// A finalized flow's accumulated statistics (everything `Flow` needs).
#[pyclass(frozen, get_all, module = "pirewall_native")]
pub struct FlowRecord {
    src: u32,
    dst: u32,
    sport: Option<u16>,
    dport: Option<u16>,
    protocol: &'static str,
    first_seen_us: i64,
    last_seen_us: i64,
    packet_count: u64,
    byte_count: u64,
    forward_packet_count: u64,
    backward_packet_count: u64,
    forward_byte_count: u64,
    backward_byte_count: u64,
    forward_payload_bytes: u64,
    backward_payload_bytes: u64,
    syn: u64,
    ack: u64,
    fin: u64,
    rst: u64,
    psh: u64,
    urg: u64,
    size_min: f64,
    size_max: f64,
    size_mean: f64,
    size_std: f64,
    payload_min: f64,
    payload_max: f64,
    payload_mean: f64,
    payload_sample_std: f64,
    iat_min: f64,
    iat_max: f64,
    iat_mean: f64,
    iat_sample_std: f64,
    opened_by_initiation: bool,
}

impl From<&FlowState> for FlowRecord {
    fn from(s: &FlowState) -> Self {
        Self {
            src: s.fwd_src,
            dst: s.fwd_dst,
            sport: s.fwd_sport,
            dport: s.fwd_dport,
            protocol: s.proto.as_str(),
            first_seen_us: s.first_seen_us,
            last_seen_us: s.last_seen_us,
            packet_count: s.packet_count,
            byte_count: s.byte_count,
            forward_packet_count: s.fwd_packets,
            backward_packet_count: s.bwd_packets,
            forward_byte_count: s.fwd_bytes,
            backward_byte_count: s.bwd_bytes,
            forward_payload_bytes: s.fwd_payload,
            backward_payload_bytes: s.bwd_payload,
            syn: s.syn,
            ack: s.ack,
            fin: s.fin,
            rst: s.rst,
            psh: s.psh,
            urg: s.urg,
            size_min: s.packet_size.min(),
            size_max: s.packet_size.max(),
            size_mean: s.packet_size.mean(),
            size_std: s.packet_size.std(),
            payload_min: s.payload_size.min(),
            payload_max: s.payload_size.max(),
            payload_mean: s.payload_size.mean(),
            payload_sample_std: s.payload_size.sample_std(),
            iat_min: s.inter_arrival.min(),
            iat_max: s.inter_arrival.max(),
            iat_mean: s.inter_arrival.mean(),
            iat_sample_std: s.inter_arrival.sample_std(),
            opened_by_initiation: s.initiated,
        }
    }
}

/// A newly opened flow (`NewFlowSignal`).
#[pyclass(frozen, get_all, module = "pirewall_native")]
pub struct NewFlowRecord {
    src: u32,
    dst: u32,
    dport: Option<u16>,
    protocol: &'static str,
    ts_us: i64,
}

/// A TCP/443 payload that could be a TLS heartbeat or ClientHello.
#[pyclass(frozen, get_all, module = "pirewall_native")]
pub struct TlsRecord {
    src: u32,
    dst: u32,
    sport: Option<u16>,
    dport: Option<u16>,
    ts_us: i64,
    payload: Py<PyBytes>,
}

type Drained = (Vec<FlowState>, Vec<flow::NewFlow>, Vec<flow::TlsCandidate>);

/// The flow table plus parser. Thread-safe; see the module docstring.
#[pyclass(frozen, module = "pirewall_native")]
pub struct FlowEngine {
    inner: Mutex<Engine>,
}

impl FlowEngine {
    fn with<R: Send>(&self, py: Python<'_>, f: impl FnOnce(&mut Engine) -> R + Send) -> R {
        py.allow_threads(|| f(&mut self.inner.lock().expect("engine mutex poisoned")))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Engine> {
        self.inner.lock().expect("engine mutex poisoned")
    }
}

fn records(states: &[FlowState]) -> Vec<FlowRecord> {
    states.iter().map(FlowRecord::from).collect()
}

#[pymethods]
impl FlowEngine {
    #[new]
    #[pyo3(signature = (
        active_timeout_seconds,
        inactive_timeout_seconds,
        max_flows,
        protected_network=None,
        tls_port=443,
        max_pending_completed=None,
        max_pending_new_flows=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        active_timeout_seconds: f64,
        inactive_timeout_seconds: f64,
        max_flows: usize,
        protected_network: Option<(u32, u8)>,
        tls_port: u16,
        max_pending_completed: Option<usize>,
        max_pending_new_flows: Option<usize>,
    ) -> PyResult<Self> {
        if max_flows == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err("max_flows must be positive"));
        }
        if let Some((_, prefix)) = protected_network {
            if prefix > 32 {
                return Err(pyo3::exceptions::PyValueError::new_err("prefix length must be <= 32"));
            }
        }
        let mut engine = Engine::new(
            active_timeout_seconds,
            inactive_timeout_seconds,
            max_flows,
            protected_network,
            tls_port,
        );
        engine.set_pending_limits(
            max_pending_completed.unwrap_or(usize::MAX),
            max_pending_new_flows.unwrap_or(usize::MAX),
        );
        Ok(Self { inner: Mutex::new(engine) })
    }

    /// Feed one Ethernet frame captured at `ts_us` (Unix microseconds). For
    /// replay and tests; live capture feeds the engine from Rust directly.
    fn feed(&self, frame: &[u8], ts_us: i64) {
        self.lock().feed(frame, ts_us);
    }

    /// Take everything produced since the last drain:
    /// `(completed flows, new-flow signals, TLS candidates)`.
    fn drain(&self, py: Python<'_>) -> PyResult<(Vec<FlowRecord>, Vec<NewFlowRecord>, Vec<TlsRecord>)> {
        let (completed, new_flows, tls): Drained = self.with(py, |e| {
            (std::mem::take(&mut e.completed), std::mem::take(&mut e.new_flows), std::mem::take(&mut e.tls))
        });
        let new_flows = new_flows
            .into_iter()
            .map(|n| NewFlowRecord {
                src: n.src,
                dst: n.dst,
                dport: n.dport,
                protocol: n.proto.as_str(),
                ts_us: n.ts_us,
            })
            .collect();
        let tls = tls
            .into_iter()
            .map(|t| TlsRecord {
                src: t.src,
                dst: t.dst,
                sport: t.sport,
                dport: t.dport,
                ts_us: t.ts_us,
                payload: PyBytes::new(py, &t.payload).unbind(),
            })
            .collect();
        Ok((records(&completed), new_flows, tls))
    }

    /// Close every flow that has timed out as of `now_us`.
    fn sweep(&self, py: Python<'_>, now_us: i64) -> Vec<FlowRecord> {
        records(&self.with(py, |e| e.sweep(now_us)))
    }

    /// `(source, destination, concurrent count, representative flow)` per qualifying pair.
    fn slow_clusters(
        &self,
        py: Python<'_>,
        now_us: i64,
        min_duration_seconds: f64,
        max_bytes_per_second: f64,
        concurrent_threshold: usize,
    ) -> Vec<(u32, u32, usize, FlowRecord)> {
        self.with(py, |e| {
            e.slow_clusters(now_us, min_duration_seconds, max_bytes_per_second, concurrent_threshold)
                .into_iter()
                .map(|c| (c.src, c.dst, c.count, FlowRecord::from(&c.representative)))
                .collect()
        })
    }

    /// Snapshot of `src`'s most recently active open flow, if any.
    fn snapshot_open_flow_from(&self, py: Python<'_>, src: u32) -> Option<FlowRecord> {
        self.with(py, |e| e.snapshot_from(src).as_ref().map(FlowRecord::from))
    }

    /// Finalize every open flow (graceful shutdown).
    fn flush(&self, py: Python<'_>) -> Vec<FlowRecord> {
        records(&self.with(py, |e| e.flush()))
    }

    /// `(packets seen, packets malformed or unsupported)`, cumulative.
    fn counters(&self, py: Python<'_>) -> (u64, u64) {
        self.with(py, |e| (e.packets_seen, e.packets_malformed))
    }

    /// `(completed flows shed, new-flow signals shed)` by the per-drain caps, cumulative.
    fn shed(&self, py: Python<'_>) -> (u64, u64) {
        self.with(py, |e| (e.completed_shed, e.new_flows_shed))
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.with(py, |e| e.len())
    }
}

#[pymodule]
fn pirewall_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FlowEngine>()?;
    m.add_class::<FlowRecord>()?;
    m.add_class::<NewFlowRecord>()?;
    m.add_class::<TlsRecord>()?;
    #[cfg(target_os = "linux")]
    m.add_class::<capture::PacketRing>()?;
    m.add("HAS_PACKET_RING", cfg!(target_os = "linux"))?;
    Ok(())
}
