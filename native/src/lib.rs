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
//! one while waiting for the other. (`feed` is the one exception: it holds
//! the GIL throughout and never waits for it, so it cannot deadlock either.)
//!
//! Panic discipline (ADDENDUM_4.md D6): the crate builds with
//! `panic = "unwind"`, and every Python-callable entry point runs inside
//! `std::panic::catch_unwind`. A panic surfaces in Python as
//! `NativeEngineError` (an ordinary `RuntimeError` subclass, not PyO3's
//! `BaseException`-derived `PanicException`), is counted in
//! `panic_stats()`, and costs the frame or batch it interrupted. A panic
//! that unwound while the engine was locked may have left the flow table
//! half-updated, so the next lock clears the table (`Engine::recover`)
//! before anything reads it; the open flows lost are counted, never silent.

pub mod flow;
pub mod parse;

#[cfg(target_os = "linux")]
mod capture;

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use flow::{Engine, FlowState};

pyo3::create_exception!(
    pirewall_native,
    NativeEngineError,
    pyo3::exceptions::PyRuntimeError,
    "A panic inside the native engine, caught at the Python boundary (ADDENDUM_4.md D6)."
);

/// The panic payload as text, for the `NativeEngineError` message.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Run `f`, turning a panic into `Err(message)`.
pub(crate) fn guarded<R>(f: impl FnOnce() -> R) -> Result<R, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| panic_message(payload.as_ref()))
}

/// A finalized flow's accumulated statistics (everything `Flow` needs).
#[pyclass(frozen, get_all, module = "pirewall_native")]
pub struct FlowRecord {
    src: u32,
    dst: u32,
    src_mac: u64,
    dst_mac: u64,
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
            src_mac: s.fwd_src_mac,
            dst_mac: s.fwd_dst_mac,
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
    src_mac: u64,
    dst_mac: u64,
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
    panics: AtomicU64,
}

impl FlowEngine {
    /// Run `f` on the engine with the GIL released, inside `catch_unwind`.
    fn with<R: Send>(
        &self,
        py: Python<'_>,
        what: &str,
        f: impl FnOnce(&mut Engine) -> R + Send,
    ) -> PyResult<R> {
        let outcome = py.allow_threads(|| {
            guarded(|| {
                let mut engine = self.lock();
                #[cfg(feature = "panic-injection")]
                engine.injected_panic(what);
                f(&mut engine)
            })
        });
        outcome.map_err(|message| self.panicked(what, &message))
    }

    /// Lock the engine. A lock poisoned by a caught panic is recovered: the
    /// table is cleared (it may be half-updated) and the poison flag reset.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Engine> {
        match self.inner.lock() {
            Ok(engine) => engine,
            Err(poisoned) => {
                let mut engine = poisoned.into_inner();
                engine.recover();
                self.inner.clear_poison();
                engine
            }
        }
    }

    /// Count a caught panic and build the error Python sees.
    pub(crate) fn panicked(&self, what: &str, message: &str) -> PyErr {
        self.panics.fetch_add(1, Ordering::Relaxed);
        NativeEngineError::new_err(format!("native engine panicked in {what}: {message}"))
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
        Ok(Self { inner: Mutex::new(engine), panics: AtomicU64::new(0) })
    }

    /// Feed one Ethernet frame captured at `ts_us` (Unix microseconds). For
    /// replay and tests; live capture feeds the engine from Rust directly.
    /// Keeps the GIL (one frame is cheaper than a GIL round trip). Raises
    /// `NativeEngineError` if the engine panicked on this frame.
    fn feed(&self, frame: &[u8], ts_us: i64) -> PyResult<()> {
        guarded(|| self.lock().feed(frame, ts_us)).map_err(|message| self.panicked("feed", &message))
    }

    /// Take everything produced since the last drain:
    /// `(completed flows, new-flow signals, TLS candidates)`.
    fn drain(&self, py: Python<'_>) -> PyResult<(Vec<FlowRecord>, Vec<NewFlowRecord>, Vec<TlsRecord>)> {
        let (completed, new_flows, tls): Drained = self.with(py, "drain", |e| {
            (std::mem::take(&mut e.completed), std::mem::take(&mut e.new_flows), std::mem::take(&mut e.tls))
        })?;
        let new_flows = new_flows
            .into_iter()
            .map(|n| NewFlowRecord {
                src: n.src,
                dst: n.dst,
                src_mac: n.src_mac,
                dst_mac: n.dst_mac,
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
    fn sweep(&self, py: Python<'_>, now_us: i64) -> PyResult<Vec<FlowRecord>> {
        Ok(records(&self.with(py, "sweep", |e| e.sweep(now_us))?))
    }

    /// `(source, destination, concurrent count, representative flow)` per qualifying pair.
    fn slow_clusters(
        &self,
        py: Python<'_>,
        now_us: i64,
        min_duration_seconds: f64,
        max_bytes_per_second: f64,
        concurrent_threshold: usize,
    ) -> PyResult<Vec<(u32, u32, usize, FlowRecord)>> {
        self.with(py, "slow_clusters", |e| {
            e.slow_clusters(now_us, min_duration_seconds, max_bytes_per_second, concurrent_threshold)
                .into_iter()
                .map(|c| (c.src, c.dst, c.count, FlowRecord::from(&c.representative)))
                .collect()
        })
    }

    /// Snapshot of `src`'s most recently active open flow, if any.
    fn snapshot_open_flow_from(&self, py: Python<'_>, src: u32) -> PyResult<Option<FlowRecord>> {
        self.with(py, "snapshot_open_flow_from", |e| e.snapshot_from(src).as_ref().map(FlowRecord::from))
    }

    /// Finalize every open flow (graceful shutdown).
    fn flush(&self, py: Python<'_>) -> PyResult<Vec<FlowRecord>> {
        Ok(records(&self.with(py, "flush", |e| e.flush())?))
    }

    /// `(packets seen, packets malformed or unsupported)`, cumulative.
    fn counters(&self, py: Python<'_>) -> PyResult<(u64, u64)> {
        self.with(py, "counters", |e| (e.packets_seen, e.packets_malformed))
    }

    /// `(completed flows shed, new-flow signals shed)` by the per-drain caps, cumulative.
    fn shed(&self, py: Python<'_>) -> PyResult<(u64, u64)> {
        self.with(py, "shed", |e| (e.completed_shed, e.new_flows_shed))
    }

    /// `(panics caught, open flows discarded recovering from them)`, cumulative.
    fn panic_stats(&self, py: Python<'_>) -> PyResult<(u64, u64)> {
        let lost = self.with(py, "panic_stats", |e| e.flows_lost_to_panics)?;
        Ok((self.panics.load(Ordering::Relaxed), lost))
    }

    /// Test-only (`panic-injection` feature): make the next `count` engine
    /// calls at `site` panic while holding the engine lock. `site` is an
    /// entry point name (`"feed"`, `"drain"`, `"sweep"`, ...); `"feed"`
    /// also covers frames fed from a `PacketRing`.
    #[cfg(feature = "panic-injection")]
    fn _arm_test_panic(&self, py: Python<'_>, site: String, count: u32) -> PyResult<()> {
        self.with(py, "_arm_test_panic", move |e| e.arm_panic(site, count))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.with(py, "__len__", |e| e.len())
    }
}

#[pymodule]
fn pirewall_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FlowEngine>()?;
    m.add_class::<FlowRecord>()?;
    m.add_class::<NewFlowRecord>()?;
    m.add_class::<TlsRecord>()?;
    m.add("NativeEngineError", m.py().get_type::<NativeEngineError>())?;
    m.add("HAS_PANIC_INJECTION", cfg!(feature = "panic-injection"))?;
    #[cfg(target_os = "linux")]
    m.add_class::<capture::PacketRing>()?;
    m.add("HAS_PACKET_RING", cfg!(target_os = "linux"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> FlowEngine {
        FlowEngine { inner: Mutex::new(Engine::new(120.0, 60.0, 100, None, 443)), panics: AtomicU64::new(0) }
    }

    fn syn(src: u8, sport: u16) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, src, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, src, 10, 0, 0, 1]);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&[0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, parse::TCP_SYN, 4, 0, 0, 0, 0, 0]);
        f
    }

    #[test]
    fn guarded_turns_a_panic_into_its_message() {
        assert_eq!(guarded(|| 5), Ok(5));
        assert_eq!(guarded(|| -> u8 { panic!("boom {}", 1) }), Err("boom 1".to_owned()));
        assert_eq!(
            guarded(|| -> u8 { std::panic::panic_any(3_u8) }),
            Err("non-string panic payload".to_owned())
        );
    }

    #[test]
    fn a_panic_while_locked_clears_the_table_and_the_lock_stays_usable() {
        let e = engine();
        e.lock().feed(&syn(5, 1000), 0);
        e.lock().feed(&syn(6, 1001), 1);
        assert_eq!(e.lock().len(), 2);
        let caught = guarded(|| {
            let _held = e.lock();
            panic!("mid-update");
        });
        assert!(caught.is_err());
        assert!(e.inner.is_poisoned());
        let mut recovered = e.lock();
        assert!(!e.inner.is_poisoned());
        assert_eq!(recovered.len(), 0);
        assert_eq!(recovered.flows_lost_to_panics, 2);
        // Pending output and counters survive; the engine keeps working.
        assert_eq!(recovered.new_flows.len(), 2);
        assert_eq!(recovered.packets_seen, 2);
        recovered.feed(&syn(7, 1002), 2);
        assert_eq!(recovered.len(), 1);
    }

    #[cfg(feature = "panic-injection")]
    #[test]
    fn an_armed_panic_fires_once_at_its_site() {
        let e = engine();
        e.lock().arm_panic("feed".to_owned(), 1);
        assert!(guarded(|| e.lock().feed(&syn(5, 1000), 0)).is_err());
        assert!(guarded(|| e.lock().feed(&syn(5, 1000), 0)).is_ok());
        assert_eq!(e.lock().len(), 1);
    }
}
