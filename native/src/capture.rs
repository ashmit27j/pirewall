//! Linux `AF_PACKET` capture over a `TPACKET_V3` memory-mapped ring.
//!
//! Replaces one `recvmsg` syscall (plus a Python object allocation) per
//! packet with a ring of blocks the kernel fills directly: one `poll` wakes
//! us for a whole block of packets, each already carrying the kernel's own
//! receive timestamp. Packets go straight into the `FlowEngine` without ever
//! becoming Python objects; only completed flows, new-flow signals and TLS
//! candidates do (see `FlowEngine.drain`).
//!
//! Every packet seen by the kernel is either placed in the ring or counted as
//! a drop (`PACKET_STATISTICS`), so drops stay measurable exactly as with
//! the Python socket.
//!
//! Defensive bounds (ADDENDUM_4.md D6): the kernel writes every offset and
//! length the ring walker reads, and the kernel is trusted, but
//! `walk_block` still clamps each of them to the block it lives in, so no
//! value read from the ring can make it read outside the mapping. A panic
//! while feeding a block costs the rest of that block: the block is handed
//! back to the kernel regardless and the panic becomes `NativeEngineError`.

use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::sync::Mutex;

use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

use crate::{guarded, FlowEngine};

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_VERSION: libc::c_int = 10;
const PACKET_MR_PROMISC: libc::c_ushort = 1;
const TPACKET_V3: libc::c_int = 2;
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;
// tp_frame_size only shapes the V3 ring's bookkeeping; packets are packed
// variably inside each block and may be as large as the block itself.
const FRAME_SIZE: u32 = 2048;

// struct tpacket_block_desc { u32 version; u32 offset_to_priv; tpacket_hdr_v1 hdr; }
const BLOCK_STATUS_OFFSET: usize = 8;
const BLOCK_NUM_PKTS_OFFSET: usize = 12;
const BLOCK_FIRST_PKT_OFFSET: usize = 16;
// struct tpacket3_hdr
const PKT_NEXT_OFFSET: usize = 0;
const PKT_SEC: usize = 4;
const PKT_NSEC: usize = 8;
const PKT_SNAPLEN: usize = 12;
const PKT_MAC: usize = 24;
// The smallest packet header the walker reads (through `tp_mac`, a u16).
const PKT_HEADER_MIN: usize = PKT_MAC + 2;

fn u32_at(block: &[u8], at: usize) -> Option<u32> {
    block.get(at..at + 4).map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn u16_at(block: &[u8], at: usize) -> Option<u16> {
    block.get(at..at + 2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
}

/// Walk one user-owned `TPACKET_V3` block, calling `on_frame(frame, ts_us)`
/// for each packet, and return how many were visited.
///
/// Every offset and length is read from the block itself and clamped to
/// it: a first-packet offset or `tp_next_offset` that leaves the block ends
/// the walk, a `tp_mac` that leaves it skips the packet, and `tp_snaplen`
/// is truncated to the bytes left in the block. At most `tp_num_pkts`
/// packets are visited. Never reads outside `block`.
pub(crate) fn walk_block(block: &[u8], mut on_frame: impl FnMut(&[u8], i64)) -> usize {
    let Some(count) = u32_at(block, BLOCK_NUM_PKTS_OFFSET) else { return 0 };
    let Some(first) = u32_at(block, BLOCK_FIRST_PKT_OFFSET) else { return 0 };
    let mut offset = first as usize;
    let mut visited = 0usize;
    for _ in 0..count {
        if offset.checked_add(PKT_HEADER_MIN).is_none_or(|end| end > block.len()) {
            break;
        }
        let header = &block[offset..];
        let (Some(sec), Some(nsec), Some(snaplen), Some(mac), Some(next)) = (
            u32_at(header, PKT_SEC),
            u32_at(header, PKT_NSEC),
            u32_at(header, PKT_SNAPLEN),
            u16_at(header, PKT_MAC),
            u32_at(header, PKT_NEXT_OFFSET),
        ) else {
            break;
        };
        let mac = mac as usize;
        if mac <= header.len() {
            let available = header.len() - mac;
            let length = (snaplen as usize).min(available);
            on_frame(&header[mac..mac + length], i64::from(sec) * 1_000_000 + i64::from(nsec) / 1_000);
        }
        visited += 1;
        if next == 0 {
            break;
        }
        offset = match offset.checked_add(next as usize) {
            Some(next_offset) if next_offset < block.len() => next_offset,
            _ => break,
        };
    }
    visited
}

/// Why a `poll` stopped early.
enum PollFailure {
    Os(PyErr),
    Panic(String),
}

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
}

#[repr(C)]
#[derive(Default)]
struct TpacketStatsV3 {
    tp_packets: u32,
    tp_drops: u32,
    tp_freeze_q_cnt: u32,
}

struct Ring {
    fd: libc::c_int,
    map: *mut u8,
    map_len: usize,
    block_size: usize,
    block_count: usize,
    current: usize,
    drops: u64,
}

// The mapping is owned exclusively by this struct and only touched under the
// `PacketRing` mutex.
unsafe impl Send for Ring {}

impl Ring {
    unsafe fn read_u32(&self, at: *const u8) -> u32 {
        std::ptr::read_volatile(at.cast::<u32>())
    }

    fn block(&self, index: usize) -> *mut u8 {
        unsafe { self.map.add(index * self.block_size) }
    }

    fn close(&mut self) {
        unsafe {
            if !self.map.is_null() {
                libc::munmap(self.map.cast(), self.map_len);
                self.map = std::ptr::null_mut();
            }
            if self.fd >= 0 {
                libc::close(self.fd);
                self.fd = -1;
            }
        }
    }

    fn kernel_drops(&mut self) -> u64 {
        if self.fd < 0 {
            return self.drops;
        }
        let mut stats = TpacketStatsV3::default();
        let mut len = std::mem::size_of::<TpacketStatsV3>() as libc::socklen_t;
        // The kernel resets these counters on every read: accumulate.
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_STATISTICS,
                (&mut stats as *mut TpacketStatsV3).cast(),
                &mut len,
            )
        };
        if rc == 0 {
            self.drops += u64::from(stats.tp_drops);
        }
        self.drops
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        self.close();
    }
}

fn os_error(what: &str) -> PyErr {
    PyOSError::new_err(format!("{what}: {}", std::io::Error::last_os_error()))
}

fn setsockopt<T>(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
    what: &str,
) -> PyResult<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(os_error(what))
    }
}

/// A `TPACKET_V3` receive ring bound to one interface.
#[pyclass(frozen, module = "pirewall_native")]
pub struct PacketRing {
    interface: String,
    ring: Mutex<Option<Ring>>,
    running: AtomicBool,
    drops: Mutex<u64>,
}

#[pymethods]
impl PacketRing {
    #[new]
    #[pyo3(signature = (interface, promiscuous, block_size, block_count, block_timeout_ms))]
    fn new(
        py: Python<'_>,
        interface: String,
        promiscuous: bool,
        block_size: u32,
        block_count: u32,
        block_timeout_ms: u32,
    ) -> PyResult<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        if block_size == 0 || block_size % page != 0 || block_size < FRAME_SIZE || block_count == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "block_size must be a positive multiple of the page size ({page}) and >= {FRAME_SIZE}; block_count must be positive"
            )));
        }
        let ring = py.allow_threads(|| {
            open_ring(&interface, promiscuous, block_size, block_count, block_timeout_ms)
        })?;
        Ok(Self {
            interface,
            ring: Mutex::new(Some(ring)),
            running: AtomicBool::new(true),
            drops: Mutex::new(0),
        })
    }

    #[getter]
    fn interface(&self) -> &str {
        &self.interface
    }

    /// Wait up to `timeout_ms` for packets, then feed every ready block into
    /// `engine` (up to roughly `max_packets`), with the GIL released.
    /// Returns the number of packets processed; 0 on timeout or once stopped.
    /// Raises `NativeEngineError` if feeding panicked; the block it was in is
    /// returned to the kernel first, so the ring keeps moving.
    fn poll(
        &self,
        py: Python<'_>,
        engine: &FlowEngine,
        timeout_ms: i32,
        max_packets: usize,
    ) -> PyResult<usize> {
        let outcome = py.allow_threads(|| {
            let mut guard = self.ring.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(ring) = guard.as_mut() else { return Ok(0) };
            let mut processed = 0usize;
            let mut waited = false;
            while self.running.load(Ordering::Relaxed) {
                let block = ring.block(ring.current);
                let status = unsafe { ring.read_u32(block.add(BLOCK_STATUS_OFFSET)) };
                fence(Ordering::Acquire);
                if status & TP_STATUS_USER == 0 {
                    if processed > 0 || waited {
                        break;
                    }
                    let mut pfd =
                        libc::pollfd { fd: ring.fd, events: libc::POLLIN | libc::POLLERR, revents: 0 };
                    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                    if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                        return Err(PollFailure::Os(os_error("poll on capture ring")));
                    }
                    waited = true;
                    continue;
                }
                // The block is user-owned until its status is handed back,
                // so the kernel does not write it while we read it.
                let bytes = unsafe { std::slice::from_raw_parts(block.cast_const(), ring.block_size) };
                let fed = guarded(|| {
                    let mut engine = engine.lock();
                    walk_block(bytes, |frame, ts_us| engine.feed(frame, ts_us))
                });
                fence(Ordering::Release);
                unsafe {
                    std::ptr::write_volatile(block.add(BLOCK_STATUS_OFFSET).cast::<u32>(), TP_STATUS_KERNEL)
                };
                ring.current = (ring.current + 1) % ring.block_count;
                match fed {
                    Ok(packets) => processed += packets,
                    Err(message) => return Err(PollFailure::Panic(message)),
                }
                if processed >= max_packets {
                    break;
                }
            }
            Ok(processed)
        });
        outcome.map_err(|failure| match failure {
            PollFailure::Os(error) => error,
            PollFailure::Panic(message) => engine.panicked("ring poll", &message),
        })
    }

    /// Cumulative packets the kernel dropped because the ring was full.
    fn kernel_drops(&self, py: Python<'_>) -> u64 {
        py.allow_threads(|| {
            let mut guard = self.ring.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut total = self.drops.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ring) = guard.as_mut() {
                *total = ring.kernel_drops();
            }
            *total
        })
    }

    /// Stop polling and release the socket and mapping. Idempotent.
    fn close(&self, py: Python<'_>) {
        self.running.store(false, Ordering::Relaxed);
        py.allow_threads(|| {
            let mut guard = self.ring.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(mut ring) = guard.take() {
                *self.drops.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = ring.kernel_drops();
                ring.close();
            }
        });
    }
}

fn open_ring(
    interface: &str,
    promiscuous: bool,
    block_size: u32,
    block_count: u32,
    block_timeout_ms: u32,
) -> PyResult<Ring> {
    let name = std::ffi::CString::new(interface)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("interface name contains NUL"))?;
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(os_error(&format!("no such interface {interface:?}")));
    }
    // Protocol 0 until bound, so nothing from other interfaces lands in the
    // ring between socket() and bind().
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(os_error("socket(AF_PACKET)"));
    }
    let mut ring = Ring {
        fd,
        map: std::ptr::null_mut(),
        map_len: (block_size as usize) * (block_count as usize),
        block_size: block_size as usize,
        block_count: block_count as usize,
        current: 0,
        drops: 0,
    };
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &TPACKET_V3, "PACKET_VERSION=TPACKET_V3")?;
    let request = TpacketReq3 {
        tp_block_size: block_size,
        tp_block_nr: block_count,
        tp_frame_size: FRAME_SIZE,
        tp_frame_nr: (block_size / FRAME_SIZE) * block_count,
        tp_retire_blk_tov: block_timeout_ms,
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };
    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &request, "PACKET_RX_RING")?;
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ring.map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(os_error("mmap capture ring"));
    }
    ring.map = map.cast();

    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as libc::c_ushort;
    address.sll_protocol = ETH_P_ALL.to_be();
    address.sll_ifindex = ifindex as libc::c_int;
    let rc = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(os_error(&format!("bind to {interface:?}")));
    }
    if promiscuous {
        let mut membership: libc::packet_mreq = unsafe { std::mem::zeroed() };
        membership.mr_ifindex = ifindex as libc::c_int;
        membership.mr_type = PACKET_MR_PROMISC;
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, "promiscuous mode")?;
    }
    Ok(ring)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block holding `frames` laid out like the kernel does, header then frame.
    fn block(size: usize, frames: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0u8; size];
        let first = 48usize;
        out[BLOCK_NUM_PKTS_OFFSET..BLOCK_NUM_PKTS_OFFSET + 4]
            .copy_from_slice(&(frames.len() as u32).to_ne_bytes());
        out[BLOCK_FIRST_PKT_OFFSET..BLOCK_FIRST_PKT_OFFSET + 4]
            .copy_from_slice(&(first as u32).to_ne_bytes());
        let mut offset = first;
        for (i, frame) in frames.iter().enumerate() {
            let mac = 32usize;
            let next = if i + 1 == frames.len() { 0 } else { (mac + frame.len() + 15) & !15 };
            let h = &mut out[offset..];
            h[PKT_NEXT_OFFSET..PKT_NEXT_OFFSET + 4].copy_from_slice(&(next as u32).to_ne_bytes());
            h[PKT_SEC..PKT_SEC + 4].copy_from_slice(&7u32.to_ne_bytes());
            h[PKT_NSEC..PKT_NSEC + 4].copy_from_slice(&((i as u32) * 1000).to_ne_bytes());
            h[PKT_SNAPLEN..PKT_SNAPLEN + 4].copy_from_slice(&(frame.len() as u32).to_ne_bytes());
            h[PKT_MAC..PKT_MAC + 2].copy_from_slice(&(mac as u16).to_ne_bytes());
            h[mac..mac + frame.len()].copy_from_slice(frame);
            offset += next;
        }
        out
    }

    fn collect(block: &[u8]) -> (usize, Vec<(Vec<u8>, i64)>) {
        let mut seen = Vec::new();
        let n = walk_block(block, |frame, ts| seen.push((frame.to_vec(), ts)));
        (n, seen)
    }

    #[test]
    fn a_well_formed_block_yields_every_frame_with_its_timestamp() {
        let (n, seen) = collect(&block(4096, &[b"first", b"second!", b"3"]));
        assert_eq!(n, 3);
        assert_eq!(seen[0], (b"first".to_vec(), 7_000_000));
        assert_eq!(seen[1], (b"second!".to_vec(), 7_000_001));
        assert_eq!(seen[2].0, b"3".to_vec());
    }

    #[test]
    fn an_oversized_snaplen_is_clamped_to_the_block() {
        let mut b = block(256, &[b"abc"]);
        b[48 + PKT_SNAPLEN..48 + PKT_SNAPLEN + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let (n, seen) = collect(&b);
        assert_eq!(n, 1);
        assert_eq!(seen[0].0.len(), 256 - 48 - 32);
    }

    #[test]
    fn offsets_that_leave_the_block_end_the_walk() {
        let mut b = block(256, &[b"abc", b"def"]);
        b[BLOCK_FIRST_PKT_OFFSET..BLOCK_FIRST_PKT_OFFSET + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(collect(&b).0, 0);

        let mut b = block(256, &[b"abc", b"def"]);
        b[48 + PKT_NEXT_OFFSET..48 + PKT_NEXT_OFFSET + 4].copy_from_slice(&10_000u32.to_ne_bytes());
        assert_eq!(collect(&b).0, 1);

        let mut b = block(256, &[b"abc"]);
        b[48 + PKT_MAC..48 + PKT_MAC + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        let (n, seen) = collect(&b);
        assert_eq!((n, seen.len()), (1, 0));
    }

    #[test]
    fn a_packet_count_beyond_the_chain_stops_at_the_last_packet() {
        let mut b = block(512, &[b"abc", b"def"]);
        b[BLOCK_NUM_PKTS_OFFSET..BLOCK_NUM_PKTS_OFFSET + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(collect(&b).0, 2);
        assert_eq!(collect(&[0u8; 8]).0, 0);
    }
}
