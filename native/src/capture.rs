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

use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::sync::Mutex;

use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

use crate::FlowEngine;

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
    fn poll(
        &self,
        py: Python<'_>,
        engine: &FlowEngine,
        timeout_ms: i32,
        max_packets: usize,
    ) -> PyResult<usize> {
        py.allow_threads(|| {
            let mut guard = self.ring.lock().expect("ring mutex poisoned");
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
                        return Err(os_error("poll on capture ring"));
                    }
                    waited = true;
                    continue;
                }
                let packets = unsafe { ring.read_u32(block.add(BLOCK_NUM_PKTS_OFFSET)) } as usize;
                let mut cursor =
                    unsafe { block.add(ring.read_u32(block.add(BLOCK_FIRST_PKT_OFFSET)) as usize) };
                {
                    let mut engine = engine.lock();
                    for _ in 0..packets {
                        unsafe {
                            let sec = i64::from(ring.read_u32(cursor.add(PKT_SEC)));
                            let nsec = i64::from(ring.read_u32(cursor.add(PKT_NSEC)));
                            let snaplen = ring.read_u32(cursor.add(PKT_SNAPLEN)) as usize;
                            let mac = std::ptr::read_volatile(cursor.add(PKT_MAC).cast::<u16>()) as usize;
                            let frame = std::slice::from_raw_parts(cursor.add(mac), snaplen);
                            engine.feed(frame, sec * 1_000_000 + nsec / 1_000);
                            let next = ring.read_u32(cursor.add(PKT_NEXT_OFFSET)) as usize;
                            if next == 0 {
                                break;
                            }
                            cursor = cursor.add(next);
                        }
                    }
                }
                fence(Ordering::Release);
                unsafe {
                    std::ptr::write_volatile(block.add(BLOCK_STATUS_OFFSET).cast::<u32>(), TP_STATUS_KERNEL)
                };
                ring.current = (ring.current + 1) % ring.block_count;
                processed += packets;
                if processed >= max_packets {
                    break;
                }
            }
            Ok(processed)
        })
    }

    /// Cumulative packets the kernel dropped because the ring was full.
    fn kernel_drops(&self, py: Python<'_>) -> u64 {
        py.allow_threads(|| {
            let mut guard = self.ring.lock().expect("ring mutex poisoned");
            let mut total = self.drops.lock().expect("drops mutex poisoned");
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
            let mut guard = self.ring.lock().expect("ring mutex poisoned");
            if let Some(mut ring) = guard.take() {
                *self.drops.lock().expect("drops mutex poisoned") = ring.kernel_drops();
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
