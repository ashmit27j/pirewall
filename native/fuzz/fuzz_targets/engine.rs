//! The whole per-packet path, `Engine::feed`, on arbitrary frame and
//! timestamp sequences, followed by every query the engine serves. Nothing
//! here may panic (ADDENDUM_4.md D6).
//!
//! Input layout, repeated: one length byte `n`, an 8-byte little-endian
//! timestamp, then `n` frame bytes (fewer if the input runs out).
#![no_main]

use libfuzzer_sys::fuzz_target;
use pirewall_native::flow::Engine;

fuzz_target!(|data: &[u8]| {
    let mut engine = Engine::new(120.0, 60.0, 8, Some((0x0A00_0000, 24)), 443);
    engine.set_pending_limits(32, 32);
    let mut rest = data;
    let mut last_ts = 0i64;
    while rest.len() >= 9 {
        let length = usize::from(rest[0]);
        last_ts = i64::from_le_bytes(rest[1..9].try_into().expect("8 bytes"));
        let end = (9 + length).min(rest.len());
        engine.feed(&rest[9..end], last_ts);
        assert!(engine.len() <= 8);
        rest = &rest[end..];
    }
    let _ = engine.slow_clusters(last_ts, 1.0, 1000.0, 2);
    let _ = engine.snapshot_from(0x0A00_0001);
    let _ = engine.sweep(last_ts);
    let _ = engine.flush();
    assert!(engine.is_empty());
});
