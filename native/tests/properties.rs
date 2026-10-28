//! Property tests for the parser and the engine (ADDENDUM_4.md D6).
//!
//! The claim under test is "no input can panic the hot path": arbitrary
//! bytes, frames that are almost valid (a real header with random fields,
//! truncated anywhere), and arbitrary frame/timestamp sequences through the
//! engine and every query it serves. `cargo test` runs the default 256 cases
//! per property; set `PROPTEST_CASES` for a longer run. The coverage-guided
//! counterpart is `native/fuzz/` (cargo-fuzz).

use pirewall_native::flow::Engine;
use pirewall_native::parse::{self, ParseError};
use proptest::prelude::*;

/// Ethernet + IPv4 + an L4 header, with every field the parser reads drawn
/// at random, then truncated to `keep` bytes.
fn almost_valid_frame() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![Just(0x0800u16), Just(0x86DDu16), any::<u16>()],
        any::<u8>(),
        any::<u16>(),
        prop_oneof![Just(6u8), Just(17u8), Just(1u8), Just(58u8), any::<u8>()],
        any::<[u8; 8]>(),
        any::<[u8; 20]>(),
        proptest::collection::vec(any::<u8>(), 0..64),
        any::<usize>(),
    )
        .prop_map(|(ethertype, version_ihl, total_length, protocol, addresses, l4, payload, keep)| {
            let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(&[version_ihl, 0]);
            frame.extend_from_slice(&total_length.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
            frame.extend_from_slice(&addresses);
            frame.extend_from_slice(&l4);
            frame.extend_from_slice(&payload);
            let keep = keep % (frame.len() + 1);
            frame.truncate(keep);
            frame
        })
}

/// A parseable IPv4/TCP frame between a few hosts and ports, so the engine
/// actually opens, updates, evicts and closes flows.
fn plausible_tcp_frame() -> impl Strategy<Value = Vec<u8>> {
    (0u8..4, 0u8..4, 0u16..4, 0u16..4, any::<u8>(), 0usize..32).prop_map(
        |(a, b, sport, dport, flags, len)| {
            let total = 40 + len;
            let mut f = vec![0x02, 0, 0, 0, 0, b, 0x02, 0, 0, 0, 0, a, 0x08, 0x00];
            f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 6, 0, 0]);
            f.extend_from_slice(&[10, 0, 0, a + 1, 10, 0, 0, b + 1]);
            f.extend_from_slice(&(1000 + sport).to_be_bytes());
            f.extend_from_slice(&(443 - dport).to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags, 4, 0, 0, 0, 0, 0]);
            f.extend(std::iter::repeat_n(22u8, len));
            f
        },
    )
}

fn any_frame() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![proptest::collection::vec(any::<u8>(), 0..256), almost_valid_frame(), plausible_tcp_frame(),]
}

/// Realistic capture clocks plus the extremes.
fn timestamp() -> impl Strategy<Value = i64> {
    prop_oneof![0i64..10_000_000_000, any::<i64>()]
}

proptest! {
    #[test]
    fn parse_never_panics_and_its_offsets_stay_in_the_frame(frame in any_frame(), ts in any::<i64>()) {
        match parse::parse(&frame, ts) {
            Ok(packet) => {
                if let Some(offset) = packet.tcp_payload_offset {
                    prop_assert!(offset <= frame.len());
                }
                if let Some(payload) = parse::tcp_payload(&frame, &packet) {
                    prop_assert!(payload.len() <= frame.len());
                }
                prop_assert!(u64::from(packet.payload_length) <= u64::from(packet.total_length));
            }
            Err(ParseError::Malformed | ParseError::Unsupported) => {}
        }
    }

    #[test]
    fn the_engine_never_panics_on_any_frame_sequence(
        frames in proptest::collection::vec((any_frame(), timestamp()), 0..64),
        max_flows in 1usize..8,
        query_at in timestamp(),
    ) {
        let mut engine = Engine::new(120.0, 60.0, max_flows, Some((0x0A00_0000, 24)), 443);
        engine.set_pending_limits(16, 16);
        for (frame, ts) in &frames {
            engine.feed(frame, *ts);
            prop_assert!(engine.len() <= max_flows);
        }
        let _ = engine.slow_clusters(query_at, 1.0, 1000.0, 2);
        let _ = engine.snapshot_from(0x0A00_0001);
        let _ = engine.sweep(query_at);
        let _ = engine.flush();
        prop_assert_eq!(engine.len(), 0);
        prop_assert!(engine.completed.len() <= 16);
        prop_assert_eq!(engine.packets_seen, frames.len() as u64);
    }
}
