//! `parse::parse` on arbitrary bytes (ADDENDUM_4.md D6): it must never
//! panic, and any payload offset it reports must stay inside the frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pirewall_native::parse;

fuzz_target!(|frame: &[u8]| {
    if let Ok(packet) = parse::parse(frame, 0) {
        if let Some(offset) = packet.tcp_payload_offset {
            assert!(offset <= frame.len());
        }
        if let Some(payload) = parse::tcp_payload(frame, &packet) {
            assert!(payload.len() <= frame.len());
        }
    }
});
