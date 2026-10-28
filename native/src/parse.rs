//! Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP header parsing.
//!
//! A line-for-line port of `pirewall/capture/parser.py`: every bounds check
//! there exists here, in the same order, and classifies the same frames as
//! malformed or unsupported. `tests/unit/test_native_parity.py` holds the two
//! implementations to that. Headers only — the one exception is the TCP
//! payload *offset*, which the TLS structural detectors need (ADDENDUM_2.md
//! B4/B5), mirroring `parser.extract_tcp_payload`.

pub const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMPV6: u8 = 58;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_MIN_HEADER_LEN: usize = 4;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// `pirewall.core.enums.Protocol`, by value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other,
}

impl Proto {
    /// The `Protocol` enum's string value on the Python side.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmpv6",
            Proto::Other => "other",
        }
    }
}

/// Parsed L3/L4 header fields of one frame (`PacketMetadata`'s shape).
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    /// Capture time, whole microseconds since the Unix epoch — the same
    /// resolution as the Python path's `datetime`, so inter-arrival
    /// arithmetic is bit-identical between the two.
    pub ts_us: i64,
    /// Ethernet source and destination, as 48-bit integers with the octets
    /// big-endian (`aa:bb:..` = 0xaabb..), like `src`/`dst` below. Carried
    /// for device identity (ADDENDUM_4.md D3); never a model feature.
    pub src_mac: u64,
    pub dst_mac: u64,
    /// IPv6 frames are parsed (and validated) but never aggregated (A5).
    pub ipv4: bool,
    pub src: u32,
    pub dst: u32,
    pub proto: Proto,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// The raw TCP flags byte; `None` for anything that is not TCP.
    pub tcp_flags: Option<u8>,
    pub total_length: u32,
    pub payload_length: u32,
    /// Start of the TCP payload within the frame (TCP over IPv4 only).
    pub tcp_payload_offset: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// A valid frame of a protocol pirewall does not analyse (ARP, VLAN, ...).
    Unsupported,
    /// Truncated or internally inconsistent headers.
    Malformed,
}

struct L4 {
    proto: Proto,
    sport: Option<u16>,
    dport: Option<u16>,
    tcp_flags: Option<u8>,
    header_length: usize,
}

#[inline]
fn be16(raw: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([raw[at], raw[at + 1]])
}

#[inline]
fn be32(raw: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]])
}

/// Six bytes at `at` as a 48-bit integer, octets big-endian.
#[inline]
fn be48(raw: &[u8], at: usize) -> u64 {
    raw[at..at + 6].iter().fold(0u64, |acc, &octet| (acc << 8) | u64::from(octet))
}

pub fn parse(raw: &[u8], ts_us: i64) -> Result<Packet, ParseError> {
    if raw.len() < ETH_HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    match be16(raw, 12) {
        ETHERTYPE_IPV4 => parse_ipv4(raw, ETH_HEADER_LEN, ts_us),
        ETHERTYPE_IPV6 => parse_ipv6(raw, ETH_HEADER_LEN, ts_us),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_ipv4(raw: &[u8], offset: usize, ts_us: i64) -> Result<Packet, ParseError> {
    if raw.len() < offset + IPV4_MIN_HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    if raw[offset] >> 4 != 4 {
        return Err(ParseError::Malformed);
    }
    let ihl = ((raw[offset] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || raw.len() < offset + ihl {
        return Err(ParseError::Malformed);
    }
    let total_length = be16(raw, offset + 2) as usize;
    if total_length < ihl || raw.len() < offset + total_length {
        return Err(ParseError::Malformed);
    }
    let ip_protocol = raw[offset + 9];
    let src = be32(raw, offset + 12);
    let dst = be32(raw, offset + 16);
    let l4_offset = offset + ihl;
    let l4_available = total_length - ihl;
    let l4 = parse_l4(raw, l4_offset, ip_protocol, l4_available)?;
    if l4_available < l4.header_length {
        return Err(ParseError::Malformed);
    }
    let tcp_payload_offset = (l4.proto == Proto::Tcp).then_some(l4_offset + l4.header_length);
    Ok(Packet {
        ts_us,
        src_mac: be48(raw, 6),
        dst_mac: be48(raw, 0),
        ipv4: true,
        src,
        dst,
        proto: l4.proto,
        sport: l4.sport,
        dport: l4.dport,
        tcp_flags: l4.tcp_flags,
        total_length: total_length as u32,
        payload_length: (l4_available - l4.header_length) as u32,
        tcp_payload_offset,
    })
}

fn parse_ipv6(raw: &[u8], offset: usize, ts_us: i64) -> Result<Packet, ParseError> {
    if raw.len() < offset + IPV6_HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    if raw[offset] >> 4 != 6 {
        return Err(ParseError::Malformed);
    }
    let declared_payload_length = be16(raw, offset + 4) as usize;
    let next_header = raw[offset + 6];
    let l4_offset = offset + IPV6_HEADER_LEN;
    let available = raw.len() - l4_offset;
    let l4_available = declared_payload_length.min(available);
    let l4 = parse_l4(raw, l4_offset, next_header, l4_available)?;
    if l4_available < l4.header_length {
        return Err(ParseError::Malformed);
    }
    Ok(Packet {
        ts_us,
        src_mac: be48(raw, 6),
        dst_mac: be48(raw, 0),
        ipv4: false,
        src: 0,
        dst: 0,
        proto: l4.proto,
        sport: l4.sport,
        dport: l4.dport,
        tcp_flags: l4.tcp_flags,
        total_length: (IPV6_HEADER_LEN + declared_payload_length) as u32,
        payload_length: (l4_available - l4.header_length) as u32,
        tcp_payload_offset: None,
    })
}

fn parse_l4(raw: &[u8], offset: usize, ip_protocol: u8, available: usize) -> Result<L4, ParseError> {
    match ip_protocol {
        IP_PROTO_TCP => {
            if available < TCP_MIN_HEADER_LEN || raw.len() < offset + TCP_MIN_HEADER_LEN {
                return Err(ParseError::Malformed);
            }
            let data_offset = ((raw[offset + 12] >> 4) as usize) * 4;
            if data_offset < TCP_MIN_HEADER_LEN {
                return Err(ParseError::Malformed);
            }
            if available < data_offset || raw.len() < offset + data_offset {
                return Err(ParseError::Malformed);
            }
            Ok(L4 {
                proto: Proto::Tcp,
                sport: Some(be16(raw, offset)),
                dport: Some(be16(raw, offset + 2)),
                tcp_flags: Some(raw[offset + 13]),
                header_length: data_offset,
            })
        }
        IP_PROTO_UDP => {
            if available < UDP_HEADER_LEN || raw.len() < offset + UDP_HEADER_LEN {
                return Err(ParseError::Malformed);
            }
            Ok(L4 {
                proto: Proto::Udp,
                sport: Some(be16(raw, offset)),
                dport: Some(be16(raw, offset + 2)),
                tcp_flags: None,
                header_length: UDP_HEADER_LEN,
            })
        }
        IP_PROTO_ICMP | IP_PROTO_ICMPV6 => {
            if available < ICMP_MIN_HEADER_LEN || raw.len() < offset + ICMP_MIN_HEADER_LEN {
                return Err(ParseError::Malformed);
            }
            let proto = if ip_protocol == IP_PROTO_ICMP { Proto::Icmp } else { Proto::Icmpv6 };
            Ok(L4 { proto, sport: None, dport: None, tcp_flags: None, header_length: ICMP_MIN_HEADER_LEN })
        }
        _ => Ok(L4 { proto: Proto::Other, sport: None, dport: None, tcp_flags: None, header_length: 0 }),
    }
}

/// The TCP payload of an already-parsed IPv4/TCP frame, bounded exactly like
/// `parser.extract_tcp_payload` (by the IP header's total length).
pub fn tcp_payload<'a>(raw: &'a [u8], packet: &Packet) -> Option<&'a [u8]> {
    let start = packet.tcp_payload_offset?;
    let end = (ETH_HEADER_LEN + packet.total_length as usize).min(raw.len());
    (start <= end).then(|| &raw[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut f = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x20];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 5, 10, 0, 0, 10]);
        f.extend_from_slice(&[0xC8, 0x00, 0x01, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags, 4, 0, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn parses_a_tcp_segment_and_its_payload() {
        let frame = tcp_frame(TCP_SYN | TCP_ACK, b"hello");
        let p = parse(&frame, 7).unwrap();
        assert!(p.ipv4);
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!((p.sport, p.dport), (Some(51200), Some(443)));
        assert_eq!(p.total_length, 45);
        assert_eq!(p.payload_length, 5);
        assert_eq!(tcp_payload(&frame, &p), Some(&b"hello"[..]));
    }

    #[test]
    fn ethernet_addresses_are_read_as_big_endian_48_bit_integers() {
        let p = parse(&tcp_frame(TCP_SYN, b""), 0).unwrap();
        assert_eq!(p.dst_mac, 0xAABB_CCDD_EEFF);
        assert_eq!(p.src_mac, 0x0200_0000_0020);
    }

    #[test]
    fn truncation_and_unknown_ethertypes_are_classified_like_the_python_parser() {
        assert_eq!(parse(&[0u8; 10], 0).unwrap_err(), ParseError::Malformed);
        let mut arp = vec![0u8; 42];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert_eq!(parse(&arp, 0).unwrap_err(), ParseError::Unsupported);
        let mut frame = tcp_frame(TCP_SYN, b"");
        frame.truncate(frame.len() - 1);
        assert_eq!(parse(&frame, 0).unwrap_err(), ParseError::Malformed);
    }
}
