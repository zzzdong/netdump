//! netdump-core: Shared types, error definitions, and protocol parsing helpers.

use std::fmt;
use std::net::IpAddr;

/// Packet metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    /// Capture timestamp seconds.
    pub ts_sec: u64,
    /// Capture timestamp microseconds.
    pub ts_usec: u64,
    /// Interface index.
    pub ifindex: i32,
    /// Captured length (snapped).
    pub cap_len: usize,
    /// Original packet length on wire.
    pub orig_len: usize,
}

impl PacketMeta {
    pub fn new(ts_sec: u64, ts_usec: u64, ifindex: i32, cap_len: usize, orig_len: usize) -> Self {
        Self {
            ts_sec,
            ts_usec,
            ifindex,
            cap_len,
            orig_len,
        }
    }
}

/// A captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub meta: PacketMeta,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(meta: PacketMeta, data: Vec<u8>) -> Self {
        Self { meta, data }
    }
}

/// Shared error type for all netdump crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetdumpError {
    /// I/O error.
    Io(String),
    /// Filter expression parse error.
    Parse(String),
    /// CBPF virtual machine execution error.
    Vm(String),
    /// Unsupported protocol or format.
    Unsupported(String),
}

impl fmt::Display for NetdumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetdumpError::Io(s) => write!(f, "io error: {s}"),
            NetdumpError::Parse(s) => write!(f, "parse error: {s}"),
            NetdumpError::Vm(s) => write!(f, "vm error: {s}"),
            NetdumpError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl std::error::Error for NetdumpError {}

/// Commonly used EtherType values.
pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_RARP: u16 = 0x8035;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// IP protocol number constants.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Parsed packet header fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketInfo {
    /// EtherType (Ethernet frame type).
    pub ethertype: Option<u16>,
    /// IP protocol number.
    pub protocol: Option<u8>,
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// Source port (TCP/UDP only).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP only).
    pub dst_port: Option<u16>,
}

/// Parse raw packet data using etherparse, extracting key header fields.
pub fn parse_packet(packet: &[u8]) -> Option<PacketInfo> {
    let sliced = etherparse::SlicedPacket::from_ethernet(packet).ok()?;
    let mut info = PacketInfo::default();

    if let Some(etherparse::LinkSlice::Ethernet2(eth)) = sliced.link {
        info.ethertype = Some(u16::from(eth.ether_type()));
    }

    match sliced.net? {
        etherparse::NetSlice::Ipv4(ipv4) => {
            let header = ipv4.header();
            info.protocol = Some(header.protocol().0);
            info.src_ip = Some(IpAddr::V4(header.source_addr()));
            info.dst_ip = Some(IpAddr::V4(header.destination_addr()));
        }
        etherparse::NetSlice::Ipv6(ipv6) => {
            let header = ipv6.header();
            info.protocol = Some(header.next_header().0);
            info.src_ip = Some(IpAddr::V6(header.source_addr()));
            info.dst_ip = Some(IpAddr::V6(header.destination_addr()));
        }
        _ => return None,
    }

    if let Some(transport) = sliced.transport {
        match transport {
            etherparse::TransportSlice::Udp(udp) => {
                info.src_port = Some(udp.source_port());
                info.dst_port = Some(udp.destination_port());
            }
            etherparse::TransportSlice::Tcp(tcp) => {
                info.src_port = Some(tcp.source_port());
                info.dst_port = Some(tcp.destination_port());
            }
            _ => {}
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn build_ip_packet(proto: u8, payload_len: usize) -> Vec<u8> {
        let mut pkt = vec![0u8; 14 + 20 + payload_len];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        let ip_start = 14;
        pkt[ip_start] = 0x45; // version=4, ihl=5 -> 20 bytes
        let total_len = (20 + payload_len) as u16;
        pkt[ip_start + 2..ip_start + 4].copy_from_slice(&total_len.to_be_bytes());
        pkt[ip_start + 9] = proto;
        pkt[ip_start + 12] = 192;
        pkt[ip_start + 13] = 168;
        pkt[ip_start + 14] = 1;
        pkt[ip_start + 15] = 1;
        pkt[ip_start + 16] = 10;
        pkt[ip_start + 17] = 0;
        pkt[ip_start + 18] = 0;
        pkt[ip_start + 19] = 2;

        // 计算并写入 IPv4 首部校验和，否则 etherparse 的严格切片会拒绝。
        let checksum = calc_ipv4_checksum(&pkt[ip_start..ip_start + 20]);
        pkt[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());
        pkt
    }

    fn calc_ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn test_parse_ip_tcp_packet() {
        let mut pkt = build_ip_packet(IPPROTO_TCP, 20);
        // 设置 TCP data offset 为 5（20 字节），否则 etherparse 无法切片。
        pkt[14 + 20 + 12] = 0x50;
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.ethertype, Some(ETHERTYPE_IP));
        assert_eq!(info.protocol, Some(IPPROTO_TCP));
        assert_eq!(info.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(info.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn test_parse_udp_ports() {
        let mut pkt = build_ip_packet(IPPROTO_UDP, 8);
        let transport = 14 + 20;
        pkt[transport] = 0x00;
        pkt[transport + 1] = 0x50; // src=80
        pkt[transport + 2] = 0x1f;
        pkt[transport + 3] = 0x90; // dst=8080
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.protocol, Some(IPPROTO_UDP));
        assert_eq!(info.src_port, Some(80));
        assert_eq!(info.dst_port, Some(8080));
    }

    #[test]
    fn test_short_packet_returns_none() {
        let pkt = vec![0u8; 10];
        assert!(parse_packet(&pkt).is_none());
    }
}
