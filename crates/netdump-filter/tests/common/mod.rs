//! 测试用报文构造辅助函数。

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

pub fn calc_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_packet(
    proto: u8,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_packet_with_ihl(proto, src_ip, dst_ip, src_port, dst_port, 5)
}

pub fn build_packet_with_ihl(
    proto: u8,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ihl: u8,
) -> Vec<u8> {
    assert!((5..=15).contains(&ihl), "IHL 必须在 5..=15 之间");
    let ip_header_len = (ihl as usize) * 4;
    let transport_len = if proto == IPPROTO_UDP { 8 } else { 20 };
    let mut pkt = vec![0u8; 14 + ip_header_len + transport_len];

    // Ethernet header.
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 header.
    let ip = 14;
    pkt[ip] = 0x40 | (ihl & 0x0f); // version 4, IHL
    let total_len = (ip_header_len + transport_len) as u16;
    pkt[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
    pkt[ip + 9] = proto;
    pkt[ip + 12..ip + 16].copy_from_slice(&src_ip);
    pkt[ip + 16..ip + 20].copy_from_slice(&dst_ip);
    let checksum = calc_ipv4_checksum(&pkt[ip..ip + ip_header_len]);
    pkt[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());

    // Transport header.
    let tp = ip + ip_header_len;
    pkt[tp..tp + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tp + 2..tp + 4].copy_from_slice(&dst_port.to_be_bytes());
    if proto == IPPROTO_TCP {
        // data offset = 5 (20 bytes)
        pkt[tp + 12] = 0x50;
    }

    pkt
}

pub fn build_ipv6_packet(
    proto: u8,
    src_ip: [u16; 8],
    dst_ip: [u16; 8],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let transport_len = if proto == IPPROTO_UDP || proto == IPPROTO_ICMPV6 {
        8
    } else {
        20
    };
    let mut pkt = vec![0u8; 14 + 40 + transport_len];

    // Ethernet header.
    pkt[12] = 0x86;
    pkt[13] = 0xdd;

    // IPv6 header.
    let ip = 14;
    pkt[ip..ip + 4].copy_from_slice(&0x60000000u32.to_be_bytes());
    pkt[ip + 4..ip + 6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    pkt[ip + 6] = proto;
    pkt[ip + 7] = 64; // hop limit
    for (i, word) in src_ip.iter().enumerate() {
        pkt[ip + 8 + i * 2..ip + 10 + i * 2].copy_from_slice(&word.to_be_bytes());
    }
    for (i, word) in dst_ip.iter().enumerate() {
        pkt[ip + 24 + i * 2..ip + 26 + i * 2].copy_from_slice(&word.to_be_bytes());
    }

    // Transport header.
    let tp = ip + 40;
    if proto != IPPROTO_ICMPV6 {
        pkt[tp..tp + 2].copy_from_slice(&src_port.to_be_bytes());
        pkt[tp + 2..tp + 4].copy_from_slice(&dst_port.to_be_bytes());
    }
    if proto == IPPROTO_TCP {
        pkt[tp + 12] = 0x50;
    }

    pkt
}

pub fn build_arp_packet() -> Vec<u8> {
    // 14 字节以太网 + 28 字节 ARP，ethertype 为 ARP。
    let mut pkt = vec![0u8; 14 + 28];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt
}

pub fn set_macs(pkt: &mut [u8], dst: [u8; 6], src: [u8; 6]) {
    pkt[0..6].copy_from_slice(&dst);
    pkt[6..12].copy_from_slice(&src);
}

pub fn all_packets() -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    let ips = [
        ([192, 168, 1, 1], [192, 168, 1, 2]),
        ([10, 0, 0, 5], [10, 0, 0, 6]),
        ([172, 16, 0, 10], [192, 168, 1, 1]),
        ([8, 8, 8, 8], [1, 1, 1, 1]),
    ];
    let ports = [80u16, 443, 53, 22, 12345, 8080];

    let macs = [
        (
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        ),
        (
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        ),
        (
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02],
        ),
        (
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    ];

    for (i, (src_ip, dst_ip)) in ips.iter().enumerate() {
        let (dst_mac, src_mac) = macs[i];
        for (src_port, dst_port) in ports.iter().zip(ports.iter().cycle().skip(1)) {
            let mut tcp = build_packet(IPPROTO_TCP, *src_ip, *dst_ip, *src_port, *dst_port);
            set_macs(&mut tcp, dst_mac, src_mac);
            pkts.push(tcp);

            let mut udp = build_packet(IPPROTO_UDP, *src_ip, *dst_ip, *src_port, *dst_port);
            set_macs(&mut udp, dst_mac, src_mac);
            pkts.push(udp);
        }
        let mut icmp = build_packet(IPPROTO_ICMP, *src_ip, *dst_ip, 0, 0);
        set_macs(&mut icmp, dst_mac, src_mac);
        pkts.push(icmp);
    }

    // 非 IPv4 报文：ARP 使用第一组 MAC。
    let mut arp = build_arp_packet();
    set_macs(&mut arp, macs[0].0, macs[0].1);
    pkts.push(arp);

    // 带 IP 选项的报文（IHL = 6/7），验证编译器使用 ldx_msh_b 计算 IP 头部长度。
    pkts.push(build_packet_with_ihl(
        IPPROTO_TCP,
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        80,
        443,
        6,
    ));
    pkts.push(build_packet_with_ihl(
        IPPROTO_UDP,
        [10, 0, 0, 5],
        [10, 0, 0, 6],
        53,
        12345,
        7,
    ));

    // IPv6 报文。
    let v6_ips = [
        ([0xfe80, 0, 0, 0, 0, 0, 0, 1], [0xfe80, 0, 0, 0, 0, 0, 0, 2]),
        (
            [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
            [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        ),
        ([0xfd00, 0, 0, 0, 0, 0, 0, 1], [0xfd00, 0, 0, 0, 0, 0, 0, 2]),
    ];
    for (i, (src_ip, dst_ip)) in v6_ips.iter().enumerate() {
        let (dst_mac, src_mac) = macs[i];
        for (src_port, dst_port) in ports.iter().zip(ports.iter().cycle().skip(1)) {
            let mut tcp = build_ipv6_packet(IPPROTO_TCP, *src_ip, *dst_ip, *src_port, *dst_port);
            set_macs(&mut tcp, dst_mac, src_mac);
            pkts.push(tcp);

            let mut udp = build_ipv6_packet(IPPROTO_UDP, *src_ip, *dst_ip, *src_port, *dst_port);
            set_macs(&mut udp, dst_mac, src_mac);
            pkts.push(udp);
        }
        let mut icmp = build_ipv6_packet(IPPROTO_ICMPV6, *src_ip, *dst_ip, 0, 0);
        set_macs(&mut icmp, dst_mac, src_mac);
        pkts.push(icmp);
    }

    pkts
}
