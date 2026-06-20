//! netdump-cbpf: CBPF virtual machine used to verify and execute compiled filter programs.

pub mod vm;

pub use vm::Vm;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use netdump_core::{ETHERTYPE_IP, IPPROTO_TCP, IPPROTO_UDP};
    use netdump_filter::{
        Direction, FilterAst, HostAddr, Instruction, Protocol, compile, parse, types::*,
    };

    use crate::Vm;

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

    fn build_ip_packet(proto: u8, payload_len: usize, src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 14 + 20 + payload_len];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        let ip = 14;
        pkt[ip] = 0x45; // version 4, ihl 5
        let total_len = (20 + payload_len) as u16;
        pkt[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        pkt[ip + 9] = proto;
        pkt[ip + 12..ip + 16].copy_from_slice(&src_ip);
        pkt[ip + 16..ip + 20].copy_from_slice(&dst_ip);
        let checksum = calc_ipv4_checksum(&pkt[ip..ip + 20]);
        pkt[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
        pkt
    }

    fn set_tcp_header(pkt: &mut [u8]) {
        // 设置 TCP data offset = 5（20 字节）。
        pkt[14 + 20 + 12] = 0x50;
    }

    fn set_udp_ports(pkt: &mut [u8], src: u16, dst: u16) {
        let off = 14 + 20;
        pkt[off..off + 2].copy_from_slice(&src.to_be_bytes());
        pkt[off + 2..off + 4].copy_from_slice(&dst.to_be_bytes());
    }

    #[test]
    fn vm_load_ethertype_and_ret() {
        // 手工构造一个 CBPF 程序：检查 ethertype 是否为 IPv4。
        // jt/jf 是相对下一条指令的偏移量。
        let mut check = jeq(ETHERTYPE_IP as u32);
        check.jt = 1; // 跳转到 accept（指令 3）
        check.jf = 0; // 跳转到 reject（指令 2）
        let program = vec![ld_abs_h(12), check, ret_k(CBPF_REJECT), ret_k(CBPF_ACCEPT)];

        let ip_pkt = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(Vm::exec(&program, &ip_pkt));

        let mut non_ip = ip_pkt.clone();
        non_ip[12] = 0x08;
        non_ip[13] = 0x06; // ARP
        assert!(!Vm::exec(&program, &non_ip));
    }

    #[test]
    fn vm_unconditional_jump() {
        // 0: ld abs b 12
        // 1: ja #2      -> 跳过两条指令到达 accept
        // 2: ret reject
        // 3: ret reject
        // 4: ret accept
        let ja = Instruction::new(BPF_JMP | BPF_JA | BPF_K, 0, 0, 2);
        let program = vec![
            ld_abs_b(12),
            ja,
            ret_k(CBPF_REJECT),
            ret_k(CBPF_REJECT),
            ret_k(CBPF_ACCEPT),
        ];

        let pkt = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(Vm::exec(&program, &pkt));
    }

    #[test]
    fn vm_store_and_transfer() {
        // 验证 ST / STX / MEM / TAX / TXA 指令。
        let program = vec![
            Instruction::new(BPF_LD | BPF_IMM | BPF_W, 0, 0, 42),
            Instruction::new(BPF_ST, 0, 0, 0),
            Instruction::new(BPF_LD | BPF_IMM | BPF_W, 0, 0, 0),
            Instruction::new(BPF_MISC | BPF_TAX, 0, 0, 0),
            Instruction::new(BPF_LDX | BPF_MEM | BPF_W, 0, 0, 0),
            Instruction::new(BPF_MISC | BPF_TXA, 0, 0, 0),
            ret_k(42),
        ];
        assert!(Vm::exec(&program, &[]));
    }

    #[test]
    fn compile_proto_tcp_matches_tcp_only() {
        let ast = FilterAst::Proto(Protocol::Tcp);
        let prog = compile(&ast);

        let mut tcp = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [10, 0, 0, 2]);
        set_tcp_header(&mut tcp);
        assert!(Vm::exec(&prog, &tcp));

        let udp = build_ip_packet(IPPROTO_UDP, 8, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(!Vm::exec(&prog, &udp));
    }

    #[test]
    fn compile_host_any_matches_src_or_dst() {
        let ast = FilterAst::Host {
            addr: HostAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dir: Direction::Any,
        };
        let prog = compile(&ast);

        let src_match = build_ip_packet(IPPROTO_TCP, 20, [192, 168, 1, 100], [10, 0, 0, 2]);
        assert!(Vm::exec(&prog, &src_match));

        let dst_match = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [192, 168, 1, 100]);
        assert!(Vm::exec(&prog, &dst_match));

        let no_match = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(!Vm::exec(&prog, &no_match));
    }

    #[test]
    fn compile_port_src_matches_udp_source_port() {
        let ast = FilterAst::Port {
            port: 53,
            dir: Direction::Src,
        };
        let prog = compile(&ast);

        let mut pkt = build_ip_packet(IPPROTO_UDP, 8, [10, 0, 0, 1], [10, 0, 0, 2]);
        set_udp_ports(&mut pkt, 53, 12345);
        assert!(Vm::exec(&prog, &pkt));

        let mut pkt2 = build_ip_packet(IPPROTO_UDP, 8, [10, 0, 0, 1], [10, 0, 0, 2]);
        set_udp_ports(&mut pkt2, 54, 12345);
        assert!(!Vm::exec(&prog, &pkt2));
    }

    #[test]
    fn compile_parsed_and_or_filter() {
        let ast = parse("tcp and host 192.168.1.1 or udp").unwrap();
        let prog = compile(&ast);

        // TCP 且目标为 192.168.1.1 -> 匹配
        let mut tcp_match = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [192, 168, 1, 1]);
        set_tcp_header(&mut tcp_match);
        assert!(Vm::exec(&prog, &tcp_match));

        // UDP -> 匹配（or 右侧）
        let udp = build_ip_packet(IPPROTO_UDP, 8, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(Vm::exec(&prog, &udp));

        // TCP 但目标不是 192.168.1.1 -> 不匹配
        let mut tcp_no = build_ip_packet(IPPROTO_TCP, 20, [10, 0, 0, 1], [10, 0, 0, 2]);
        set_tcp_header(&mut tcp_no);
        assert!(!Vm::exec(&prog, &tcp_no));
    }
}
