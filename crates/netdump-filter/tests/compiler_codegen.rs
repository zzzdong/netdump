//! 编译器与汇编器专项测试，重点关注多重判断与跳转。

mod common;

use common::{
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, all_packets, build_arp_packet,
    build_ipv6_packet, build_packet, build_packet_with_ihl, set_macs,
};
use netdump_cbpf::Vm;
use netdump_filter::{assembler::Assembler, compile, parse, types::*};

#[test]
fn assembler_resolves_multiple_forward_jumps() {
    // 手动构造：
    // 0: ldabs h [12]
    // 1: jeq 0x0800, L1, L2
    // 2: ret reject      (L2)
    // 3: ret accept      (L1)
    let mut asm = Assembler::new();
    let l1 = asm.new_label();
    let l2 = asm.new_label();

    asm.emit(ld_abs_h(12));
    asm.emit_jump(jeq(0x0800), l1, l2);
    asm.place_label(l2, asm.next_index());
    asm.emit(ret_k(CBPF_REJECT));
    asm.place_label(l1, asm.next_index());
    asm.emit(ret_k(CBPF_ACCEPT));

    let prog = asm.resolve();
    assert_eq!(prog.len(), 4);
    assert_eq!(prog[1].jt, 1); // L1 在 idx 3 -> 3 - 1 - 1 = 1
    assert_eq!(prog[1].jf, 0); // L2 在 idx 2 -> 2 - 1 - 1 = 0
}

#[test]
fn assembler_resolves_out_of_order_labels() {
    // 0: ldh [12]
    // 1: jeq 0x0800, L2, L1
    // 2: ret reject      (L1)
    // 3: ret accept      (L2)
    let mut asm = Assembler::new();
    let l1 = asm.new_label();
    let l2 = asm.new_label();

    asm.emit(ld_abs_h(12));
    asm.emit_jump(jeq(0x0800), l2, l1);
    asm.place_label(l1, asm.next_index());
    asm.emit(ret_k(CBPF_REJECT));
    asm.place_label(l2, asm.next_index());
    asm.emit(ret_k(CBPF_ACCEPT));

    let prog = asm.resolve();
    assert_eq!(prog[1].jt, 1); // l2 在 idx 3 -> 3 - 1 - 1 = 1
    assert_eq!(prog[1].jf, 0); // l1 在 idx 2 -> 2 - 1 - 1 = 0
}

#[test]
fn compile_program_contains_both_accept_and_reject() {
    let ast = parse("tcp").unwrap();
    let prog = compile(&ast);

    let accepts: Vec<_> = prog
        .iter()
        .filter(|i| i.code == (BPF_RET | BPF_K) && i.k == CBPF_ACCEPT)
        .collect();
    let rejects: Vec<_> = prog
        .iter()
        .filter(|i| i.code == (BPF_RET | BPF_K) && i.k == CBPF_REJECT)
        .collect();
    assert_eq!(accepts.len(), 1);
    assert_eq!(rejects.len(), 1);
}

#[test]
fn compile_chained_and_requires_all_conditions() {
    let ast = parse("tcp and host 192.168.1.1 and port 80").unwrap();
    let prog = compile(&ast);

    let tcp_match = build_packet(IPPROTO_TCP, [192, 168, 1, 1], [10, 0, 0, 2], 80, 443);
    let mut tcp_match = tcp_match;
    tcp_match[14 + 20 + 12] = 0x50;
    assert!(Vm::exec(&prog, &tcp_match));

    // 端口不对
    let mut wrong_port = build_packet(IPPROTO_TCP, [192, 168, 1, 1], [10, 0, 0, 2], 81, 443);
    wrong_port[14 + 20 + 12] = 0x50;
    assert!(!Vm::exec(&prog, &wrong_port));

    // IP 不对
    let mut wrong_ip = build_packet(IPPROTO_TCP, [192, 168, 1, 2], [10, 0, 0, 2], 80, 443);
    wrong_ip[14 + 20 + 12] = 0x50;
    assert!(!Vm::exec(&prog, &wrong_ip));

    // 协议不对
    let wrong_proto = build_packet(IPPROTO_UDP, [192, 168, 1, 1], [10, 0, 0, 2], 80, 443);
    assert!(!Vm::exec(&prog, &wrong_proto));
}

#[test]
fn compile_chained_or_matches_any_condition() {
    let ast = parse("tcp or udp or icmp").unwrap();
    let prog = compile(&ast);

    let mut tcp = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    tcp[14 + 20 + 12] = 0x50;
    assert!(Vm::exec(&prog, &tcp));

    let udp = build_packet(IPPROTO_UDP, [10, 0, 0, 1], [10, 0, 0, 2], 53, 443);
    assert!(Vm::exec(&prog, &udp));

    let icmp = build_packet(IPPROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
    assert!(Vm::exec(&prog, &icmp));

    let arp = build_arp_packet();
    assert!(!Vm::exec(&prog, &arp));
}

#[test]
fn compile_not_with_multiple_subexpressions() {
    let ast = parse("not (tcp or udp)").unwrap();
    let prog = compile(&ast);

    let mut tcp = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    tcp[14 + 20 + 12] = 0x50;
    assert!(!Vm::exec(&prog, &tcp));

    let udp = build_packet(IPPROTO_UDP, [10, 0, 0, 1], [10, 0, 0, 2], 53, 443);
    assert!(!Vm::exec(&prog, &udp));

    let icmp = build_packet(IPPROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
    assert!(Vm::exec(&prog, &icmp));

    let arp = build_arp_packet();
    assert!(Vm::exec(&prog, &arp));
}

#[test]
fn compile_mixed_nesting_evaluates_correctly() {
    let ast = parse("(tcp and src host 10.0.0.5) or (udp and dst host 1.1.1.1) or icmp").unwrap();
    let prog = compile(&ast);

    let mut tcp_match = build_packet(IPPROTO_TCP, [10, 0, 0, 5], [192, 168, 1, 2], 80, 443);
    tcp_match[14 + 20 + 12] = 0x50;
    assert!(Vm::exec(&prog, &tcp_match));

    let udp_match = build_packet(IPPROTO_UDP, [192, 168, 1, 1], [1, 1, 1, 1], 53, 12345);
    assert!(Vm::exec(&prog, &udp_match));

    let icmp_match = build_packet(IPPROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
    assert!(Vm::exec(&prog, &icmp_match));

    let mut tcp_no = build_packet(IPPROTO_TCP, [10, 0, 0, 6], [192, 168, 1, 2], 80, 443);
    tcp_no[14 + 20 + 12] = 0x50;
    assert!(!Vm::exec(&prog, &tcp_no));
}

#[test]
fn compile_ip_options_with_multiple_conditions() {
    // IHL = 6，且同时包含 src/dst 条件，验证 ldx_msh_b 与多个跳转配合。
    let ast = parse("tcp and src host 192.168.1.1 and dst port 443").unwrap();
    let prog = compile(&ast);

    let mut pkt =
        build_packet_with_ihl(IPPROTO_TCP, [192, 168, 1, 1], [10, 0, 0, 2], 12345, 443, 6);
    pkt[14 + 24 + 12] = 0x50;
    assert!(Vm::exec(&prog, &pkt));
}

#[test]
fn compile_ether_host_with_direction_any_uses_both_offsets() {
    let ast = parse("ether host aa:bb:cc:dd:ee:ff").unwrap();
    let prog = compile(&ast);

    let mut pkt = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    set_macs(
        &mut pkt,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    );
    assert!(Vm::exec(&prog, &pkt));

    // src MAC 匹配也应通过
    let mut pkt2 = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    set_macs(
        &mut pkt2,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    assert!(Vm::exec(&prog, &pkt2));

    // 都不匹配
    let mut pkt3 = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    set_macs(
        &mut pkt3,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
    );
    assert!(!Vm::exec(&prog, &pkt3));
}

#[test]
fn compile_portrange_generates_two_jumps() {
    let ast = parse("src portrange 1000-2000").unwrap();
    let prog = compile(&ast);

    let ok = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 1500, 443);
    assert!(Vm::exec(&prog, &ok));

    let too_low = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 500, 443);
    assert!(!Vm::exec(&prog, &too_low));

    let too_high = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 3000, 443);
    assert!(!Vm::exec(&prog, &too_high));
}

#[test]
fn compile_net_mask_and_direction() {
    let ast = parse("src net 192.168.0.0/16").unwrap();
    let prog = compile(&ast);

    let ok = build_packet(IPPROTO_TCP, [192, 168, 1, 1], [10, 0, 0, 2], 80, 443);
    assert!(Vm::exec(&prog, &ok));

    let no = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    assert!(!Vm::exec(&prog, &no));
}

#[test]
fn compile_len_relops() {
    let ast = parse("len > 50").unwrap();
    let prog = compile(&ast);

    let short = build_packet(IPPROTO_UDP, [10, 0, 0, 1], [10, 0, 0, 2], 53, 443);
    assert!(!Vm::exec(&prog, &short));

    let mut long = build_packet(IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 0, 2], 80, 443);
    long.resize(long.len() + 100, 0);
    assert!(Vm::exec(&prog, &long));
}

#[test]
fn compile_all_supported_predicates_run_without_crash() {
    // 确保所有支持的表达式都能成功编译，覆盖 parser 与 compiler 的完整路径。
    let expressions = [
        "ip",
        "ip6",
        "tcp",
        "udp",
        "icmp",
        "icmp6",
        "arp",
        "rarp",
        "host 192.168.1.1",
        "host fe80::1",
        "src host 10.0.0.1",
        "dst host 1.1.1.1",
        "dst host 2001:db8::2",
        "port 80",
        "src port 443",
        "dst port 53",
        "portrange 1000-2000",
        "src portrange 80-443",
        "dst portrange 1024-65535",
        "ether host aa:bb:cc:dd:ee:ff",
        "ether src 11:22:33:44:55:66",
        "ether dst ff:ff:ff:ff:ff:ff",
        "net 192.168.1.0/24",
        "src net 10.0.0.0/8",
        "dst net 172.16.0.0 mask 255.255.0.0",
        "net fe80::/10",
        "net 2001:db8::/32",
        "len > 100",
        "greater 64",
        "less 100",
        "tcp and host 192.168.1.1",
        "tcp or udp or icmp",
        "not arp",
        "(tcp and src port 80) or (udp and dst port 53)",
        "ip6 and tcp and host fe80::1",
    ];

    for expr in expressions {
        let ast = parse(expr).unwrap_or_else(|e| panic!("解析失败 `{expr}`: {e}"));
        let prog = compile(&ast);
        assert!(!prog.is_empty(), "`{expr}` 编译结果为空");

        // 所有程序在任意报文上执行都不应 panic。
        for pkt in all_packets() {
            let _ = Vm::exec(&prog, &pkt);
        }
    }
}

#[test]
fn compile_ipv6_host_matches_v6_only() {
    let ast = parse("host fe80::1").unwrap();
    let prog = compile(&ast);

    let v6_match = build_ipv6_packet(
        IPPROTO_TCP,
        [0xfe80, 0, 0, 0, 0, 0, 0, 1],
        [0xfe80, 0, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    assert!(Vm::exec(&prog, &v6_match));

    let v6_no = build_ipv6_packet(
        IPPROTO_TCP,
        [0xfe80, 0, 0, 0, 0, 0, 0, 3],
        [0xfe80, 0, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    assert!(!Vm::exec(&prog, &v6_no));

    let v4 = build_packet(IPPROTO_TCP, [192, 168, 1, 1], [192, 168, 1, 2], 80, 443);
    assert!(!Vm::exec(&prog, &v4));
}

#[test]
fn compile_tcp_matches_ipv4_and_ipv6() {
    let ast = parse("tcp").unwrap();
    let prog = compile(&ast);

    let mut v4 = build_packet(IPPROTO_TCP, [192, 168, 1, 1], [192, 168, 1, 2], 80, 443);
    v4[14 + 20 + 12] = 0x50;
    assert!(Vm::exec(&prog, &v4));

    let mut v6 = build_ipv6_packet(
        IPPROTO_TCP,
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    v6[14 + 40 + 12] = 0x50;
    assert!(Vm::exec(&prog, &v6));

    let udp_v6 = build_ipv6_packet(
        IPPROTO_UDP,
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        53,
        443,
    );
    assert!(!Vm::exec(&prog, &udp_v6));
}

#[test]
fn compile_ipv6_port_matches_fixed_header() {
    let ast = parse("ip6 and dst port 443").unwrap();
    let prog = compile(&ast);

    let mut v6 = build_ipv6_packet(
        IPPROTO_TCP,
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    v6[14 + 40 + 12] = 0x50;
    assert!(Vm::exec(&prog, &v6));

    let mut v6_no = build_ipv6_packet(
        IPPROTO_TCP,
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        80,
        80,
    );
    v6_no[14 + 40 + 12] = 0x50;
    assert!(!Vm::exec(&prog, &v6_no));
}

#[test]
fn compile_ipv6_net_prefix() {
    let ast = parse("net 2001:db8::/32").unwrap();
    let prog = compile(&ast);

    let ok = build_ipv6_packet(
        IPPROTO_TCP,
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    assert!(Vm::exec(&prog, &ok));

    let no = build_ipv6_packet(
        IPPROTO_TCP,
        [0xfe80, 0, 0, 0, 0, 0, 0, 1],
        [0xfe80, 0, 0, 0, 0, 0, 0, 2],
        80,
        443,
    );
    assert!(!Vm::exec(&prog, &no));
}

#[test]
fn compile_icmp6_matches_ipv6_only() {
    let ast = parse("icmp6").unwrap();
    let prog = compile(&ast);

    let v6 = build_ipv6_packet(
        IPPROTO_ICMPV6,
        [0xfe80, 0, 0, 0, 0, 0, 0, 1],
        [0xfe80, 0, 0, 0, 0, 0, 0, 2],
        0,
        0,
    );
    assert!(Vm::exec(&prog, &v6));

    let v4 = build_packet(IPPROTO_ICMP, [192, 168, 1, 1], [192, 168, 1, 2], 0, 0);
    assert!(!Vm::exec(&prog, &v4));
}
