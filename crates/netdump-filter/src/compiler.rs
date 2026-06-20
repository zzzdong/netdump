//! Compile FilterAst into CBPF bytecode.

use std::net::{Ipv4Addr, Ipv6Addr};

use netdump_core::{
    ETHERTYPE_ARP, ETHERTYPE_IP, ETHERTYPE_IPV6, ETHERTYPE_RARP, IPPROTO_ICMP, IPPROTO_ICMPV6,
    IPPROTO_TCP, IPPROTO_UDP,
};

use crate::assembler::{Assembler, LabelId};
use crate::types::*;
use crate::{Direction, FilterAst, HostAddr, NetAddr, Protocol, RelOp};

/// Compile a filter AST into a CBPF program.
pub fn compile(ast: &FilterAst) -> Vec<Instruction> {
    let mut asm = Assembler::new();
    let accept = asm.new_label();
    let reject = asm.new_label();

    compile_node(ast, &mut asm, accept, reject);

    asm.place_label(accept, asm.next_index());
    asm.emit(ret_k(CBPF_ACCEPT));
    asm.place_label(reject, asm.next_index());
    asm.emit(ret_k(CBPF_REJECT));

    asm.resolve()
}

fn compile_node(ast: &FilterAst, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    match ast {
        FilterAst::And(left, right) => {
            let mid = asm.new_label();
            compile_node(left, asm, mid, reject);
            asm.place_label(mid, asm.next_index());
            compile_node(right, asm, accept, reject);
        }
        FilterAst::Or(left, right) => {
            let mid = asm.new_label();
            compile_node(left, asm, accept, mid);
            asm.place_label(mid, asm.next_index());
            compile_node(right, asm, accept, reject);
        }
        FilterAst::Not(inner) => {
            compile_node(inner, asm, reject, accept);
        }
        FilterAst::Proto(proto) => compile_proto(*proto, asm, accept, reject),
        FilterAst::Host { addr, dir } => compile_host(*addr, *dir, asm, accept, reject),
        FilterAst::Port { port, dir } => compile_port(*port, *dir, asm, accept, reject),
        FilterAst::PortRange { start, end, dir } => {
            compile_port_range(*start, *end, *dir, asm, accept, reject);
        }
        FilterAst::EtherHost { addr, dir } => compile_ether_host(*addr, *dir, asm, accept, reject),
        FilterAst::Net { addr, dir } => compile_net(*addr, *dir, asm, accept, reject),
        FilterAst::Len { op, len } => compile_len(*op, *len, asm, accept, reject),
    }
}

fn compile_proto(proto: Protocol, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    match proto {
        Protocol::Ip => check_ethertype(ETHERTYPE_IP, asm, accept, reject),
        Protocol::Ip6 => check_ethertype(ETHERTYPE_IPV6, asm, accept, reject),
        Protocol::Arp => check_ethertype(ETHERTYPE_ARP, asm, accept, reject),
        Protocol::Rarp => check_ethertype(ETHERTYPE_RARP, asm, accept, reject),
        Protocol::Tcp | Protocol::Udp => compile_transport_proto(proto, asm, accept, reject),
        Protocol::Icmp => compile_icmpv4(asm, accept, reject),
        Protocol::Icmp6 => compile_icmpv6(asm, accept, reject),
    }
}

fn check_ethertype(ethertype: u16, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    asm.emit(ld_abs_h(12));
    asm.emit_jump(jeq(ethertype as u32), accept, reject);
}

fn compile_transport_proto(proto: Protocol, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    let proto_num = match proto {
        Protocol::Tcp => IPPROTO_TCP,
        Protocol::Udp => IPPROTO_UDP,
        _ => unreachable!(),
    } as u32;

    asm.emit(ld_abs_h(12));
    let ipv4_label = asm.new_label();
    let check_v6 = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), ipv4_label, check_v6);

    // IPv6 路径：检查 next header 字段（偏移 20）。
    asm.place_label(check_v6, asm.next_index());
    let ipv6_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), ipv6_label, reject);
    asm.place_label(ipv6_label, asm.next_index());
    asm.emit(ld_abs_b(20));
    asm.emit_jump(jeq(proto_num), accept, reject);

    // IPv4 路径：检查 IP 协议字段（偏移 23）。
    asm.place_label(ipv4_label, asm.next_index());
    asm.emit(ld_abs_b(23));
    asm.emit_jump(jeq(proto_num), accept, reject);
}

fn compile_icmpv4(asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    asm.emit(ld_abs_h(12));
    let proto_check = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), proto_check, reject);
    asm.place_label(proto_check, asm.next_index());
    asm.emit(ld_abs_b(23));
    asm.emit_jump(jeq(IPPROTO_ICMP as u32), accept, reject);
}

fn compile_icmpv6(asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    asm.emit(ld_abs_h(12));
    let proto_check = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), proto_check, reject);
    asm.place_label(proto_check, asm.next_index());
    asm.emit(ld_abs_b(20));
    asm.emit_jump(jeq(IPPROTO_ICMPV6 as u32), accept, reject);
}

fn compile_host(
    addr: HostAddr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    match addr {
        HostAddr::V4(a) => compile_ipv4_host(a, dir, asm, accept, reject),
        HostAddr::V6(a) => compile_ipv6_host(a, dir, asm, accept, reject),
    }
}

fn compile_ipv4_host(
    addr: Ipv4Addr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let addr_u32 = u32::from(addr);

    asm.emit(ld_abs_h(12));
    let ip_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), ip_label, reject);
    asm.place_label(ip_label, asm.next_index());

    match dir {
        Direction::Any => {
            asm.emit(ld_abs_w(26));
            let dst_check = asm.new_label();
            asm.emit_jump(jeq(addr_u32), accept, dst_check);
            asm.place_label(dst_check, asm.next_index());

            asm.emit(ld_abs_w(30));
            asm.emit_jump(jeq(addr_u32), accept, reject);
        }
        Direction::Src => {
            asm.emit(ld_abs_w(26));
            asm.emit_jump(jeq(addr_u32), accept, reject);
        }
        Direction::Dst => {
            asm.emit(ld_abs_w(30));
            asm.emit_jump(jeq(addr_u32), accept, reject);
        }
    }
}

fn compile_ipv6_host(
    addr: Ipv6Addr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let words = ipv6_words(addr);

    asm.emit(ld_abs_h(12));
    let ip6_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), ip6_label, reject);
    asm.place_label(ip6_label, asm.next_index());

    match dir {
        Direction::Any => {
            let dst_check = asm.new_label();
            check_ipv6_addr_at(asm, 22, &words, accept, dst_check);
            asm.place_label(dst_check, asm.next_index());
            check_ipv6_addr_at(asm, 38, &words, accept, reject);
        }
        Direction::Src => check_ipv6_addr_at(asm, 22, &words, accept, reject),
        Direction::Dst => check_ipv6_addr_at(asm, 38, &words, accept, reject),
    }
}

fn check_ipv6_addr_at(
    asm: &mut Assembler,
    offset: u32,
    words: &[u32; 4],
    accept: LabelId,
    reject: LabelId,
) {
    for (i, &word) in words.iter().enumerate() {
        asm.emit(ld_abs_w(offset + (i as u32) * 4));
        if i == words.len() - 1 {
            asm.emit_jump(jeq(word), accept, reject);
        } else {
            let next = asm.new_label();
            asm.emit_jump(jeq(word), next, reject);
            asm.place_label(next, asm.next_index());
        }
    }
}

fn compile_port(port: u16, dir: Direction, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    let port_u32 = port as u32;

    asm.emit(ld_abs_h(12));
    let ipv4_label = asm.new_label();
    let check_v6 = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), ipv4_label, check_v6);

    // IPv6 路径。
    asm.place_label(check_v6, asm.next_index());
    let ipv6_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), ipv6_label, reject);
    asm.place_label(ipv6_label, asm.next_index());
    check_transport_and_compare_ports(asm, 54, 56, port_u32, dir, accept, reject);

    // IPv4 路径。
    asm.place_label(ipv4_label, asm.next_index());
    asm.emit(ld_abs_b(23));
    let udp_check = asm.new_label();
    let port_check = asm.new_label();
    asm.emit_jump(jeq(IPPROTO_TCP as u32), port_check, udp_check);
    asm.place_label(udp_check, asm.next_index());
    asm.emit_jump(jeq(IPPROTO_UDP as u32), port_check, reject);
    asm.place_label(port_check, asm.next_index());
    asm.emit(ldx_msh_b(14));
    compare_port_ind(asm, 14, 16, port_u32, dir, accept, reject);
}

fn compile_port_range(
    start: u16,
    end: u16,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let start_u32 = start as u32;
    let end_u32 = end as u32;

    asm.emit(ld_abs_h(12));
    let ipv4_label = asm.new_label();
    let check_v6 = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), ipv4_label, check_v6);

    // IPv6 路径。
    asm.place_label(check_v6, asm.next_index());
    let ipv6_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), ipv6_label, reject);
    asm.place_label(ipv6_label, asm.next_index());
    check_transport_and_compare_portrange(asm, 54, 56, start_u32, end_u32, dir, accept, reject);

    // IPv4 路径。
    asm.place_label(ipv4_label, asm.next_index());
    asm.emit(ld_abs_b(23));
    let udp_check = asm.new_label();
    let port_check = asm.new_label();
    asm.emit_jump(jeq(IPPROTO_TCP as u32), port_check, udp_check);
    asm.place_label(udp_check, asm.next_index());
    asm.emit_jump(jeq(IPPROTO_UDP as u32), port_check, reject);
    asm.place_label(port_check, asm.next_index());
    asm.emit(ldx_msh_b(14));
    compare_portrange_ind(asm, 14, 16, start_u32, end_u32, dir, accept, reject);
}

fn check_transport_and_compare_ports(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    port: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    asm.emit(ld_abs_b(20));
    let udp_check = asm.new_label();
    let port_check = asm.new_label();
    asm.emit_jump(jeq(IPPROTO_TCP as u32), port_check, udp_check);
    asm.place_label(udp_check, asm.next_index());
    asm.emit_jump(jeq(IPPROTO_UDP as u32), port_check, reject);
    asm.place_label(port_check, asm.next_index());
    compare_port_abs(asm, src_off, dst_off, port, dir, accept, reject);
}

#[allow(clippy::too_many_arguments)]
fn check_transport_and_compare_portrange(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    start: u32,
    end: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    asm.emit(ld_abs_b(20));
    let udp_check = asm.new_label();
    let port_check = asm.new_label();
    asm.emit_jump(jeq(IPPROTO_TCP as u32), port_check, udp_check);
    asm.place_label(udp_check, asm.next_index());
    asm.emit_jump(jeq(IPPROTO_UDP as u32), port_check, reject);
    asm.place_label(port_check, asm.next_index());
    compare_portrange_abs(asm, src_off, dst_off, start, end, dir, accept, reject);
}

fn compare_port_abs(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    port: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    match dir {
        Direction::Any => {
            asm.emit(ld_abs_h(src_off));
            let dst_check = asm.new_label();
            asm.emit_jump(jeq(port), accept, dst_check);
            asm.place_label(dst_check, asm.next_index());
            asm.emit(ld_abs_h(dst_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
        Direction::Src => {
            asm.emit(ld_abs_h(src_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
        Direction::Dst => {
            asm.emit(ld_abs_h(dst_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
    }
}

fn compare_port_ind(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    port: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    match dir {
        Direction::Any => {
            asm.emit(ld_ind_h(src_off));
            let dst_check = asm.new_label();
            asm.emit_jump(jeq(port), accept, dst_check);
            asm.place_label(dst_check, asm.next_index());
            asm.emit(ld_ind_h(dst_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
        Direction::Src => {
            asm.emit(ld_ind_h(src_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
        Direction::Dst => {
            asm.emit(ld_ind_h(dst_off));
            asm.emit_jump(jeq(port), accept, reject);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_portrange_abs(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    start: u32,
    end: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    match dir {
        Direction::Any => {
            asm.emit(ld_abs_h(src_off));
            let src_in = asm.new_label();
            asm.emit_jump(jge(start), src_in, reject);
            asm.place_label(src_in, asm.next_index());
            let src_out = asm.new_label();
            asm.emit_jump(jgt(end), src_out, accept);
            asm.place_label(src_out, asm.next_index());

            asm.emit(ld_abs_h(dst_off));
            let dst_in = asm.new_label();
            asm.emit_jump(jge(start), dst_in, reject);
            asm.place_label(dst_in, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
        Direction::Src => {
            asm.emit(ld_abs_h(src_off));
            let in_range = asm.new_label();
            asm.emit_jump(jge(start), in_range, reject);
            asm.place_label(in_range, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
        Direction::Dst => {
            asm.emit(ld_abs_h(dst_off));
            let in_range = asm.new_label();
            asm.emit_jump(jge(start), in_range, reject);
            asm.place_label(in_range, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_portrange_ind(
    asm: &mut Assembler,
    src_off: u32,
    dst_off: u32,
    start: u32,
    end: u32,
    dir: Direction,
    accept: LabelId,
    reject: LabelId,
) {
    match dir {
        Direction::Any => {
            asm.emit(ld_ind_h(src_off));
            let src_in = asm.new_label();
            asm.emit_jump(jge(start), src_in, reject);
            asm.place_label(src_in, asm.next_index());
            let src_out = asm.new_label();
            asm.emit_jump(jgt(end), src_out, accept);
            asm.place_label(src_out, asm.next_index());

            asm.emit(ld_ind_h(dst_off));
            let dst_in = asm.new_label();
            asm.emit_jump(jge(start), dst_in, reject);
            asm.place_label(dst_in, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
        Direction::Src => {
            asm.emit(ld_ind_h(src_off));
            let in_range = asm.new_label();
            asm.emit_jump(jge(start), in_range, reject);
            asm.place_label(in_range, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
        Direction::Dst => {
            asm.emit(ld_ind_h(dst_off));
            let in_range = asm.new_label();
            asm.emit_jump(jge(start), in_range, reject);
            asm.place_label(in_range, asm.next_index());
            asm.emit_jump(jgt(end), reject, accept);
        }
    }
}

fn compile_ether_host(
    addr: [u8; 6],
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let high = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    let low = u16::from_be_bytes([addr[4], addr[5]]) as u32;

    let check_at = |asm: &mut Assembler, offset: u32, accept: LabelId, reject: LabelId| {
        let high_ok = asm.new_label();
        asm.emit(ld_abs_w(offset));
        asm.emit_jump(jeq(high), high_ok, reject);
        asm.place_label(high_ok, asm.next_index());
        asm.emit(ld_abs_h(offset + 4));
        asm.emit_jump(jeq(low), accept, reject);
    };

    match dir {
        Direction::Any => {
            let src_check = asm.new_label();
            // dst MAC at offset 0
            check_at(asm, 0, accept, src_check);
            asm.place_label(src_check, asm.next_index());
            // src MAC at offset 6
            check_at(asm, 6, accept, reject);
        }
        Direction::Src => check_at(asm, 6, accept, reject),
        Direction::Dst => check_at(asm, 0, accept, reject),
    }
}

fn compile_net(
    addr: NetAddr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    match addr {
        NetAddr::V4 { addr, mask } => compile_ipv4_net(addr, mask, dir, asm, accept, reject),
        NetAddr::V6 { addr, mask } => compile_ipv6_net(addr, mask, dir, asm, accept, reject),
    }
}

fn compile_ipv4_net(
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let net_u32 = u32::from(addr) & u32::from(mask);
    let mask_u32 = u32::from(mask);

    asm.emit(ld_abs_h(12));
    let ip_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IP as u32), ip_label, reject);
    asm.place_label(ip_label, asm.next_index());

    let check_addr = |asm: &mut Assembler, offset: u32, accept: LabelId, reject: LabelId| {
        asm.emit(ld_abs_w(offset));
        asm.emit(Instruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, mask_u32));
        asm.emit_jump(jeq(net_u32), accept, reject);
    };

    match dir {
        Direction::Any => {
            let dst_check = asm.new_label();
            check_addr(asm, 26, accept, dst_check);
            asm.place_label(dst_check, asm.next_index());
            check_addr(asm, 30, accept, reject);
        }
        Direction::Src => check_addr(asm, 26, accept, reject),
        Direction::Dst => check_addr(asm, 30, accept, reject),
    }
}

fn compile_ipv6_net(
    addr: Ipv6Addr,
    mask: Ipv6Addr,
    dir: Direction,
    asm: &mut Assembler,
    accept: LabelId,
    reject: LabelId,
) {
    let addr_words = ipv6_words(addr);
    let mask_words = ipv6_words(mask);

    asm.emit(ld_abs_h(12));
    let ip6_label = asm.new_label();
    asm.emit_jump(jeq(ETHERTYPE_IPV6 as u32), ip6_label, reject);
    asm.place_label(ip6_label, asm.next_index());

    match dir {
        Direction::Any => {
            let dst_check = asm.new_label();
            check_ipv6_net_at(asm, 22, &addr_words, &mask_words, accept, dst_check);
            asm.place_label(dst_check, asm.next_index());
            check_ipv6_net_at(asm, 38, &addr_words, &mask_words, accept, reject);
        }
        Direction::Src => check_ipv6_net_at(asm, 22, &addr_words, &mask_words, accept, reject),
        Direction::Dst => check_ipv6_net_at(asm, 38, &addr_words, &mask_words, accept, reject),
    }
}

fn check_ipv6_net_at(
    asm: &mut Assembler,
    offset: u32,
    addr_words: &[u32; 4],
    mask_words: &[u32; 4],
    accept: LabelId,
    reject: LabelId,
) {
    for (i, (&addr_word, &mask_word)) in addr_words.iter().zip(mask_words.iter()).enumerate() {
        asm.emit(ld_abs_w(offset + (i as u32) * 4));
        asm.emit(Instruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, mask_word));
        if i == addr_words.len() - 1 {
            asm.emit_jump(jeq(addr_word), accept, reject);
        } else {
            let next = asm.new_label();
            asm.emit_jump(jeq(addr_word), next, reject);
            asm.place_label(next, asm.next_index());
        }
    }
}

fn compile_len(op: RelOp, len: u32, asm: &mut Assembler, accept: LabelId, reject: LabelId) {
    // BPF_LEN 加载报文长度到 A。
    asm.emit(Instruction::new(BPF_LD | BPF_LEN | BPF_W, 0, 0, 0));
    match op {
        RelOp::Eq => asm.emit_jump(jeq(len), accept, reject),
        RelOp::Ne => asm.emit_jump(jeq(len), reject, accept),
        RelOp::Gt => asm.emit_jump(jgt(len), accept, reject),
        RelOp::Ge => asm.emit_jump(jge(len), accept, reject),
        RelOp::Lt => asm.emit_jump(jge(len), reject, accept),
        RelOp::Le => asm.emit_jump(jgt(len), reject, accept),
    };
}

fn ipv6_words(addr: Ipv6Addr) -> [u32; 4] {
    let octets = addr.octets();
    [
        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}
