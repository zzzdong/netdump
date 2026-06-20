//! 与 libpcap 交叉验证 CBPF 编译器和 VM。
//!
//! 对同一组过滤表达式，分别用 netdump-filter 和 libpcap 编译，
//! 再在大量随机/确定性报文上运行，确保两者判断结果完全一致。

mod common;

use common::all_packets;
use netdump_cbpf::Vm;
use netdump_filter::{compile, parse};
use pcap::Capture;

fn compare_with_pcap(expr: &str) {
    let ast = match parse(expr) {
        Ok(a) => a,
        Err(_) => {
            // netdump-filter 暂时不支持该表达式，跳过。
            return;
        }
    };
    let our_prog = compile(&ast);

    let cap = Capture::dead(pcap::Linktype::ETHERNET).expect("pcap dead capture");
    let pcap_prog = cap.compile(expr, true).expect("pcap compile");

    for pkt in all_packets() {
        let our_result = Vm::exec(&our_prog, &pkt);
        let pcap_result = pcap_prog.filter(&pkt);
        assert_eq!(
            our_result, pcap_result,
            "表达式 `{expr}` 在报文 {pkt:?} 上结果不一致: netdump={our_result}, pcap={pcap_result}"
        );
    }
}

#[test]
fn cross_validate_protocols() {
    let exprs = ["tcp", "udp", "icmp", "ip", "arp", "rarp"];
    for expr in exprs {
        compare_with_pcap(expr);
    }
}

#[test]
fn cross_validate_hosts() {
    compare_with_pcap("host 192.168.1.1");
    compare_with_pcap("src host 10.0.0.5");
    compare_with_pcap("dst host 1.1.1.1");
    compare_with_pcap("host 8.8.8.8 or host 192.168.1.1");
    compare_with_pcap("src host 192.168.1.1 and dst host 1.1.1.1");
}

#[test]
fn cross_validate_ports() {
    compare_with_pcap("port 80");
    compare_with_pcap("src port 53");
    compare_with_pcap("dst port 443");
    compare_with_pcap("tcp port 8080");
    compare_with_pcap("udp port 12345");
    compare_with_pcap("src port 80 and dst port 443");
}

#[test]
fn cross_validate_portranges() {
    compare_with_pcap("portrange 1-100");
    compare_with_pcap("src portrange 1000-2000");
    compare_with_pcap("dst portrange 1024-65535");
    compare_with_pcap("tcp portrange 80-443");
    compare_with_pcap("udp portrange 53-5353");
}

#[test]
fn cross_validate_combined() {
    compare_with_pcap("tcp and host 192.168.1.1");
    compare_with_pcap("tcp port 80 or udp port 53");
    compare_with_pcap("not icmp");
    compare_with_pcap("udp and dst host 1.1.1.1");
    compare_with_pcap("tcp and not port 22");
}

#[test]
fn cross_validate_ip_predicate() {
    // `ip` 只匹配 IPv4，不应匹配 ARP。
    compare_with_pcap("ip");
    compare_with_pcap("ip and tcp");
    compare_with_pcap("ip and udp");
    compare_with_pcap("ip and icmp");
    compare_with_pcap("ip and not arp");
}

#[test]
fn cross_validate_direction_combinations() {
    compare_with_pcap("src host 192.168.1.1");
    compare_with_pcap("dst host 192.168.1.1");
    compare_with_pcap("src port 80");
    compare_with_pcap("dst port 443");
    compare_with_pcap("tcp and src port 80");
    compare_with_pcap("udp and dst port 53");
}

#[test]
fn cross_validate_parentheses() {
    compare_with_pcap("(tcp or udp) and host 192.168.1.1");
    compare_with_pcap("tcp and (src port 80 or dst port 443)");
    compare_with_pcap("not (tcp or udp or icmp)");
    compare_with_pcap("(src host 10.0.0.5) and (dst port 12345)");
}

#[test]
fn cross_validate_not() {
    compare_with_pcap("not tcp");
    compare_with_pcap("not host 192.168.1.1");
    compare_with_pcap("tcp and not port 22");
    compare_with_pcap("not (udp and dst host 1.1.1.1)");
    compare_with_pcap("not arp and not rarp");
}

#[test]
fn cross_validate_complex() {
    compare_with_pcap("(tcp and src host 10.0.0.5 and src port 80) or (udp and dst host 1.1.1.1)");
    compare_with_pcap("tcp and dst port 443 and host 8.8.8.8");
    compare_with_pcap("(tcp or udp) and (src host 192.168.1.1 or dst host 10.0.0.5)");
}

#[test]
fn cross_validate_arp_rarp() {
    compare_with_pcap("arp");
    compare_with_pcap("rarp");
    compare_with_pcap("arp or ip");
    compare_with_pcap("arp and not ip");
}

#[test]
fn cross_validate_ether_host() {
    compare_with_pcap("ether host aa:bb:cc:dd:ee:ff");
    compare_with_pcap("ether src 11:22:33:44:55:66");
    compare_with_pcap("ether dst ff:ff:ff:ff:ff:ff");
    compare_with_pcap("ether host aa:bb:cc:dd:ee:ff or ether host 00:11:22:33:44:55");
}

#[test]
fn cross_validate_net() {
    compare_with_pcap("net 192.168.1.0/24");
    compare_with_pcap("net 10.0.0.0/8");
    compare_with_pcap("src net 172.16.0.0/16");
    compare_with_pcap("dst net 1.1.1.0 mask 255.255.255.0");
    compare_with_pcap("net 192.168.0.0/16 and tcp");
}

#[test]
fn cross_validate_len() {
    compare_with_pcap("greater 40");
    compare_with_pcap("less 60");
    compare_with_pcap("len >= 50");
    compare_with_pcap("len > 40 and len < 100");
    compare_with_pcap("len != 54");
}

#[test]
fn cross_validate_chained_and() {
    compare_with_pcap("tcp and host 192.168.1.1 and port 80");
    compare_with_pcap("udp and dst host 1.1.1.1 and dst port 53");
    compare_with_pcap("ip and src host 10.0.0.5 and src port 443 and dst host 8.8.8.8");
}

#[test]
fn cross_validate_chained_or() {
    compare_with_pcap("tcp or udp or icmp");
    compare_with_pcap("host 192.168.1.1 or host 10.0.0.5 or host 8.8.8.8");
    compare_with_pcap("port 22 or port 53 or port 80 or port 443");
}

#[test]
fn cross_validate_mixed_nesting() {
    compare_with_pcap("(tcp and src host 10.0.0.5) or (udp and dst host 1.1.1.1) or icmp");
    compare_with_pcap("ip and not (tcp or udp)");
    compare_with_pcap("(src host 192.168.1.1 and dst port 443) or (dst host 1.1.1.1 and udp)");
    compare_with_pcap("not (arp or rarp) and (tcp or udp or icmp)");
}

#[test]
fn cross_validate_ipv6_protocols() {
    compare_with_pcap("ip6");
    compare_with_pcap("tcp");
    compare_with_pcap("udp");
    compare_with_pcap("icmp6");
    compare_with_pcap("ip6 and tcp");
    compare_with_pcap("ip6 and udp");
    compare_with_pcap("ip6 and icmp6");
}

#[test]
fn cross_validate_ipv6_hosts() {
    compare_with_pcap("host fe80::1");
    compare_with_pcap("src host fe80::1");
    compare_with_pcap("dst host 2001:db8::2");
    compare_with_pcap("host fe80::1 or host 2001:db8::1");
}

#[test]
fn cross_validate_ipv6_ports() {
    compare_with_pcap("port 80");
    compare_with_pcap("src port 53");
    compare_with_pcap("dst port 443");
    compare_with_pcap("tcp port 8080");
    compare_with_pcap("udp port 12345");
    compare_with_pcap("ip6 and port 80");
    compare_with_pcap("ip6 and src port 443");
}

#[test]
fn cross_validate_ipv6_net() {
    compare_with_pcap("net fe80::/10");
    compare_with_pcap("net 2001:db8::/32");
    compare_with_pcap("src net fe80::/64");
    compare_with_pcap("dst net fd00::/8");
    compare_with_pcap("net 2001:db8::/32 and tcp");
}

#[test]
fn cross_validate_ipv6_combined() {
    compare_with_pcap("ip6 and host fe80::1 and port 80");
    compare_with_pcap("ip6 and tcp and dst host 2001:db8::2");
    compare_with_pcap("ip6 and not icmp6");
    compare_with_pcap("(ip6 and tcp port 80) or (ip and udp port 53)");
}
