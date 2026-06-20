//! netdump-filter: pcap-filter expression parser and CBPF compiler.

pub mod assembler;
pub mod compiler;
pub mod types;

pub use compiler::compile;
pub use types::{
    BPF_ABS, BPF_ADD, BPF_ALU, BPF_AND, BPF_B, BPF_DIV, BPF_H, BPF_IMM, BPF_IND, BPF_JA, BPF_JEQ,
    BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_LEN, BPF_LSH, BPF_MEM,
    BPF_MISC, BPF_MOD, BPF_MSH, BPF_MUL, BPF_NEG, BPF_OR, BPF_RET, BPF_RSH, BPF_ST, BPF_STX,
    BPF_SUB, BPF_TAX, BPF_TXA, BPF_W, BPF_X, BPF_XOR, CBPF_ACCEPT, CBPF_REJECT, Instruction, jeq,
    jge, jgt, ld_abs_b, ld_abs_h, ld_abs_w, ld_ind_h, ldx_msh_b, ret_k,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;

/// Network protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ip,
    Ip6,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Arp,
    Rarp,
}

/// Relational operators for comparison expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

/// Packet direction qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Any direction (default).
    #[default]
    Any,
    /// Source.
    Src,
    /// Destination.
    Dst,
}

/// Host address, supports IPv4 and IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<IpAddr> for HostAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => HostAddr::V4(a),
            IpAddr::V6(a) => HostAddr::V6(a),
        }
    }
}

/// Network address with subnet mask, supports IPv4 and IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetAddr {
    V4 { addr: Ipv4Addr, mask: Ipv4Addr },
    V6 { addr: Ipv6Addr, mask: Ipv6Addr },
}

/// Filter expression AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAst {
    /// Protocol match, e.g. tcp, udp, ip6.
    Proto(Protocol),
    /// Host address match.
    Host { addr: HostAddr, dir: Direction },
    /// Port match.
    Port { port: u16, dir: Direction },
    /// Port range match.
    PortRange {
        start: u16,
        end: u16,
        dir: Direction,
    },
    /// Ethernet MAC address match.
    EtherHost { addr: [u8; 6], dir: Direction },
    /// IPv4/IPv6 network match.
    Net { addr: NetAddr, dir: Direction },
    /// Packet length comparison.
    Len { op: RelOp, len: u32 },
    /// Logical AND.
    And(Box<FilterAst>, Box<FilterAst>),
    /// Logical OR.
    Or(Box<FilterAst>, Box<FilterAst>),
    /// Logical NOT.
    Not(Box<FilterAst>),
}

/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

#[derive(Parser)]
#[grammar = "filter.pest"]
struct FilterParser;

/// Parse a filter expression string into an AST.
pub fn parse(input: &str) -> Result<FilterAst, ParseError> {
    let mut pairs =
        FilterParser::parse(Rule::filter, input).map_err(|e| ParseError(e.to_string()))?;
    let filter = pairs
        .next()
        .ok_or_else(|| ParseError("no filter expression found".into()))?;
    for pair in filter.into_inner() {
        if pair.as_rule() == Rule::expr {
            return build_expr(pair);
        }
    }
    Err(ParseError("no filter expression found".into()))
}

fn build_expr(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut inner = pair.into_inner();
    let or_expr = inner
        .next()
        .ok_or_else(|| ParseError("empty expression".into()))?;
    build_or(or_expr)
}

fn build_or(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut pairs = pair.into_inner().peekable();
    let mut left = build_and(
        pairs
            .next()
            .ok_or_else(|| ParseError("empty operand in OR expression".into()))?,
    )?;
    while let Some(op) = pairs.peek() {
        if op.as_rule() == Rule::or_op {
            pairs.next();
            let right = build_and(
                pairs
                    .next()
                    .ok_or_else(|| ParseError("missing right operand in OR".into()))?,
            )?;
            left = FilterAst::Or(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn build_and(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut pairs = pair.into_inner().peekable();
    let mut left = build_not(
        pairs
            .next()
            .ok_or_else(|| ParseError("empty operand in AND expression".into()))?,
    )?;
    while pairs.peek().is_some() {
        if pairs.peek().map(|p| p.as_rule()) == Some(Rule::and_op) {
            pairs.next();
        }
        let right = build_not(
            pairs
                .next()
                .ok_or_else(|| ParseError("missing right operand in AND".into()))?,
        )?;
        left = FilterAst::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn build_not(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut pairs = pair.into_inner().peekable();
    if let Some(p) = pairs.peek()
        && p.as_rule() == Rule::not_op
    {
        pairs.next();
        let primary = pairs
            .next()
            .ok_or_else(|| ParseError("expression expected after 'not'".into()))?;
        return Ok(FilterAst::Not(Box::new(build_primary(primary)?)));
    }
    let primary = pairs
        .next()
        .ok_or_else(|| ParseError("empty expression".into()))?;
    build_primary(primary)
}

fn build_primary(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut inner = pair.into_inner();
    let child = inner
        .next()
        .ok_or_else(|| ParseError("empty primary expression".into()))?;
    match child.as_rule() {
        Rule::predicate => build_predicate(child),
        Rule::expr => build_expr(child),
        _ => Err(ParseError(format!(
            "unexpected rule: {:?}",
            child.as_rule()
        ))),
    }
}

fn build_predicate(pair: Pair<Rule>) -> Result<FilterAst, ParseError> {
    let mut pairs = pair.into_inner();
    let first = pairs
        .next()
        .ok_or_else(|| ParseError("empty predicate".into()))?;

    let (dir, kind) = if first.as_rule() == Rule::direction {
        let dir = parse_direction(first.as_str())?;
        let kind = pairs
            .next()
            .ok_or_else(|| ParseError("predicate missing qualifier".into()))?;
        (dir, kind)
    } else {
        (Direction::Any, first)
    };

    match kind.as_rule() {
        Rule::proto => parse_proto(kind.as_str()),
        Rule::host => {
            let ip_pair = kind
                .into_inner()
                .next()
                .ok_or_else(|| ParseError("host missing address".into()))?;
            let addr = parse_host_addr(ip_pair.as_str())?;
            Ok(FilterAst::Host { addr, dir })
        }
        Rule::port => {
            let num_pair = kind
                .into_inner()
                .next()
                .ok_or_else(|| ParseError("port missing number".into()))?;
            let port: u16 = num_pair
                .as_str()
                .parse()
                .map_err(|e| ParseError(format!("invalid port: {e}")))?;
            Ok(FilterAst::Port { port, dir })
        }
        Rule::portrange => {
            let mut inner = kind.into_inner();
            let start: u16 = parse_number(
                inner
                    .next()
                    .ok_or_else(|| ParseError("portrange missing start port".into()))?,
            )?;
            let end: u16 = parse_number(
                inner
                    .next()
                    .ok_or_else(|| ParseError("portrange missing end port".into()))?,
            )?;
            if start > end {
                return Err(ParseError(
                    "portrange start port is greater than end port".into(),
                ));
            }
            Ok(FilterAst::PortRange { start, end, dir })
        }
        Rule::net => {
            let net = parse_net(kind)?;
            Ok(FilterAst::Net { addr: net, dir })
        }
        Rule::len_expr => {
            let text = kind.as_str();
            let mut inner = kind.into_inner();
            if text.eq_ignore_ascii_case("greater")
                || text.to_ascii_lowercase().starts_with("greater ")
            {
                let len = parse_number_u32(
                    inner
                        .next()
                        .ok_or_else(|| ParseError("greater missing value".into()))?,
                )?;
                return Ok(FilterAst::Len { op: RelOp::Gt, len });
            }
            if text.eq_ignore_ascii_case("less") || text.to_ascii_lowercase().starts_with("less ") {
                let len = parse_number_u32(
                    inner
                        .next()
                        .ok_or_else(|| ParseError("less missing value".into()))?,
                )?;
                return Ok(FilterAst::Len { op: RelOp::Lt, len });
            }
            let relop_pair = inner
                .next()
                .ok_or_else(|| ParseError("len missing relational operator".into()))?;
            let op = parse_relop(relop_pair.as_str())?;
            let len = parse_number_u32(
                inner
                    .next()
                    .ok_or_else(|| ParseError("len missing value".into()))?,
            )?;
            Ok(FilterAst::Len { op, len })
        }
        Rule::ether_host => {
            let mut inner = kind.into_inner();
            // inner has direction? ~ mac.
            let first = inner
                .next()
                .ok_or_else(|| ParseError("ether host is empty".into()))?;
            let (dir, mac_pair) = if first.as_rule() == Rule::direction {
                let dir = parse_direction(first.as_str())?;
                let mac = inner
                    .next()
                    .ok_or_else(|| ParseError("ether host missing MAC".into()))?;
                (dir, mac)
            } else {
                (Direction::Any, first)
            };
            let addr = parse_mac(mac_pair.as_str())?;
            Ok(FilterAst::EtherHost { addr, dir })
        }
        _ => Err(ParseError(format!(
            "unexpected predicate type: {:?}",
            kind.as_rule()
        ))),
    }
}

fn parse_direction(s: &str) -> Result<Direction, ParseError> {
    if s.eq_ignore_ascii_case("src") {
        Ok(Direction::Src)
    } else if s.eq_ignore_ascii_case("dst") {
        Ok(Direction::Dst)
    } else {
        Err(ParseError(format!("invalid direction: {s}")))
    }
}

fn parse_proto(s: &str) -> Result<FilterAst, ParseError> {
    let proto = if s.eq_ignore_ascii_case("ip") {
        Protocol::Ip
    } else if s.eq_ignore_ascii_case("ip6") {
        Protocol::Ip6
    } else if s.eq_ignore_ascii_case("tcp") {
        Protocol::Tcp
    } else if s.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else if s.eq_ignore_ascii_case("icmp") {
        Protocol::Icmp
    } else if s.eq_ignore_ascii_case("icmp6") {
        Protocol::Icmp6
    } else if s.eq_ignore_ascii_case("arp") {
        Protocol::Arp
    } else if s.eq_ignore_ascii_case("rarp") {
        Protocol::Rarp
    } else {
        return Err(ParseError(format!("invalid protocol: {s}")));
    };
    Ok(FilterAst::Proto(proto))
}

fn parse_host_addr(s: &str) -> Result<HostAddr, ParseError> {
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Ok(HostAddr::V4(v4));
    }
    if let Ok(v6) = s.parse::<Ipv6Addr>() {
        return Ok(HostAddr::V6(v6));
    }
    Err(ParseError(format!("invalid IP address: {s}")))
}

fn parse_net(pair: Pair<Rule>) -> Result<NetAddr, ParseError> {
    let mut inner = pair.into_inner();
    let ip_pair = inner
        .next()
        .ok_or_else(|| ParseError("net missing IP".into()))?;
    let host = parse_host_addr(ip_pair.as_str())?;
    let mask = if let Some(mask_pair) = inner.next() {
        parse_netmask(mask_pair, &host)?
    } else {
        default_netmask(&host)
    };
    combine_net(host, mask)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetMask {
    Prefix(u8),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

fn default_netmask(host: &HostAddr) -> NetMask {
    match host {
        HostAddr::V4(addr) => {
            let first = addr.octets()[0];
            // Classful address inference, consistent with tcpdump behavior.
            if first < 128 {
                NetMask::Prefix(8) // Class A
            } else if first < 192 {
                NetMask::Prefix(16) // Class B
            } else if first < 224 {
                NetMask::Prefix(24) // Class C
            } else {
                NetMask::Prefix(32)
            }
        }
        HostAddr::V6(_) => NetMask::Prefix(128),
    }
}

fn parse_netmask(pair: Pair<Rule>, host: &HostAddr) -> Result<NetMask, ParseError> {
    let mut inner = pair.into_inner();
    let value = inner
        .next()
        .ok_or_else(|| ParseError("netmask is empty".into()))?;
    match value.as_rule() {
        Rule::ip => match host {
            HostAddr::V4(_) => {
                let mask: Ipv4Addr = value
                    .as_str()
                    .parse()
                    .map_err(|e| ParseError(format!("invalid IPv4 mask: {e}")))?;
                Ok(NetMask::V4(mask))
            }
            HostAddr::V6(_) => {
                let mask: Ipv6Addr = value
                    .as_str()
                    .parse()
                    .map_err(|e| ParseError(format!("invalid IPv6 mask: {e}")))?;
                Ok(NetMask::V6(mask))
            }
        },
        Rule::number => {
            let prefix: u8 = value
                .as_str()
                .parse()
                .map_err(|e| ParseError(format!("invalid prefix length: {e}")))?;
            match host {
                HostAddr::V4(_) if prefix > 32 => {
                    Err(ParseError("IPv4 prefix length must be <= 32".into()))
                }
                HostAddr::V6(_) if prefix > 128 => {
                    Err(ParseError("IPv6 prefix length must be <= 128".into()))
                }
                _ => Ok(NetMask::Prefix(prefix)),
            }
        }
        _ => Err(ParseError(format!(
            "unexpected netmask rule: {:?}",
            value.as_rule()
        ))),
    }
}

fn combine_net(host: HostAddr, mask: NetMask) -> Result<NetAddr, ParseError> {
    match (host, mask) {
        (HostAddr::V4(addr), NetMask::Prefix(p)) => {
            let mask = Ipv4Addr::from(u32::MAX << (32 - p));
            Ok(NetAddr::V4 { addr, mask })
        }
        (HostAddr::V4(addr), NetMask::V4(mask)) => Ok(NetAddr::V4 { addr, mask }),
        (HostAddr::V6(addr), NetMask::Prefix(p)) => {
            let mask = Ipv6Addr::from(u128::MAX << (128 - p));
            Ok(NetAddr::V6 { addr, mask })
        }
        (HostAddr::V6(addr), NetMask::V6(mask)) => Ok(NetAddr::V6 { addr, mask }),
        _ => Err(ParseError("IP address and mask version mismatch".into())),
    }
}

fn parse_number(pair: Pair<Rule>) -> Result<u16, ParseError> {
    pair.as_str()
        .parse()
        .map_err(|e| ParseError(format!("invalid number: {e}")))
}

fn parse_number_u32(pair: Pair<Rule>) -> Result<u32, ParseError> {
    pair.as_str()
        .parse()
        .map_err(|e| ParseError(format!("invalid number: {e}")))
}

fn parse_relop(s: &str) -> Result<RelOp, ParseError> {
    match s {
        "=" | "==" => Ok(RelOp::Eq),
        "!=" => Ok(RelOp::Ne),
        ">" => Ok(RelOp::Gt),
        ">=" => Ok(RelOp::Ge),
        "<" => Ok(RelOp::Lt),
        "<=" => Ok(RelOp::Le),
        _ => Err(ParseError(format!("invalid relational operator: {s}"))),
    }
}

fn parse_mac(s: &str) -> Result<[u8; 6], ParseError> {
    let mut octets = [0u8; 6];
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            return Err(ParseError("MAC address exceeds 6 bytes".into()));
        }
        octets[i] =
            u8::from_str_radix(part, 16).map_err(|e| ParseError(format!("invalid MAC: {e}")))?;
    }
    Ok(octets)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn parse_simple_proto() {
        let ast = parse("tcp").unwrap();
        assert_eq!(ast, FilterAst::Proto(Protocol::Tcp));
    }

    #[test]
    fn parse_host() {
        let ast = parse("host 192.168.1.1").unwrap();
        assert_eq!(
            ast,
            FilterAst::Host {
                addr: HostAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dir: Direction::Any,
            }
        );
    }

    #[test]
    fn parse_src_host_ipv6() {
        let ast = parse("src host fe80::1").unwrap();
        assert_eq!(
            ast,
            FilterAst::Host {
                addr: HostAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                dir: Direction::Src,
            }
        );
    }

    #[test]
    fn parse_port() {
        let ast = parse("port 80").unwrap();
        assert_eq!(
            ast,
            FilterAst::Port {
                port: 80,
                dir: Direction::Any
            }
        );
    }

    #[test]
    fn parse_src_port() {
        let ast = parse("src port 443").unwrap();
        assert_eq!(
            ast,
            FilterAst::Port {
                port: 443,
                dir: Direction::Src
            }
        );
    }

    #[test]
    fn parse_portrange() {
        let ast = parse("portrange 1000-2000").unwrap();
        assert_eq!(
            ast,
            FilterAst::PortRange {
                start: 1000,
                end: 2000,
                dir: Direction::Any
            }
        );
    }

    #[test]
    fn parse_net_ipv4() {
        let ast = parse("net 192.168.0.0/16").unwrap();
        assert_eq!(
            ast,
            FilterAst::Net {
                addr: NetAddr::V4 {
                    addr: Ipv4Addr::new(192, 168, 0, 0),
                    mask: Ipv4Addr::new(255, 255, 0, 0)
                },
                dir: Direction::Any,
            }
        );
    }

    #[test]
    fn parse_net_ipv6() {
        let ast = parse("src net fe80::/10").unwrap();
        assert_eq!(
            ast,
            FilterAst::Net {
                addr: NetAddr::V6 {
                    addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
                    mask: Ipv6Addr::new(0xffc0, 0, 0, 0, 0, 0, 0, 0)
                },
                dir: Direction::Src,
            }
        );
    }

    #[test]
    fn parse_ether_host() {
        let ast = parse("ether host aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(
            ast,
            FilterAst::EtherHost {
                addr: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                dir: Direction::Any,
            }
        );
    }

    #[test]
    fn parse_line_protocol_shortcuts() {
        assert_eq!(parse("ip").unwrap(), FilterAst::Proto(Protocol::Ip));
        assert_eq!(parse("ip6").unwrap(), FilterAst::Proto(Protocol::Ip6));
        assert_eq!(parse("arp").unwrap(), FilterAst::Proto(Protocol::Arp));
        assert_eq!(parse("rarp").unwrap(), FilterAst::Proto(Protocol::Rarp));
        assert_eq!(parse("icmp").unwrap(), FilterAst::Proto(Protocol::Icmp));
        assert_eq!(parse("icmp6").unwrap(), FilterAst::Proto(Protocol::Icmp6));
    }

    #[test]
    fn parse_and_expression() {
        let ast = parse("tcp and port 80").unwrap();
        assert_eq!(
            ast,
            FilterAst::And(
                Box::new(FilterAst::Proto(Protocol::Tcp)),
                Box::new(FilterAst::Port {
                    port: 80,
                    dir: Direction::Any
                }),
            )
        );
    }

    #[test]
    fn parse_or_expression() {
        let ast = parse("tcp or udp").unwrap();
        assert_eq!(
            ast,
            FilterAst::Or(
                Box::new(FilterAst::Proto(Protocol::Tcp)),
                Box::new(FilterAst::Proto(Protocol::Udp)),
            )
        );
    }

    #[test]
    fn parse_not_expression() {
        let ast = parse("not arp").unwrap();
        assert_eq!(
            ast,
            FilterAst::Not(Box::new(FilterAst::Proto(Protocol::Arp)))
        );
    }

    #[test]
    fn parse_parens_precedence() {
        let ast = parse("tcp and (port 80 or port 443)").unwrap();
        assert_eq!(
            ast,
            FilterAst::And(
                Box::new(FilterAst::Proto(Protocol::Tcp)),
                Box::new(FilterAst::Or(
                    Box::new(FilterAst::Port {
                        port: 80,
                        dir: Direction::Any
                    }),
                    Box::new(FilterAst::Port {
                        port: 443,
                        dir: Direction::Any
                    }),
                )),
            )
        );
    }

    #[test]
    fn parse_len_shortcuts() {
        let ast1 = parse("greater 100").unwrap();
        assert_eq!(
            ast1,
            FilterAst::Len {
                op: RelOp::Gt,
                len: 100
            }
        );
        let ast2 = parse("less 50").unwrap();
        assert_eq!(
            ast2,
            FilterAst::Len {
                op: RelOp::Lt,
                len: 50
            }
        );
        let ast3 = parse("len >= 64").unwrap();
        assert_eq!(
            ast3,
            FilterAst::Len {
                op: RelOp::Ge,
                len: 64
            }
        );
    }

    #[test]
    fn parse_error_empty() {
        let err = parse("");
        assert!(err.is_err());
    }

    #[test]
    fn parse_error_invalid_proto() {
        let err = parse("unknown_proto").unwrap_err();
        // pest will produce a parse error for unrecognized tokens
        assert!(!err.0.is_empty());
    }

    #[test]
    fn parse_error_invalid_port() {
        let err = parse("port 99999").unwrap_err();
        assert!(err.0.contains("invalid port"));
    }

    #[test]
    fn parse_error_invalid_ip() {
        let err = parse("host 999.999.999.999").unwrap_err();
        // pest will produce a parse error for invalid IP format
        assert!(!err.0.is_empty());
    }
}
