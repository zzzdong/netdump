//! netdump-cli: Command-line entrypoint for the netdump packet analyzer.

use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::{ArgAction, Parser};
use netdump_afpacket::{AfPacketSocket, OpenOptions, RawBpfInsn};
use netdump_cbpf::Vm;
use netdump_core::{NetdumpError, Packet, PacketMeta, parse_packet};
use netdump_filter::{compile, parse};
use pcap_file::{
    DataLink,
    pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter},
};

/// Packet printing context: sequence number, previous timestamp, first timestamp.
struct PktCtx {
    num: usize,
    prev_ts: (i64, u64),
    first_ts: (i64, u64),
}

#[derive(Parser, Debug)]
#[command(name = "netdump", version, about = "A simple tcpdump clone in Rust")]
struct Args {
    /// Network interface to listen on; uses the default interface if omitted.
    #[arg(short, long)]
    interface: Option<String>,

    /// Filter expression, e.g. `tcp port 80`.
    filter: Option<String>,

    /// Read the filter expression from a file.
    #[arg(short, long, value_name = "FILE")]
    filter_file: Option<PathBuf>,

    /// Exit after receiving this many packets.
    #[arg(short, long)]
    count: Option<usize>,

    /// Write captured packets to a pcap file.
    #[arg(short, long, value_name = "FILE")]
    write: Option<PathBuf>,

    /// Read packets from a pcap file instead of capturing.
    #[arg(short, long, value_name = "FILE")]
    read: Option<PathBuf>,

    /// Set the snap length; 0 means no limit.
    #[arg(short = 's', long, value_name = "SNAPLEN", default_value = "0")]
    snaplen: u32,

    /// Do not put the interface into promiscuous mode.
    #[arg(short = 'p', long = "no-promiscuous", action = ArgAction::SetTrue)]
    no_promiscuous: bool,

    /// List available interfaces and exit.
    #[arg(short = 'D', long, action = ArgAction::SetTrue)]
    list_interfaces: bool,

    /// Print the link-level header on each line.
    #[arg(short = 'e', long = "link-header", action = ArgAction::SetTrue)]
    link_header: bool,

    /// Print each packet in ASCII (minus the link-level header).
    #[arg(short = 'A', long, action = ArgAction::SetTrue)]
    ascii: bool,

    /// Quick (quiet) output.
    #[arg(short, long, action = ArgAction::SetTrue)]
    quiet: bool,

    /// Verbose output; can be repeated.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Do not resolve addresses/port names; -nn also disables protocol names.
    #[arg(short = 'n', long = "no-resolve", action = ArgAction::Count)]
    no_resolve: u8,

    /// Dump the generated CBPF bytecode and exit.
    #[arg(short, long)]
    dump_bpf: bool,

    /// Force userspace CBPF VM filtering instead of kernel BPF filtering.
    #[arg(long)]
    userspace_filter: bool,

    /// Print each packet in hex (sans link-level header); -xx also prints link-level.
    #[arg(short = 'x', long, action = ArgAction::Count)]
    hex: u8,

    /// Print each packet in hex+ASCII (sans link-level header); -XX also prints link-level.
    #[arg(short = 'X', long, action = ArgAction::Count)]
    hex_ascii: u8,

    /// Timestamp format: -t (none), -tt (Unix), -ttt (delta), -tttt (date), -ttttt (delta since first).
    #[arg(short = 't', long, action = ArgAction::Count)]
    timestamp_format: u8,

    /// Set the operating system capture buffer size (KiB).
    #[arg(short = 'B', long = "buffer-size", value_name = "BUFFER_SIZE")]
    buffer_size: Option<u32>,

    /// Don't verify IP, TCP, or UDP checksums.
    #[arg(short = 'K', long = "dont-verify-checksums", action = ArgAction::SetTrue)]
    no_checksum_verify: bool,

    /// Print a packet number at the beginning of the line.
    #[arg(short = '#', long = "number", action = ArgAction::SetTrue)]
    packet_number: bool,

    /// Print absolute, rather than relative, TCP sequence numbers.
    #[arg(short = 'S', long = "absolute-tcp-sequence-numbers", action = ArgAction::SetTrue)]
    absolute_tcp_seq: bool,

    /// Make stdout line buffered (useful when piping to tee).
    #[arg(short = 'l', long, action = ArgAction::SetTrue)]
    line_buffered: bool,

    /// Print parsed packet output even when saving to file with -w.
    #[arg(long, action = ArgAction::SetTrue)]
    print: bool,

    /// Choose send/receive direction for which packets should be captured: in, out, or inout.
    #[arg(short = 'Q', long = "direction", value_name = "DIRECTION")]
    direction: Option<String>,

    /// TPACKET_V3 ring block size (KiB, default 1024).
    #[arg(long = "block-size", value_name = "KIB", default_value_t = 1024)]
    block_size_kib: u32,

    /// Number of TPACKET_V3 ring blocks (default 64).
    #[arg(long = "block-nr", value_name = "COUNT", default_value_t = 64)]
    block_nr: u32,

    /// Frame size (bytes, default 2048).
    #[arg(long = "frame-size", value_name = "BYTES", default_value_t = 2048)]
    frame_size: u32,

    /// Block retire timeout (ms, default 100).
    #[arg(long = "retire-tov", value_name = "MS", default_value_t = 100)]
    retire_tov_ms: u32,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), NetdumpError> {
    let args = Args::parse();

    if args.list_interfaces {
        for info in netdump_afpacket::list_interfaces()? {
            let flag = if info.is_up { "*" } else { "" };
            println!("{}. {}{flag}", info.ifindex, info.name);
        }
        return Ok(());
    }

    let filter_expr = if let Some(path) = &args.filter_file {
        let mut s = String::new();
        File::open(path)
            .map_err(|e| NetdumpError::Io(e.to_string()))?
            .read_to_string(&mut s)
            .map_err(|e| NetdumpError::Io(e.to_string()))?;
        let s = s.trim();
        if s.is_empty() {
            return Err(NetdumpError::Parse("empty filter file".into()));
        }
        Some(s.to_string())
    } else {
        args.filter.clone()
    };

    let program = if let Some(expr) = &filter_expr {
        let ast = parse(expr).map_err(|e| NetdumpError::Parse(e.to_string()))?;
        let prog = compile(&ast);
        if args.dump_bpf {
            eprintln!("CBPF program ({} instructions):", prog.len());
            for (i, inst) in prog.iter().enumerate() {
                eprintln!("  {i}: {inst:?}");
            }
            return Ok(());
        }
        Some(prog)
    } else {
        if args.dump_bpf {
            return Err(NetdumpError::Parse("no filter expression to dump".into()));
        }
        None
    };

    let mut pcap_writer = if let Some(path) = &args.write {
        let file = File::create(path).map_err(|e| NetdumpError::Io(e.to_string()))?;
        let header = PcapHeader {
            datalink: DataLink::ETHERNET,
            ..PcapHeader::default()
        };
        let writer =
            PcapWriter::with_header(file, header).map_err(|e| NetdumpError::Io(e.to_string()))?;
        Some(writer)
    } else {
        None
    };

    let mut captured = 0usize;

    let mut pkt_ctx = PktCtx {
        num: 0,
        prev_ts: (0, 0),
        first_ts: (0, 0),
    };

    if let Some(path) = &args.read {
        let file = File::open(path).map_err(|e| NetdumpError::Io(e.to_string()))?;
        let mut reader = PcapReader::new(file).map_err(|e| NetdumpError::Io(e.to_string()))?;

        loop {
            if let Some(max) = args.count
                && captured >= max
            {
                break;
            }

            let pkt = match reader.next_packet() {
                None => break,
                Some(Ok(p)) => p,
                Some(Err(e)) => return Err(NetdumpError::Io(e.to_string())),
            };

            let matched = program
                .as_ref()
                .is_none_or(|prog| Vm::exec(prog, &pkt.data));
            if !matched {
                continue;
            }
            captured += 1;
            pkt_ctx.num += 1;

            if let Some(writer) = pcap_writer.as_mut() {
                writer
                    .write_packet(&pkt)
                    .map_err(|e| NetdumpError::Io(e.to_string()))?;
                if args.print {
                    let p = pcap_packet_to_packet(&pkt, 0);
                    pkt_ctx.first_ts = (p.meta.ts_sec as i64, p.meta.ts_usec);
                    print_packet(&p, &args, &mut pkt_ctx);
                }
            } else {
                let p = pcap_packet_to_packet(&pkt, 0);
                pkt_ctx.first_ts = (p.meta.ts_sec as i64, p.meta.ts_usec);
                print_packet(&p, &args, &mut pkt_ctx);
            }
        }
    } else {
        let ifname = match &args.interface {
            Some(name) => name.clone(),
            None => netdump_afpacket::default_interface()?,
        };

        let snaplen = if args.snaplen == 0 {
            65535
        } else {
            args.snaplen as usize
        };
        let options = OpenOptions {
            snaplen,
            promiscuous: !args.no_promiscuous,
            buffer_size: args.buffer_size,
            block_size: (args.block_size_kib as usize)
                .checked_mul(1024)
                .unwrap_or(1 << 20),
            block_nr: args.block_nr as usize,
            frame_size: Some(args.frame_size as usize),
            retire_tov_ms: Some(args.retire_tov_ms),
        };
        let mut socket = AfPacketSocket::open_with_options(&ifname, options)?;

        // -Q: 获取接口 MAC 地址用于方向判断
        let iface_mac = if args.direction.is_some() {
            Some(get_iface_mac(&ifname)?)
        } else {
            None
        };

        let mut kernel_attached = false;
        if let Some(prog) = program.as_ref()
            && !args.userspace_filter
        {
            let raw: Vec<RawBpfInsn> = prog.iter().map(|i| RawBpfInsn::from(*i)).collect();
            socket.attach_filter(&raw)?;
            kernel_attached = true;
        }

        loop {
            if let Some(max) = args.count
                && captured >= max
            {
                break;
            }

            let packet = socket.next_packet()?;
            let data = &packet.data;

            let matched =
                kernel_attached || program.as_ref().is_none_or(|prog| Vm::exec(prog, data));
            if !matched {
                continue;
            }

            // -Q: 方向过滤
            if let Some(ref dir) = args.direction
                && let Some(ref mac) = iface_mac
                && data.len() >= 14
            {
                let src_mac = &data[6..12];
                let outgoing = src_mac == mac.as_slice();
                match dir.as_str() {
                    "in" if outgoing => continue,
                    "out" if !outgoing => continue,
                    _ => {}
                }
            }

            captured += 1;
            pkt_ctx.num += 1;

            if let Some(writer) = pcap_writer.as_mut() {
                let ts = Duration::new(packet.meta.ts_sec, (packet.meta.ts_usec * 1000) as u32);
                let pkt = PcapPacket::new(ts, packet.meta.orig_len as u32, data);
                writer
                    .write_packet(&pkt)
                    .map_err(|e| NetdumpError::Io(e.to_string()))?;
                if args.print {
                    if pkt_ctx.num == 1 {
                        pkt_ctx.first_ts = (packet.meta.ts_sec as i64, packet.meta.ts_usec);
                    }
                    print_packet(&packet, &args, &mut pkt_ctx);
                }
            } else {
                if pkt_ctx.num == 1 {
                    pkt_ctx.first_ts = (packet.meta.ts_sec as i64, packet.meta.ts_usec);
                }
                print_packet(&packet, &args, &mut pkt_ctx);
            }
        }
    }

    eprintln!("captured {captured} packets");
    Ok(())
}

fn pcap_packet_to_packet(pkt: &PcapPacket, ifindex: i32) -> Packet {
    let ts = pkt.timestamp;
    let meta = PacketMeta::new(
        ts.as_secs(),
        ts.subsec_micros() as u64,
        ifindex,
        pkt.data.len(),
        pkt.orig_len as usize,
    );
    Packet::new(meta, pkt.data.to_vec())
}

fn print_packet(packet: &Packet, args: &Args, ctx: &mut PktCtx) {
    let meta = &packet.meta;
    let data = &packet.data;

    // 时间戳格式化
    let ts = match args.timestamp_format {
        1 => String::new(),              // -t: 不打印时间戳
        2 => format!("{}", meta.ts_sec), // -tt: Unix 秒
        3 => {
            // -ttt: 增量
            let delta = (meta.ts_sec as i64 - ctx.prev_ts.0) * 1_000_000
                + (meta.ts_usec as i64 - ctx.prev_ts.1 as i64);
            ctx.prev_ts = (meta.ts_sec as i64, meta.ts_usec);
            format!("{:03}.{:06}", delta / 1_000_000, delta.abs() % 1_000_000)
        }
        4 => {
            // -tttt: 含日期
            let ts_secs = meta.ts_sec as i64;
            let days = ts_secs.div_euclid(86400);
            let rem = ts_secs.rem_euclid(86400);
            let h = rem / 3600;
            let m = (rem / 60) % 60;
            let s = rem % 60;
            let (y, mon, day) = epoch_days_to_date(days);
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                y, mon, day, h, m, s, meta.ts_usec
            )
        }
        5 => {
            // -ttttt: 自首包增量
            let delta = (meta.ts_sec as i64 - ctx.first_ts.0) * 1_000_000
                + (meta.ts_usec as i64 - ctx.first_ts.1 as i64);
            format!("{:03}.{:06}", delta / 1_000_000, delta.abs() % 1_000_000)
        }
        _ => format!(
            // 默认
            "{:02}:{:02}:{:02}.{:06}",
            (meta.ts_sec / 3600) % 24,
            (meta.ts_sec / 60) % 60,
            meta.ts_sec % 60,
            meta.ts_usec
        ),
    };

    // 更新 prev_ts 用于 -ttt
    if args.timestamp_format != 3 {
        ctx.prev_ts = (meta.ts_sec as i64, meta.ts_usec);
    }

    // 包序号
    let num_prefix = if args.packet_number {
        format!("{:>4}  ", ctx.num)
    } else {
        String::new()
    };

    if args.quiet {
        let line = if let Some(info) = parse_packet(data) {
            let proto = protocol_name(info.protocol.unwrap_or(0), args.no_resolve >= 2);
            let src = format_addr(&info.src_ip, info.src_port, args.no_resolve >= 1);
            let dst = format_addr(&info.dst_ip, info.dst_port, args.no_resolve >= 1);
            if ts.is_empty() {
                format!("{num_prefix}{proto} {src} > {dst} len={}", meta.cap_len)
            } else {
                format!(
                    "{num_prefix}{ts} {proto} {src} > {dst} len={}",
                    meta.cap_len
                )
            }
        } else {
            format!("{num_prefix}{ts} [unknown] len={}", meta.cap_len)
        };
        println!("{line}");
        return;
    }

    let mut parts: Vec<String> = Vec::new();

    // 时间戳 + 包序号
    if !ts.is_empty() {
        parts.push(format!("{num_prefix}{ts}"));
    } else if args.packet_number {
        parts.push(num_prefix.trim().to_string());
    }

    if args.link_header && data.len() >= 14 {
        let src = format_mac(&data[6..12]);
        let dst = format_mac(&data[0..6]);
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        parts.push(format!("{src} > {dst} ethertype {ethertype:#06x}"));
    }

    if let Some(info) = parse_packet(data) {
        let proto = protocol_name(info.protocol.unwrap_or(0), args.no_resolve >= 2);
        let src = format_addr(&info.src_ip, info.src_port, args.no_resolve >= 1);
        let dst = format_addr(&info.dst_ip, info.dst_port, args.no_resolve >= 1);
        let mut line = format!("{src} > {dst} {proto}");

        if args.verbose > 0 {
            let mut details = Vec::new();
            if data.len() >= 14 {
                match info.ethertype {
                    Some(0x0800) if data.len() >= 14 + 20 => {
                        let ihl = (data[14] & 0x0f) as usize * 4;
                        if data.len() >= 14 + ihl {
                            details.push(format!("ttl {}", data[14 + 8]));
                            let id = u16::from_be_bytes([data[14 + 4], data[14 + 5]]);
                            let off = u16::from_be_bytes([data[14 + 6], data[14 + 7]]) & 0x1fff;
                            let mf = (data[14 + 6] & 0x20) != 0;
                            details.push(format!(
                                "id {id},offset {off},{}",
                                if mf { "+" } else { "" }
                            ));
                        }
                    }
                    Some(0x86dd) if data.len() >= 14 + 40 => {
                        details.push(format!("hlim {}", data[14 + 7]));
                    }
                    _ => {}
                }

                if info.protocol == Some(6) && data.len() >= 14 + 20 {
                    let ip_header_len = if info.ethertype == Some(0x0800) {
                        (data[14] & 0x0f) as usize * 4
                    } else {
                        40
                    };
                    let tcp_start = 14 + ip_header_len;
                    if data.len() >= tcp_start + 20 {
                        let flags = data[tcp_start + 13];
                        details.push(format_tcp_flags(flags));
                        let seq = u32::from_be_bytes([
                            data[tcp_start + 4],
                            data[tcp_start + 5],
                            data[tcp_start + 6],
                            data[tcp_start + 7],
                        ]);
                        let ack = u32::from_be_bytes([
                            data[tcp_start + 8],
                            data[tcp_start + 9],
                            data[tcp_start + 10],
                            data[tcp_start + 11],
                        ]);
                        let win = u16::from_be_bytes([data[tcp_start + 14], data[tcp_start + 15]]);
                        details.push(format!("seq {seq} ack {ack} win {win}"));
                    }
                }
            }
            if !details.is_empty() {
                line.push(' ');
                line.push_str(&details.join(" "));
            }
        }

        parts.push(line);
        parts.push(format!("len={}", meta.cap_len));
    } else {
        parts.push("[unknown]".into());
        parts.push(format!("len={}", meta.cap_len));
    }

    println!("{}", parts.join(" "));

    // -x / -X 十六进制输出
    let hex_level = args.hex;
    let hex_ascii_level = args.hex_ascii;
    if hex_level > 0 || hex_ascii_level > 0 {
        // -xx / -XX 包含链路层头
        let do_hex = |payload: &[u8]| {
            if hex_level > 0 {
                print!("{}", format_hex(payload));
            }
            if hex_ascii_level > 0 {
                print!("{}", format_hex_ascii(payload));
            }
        };
        if hex_level >= 2 || hex_ascii_level >= 2 {
            // -xx / -XX: 包含链路层头
            do_hex(data);
        } else if let Some(payload) = data.get(14..) {
            // -x / -X: 跳过链路层头
            do_hex(payload);
        }
    }

    // -A ASCII 输出（与 -X 互斥，仅在未使用 -X 时输出）
    if args.ascii
        && hex_ascii_level == 0
        && let Some(payload) = data.get(14..)
        && !payload.is_empty()
    {
        println!("{}", format_ascii(payload));
    }

    // -l: 行缓冲（抓包输出立即刷新）
    if args.line_buffered {
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
}

fn format_ascii(payload: &[u8]) -> String {
    payload
        .chunks(64)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Hex dump output, same format as tcpdump -x (16 bytes per line).
fn format_hex(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("    {:04x}: ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x}"));
            if j == 7 {
                out.push_str("  ");
            } else if j < 15 {
                out.push(' ');
            }
        }
        if chunk.len() < 16 {
            let remaining = 16 - chunk.len();
            let space = if chunk.len() <= 7 { 1 } else { 0 };
            for _ in 0..remaining {
                out.push_str("   ");
            }
            if space != 0 {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out
}

/// Hex dump with ASCII side-by-side, same format as tcpdump -X.
fn format_hex_ascii(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("    {:04x}: ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x}"));
            if j == 7 {
                out.push_str("  ");
            } else if j < 15 {
                out.push(' ');
            }
        }
        if chunk.len() < 16 {
            let remaining = 16 - chunk.len();
            for _ in 0..remaining {
                out.push_str("   ");
            }
        }
        out.push_str("  ");
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' {
                out.push(*b as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
    out
}

fn format_mac(mac: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_addr(ip: &Option<IpAddr>, port: Option<u16>, numeric: bool) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => {
            if numeric {
                format!("{ip}:{port}")
            } else {
                format!("{ip}.{}", port_name(port))
            }
        }
        (Some(ip), None) => ip.to_string(),
        _ => "?".to_string(),
    }
}

fn port_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        993 => "imaps",
        995 => "pop3s",
        8080 => "http-alt",
        _ => "",
    }
}

fn protocol_name(proto: u8, numeric: bool) -> String {
    if numeric {
        return proto.to_string();
    }
    match proto {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        58 => "icmp6".to_string(),
        _ => proto.to_string(),
    }
}

fn format_tcp_flags(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 {
        s.push('F');
    }
    if flags & 0x02 != 0 {
        s.push('S');
    }
    if flags & 0x04 != 0 {
        s.push('R');
    }
    if flags & 0x08 != 0 {
        s.push('P');
    }
    if flags & 0x10 != 0 {
        s.push('.');
    }
    if flags & 0x20 != 0 {
        s.push('U');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_date(days: i64) -> (i64, u32, u32) {
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let diy = if is_leap(y) { 366 } else { 365 };
        if d < diy {
            break;
        }
        d -= diy;
        y += 1;
    }
    let month_days: &[u32] = if is_leap(y) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0u32;
    for &md in month_days {
        if d < md as i64 {
            break;
        }
        d -= md as i64;
        m += 1;
    }
    (y, m + 1, (d + 1) as u32)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Get the MAC address of an interface via SIOCGIFHWADDR.
fn get_iface_mac(ifname: &str) -> Result<[u8; 6], NetdumpError> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(NetdumpError::Io(format!(
            "socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = ifname.as_bytes();
    let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in name_bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as i8;
    }

    let r = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    unsafe { libc::close(fd) };

    if r < 0 {
        return Err(NetdumpError::Io(format!(
            "ioctl SIOCGIFHWADDR: {}",
            std::io::Error::last_os_error()
        )));
    }

    // sa_data 的前 6 字节即 MAC 地址
    let mut mac = [0u8; 6];
    let sa_data = unsafe { &ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (i, b) in mac.iter_mut().enumerate() {
        *b = sa_data[i] as u8;
    }
    Ok(mac)
}
