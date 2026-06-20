# netdump

A simple tcpdump clone written in Rust — powered by AF_PACKET + TPACKET_V3 zero-copy capture.

## Features

- **Zero-copy packet capture** via TPACKET_V3 ring buffer on Linux
- **pcap-filter expression** parser and CBPF compiler (supports host, net, port, protocol filtering with and/or/not)
- **CBPF virtual machine** for both kernel-attached and userspace filtering
- **pcap save/read** with `-w` / `-r`
- Timestamp formats (`-t` / `-tt` / `-ttt` / `-tttt` / `-ttttt`)
- Hex dump output (`-x` / `-X`)
- Direction filtering (`-Q in|out|inout`)
- Configurable ring buffer (`--block-size` / `--block-nr` / `--frame-size` / `--retire-tov`)
- Line buffered output (`-l`) for piping

## Installation

### From crates.io

```bash
cargo install netdump
```

### From source

```bash
git clone https://github.com/zzzdong/netdump.git
cd netdump
cargo build --release
sudo ./target/release/netdump -i eth0
```

> **Note**: packet capture requires root privileges or `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

## Usage

```bash
# Capture all packets on interface eth0
sudo netdump -i eth0

# Capture with BPF filter
sudo netdump -i eth0 -v tcp port 80

# Save to pcap file
sudo netdump -i eth0 -w capture.pcap

# Read from pcap file
netdump -r capture.pcap

# Hex dump output
sudo netdump -i any -x 'icmp'

# Direction filtering
sudo netdump -i eth0 -Q out

# List available interfaces
sudo netdump -D
```

See `netdump --help` for the full list of options.

## Project Structure

| Crate | Description |
|-------|-------------|
| `netdump-core` | Core types, packet metadata, protocol parsing |
| `netdump-filter` | pcap-filter expression parser and CBPF compiler |
| `netdump-cbpf` | CBPF (classic BPF) virtual machine |
| `netdump-afpacket` | AF_PACKET + TPACKET_V3 capture engine (Linux only) |
| `netdump` | Command-line interface |

## License

MIT