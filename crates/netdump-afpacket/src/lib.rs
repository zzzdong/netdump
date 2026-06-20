//! netdump-afpacket: AF_PACKET + TPACKET_V3 zero-copy ring buffer packet capture engine.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::c_int;
use netdump_core::{NetdumpError, Packet, PacketMeta};

/// Returns ETH_P_ALL in network byte order.
fn eth_p_all() -> u16 {
    (libc::ETH_P_ALL as u16).to_be()
}

/// Default ring buffer configuration.
const DEFAULT_BLOCK_SIZE: usize = 1 << 20; // 1 MiB
const DEFAULT_BLOCK_NR: usize = 64;
const DEFAULT_FRAME_SIZE: usize = 2048;
const DEFAULT_RETIRE_TOV_MS: u32 = 100; // retire empty blocks quickly for observability
const POLL_TIMEOUT_MS: i32 = 100;

/// AF_PACKET socket open options.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// Maximum capture length, 0 means default.
    pub snaplen: usize,
    /// Whether to enable promiscuous mode.
    pub promiscuous: bool,
    /// Ring buffer block size (bytes).
    pub block_size: usize,
    /// Number of ring buffer blocks.
    pub block_nr: usize,
    /// Kernel socket receive buffer size (KiB), None uses system default.
    pub buffer_size: Option<u32>,
    /// Frame size (bytes), None derives from snaplen automatically.
    pub frame_size: Option<usize>,
    /// Block retire timeout (milliseconds), None uses default.
    pub retire_tov_ms: Option<u32>,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            snaplen: 65535,
            promiscuous: true,
            block_size: DEFAULT_BLOCK_SIZE,
            block_nr: DEFAULT_BLOCK_NR,
            buffer_size: None,
            frame_size: None,
            retire_tov_ms: None,
        }
    }
}

/// TPACKET_V3 ring buffer capture socket.
pub struct AfPacketSocket {
    fd: OwnedFd,
    ifindex: i32,
    ring: *mut u8,
    ring_size: usize,
    block_size: usize,
    block_nr: usize,
    current_block: usize,
    cursor: Option<BlockCursor>,
}

/// Cursor tracking position within the current block.
struct BlockCursor {
    base: *mut u8,
    num_pkts: u32,
    seen: u32,
    next_offset: u32,
}

impl AfPacketSocket {
    /// Open an AF_PACKET TPACKET_V3 capture socket with default options.
    pub fn open(ifname: &str) -> Result<Self, NetdumpError> {
        Self::open_with_options(ifname, OpenOptions::default())
    }

    /// Open an AF_PACKET TPACKET_V3 capture socket with custom options.
    ///
    /// The special interface name `any` listens on all interfaces (ifindex 0),
    /// and interface-level promiscuous mode is not set in that case.
    pub fn open_with_options(ifname: &str, options: OpenOptions) -> Result<Self, NetdumpError> {
        let (ifindex, is_any) = if ifname == "any" {
            (0, true)
        } else {
            (ifname_to_index(ifname)?, false)
        };

        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all() as c_int) };
        if fd < 0 {
            return Err(NetdumpError::Io(format!(
                "socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        set_non_blocking(fd.as_raw_fd())?;

        if let Some(buf_kib) = options.buffer_size {
            let buf_bytes: i32 = (buf_kib as i32).checked_mul(1024).unwrap_or(i32::MAX);
            let r = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &buf_bytes as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&buf_bytes) as libc::socklen_t,
                )
            };
            if r < 0 {
                return Err(NetdumpError::Io(format!(
                    "setsockopt SO_RCVBUF: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        if options.promiscuous && !is_any {
            set_promiscuous(fd.as_raw_fd(), ifname)?;
        }

        // 启用 TPACKET_V3。
        let version = libc::tpacket_versions::TPACKET_V3 as c_int;
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                std::mem::size_of_val(&version) as libc::socklen_t,
            )
        };
        if r < 0 {
            let err = std::io::Error::last_os_error();
            let hint = if cfg!(target_os = "linux") {
                " (TPACKET_V3 requires Linux >= 3.2)"
            } else {
                ""
            };
            return Err(NetdumpError::Io(format!(
                "setsockopt PACKET_VERSION:{}{}",
                err, hint
            )));
        }

        // 先 bind 接口，再设置 RX_RING，顺序与 babyshark / 内核文档一致。
        bind_to_interface(fd.as_raw_fd(), ifindex)?;

        let page_size = page_size();
        // 帧大小需要是 2 的幂，并且整除块大小，否则内核会返回 EINVAL。
        let frame_size = options
            .frame_size
            .unwrap_or(DEFAULT_FRAME_SIZE)
            .max(options.snaplen + 256)
            .next_power_of_two();
        let block_size = align_to(std::cmp::max(options.block_size, frame_size), page_size);
        let block_nr = options.block_nr;
        let ring_size = block_size * block_nr;
        let retire_tov = options.retire_tov_ms.unwrap_or(DEFAULT_RETIRE_TOV_MS);

        let req = libc::tpacket_req3 {
            tp_block_size: block_size as libc::c_uint,
            tp_block_nr: block_nr as libc::c_uint,
            tp_frame_size: frame_size as libc::c_uint,
            tp_frame_nr: (ring_size / frame_size) as libc::c_uint,
            tp_retire_blk_tov: retire_tov,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                std::mem::size_of_val(&req) as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(NetdumpError::Io(format!(
                "setsockopt PACKET_RX_RING: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(NetdumpError::Io(format!(
                "mmap: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            fd,
            ifindex,
            ring: ring as *mut u8,
            ring_size,
            block_size,
            block_nr,
            current_block: 0,
            cursor: None,
        })
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Read the next packet from the ring buffer (copies data to user space).
    pub fn next_packet(&mut self) -> Result<Packet, NetdumpError> {
        loop {
            if let Some(cursor) = self.cursor.as_mut() {
                if cursor.seen < cursor.num_pkts {
                    let frame = unsafe {
                        &*(cursor.base.add(cursor.next_offset as usize)
                            as *const libc::tpacket3_hdr)
                    };

                    let snap_len = frame.tp_snaplen as usize;
                    let pkt_start = cursor.next_offset as usize + frame.tp_mac as usize;
                    let data =
                        unsafe { std::slice::from_raw_parts(cursor.base.add(pkt_start), snap_len) };

                    let packet = build_packet(
                        data,
                        frame.tp_sec as u64,
                        frame.tp_nsec as u64,
                        self.ifindex,
                    );

                    cursor.seen += 1;
                    cursor.next_offset += frame.tp_next_offset;
                    return Ok(packet);
                }

                // 当前块已处理完，归还给内核。
                unsafe {
                    let desc = &mut *(cursor.base as *mut libc::tpacket_block_desc);
                    core::ptr::addr_of_mut!(desc.hdr.bh1.block_status)
                        .write_volatile(libc::TP_STATUS_KERNEL);
                }
                self.cursor = None;
                self.current_block = (self.current_block + 1) % self.block_nr;
            }

            self.wait_for_block()?;

            let base = unsafe { self.ring.add(self.current_block * self.block_size) };
            let h1 = unsafe { &(*(base as *const libc::tpacket_block_desc)).hdr.bh1 };
            self.cursor = Some(BlockCursor {
                base,
                num_pkts: h1.num_pkts,
                seen: 0,
                next_offset: h1.offset_to_first_pkt,
            });
        }
    }

    fn wait_for_block(&self) -> Result<(), NetdumpError> {
        let base = unsafe { self.ring.add(self.current_block * self.block_size) };
        let desc = base as *const libc::tpacket_block_desc;

        loop {
            let status =
                unsafe { core::ptr::addr_of!((*desc).hdr.bh1.block_status).read_volatile() };
            if status & libc::TP_STATUS_USER != 0 {
                return Ok(());
            }
            self.poll()?;
        }
    }

    fn poll(&self) -> Result<(), NetdumpError> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
        if r < 0 {
            Err(NetdumpError::Io(format!(
                "poll: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    /// 读取内核统计，调用后会重置计数器。
    pub fn statistics(&self) -> Result<PacketStats, NetdumpError> {
        let mut stats: libc::tpacket_stats_v3 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 {
            Err(NetdumpError::Io(format!(
                "getsockopt PACKET_STATISTICS: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(PacketStats {
                packets: stats.tp_packets,
                drops: stats.tp_drops,
            })
        }
    }

    /// Attach a BPF program to the socket (kernel-side filtering).
    pub fn attach_filter(&self, program: &[RawBpfInsn]) -> Result<(), NetdumpError> {
        if program.is_empty() {
            return Ok(());
        }

        let fprog = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr() as *mut libc::sock_filter,
        };

        let r = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                std::mem::size_of_val(&fprog) as libc::socklen_t,
            )
        };
        if r < 0 {
            Err(NetdumpError::Io(format!(
                "setsockopt SO_ATTACH_FILTER: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }
}

impl Drop for AfPacketSocket {
    fn drop(&mut self) {
        if !self.ring.is_null() {
            unsafe {
                libc::munmap(self.ring as *mut libc::c_void, self.ring_size);
            }
        }
        // fd 由 OwnedFd 负责关闭。
    }
}

// Safety: AfPacketSocket 中的所有裸指针访问都通过 &mut self 进行，
// 没有内部可变性或共享可变状态。OwnedFd 是 Send + Sync。
// 只要不同时在多个线程中调用 &mut self 方法，就是安全的。
unsafe impl Send for AfPacketSocket {}
unsafe impl Sync for AfPacketSocket {}

fn build_packet(data: &[u8], sec: u64, nsec: u64, ifindex: i32) -> Packet {
    let usec = nsec / 1000;
    let meta = PacketMeta::new(sec, usec, ifindex, data.len(), data.len());
    Packet::new(meta, data.to_vec())
}

fn ifname_to_index(name: &str) -> Result<i32, NetdumpError> {
    let cname = CString::new(name).map_err(|e| NetdumpError::Io(e.to_string()))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(NetdumpError::Io(format!(
            "if_nametoindex({name}): {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(idx as i32)
    }
}

fn bind_to_interface(fd: RawFd, ifindex: i32) -> Result<(), NetdumpError> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = eth_p_all();
    addr.sll_ifindex = ifindex;

    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(NetdumpError::Io(format!(
            "bind: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn set_non_blocking(fd: RawFd) -> Result<(), NetdumpError> {
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    if r < 0 {
        Err(NetdumpError::Io(format!(
            "fcntl O_NONBLOCK: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn set_promiscuous(fd: RawFd, ifname: &str) -> Result<(), NetdumpError> {
    if ifname.len() >= libc::IFNAMSIZ {
        return Err(NetdumpError::Io("interface name too long".into()));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            ifname.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast(),
            ifname.len(),
        );

        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            return Err(NetdumpError::Io(format!(
                "ioctl SIOCGIFFLAGS: {}",
                std::io::Error::last_os_error()
            )));
        }

        ifr.ifr_ifru.ifru_flags |= libc::IFF_PROMISC as i16;

        if libc::ioctl(fd, libc::SIOCSIFFLAGS, &mut ifr) < 0 {
            return Err(NetdumpError::Io(format!(
                "ioctl SIOCSIFFLAGS: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// A raw BPF instruction compatible with `libc::sock_filter` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawBpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl From<RawBpfInsn> for libc::sock_filter {
    fn from(insn: RawBpfInsn) -> Self {
        libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        }
    }
}

#[cfg(feature = "netdump-filter")]
impl From<netdump_filter::Instruction> for RawBpfInsn {
    fn from(i: netdump_filter::Instruction) -> Self {
        Self {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        }
    }
}

/// Kernel statistics: number of received and dropped packets.
#[derive(Debug, Clone, Copy)]
pub struct PacketStats {
    pub packets: u32,
    pub drops: u32,
}

/// Network interface information.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ifindex: i32,
    pub is_up: bool,
}

/// List all network interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, NetdumpError> {
    let mut ifaces = Vec::new();
    let mut seen = HashSet::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) < 0 {
            return Err(NetdumpError::Io(format!(
                "getifaddrs: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let name = CStr::from_ptr((*cur).ifa_name)
                .to_string_lossy()
                .into_owned();
            if seen.insert(name.clone()) {
                let idx = libc::if_nametoindex((*cur).ifa_name) as i32;
                let flags = (*cur).ifa_flags as u32;
                let is_up =
                    flags & (libc::IFF_UP as u32) != 0 && flags & (libc::IFF_LOOPBACK as u32) == 0;
                ifaces.push(InterfaceInfo {
                    name,
                    ifindex: idx,
                    is_up,
                });
            }
            cur = (*cur).ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    ifaces.sort_by_key(|x| x.ifindex);
    Ok(ifaces)
}

/// Select a default interface: the lowest-index UP non-loopback interface.
pub fn default_interface() -> Result<String, NetdumpError> {
    list_interfaces()?
        .into_iter()
        .find(|info| info.is_up)
        .map(|info| info.name)
        .ok_or_else(|| NetdumpError::Io("no suitable interface found".into()))
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize }
}

fn align_to(value: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_to_index_loopback_ok() {
        let idx = ifname_to_index("lo").expect("loopback index");
        assert!(idx > 0);
    }

    #[test]
    fn ifname_to_index_nonexistent_fails() {
        assert!(ifname_to_index("netdump-dummy0").is_err());
    }

    #[test]
    fn open_loopback_result() {
        // 未具备 CAP_NET_RAW 时通常会失败，具备权限时则能成功。
        let _ = AfPacketSocket::open("lo");
    }
}
