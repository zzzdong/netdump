# 架构设计

## 总览

netdump 是一个模块化的 tcpdump 克隆，按职责拆分为 5 个 crate，依赖关系如下：

```
┌─────────────────────────────────────────────────┐
│                    netdump                       │
│  (CLI: clap args -> 编排抓包->打印/保存)         │
└──────────────────────┬──────────────────────────┘
          │                    │              │
          ▼                    ▼              ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ netdump-afpacket │  │  netdump-cbpf   │  │  netdump-filter  │
│ (AF_PACKET +     │  │ (CBPF 虚拟机,   │  │ (pcap-filter     │
│  TPACKET_V3      │  │  执行过滤指令)  │  │  解析器+编译器)  │
│  零拷贝抓包)     │  └────────┬────────┘  └────────┬─────────┘
└────────┬─────────┘           │                     │
         │                     │                     │
         └──────────┬──────────┘────────────────────┘
                    ▼
          ┌─────────────────┐
          │  netdump-core   │
          │ (PacketMeta,    │
          │  NetdumpError,  │
          │  协议解析)       │
          └─────────────────┘
```

## Crate 职责

### netdump-core — 核心类型和协议解析

**依赖**: `etherparse`

提供所有 crate 共享的基础类型：

- `Packet` / `PacketMeta` — 包的元数据和原始数据
- `NetdumpError` — 统一错误类型
- 基于 `etherparse` 的协议头部解析（Ethernet / IP / TCP / UDP / ICMP）

### netdump-filter — pcap-filter 解析器 + CBPF 编译器

**依赖**: `netdump-core`, `pest`

两个阶段：

1. **解析 (parse)**: 使用 `pest` PEG 文法（`filter.pest`）将 pcap-filter 表达式解析为 AST（`ast::Expr`）
2. **编译 (compile)**: 遍历 AST 生成 CBPF 字节码（`Vec<cbpf::Insn>`）
   - 根据谓词类型（host/net/port/protocol）生成不同的 CBPF 指令序列
   - 子网掩码推断（根据 IP 地址分类自动确定）

AST 类型定义在 `types.rs`，包含谓词、原语、逻辑组合等节点。

> 注意：本 crate 只负责编译到 CBPF，不执行过滤，也不依赖 `netdump-cbpf`

### netdump-cbpf — CBPF 虚拟机

**依赖**: `netdump-core`, `netdump-filter`

提供 CBPF 指令的直接执行能力：

- `Vm::exec(program, data)` — 在用户态执行 CBPF 指令序列，返回 true/false
- 当内核 BPF 不可用（或指定 `--userspace-filter`）时使用

### netdump-afpacket — 抓包引擎

**依赖**: `netdump-core`, `libc`

Linux 专属的 AF_PACKET + TPACKET_V3 零拷贝抓包实现：

```
┌─────────────────────────────────────┐
│           userspace                 │
│  ┌─────────────────────────────┐    │
│  │   mmap region (ring buffer) │    │
│  │   ┌──────┬──────┬──────┐   │    │
│  │   │blk 0 │blk 1 │ ...  │   │    │
│  │   └──────┴──────┴──────┘   │    │
│  └─────────────────────────────┘    │
│         ▲           ▲              │
│         │  mmap     │ poll         │
├─────────┼───────────┼──────────────┤
│         │  kernel                   │
│  ┌──────┴───────────┴─────────┐    │
│  │    AF_PACKET socket         │    │
│  │    + TPACKET_V3 ring        │    │
│  │    + sk_filter (BPF)        │    │
│  └─────────────────────────────┘    │
│         ▲                           │
│         │ netif_receive_skb()       │
│    ┌────┴────┐                      │
│    │ NIC     │                      │
│    └─────────┘                      │
└─────────────────────────────────────┘
```

关键流程：
1. `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` — 创建原始套接字
2. `setsockopt(PACKET_VERSION, TPACKET_V3)` — 启用 V3
3. `bind()` — 绑定到接口
4. `setsockopt(PACKET_RX_RING, tpacket_req3)` — 配置环形缓冲区
5. `mmap()` — 映射共享内存
6. 可选 `setsockopt(SO_ATTACH_FILTER, bpf_prog)` — 内核 BPF 过滤
7. `poll()` → 读取 ring block → 逐个帧交付

配置参数通过 `OpenOptions` 控制：block_size、block_nr、frame_size、retire_tov_ms、buffer_size (SO_RCVBUF)。

### netdump — 命令行界面

**依赖**: 全部其他 crate, `clap`, `pcap-file`, `libc`

包名 `netdump`，二进制名 `netdump`。

主要函数 `run()` 的流程：

```
Args::parse()
    │
    ├── ─D → list_interfaces() → 出口
    ├── ─d → 编译过滤器 → dump BPF bytecode → 出口
    │
    └── 抓包 / 读包
         │
         ├── 读包 (-r)
         │   ├── pcap_file::Reader → 逐包读取
         │   ├── 可选: 用户态 CBPF 过滤
         │   └── 写入 pcap 或 print_packet()
         │
         └── 抓包 (-i)
             ├── AfPacketSocket::open_with_options()
             ├── 可选: socket.attach_filter() (内核 BPF)
             ├── 可选: -Q 方向过滤 (MAC 对比)
             ├── 逐包 poll → next_packet()
             ├── 可选: 用户态 CBPF 过滤
             └── 写入 pcap 或 print_packet()
```

`print_packet()` 负责格式化输出，支持：
- `-e` 链路层头部
- `-v` / `-vv` / `-vvv` 详细级别
- `-n` / `-nn` 名称解析控制
- `-t` / `-tt` / `-ttt` / `-tttt` / `-ttttt` 时间戳格式
- `-x` / `-X` 十六进制 + ASCII
- `-A` ASCII 输出
- `-#` 包序号
- `-q` 安静模式
- `-S` 绝对 TCP 序列号
- `-l` 行缓冲

## 数据流

```
网卡报文
    │
    ▼
[内核: AF_PACKET + sk_filter(BPF)]
    │ (命中则进入 ring buffer)
    ▼
[netdump-afpacket: poll → 读帧]
    │
    ▼
[netdump-core: Packet / PacketMeta]
    │
    ├─ 可选: [netdump-cbpf: Vm::exec() 二次过滤]
    │
    ├─ 可选: [-Q 方向过滤 (MAC 地址对比)]
    │
    ├─ [-w]: [pcap-file 写入]
    │
    └─ [print_packet() 格式化输出]
         ├─ 协议解析 (etherparse)
         ├─ 时间戳处理
         └─ 终端打印
```

## 关键设计决策

### 1. 为什么用 CBPF 而非 eBPF？

| | CBPF (classic BPF) | eBPF |
|--|-------------------|------|
| 内核支持 | 所有 Linux 版本 | Linux 3.18+ |
| 接口 | `SO_ATTACH_FILTER` | `SO_ATTACH_BPF` |
| 指令集 | 4 字节定长，最多 4096 条 | 8 字节定长，可附加 map/helper |
| 适用场景 | 包过滤 | 包过滤、跟踪、性能监控 |

CBPF 对包过滤已经足够。eBPF 的额外能力（map、helper 调用）在流量过滤场景用不上，反而增加了编译器和运行时的复杂度。Linux 内核将 CBPF 字节码透明地转为 eBPF 执行，所以 **`attach_filter()` 实际跑的是 eBPF**，但接口保持 CBPF 兼容。

### 2. 为什么要自研过滤器而非调用 libpcap？

| 对比 | 自研 | libpcap |
|------|------|---------|
| 依赖 | 无（仅 pest + 自研编译器） | C 库绑定 + pcap ABI 兼容 |
| filter 语法 | 覆盖 pcap-filter 子集 | 完整 pcap-filter |
| 可移植性 | 纯 Rust，跨平台编译 | 需 libpcap 安装和 C 绑定 |
| 安全性 | 类型安全 + 内存安全 | C 库潜在内存问题 |
| 编译目标 | CBPF 字节码 | CBPF / eBPF |

自研的核心动机是**纯 Rust 实现、零 C 依赖**。这样用户只需 `cargo install netdump`，不需要系统中预先安装 libpcap 及其头文件。

### 3. 为什么只支持 Linux？

网络抓包严重依赖操作系统 API：

| 平台 | 零拷贝接口 | 实现状态 |
|------|-----------|---------|
| Linux | AF_PACKET + TPACKET_V3 | ✅ 已实现 |
| macOS/Darwin | BPF (/dev/bpf*) | ❌ 未实现 |
| Windows | Npcap/WinPcap | ❌ 未实现 |
| FreeBSD | BPF (zero-copy) | ❌ 未实现 |

未来可以抽象 `CaptureEngine` trait，为各平台分别实现，但目前聚焦 Linux。

### 4. 为什么不用异步？

抓包循环是**纯 CPU 密集型 + 阻塞 I/O**（`poll()` 等待包），没有并发 I/O 或任务调度的需求。用 `async` 只会增加复杂度而无收益。一个同步 `loop { poll(); process(); }` 就是最适合的模型。

### 5. 错误处理哲学

使用统一的 `NetdumpError` 枚举，所有内部错误向上透传至 `run()` 统一处理。不 panic（除非不可恢复的系统错误，如 mmap 失败），不吞错误。

### 6. 零拷贝 vs 数据拷贝

```
网卡──DMA──→内核 ring buffer──mmap──→用户态（零拷贝）
                                          │
                     ┌────────────────────┘
                     ▼
              解析协议头（引用原始数据）
                     │
            ┌────────┴────────┐
            ▼                  ▼
      pcap 写入（拷贝）   终端打印（格式化+拷贝）
```

抓包阶段通过 TPACKET_V3 ring buffer + mmap 实现零拷贝，用户态直接读取共享内存中的原始包数据。仅在写入 pcap 文件和终端格式化时发生数据拷贝。

### 7. 模块拆分粒度

5 个 crate 的拆分边界按**独立可发布的库**来划分：
- `netdump-core` — 任何网络工具都可以复用
- `netdump-cbpf` — 任何需要在用户态执行 CBPF 的项目
- `netdump-filter` — 任何需要解析 pcap-filter 或编译 CBPF 的项目
- `netdump-afpacket` — 任何需要在 Linux 上零拷贝抓包的项目
- `netdump` — 组装成 CLI

每个 crate 都可在 crates.io 上独立发布和版本管理，降低上下游依赖耦合。