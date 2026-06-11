# nettools

[English](README.md) | [中文](README_CN.md)

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/baidu/nettools.svg)](https://pkg.go.dev/github.com/baidu/nettools)
[![CI](https://github.com/baidu/nettools/actions/workflows/ci.yml/badge.svg)](https://github.com/baidu/nettools/actions/workflows/ci.yml)

一组百度物理网络黑盒监控方向开发的网络诊断工具，包括：
- **bitflip**: 用于检测大规模物理网络中的丢包和比特翻转错误。
- **bitflip6**: bitflip 的 IPv6 版本，用于 IPv6 网络诊断。
- **baize**: 配置驱动的网络质量持续监控工具，适合长期部署场景。
- **kuiniu**: AI 训练集群 GPU 网卡（RoCEv2/UDP）互联探测工具，按 GPU 对组织，支持 `role=both` 单进程双角色同构部署。
- **lidar**: TCP SYN 网络可达性探测工具，无需在远端部署任何软件。
- **mping**: 多目标 ICMP Echo 批量 ping 工具，支持 CIDR 展开、DNS 解析、硬件时间戳和改包检测。
- **mping6**: mping 的 IPv6 版本，用于 ICMPv6 Echo 探测，支持改包检测。
- **evr**: 基于 VXLAN 的 EVR 设备探测工具——通过把 EVR 真实源 IP 内嵌在 payload 中，借助 EVR 自身的 VXLAN 反射做无对端探测，单机即可部署。

> 百度系统部出品


## 安装

```bash
curl -fsSL https://nettools.rpcx.io/install.sh | sh
```

或者指定安装目录：

```bash
BINDIR=~/.local/bin curl -fsSL https://nettools.rpcx.io/install.sh | sh
```

或者从源码编译：

```bash
make build
```


## bitflip

![](docs/bitflip.png)

高频 UDP 探测工具，用于网络比特翻转（报文损坏）检测。

**工作原理：** 客户端每秒向服务端发送大量 UDP 报文，服务端原样回显。双端独立检测：

- **Client 端（往返检测）：** 检测全链路往返丢包和 bitflip。若报文在任一方向丢失，计为丢包；若返回报文内容与预期不符，记录发生 bitflip 的五元组。
- **Server 端（单向检测）：** 仅检测 Client→Server 方向的丢包和 bitflip。每个报文携带 Client 上一时间窗口的实际发送计数和起始端口对，Server 据此计算单向丢包率并还原该窗口的全部端口对——实现**单向丢包五元组定位**，无需时钟同步或跟踪 Client 状态。Server 收到未知 Client 的第一个包时自动创建统计实例，无需预配置 `-c`。

通过对比 Client 端和 Server 端的丢包率，可判断丢包发生在**正向路径**（Client→Server）还是**回程路径**（Server→Client）。

### 快速开始

**编译：**
```bash
make build
```

**启动服务端（远程主机）：**
```bash
# 最简方式——自动检测本机 IP
./bitflip

# 指定 IP
./bitflip -r server -s <server_ip> -c <client_ip>
```

**启动客户端（本地主机）：**
```bash
# -c 未设置时自动检测，-s 为必填
./bitflip -r client -s <server_ip>

# 指定 IP
./bitflip -r client -c <client_ip> -s <server_ip>
```

### 命令行参数

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-r` | `--role` | server | 角色：client 或 server |
| `-c` | `--client-addr` | "" | 客户端 IP 地址（为空时自动检测） |
| `-s` | `--server-addr` | "" | 服务端 IP 地址（server 角色为空时自动检测） |
| `-t` | `--tos` | 64 | IP TOS/DSCP 值 |
| `-n` | `--count` | 0 | 最大发送报文数（0 = 无限制） |
| `-d` | `--duration` | 0 | 最大发送时长（0 = 无限制） |
| | `--client-ports` | "43500,43599" | 客户端端口范围 [min,max] |
| | `--server-ports` | "43500,43509" | 服务端端口范围 [min,max] |
| | `--rate` | 5000 | 每个 span 内的发送速率 |
| | `--msglen` | 1024 | 报文载荷大小（不含 32 字节头部） |
| | `--delay` | 3s | 统计处理延迟（等待在途报文） |
| | `--verbose` | false | 丢包时打印详细端口信息（Client 和 Server 均支持） |

### 示例

```bash
# 服务端——自动检测 IP
./bitflip

# 客户端
sudo ./bitflip -r client -s 10.0.0.2

# 客户端——自定义速率和时长
sudo ./bitflip --role client --server-addr 10.0.0.2 --rate 10000 --duration 60s
```

### 比特翻转检测原理

客户端使用 4 种 salt 填充模式发送报文，通过 `seq % 4` 选择：

| 序号 | 填充模式 | 说明 |
|------|----------|------|
| 0 | `0xFF` | 全 1 字节 |
| 1 | `0x00` | 全 0 字节 |
| 2 | `0x5A` | 固定模式 `01011010` |
| 3 | 互补交替 | `0xAAAA` / `0x5555` 交替 16-bit 字 |

服务端使用相同的 4 种 salt 模式验证报文，确保能准确识别哪个字节发生了翻转。

### 报文格式

```
+----------+----------+-----------+---------------+------------------+------------------+----------+
| Magic(8) | Seq(8)   | Ts(8)     | LastSent(4)   | LastSrcPort(2)   | LastDstPort(2)   | Salt(N)  |
+----------+----------+-----------+---------------+------------------+------------------+----------+
```

- **Magic**：8 字节魔数标识
- **Seq**：8 字节序列号
- **Ts**：8 字节纳秒时间戳
- **LastSent**：4 字节上一 span 发送计数
- **LastSrcPort**：2 字节上一 span 起始源端口
- **LastDstPort**：2 字节上一 span 起始目的端口
- **Salt**：N 字节填充数据（用于比特翻转检测）

通过这种精巧的协议设计，Server 端仅需 `(LastSrcPort, LastDstPort, LastSent)` 三个字段加上确定性的 `GetNextPorts` 算法，即可还原上一个 span 中每一个包的端口对——从而实现**单向丢包的五元组级定位**，无需 Server 维护任何 Client 发送状态。

## bitflip6

bitflip 的 IPv6 版本。用法与 bitflip 一致，使用 IPv6 地址：

```bash
# 服务端
./bitflip6

# 客户端
sudo ./bitflip6 -r client -s fd00::2
```

## mping

多目标 ICMP Echo 批量 ping 工具，支持 CIDR 网段展开、DNS 主机名解析、硬件时间戳（Linux）、高速率探测和改包检测。mping6 是 IPv6 版本。

**核心特性：**
- **CIDR 展开：** 传入网段（如 `10.0.1.0/24`）自动展开所有主机地址。IPv6 支持 `/112`–`/128` 前缀，`--max-targets` 防止意外展开过大网段。
- **DNS 解析：** 传入主机名自动解析（mping 取 A 记录，mping6 取 AAAA 记录）。
- **硬件时间戳：** Linux 默认启用 `SO_TIMESTAMPING`，纳秒级延迟精度。macOS 自动回退到软件时间戳。
- **速率控制：** 内置令牌桶限速，精确控制每目标每秒发包数。
- **多目标混合：** 逗号分隔 IP、CIDR 网段、DNS 主机名可混合使用。
- **改包检测：** 通过在每个探测包中嵌入已知 salt 填充模式，检测 ICMP 回复报文中的比特翻转错误。

### 快速开始

**编译：**
```bash
make compile
```

**运行：**
```bash
# 单目标（默认 100 pps）
sudo ./mping -T 10.0.0.2

# 多目标
sudo ./mping -T 10.0.0.2,10.0.0.3,10.0.0.4

# CIDR 网段——探测整个 /24
sudo ./mping -T 10.0.1.0/24

# DNS 主机名
sudo ./mping -T www.example.com

# 高速率探测 30 秒
sudo ./mping -T 10.0.0.2 -r 1000 -d 30s

# IPv6
sudo ./mping6 -T fd00::2
```

### 命令行参数（mping）

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-T` | `--targets` | — | 目标 IPv4 地址/CIDR/主机名，逗号分隔（必填） |
| `-l` | `--local-addr` | 自动检测 | 本机 IP 地址 |
| `-I` | `--interface` | 自动检测 | 出接口名称 |
| `-z` | `--tos` | 0 | IP TOS/DSCP 值 |
| | `--ttl` | 64 | IP TTL |
| `-c` | `--count` | 0 | 每个目标最大发包数（0 = 无限制） |
| `-d` | `--duration` | 0 | 最大发送时长（0 = 无限制） |
| | `--delay` | 3s | 统计处理延迟（等待在途报文） |
| `-t` | `--timeout` | 1s | Socket 读超时 |
| `-r` | `--rate` | 100 | 每秒每目标发包数（pps） |
| `-s` | `--size` | 64 | ICMP 载荷大小（字节，最小 8） |
| | `--verbose` | false | 打印逐包 ICMP 回复详情 |
| | `--hwts` | true | 启用硬件时间戳（默认开启） |
| | `--max-targets` | 65536 | CIDR/DNS 展开后最大目标数 |
| `-V` | `--version` | false | 打印版本信息 |

mping6 参数相同，仅用 IPv6 对应项替换（如 `--tc` 替代 `--tos`，`--hlim` 替代 `--ttl`）。

详见 [mping 使用指南](docs/mping.html)。

## baize

配置驱动的网络质量持续监控工具，适合长期部署场景。与 bitflip 的命令行参数模式不同，baize 使用 JSON 配置文件，支持在同一进程中同时运行 Client 和 Server。

**核心特性：**
- **配置驱动：** 通过 JSON 配置文件管理所有参数，便于自动化部署。
- **单进程双角色：** 支持同一进程同时运行 Client 和 Server。
- **日志轮转：** 内置按日期轮转的日志系统，自动清理过期日志文件，symlink 指向最新日志。
- **pprof 集成：** 内置 Go pprof HTTP 服务，方便运行时性能分析。
- **优雅退出：** 监听 SIGINT/SIGTERM 信号，优雅关闭所有 goroutine。

> 百度物理网络内部使用的 baize 工具既支持配置文件，也支持定时拉取数据库节点的配置数据，开源版做了简化，只支持配置文件。同时内部版还会将数据推送到 Kafka 中供聚合程序处理，开源版默认输出到日志中，但已提供了接口可以各种实现。

### 使用场景

- **集群间高频探测：** 大规模集群间的网络质量持续监控，高频探测（默认 5000 pps）快速暴露间歇性丢包，多端口覆盖 ECMP 路径定位具体故障链路。
- **LCC 机房探测：** 跨 LCC 机房的网络质量监测，配置驱动便于批量部署到多机房节点。
- **ADC/DC 网络改造监控：** 网络设备割接、升级期间持续监控，改造前后质量对比量化改造效果，自动检测改造引入的丢包和改包问题。
- **专线监控：** 运营商专线质量持续监测，专线丢包、延迟异常实时告警，为 SLA 评估提供数据支撑。
- **回切验证：** 故障恢复后流量回切的网络质量验证，确认回切路径无丢包、无 bitflip，对比回切前后丢包率变化。
- **临时点对点监控：** 故障排查时的临时端到端探测，最小配置即可启动（仅需双方 IP），验证后可快速停止。

### 快速开始

**编译：**
```bash
go build -o baize ./cmd/baize/
```

**创建配置文件**（如 `baize.json`）：
```json
{
  "pprof_addr": ":6060",
  "log_dir": "/var/log/baize",
  "log_max_age_days": 7,
  "client": {
    "client_addr": "10.0.0.1",
    "server_addrs": "10.0.0.2",
    "rate_in_span": 5000,
    "span": "1s",
    "delay": "3s",
    "msg_len": 1024,
    "tos": 64
  },
  "server": {
    "server_addr": "10.0.0.2",
    "client_addrs": "10.0.0.1",
    "rate_in_span": 5000,
    "span": "1s",
    "delay": "3s",
    "msg_len": 1024,
    "tos": 64
  }
}
```

**运行：**
```bash
# 使用默认配置文件 (baize.json)
sudo ./baize

# 指定配置文件路径
sudo ./baize -c /etc/baize/baize.json
```

### 配置说明

**顶层字段：**

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `pprof_addr` | string | "" | pprof HTTP 监听地址（如 `:6060`），为空则不启动 |
| `log_dir` | string | "" | 日志文件目录，为空则输出到 stderr |
| `log_max_age_days` | int | 7 | 日志保留天数（≤0 默认 7 天） |
| `client` | object | null | Client 配置，null 则不启动 |
| `server` | object | null | Server 配置，null 则不启动 |

**Client/Server 字段：**

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `client_addr` / `server_addr` | string | "" | 本机 IP 地址 |
| `server_addrs` / `client_addrs` | string | "" | 对端 IP 地址，逗号分隔 |
| `tos` | int | 0 | IP TOS/DSCP 值 |
| `client_port_range` | string | "" | 客户端端口范围 `min,max` |
| `server_port_range` | string | "" | 服务端端口范围 `min,max` |
| `rate_in_span` | int64 | 0 | 每个 span 发包速率 |
| `span` | string | "0s" | 统计时间窗口（Go duration 格式） |
| `delay` | string | "0s" | 统计处理延迟 |
| `msg_len` | int | 0 | 报文载荷大小（不含 32 字节头部） |
| `count` | int | 0 | 最大发包数，仅 Client（0 = 无限制） |
| `send_duration` | string | "0s" | 最大发送时长，仅 Client（0 = 无限制） |
| `verbose` | bool | false | 丢包时打印详细端口信息 |

详见 [baize 使用指南](docs/baize-usage-guide.html)。

## kuiniu

面向 AI 训练集群 GPU 网卡（RoCEv2/UDP）的互联探测工具。按 **GPU 对** 组织（`local_gpu_addrs[i] ↔ remote_gpu_addrs[i]` 平行数组）双向对称探测，单进程通过 `role=both` 同时承担 client + server，所有训练节点配置同构。

**核心特性：**
- **GPU NIC 绑定：** 按 GPU 网卡 IP 绑定源地址发包，覆盖训练节点真实使用的 RoCEv2 路径，丢包归因精确到方向。
- **GPU 对数组模型：** `local_gpu_addrs[i]` ↔ `remote_gpu_addrs[i]` 平行数组配置，N 张 GPU 卡一次性展开 N 个对称探测对，单机多卡场景天然适配。
- **role=both 单配置部署：** 一份 JSON、一行 `role=both` 同时启动 client + server，server 端维护 `localGPUSet` 防止自回声，所有节点配置同构、运维成本极低。
- **4-Salt bitflip 检测：** 复用 baize 同款 4 种 Salt 填充模式，专门覆盖 RoCE 链路上 TCP/UDP 校验和发现不了的互补比特翻转。
- **共享日志组件：** 复用 `util.RotateWriter`（与 baize 共用）按日期轮转，同时输出到终端和文件。

### 快速开始

**编译：**
```bash
go build -o kuiniu ./cmd/kuiniu/
```

**创建配置文件**（如 `kuiniu.json`）：
```json
{
  "pprof_addr": ":6060",
  "log_dir": "/var/log/kuiniu",
  "log_max_age_days": 7,
  "role": "both",
  "local_gpu_addrs": [
    "33.0.1.25", "33.0.1.26", "33.0.1.153", "33.0.1.154"
  ],
  "remote_gpu_addrs": [
    "33.0.2.27", "33.0.2.28", "33.0.2.155", "33.0.2.156"
  ],
  "tos": 64,
  "client_port_range": "43600,43699",
  "server_port_range": "44600,44609",
  "rate_in_span": 5000,
  "span": "1s",
  "delay": "3s",
  "msg_len": 1024
}
```

**运行：**
```bash
# 使用 JSON 配置（命令行参数会覆盖配置项）
sudo ./kuiniu -c kuiniu.json

# 纯命令行模式（单 GPU 对）
sudo ./kuiniu --role both \
  --local-gpu  33.0.1.25 \
  --remote-gpu 33.0.2.27
```

### 命令行参数

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-r` | `--role` | "" | 角色：`client` / `server` / `both` |
| | `--local-gpu` | "" | 本机 GPU IP 列表（逗号分隔） |
| | `--remote-gpu` | "" | 对端 GPU IP 列表（逗号分隔） |
| `-t` | `--tos` | 64 | IP TOS/DSCP 值 |
| `-n` | `--count` | 0 | 每对 GPU 最大发包数（0 = 无限制） |
| `-d` | `--duration` | 0 | 最大发送时长（0 = 无限制） |
| | `--client-ports` | "43600,43699" | 客户端端口范围 [min,max] |
| | `--server-ports` | "43600,43609" | 服务端端口范围 [min,max] |
| | `--rate` | 5000 | 所有 GPU 对总速率（每个 span） |
| | `--msglen` | 1024 | 报文载荷大小（不含 44 字节头部） |
| | `--delay` | 3s | 统计处理延迟 |
| | `--verbose` | false | 丢包时打印详细端口信息 |
| `-c` | `--config` | "" | JSON 配置文件路径（命令行参数会覆盖配置项） |
| | `--pprof` | "" | pprof 监听地址（如 `:6060`） |
| | `--log-dir` | "" | 日志目录（启用按日轮转） |
| | `--log-max-age` | 7 | 日志保留天数 |

### 使用场景

- **AI 训练集群 GPU 互联监控：** 大规模训练集群 GPU 网卡间的持续探测，提前暴露 RoCE 链路问题，避免训练任务因丢包而 stall。
- **RoCEv2 链路丢包定位：** 按 GPU 对的对称探测精确归因丢包方向（正向/回程）。
- **GPU 网卡 bitflip 排查：** 捕捉 TCP/UDP 校验和漏检的互补比特翻转。
- **训练前预检：** 启动训练前快速验证所有 GPU 对的连通性。
- **故障复盘：** 基于双向对称数据精确定位故障 GPU 网卡或交换机端口。

详见 [kuiniu 使用指南](docs/kuiniu.html)。

## lidar

TCP SYN 网络可达性探测工具。通过发送原始 TCP SYN 报文并分析响应来判定目标主机和端口的网络状态，无需在远端部署任何软件。利用目标主机内核 TCP 协议栈自动响应 SYN 报文的特性，只需目标 IP 和端口即可探测。

**工作原理：** lidar 通过 raw socket 构造 TCP SYN 报文发送到目标 IP，通过 BPF 设备（macOS）或 raw socket（Linux）接收响应。内核 TCP 协议栈不会处理这些报文，因此不会影响系统已有的 TCP 连接。

**核心特性：**
- **无需服务端：** 只需目标 IP 和端口，无需在远端安装任何软件。
- **精准分类：** 区分 SYN-ACK（端口开放）、RST（端口关闭/拒绝）、Timeout（不可达/丢包）三种状态。
- **源端口轮转：** 自动轮转源端口覆盖多条 ECMP 路径，可配置端口范围。
- **速率控制：** 内置令牌桶限速，精确控制探测频率。
- **多目标并行：** 支持逗号分隔多 IP，每个目标独立统计。

### 快速开始

**编译：**
```bash
go build -o lidar ./cmd/lidar/
```

**运行：**
```bash
# 探测单个目标的 80 端口（默认 10 pps）
sudo ./lidar -t 10.0.0.2 -p 80

# 探测多个目标
sudo ./lidar -t 10.0.0.2,10.0.0.3,10.0.0.4 -p 22

# 高速率探测，持续 30 秒
sudo ./lidar -t 10.0.0.2 -p 80 --rate 100 -d 30s

# 发送固定数量探测包
sudo ./lidar -t 10.0.0.2 -p 80 -n 1000

# Verbose 模式，打印丢包端口详情
sudo ./lidar -t 10.0.0.2 -p 80 -v
```

### 命令行参数

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-t` | `--targets` | — | 目标 IP 地址，逗号分隔（必填） |
| `-p` | `--port` | 22 | 目标 TCP 端口 |
| `-l` | `--local-addr` | 自动检测 | 源 IP 地址 |
| | `--local-port` | 54321 | 源端口起始值 |
| | `--local-port-count` | 100 | 源端口数量（用于 ECMP 路径覆盖） |
| | `--rate` | 10 | 每秒发送探测包数（pps） |
| `-s` | `--span` | 1s | 统计报告间隔 |
| | `--delay` | 3s | 首次统计前的等待时间 |
| `-n` | `--count` | 0 | 最大发送数量（0 = 无限） |
| `-d` | `--duration` | 0 | 最大发送时长（0 = 无限） |
| `-i` | `--interface` | 自动检测 | 出接口名称 |
| `-v` | `--verbose` | false | 打印丢包的详细端口信息 |

### 输出示例

```
2026/06/05 21:37:14 [INFO] probing 1 target(s) on port 80 from 192.168.1.14 (rate: 10 pps)
2026/06/05 21:37:14 [INFO] bound BPF to en0 (DLT=1)
2026/06/05 21:37:17 [WARN] 21:37:14, [192.168.1.14 -> 74.48.173.243], sent: 10, received: 10 (SYN-ACK: 10, RST: 0), timeout: 0
2026/06/05 21:37:18 [INFO] 21:37:15, [192.168.1.14 -> 74.48.173.243], sent: 10, received: 10 (SYN-ACK: 10, RST: 0), timeout: 0
```

| 字段 | 说明 |
|------|------|
| `sent` | 该时间窗口内发送的探测包总数 |
| `received` | 收到响应的探测包总数 |
| `SYN-ACK` | 收到 SYN-ACK 响应的数量（目标端口开放） |
| `RST` | 收到 RST 响应的数量（目标端口关闭/拒绝） |
| `timeout` | 未收到响应的探测包数量（目标不可达/丢包） |

详见 [lidar 使用指南](docs/lidar.html)。

## evr

基于 VXLAN 的 **EVR（边缘虚拟路由器）** 设备探测工具。借助 EVR 自身的 VXLAN 反射能力——探测机构造一个 UDP/VXLAN 包，内层 Ethernet/IPv4/UDP 帧的内层 src 和 dst IP 都填本机探测 IP，再把真实的 EVR 源 IP 写入 payload，使得反射回来的探测包能够直接被本机原始套接字接收，并通过 payload 内嵌的源 IP 反查归因到具体目标。**无需对端运行 server 进程**——EVR 设备本身就是反射点。

**工作原理：** 探测进程通过 `ipv4.NewRawConn` 自建外层 IPv4 头（这样 `mock_src` 源地址伪造才能生效），封装 VXLAN 头 + 内层 Ethernet/IPv4/UDP 帧——内层 src/dst 都填本机 IP，并把 EVR 真实源 IP 写在 payload[24:28]。EVR 反射的内层报文直接命中本机 socket，`peerByEVRSrc` 映射把每个回包归因到具体目标。读 socket 上挂 BPF 预过滤（按内层 UDP 目的端口 + IPv4 TOS 匹配），廉价丢弃无关流量。

**核心特性：**
- **自环内层帧设计：** 内层 src == 内层 dst == 本机 IP，EVR 反射回来的包直接落到探测 socket，免去额外路由配置和对端服务。
- **payload 内嵌 EVR 源 IP：** 真实 EVR src IP 写在 payload[24:28]，单 socket 同时监控多个 EVR，回包通过 `peerByEVRSrc` 精确归因。
- **`mock_src` 源地址伪造：** 通过 `IP_HDRINCL` + `ipv4.NewRawConn` 自建外层 IPv4 头，每个目标可独立伪造 outer src IP，灵活验证 EVR 在不同源地址下的转发策略。
- **4-Salt bitflip 检测：** 复用 baize/kuiniu 同款 4 种 Salt 填充模式，覆盖 VXLAN 隧道+EVR 反射全路径上 校验和漏检的比特翻转。
- **JSON 配置 + CLI 覆盖：** 与 baize/kuiniu 相同的运维方式——JSON 文件为权威配置，CLI flag 仅覆盖显式传入的字段（`pflag.Visit`）。
- **日志按天轮转 + pprof：** 复用 `util.RotateWriter`，内置 pprof 端点。

### 快速开始

**编译：**
```bash
go build -o evr ./cmd/evr/
```

**创建配置文件**（如 `evr.json`）：
```json
{
  "id": "evr-probe-1",
  "client_addr": "203.0.113.10",
  "targets": "198.51.100.96#192.0.2.1#203.0.113.99,198.51.100.97#192.0.2.2#203.0.113.99",
  "dst_port": 4789,
  "inner_dst_port": 8972,
  "src_mac": "00:00:00:00:ff:ff",
  "dst_mac": "00:00:5e:00:01:ff",
  "vni": 15990000,
  "tos": 64,
  "ttl": 64,
  "client_port_range": "63000,63999",
  "rate_in_span": 2000,
  "span": "1s",
  "delay": "5s",
  "msg_len": 1024,
  "log_dir": "./log",
  "log_max_age_days": 3
}
```

每个 target 形如 `vtep#evrSrc[#mockSrc]`：
- `vtep`：外层目的 IP（EVR VTEP 地址）。
- `evrSrc`：真实 EVR 源 IP，内嵌到 payload 中用于回包归因。
- `mockSrc`（可选）：外层伪造源 IP，省略时使用 `client_addr`。

**运行：**
```bash
# 使用 JSON 配置（命令行参数会覆盖配置项）
sudo ./evr -c evr.json

# 纯命令行模式（单目标）
sudo ./evr --client-addr 203.0.113.10 \
  --targets 198.51.100.96#192.0.2.1
```

### 命令行参数

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-c` | `--config` | "" | JSON 配置文件路径（命令行参数会覆盖配置项） |
| | `--id` | "" | Agent 标识符（用于日志） |
| | `--client-addr` | 自动检测 | 本机 IPv4，作为外层源地址 |
| `-t` | `--targets` | — | 逗号分隔的目标列表，格式 `vtep#evrSrc[#mockSrc]` |
| | `--dst-port` | 4789 | 外层 UDP 目的端口 |
| | `--inner-dst-port` | 8972 | 内层 UDP 目的端口 |
| | `--src-mac` | `00:00:00:00:ff:ff` | 内层以太网源 MAC |
| | `--dst-mac` | `00:00:5e:00:01:ff` | 内层以太网目的 MAC |
| | `--vni` | 15990000 | VXLAN Network Identifier |
| | `--tos` | 0 | IPv4 TOS/DSCP（同时作用于外层和内层 IP） |
| | `--ttl` | 64 | IPv4 TTL（同时作用于外层和内层 IP） |
| | `--client-port-range` | "9981,9981" | 外层源 UDP 端口范围，如 `63000,63999` |
| | `--rate-in-span` | 1 | 所有目标合计每个 span 的发包数 |
| `-s` | `--span` | 100ms | 统计报告间隔 |
| | `--delay` | 100ms | 统计窗口最终化前的延迟 |
| | `--msg-len` | 28 | 内层 UDP 载荷长度（包头 + salt） |
| | `--pprof` | "" | pprof 监听地址（如 `:6060`） |
| | `--log-dir` | "" | 日志目录（启用按日轮转） |
| | `--log-max-age` | 3 | 日志保留天数 |
| `-v` | `--verbose` | false | 打印逐端口丢包详情 |
| `-V` | `--version` | false | 打印版本信息 |

### 使用场景

- **EVR 设备健康度监控：** 通过 EVR 自身的 VXLAN 反射做持续探测——单机部署、无需远端软件。
- **VXLAN 隧道路径监控：** 探测外层 VXLAN 隧道到 EVR 的丢包和比特翻转。
- **多 EVR 并发对比：** 一个探测进程同时覆盖多个 EVR（每个 EVR 一个 `vtep#evrSrc`），`peerByEVRSrc` 保证每个目标的统计互不干扰。
- **虚拟网络 NIC bitflip 检测：** 4-Salt 方案暴露 VXLAN/UDP 校验和漏检的互补比特翻转。

详见 [evr 使用指南](docs/evr.html)。

## 测试

```bash
make test
```

## 测试覆盖率

![](coverage.svg)

## 参与贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全漏洞

参见 [SECURITY.md](SECURITY.md)。

## 许可证

本项目基于 [MIT 许可证](LICENSE) 开源。
