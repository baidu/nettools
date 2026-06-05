# nettools

[English](README.md) | [中文](README_CN.md)

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/baidu/nettools)](https://goreportcard.com/report/github.com/baidu/nettools)
[![Go Reference](https://pkg.go.dev/badge/github.com/baidu/nettools.svg)](https://pkg.go.dev/github.com/baidu/nettools)
[![CI](https://github.com/baidu/nettools/actions/workflows/ci.yml/badge.svg)](https://github.com/baidu/nettools/actions/workflows/ci.yml)

一组百度物理网络黑盒监控方向开发的网络诊断工具，包括：
- **bitflip**: 用于检测大规模物理网络中的丢包和比特翻转错误。
- **bitflip6**: bitflip 的 IPv6 版本，用于 IPv6 网络诊断。
- **baize**: 配置驱动的网络质量持续监控工具，适合长期部署场景。

> 百度系统部出品


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
