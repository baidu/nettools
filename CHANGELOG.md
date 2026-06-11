# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **evr**: VXLAN-based EVR device probing tool (`cmd/evr`)
  - Sends UDP/VXLAN probes to one or more EVR VTEPs from a single raw `ip4:udp` socket
  - "Self-loop" inner frame design: inner src/dst IPs both equal the local probe address while the real EVR src IP is embedded in the payload, so reflected responses can be matched back to the originating target without a 5-tuple key
  - `targets` config in `vtep#evrSrc[#mockSrc]` form, with optional spoofed outer src per-target
  - Reuses `stat.Processor` / `stat.NewStat` / `stat.LogSender` for per-target loss/latency reporting and `util.RotateWriter` for daily-rotated logs
  - BPF prefilter on inner UDP dst port + IPv4 TOS for the read socket
  - Salt-based bit-flip detection via the shared `util.Salts`
  - Built atop `goscapy` for VXLAN/Ethernet/IPv4/UDP encoding (no `gopacket` dependency)
  - JSON config file (`cmd/evr/evr.example.json`) and `make build-evr` target
  - Unit tests for codec round-trip and config parsing/validation

## [0.4.0] - 2026-06-10

### Added
- **kuiniu**: GPU NIC interconnect probing tool for AI training clusters
  - GPU pair model with parallel `local_gpu_addrs` / `remote_gpu_addrs` arrays
  - JSON config file with CLI flag override support
  - `role=both` for single-process client + server with `localGPUSet` self-echo guard
  - Concurrent client/server execution under shared context/processor/logger
  - 4-Salt bit-flip detection on RoCEv2/UDP paths
  - Logs to both terminal and file, with key milestone logs at startup
  - Continues running when client/server `Run()` returns error (no process exit)
- `util.RotateWriter`: shared daily-rotated log writer with stable symlink and prefix-isolated pruning, used by both `baize` and `kuiniu`
- Per-tool documentation page `docs/kuiniu.html`; `docs/index.html` updated with kuiniu section, tool index entry, and comparison table column
- Unit tests for `kuiniu/config`, `kuiniu/client`, `kuiniu/server`, `kuiniu/transport`, `ping`, `ping6`, and `util.salts`

### Fixed
- kuiniu client peer matching now uses the correct IP field
- kuiniu server now echoes via the matching GPU network and skips self-echo loops under `role=both`

## [0.3.0] - 2026-06-08

### Added
- **mping**: multi-target ICMP Echo ping tool with CIDR expansion, DNS resolution, and hardware timestamping
- **mping6**: IPv6 variant of mping for ICMPv6 Echo probing
- `--hwts` flag to enable/disable hardware timestamping (mping)
- `--max-targets` flag to cap CIDR/DNS target expansion
- Bit-flip detection in mping/mping6 via deterministic salts (shared `util` package)
- `install.sh` automated binary installation script, with install docs in README and website
- mping/mping6 documentation pages
- mping/mping6 packaging in Makefile and goreleaser config

### Fixed
- mping6 100% packet-loss issues: ICMPv6 socket binding (`SOCK_RAW` bound to `::`), receive-path dissection order, and Linux local address/interface auto-detection
- Docs: tool count, latency reporting, and mping bitflip-detection description

## [0.2.2] - 2026-06-06

### Added
- `--version` flag for all CLI tools, populated via `-ldflags` injection at build time

## [0.2.1] - 2026-06-06

### Changed
- goreleaser now packages all binaries into a single `nettools` archive per OS/arch (separate per-build entries)

## [0.2.0] - 2026-06-06

### Added
- GoReleaser config and GitHub release workflow

### Removed
- Custom `go-badges` job in favor of standard badge sources

## [0.1.0] - 2026-06-06

Initial open-source release.

### Added
- **bitflip**: IPv4 packet loss and bit-flip detection with dedicated client/server
- **bitflip6**: IPv6 variant of bitflip
- **baize**: configuration-driven continuous network quality monitoring tool
- **lidar**: TCP SYN probing tool for network reachability detection (no server-side deployment), with Linux raw-socket support and classic BPF filter
- Switch from gopacket to goscapy for packet construction
- GitHub Actions CI
- Unit tests for `lidar` and `stat` packages

[Unreleased]: https://github.com/baidu/nettools/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/baidu/nettools/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/baidu/nettools/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/baidu/nettools/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/baidu/nettools/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/baidu/nettools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/baidu/nettools/releases/tag/v0.1.0
