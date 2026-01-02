## Further Improvements / Next Steps

This repo is a solid educational sniffer, but it can be made much more usable and correct with the improvements below.

### Correctness

- **Fix EtherType handling**: compare against `0x0800` (IPv4) explicitly and remove confusing `htons`/`ntohs` conversions.
- **Parse more IPv4 fields**: total length, identification, flags/fragment offset, header checksum, DSCP/ECN.
- **Decode TCP options**: parse MSS, SACK permitted, timestamps, window scaling, etc.
- **Decode UDP checksum** (and optionally validate checksums).
- **Handle VLAN tags**: support 802.1Q/802.1ad headers (EtherType `0x8100`, `0x88A8`) before the inner EtherType.
- **Support IPv6**: EtherType `0x86DD` plus IPv6 header parsing and next-header chain.

### UX / Developer Experience

- **CLI flags** (argparse):
  - interface selection (e.g. `-i eth0`)
  - protocol filters (`--tcp`, `--udp`, `--icmp`)
  - port filters (`--src-port`, `--dst-port`)
  - max packet count (`-n`)
  - verbosity levels (`-v`, `-vv`)
- **Structured output**: optional JSON output for machine consumption.
- **Better payload rendering**:
  - ASCII preview alongside hex
  - safe truncation (`--max-bytes`)
  - optional reassembly-aware views (see below)

### Performance / Noise Reduction

- **BPF filters**: integrate kernel-level filtering (or shell out compatibility instructions for using `tcpdump`/`iptables`).
- **Sampling / rate limiting**: prevent terminal spam on busy links.
- **Ring buffer / batching**: reduce per-packet overhead when printing/logging.

### Features

- **PCAP export**: write captured frames to `.pcap` so Wireshark can inspect them.
- **Application-level decoders**:
  - basic HTTP request/response parsing for TCP streams
  - DNS decoding for UDP/53
  - TLS ClientHello SNI extraction (best-effort)
- **TCP stream reassembly**: reconstruct payload streams across segments (non-trivial but very useful).

### Portability / Permissions

- **Non-root capture options**:
  - document Linux capabilities (e.g. `CAP_NET_RAW`, `CAP_NET_ADMIN`)
  - guidance for running in containers/CI
- **Cross-platform story**:
  - Linux: `AF_PACKET` (current approach)
  - macOS/BSD: BPF devices
  - Windows: Npcap/WinPcap
  - alternatively: use a library like Scapy (trade-offs: dependencies vs portability)

### Code Quality

- **Remove unused imports** and tidy module-level comments.
- **Type hints + tests**:
  - unit tests for parsing functions with known binary fixtures
  - golden tests for formatted output
- **Package layout**:
  - move parsers into a module (e.g. `sniffer/parsers.py`)
  - keep CLI entrypoint thin (e.g. `sniffer/__main__.py`)
- **Add a dependency file** if keeping `getmac` usage (`requirements.txt` or `pyproject.toml`).

