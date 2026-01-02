## Packet Sniffer (Raw Sockets, Python)

This repo is a small, educational packet sniffer that captures raw Ethernet frames and decodes common protocol layers to a human-readable, console-friendly output.

The primary script (`packet_sniffer.py`) listens on a raw socket, parses:

- **Ethernet II** headers (destination/source MAC + EtherType)
- **IPv4** headers (version, header length, TTL, protocol, source/destination IP)
- **ICMP**, **TCP**, and **UDP** payload headers (basic fields + raw payload dump)

### Docs

- **Implementation deep dive**: `docs/Implementation.md`
- **Future improvements**: `docs/Improvements.md`

### Files

- **`packet_sniffer.py`**: Main sniffer + parsers for Ethernet/IPv4/ICMP/TCP/UDP and pretty-print helpers.
- **`initial-trial-packet-sniffer.py`**: Early experiment for parsing an Ethernet header (uses `getmac`; may not run as-is).
- **`read-network.py`**: Minimal raw-socket example that prints received TCP packets.

### Requirements

- **Linux** (the main sniffer uses `AF_PACKET`, which is Linux-specific)
- **Root privileges** (raw sockets require elevated permissions)
- **Python 3**

### Run

In a terminal:

```bash
sudo python3 packet_sniffer.py
```

You should see output like:

- Ethernet frame summary (MACs + protocol/EtherType)
- If IPv4: IPv4 header fields
- Then one of:
  - ICMP fields + payload
  - TCP ports/sequence/ack/flags + payload
  - UDP ports/length

Stop with **Ctrl+C**.

### Notes / Caveats

- **High volume**: printing every packet can be very noisy and slow on busy interfaces.
- **No filtering**: there is no BPF/tcpdump-like filter; everything is parsed best-effort.
- **Payload rendering**: payload bytes are shown as hex escape sequences (`\\xNN`) wrapped to fit the terminal.
- **Not a PCAP tool**: it does not write `.pcap` files or integrate with Wireshark.

