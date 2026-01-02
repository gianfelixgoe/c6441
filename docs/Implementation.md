## Implementation Notes (How the Sniffer Works)

This doc explains how `packet_sniffer.py` captures packets and decodes them into readable protocol fields.

### 1) Capturing raw Ethernet frames

The sniffer creates a raw socket at the Ethernet layer:

- **Family**: `socket.AF_PACKET` (Linux link-layer access)
- **Type**: `socket.SOCK_RAW` (deliver full frames, not just payloads)
- **Protocol**: `socket.ntohs(3)` (a common pattern to capture “all” protocols)

Then it loops forever:

- `raw_data, addr = conn.recvfrom(65536)`
  - `raw_data` is the bytes of the full Ethernet frame.
  - `addr` is link-layer addressing metadata from the kernel.

### 2) Ethernet II decoding (`ethernet_frame`)

Ethernet II header is 14 bytes:

- Destination MAC: 6 bytes
- Source MAC: 6 bytes
- EtherType: 2 bytes

The code unpacks those first 14 bytes:

- `struct.unpack('! 6s 6s H', data[:14])`
  - `!` means network byte order (big-endian)
  - `6s` is 6 raw bytes for each MAC
  - `H` is an unsigned 16-bit EtherType

It then:

- Formats MAC bytes into `AA:BB:CC:DD:EE:FF` via `get_mac_addr`
- Converts the EtherType with `socket.htons(proto)` so comparisons match the values the script expects
- Returns the payload (`data[14:]`) which begins immediately after the Ethernet header

In the main loop, the code checks:

- `if eth_proto == 8:` → treat payload as IPv4

This is intended to correspond to EtherType `0x0800` (IPv4). (The code’s `htons`/`ntohs` usage makes this appear as `8` rather than `0x0800`.)

### 3) IPv4 decoding (`ipv4_packet`)

The IPv4 header is typically 20 bytes, but can be longer if options are present.

#### Version + header length

The first byte contains two 4-bit fields:

- High nibble: version
- Low nibble: IHL (Internet Header Length) in 32-bit words

The code extracts them with bit operations:

- `version = version_header_length >> 4`
- `header_length = (version_header_length & 15) * 4`
  - `15` is `0b1111`, masking the low nibble
  - multiply by 4 to convert 32-bit words to bytes

#### TTL, protocol, and addresses

It then unpacks common fields out of the first 20 bytes:

- `ttl` (1 byte)
- `proto` (1 byte) — “next header”
- `src` (4 bytes)
- `target` (4 bytes)

with:

- `struct.unpack('! 8x B B 2x 4s 4s', data[:20])`
  - `8x` skips 8 bytes (version/IHL, DSCP/ECN, total length, identification, flags/fragment offset)
  - `B B` reads TTL and protocol
  - `2x` skips header checksum
  - `4s 4s` reads source and destination addresses

Finally it returns:

- Parsed header fields
- The remaining payload, starting at `data[header_length:]` (respects options if IHL > 20 bytes)

### 4) Protocol dispatch (ICMP / TCP / UDP)

Inside the IPv4 branch, the script switches on the IPv4 `proto` field:

- **1** → ICMP
- **6** → TCP
- **17** → UDP

Anything else is printed as raw data.

### 5) ICMP decoding (`icmp_packet`)

ICMP header starts with:

- Type (1 byte)
- Code (1 byte)
- Checksum (2 bytes)

The function unpacks the first 4 bytes:

- `struct.unpack('! B B H', data[:4])`

and returns the remainder (`data[4:]`) as ICMP payload.

### 6) TCP decoding (`tcp_segment`)

TCP starts with a fixed 20-byte header, but may include options (making it larger).

This implementation unpacks:

- Source port (2 bytes)
- Destination port (2 bytes)
- Sequence number (4 bytes)
- Acknowledgement number (4 bytes)
- Data offset/reserved/flags (2 bytes)

via:

- `struct.unpack('! H H L L H', data[:14])`

#### Data offset and flags

The 16-bit “offset/reserved/flags” field is interpreted as:

- Data offset: top 4 bits → header length in 32-bit words
- Flags: low bits → URG/ACK/PSH/RST/SYN/FIN

The code computes:

- `offset = (offset_reserved_flags >> 12) * 4`

and extracts flags with masks like:

- `flag_ack = (offset_reserved_flags & 16) >> 4`

Payload begins at `data[offset:]` (so TCP options are skipped correctly when present).

### 7) UDP decoding (`udp_segment`)

UDP header is 8 bytes:

- Source port (2)
- Destination port (2)
- Length (2)
- Checksum (2)

This implementation reads ports and length, skipping the checksum:

- `struct.unpack('! H H 2x H', data[:8])`

and returns `data[8:]` as UDP payload.

### 8) Payload formatting (`format_multi_line`)

To keep console output readable:

- If payload is bytes, it is converted to a string of hex escapes like `\\x45\\x00...`
- The output is wrapped to a target width (default 80) using `textwrap.wrap`
- Each line is prefixed with an indentation string (e.g. `DATA_TAB_3`)

### 9) Why some fields look “odd”

This is a learning-focused implementation rather than a full-featured protocol analyzer:

- EtherType handling uses `htons`/`ntohs` patterns that can make IPv4 appear as `8` rather than `0x0800`.
- Some headers are partially parsed (e.g., UDP checksum is skipped, many IPv4 fields are not shown).

