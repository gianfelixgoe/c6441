from email import header
from email.base64mime import header_length
import struct
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Computers will check the electricity pulses as 1 (pulse) and 0 (no pulse)

'''
If we want to monitor the traffic, rather than sending them to the router/network directly, we can sniff them 
- Can find where is the bottleneck of the network

'''

# Step 1: Get the data from computer to the router
### HTTP request (data) is wrapped up inside an IP packet, and this is wrapped in an Ethernet Frame 
"""
Ethernet Frame -> What your computer sent
- Sync(8) -> Control
- Receiver(6) -> Addr
- Sender(6) -> Addr
- Type(2) -> Ethernet type or protocol
- Payload(46 to 1500) -> IP Frame and the data
- CRC(4) -> Control
"""

def main():
  # We need socket to have connections with other computer
  # The last argument means that it works with all OS, big endian vs small endian etc.
  conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  while True:

    # raw_data is the ethernet frame, addr is where to / from it's going
    # remember that raw_data is just a pulse of 1s and 0s
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    if (dest_mac == '00:00:00:00:00:00'):
      continue
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

    # 8 for IPv4
    if eth_proto == 8:
      (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
      print(TAB_1 + 'IPv4 Packet:')
      print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
      print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

      # ICMP
      if proto == 1:  
        icmp_type, code, checksum, data = icmp_packet(data)
        print(TAB_1 + 'ICMP Packet:')
        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
        print(TAB_2 + 'Data:')
        print(format_multi_line(DATA_TAB_3, data))
      
      # TCP
      elif proto == 6:
        src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
        print(TAB_1 + 'TCP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
        print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
        print(TAB_2 + 'Flags:')
        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
        print(TAB_2 + 'Data:')
        print(format_multi_line(DATA_TAB_3, data))
      
      #U UDP
      elif proto == 17:
        src_port, dest_port, length, data = udp_segment(data)
        print(TAB_1 + 'UDP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
      
      # Other
      else:
        print(TAB_1 + 'Data:')
        print(format_multi_line(DATA_TAB_2, data))
    
    else:
      print('Data:')
      print(format_multi_line(DATA_TAB_1, data))


################################# Build the helper functions below

# Unpack ethernet frame, figuring out what the one and zeros are
def ethernet_frame(data):

  # Convert data from Bytes Format, unpacking
  # First argument of the struct: the format of the data. ! converting from beginning little-endian??. 6s = 6 string, H = small unsigned int for proto (2 bytes)
  dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
  return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
  # The bytes passed in will be 6 bytes. Taking all byte in bytes_addr and formatting them into a 2 digits place
  bytes_str = map('{:02x}'.format, bytes_addr)
  mac_addr = ':'.join(bytes_str).upper()
  return mac_addr



# Step 2: Get the data from the router to the Reddit address and return address (your computer)


# Step X: Unpacking IP Data / Header
"""
IP Header is how we communicate from server and client.
"""

# returns properly formatted IPv4 address (127.0.0.1)
def ipv4(addr):
  return '.'.join(map(str, addr))

# Unpacks IPv4 packet
def ipv4_packet(data):
  # step 1: Get the Header (the label of the package) get the version and header length, get the Time To Live (TTL), get the protocol, source address and destination address
  version_header_length = data[0] # Get the first byte

  # Use bitwise operations to get the version and header length
  version = version_header_length >> 4
  header_length = (version_header_length & 15) * 4 # (00001111) is 15. Why multiply by 4?? Because 1 bit in header_length represent a double word. So if the header_length is 0110 (6) then the length is 6 doublewords = 24 bytes. Maximum header_length is going to be 60 bytes (15 * 4). Usually header_length will be 20 bytes, hence see the function bellow.

  ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # Seems like it means, ignore the first 8 byte, get 1 Byte, get 1 Byte, ignore next 2 byte, get 4 bytes, get 4 bytes
  
  return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Unpacks ICMP (Internet Control Message Protocol) Packet
def icmp_packet(data):
  icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
  return icmp_type, code, checksum, data[4:]

# Unpacks tcp segment
def tcp_segment(data):
  (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

  offset = (offset_reserved_flags >> 12) * 4
  flag_urg = (offset_reserved_flags & 32) >> 5
  flag_ack = (offset_reserved_flags & 16) >> 4
  flag_psh = (offset_reserved_flags & 8) >> 3
  flag_rst = (offset_reserved_flags & 4) >> 2
  flag_syn = (offset_reserved_flags & 2) >> 1
  flag_fin = (offset_reserved_flags & 1)

  return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
  src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
  return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
  size -= len(prefix)
  if isinstance(string, bytes):
    string= ''.join(r'\x{:02x}'.format(byte) for byte in string)
    if size & 2:
      size -= 1
  return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



main()