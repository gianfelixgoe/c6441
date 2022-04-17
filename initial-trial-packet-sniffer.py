import struct
import sys
from getmac import get_mac_address
import socket

def ethernet_head(raw_data):
  dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
  dest_mac = get_mac_address(dest)
  src_mac = get_mac_address(src)
  proto = socket.htons(prototype)
  data = raw_data[14:]
  return dest_mac, src_mac, proto, data

def main():
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))
  while True:
    raw_data, addr = s.recvfrom(65535)
    eth = ethernet_head(raw_data)
    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))

main()
