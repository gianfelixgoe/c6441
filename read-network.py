import socket

# Socket = 1 endpoint of two way communication
# Port = Physical Docking Point -> allows an external device can be connected to the computer
# Port in networking = Software defined number associated to a network protocol to receive or transmit communication to allow incoming traffic, use different port number

# Port allows single physical network connection to handle many incoming and outgoing request by assigning port number to each

# Socket is attached to a network port


''' Creating raw socket. Params:
1. Address Family of the socket (AF_INET = IPV4)
2. Type of Socket (SOCK_RAW = Raw Socket)
3. Protocol of the packet (number defined by IANA). Since we choose IPV4 in first param, then the third must be an IP based protocol
'''

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
while True:
  print(s.recvfrom(65565))