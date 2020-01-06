#!/usr/bin/env python3
from util import *

"""
Read packet from input file and pretty print Ethernet header.
"""

"""
  Ethernet frame header
  Destination MAC - 6bytes
  Source MAC - 6bytes
  802.1Q header - 4bytes
    TPID (Tag Protocol Identifier) - 16bit field (0x8100) to identify frame as
    802.1Q tagged frame.
    PCP (Priority code point) - 3bit to define class of traffic.
    DEI (Drop Eligible Indicator) - 1bit to indicate frames eligible to be 
    dropped in case of congestion.
    VLAN Identifier - 12bit VLAN ID.
"""

"""
  IPv4 Header: (20 bytes)
    Version field (4 bits)
    Internet Header Length - number of 32 bit words in the header (4 bits)
      min: 4 ==> 4 x 32 = 128 bits/ 20 bytes v4 header
      max: 15 ==> 15 x 32 = 60 bytes v4 header
    Differentiated Service Code Point (DSCP) (6 bits)
      used for special traffic eg. VoIP
    Explicit Congestion Notification (ECN) (2 bits)
    Total length (16 bits/2 bytes)
      total IP packet size including header and data
      min: 20 bytes (header without data)
      max: 65535 bytes
    Identification (16 bits/2 bytes)
      used to uniquely identify group of fragments of a single IP datagram
    Flags (3 bits)
      Bit 0: Reserved, must be zero
      Bit 1: Don't Fragment (DF)
      Bit 2: More fragments (MF)
      Packets with DF set that may require fragmentation are dropped.
      For fragmented packet, all packets other than last one has MF set.
    Fragment offset (13 bits)
    TTL (Time To Live) (8 bits/1 byte)
      max is 255. recommended initial is 64.
    Protocol (8 bits/1 byte)
      next layer protocol (eg. TCP/UDP)
    Header checksum (16 bits/2 bytes)
      Note that IP header csum does not take into account the errors in data portion of the packet.
      This must be handled by the upper layer protocol.
    Source IP adress (32 bits/ 4 bytes)
    Destination IP address (32 bits/4 bytes)
    Options (if IHL > 5)
"""
    
MAC_ADDR_SIZE = 12  #6bytes
TPID_SIZE = 4  #2bytes
ETHER_TYPE_SIZE = 4 #2bytes
IP_VERSION_SIZE = 1  #4bits
etherType = {}
l2Type = None
length = 0
offset = 0

class Ethernet:
  def __init__(self):  # Constructor
    self.dst = 10
    self.src = 9;

class IPv4:
  def __init__(self):
    self.version = None
    self.ihl = None
    self.dscp = None
    self.ecn = None
    self.totalLen = None
    self.identification = None
    self.flags = None
    self.fragmentOffset = None
    self.ttl = None
    self.protocol = None
    self.headerCsum = None
    self.srcIP = None
    self.dstIP = None
    self.options = None
    
def init():
  etherType["0800"] = "IPv4"
  etherType["86dd"] = "IPv6"
  etherType["0806"] = "ARP"
  etherType["8100"] = "VLAN tagged frame (802.1Q)"

def main():
  with open('./input.txt', 'r') as file:
    data = file.read().replace('\n', ' ').replace(' ', '')
  parseL2(data)
  parseL3(data)
  #parseL4(data)
  #parseL5(data)

def getField(data):
  global offset, length
  res = data[offset: offset + length]
  offset += length
  return res

def parseL2(data):
  global length, offset, l2Type
  offset = 0
  length = MAC_ADDR_SIZE
  print ("DST MAC: " + printMAC(data, offset, length))
  offset += length
  print ("SRC MAC: " + printMAC(data, offset, length))
  offset += length
  length = TPID_SIZE
  isVLANTagged = data[offset: offset + length] == "8100"
  length = ETHER_TYPE_SIZE
  if isVLANTagged is True:
    offset += VLAN_HEADER_SIZE
    l2Type = etherType[data[offset:offset + length]]
  else:
    l2Type = etherType[data[offset: offset + length]]
  print ("type: " + l2Type)
  offset += length

def parseIPv4(data):
  global length, offset
  print ("Parsing IPv4 header")
  ip = IPv4()
  length = IP_VERSION_SIZE
  ip.version = getField(data)
  attrs = vars(ip)
  print ('\n '.join("%s: %s" % item for item in attrs.items()))

def parseL3(data):
  if l2Type == "IPv4":
    parseIPv4(data)
  else:
    print ("Non IPv4 packet")
  

def parseL4(data):
  pass

def parseL5(data):
  pass

if __name__ == "__main__":
  init()
  main()
