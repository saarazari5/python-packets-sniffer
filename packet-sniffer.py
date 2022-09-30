from email.base64mime import header_length
from ensurepip import version
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '


def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #all machine compatible

    while True:
        raw_data, addr = conn.recvfrom(65536) #biggest buffer size available
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
         #8 for IPv4
       if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        print(TAB_1 + 'IPv4 Packer: ')


#unpack ethernet memory frame
#parse the first 14 bytes of the data,
#return the rest of the data because it is actually the payload.
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

 
 #return property formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(byte_addr):
    byte_str = map('{:02x}'.format, byte_addr) #%x is a format specifier that format and output the hex value.
    return ':'.join(byte_str).upper()

#unpacks IPv4 packet
def ipv4_packet(data): 
    version_header_length = data[0]
    #remove the length
    version = version_header_length >> 4 
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] 


#foramt IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


#unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpack TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[14:])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syh = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syh, flag_fin, data[offset:]

#unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2: 
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])