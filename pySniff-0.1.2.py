#!/usr/bin/python3
import socket
import struct
import textwrap


def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # Receive data and trys to figure out what it is
        raw_data, addr = connect.recvfrom(65535)
        # Here the raw_data is devided into diffetent variables
        # data variable is new, and is interpeted in the eth_frame function
        dest_mac, src_mac, eth_protocol, data = eth_frame(raw_data)
        print('\nEthernet Frame:')
        print('\tDestination: {}, Source: {}, Protocol: {}'.format(
        dest_mac, src_mac, eth_protocol))

        # IPv4 is equal to protocol 8
        if eth_protocol == 8:
            version, header_length, ttl, protocol, src, target, data = ipv4_pkt(data)
            print('\tIPv4 Packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(
            version, header_length, ttl))
            print('\t\tProtocol: {}, Source: {}, Target: {}'.format(
            protocol, src, target))

            # ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_pkt(data)
                print('\tICMP Packet:')
                print('\t\tType: {}, Code: {}, Checksum: {}'.format(
                icmp_type, code, checksum))
                print('\t\tData:')
                print(multi_line_formater('\t\t\t', data))

            # TCP
            elif protocol == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, \
                flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('\tTCP Segments:')
                print('\t\tSource Port: {}, Destination Port: {}'.format(
                src_port, dest_port))
                print('\t\tSequence: {}, Acknowledgment: {}'.format(
                sequence, acknowledgment))
                print('\t\tFlags:')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\tData:')
                print(multi_line_formater('\t\t\t', data))

            # UDP
            elif protocol == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('\tUDP Segment:')
                print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(
                src_port, dest_port, length))

            # Others
            else:
                print('\tData:')
                print(multi_line_formater('\t\t', data))
        else:
            print('Data:')
            print(multi_line_formater('\t', data))

# Unpack the Ethernet frame - "!" is for network big-endian"
# get the first 14 bytes as the header, then return the data
def eth_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac),\
    socket.htons(protocol), data[14:]  # Data is after the first 14 bytes

# Return the formatted MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    # Makes sure the bytes are maped in correctly in two decimal places,
    # Capital X automatically convert it to uppercase
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str)  # Seperate the address with colon

# Unpacks the IPv4 packets
def ipv4_pkt(data):
    version_hdr_length = data[0]
    version = version_hdr_length >> 4
    header_length = (version_hdr_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target),\
    data[header_length:]

# Returns formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packets
def icmp_pkt(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP Segments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(\
        '! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,\
    flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP Segments
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multi-line data
def multi_line_formater(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



main()
