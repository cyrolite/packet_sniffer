import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t '


# unpacking of ethernet frames
def ethernet_frame(data):
    # grabs first 14 bytes and unpack the data passed into the function 
    # returns destination, source and the type of information
    # here, data[:14] refers to payload
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])

    # returns the mac address of destination, source and the type (into human readable format)
    return get_mac_address(dest), get_mac_address(src), socket.htons(proto), data[14:]

# return properly formatted mac address
def get_mac_address(addr):
    # takes all the address and formats them to the correct format (2dp for each one)
    # (eg A0:B1:C2:D3:E4:F5)
    bytes_str = map('{:02x}'.format, addr)

    # joins all the bytes into a string, and converts it to uppercase
    addr = ':'.join(bytes_str).upper()

    # returns the properly formatted address
    return addr

# unpacks IPV4 address
def ipv4_packet(data):
    # get version header length
    version_header_length = data[0]

    # get the version
    version = version_header_length >> 4

    # get the header length
    header_length = (version_header_length & 15) * 4

    # gets subsequent header information
    ttl, ip_proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    # return header version and payload
    return version, header_length, ttl, ip_proto, ipv4(src), ipv4(target), data[header_length:]

# returns properly formatted IPV4 address
def ipv4(addr):
    # appends and joins and returns properly formatted IPV4 address
    return '.'.join(map(str, addr))

# unpacks ICMP packet
def icmp_packet(data):
    # gets the type, code, and the checksum of the packet
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    # returns the attained values above, and includes the remaining payload
    return icmp_type, code, checksum, data[4:]

# unpacks TCP segment
def tcp_segment(data):
    # retrieves information from the packet (source port, destination port, etc)
    (src_port, dest_port, seq, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    
    # gets offset
    offset = (offset_reserved_flags >> 12) * 4

    # get flags
    flags_urg = (offset_reserved_flags & 32) >> 5
    flags_ack = (offset_reserved_flags & 16) >> 4
    flags_psh = (offset_reserved_flags & 8) >> 3
    flags_rst = (offset_reserved_flags & 4) >> 2
    flags_syn = (offset_reserved_flags & 2) >> 1
    flags_fin = (offset_reserved_flags & 1) >> 0

    # returns all information, including the payload
    return src_port, dest_port, seq, acknowledgement, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data[offset:]

# unpacks UDP segment
def udp_segment(data):
    # retrieves information from the packet
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])

    # returns information
    return src_port, dest_port, size, data[:8]

# helps format multi line data
def format_multi_line_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    # creates a socket for incoming network traffic flow, and ensures that the script
    # is compatible with all machines (independent on endianness)
    # this ensures that the order is correct and readable

    # conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # formatted properly for Windows users
    ip = socket.gethostbyname(socket.gethostname())
    port  = 0
    conn = socket.socket(socket.AF_INET , socket.SOCK_RAW)

    conn.bind((ip , port))

    conn.ioctl(socket.SIO_RCVALL , socket.RCVALL_ON)

   # loop to listen for data
    while True:
        # captures raw data and the address received from the socket
        raw_data, addr = conn.recvfrom(65536)

        dest, src, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(dest, src, eth_proto))

        # check ethernet protocol (8)
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPV4 Packet: ')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # checks proto
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                src_port, dest_port, seq, acknowledgement, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence : {}, Acknowledgement: {}'.format(seq, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                    flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data :')
                print(format_multi_line_data(DATA_TAB_3, data))
            
            # other types of data
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_2, data))
        
        else:
            print('Data: ')
            print(format_multi_line_data(DATA_TAB_1, data))

# method to sniff packets (to be exported to other files for external use)
def sniff_packets(captured_packets):
    # Creates the socket for capturing the packets
    ip = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((ip, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, _ = conn.recvfrom(65536)
        captured_packets.append(raw_data)


if __name__ == "__main__":
    main()
