import socket
import struct
import textwrap

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
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

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

    while True:
        raw_data , addr = conn.recvfrom(65536)

    # loop to listen for data
    while True:
        # captures raw data and the address received from the socket
        raw_data, addr = conn.recvfrom(65536)

        dest, src, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Destination: {}, Source: {}, Protocol: {}\n'.format(dest, src, eth_proto))


if __name__ == "__main__":
    main()
