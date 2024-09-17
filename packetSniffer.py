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

def main():
    # creates a socket for incoming network traffic flow, and ensures that the script
    # is compatible with all machines (independent on endianness)
    # this ensures that the order is correct and readable

    # conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

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
