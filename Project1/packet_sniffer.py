"""
CSCI-651: Project 1
Author: Suraj Sureshkumar (ss7495@g.rit.edu)

This is a packet sniffer analyzer
"""
import binascii

from scapy.all import *


class Ether:

    def __init__(self, packet_data):
        """
        Constructor where all the information are sliced and store in a reference variable
        :param packet_data: taken as argument
        """
        self.ether_pkt_len = len(packet_data)
        self.ether_dst_add = binascii.hexlify(packet_data[0:6], ':').decode()
        self.ether_src_add = binascii.hexlify(packet_data[6:12], ':').decode()
        self.ether_type = binascii.hexlify(packet_data[12:14]).decode()

    def print(self):
        """
        This is the print function to print the Ether information
        :return: None
        """
        print(f'ETHER:--------Ether Header--------\n'
              f'ETHER: \n'
              f'ETHER: Packet size = {self.ether_pkt_len} bytes \n'
              f'ETHER: Destination = {self.ether_dst_add}, \n'
              f'ETHER: Source      = {self.ether_src_add} \n'
              f'ETHER: Ethertype   = {self.ether_type} \n'
              f'ETHER:')


class Ip:
    def __init__(self, packet_data):
        """
        Constructor where all the information are sliced and store in a reference variable
        :param packet_data: taken as argument
        """
        self.ip_version = binascii.hexlify(packet_data[14:15]).decode()[0]
        self.header_length = int(binascii.hexlify(packet_data[14:15]).decode()[1]) * 4

        self.type_of_service = binascii.hexlify(packet_data[15:16], ':').decode()
        self.total_length = int.from_bytes(packet_data[16:18], 'big')
        self.identification = int.from_bytes(packet_data[18:20], 'big')
        binary_representation = ''.join(bin(x)[2:].zfill(8) for x in packet_data[20:22])
        # print(binary_representation)
        self.ip_flags = binary_representation[:3]
        self.fragment_offset = int(binary_representation[3:], 2)

        self.time_to_live = int.from_bytes(packet_data[22:23], 'big')
        self.protocol = int.from_bytes(packet_data[23:24], 'big')
        self.header_checksum = hex(int.from_bytes(packet_data[24:26], 'big'))

        self.source_address = binascii.hexlify(packet_data[26:30], ':').decode()
        octets = self.source_address.split(":")
        ip_address = ".".join([str(int(octet, 16)) for octet in octets])
        self.source_address = ip_address

        self.destination_address = binascii.hexlify(packet_data[30:34], ':').decode()  # not done
        octets = self.destination_address.split(":")
        ipp_address = ".".join([str(int(octet, 16)) for octet in octets])
        self.destination_address = ipp_address

        self.options = "No Options"

    def print(self):
        """
        This is the print function to print the Ip information
        :return: None
        """
        print(f'IP:--------IP Header-------- \n'
              f'IP: \n'
              f'IP: Version = {self.ip_version} \n'
              f'IP: Header length = {self.header_length} bytes'
              f'IP: Type of service = {self.type_of_service} \n'
              f'IP: Total length = {self.total_length} bytes \n'
              f'IP: Identification = {self.identification} \n'
              f'IP: Flags = {self.ip_flags}'
              f'IP: Fragment offset = {self.fragment_offset}'
              f'IP: Time to live = {self.time_to_live} \n'
              f'IP: Protocol : {self.protocol} \n'
              f'IP: Header checksum = {self.header_checksum} \n'
              f'IP: Source address = {self.source_address} \n'
              f'IP: Destination address = {self.destination_address} \n'
              f'IP: {self.options} \n'
              f'IP')


class ICMP:
    def __init__(self, packet_data):
        """
        Constructor where all the information are sliced and store in a reference variable
        :param packet_data: taken as argument
        """
        self.ether = Ether(packet_data)
        self.ip = Ip(packet_data)
        self.protocol_name = ICMP
        self.icmp_type = int.from_bytes(packet_data[34:35], 'big')
        self.icmp_code = int.from_bytes(packet_data[35:36], 'big')
        self.icmp_checksum = hex(int.from_bytes(packet_data[36:38], 'big'))

    def print(self):
        """
        This is the print function to print the ICMP information
        :return: None
        """
        print(f'ICMP:--------ICMP Header-------- \n'
              f'ICMP: \n'
              f'ICMP: Type = {self.icmp_type} \n'
              f'ICMP: Code = {self.icmp_code} \n'
              f'ICMP: Checksum = {self.icmp_checksum} \n'
              f'ICMP')


class TCP:
    def __init__(self, packet_data):
        """
        Constructor where all the information are sliced and store in a reference variable
        :param packet_data: taken as argument
        """
        self.ether = Ether(packet_data)
        self.ip = Ip(packet_data)
        self.source_port = int.from_bytes(packet_data[34:36], 'big')  # question
        self.destination_port = int.from_bytes(packet_data[36:38], 'big')  # question
        self.tcp_sequence_number = int.from_bytes(packet_data[38:42], 'big')
        self.tcp_ack_number = int.from_bytes(packet_data[42:46], 'big')

        binary_representation2 = ''.join(bin(x)[2:].zfill(8) for x in packet_data[46:48])
        self.tcp_data_offset = int(binary_representation2[:4], 2) * 4
        self.tcp_reserved = binary_representation2[4:7]
        self.tcp_flags = binary_representation2[7:]
        self.window = int.from_bytes(packet_data[48:50], 'big')  # check

        self.tcp_checksum = hex(int.from_bytes(packet_data[50:52], 'big'))
        self.tcp_urgent_pointer = int.from_bytes(packet_data[52:54], 'big')
        self.tcp_options = 0
        self.tcp_padding = 0

    def print(self):
        """
        This is the print function to print the TCP information
        :return: None
        """
        print(f'TCP:--------TCP Header-------- \n'
              f'TCP: \n'
              f'TCP: Source port = {self.source_port} \n'
              f'TCP: Destination port = {self.destination_port} \n'
              f'TCP: Sequence number = {self.tcp_sequence_number} \n'
              f'TCP: Acknowledgement number = {self.tcp_ack_number} \n'
              f'TCP: Data offset = {self.tcp_data_offset} bytes \n'
              f'TCP: Flags = {self.tcp_flags} \n'
              f'TCP: Window = {self.window} \n'
              f'TCP: Checksum = {self.tcp_checksum} \n'
              f'TCP: Urgent Pointer = {self.tcp_urgent_pointer} \n'
              f'TCP: ')


class Udp:
    def __init__(self, packet_data: bytes):
        """
        Constructor where all the information are sliced and store in a reference variable
        :param packet_data: taken as argument
        """
        self.ether = Ether(packet_data)
        self.ip = Ip(packet_data)
        self.source_port = int.from_bytes(packet_data[34:36], 'big')
        self.destination_port = int.from_bytes(packet_data[36:38], 'big')
        self.udp_length = int.from_bytes(packet_data[38:40], 'big')
        self.udp_checksum = hex(int.from_bytes(packet_data[40:42], 'big'))

    def print(self):
        """
        This is the print function to print the UDP information
        :return: None
        """
        print(f'UDP:--------UDP Header--------\n'
              f'UDP: \n'
              f'UDP: Source port = {self.source_port} \n'
              f'UDP: Destination port = {self.destination_port} \n'
              f'UDP: Length = {self.udp_length} \n'
              f'UDP: Checksum = {self.udp_checksum}')


def packet_sniffer(argv):
    """
    Function where parsing and reading of file is handled
    :param argv: argument to be passed
    :return: None
    """
    if len(argv) <= 2:  # Exits if the length of argument is less than 2
        print("Incorrect arguments")
        sys.exit(0)
    packets = rdpcap(argv[2])

    for packet in packets:
        data = bytes(packet)
        eth = Ether(data)  # ether objects
        ip = Ip(data)  # ip objects

        # data which is in bytes format is passed to the respective classes where the operations are
        # performed to get the expected information
        if ip.protocol == 6:
            transport_control = TCP(data)
        elif ip.protocol == 17:
            transport_control = Udp(data)
        elif ip.protocol == 1:
            transport_control = ICMP(data)
        else:
            continue

        total_count = 0
        # checking if the argument is equal to -c and if total count is equal to the argument passed then break or else
        # display the packets information for the specified number
        if argv[3] == "-c" and total_count == int(argv[4]):
            break

        # checking if argument3 is equal to host and argument 4 is source address
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "host":
            if argv[4] == ip.source_address:
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n')

        # checking if argument3 is equal to port and argument 4 is the required port
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "port":
            if ip.protocol in (7, 17) and argv[4] == int(str(transport_control.source_port),
                                                         transport_control.destination_port):
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n' * 2)

        # checking if argument3 is equal to ip and argument 4 is the source or destination address
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "ip":
            if argv[4] in (ip.source_address, ip.destination_address):
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n' * 2)

        # checking if argument3 is equal to tcp and argument 4 is the protocol number
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "tcp":
            if ip.protocol == 7:
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n' * 2)

        # checking if argument3 is equal to udp and argument 4 is the protocol number
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "udp":
            if ip.protocol == 17:
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n' * 2)

        # checking if argument3 is equal to icmp and argument 4 is the protocol number
        # then increment count by 1 and print the eth and ip and the respective protocol to which the protocol
        # number matches
        elif argv[3] == "icmp":
            if ip.protocol == 1:
                total_count += 1
                eth.print()
                ip.print()
                transport_control.print()
                print('\n' * 2)

        # checking if argument3 is equal to net and argument 4 is the source or destination address
        # then increment count by 1 and print the network address
        elif argv[3] == "net":
            if argv[4] in (ip.source_address, ip.destination_address):
                network_address = argv[4].network()
                print(network_address)
        else:
            total_count += 1
            eth.print()
            ip.print()
            transport_control.print()
            print('\n' * 2)


def main():
    """
    Main Method
    :return: None
    """
    packet_sniffer(sys.argv)


if __name__ == '__main__':
    main()
