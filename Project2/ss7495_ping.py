"""
CSCI-651: Project 2
Author: Suraj Sureshkumar (ss7495@g.rit.edu)

Ping Traceroute program
"""
import argparse
import socket
import struct
import time
import select

MAX_HOPS = 50

"""
The below code has been referenced from:
Author: surajsinghbisht054@gmail.com 
Title of program - Simplest Function To Send Ping Request
Type -source code
Web address - https://www.bitforestinfo.com/blog/01/21/code-to-ping-request-using-raw-python.html
"""


def extract_data(data):
    """
    Extracting the icmp data from the packet
    :param data: the icmp data
    :return: None
    """
    icmp_data = struct.unpack("bbHHh", data)
    return {
        'type': icmp_data[0],
        "code": icmp_data[1],
        "checksum": icmp_data[2],
        'id': icmp_data[3],
        'seq': icmp_data[4],
    }


"""
The below code has been referenced from:
Author: surajsinghbisht054@gmail.com 
Title of program - Simplest Function To Send Ping Request
Type -source code
Web address - https://www.bitforestinfo.com/blog/01/21/code-to-ping-request-using-raw-python.html
"""


def checksum(msg):
    s = 0  # Binary Sum

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i + 1]
        s = s + (a + (b << 8))

    # One's Complement
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s


class PT:

    def __init__(self, destination, timeout):
        """
        The constructor
        :param destination: destination to which the packet to be sent
        :param timeout: the timeout between sending each packet
        """
        self.type = 8
        self.code = 0
        self.ttl = 1
        self.checksum = 0
        self.destination = destination
        self.sequence_number = 1
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.timeout = timeout or 1
        if timeout:
            self.socket.settimeout(timeout)
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(self.hostname)

    def create_packet(self, packet_id, packet_size=56):
        """
        Creating the icmp packet
        :param packet_id: the packet identifier
        :param packet_size: the size of packet in bytes
        :return: icmp_header
        """
        self.checksum = 0  # initializing checksum to zero

        icmp_header = struct.pack("bbHHh", self.type, self.code, self.checksum, packet_id,
                                  self.sequence_number)  # packing with checksum 0

        icmp_payload = 'X' * (packet_size - len(icmp_header))  # creating the icmp payload

        self.checksum = checksum(icmp_header + icmp_payload.encode())  # calculating the checksum

        icmp_header = struct.pack("bbHHh", self.type, self.code, self.checksum, packet_id,
                                  self.sequence_number)  # loading the final packet

        return icmp_header

    def send(self, destination_address, size):
        """
        The send function for the packet
        :param destination_address: the destination address to which the paket needs to be sent
        :param size: the size of the packet
        :return: packet_id
        """
        packet_id = int((id(time.time()) * 1000) % 65535)  # generating unique packet id

        icmp_packet = self.create_packet(packet_id, size)  # creating the packet with the default size

        while icmp_packet:
            # sending the packet to the destination
            icmp_send = self.socket.sendto(icmp_packet, (destination_address, 1))
            icmp_packet = icmp_packet[icmp_send:]
        return packet_id  # returning the packet id

    def ping(self, count=1, wait=1, size=56):
        """
        The ping function
        :param count: the number of packets to be sent
        :param wait: the wait time between each packet
        :param size: the size of the packet
        :return: None
        """
        try:
            destination_address = socket.gethostbyname(self.destination)  # getting the destination address

            for i in range(count):  # for loop to send the number of packets
                start = time.time()  # start time
                packet_id = self.send(destination_address, size)  # sending the packet to the destination
                self.receive(packet_id)

                duration = time.time() - start  # calculating the round trip time

                print(f'Reply from:{destination_address}: bytes={size} time:{int(duration * 1000)}ms')
                time.sleep(wait)  # waiting interval for the packets

        except socket.error:
            print("Invalid")

    """
    The below code has been referenced from:
    Author: surajsinghbisht054@gmail.com 
    Title of program - Simplest Function To Send Ping Request
    Type -source code
    Web address - https://www.bitforestinfo.com/blog/01/21/code-to-ping-request-using-raw-python.html
    """

    def receive(self, packet_id):
        """
        Receiving the packet
        :param packet_id: the packet identifier
        :return: None
        """
        while True:

            # to handle timeout function of socket
            process = select.select([self.socket], [], [], self.timeout)

            # check if timeout
            if not process[0]:
                return

            # receive packet
            rec_packet, addr = self.socket.recvfrom(1024)

            # extract icmp packet from received packet
            received_icmp = rec_packet[20:28]

            # extract the information from the icmp packet
            data = extract_data(received_icmp)

            # check the packet identification
            if data['id'] == packet_id:
                return data


def printHelp():
    """
    Function describing the available commands to execute when running the program with ping and traceroute
    :return:
    """
    print('If you want to run the ping these are some of the commands supported: \n'
          '-c count \n'
          '-i wait - wait seconds between sending each packet \n'
          '-s packetsize - the number of data bytes to be sent \n'
          '-t timeout - specify a timeout in seconds \n'
          ''
          'If you want to run the traceroute these are some of the commands supported: \n'
          '-n prints hop addresses numerically \n'
          '-q sets the probes \n'
          '-S print a summary of how many probes were not answered \n')


def init_argument():
    parser = argparse.ArgumentParser(
        prog='ping_traceroute.py',
        description='Creates a ping and traceroute to the given destination')

    parser.add_argument('action', type=str, help='ping or traceroute')
    parser.add_argument('destination', type=str, help='destination address')
    parser.add_argument('-c', '--count', default=1, type=int, help='number of packets to be sent')
    parser.add_argument('-i', '--wait', default=1, type=int, help='wait in between packets')
    parser.add_argument('-s', '--size', default=56, type=int, help='size of the packets')
    parser.add_argument('-t', '--timeout', type=int, help='Specify a timeout, in seconds')
    parser.add_argument('-n', '--hopaddress', type=int, help='Print hop addresses numerically')
    parser.add_argument('-q', '--nqueries', type=int, help='Set the number of probes')
    parser.add_argument('-S', '--summary', type=int,
                        help='Print a summary of how many probes were not answered for each hop')

    return parser.parse_args()


def main():
    """
    The main method
    :return: None
    """
    arguments = init_argument()
    ping_traceroute = PT(arguments.destination, arguments.timeout)
    if arguments.action == "ping":
        ping_traceroute.ping(arguments.count, arguments.wait, arguments.size)
    else:
        printHelp()


if __name__ == '__main__':
    main()
