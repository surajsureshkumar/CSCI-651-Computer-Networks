import argparse
import socket
import time

MAX_HOPS = 500

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


class Trace:
    def _init_(self, destination, timeout):
        self.type = 8
        self.code = 0
        self.ttl = 1
        self.checksum = 0
        self.destination = destination
        self.sequence_number = 1
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(self.hostname)
        self.timeout = timeout or 1
        if timeout:
            self.receiver.settimeout(timeout)

    def traceroute(self, hopaddress, nqueries, summary):
        """
        The traceroute function
        :param hopaddress: the hop address
        :param nqueries: number of probes
        :param summary: count of probes
        :return: None
        """

        destination_address = socket.gethostbyname(self.destination)  # Destination address
        self.sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # socket options sender
        self.receiver.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)  # socket options receiver

        print(f'Trace the route to {destination_address}')

        self.receiver.settimeout(1)  # setting the timeout to 1

        probe_count_unanswered = 0  # initializing probe count to 0

        self.ttl = 1  # initial ttl value
        received_ip = None

        while received_ip != destination_address and self.ttl != nqueries:
            try:
                self.sender.setsockopt(
                    socket.IPPROTO_IP, socket.IP_TTL, self.ttl)  # sender socket options

                start = time.time()  # start time
                self.sender.sendto(''.encode(), (destination_address, 1))  # sending to the destination

                rec_packet, addr = self.receiver.recvfrom(1024)  # receiving at the receiver
                received_ip = addr[0]  # getting the received up address
                duration = time.time() - start  # calculating the round trip time

            except socket.timeout:
                probe_count_unanswered += 1  # incrementing the probe count
                print('*')
                continue

            # summary is a boolean
            if summary and probe_count_unanswered:
                # printing the total number of uncounted probes
                print(f'Probes Unanswered:{probe_count_unanswered}')
                probe_count_unanswered = 0  # initializing probe to 0 again

            if hopaddress:
                print(
                    f'{self.ttl}\t{received_ip}\t{round(duration * 1000, 3)}ms')  # printing the address numerically
            else:
                # printing the destination name
                print(
                    f'{self.ttl}\t{received_ip} Destination{self.destination}\t{round(duration * 1000, 3)}ms')

            self.ttl += 1  # incrementing ttl by 1

        self.receiver.close()  # closing socket


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
    """
    Argument parser function
    :return: parser
    """
    parser = argparse.ArgumentParser(
        prog='ping_traceroute.py',
        description='Creates a ping and traceroute to the given destination')

    parser.add_argument('action', type=str, help='ping or traceroute')
    parser.add_argument('destination', type=str, help='destination address')
    parser.add_argument('-s', '--size', default=56, type=int, help='size of the packets')
    parser.add_argument('-n', '--hopaddress', type=bool, help='Print hop addresses numerically')
    parser.add_argument('-t', '--timeout', type=int,
                        help='Specify a timeout, in seconds')
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
    ping_traceroute = Trace(arguments.destination, arguments.timeout)
    if arguments.action == "traceroute":
        ping_traceroute.traceroute(arguments.size, arguments.hopaddress, arguments.nqueries, arguments.summary)
    else:
        printHelp()


if __name__ == '_main_':
    main()
