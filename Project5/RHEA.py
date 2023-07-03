import socket
import time
from multiprocessing import Process


class RHEA:
    __slots__ = "routers", "link_costs", "routing_table", "id", "port", "neighbour_routing_table", "socket"

    def __init__(self):
        """
        Constructor
        """
        self.id = 'rhea'
        self.port = 4503
        # defining the routers
        self.routers = {
            'comet': ('127.0.0.1', 2, 4502),
            'glados': ('127.0.0.1', 1, 4504),
            'queeg': ('127.0.0.1', 16, 4501)}
        self.neighbour_routing_table = dict()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', self.port))
        self.socket.settimeout(5)
        self.routing_table = dict()
        self.initialize_table()
        self.display_routing_table()

        time.sleep(3)

    def initialize_table(self):
        """
        Initializing the table
        :return: None
        """
        # looping through the routers and if the cost is less than 16 then we are going to give the ip, cost and
        # next-hop
        for each in self.routers:
            if self.routers[each][1] < 16:
                self.routing_table[each] = [each, self.routers[each][1], each]
                self.neighbour_routing_table[each] = None
            else:
                self.routing_table[each] = [each, self.routers[each][1], None]

    def init_nbr_tables(self):
        """
        Initializing the neighbour table
        :return: None
        """
        for each in self.neighbour_routing_table:
            self.neighbour_routing_table[each] = None

    def update_table(self):
        """
        Update table function
        :return: None
        """
        # looping through the neighbour routing table
        for neighbour in self.neighbour_routing_table:
            if self.neighbour_routing_table[neighbour] is None:
                continue
            nbl_rt = self.neighbour_routing_table[neighbour]
            # looping through the routing table
            for node in self.routing_table:
                # node and neighbour are same then we are going to the begining or else we check if the cost of the
                # routing table is greater than the cost of the routing table and the nbr table and change the cost
                if node == neighbour:
                    continue
                elif self.routing_table[node][1] == 16 and self.routing_table[node][0] == neighbour:
                    if node in self.neighbour_routing_table:
                        self.routing_table[node][0] = neighbour
                        self.routing_table[node][1] = self.neighbour_routing_table[neighbour]
                    else:
                        self.routing_table[node][1] = None
                elif node in nbl_rt and self.routing_table[node][1] > self.routing_table[neighbour][1] + nbl_rt[node][
                    0]:
                    self.routing_table[node][1] = self.routing_table[neighbour][1] + nbl_rt[node][0]
                    self.routing_table[node][-1] = neighbour

    def split_horizon_poison_reverse(self):
        """
        Split horizon with poison reverse
        :return: None
        """
        # looping through the neighbour routing table, if next hop is equal to the router ip then that means it cant do
        # a self on itself so we proceed ahead
        dead_router = None
        for each_router in self.routing_table:
            # we identify the dead router
            if self.neighbour_routing_table[each_router] is None:
                dead_router = each_router
                break
            # if the dead router is in the routing then pop it out as there is no link to it
            if dead_router in self.routing_table:
                self.routing_table.pop(dead_router)
            # if the dead router is in the neighbouring table then pop it out as there is no link to it
            if dead_router in self.neighbour_routing_table:
                self.neighbour_routing_table.pop(dead_router)
            for each in self.routing_table:
                # if the dead router is the same as the neighbouring router then we set the cost to 16 and the next hop
                # of it to None as it does not exist
                if dead_router == self.neighbour_routing_table[each][0]:
                    self.routing_table[each][1] = 16
                    self.routing_table[each][2] = None
                # if the dead router is the same as the one in routing table next hop then we check if the routing table
                # router is the same as neighbour routing table then we set the router to the next hop of the current
                # routing table and the cost is updated and the link is established again
                elif dead_router == self.routing_table[each][2]:
                    if self.routing_table[each] in self.neighbour_routing_table[each]:
                        self.routing_table[each][2] = self.neighbour_routing_table[self.routing_table[each][0]]
                        self.routing_table[each][1] = self.routing_table[each][0]
                else:
                    self.routing_table[each][1] = 16
                    self.routing_table[each][2] = None

    def get_routing_table_from_pkt(self, pkt):
        """
        Getting the packet
        :param pkt: data
        :return: node and routing_tbl
        """
        packet = pkt.split('\n')
        node = packet[0]
        routing_tbl = dict()
        for i in range(1, len(packet)):
            line = packet[i].split()
            router = line[0]
            cost = int(line[1])
            next_hop = line[2] if line[2] != 'None' else None
            routing_tbl[router] = [cost, next_hop]
        return node, routing_tbl

    def get_packet(self):
        """
        Retrieving the packet
        :return: data
        """
        data = self.id + '\n'
        for each in self.routing_table:
            data += str(self.routing_table[each][0]) + ' ' + str(self.routing_table[each][1]) + ' ' + str(
                self.routing_table[each][2]) + '\n'
        return data[:-1]

    def rhea_send(self):
        """
        Send function
        :return: None
        """
        rhea_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # socket creation
        data = self.id + '\n'
        for each in self.routing_table:
            data += str(self.routing_table[each][0]) + ' ' + str(self.routing_table[each][1]) + ' ' + str(
                self.routing_table[each][2]) + '\n'
        data = data[:-1]
        address1 = (self.routers['comet'][0], self.routers['comet'][-1])  # address to send to
        address2 = (self.routers['glados'][0], self.routers['glados'][-1])  # address to send to
        rhea_socket.sendto(data.encode(), address1)  # sending the data to the destination
        time.sleep(2)
        rhea_socket.sendto(data.encode(), address2)
        rhea_socket.close()

    def rhea_receive(self):
        """
        Receive function
        :return: None
        """
        self.rhea_send()
        for each in self.neighbour_routing_table:
            self.neighbour_routing_table[each] = None
        # for the number of neighbors present receive from them
        for _ in range(2):
            response, addr = self.socket.recvfrom(1024)

            packet = response.decode().split('\n')  # decoding the response
            node = packet[0]  # the router from which data has arrived
            routing_tbl = dict()
            for i in range(1, len(packet)):
                line = packet[i].split()
                router = line[0]
                cost = int(line[1])
                next_hop = line[2] if line[2] != 'None' else None
                routing_tbl[router] = [cost, next_hop]
            self.neighbour_routing_table[node] = routing_tbl.copy()
        self.update_table()
        self.display_routing_table()
        self.rhea_send()

    def display_routing_table(self):
        """
        Displaying the routing table
        :return: None
        """
        for router, data in self.routing_table.items():
            print("{:<10} {:<10} {:<10}".format(router, data[1], data[2] if data[2] else "-"))


def main():
    rhea = RHEA()
    p1 = Process(target=rhea.rhea_send)
    p1.start()
    count = 0

    for _ in range(1000):
        rhea.rhea_receive()
        if count == 0:
            p1.join()
        count += 1
    rhea.socket.close()


if __name__ == '__main__':
    main()
