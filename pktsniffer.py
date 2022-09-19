import sys

from Packet import Packet


def getPktSize(string):
    s = string[6:8] + string[4:6] + string[2:4] + string[0:2]
    return int(s, 16)


def str_to_Mac(string):
    return ':'.join(string[i:i + 2] for i in range(0, 12, 2))


def readFile(filename):
    with open(filename, 'rb') as f:
        hexdata = f.read().hex()
        return hexdata


class PacketSniffer:
    __slots__ = "index", "data", "reach_dest", "reach_version", "size_start", "size_end", "packet_list", "packet_set", \
                "packet_dict"

    def __init__(self, filename):
        self.packet_list = []
        self.packet_set = set()
        self.packet_dict = {}
        self.index = 48
        self.reach_dest = 32
        self.size_start = 16
        self.size_end = 8
        self.reach_version = 28
        self.data = readFile(filename)
        packet_no = 0
        while self.index < len(self.data):
            packet_no += 1
            size_start = self.index + self.size_start
            pkt_size = getPktSize(self.data[size_start:size_start + 8])
            if self.data[self.index + self.reach_dest + self.reach_version] == "4":
                pkt_start = self.index + self.reach_dest
                packet = self.data[pkt_start:pkt_start + (pkt_size * 2)]
                pkt_obj = Packet(packet, packet_no)
                self.packet_list.append(pkt_obj)
                self.packet_set.add(packet_no)
                self.packet_dict[packet_no] = pkt_obj
                self.index += self.reach_dest + (pkt_size * 2)
            else:
                self.index += self.reach_dest + (pkt_size * 2)


def commandC(packet_list, num):
    record_set = set()
    min_len = min(num, len(packet_list))
    for pkt in range(min_len):
        record_set.add(packet_list[pkt].packet_no)
    return record_set


def commandHost(packet_list, addr):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchHost(addr):
            record_set.add(pkt.packet_no)
    return record_set


def commandNet(packet_list, addr):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchNet(addr):
            record_set.add(pkt.packet_no)
    return record_set


def commandICMP(packet_list):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchICMP():
            record_set.add(pkt.packet_no)
    return record_set


def commandTCP(packet_list):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchTCP():
            record_set.add(pkt.packet_no)
    return record_set


def commandUDP(packet_list):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchUDP():
            record_set.add(pkt.packet_no)
    return record_set


def commandPort(packet_list, port_num):
    record_set = set()
    for pkt in packet_list:
        if pkt.matchPort(port_num):
            record_set.add(pkt.packet_no)
    return record_set


def commandNot(rSet):
    return packet_set - rSet


def getResultSet(command, param=None):
    if command == "host":
        return commandHost(packet_list, param)
    elif command == "port":
        return commandPort(packet_list, param)
    elif command == "-net":
        return commandNet(packet_list, param)
    elif command == "icmp":
        return commandICMP(packet_list)
    elif command == "tcp":
        return commandTCP(packet_list)
    elif command == "udp":
        return commandUDP(packet_list)


if __name__ == '__main__':
    filename = sys.argv[2]
    pktsniffer = PacketSniffer(filename)
    boolean_ops = {'and', 'or', 'not'}
    packet_list = pktsniffer.packet_list
    packet_set = pktsniffer.packet_set
    packt_dict = pktsniffer.packet_dict
    i = 0
    ans_set = set()
    stack = []
    while i < len(sys.argv):
        if sys.argv[i] in {"and", "or", "not"}:
            stack.append(sys.argv[i])
        elif sys.argv[i] in {"icmp", "tcp", "udp"}:
            stack.append(getResultSet(sys.argv[i]))
        elif sys.argv[i] in {"host", "port", "-net"}:
            stack.append(getResultSet(sys.argv[i], sys.argv[i + 1]))
            i += 1
        i += 1

    exec_not = []
    i = 0
    while i < len(stack):
        if stack[i] == "not":
            exec_not.append(commandNot(stack[i + 1]))
            i += 1
        else:
            exec_not.append(stack[i])
        i += 1

    exec_and = []
    i = 0
    while i < len(exec_not):
        if exec_not[i] == "and":
            set1 = exec_and.pop()
            set2 = exec_not[i + 1]
            i += 1
            exec_and.append(set1.intersection(set2))
        else:
            exec_and.append(exec_not[i])
        i += 1

    exec_or = []
    i = 0
    while i < len(exec_and):
        if exec_and[i] == "or":
            set1 = exec_or.pop()
            set2 = exec_and[i + 1]
            i += 1
            exec_or.append(set1.union(set2))
        else:
            exec_or.append(exec_and[i])
        i += 1

    length = len(exec_or)
    if "-c" in sys.argv:
        length = int(sys.argv[sys.argv.index("-c") + 1])

    for pkt_num in exec_or[0]:
        print(packt_dict[pkt_num])
        length -= 1
        if length == 0:
            break
