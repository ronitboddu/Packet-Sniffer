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
    __slots__ = "index", "data", "reach_dest", "reach_version", "size_start", "size_end"

    def __init__(self, filename):
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
                print("packet number: " + str(packet_no))
                pkt_start = self.index + self.reach_dest
                packet = self.data[pkt_start:pkt_start + (pkt_size * 2)]
                self.processPkt(packet)
                self.index += self.reach_dest + (pkt_size * 2)
                print()
            else:
                self.index += self.reach_dest + (pkt_size * 2)

    def printEtherData(self, packet):
        i = 0
        destination = str_to_Mac(packet[i:i + 12])
        i += 12
        source = str_to_Mac(packet[i:i + 12])
        i += 12
        ether_type = packet[i:i + 4]
        i += 4
        ether_data = "----- Ether Header -----\n" \
                     "Packet size = %d bytes\n" \
                     "Destination = %s\n" \
                     "Source = %s\n" \
                     "Ethertype = %s"
        print(ether_data % (len(packet) // 2, destination, source, ether_type))
        self.printIp(i, packet)

    def printIp(self, i, packet):
        version = packet[i]
        header_len = "20 bytes"
        type_of_service = "0x00"
        type_of_service += "\n\txxx. ... = 0 (precedence)\n" \
                           "\t...0 .... = normal delay\n" \
                           "\t.... 0... = normal throughput\n" \
                           "\t.... .0.. = normal reliability"
        i += 4
        total_len = str(int(packet[i:i + 4], 16)) + " bytes"
        i += 4
        identification = str(int(packet[i:i + 4], 16))
        i += 4
        flags = "0x" + packet[i:i + 2]
        flags += "\n\t.1.. .... = do not fragment" \
                 "\n\t..0. .... = last fragment"
        fragment_offset = "0 bytes"
        i += 4
        time_to_live = str(int(packet[i:i + 2], 16)) + " seconds/hops"
        i += 2
        protocol = ""
        if (packet[i:i + 2]) == "06":
            protocol = "6 (TCP)"
        elif (packet[i:i + 2]) == "11":
            protocol = "17 (UDP)"
        elif (packet[i:i + 2]) == "01":
            protocol = "1 (ICMP)"
        i += 2
        header_checksum = packet[i:i + 4]
        i += 4
        src_add = self.getAddr(packet[i:i + 8])
        i += 8
        dest_add = self.getAddr(packet[i:i + 8])
        i += 8
        IP_data = "----- IP Header -----\n" \
                  "Version = %s\n" \
                  "Header Length = %s\n" \
                  "Type of Service = %s\n" \
                  "Total length = %s\n" \
                  "Identification = %s\n" \
                  "Flags = %s\n" \
                  "Fragment offset = %s\n" \
                  "Time to live = %s\n" \
                  "Protocol = %s\n" \
                  "Header checksum = %s\n" \
                  "Source Address = %s\n" \
                  "Destination Address = %s\n" \
                  "No Options"
        print(IP_data % (
        version, header_len, type_of_service, total_len, identification, flags, fragment_offset, time_to_live,
        protocol, header_checksum, src_add, dest_add))

        if protocol == "6 (TCP)":
            self.printTCP(i, packet)
        elif protocol == "17 (UDP)":
            self.printUDP(i, packet)
        elif protocol == "1 (ICMP)":
            self.printICMP(i, packet)

    def printICMP(self, i, packet):
        type = str(int(packet[i:i + 2], 16))
        i += 2
        code = str(int(packet[i:i + 2], 16))
        i += 2
        checksum = packet[i:i + 4]
        i += 4
        icmp_header = "----- ICMP Header -----\n" \
                      "Type = %s\n" \
                      "Code = %s\n" \
                      "Checksum = %s\n"
        print(icmp_header % (type, code, checksum))

    def printUDP(self, i, packet):
        src_port = str(int(packet[i:i + 4], 16))
        i += 4
        dest_port = str(int(packet[i:i + 4], 16))
        i += 4
        length = str(int(packet[i:i + 4], 16))
        i += 4
        checksum = packet[i:i + 4]
        i += 4
        udp_header = "----- UDP Header -----\n" \
                     "Source port = %s\n" \
                     "Destination port = %s\n" \
                     "Length = %s\n" \
                     "Checksum = %s\n"
        print(udp_header % (src_port, dest_port, length, checksum))

    def printTCP(self, i, packet):
        src_port = str(int(packet[i:i + 4], 16))
        i += 4
        dst_port = str(int(packet[i:i + 4], 16))
        i += 4
        seq_no = str(int(packet[i:i + 8], 16))
        i += 8
        ack_no = str(int(packet[i:i + 8], 16))
        i += 8
        data_offset = "20 bytes"
        i += 2
        flags = "0x" + packet[i:i + 2]
        flags += "\n\t..0. .... = No urgent pointer" \
                 "\n\t...1 .... = Acknowledgement" \
                 "\n\t.... 1... = Push" \
                 "\n\t.... .0.. = No reset" \
                 "\n\t.... ..0. = No Syn" \
                 "\n\t.... ...0 = No Fin"
        i += 2
        window = str(int(packet[i:i + 4], 16))
        i += 4
        checksum = "0x" + packet[i:i + 4]
        i += 4
        urgent_ptr = str(int(packet[i:i + 4], 16))
        i += 4
        tcp_header = "----- TCP Header -----\n" \
                     "Source port = %s\n" \
                     "Destination port = %s\n" \
                     "Sequence number = %s\n" \
                     "Acknowledgement number = %s\n" \
                     "Data offset = %s\n" \
                     "Flags = %s\n" \
                     "Window = %s\n" \
                     "Checksum = %s\n" \
                     "Urgent pointer = %s\n" \
                     "No options\n"
        print(tcp_header % (src_port, dst_port, seq_no, ack_no, data_offset, flags, window, checksum, urgent_ptr))

    def skipIPv6(self, start):
        pkt_size = int(self.data[start + 64:start + 68], 16) + 14
        self.index += self.reach_dest + (pkt_size * 2)

    def processPkt(self, packet):
        self.printEtherData(packet)

    def getAddr(self, string):
        return str(int(string[0:2], 16)) \
               + "." + str(int(string[2:4], 16)) \
               + "." + str(int(string[4:6], 16)) + "." + str(int(string[6:8], 16))



temp = PacketSniffer("first_packet.pcap")
