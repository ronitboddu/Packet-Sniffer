def getAddr(string):
    return str(int(string[0:2], 16)) \
           + "." + str(int(string[2:4], 16)) \
           + "." + str(int(string[4:6], 16)) + "." + str(int(string[6:8], 16))


class IP:
    __slots__ = "version", "header_len", "type_of_serv", "total_len", "id", "flags", "frag_offset", "time_to_live", \
                "protocol", "hdr_checksum", "src_addr", "dest_addr", "index"

    def __init__(self, i, packet):
        self.version = packet[i]
        self.header_len = "20 bytes"
        i+=2
        self.type_of_serv = "0x" + packet[i:i + 2]
        binary = "{0:08b}".format(int(packet[i:i + 2], 16))
        self.type_of_serv += "\n\txxx. ... = 0 (precedence)\n" \
                             "\t..." + binary[3] + " .... = normal delay\n" \
                             "\t.... " + binary[4] + "... = normal throughput\n" \
                             "\t.... ." + binary[5] + ".. = normal reliability"
        i += 2
        self.total_len = str(int(packet[i:i + 4], 16)) + " bytes"
        i += 4
        self.id = str(int(packet[i:i + 4], 16))
        i += 4
        self.flags = "0x" + packet[i:i + 2]
        binary = "{0:016b}".format(int(packet[i:i+4], 16))
        self.flags += "\n\t." + binary[1] + ".. .... = do not fragment" \
                                            "\n\t.." + binary[2] + ". .... = last fragment"
        self.frag_offset = str(int(binary[3:], 16))
        i += 4
        self.time_to_live = str(int(packet[i:i + 2], 16)) + " seconds/hops"
        i += 2
        self.protocol = ""
        if (packet[i:i + 2]) == "06":
            self.protocol = "6 (TCP)"
        elif (packet[i:i + 2]) == "11":
            self.protocol = "17 (UDP)"
        elif (packet[i:i + 2]) == "01":
            self.protocol = "1 (ICMP)"
        i += 2
        self.hdr_checksum = packet[i:i + 4]
        i += 4
        self.src_addr = getAddr(packet[i:i + 8])
        i += 8
        self.dest_addr = getAddr(packet[i:i + 8])
        i += 8
        self.index = i

    def getIndex(self):
        return self.index

    def getVersion(self):
        return self.version

    def getHeaderLength(self):
        return self.header_len

    def getTypeOfService(self):
        return self.type_of_serv

    def getTotalLength(self):
        return self.total_len

    def getId(self):
        return self.id

    def getFlags(self):
        return self.flags

    def getFragOffset(self):
        return self.frag_offset

    def timeToLive(self):
        return self.time_to_live

    def getProtocol(self):
        return self.protocol

    def getHeaderChecksum(self):
        return self.hdr_checksum

    def getSourceAddr(self):
        return self.src_addr

    def getDestAddr(self):
        return self.dest_addr

    def __str__(self):
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
                  "No Options\n"

        return IP_data % (self.version, self.header_len, self.type_of_serv, self.total_len, self.id, self.flags,
                          self.frag_offset, self.time_to_live, self.protocol, self.hdr_checksum, self.src_addr,
                          self.dest_addr)
