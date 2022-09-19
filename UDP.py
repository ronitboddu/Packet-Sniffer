class UDP:
    __slots__ = "src_port", "dest_port", "length", "checksum","index"

    def __init__(self, i, packet):
        self.src_port = str(int(packet[i:i + 4], 16))
        i += 4
        self.dest_port = str(int(packet[i:i + 4], 16))
        i += 4
        self.length = str(int(packet[i:i + 4], 16))
        i += 4
        self.checksum = packet[i:i + 4]
        i += 4
        self.index = i

    def getIndex(self):
        return self.index

    def getSrcPort(self):
        return self.src_port

    def getDestPort(self):
        return self.dest_port

    def getLength(self):
        return self.length

    def getCheckSum(self):
        return self.checksum

    def __str__(self):
        udp_header = "----- UDP Header -----\n" \
                     "Source port = %s\n" \
                     "Destination port = %s\n" \
                     "Length = %s\n" \
                     "Checksum = %s\n"
        return udp_header % (self.src_port, self.dest_port, self.length, self.checksum)
