class ICMP:
    __slots__ = "type", "code", "checksum","index"

    def __init__(self, i, packet):
        self.type = str(int(packet[i:i + 2], 16))
        i += 2
        self.code = str(int(packet[i:i + 2], 16))
        i += 2
        self.checksum = packet[i:i + 4]
        i += 4
        self.index = i

    def getIndex(self):
        return self.index

    def getType(self):
        return self.type

    def getCode(self):
        return self.code

    def getCheckSum(self):
        return self.checksum

    def __str__(self):
        icmp_header = "----- ICMP Header -----\n" \
                      "Type = %s\n" \
                      "Code = %s\n" \
                      "Checksum = %s\n"
        return icmp_header % (self.type, self.code, self.checksum)
