class Ether:
    __slots__ = "packet", "dest", "src", "ether_type"

    def __init__(self, packet, dest, src, ether_type):
        self.packet = packet
        self.dest = dest
        self.src = src
        self.ether_type = ether_type

    def getDest(self):
        return self.dest

    def getSrc(self):
        return self.src

    def getEtherType(self):
        return self.ether_type

    def __str__(self):
        ether_data = "----- Ether Header -----\n" \
                     "Packet size = %d bytes\n" \
                     "Destination = %s\n" \
                     "Source = %s\n" \
                     "Ethertype = %s\n"
        return ether_data % (len(self.packet) // 2, self.dest, self.src, self.ether_type)
