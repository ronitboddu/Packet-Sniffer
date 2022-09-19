class TCP:
    __slots__ = "src_port","dest_port","seq_no","ack_no","data_offset","flags","window","checksum","urgent_ptr"\
                ,"index"

    def __init__(self,i,packet):
        self.src_port = str(int(packet[i:i + 4], 16))
        i += 4
        self.dest_port = str(int(packet[i:i + 4], 16))
        i += 4
        self.seq_no = str(int(packet[i:i + 8], 16))
        i += 8
        self.ack_no = str(int(packet[i:i + 8], 16))
        i += 8
        self.data_offset = "20 bytes"
        i += 2
        self.flags = "0x" + packet[i:i + 2]
        binary = "{0:08b}".format(int(packet[i:i + 2], 16))
        self.flags += "\n\t.."+binary[2]+". .... = No urgent pointer" \
                 "\n\t..."+binary[3] + " .... = Acknowledgement" \
                 "\n\t.... "+binary[4]+"... = Push" \
                 "\n\t.... ."+binary[5]+".. = No reset" \
                 "\n\t.... .."+binary[6]+". = No Syn" \
                 "\n\t.... ..."+binary[7]+" = No Fin"
        i += 2
        self.window = str(int(packet[i:i + 4], 16))
        i += 4
        self.checksum = "0x" + packet[i:i + 4]
        i += 4
        self.urgent_ptr = str(int(packet[i:i + 4], 16))
        i += 4
        self.index = i

    def getIndex(self):
        return self.index

    def getSrcPort(self):
        return self.src_port

    def getDestPort(self):
        return self.dest_port

    def getSeqNo(self):
        return self.seq_no

    def getAckNo(self):
        return self.ack_no

    def getDataOffset(self):
        return self.data_offset

    def getFlags(self):
        return self.flags

    def getWindow(self):
        return self.window

    def getCheckSum(self):
        return self.checksum

    def getUrgentPtr(self):
        return self.urgent_ptr

    def __str__(self):
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
        return tcp_header % (self.src_port, self.dest_port, self.seq_no, self.ack_no, self.data_offset,
                             self.flags, self.window, self.checksum, self.urgent_ptr)