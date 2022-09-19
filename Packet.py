from Ether import Ether
from ICMP import ICMP
from IP import IP
from TCP import TCP
from UDP import UDP


def str_to_Mac(string):
    return ':'.join(string[i:i + 2] for i in range(0, 12, 2))


def getAddr(string):
    return str(int(string[0:2], 16)) \
           + "." + str(int(string[2:4], 16)) \
           + "." + str(int(string[4:6], 16)) + "." + str(int(string[6:8], 16))


def ether(packet, i):
    destination = str_to_Mac(packet[i:i + 12])
    i += 12
    source = str_to_Mac(packet[i:i + 12])
    i += 12
    ether_type = packet[i:i + 4]
    i += 4
    return Ether(packet, destination, source, ether_type),i


def ip(i, packet):
    ip = IP(i,packet)
    return ip,ip.getIndex()


class Packet:
    __slots__ = "packet", "ether", "ip", "prot","i","packet_no"

    def __init__(self, packet,packet_no):
        i = 0
        self.packet_no = packet_no
        self.packet = packet
        self.ether,i = ether(self.packet, i)
        self.ip,i = ip(i, self.packet)
        self.prot = None
        if self.ip.getProtocol() == "6 (TCP)":
            tcp = TCP(i, self.packet)
            self.prot,i = tcp,tcp.getIndex()
        elif self.ip.getProtocol() == "17 (UDP)":
            udp = UDP(i, self.packet)
            self.prot,i = udp, udp.getIndex()
        elif self.ip.getProtocol() == "1 (ICMP)":
            icmp = ICMP(i, self.packet)
            self.prot,i = icmp, icmp.getIndex()

    def getEther(self):
        return self.ether

    def getIp(self):
        return self.ip

    def matchHost(self,addr):
        if self.ip.getSourceAddr()==addr or self.ip.getDestAddr()==addr:
            return True
        return False

    def matchICMP(self):
        if self.ip.getProtocol() == "1 (ICMP)":
            return True
        return False

    def matchUDP(self):
        if self.ip.getProtocol() == "17 (UDP)":
            return True
        return False

    def matchTCP(self):
        if self.ip.getProtocol() == "6 (TCP)":
            return True
        return False

    def matchNet(self,addr):
        addr_str = addr.split(".")
        index = 0
        for i in range(len(addr_str)-1,-1,-1):
            if addr_str[i]!="0":
                index=i
                break
        subString = "".join(s+"." for s in addr_str[:index+1])
        subString = subString[:len(subString)-1]
        if subString in self.ip.getSourceAddr() or subString in self.ip.getDestAddr():
            return True
        return False

    def matchPort(self,port_no):
        if self.ip.getProtocol() == "6 (TCP)" or self.ip.getProtocol() == "17 (UDP)":
            if port_no == self.prot.getSrcPort() or port_no == self.prot.getDestPort():
                return True
        return False


    def __str__(self):
        return "Packet Number: "+str(self.packet_no)+"\n"+str(self.ether) + str(self.ip) + str(self.prot)
