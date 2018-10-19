import struct
import socket

from core.settings import LOCALHOST_IP
from core.settings import IPPROTO_LUT
from core.enums import PROTO
from core.net.addr import inet_ntoa6

class Packet(object):
    src_port = "-"
    dst_port = "-"
    proto = None # Protocol name ex. TCP
    isEmpty = False

    def __init__(self, packet, sec, usec, ip_offset):
        self.sec = sec
        self.usec = usec
        
        self.ip_data = packet[ip_offset:]
        self.ip_version = ord(self.ip_data[0]) >> 4
        self.localhost_ip = LOCALHOST_IP[self.ip_version]

        if self.ip_version == 0x04:  # IPv4
            self.ip_header = struct.unpack("!BBHHHBBH4s4s", self.ip_data[:20])
            self.iph_length = (self.ip_header[0] & 0xf) << 2
            self.protocol = self.ip_header[6]
            self.src_ip = socket.inet_ntoa(self.ip_header[8])
            self.dst_ip = socket.inet_ntoa(self.ip_header[9])
        elif self.ip_version == 0x06:  # IPv6
            # Reference: http://chrisgrundemann.com/index.php/2012/introducing-ipv6-understanding-ipv6-addresses/
            self.ip_header = struct.unpack("!BBHHBB16s16s", self.ip_data[:40])
            self.iph_length = 40
            self.protocol = self.ip_header[4]
            self.src_ip = inet_ntoa6(self.ip_header[6])
            self.dst_ip = inet_ntoa6(self.ip_header[7])

        if self.protocol == socket.IPPROTO_TCP:
            self.proto = PROTO.TCP
            tcp_data = self.ip_data[self.iph_length:self.iph_length+14]
            self.tcp = struct.unpack("!HHLLBB", tcp_data)
        elif self.protocol == socket.IPPROTO_UDP:
            self.proto = PROTO.UDP
            udp_data = self.ip_data[self.iph_length:self.iph_length + 4]
            if len(udp_data) < 4:
                self.isEmpty = True
            else:
                self.udp = struct.unpack("!HH", udp_data)
        else:
            self.proto = IPPROTO_LUT[self.protocol]
