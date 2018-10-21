import struct
import socket

from core.settings import LOCALHOST_IP
from core.settings import IPPROTO_LUT
from core.enums import PROTO

from impacket.ImpactDecoder import IPDecoder

class Packet(object):
    src_port = "-"
    dst_port = "-"
    proto = None  # Protocol name ex. TCP
    is_empty = False
    decoder = IPDecoder()

    def __init__(self, packet, sec, usec, ip_offset):
        self.sec = sec
        self.usec = usec
        ip_data = packet[ip_offset:]
        self.ip = self.decoder.decode(ip_data)  # Parsed IP Packet

        # Everything below this comment is deprecated!
        self.ip_data = ip_data
        self.ip_version = self.ip.get_ip_v()
        self.localhost_ip = LOCALHOST_IP[self.ip_version]
        self.src_ip = self.ip.get_ip_src()
        self.dst_ip = self.ip.get_ip_dst()
        self.iph_length = self.ip.get_header_size()
        self.protocol = self.ip.get_ip_p()

        if self.protocol == socket.IPPROTO_TCP:
            self.proto = PROTO.TCP
            tcp_data = self.ip_data[self.iph_length:self.iph_length+14]
            self.tcp = struct.unpack("!HHLLBB", tcp_data)
            self.src_port = self.tcp[0]
            self.dst_port = self.tcp[1]
        elif self.protocol == socket.IPPROTO_UDP:
            self.proto = PROTO.UDP
            udp_data = self.ip_data[self.iph_length:self.iph_length + 4]
            if len(udp_data) < 4:
                self.is_empty = True
            else:
                self.udp = struct.unpack("!HH", udp_data)
            self.src_port = self.udp[0]
            self.dst_port = self.udp[1]
        else:
            self.proto = IPPROTO_LUT[self.protocol]
