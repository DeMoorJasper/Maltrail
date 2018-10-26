import struct
import socket
from impacket import ImpactPacket

from core.settings import LOCALHOST_IP
from core.settings import IPPROTO_LUT
from core.enums import PROTO

class Packet(object):
    def __init__(self, decodedFrame, sec, usec):
        self.sec = sec
        self.usec = usec

        self.ethernet = decodedFrame
        
        # TODO: Figure out how to handle non-ip based packets
        if self.ethernet.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip = self.ethernet.child()  # Parsed IP Packet

            # !!! Everything below this comment is deprecated!
            # !!! Do not use any of the keys defined after this comment on new code and plugins!
            self.ip_data = self.ip.get_packet()
            self.ip_version = self.ip.get_ip_v()
            self.localhost_ip = LOCALHOST_IP[self.ip_version]
            self.src_ip = self.ip.get_ip_src()
            self.dst_ip = self.ip.get_ip_dst()
            self.iph_length = self.ip.get_header_size()
            self.protocol = self.ip.get_ip_p()
            self.src_port = "-"
            self.dst_port = "-"
            self.proto = None  # Protocol name ex. TCP
            self.is_empty = False

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
