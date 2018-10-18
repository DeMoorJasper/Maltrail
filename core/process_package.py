import socket
import struct
import traceback

from core.settings import config
from core.logger import log_info
from core.settings import LOCALHOST_IP
from core.settings import MAX_RESULT_CACHE_ENTRIES
from core.settings import IPPROTO_LUT
from core.addr import inet_ntoa6
from core.enums import PROTO

result_cache = {}

class Package(object):
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

def process_packet(packet, sec, usec, ip_offset):
    if len(result_cache) > MAX_RESULT_CACHE_ENTRIES:
        result_cache.clear()

    try:
        pkg = Package(packet, sec, usec, ip_offset)

        # This is not an IP package
        if pkg.ip_version is None or pkg.isEmpty:
            return

        # Run through all the plugins
        if config.plugin_functions:
            for (plugin, function) in config.plugin_functions:
                try:
                    function(pkg)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
