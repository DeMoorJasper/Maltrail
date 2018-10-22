import socket

from core.settings import IPPROTO_LUT

class Event(object):
    # proto, trail_type, trail, info, reference, ip_data
    def __init__(self, packet, trail_type, trail, info, reference):
        # IP Package data
        self.packet = packet

        # Event data
        self.trail_type = trail_type
        self.trail = trail
        self.info = info
        self.reference = reference

    # Tuple:
    # (sec, usec, source ip, source port, destination ip, destination port, protocol, trail type, trail, info, reference)
    def createTuple(self):
        src_ip = self.packet.ip.get_ip_src()
        dst_ip = self.packet.ip.get_ip_dst()
        protocol = self.packet.ip.get_ip_p()
        proto = IPPROTO_LUT[protocol]
        src_port = "-"
        dst_port = "-"

        if protocol == socket.IPPROTO_TCP:
            tcp_header = self.packet.ip.child()
            src_port = tcp_header.get_th_sport()
            dst_port = tcp_header.get_th_dport()
        elif protocol == socket.IPPROTO_UDP:
            udp_header = self.packet.ip.child()
            src_port = udp_header.get_uh_sport()
            dst_port = udp_header.get_uh_dport()

        res = (self.packet.sec, self.packet.usec, src_ip, src_port, dst_ip, dst_port, proto, self.trail_type, 
            self.trail, self.info, self.reference)
        
        return res