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
        return (self.packet.sec, self.packet.usec, self.packet.src_ip, self.packet.src_port, self.packet.dst_ip, self.packet.dst_port, 
            self.packet.proto, self.trail_type, self.trail, self.info, self.reference)