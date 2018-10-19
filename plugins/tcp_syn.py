import socket
import struct

from core.settings import config
from core.settings import trails
from core.enums import PROTO
from core.enums import TRAIL
from core.log import log_event
from core.log import Event

_last_syn = None
_last_logged_syn = None
_connect_src_dst = {}
_connect_src_details = {}

def plugin(packet):
    global _last_syn
    global _last_logged_syn
    global _connect_src_dst
    global _connect_src_details

    if hasattr(packet, 'tcp'):
        src_port, dst_port, _, _, doff_reserved, flags = packet.tcp

        if flags == 2:  # SYN set (only)
            _ = _last_syn
            _last_syn = (packet.sec, packet.src_ip, src_port, packet.dst_ip, dst_port)
            if _ == _last_syn:  # skip bursts
                return

            if packet.dst_ip in trails or "%s:%s" % (packet.dst_ip, dst_port) in trails:
                _ = _last_logged_syn
                _last_logged_syn = _last_syn
                if _ != _last_logged_syn:
                    trail = packet.dst_ip if packet.dst_ip in trails else "%s:%s" % (packet.dst_ip, dst_port)
                    log_event(Event(packet, TRAIL.IP if ':' not in trail else TRAIL.ADDR, trail, trails[trail][0], trails[trail][1]))

            elif (packet.src_ip in trails or "%s:%s" % (packet.src_ip, src_port) in trails) and packet.dst_ip != packet.localhost_ip:
                _ = _last_logged_syn
                _last_logged_syn = _last_syn
                if _ != _last_logged_syn:
                    trail = packet.src_ip if packet.src_ip in trails else "%s:%s" % (packet.src_ip, src_port)
                    log_event(Event(packet, TRAIL.IP if ':' not in trail else TRAIL.ADDR, trail, trails[trail][0], trails[trail][1]))
            
            if config.USE_HEURISTICS:
                if packet.dst_ip != packet.localhost_ip:
                    key = "%s~%s" % (packet.src_ip, packet.dst_ip)
                    if key not in _connect_src_dst:
                        _connect_src_dst[key] = set()
                        _connect_src_details[key] = set()
                    _connect_src_dst[key].add(dst_port)
                    _connect_src_details[key].add((packet.sec, packet.usec, src_port, dst_port))
