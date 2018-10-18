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

def plugin(pkg):
    global _last_syn
    global _last_logged_syn
    global _connect_src_dst
    global _connect_src_details

    if pkg.protocol == socket.IPPROTO_TCP:
        src_port, dst_port, _, _, doff_reserved, flags = pkg.tcp

        if flags == 2:  # SYN set (only)
            _ = _last_syn
            _last_syn = (pkg.sec, pkg.src_ip, src_port, pkg.dst_ip, dst_port)
            if _ == _last_syn:  # skip bursts
                return

            if pkg.dst_ip in trails or "%s:%s" % (pkg.dst_ip, dst_port) in trails:
                _ = _last_logged_syn
                _last_logged_syn = _last_syn
                if _ != _last_logged_syn:
                    trail = pkg.dst_ip if pkg.dst_ip in trails else "%s:%s" % (pkg.dst_ip, dst_port)
                    log_event(Event(pkg, TRAIL.IP if ':' not in trail else TRAIL.ADDR, trail, trails[trail][0], trails[trail][1]))

            elif (pkg.src_ip in trails or "%s:%s" % (pkg.src_ip, src_port) in trails) and pkg.dst_ip != pkg.localhost_ip:
                _ = _last_logged_syn
                _last_logged_syn = _last_syn
                if _ != _last_logged_syn:
                    trail = pkg.src_ip if pkg.src_ip in trails else "%s:%s" % (pkg.src_ip, src_port)
                    log_event(Event(pkg, TRAIL.IP if ':' not in trail else TRAIL.ADDR, trail, trails[trail][0], trails[trail][1]))
            
            if config.USE_HEURISTICS:
                if pkg.dst_ip != pkg.localhost_ip:
                    key = "%s~%s" % (pkg.src_ip, pkg.dst_ip)
                    if key not in _connect_src_dst:
                        _connect_src_dst[key] = set()
                        _connect_src_details[key] = set()
                    _connect_src_dst[key].add(dst_port)
                    _connect_src_details[key].add((pkg.sec, pkg.usec, src_port, dst_port))
