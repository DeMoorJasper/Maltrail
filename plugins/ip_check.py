import socket

from core.settings import IPPROTO_LUT
from core.settings import trails
from core.enums import TRAIL
from core.log import log_event
from core.log import Event

def plugin(pkg):
  if pkg.protocol not in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:  # non-TCP/UDP (e.g. ICMP)
    if pkg.protocol not in IPPROTO_LUT:
      return

    if pkg.protocol == socket.IPPROTO_ICMP:
      if ord(pkg.ip_data[pkg.iph_length]) != 0x08:  # Non-echo request
        return
    elif pkg.protocol == socket.IPPROTO_ICMPV6:
      if ord(pkg.ip_data[pkg.iph_length]) != 0x80:  # Non-echo request
        return

    if pkg.dst_ip in trails:
      log_event(Event(pkg, TRAIL.IP, pkg.dst_ip, trails[pkg.dst_ip][0], trails[pkg.dst_ip][1]))
    elif pkg.src_ip in trails:
      log_event(Event(pkg, TRAIL.IP, pkg.src_ip, trails[pkg.src_ip][0], trails[pkg.src_ip][1]))
