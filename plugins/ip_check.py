import socket

from core.settings import IPPROTO_LUT
from core.settings import trails

def plugin(pkg):
  if pkg.protocol != socket.IPPROTO_TCP and pkg.protocol != socket.IPPROTO_UDP:  # non-TCP/UDP (e.g. ICMP)
    if pkg.protocol not in IPPROTO_LUT:
      return

    if pkg.protocol == socket.IPPROTO_ICMP:
      if ord(pkg.ip_data[pkg.iph_length]) != 0x08:  # Non-echo request
        return
    elif pkg.protocol == socket.IPPROTO_ICMPV6:
      if ord(pkg.ip_data[pkg.iph_length]) != 0x80:  # Non-echo request
        return

    if pkg.dst_ip in trails:
      # log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]), packet)
      return "Known destination ip"
    elif pkg.src_ip in trails:
      # log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]), packet)
      return "Known source ip"