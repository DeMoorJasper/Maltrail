import socket
import time
from core.settings import CEF_FORMAT


def trigger(event, config):
  extension = "src=%s spt=%s dst=%s dpt=%s trail=%s ref=%s" % (event.packet.src_ip, event.packet.src_port, event.packet.dst_ip, event.packet.dst_port, event.trail, event.reference)
  _ = CEF_FORMAT.format(syslog_time=time.strftime("%b %d %H:%M:%S", time.localtime(int(event.packet.sec))), host=HOSTNAME, device_vendor=NAME, device_product="sensor", device_version=VERSION, signature_id=time.strftime("%Y-%m-%d", time.localtime(os.path.getctime(TRAILS_FILE))), name=event.info, severity=0, extension=extension)
  remote_host, remote_port = config.SYSLOG_SERVER.split(':')
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.sendto(_, (remote_host, int(remote_port)))
