import socket
import time
from core.logging.utils import safe_value
from core.settings import TIME_FORMAT


def trigger(event, config):
  localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(event.packet.sec))), event.packet.usec)
  event_log_entry = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event.createTuple()[2:]))
  remote_host, remote_port = config.LOG_SERVER.split(':')
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.sendto("%s %s" % (event.packet.sec, event_log_entry), (remote_host, int(remote_port)))
  