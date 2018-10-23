import os
import time
from core.logging.utils import safe_value
from core.settings import TIME_FORMAT
from core.logging.file_log import get_event_log_handle

def trigger(event, config):
  localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(event.packet.sec))), event.packet.usec)
  event_log_entry = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event.createTuple()[2:]))
  handle = get_event_log_handle(config.LOG_DIR, event.packet.sec)
  os.write(handle, event_log_entry)
