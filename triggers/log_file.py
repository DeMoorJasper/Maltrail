import os
import time
import core.logger as logger

from core.utils.safe_value import safe_value
from core.settings import TIME_FORMAT
from core.utils.timestamp import get_sec_timestamp
from core.utils.file_handler import get_write_handler
from core.settings import config

open_handlers = {}

def trigger(event, config):
    file_location = os.path.join(config.LOG_DIR, 'events-' + get_sec_timestamp(int(event.packet.sec)) + '.log')
    
    localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(event.packet.sec))), event.packet.usec)
    event_log_entry = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event.createTuple()[2:]))
    
    if config.SHOW_DEBUG:
        logger.warning(event_log_entry)

    if file_location not in open_handlers:
        open_handlers[file_location] = get_write_handler(file_location)

    # TODO: Error handling & recovery
    os.write(open_handlers[file_location], event_log_entry)

    # TODO: Close inactive streams
    # os.close(file_handler)
    