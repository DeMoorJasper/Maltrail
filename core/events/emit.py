import traceback
import time

from core.events.ignore import ignore_event
from core.common import check_whitelisted
from core.logging.utils import safe_value
from core.settings import config
from core.settings import TIME_FORMAT
from core.logging.logger import log_error
from core.logging.file_log import event_throttle
from core.enums import TRAIL

def emit_event(event):
    try:
        if ignore_event(event):
            return
        
        # TODO: Get rid of this somehow
        event_throttle(event, config.PROCESS_COUNT)

        # Run event triggers
        if config.trigger_functions:
            for (trigger, function) in config.trigger_functions:
                try:
                    function(event, config)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()
        else:
            localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(event.packet.sec))), event.packet.usec)
            event_log_entry = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event.createTuple()[2:]))
            log_error(event_log_entry)
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()
