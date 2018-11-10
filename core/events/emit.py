import traceback
import time
import core.logger as logger

from core.events.ignore import ignore_event
from core.common import check_whitelisted
from core.utils.safe_value import safe_value
from core.settings import config
from core.settings import TIME_FORMAT
from core.enums import TRAIL

def emit_event(event):
    try:
        if ignore_event(event):
            return

        # Run event triggers
        if config.trigger_functions:
            for (_, function) in config.trigger_functions:
                try:
                    function(event, config)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()
                        
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()
