#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import signal
import socket
import SocketServer
import sys
import threading
import time
import traceback

from core.common import check_whitelisted
from core.enums import TRAIL
from core.settings import config
from core.settings import CONDENSE_ON_INFO_KEYWORDS
from core.settings import CONDENSED_EVENTS_FLUSH_PERIOD
from core.settings import TIME_FORMAT
from core.events.ignore import ignore_event
from core.logging.logger import log_info
from core.logging.logger import log_error
from core.logging.file_log import event_throttle
from core.logging.file_log import get_event_log_handle
from core.logging.utils import safe_value

def log_event(event):
    try:
        if ignore_event(event):
            return
        
        if not (any(check_whitelisted(_) for _ in (event.packet.src_ip, event.packet.dst_ip)) and event.trail_type != TRAIL.DNS):  # DNS requests/responses can't be whitelisted based on src_ip/dst_ip
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

def start_logd(address=None, port=None, join=False):
    class ThreadingUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
        pass

    class UDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            try:
                data, _ = self.request
                sec, event = data.split(" ", 1)
                handle = get_event_log_handle(config.LOG_DIR, int(sec), reuse=False)
                os.write(handle, event)
                os.close(handle)
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    server = ThreadingUDPServer((address, port), UDPHandler)

    log_info("running UDP server at '%s:%d'" % (server.server_address[0], server.server_address[1]))

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

def set_sigterm_handler():
    def handler(signum, frame):
        log_error("SIGTERM")
        raise SystemExit

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)

if __name__ != "__main__":
    set_sigterm_handler()
