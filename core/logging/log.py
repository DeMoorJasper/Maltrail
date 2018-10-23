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

_condensed_events = {}
_condensing_thread = None
_condensing_lock = threading.Lock()

def flush_condensed_events():
    while True:
        time.sleep(CONDENSED_EVENTS_FLUSH_PERIOD)

        with _condensing_lock:
            for key in _condensed_events:
                condensed = False
                events = _condensed_events[key]

                first_event = events[0]
                condensed_event = [_ for _ in first_event]

                for i in xrange(1, len(events)):
                    current_event = events[i]
                    for j in xrange(3, 7):  # src_port, dst_ip, dst_port, proto
                        if current_event[j] != condensed_event[j]:
                            condensed = True
                            if not isinstance(condensed_event[j], set):
                                condensed_event[j] = set((condensed_event[j],))
                            condensed_event[j].add(current_event[j])

                if condensed:
                    for i in xrange(len(condensed_event)):
                        if isinstance(condensed_event[i], set):
                            condensed_event[i] = ','.join(str(_) for _ in sorted(condensed_event[i]))

                log_event(condensed_event, skip_condensing=True)

            _condensed_events.clear()

def log_event(event, skip_write=False, skip_condensing=False):
    global _condensing_thread

    if _condensing_thread is None:
        _condensing_thread = threading.Thread(target=flush_condensed_events)
        _condensing_thread.daemon = True
        _condensing_thread.start()

    try:
        if ignore_event(event):
            return
        
        if not (any(check_whitelisted(_) for _ in (event.packet.src_ip, event.packet.dst_ip)) and event.trail_type != TRAIL.DNS):  # DNS requests/responses can't be whitelisted based on src_ip/dst_ip
            if not skip_write:
                if not skip_condensing:
                    if any(_ in event.info for _ in CONDENSE_ON_INFO_KEYWORDS):
                        with _condensing_lock:
                            key = (event.packet.src_ip, event.trail)
                            if key not in _condensed_events:
                                _condensed_events[key] = []
                            _condensed_events[key].append(event)

                        return
                
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
