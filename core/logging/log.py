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
import stat

from core.common import check_whitelisted
from core.common import check_sudo
from core.enums import TRAIL
from core.config.settings import config
from core.config.constants import HOSTNAME
from core.config.constants import NAME
from core.config.constants import TIME_FORMAT
from core.config.constants import VERSION
from core.trails.constants import TRAILS_FILE
from core.events.ignore import ignore_event
from core.logging.logger import log_info

_condensed_events = {}
_condensing_thread = None
_condensing_lock = threading.Lock()
_thread_data = threading.local()

CEF_FORMAT = "{syslog_time} {host} CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension}"
CONDENSE_ON_INFO_KEYWORDS = ("attacker", "reputation", "scanner", "user agent", "tor exit", "port scanning")
CONDENSED_EVENTS_FLUSH_PERIOD = 10
DEFAULT_EVENT_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
DEFAULT_ERROR_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH

class Event(object):
    # proto, trail_type, trail, info, reference, ip_data
    def __init__(self, packet, trail_type, trail, info, reference):
        # IP Package data
        self.packet = packet

        # Event data
        self.trail_type = trail_type
        self.trail = trail
        self.info = info
        self.reference = reference

    # Tuple:
    # (sec, usec, source ip, source port, destination ip, destination port, protocol, trail type, trail, info, reference)
    def createTuple(self):
        return (self.packet.sec, self.packet.usec, self.packet.src_ip, self.packet.src_port, self.packet.dst_ip, self.packet.dst_port, 
            self.packet.proto, self.trail_type, self.trail, self.info, self.reference)

def create_log_directory():
    if not os.path.isdir(config.LOG_DIR):
        if check_sudo() is False:
            exit("please rerun with sudo/Administrator privileges")
        os.makedirs(config.LOG_DIR, 0755)
    log_info("using '%s' for log storage" % config.LOG_DIR)

def get_event_log_handle(sec, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY, reuse=True):
    retval = None
    localtime = time.localtime(sec)

    _ = os.path.join(config.LOG_DIR, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))

    if not reuse:
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_EVENT_LOG_PERMISSIONS)

        retval = os.open(_, flags)
    else:
        if _ != getattr(_thread_data, "event_log_path", None):
            if getattr(_thread_data, "event_log_handle", None):
                try:
                    os.close(_thread_data.event_log_handle)
                except OSError:
                    pass

            if not os.path.exists(_):
                open(_, "w+").close()
                os.chmod(_, DEFAULT_EVENT_LOG_PERMISSIONS)

            _thread_data.event_log_path = _
            _thread_data.event_log_handle = os.open(_thread_data.event_log_path, flags)

        retval = _thread_data.event_log_handle

    return retval

def get_error_log_handle(flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    if not hasattr(_thread_data, "error_log_handle"):
        _ = os.path.join(config.LOG_DIR, "error.log")
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_ERROR_LOG_PERMISSIONS)
        _thread_data.error_log_path = _
        _thread_data.error_log_handle = os.open(_thread_data.error_log_path, flags)
    return _thread_data.error_log_handle

def safe_value(value):
    retval = str(value or '-')
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    return retval

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
                localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(event.packet.sec))), event.packet.usec)

                if not skip_condensing:
                    if any(_ in event.info for _ in CONDENSE_ON_INFO_KEYWORDS):
                        with _condensing_lock:
                            key = (event.packet.src_ip, event.trail)
                            if key not in _condensed_events:
                                _condensed_events[key] = []
                            _condensed_events[key].append(event)

                        return

                current_bucket = event.packet.sec / config.PROCESS_COUNT
                if getattr(_thread_data, "log_bucket", None) != current_bucket:  # log throttling
                    _thread_data.log_bucket = current_bucket
                    _thread_data.log_trails = set()
                else:
                    if any(_ in _thread_data.log_trails for _ in ((event.packet.src_ip, event.trail), (event.packet.dst_ip, event.trail))):
                        return
                    else:
                        _thread_data.log_trails.add((event.packet.src_ip, event.trail))
                        _thread_data.log_trails.add((event.packet.dst_ip, event.trail))
                
                event_log_entry = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event.createTuple()[2:]))
                if not config.DISABLE_LOCAL_LOG_STORAGE:
                    handle = get_event_log_handle(event.packet.sec)
                    os.write(handle, event_log_entry)

                if config.LOG_SERVER:
                    remote_host, remote_port = config.LOG_SERVER.split(':')
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto("%s %s" % (event.packet.sec, event_log_entry), (remote_host, int(remote_port)))

                if config.SYSLOG_SERVER:
                    extension = "src=%s spt=%s dst=%s dpt=%s trail=%s ref=%s" % (event.packet.src_ip, event.packet.src_port, event.packet.dst_ip, event.packet.dst_port, event.trail, event.reference)
                    _ = CEF_FORMAT.format(syslog_time=time.strftime("%b %d %H:%M:%S", time.localtime(int(event.packet.sec))), host=HOSTNAME, device_vendor=NAME, device_product="sensor", device_version=VERSION, signature_id=time.strftime("%Y-%m-%d", time.localtime(os.path.getctime(TRAILS_FILE))), name=event.info, severity=0, extension=extension)
                    remote_host, remote_port = config.SYSLOG_SERVER.split(':')
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(_, (remote_host, int(remote_port)))

                if config.DISABLE_LOCAL_LOG_STORAGE and not any(config.LOG_SERVER, config.SYSLOG_SERVER) or config.console:
                    sys.stderr.write(event_log_entry)
                    sys.stderr.flush()
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

def log_error(msg):
    try:
        handle = get_error_log_handle()
        os.write(handle, "%s %s\n" % (time.strftime(TIME_FORMAT, time.localtime()), msg))
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
                handle = get_event_log_handle(int(sec), reuse=False)
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
