import threading
import time
import os
import stat

_thread_data = threading.local()

DEFAULT_EVENT_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
DEFAULT_ERROR_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH

def event_throttle(event, process_count):
    current_bucket = event.packet.sec / process_count
    if getattr(_thread_data, "log_bucket", None) != current_bucket:  # log throttling
        _thread_data.log_bucket = current_bucket
        _thread_data.log_trails = set()
    else:
        if any(_ in _thread_data.log_trails for _ in ((event.packet.src_ip, event.trail), (event.packet.dst_ip, event.trail))):
            return
        else:
            _thread_data.log_trails.add((event.packet.src_ip, event.trail))
            _thread_data.log_trails.add((event.packet.dst_ip, event.trail))

def get_event_log_handle(log_dir, sec, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY, reuse=True):
    retval = None
    localtime = time.localtime(sec)

    _ = os.path.join(log_dir, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))

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

def get_error_log_handle(log_dir, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    if not hasattr(_thread_data, "error_log_handle"):
        _ = os.path.join(log_dir, "error.log")
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_ERROR_LOG_PERMISSIONS)
        _thread_data.error_log_path = _
        _thread_data.error_log_handle = os.open(_thread_data.error_log_path, flags)
    return _thread_data.error_log_handle
