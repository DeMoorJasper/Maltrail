#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import signal

from core.logging.logger import log_error

def set_sigterm_handler():
    def handler(signum, frame):
        log_error("SIGTERM")
        raise SystemExit

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)

if __name__ != "__main__":
    set_sigterm_handler()
