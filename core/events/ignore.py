#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

# simple ignore rule mechanism configured by file 'misc/ignore_event.txt' and/or user defined `USER_IGNORELIST`

from core.config.settings import config
from core.config.settings import IGNORE_EVENTS
from core.logging.logger import log_info

def ignore_event(event):
    retval = False

    for ignore_src_ip, ignore_src_port, ignore_dst_ip, ignore_dst_port in IGNORE_EVENTS:
        if ignore_src_ip != '*' and ignore_src_ip != event.packet.src_ip :
            continue
        if ignore_src_port != '*' and ignore_src_port != str(event.packet.src_port) :
            continue
        if ignore_dst_ip != '*' and ignore_dst_ip != event.packet.dst_ip :
            continue
        if ignore_dst_port != '*' and ignore_dst_port != str(event.packet.dst_port) :
            continue
        retval = True
        break

    if retval and config.SHOW_DEBUG:
        log_info("ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s" % (event.packet.src_ip, event.packet.src_port, event.packet.dst_ip, event.packet.dst_port)) 

    return retval
