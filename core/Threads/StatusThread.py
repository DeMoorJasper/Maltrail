#!/usr/bin/env python

import threading

from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.logging.logger import log_info
from core.Threads.EventThread import event_count
from core.Threads.ProcessorThread import packet_count
from core.Threads.ReaderAndDecoderThread import read_count

def print_status():
    threading.Timer(5, print_status, []).start()
    status_msg = 'PROGRESS: ' + str(read_count.value) + ' QUEUED | ' + str(packet_count.value) + ' PROCESSED | ' + str(event_count) + ' EVENTS'
    log_info(status_msg)
