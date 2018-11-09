#!/usr/bin/env python

import Queue
import multiprocessing
import threading

from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.logging.logger import log_info

status_queue = multiprocessing.Queue(maxsize=500)
status_msg = 'PROGRESS: 0 QUEUED | 0 PROCESSED | 0 EVENTS'

def print_status():
    threading.Timer(5, print_status, []).start()
    log_info(status_msg)

class StatusThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.counts = {
            'queued': 0,
            'processed': 0,
            'events': 0
        }
        
    def run(self):
        global status_msg

        while True:
            try:
                count_type, count = status_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)
                self.counts[count_type] = count
                status_msg = 'PROGRESS: ' + str(self.counts['queued']) + ' QUEUED | ' + str(self.counts['processed']) + ' PROCESSED | ' + str(self.counts['events']) + ' EVENTS'
                
            except Queue.Empty:
                pass
                
            except KeyboardInterrupt:
                break
