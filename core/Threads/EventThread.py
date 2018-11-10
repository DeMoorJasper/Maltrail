#!/usr/bin/env python

import Queue
import click
import threading
import multiprocessing

from core.events.emit import emit_event
from core.settings import REGULAR_SENSOR_SLEEP_TIME

event_queue = multiprocessing.Queue(maxsize=500)
exit_event_thread = threading.Event()
event_count = 0

class EventThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        global event_count

        while True:
            try:
                event = event_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)
                emit_event(event)
                
                event_count += 1

            except Queue.Empty:
                if exit_event_thread.is_set():
                    break
                pass
                
            except KeyboardInterrupt:
                break