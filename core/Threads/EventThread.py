#!/usr/bin/env python

import Queue
import click
import multiprocessing

from core.events.emit import emit_event
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.Threads.StatusThread import status_queue

event_queue = multiprocessing.Queue(maxsize=500)
exit_event_thread = multiprocessing.Event()

class EventThread(multiprocessing.Process):
    def __init__(self):
        multiprocessing.Process.__init__(self)
        self.event_count = 0
        
    def run(self):
        while True:
            try:
                event = event_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)
                emit_event(event)
                
                self.event_count += 1
                status_queue.put(('events', self.event_count))

            except Queue.Empty:
                if exit_event_thread.is_set():
                    break
                pass
                
            except KeyboardInterrupt:
                break