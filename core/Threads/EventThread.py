#!/usr/bin/env python

import Queue
import threading
import click

from core.events.emit import emit_event
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.Threads.status import status_lines

event_queue = Queue.Queue(maxsize=500)
exit_event_thread = threading.Event()

class EventThread(threading.Thread):
    def __init__(self, event_queue):
        threading.Thread.__init__(self)
        self.event_queue = event_queue
        self.event_count = 0
        return
        
    def run(self):
        while True:
            try:
                event = self.event_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)
                emit_event(event)
                self.event_count += 1
                status_lines[6] = click.style('Events emitted: ', fg='green') + click.style(str(self.event_count), fg='white')

            except Queue.Empty:
                if exit_event_thread.is_set():
                    break
                pass
            except KeyboardInterrupt:
                break