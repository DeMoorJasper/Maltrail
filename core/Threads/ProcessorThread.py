#!/usr/bin/env python

import Queue
import traceback
import threading
import click

from core.process_package import process_packet
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.Threads.status import status_lines

packet_queue = Queue.Queue(maxsize=500)
exit_processor_thread = threading.Event()

class ProcessorThread(threading.Thread):
    def __init__(self, packet_queue, event_queue):
        threading.Thread.__init__(self)
        self.packet_queue = packet_queue
        self.event_queue = event_queue
        self.packet_count = 0
        return

    def process_queue(self):
        sec, usec, packet = self.packet_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)

        event = None

        try:
            event = process_packet(packet, sec, usec)
            
        except Exception:
            traceback.print_exc()
            pass
            
        if event:
            self.event_queue.put(event)

        self.packet_count += 1
        status_lines['packets_processed'] = click.style('Packets processed: ', fg='green') + click.style(str(self.packet_count), fg='white')
    
    def run(self):
        # Listen for packets and process them
        while True:
            try:
                self.process_queue()
            except Queue.Empty:
                if exit_processor_thread.is_set():
                    break
                pass
            except KeyboardInterrupt:
                break