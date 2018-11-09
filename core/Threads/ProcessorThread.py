#!/usr/bin/env python

import Queue
import traceback
import click
import multiprocessing

from core.process_package import process_packet
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.Threads.StatusThread import status_queue
from core.Threads.EventThread import event_queue

packet_queue = multiprocessing.Queue(maxsize=500)
exit_processor_thread = multiprocessing.Event()

class ProcessorThread(multiprocessing.Process):
    def __init__(self):
        multiprocessing.Process.__init__(self)

        self.packet_queue = packet_queue
        self.packet_count = 0

    def process_queue(self):
        sec, usec, packet = self.packet_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)

        event = None

        try:
            event = process_packet(packet, sec, usec)
            
        except Exception:
            traceback.print_exc()
            pass
            
        if event:
            event_queue.put(event)
        
        self.packet_count += 1
        status_queue.put(('processed', self.packet_count))
    
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