#!/usr/bin/env python

import Queue
import traceback
import click
import multiprocessing

from core.process_package import process_packet
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.Threads.EventThread import event_queue

packet_queue = multiprocessing.Queue(maxsize=500)
exit_processor_thread = multiprocessing.Event()
packet_count = multiprocessing.Value('L', 0)

class ProcessorThread(multiprocessing.Process):
    def __init__(self):
        multiprocessing.Process.__init__(self)

        self.packet_queue = packet_queue
    
    def run(self):
        global packet_count

        # Listen for packets and process them
        while True:
            try:
                sec, usec, packet = self.packet_queue.get(True, REGULAR_SENSOR_SLEEP_TIME)
                event = None
                
                try:
                    event = process_packet(packet, sec, usec)
                    
                except Exception:
                    traceback.print_exc()
                    pass
                    
                if event:
                    event_queue.put(event)
                
                with packet_count.get_lock():
                    packet_count.value += 1

            except Queue.Empty:
                if exit_processor_thread.is_set():
                    break
                pass
            except KeyboardInterrupt:
                break