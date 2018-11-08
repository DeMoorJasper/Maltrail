#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import struct
import time
import pcapy
import multiprocessing
import Queue
import threading
import traceback

from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.settings import CPU_CORES, LOAD_TRAILS_RETRY_SLEEP_TIME, REGULAR_SENSOR_SLEEP_TIME, TRAILS_FILE
from core.settings import config, trails
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from multiprocessing import Queue as processQueue, Lock, Array as SynchronizedArray
from core.process_package import process_packet
from core.events.emit import emit_event
from core.logging.logger import log_info

q = processQueue(CPU_CORES * 50)
_processes = []

class Worker(multiprocessing.Process):
    def __init__(self, q, process_packet, last_finished_packet,):
        multiprocessing.Process.__init__(self)
        self.exit = multiprocessing.Event()
        self.last_finished_packet = last_finished_packet

    def update_timer(self):
        if (time.time() - os.stat(TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD:
            _ = None
            while True:
                _ = load_trails(True)
                if _:
                    trails.clear()
                    trails.update(_)
                    break
                else:
                    time.sleep(LOAD_TRAILS_RETRY_SLEEP_TIME)

        threading.Timer(config.UPDATE_PERIOD, self.update_timer).start()

    def process_queue(self):
        try:
            (streamId, packet_id), sec, usec, datalink, packet = q.get(True, 1)

            event = None
            decoder = None

            try:
                if pcapy.DLT_EN10MB == datalink:
                    decoder = EthDecoder()
                elif pcapy.DLT_LINUX_SLL == datalink:
                    decoder = LinuxSLLDecoder()
                else:
                    raise Exception("Datalink type not supported: " % datalink)
                            
                event = process_packet(decoder.decode(packet), sec, usec)

            except Exception:
                traceback.print_exc()
                pass
                    
            while True:
                if not (self.last_finished_packet[streamId] + 1 == packet_id):
                    continue
                        
                self.last_finished_packet[streamId] = packet_id
                        
                if event:
                    emit_event(event)

                break

        except Exception:
            traceback.print_exc()
            pass

    def run(self):
        # Register timer to update trails
        self.update_timer()

        # Listen for packets and process them
        while True:
            try:
                self.process_queue()
            except Queue.Empty:
                if self.exit.is_set():
                    print('Queue is empty, exiting thread.')
                    break
                pass
            except KeyboardInterrupt:
                break

    def shutdown(self):
        self.exit.set()

def stop_multiprocessing():
    for process in _processes:
        process.shutdown()

    while multiprocessing.active_children():
        time.sleep(REGULAR_SENSOR_SLEEP_TIME)

def show_progress(last_finished_packet, stream_count):
    threading.Timer(1, show_progress, [last_finished_packet, stream_count]).start()
    for cap_stream_id in range(0, stream_count):
        log_info('Progress INTERFACE: ' + str(cap_stream_id) + ' PACKET:' + str(last_finished_packet[cap_stream_id]))

def init_multiprocessing(stream_count, threadCount):
    """
    Inits worker processes used in multiprocessing mode
    """

    last_finished_packet = SynchronizedArray('L', range(stream_count))
    
    for _ in xrange(threadCount):
        process = Worker(q, process_packet, last_finished_packet, )
        process.daemon = True
        process.start()
        _processes.append(process)
    
    if config.SHOW_DEBUG:
        show_progress(last_finished_packet, stream_count)
