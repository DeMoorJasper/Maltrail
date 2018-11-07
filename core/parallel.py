#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import struct
import threading
import time
import pcapy
import multiprocessing
import Queue

from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.settings import BLOCK_LENGTH
from core.settings import config
from core.settings import LOAD_TRAILS_RETRY_SLEEP_TIME
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SHORT_SENSOR_SLEEP_TIME
from core.settings import trails
from core.settings import TRAILS_FILE
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from multiprocessing import Queue as processQueue
from core.process_package import process_packet

q = processQueue()
_processes = []

class Worker(multiprocessing.Process):
    def __init__(self, q, process_packet,):
        multiprocessing.Process.__init__(self)
        self.exit = multiprocessing.Event()

    def run(self):
        def update_timer():
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
            threading.Timer(config.UPDATE_PERIOD, update_timer).start()

        update_timer()

        while True:
            try:
                try:
                    sec, usec, datalink, packet = q.get(True, 1)

                    decoder = None
                    if pcapy.DLT_EN10MB == datalink:
                        decoder = EthDecoder()
                    elif pcapy.DLT_LINUX_SLL == datalink:
                        decoder = LinuxSLLDecoder()
                    else:
                        raise Exception("Datalink type not supported: " % datalink)
                        
                    process_packet(decoder.decode(packet), sec, usec)

                except Queue.Empty:
                    if self.exit.is_set():
                        break
                    pass

                except IndexError:
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

def init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    for _ in xrange(config.PROCESS_COUNT - 1):
        process = Worker(q, process_packet)
        process.daemon = True
        process.start()
        _processes.append(process)
