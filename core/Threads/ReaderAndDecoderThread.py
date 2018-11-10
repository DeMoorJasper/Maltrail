#!/usr/bin/env python

import pcapy
import socket
import traceback
import time
import click
import multiprocessing

from core.settings import config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from core.Threads.ProcessorThread import packet_queue

reader_end_of_file = multiprocessing.Event()
exit_reader_and_decoder_thread = multiprocessing.Event()
read_count = multiprocessing.Value('L', 0)

class ReaderAndDecoderThread(multiprocessing.Process):
    def __init__(self, cap_stream):
        multiprocessing.Process.__init__(self)
        self.cap_stream = cap_stream
        self.datalink = cap_stream.datalink()

        if pcapy.DLT_EN10MB == self.datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == self.datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % self.datalink)

    def run(self):
        global read_count

        while True:
            success = False
            try:
                # Quit reader (Keyboardinterrupt)
                if exit_reader_and_decoder_thread.is_set():
                    break

                (header, packet) = self.cap_stream.next()
                if header is not None:
                    success = True
                    sec, usec = header.getts()

                    packet_queue.put((sec, usec, self.decoder.decode(packet)))
                    
                    with read_count.get_lock():
                        read_count.value += 1
                    
                elif config.pcap_file:
                    reader_end_of_file.set()
                    break
            
            except (pcapy.PcapError, socket.timeout):
                traceback.print_exc()
                pass
            
            except KeyboardInterrupt:
                break

            if not success:
                time.sleep(REGULAR_SENSOR_SLEEP_TIME)
