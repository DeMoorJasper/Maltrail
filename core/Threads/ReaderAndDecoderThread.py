#!/usr/bin/env python

import Queue
import threading
import pcapy
import socket
import traceback
import time
import click

from core.settings import config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
from core.Threads.status import status_lines

reader_end_of_file = threading.Event()
exit_reader_and_decoder_thread = threading.Event()

class ReaderAndDecoderThread(threading.Thread):
    def __init__(self, cap_stream, packet_queue):
        threading.Thread.__init__(self)
        self.cap_stream = cap_stream
        self.datalink = cap_stream.datalink()
        self.packet_queue = packet_queue
        self.read_count = 0

        if pcapy.DLT_EN10MB == self.datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == self.datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % self.datalink)
        
        return

    def process_queue(self):
        return

    def run(self):
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
                    self.packet_queue.put((sec, usec, self.decoder.decode(packet)))
                    self.read_count += 1
                    status_lines[4] = click.style('Packets read: ', fg='green') + click.style(str(self.read_count), fg='white')
                    
                elif config.pcap_file:
                    reader_end_of_file.set()
                    break
            
            except (pcapy.PcapError, socket.timeout):
                traceback.print_exc()
                pass

            if not success:
                time.sleep(REGULAR_SENSOR_SLEEP_TIME)
