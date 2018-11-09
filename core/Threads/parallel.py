#!/usr/bin/env python

from core.Threads.ReaderAndDecoderThread import exit_reader_and_decoder_thread
from core.Threads.ProcessorThread import ProcessorThread, packet_queue, exit_processor_thread
from core.Threads.EventThread import EventThread, event_queue, exit_event_thread

processor_thread = None
event_thread = None

def init_threads():
    global processor_thread
    global event_thread

    processor_thread = ProcessorThread(packet_queue, event_queue)
    processor_thread.start()

    event_thread = EventThread(event_queue)
    event_thread.start()
    
def stop_threads():
    # Stop reader
    exit_reader_and_decoder_thread.set()

    # Stop processing thread
    exit_processor_thread.set()
    processor_thread.join()

    # Stop event thread
    exit_event_thread.set()
    event_thread.join()
    
    return
