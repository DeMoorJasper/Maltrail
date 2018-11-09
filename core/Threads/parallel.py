#!/usr/bin/env python

from core.Threads.ReaderAndDecoderThread import exit_reader_and_decoder_thread
from core.Threads.ProcessorThread import ProcessorThread, exit_processor_thread
from core.Threads.EventThread import EventThread, exit_event_thread
from core.Threads.StatusThread import StatusThread, print_status
from core.logging.logger import log_info

processor_thread = None
event_thread = None

def init_threads():
    global processor_thread
    global event_thread

    status_thread = StatusThread()
    status_thread.daemon = True
    status_thread.start()

    print_status()

    processor_thread = ProcessorThread()
    processor_thread.start()

    event_thread = EventThread()
    event_thread.start()
    
def stop_threads():
    # Stop reader
    log_info('Stopping reader and decoder thread...')
    exit_reader_and_decoder_thread.set()

    # Stop processing thread
    log_info('Stopping processing thread...')
    exit_processor_thread.set()
    processor_thread.join()

    # Stop event thread
    log_info('Stopping logger thread...')
    exit_event_thread.set()
    event_thread.join()
