#!/usr/bin/env python

import core.logger as logger
import threading

from core.Threads.ReaderAndDecoderThread import exit_reader_and_decoder_thread
from core.Threads.ProcessorThread import ProcessorThread, exit_processor_thread
from core.Threads.EventThread import EventThread, exit_event_thread

processor_thread = None
event_thread = None

def init_threads():
    global processor_thread
    global event_thread

    logger_thread = threading.Thread(target=logger.log_listener)
    logger_thread.daemon = True
    logger_thread.start()

    processor_thread = ProcessorThread()
    processor_thread.start()

    event_thread = EventThread()
    event_thread.start()
    
def stop_threads():
    # Stop reader
    logger.info('Stopping reader and decoder thread...')
    exit_reader_and_decoder_thread.set()

    # Stop processing thread
    logger.info('Stopping processing thread...')
    exit_processor_thread.set()
    processor_thread.join()

    # Stop event thread
    logger.info('Stopping logger thread...')
    exit_event_thread.set()
    event_thread.join()
