import multiprocessing
import logging
import os
import datetime

from core.settings import config
from core.utils.timestamp import get_current_timestamp
from core.utils.ColoredLogger import ColoredLogger

log_queue = multiprocessing.Queue()

# logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')

logging.setLoggerClass(ColoredLogger)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def init_file_loggers():
    global logger

    log_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    error_formatter = logging.Formatter('[%(asctime)s]: %(message)s', datefmt='%d-%b-%y %H:%M:%S')

    error_file_location = os.path.join(config.LOG_DIR, 'error-' + get_current_timestamp() + '.log')

    error_handler = logging.FileHandler(filename=error_file_location)
    error_handler.setFormatter(error_formatter)
    error_handler.setLevel(logging.ERROR)

    logger.addHandler(error_handler)
    
    if config.SHOW_DEBUG:
        print('create debug handler')
        debug_file_location = os.path.join(config.LOG_DIR, 'debug-' + get_current_timestamp() + '.log')
        error_handler.setLevel(logging.DEBUG)

        debug_file_handler = logging.FileHandler(filename=debug_file_location)
        debug_file_handler.setLevel(logging.DEBUG)
        debug_file_handler.setFormatter(log_formatter)

        logger.addHandler(debug_file_handler)
    else:
        logger.setLevel(logging.INFO)
        

def _join_args(args):
    return ' '.join(map(str, args))

def debug(*args):
    log(logging.DEBUG, args)

def info(*args):
    log(logging.INFO, args)

def warning(*args):
    log(logging.WARNING, args)

def error(*args):
    log(logging.ERROR, args)

def critical(*args):
    log(logging.CRITICAL, args)

def log_listener():
    while True:
        try:
            level, args = log_queue.get()
            log(level, args)
        except KeyboardInterrupt:
            break

def log(level, args):
    if (multiprocessing.current_process().name == 'MainProcess'):
        message = _join_args(args)
        
        logger.log(level, message)
    else:
        log_queue.put((level, args))
        