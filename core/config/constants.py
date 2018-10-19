import os
import sys
import urllib
import socket
import stat
import string
import subprocess

NAME = "Maltrail"
VERSION = "0.10.475"
DATE_FORMAT = "%Y-%m-%d"
ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
USERS_DIR = os.path.join(os.path.expanduser("~"), ".%s" % NAME.lower())
CHECK_CONNECTION_MAX_RETRIES = 3
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
HTTP_DEFAULT_PORT = 8338
HTTP_TIME_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"  # Reference: http://stackoverflow.com/a/225106
SNAP_LEN = 2000
BLOCK_LENGTH = 1 + 2 + 4 + 4 + 4 + SNAP_LEN  # primitive mutex + short for packet size + int for sec + int for usec + int for IP offset + max packet size
SHORT_SENSOR_SLEEP_TIME = 0.00001
REGULAR_SENSOR_SLEEP_TIME = 0.001
NO_BLOCK = -1
END_BLOCK = -2
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
CAPTURE_TIMEOUT = 100  # ms
CONFIG_FILE = os.path.join(ROOT_DIR, "maltrail.conf")
SYSTEM_LOG_DIR = "/var/log" if not subprocess.mswindows else "C:\\Windows\\Logs"
HOSTNAME = socket.gethostname()
IGNORE_DNS_QUERY_SUFFIXES = (".arpa", ".local", ".guest")
OBSOLETE_UA_REGEX = r"(?i)windows NT [3-5]\.\d+|windows (3\.\d+|95|98|xp)|MSIE [1-6]\.\d+|Navigator/|Safari/[1-4]|Opera/[1-3]|Firefox/1?[0-9]\."
DEFLATE_COMPRESS_LEVEL = 9
PORT_SCANNING_THRESHOLD = 10
MMAP_ZFILL_CHUNK_LENGTH = 1024 * 1024
DAILY_SECS = 24 * 60 * 60
DEFAULT_PLUGINS = ["check_domain", "ip_check", "tcp_syn", "tcp", "udp"]

# Reference: https://gist.github.com/ryanwitt/588678
DLT_OFFSETS = { 0: 4, 1: 14, 6: 22, 7: 6, 8: 16, 9: 4, 10: 21, 117: 48, 18: 4, 12 if sys.platform.find('openbsd') != -1 else 108: 4, 14 if sys.platform.find('openbsd') != -1 else 12: 0, 113: 16 }

try:
    import multiprocessing
    CPU_CORES = multiprocessing.cpu_count()
except ImportError:
    CPU_CORES = 1