#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import sys

sys.dont_write_bytecode = True

import mmap
import optparse
import os
import platform
import re
import socket
import subprocess
import struct
import threading
import time
import traceback

from core.attribdict import AttribDict
from core.common import check_connection
from core.common import check_sudo
from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.logging.log import create_log_directory
from core.logging.log import get_error_log_handle
from core.logging.log import log_error
from core.parallel import worker
from core.parallel import write_block
from core.utils.memory import check_memory
from core.config.settings import config
from core.config.settings import CAPTURE_TIMEOUT
from core.config.settings import CHECK_CONNECTION_MAX_RETRIES
from core.config.settings import CONFIG_FILE
from core.config.settings import DLT_OFFSETS
from core.config.settings import HTTP_TIME_FORMAT
from core.config.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.config.settings import NAME
from core.config.settings import read_config
from core.config.settings import REGULAR_SENSOR_SLEEP_TIME
from core.config.settings import SNAP_LEN
from core.config.settings import trails
from core.config.settings import TRAILS_FILE
from core.config.settings import VERSION
from core.config.settings import DEFAULT_PLUGINS
from core.trails.update import update_ipcat
from core.trails.update import update_trails
from core.config.load_plugins import load_plugins
from core.process_package import process_packet
from core.logging.logger import log_info
from core.logging.logger import log_error

_buffer = None
_caps = []
_connect_sec = 0
_count = 0
_locks = AttribDict()
_multiprocessing = None
_n = None
_quit = threading.Event()

try:
    import pcapy
except ImportError:
    if subprocess.mswindows:
        exit("[!] please install 'WinPcap' (e.g. 'http://www.winpcap.org/install/') and Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy')")
    else:
        msg, _ = "[!] please install 'Pcapy'", platform.linux_distribution()[0].lower()
        for distro, install in {("fedora", "centos"): "sudo yum install pcapy", ("debian", "ubuntu"): "sudo apt-get install python-pcapy"}.items():
            if _ in distro:
                msg += " (e.g. '%s')" % install
                break
        exit(msg)

def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    try:
        import multiprocessing

        if config.PROCESS_COUNT > 1:
            _multiprocessing = multiprocessing
    except (ImportError, OSError, NotImplementedError):
        pass

    def update_timer():
        retries = 0
        if not config.no_updates:
            while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
                sys.stdout.write("[ERROR]: can't update because of lack of Internet connection (waiting..." if not retries else '.')
                sys.stdout.flush()
                time.sleep(10)
                retries += 1

            if retries:
                sys.stdout.write(")\n")

        if config.no_updates or retries == CHECK_CONNECTION_MAX_RETRIES:
            if retries == CHECK_CONNECTION_MAX_RETRIES:
                log_error("going to continue without online update")
            _ = update_trails(offline=True)
        else:
            _ = update_trails(server=config.UPDATE_SERVER)
            update_ipcat()

        if _:
            trails.clear()
            trails.update(_)
        elif not trails:
            trails.update(load_trails())

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    create_log_directory()
    get_error_log_handle()

    check_memory()

    msg = "using '%s' for trail storage" % TRAILS_FILE
    if os.path.isfile(TRAILS_FILE):
        mtime = time.gmtime(os.path.getmtime(TRAILS_FILE))
        msg += " (last modification: '%s')" % time.strftime(HTTP_TIME_FORMAT, mtime)

    log_info(msg)

    update_timer()

    if check_sudo() is False:
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

    if config.plugins is None:
        exit("[!] No plugins defined!")

    log_info("Loading plugins:", config.plugins)
    config.plugin_functions = load_plugins(config.plugins)

    if config.pcap_file:
        _caps.append(pcapy.open_offline(config.pcap_file))
    else:
        interfaces = set(_.strip() for _ in config.MONITOR_INTERFACE.split(','))

        if (config.MONITOR_INTERFACE or "").lower() == "any":
            if subprocess.mswindows or "any" not in pcapy.findalldevs():
                log_error("virtual interface 'any' missing. Replacing it with all interface names")
                interfaces = pcapy.findalldevs()
            else:
                log_info("in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

        for interface in interfaces:
            if interface.lower() != "any" and interface not in pcapy.findalldevs():
                hint = "[?] available interfaces: '%s'" % ",".join(pcapy.findalldevs())
                exit("[!] interface '%s' not found\n%s" % (interface, hint))

            log_info("opening interface '%s'" % interface)
            try:
                _caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
            except (socket.error, pcapy.PcapError):
                if "permitted" in str(sys.exc_info()[1]):
                    exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)
                elif "No such device" in str(sys.exc_info()[1]):
                    exit("[!] no such device '%s'" % interface)
                else:
                    raise

    if config.LOG_SERVER and not len(config.LOG_SERVER.split(':')) == 2:
        exit("[!] invalid configuration value for 'LOG_SERVER' ('%s')" % config.LOG_SERVER)

    if config.SYSLOG_SERVER and not len(config.SYSLOG_SERVER.split(':')) == 2:
        exit("[!] invalid configuration value for 'SYSLOG_SERVER' ('%s')" % config.SYSLOG_SERVER)

    if config.CAPTURE_FILTER:
        log_info("setting capture filter '%s'" % config.CAPTURE_FILTER)
        for _cap in _caps:
            try:
                _cap.setfilter(config.CAPTURE_FILTER)
            except:
                pass

    if _multiprocessing:
        _init_multiprocessing()

    if not subprocess.mswindows and not config.DISABLE_CPU_AFFINITY:
        try:
            try:
                mod = int(subprocess.check_output("grep -c ^processor /proc/cpuinfo", stderr=subprocess.STDOUT, shell=True).strip())
                used = subprocess.check_output("for pid in $(ps aux | grep python | grep sensor.py | grep -E -o 'root[ ]*[0-9]*' | tr -d '[:alpha:] '); do schedtool $pid; done | grep -E -o 'AFFINITY .*' | cut -d ' ' -f 2 | grep -v 0xf", stderr=subprocess.STDOUT, shell=True).strip().split('\n')
                max_used = max(int(_, 16) for _ in used)
                affinity = max(1, (max_used << 1) % 2 ** mod)
            except:
                affinity = 1
            p = subprocess.Popen("schedtool -n -2 -M 2 -p 10 -a 0x%02x %d" % (affinity, os.getpid()), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _, stderr = p.communicate()
            if "not found" in stderr:
                msg, _ = "please install 'schedtool' for better CPU scheduling", platform.linux_distribution()[0].lower()
                for distro, install in {("fedora", "centos"): "sudo yum install schedtool", ("debian", "ubuntu"): "sudo apt-get install schedtool"}.items():
                    if _ in distro:
                        msg += " (e.g. '%s')" % install
                        break
                log_info(msg)
        except:
            pass

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        log_info("preparing capture buffer...")
        try:
            _buffer = mmap.mmap(-1, config.CAPTURE_BUFFER)  # http://www.alexonlinux.com/direct-io-in-python

            _ = "\x00" * MMAP_ZFILL_CHUNK_LENGTH
            for i in xrange(config.CAPTURE_BUFFER / MMAP_ZFILL_CHUNK_LENGTH):
                _buffer.write(_)
            _buffer.seek(0)
        except KeyboardInterrupt:
            raise
        except:
            exit("[!] unable to allocate network capture buffer. Please adjust value of 'CAPTURE_BUFFER'")

        log_info("creating %d more processes (out of total %d)" % (config.PROCESS_COUNT - 1, config.PROCESS_COUNT))
        _n = _multiprocessing.Value('L', lock=False)

        for i in xrange(config.PROCESS_COUNT - 1):
            process = _multiprocessing.Process(target=worker, name=str(i), args=(_buffer, _n, i, config.PROCESS_COUNT - 1, process_packet))
            process.daemon = True
            process.start()

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    log_info("running...")

    def packet_handler(datalink, header, packet):
        global _count

        ip_offset = None
        dlt_offset = DLT_OFFSETS[datalink]

        try:
            if datalink == pcapy.DLT_RAW:
                ip_offset = dlt_offset

            elif datalink == pcapy.DLT_PPP:
                if packet[2:4] in ("\x00\x21", "\x00\x57"):  # (IPv4, IPv6)
                    ip_offset = dlt_offset

            elif dlt_offset >= 2:
                if packet[dlt_offset - 2:dlt_offset] == "\x81\x00":  # VLAN
                    dlt_offset += 4
                if packet[dlt_offset - 2:dlt_offset] in ("\x08\x00", "\x86\xdd"):  # (IPv4, IPv6)
                    ip_offset = dlt_offset

        except IndexError:
            pass

        if ip_offset is None:
            return

        try:
            sec, usec = header.getts()
            if _multiprocessing:
                if _locks.count:
                    _locks.count.acquire()

                write_block(_buffer, _count, struct.pack("=III", sec, usec, ip_offset) + packet)
                _n.value = _count = _count + 1

                if _locks.count:
                    _locks.count.release()
            else:
                process_packet(packet, sec, usec, ip_offset)
        except socket.timeout:
            pass

    try:
        def _(_cap):
            datalink = _cap.datalink()
            while True:
                success = False
                try:
                    (header, packet) = _cap.next()
                    if header is not None:
                        success = True
                        packet_handler(datalink, header, packet)
                    elif config.pcap_file:
                        _quit.set()
                        break
                except (pcapy.PcapError, socket.timeout):
                    pass

                if not success:
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)

        if len(_caps) > 1:
            if _multiprocessing:
                _locks.count = threading.Lock()
            _locks.connect_sec = threading.Lock()

        for _cap in _caps:
            threading.Thread(target=_, args=(_cap,)).start()

        while _caps and not _quit.is_set():
            time.sleep(1)

        log_info("all capturing interfaces closed")
    except SystemError, ex:
        if "error return without" in str(ex):
            log_error("stopping (Ctrl-C pressed)")
        else:
            raise
    except KeyboardInterrupt:
        log_error("stopping (Ctrl-C pressed)")
    finally:
        log_info("please wait...")
        if _multiprocessing:
            try:
                for _ in xrange(config.PROCESS_COUNT - 1):
                    write_block(_buffer, _n.value, "", BLOCK_MARKER.END)
                    _n.value = _n.value + 1
                while _multiprocessing.active_children():
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)
            except KeyboardInterrupt:
                pass

def main():
    log_info("%s (sensor) #v%s" % (NAME, VERSION))

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_option("-i", dest="pcap_file", help="open pcap file for offline analysis")
    parser.add_option("-p", dest="plugins", help="plugin(s) to be used per event")
    parser.add_option("--console", dest="console", action="store_true", help="print events to console (too)")
    parser.add_option("--no-updates", dest="no_updates", action="store_true", help="disable (online) trail updates")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    options, _ = parser.parse_args()

    if not check_sudo():
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

    read_config(options.config_file)

    config.plugins = DEFAULT_PLUGINS

    if config.PLUGINS:
        options.plugins = config.PLUGINS
    
    if options.plugins:
        config.plugins += re.split(r"[,;]", options.plugins)

    for option in dir(options):
        if isinstance(getattr(options, option), (basestring, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)

    if options.debug:
        config.console = True
        config.PROCESS_COUNT = 1
        config.SHOW_DEBUG = True

    if options.pcap_file:
        if options.pcap_file == '-':
            log_info("using STDIN")
        elif not os.path.isfile(options.pcap_file):
            exit("[!] missing pcap file '%s'" % options.pcap_file)
        else:
            log_info("using pcap file '%s'" % options.pcap_file)

    try:
        init()
        monitor()
    except KeyboardInterrupt:
        log_error("stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    show_final = True

    try:
        main()
    except SystemExit, ex:
        show_final = False

        if not isinstance(getattr(ex, "message"), int):
            log_error(ex)
    except IOError:
        show_final = False
        log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
    except Exception:
        msg = "unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\nplease report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        log_error("\n\n%s" % msg.replace("\r", ""))

        log_error(msg)
    finally:
        if show_final:
            log_info("finished")

        os._exit(0)
