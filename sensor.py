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
from core.logging.file_log import create_log_directory
from core.logging.file_log import get_error_log_handle
from core.logging.log import log_error
from core.parallel import q, init_multiprocessing, stop_multiprocessing
from core.utils.memory import check_memory
from core.settings import config
from core.settings import CAPTURE_TIMEOUT
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import DLT_OFFSETS
from core.settings import HTTP_TIME_FORMAT
from core.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.settings import NAME
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import trails
from core.settings import TRAILS_FILE
from core.settings import VERSION
from core.settings import DEFAULT_PLUGINS
from core.trails.update import update_ipcat
from core.trails.update import update_trails
from core.plugins.load_plugins import load_plugins
from core.plugins.load_triggers import load_triggers
from core.logging.logger import log_info, log_error
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

_caps = []
_count = 0
_locks = AttribDict()
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

    create_log_directory(config.LOG_DIR)
    get_error_log_handle(config.LOG_DIR)

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

    if config.triggers:
        log_info("Loading triggers:", config.triggers)
        config.trigger_functions = load_triggers(config.triggers)

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

    log_info("creating %d more processes (out of total %d)" % (config.PROCESS_COUNT - 1, config.PROCESS_COUNT))
    init_multiprocessing()
        

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    log_info("running...")

    def packet_handler(datalink, header, packet):
        try:
            sec, usec = header.getts()

            if _locks.count:
                _locks.count.acquire()
                    
            q.put((sec, usec, datalink, packet))

            if _locks.count:
                _locks.count.release()

        except socket.timeout:
            pass

    try:
        def _(_cap):
            datalink = _cap.datalink()
            while True:
                # print('process packet')
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
        log_info("Captures added to queue")
        try:
            stop_multiprocessing()
            log_info("Processing complete.")
        except KeyboardInterrupt:
            pass
            

def main():
    log_info("%s (sensor) #v%s" % (NAME, VERSION))

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_option("-i", dest="pcap_file", help="open pcap file for offline analysis")
    parser.add_option("--console", dest="console", action="store_true", help="print events to console (too)")
    parser.add_option("--no-updates", dest="no_updates", action="store_true", help="disable (online) trail updates")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    options, _ = parser.parse_args()

    if not check_sudo():
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

    read_config(options.config_file)

    config.plugins = DEFAULT_PLUGINS
    
    if config.PLUGINS:
        config.plugins += re.split(r"[,;]", config.PLUGINS)

    config.triggers = []
    
    if config.TRIGGERS:
        config.triggers += re.split(r"[,;]", config.TRIGGERS)

    for option in dir(options):
        if isinstance(getattr(options, option), (basestring, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)

    if options.debug:
        config.console = True
        config.SHOW_DEBUG = True
        # config.PROCESS_COUNT = 1

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
