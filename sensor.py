#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import subprocess

# Drop windows support as it was buggy anyways
if subprocess.mswindows:
    exit("Windows is currently not supported!")

import sys

sys.dont_write_bytecode = True

import optparse
import os
import platform
import re
import socket
import threading
import time
import traceback
import core.logger as logger

from pyfiglet import Figlet
from core.attribdict import AttribDict
from core.common import check_connection
from core.common import check_sudo
from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.utils.memory import check_memory
from core.settings import config
from core.settings import CAPTURE_TIMEOUT
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import DLT_OFFSETS
from core.settings import HTTP_TIME_FORMAT
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
from core.Threads.parallel import init_threads, stop_threads
from core.Threads.ReaderAndDecoderThread import ReaderAndDecoderThread, reader_end_of_file
from core.Threads.ProcessorThread import packet_queue
from core.utils.Figlet import figlet
from core.Threads.StatusThread import print_status
from core.utils.file_handler import create_log_directory

_caps = []

try:
    import pcapy
except ImportError:
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
                logger.error("going to continue without online update")
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
        thread.start()

    check_memory()

    msg = "using '%s' for trail storage" % TRAILS_FILE
    if os.path.isfile(TRAILS_FILE):
        mtime = time.gmtime(os.path.getmtime(TRAILS_FILE))
        msg += " (last modification: '%s')" % time.strftime(HTTP_TIME_FORMAT, mtime)

    logger.info(msg)

    update_timer()

    if check_sudo() is False:
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

    if config.plugins is None:
        exit("[!] No plugins defined!")

    logger.info("Loading plugins:" + str(config.plugins))
    config.plugin_functions = load_plugins(config.plugins)

    if config.triggers:
        logger.info("Loading triggers:" + str(config.triggers))
        config.trigger_functions = load_triggers(config.triggers)

    if config.pcap_file:
        _caps.append(pcapy.open_offline(config.pcap_file))
    else:
        interfaces = set(_.strip() for _ in config.MONITOR_INTERFACE.split(','))

        if (config.MONITOR_INTERFACE or "").lower() == "any":
            if "any" not in pcapy.findalldevs():
                logger.error("virtual interface 'any' missing. Replacing it with all interface names")
                interfaces = pcapy.findalldevs()
            else:
                logger.info("in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

        for interface in interfaces:
            if interface.lower() != "any" and interface not in pcapy.findalldevs():
                hint = "[?] available interfaces: '%s'" % ",".join(pcapy.findalldevs())
                exit("[!] interface '%s' not found\n%s" % (interface, hint))

            logger.info("opening interface '%s'" % interface)
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
        logger.info("setting capture filter '%s'" % config.CAPTURE_FILTER)
        for _cap in _caps:
            try:
                _cap.setfilter(config.CAPTURE_FILTER)
            except:
                pass
    
    logger.info("Starting processing threads...")

    init_threads()

    logger.info("Threads started...")

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    logger.info("running...")

    print_status()
    
    try:
        for _cap in _caps:
            reader_and_decoder_thread = ReaderAndDecoderThread(_cap)
            reader_and_decoder_thread.daemon = True
            reader_and_decoder_thread.start()

        while _caps and not reader_end_of_file.is_set():
            time.sleep(1)

        logger.info("all capturing interfaces closed")
    except SystemError, ex:
        if "error return without" in str(ex):
            logger.error("stopping (Ctrl-C pressed)")
        else:
            raise
    except KeyboardInterrupt:
        logger.error("stopping (Ctrl-C pressed)")
    finally:
        logger.info("Captures added to queue")
        try:
            stop_threads()
            logger.info("Processing complete.")
        except KeyboardInterrupt:
            pass
            

def main():
    print(figlet)
    
    logger.info("%s (sensor) #v%s" % (NAME, VERSION))

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

    if options.debug:
        config.console = True
        config.SHOW_DEBUG = True
    
    create_log_directory(config.LOG_DIR)

    logger.init_file_loggers()

    config.plugins = DEFAULT_PLUGINS
    
    if config.PLUGINS:
        config.plugins += re.split(r"[,;]", config.PLUGINS)

    config.triggers = []
    
    if config.TRIGGERS:
        config.triggers += re.split(r"[,;]", config.TRIGGERS)

    for option in dir(options):
        if isinstance(getattr(options, option), (basestring, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)

    if options.pcap_file:
        if options.pcap_file == '-':
            logger.info("using STDIN")
        elif not os.path.isfile(options.pcap_file):
            exit("missing pcap file '%s'" % options.pcap_file)
        else:
            logger.info("using pcap file '%s'" % options.pcap_file)

    try:
        init()
        monitor()
    except KeyboardInterrupt:
        logger.error("stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    show_final = True

    try:
        main()
    except SystemExit, ex:
        show_final = False

        if not isinstance(getattr(ex, "message"), int):
            logger.error(ex)
    except IOError:
        show_final = False
        logger.error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
    except Exception:
        msg = "unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\nplease report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        logger.error(msg)
    finally:
        if show_final:
            logger.info("finished")

        os._exit(0)
