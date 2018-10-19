#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import re
import subprocess
import urllib2

from core.net.addr import addr_to_int
from core.net.addr import make_mask
from core.attribdict import AttribDict
from core.trails.trailsdict import TrailsDict
from core.logging.logger import log_warning
from core.logging.logger import log_info
from core.config.constants import CPU_CORES
from core.config.constants import NAME
from core.config.constants import ROOT_DIR
from core.config.constants import BLOCK_LENGTH
from core.utils.memory import get_total_physmem

config = AttribDict()
trails = TrailsDict()

WHITELIST = set()
WHITELIST_RANGES = set()
IGNORE_EVENTS = set()
WEB_SHELLS = set()
WORST_ASNS = {}
CDN_RANGES = {}
BOGON_RANGES = {}
PROXIES = {}
SUSPICIOUS_UA_REGEX = ""

def read_config(config_file):
    global config

    if not os.path.isfile(config_file):
        exit("missing configuration file '%s'" % config_file)
    else:
        log_info("using configuration file '%s'" % config_file)

    config.clear()

    try:
        array = None
        content = open(config_file, "rb").read()

        for line in content.split("\n"):
            line = line.strip('\r')
            line = re.sub(r"\s*#.*", "", line)
            if not line.strip():
                continue

            if line.count(' ') == 0:
                if re.search(r"[^\w]", line):
                    if array == "USERS":
                        exit("[!] invalid USERS entry '%s'\n[?] (hint: add whitespace at start of line)" % line)
                    else:
                        exit("[!] invalid configuration (line: '%s')" % line)
                array = line.upper()
                config[array] = []
                continue

            if array and line.startswith(' '):
                config[array].append(line.strip())
                continue
            else:
                array = None
                try:
                    name, value = line.strip().split(' ', 1)
                except ValueError:
                    name = line
                    value = ""
                finally:
                    name = name.strip().upper()
                    value = value.strip("'\"").strip()

            _ = os.environ.get("%s_%s" % (NAME.upper(), name))
            if _:
                value = _

            if any(name.startswith(_) for _ in ("USE_", "SET_", "CHECK_", "ENABLE_", "SHOW_", "DISABLE_")):
                value = value.lower() in ("1", "true")
            elif value.isdigit():
                value = int(value)
            else:
                for match in re.finditer(r"\$([A-Z0-9_]+)", value):
                    if match.group(1) in globals():
                        value = value.replace(match.group(0), str(globals()[match.group(1)]))
                    else:
                        value = value.replace(match.group(0), os.environ.get(match.group(1), match.group(0)))
                if name.endswith("_DIR"):
                    value = os.path.realpath(os.path.join(ROOT_DIR, os.path.expanduser(value)))

            config[name] = value

    except (IOError, OSError):
        pass

    for option in ("MONITOR_INTERFACE", "CAPTURE_BUFFER", "LOG_DIR"):
        if not option in config:
            exit("[!] missing mandatory option '%s' in configuration file '%s'" % (option, config_file))

    for entry in (config.USERS or []):
        if len(entry.split(':')) != 4:
            exit("[!] invalid USERS entry '%s'" % entry)
        if re.search(r"\$\d+\$", entry):
            exit("[!] invalid USERS entry '%s'\n[?] (hint: please update PBKDF2 hashes to SHA256 in your configuration file)" % entry)

    if config.SSL_PEM:
        config.SSL_PEM = config.SSL_PEM.replace('/', os.sep)

    if config.USER_WHITELIST:
        if ',' in config.USER_WHITELIST:
            log_warning("configuration value 'USER_WHITELIST' has been changed. Please use it to set location of whitelist file")
        elif not os.path.isfile(config.USER_WHITELIST):
            exit("[!] missing 'USER_WHITELIST' file '%s'" % config.USER_WHITELIST)
        else:
            read_whitelist()
            
    if config.USER_IGNORELIST:
        if not os.path.isfile(config.USER_IGNORELIST):
            exit("[!] missing 'USER_IGNORELIST' file '%s'" % config.USER_IGNORELIST)
        else:
            read_ignorelist()
            
    config.PROCESS_COUNT = int(config.PROCESS_COUNT or CPU_CORES)

    if config.USE_MULTIPROCESSING:
        log_warning("configuration switch 'USE_MULTIPROCESSING' is deprecated. Please use 'PROCESS_COUNT' instead")

    if config.DISABLE_LOCAL_LOG_STORAGE and not any((config.LOG_SERVER, config.SYSLOG_SERVER)):
        log_warning("configuration switch 'DISABLE_LOCAL_LOG_STORAGE' turned on and neither option 'LOG_SERVER' nor 'SYSLOG_SERVER' are set. Falling back to console output of event data")

    if config.UDP_ADDRESS is not None and config.UDP_PORT is None:
        exit("[!] usage of configuration value 'UDP_ADDRESS' requires also usage of 'UDP_PORT'")

    if config.UDP_ADDRESS is None and config.UDP_PORT is not None:
        exit("[!] usage of configuration value 'UDP_PORT' requires also usage of 'UDP_ADDRESS'")

    if not str(config.HTTP_PORT or "").isdigit():
        exit("[!] invalid configuration value for 'HTTP_PORT' ('%s')" % config.HTTP_PORT)

    if config.PROCESS_COUNT and subprocess.mswindows:
        log_warning("multiprocessing is currently not supported on Windows OS")
        config.PROCESS_COUNT = 1

    if config.CAPTURE_BUFFER:
        if str(config.CAPTURE_BUFFER or "").isdigit():
            config.CAPTURE_BUFFER = int(config.CAPTURE_BUFFER)
        elif re.search(r"\d+\s*[kKmMgG]B", config.CAPTURE_BUFFER):
            match = re.search(r"(\d+)\s*([kKmMgG])B", config.CAPTURE_BUFFER)
            config.CAPTURE_BUFFER = int(match.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[match.group(2).upper()]
        elif re.search(r"\d+%", config.CAPTURE_BUFFER):
            physmem = get_total_physmem()

            if physmem:
                config.CAPTURE_BUFFER = physmem * int(re.search(r"(\d+)%", config.CAPTURE_BUFFER).group(1)) / 100
            else:
                exit("[!] unable to determine total physical memory. Please use absolute value for 'CAPTURE_BUFFER'")
        else:
            exit("[!] invalid configuration value for 'CAPTURE_BUFFER' ('%s')" % config.CAPTURE_BUFFER)

        config.CAPTURE_BUFFER = config.CAPTURE_BUFFER / BLOCK_LENGTH * BLOCK_LENGTH

    if config.PROXY_ADDRESS:
        PROXIES.update({"http": config.PROXY_ADDRESS, "https": config.PROXY_ADDRESS})
        opener = urllib2.build_opener(urllib2.ProxyHandler(PROXIES))
        urllib2.install_opener(opener)

def read_whitelist():
    WHITELIST.clear()
    WHITELIST_RANGES.clear()

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "whitelist.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line):
                    try:
                        prefix, mask = line.split('/')
                        WHITELIST_RANGES.add((addr_to_int(prefix), make_mask(int(mask))))
                    except (IndexError, ValueError):
                        WHITELIST.add(line)
                else:
                    WHITELIST.add(line)

    if config.USER_WHITELIST and os.path.isfile(config.USER_WHITELIST):
        with open(config.USER_WHITELIST, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line):
                    try:
                        prefix, mask = line.split('/')
                        WHITELIST_RANGES.add((addr_to_int(prefix), make_mask(int(mask))))
                    except (IndexError, ValueError):
                        WHITELIST.add(line)
                else:
                    WHITELIST.add(line)
                    
# add rules to ignore event list from passed file                
def add_ignorelist(filepath):
    if filepath and os.path.isfile(filepath):         
        with open(filepath, "r") as f:
            for line in f:
                line = re.sub(r"\s+", "", line)

                if not line or line.startswith('#'):
                    continue
                elif line.count(';') == 3:
                    src_ip, src_port, dst_ip, dst_port = line.split(';')
                    IGNORE_EVENTS.add((src_ip, src_port, dst_ip, dst_port))

def read_ignorelist():
    IGNORE_EVENTS.clear()
    
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "ignore_events.txt"))
    add_ignorelist(_)
                        
    if config.USER_IGNORELIST and os.path.isfile(config.USER_IGNORELIST):
        add_ignorelist(config.USER_IGNORELIST)  
    
def read_ua():
    global SUSPICIOUS_UA_REGEX

    SUSPICIOUS_UA_REGEX = ""
    items = []

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "ua.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    items.append(line)

    if items:
        SUSPICIOUS_UA_REGEX = "(?i)%s" % '|'.join(items)

def read_web_shells():
    WEB_SHELLS.clear()

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "web_shells.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    WEB_SHELLS.add(line)

def read_worst_asn():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "worst_asns.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in WORST_ASNS:
                        WORST_ASNS[key] = []
                    prefix, mask, name = re.search(r"([\d.]+)/(\d+),(.+)", line).groups()
                    WORST_ASNS[key].append((addr_to_int(prefix), make_mask(int(mask)), name))

def read_cdn_ranges():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "cdn_ranges.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in CDN_RANGES:
                        CDN_RANGES[key] = []
                    prefix, mask = line.split('/')
                    CDN_RANGES[key].append((addr_to_int(prefix), make_mask(int(mask))))

def read_bogon_ranges():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "bogon_ranges.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in BOGON_RANGES:
                        BOGON_RANGES[key] = []
                    prefix, mask = line.split('/')
                    BOGON_RANGES[key].append((addr_to_int(prefix), make_mask(int(mask))))

if __name__ != "__main__":
    read_whitelist()
    read_ignorelist()
    read_ua()
    read_web_shells()
    read_worst_asn()
    read_cdn_ranges()
    read_bogon_ranges()
