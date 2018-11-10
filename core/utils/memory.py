import subprocess
import re

# Minimum MEMORY_SIZE = 2GB
MIN_MEMORY_SIZE = 2048 * 1024 * 1024

def get_total_physmem():
    retval = None

    try:
        retval = 1024 * int(re.search(r"(?i)MemTotal:\s+(\d+)\skB", open("/proc/meminfo").read()).group(1))
    except:
        pass

    if not retval:
        try:
            import psutil
            retval = psutil.virtual_memory().total
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"real mem(ory)?\s*=\s*(\d+) ", open("/var/run/dmesg.boot").read()).group(2))
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"hw\.(physmem|memsize):\s*(\d+)", subprocess.check_output("sysctl hw", shell=True, stderr=subprocess.STDOUT)).group(2))
        except:
            pass

    if not retval:
        try:
            retval = 1024 * int(re.search(r"\s+(\d+) K total memory", subprocess.check_output("vmstat -s", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"Mem:\s+(\d+)", subprocess.check_output("free -b", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    if not retval:
        try:
            retval = 1024 * int(re.search(r"KiB Mem:\s*\x1b[^\s]+\s*(\d+)", subprocess.check_output("top -n 1", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    return retval

def check_memory():
    if get_total_physmem() < MIN_MEMORY_SIZE:
        exit("Not enough memory, at least %dGB of memory required" % (MIN_MEMORY_SIZE / 1024 / 1024 / 1024))
        