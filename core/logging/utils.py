import os

from core.common import check_sudo

def safe_value(value):
    retval = str(value or '-')
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    return retval

def create_log_directory(log_dir):
    if not os.path.isdir(log_dir):
        if check_sudo() is False:
            exit("please rerun with sudo/Administrator privileges")
        os.makedirs(log_dir, 0755)
    # log_info("using '%s' for log storage" % log_dir)