import os
import stat

from core.common import check_sudo

DEFAULT_FILE_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH

def get_write_handler(file_path, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    if not os.path.exists(file_path):
        open(file_path, "w+").close()
        os.chmod(file_path, DEFAULT_FILE_PERMISSIONS)

    return os.open(file_path, flags)

def create_log_directory(log_dir):
    if not os.path.isdir(log_dir):
        if check_sudo() is False:
            exit("please rerun with sudo/Administrator privileges")
        os.makedirs(log_dir, 0755)