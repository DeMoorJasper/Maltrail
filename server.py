#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import sys

sys.dont_write_bytecode = True

import optparse
import os
import platform
import subprocess
import threading
import time
import traceback

from core.common import check_connection
from core.common import check_sudo
from core.httpd import start_httpd
from core.logging.log import create_log_directory
from core.logging.log import log_error
from core.logging.log import start_logd
from core.settings import config
from core.settings import read_config
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import NAME
from core.settings import VERSION
from core.trails.update import update_ipcat
from core.trails.update import update_trails

from core.logging.logger import log_info
from core.logging.logger import log_error

def main():

    log_info("%s (server) #v%s" % (NAME, VERSION))

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    options, _ = parser.parse_args()

    read_config(options.config_file)

    if config.USE_SSL:
        try:
            import OpenSSL
        except ImportError:
            if subprocess.mswindows:
                exit("[!] please install 'pyopenssl' (e.g. 'pip install pyopenssl')")
            else:
                msg, _ = "[!] please install 'pyopenssl'", platform.linux_distribution()[0].lower()
                for distro, install in {("fedora", "centos"): "sudo yum install pyOpenSSL", ("debian", "ubuntu"): "sudo apt-get install python-openssl"}.items():
                    if _ in distro:
                        msg += " (e.g. '%s')" % install
                        break
                exit(msg)

        if not config.SSL_PEM or not os.path.isfile(config.SSL_PEM):
            hint = "openssl req -new -x509 -keyout %s -out %s -days 365 -nodes -subj '/O=%s CA/C=EU'" % (config.SSL_PEM or "server.pem", config.SSL_PEM or "server.pem", NAME)
            exit("[!] invalid configuration value for 'SSL_PEM' ('%s')\n[?] (hint: \"%s\")" % (config.SSL_PEM, hint))

    def update_timer():
        retries = 0
        while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
            sys.stdout.write("[ERROR]: can't update because of lack of Internet connection (waiting..." if not retries else '.')
            sys.stdout.flush()
            time.sleep(10)
            retries += 1

        if retries:
            sys.stdout.write(")")

        if retries == CHECK_CONNECTION_MAX_RETRIES:
            log_error("going to continue without online update")
            _ = update_trails(offline=True)
        else:
            _ = update_trails(server=config.UPDATE_SERVER)
            update_ipcat()

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    if config.UDP_ADDRESS and config.UDP_PORT:
        if config.UDP_PORT <= 1024 and check_sudo() is False:
            exit("[!] please run '%s' with sudo/Administrator privileges when using 'UDP_ADDRESS' configuration value" % __file__)

        create_log_directory(config.LOG_DIR)
        start_logd(address=config.UDP_ADDRESS, port=config.UDP_PORT, join=False)

    try:
        if config.USE_SERVER_UPDATE_TRAILS:
            update_timer()

        start_httpd(address=config.HTTP_ADDRESS, port=config.HTTP_PORT, pem=config.SSL_PEM if config.USE_SSL else None, join=True)
    except KeyboardInterrupt:
        log_error("[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    show_final = True

    try:
        main()
    except SystemExit, ex:
        show_final = False

        log_error(ex)
    except IOError:
        show_final = False
        log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
    except Exception:
        log_error("unhandled exception occurred ('%s')" % sys.exc_info()[1])
        log_error("please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc())
    finally:
        if show_final:
            log_info("finished")

        os._exit(0)
