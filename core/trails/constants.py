import os

from core.config.constants import USERS_DIR

TRAILS_FILE = os.path.join(USERS_DIR, "trails.csv")
IPCAT_CSV_FILE = os.path.join(USERS_DIR, "ipcat.csv")
IPCAT_SQLITE_FILE = os.path.join(USERS_DIR, "ipcat.sqlite")
IPCAT_URL = "https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv"
LOAD_TRAILS_RETRY_SLEEP_TIME = 60