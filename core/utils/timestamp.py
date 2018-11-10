import datetime
import time

def get_current_timestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d')

def get_sec_timestamp(sec):
    localtime = time.localtime(sec)
    return "%d-%02d-%02d" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday)
