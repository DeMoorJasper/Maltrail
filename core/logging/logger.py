import sys

def _join_args(args):
  return ' '.join(map(str, args))

def log_info(*args):
  sys.stdout.write("[INFO]: " + _join_args(args) + "\n")
  sys.stdout.flush()
  
#def log_error(msg):
#    try:
#        handle = get_error_log_handle(config.LOG_DIR)
#        os.write(handle, "%s %s\n" % (time.strftime(TIME_FORMAT, time.localtime()), msg))
#    except (OSError, IOError):
#        if config.SHOW_DEBUG:
#            traceback.print_exc()

def log_error(*args):
  sys.stderr.write("[ERROR]: " + _join_args(args) + "\n")
  sys.stderr.flush()
  
def log_warning(*args):
  sys.stdout.write("[DEBUG]: " + _join_args(args) + "\n")
  sys.stdout.flush()