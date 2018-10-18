import sys

from core.settings import config

def _join_args(args):
  return ' '.join(map(str, args))

def log_info(*args):
  sys.stdout.writelines("[INFO]: " + _join_args(args) + "\n")
  sys.stdout.flush()

def log_debug(*args):
  if config.SHOW_DEBUG:
    sys.stdout.writelines("[DEBUG]: " + _join_args(args) + "\n")
    sys.stdout.flush()
  
def log_error(*args):
  sys.stderr.writelines("[ERROR]: " + _join_args(args) + "\n")
  sys.stderr.flush()
  