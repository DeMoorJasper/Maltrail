from core.logging.logger import log_info

def trigger(event):
  log_info("TEST TRIGGER:", event.info)
