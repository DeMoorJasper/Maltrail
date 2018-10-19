import traceback
import struct

from core.settings import config
from core.net.Packet import Packet
from core.cache import checkCache
from core.logging.log import log_event

def process_packet(raw_packet, sec, usec, ip_offset):
    checkCache()

    try:
        packet = Packet(raw_packet, sec, usec, ip_offset)

        # This is not an IP package
        if packet.ip_version is None or packet.is_empty:
            return

        # Run through all the plugins
        if config.plugin_functions:
            for (plugin, function) in config.plugin_functions:
                try:
                    function(packet, log_event)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
