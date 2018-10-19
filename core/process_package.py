import traceback
import struct

from core.settings import config
from core.Packet import Packet
from core.cache import checkCache

def process_packet(raw_packet, sec, usec, ip_offset):
    checkCache()

    try:
        packet = Packet(raw_packet, sec, usec, ip_offset)

        # This is not an IP package
        if packet.ip_version is None or packet.isEmpty:
            return

        # Run through all the plugins
        if config.plugin_functions:
            for (plugin, function) in config.plugin_functions:
                try:
                    function(packet)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
