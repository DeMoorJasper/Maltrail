import traceback
import struct

from core.net.Packet import Packet
from core.cache import checkCache
from core.events.emit import emit_event
from core.settings import trails
from core.settings import config

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
                    event = function(packet, config, trails)
                    # if the plugin returns an event, emit it and return
                    # each packet should only be associated with one attack
                    # TODO: Figure out a way to give certain returned events priority over others based on severity and accuracy
                    if event:
                        emit_event(event)
                        return
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
