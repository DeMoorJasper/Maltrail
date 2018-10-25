import traceback
import struct

from core.net.Packet import Packet
from core.cache import checkCache
from core.events.emit import emit_event
from core.settings import trails
from core.settings import config

ACCURACY_MARGIN = 25

def process_packet(raw_packet, sec, usec, ip_offset):
    checkCache()

    try:
        packet = Packet(raw_packet, sec, usec, ip_offset)

        # This is not an IP package
        if packet.ip_version is None or packet.is_empty:
            return

        # Run through all the plugins
        if config.plugin_functions:
            events = []
            for (plugin, function) in config.plugin_functions:
                try:
                    event = function(packet, config, trails)
                    if event:
                        events.append(event)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

            if (len(events) > 0):
                emitted_event = events[0]
                for event in events:
                    severity_difference = emitted_event.severity - event.severity
                    accuracy_difference = emitted_event.accuracy - event.accuracy
                    if ((severity_difference == 0 and accuracy_difference < 0) or 
                        (severity_difference < 0 and accuracy_difference - ACCURACY_MARGIN < 0) or 
                        (severity_difference > 0 and accuracy_difference < ACCURACY_MARGIN)):
                        emitted_event = event

                if emitted_event:
                    emit_event(emitted_event)
                    return

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
