import traceback
import struct

from core.net.Packet import Packet
from core.cache import checkCache
from core.settings import trails
from core.settings import config

ACCURACY_MARGIN = 25

def process_packet(decodedFrame, sec, usec):
    checkCache()

    try:
        packet = Packet(decodedFrame, sec, usec)

        # TODO: Add ability to detect non-ip attacks
        if not hasattr(packet, 'ip'):
            return

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

                return emitted_event

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
