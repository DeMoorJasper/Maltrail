import os
import time
import socket
import core.logger as logger

from core.settings import config
from threading import Thread
from Queue import Queue
from core.utils.safe_value import safe_value
from core.utils.timestamp import get_sec_timestamp
from core.utils.file_handler import get_write_handler

# SEC is packet timestamp
# USEC is milliseconds since packet timestamp
# columns = ['flow ID', 'trail_type', 'info', 'reference', 'accuracy', 'severity', 'sec', 'usec', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']

def create_event_entry(event):
    src_port = "-"
    dst_port = "-"

    if event.packet.ip.get_ip_p() == socket.IPPROTO_TCP:
        tcp = event.packet.ip.child()
        src_port = tcp.get_th_sport()
        dst_port = tcp.get_th_dport()
    elif event.packet.ip.get_ip_p() == socket.IPPROTO_UDP:
        udp = event.packet.ip.child()
        src_port = udp.get_uh_sport()
        dst_port = udp.get_uh_dport()

    flow_id = event.packet.ip.get_ip_dst() + '-' + event.packet.ip.get_ip_src() + '-' + str(dst_port) + '-' + str(src_port) + '-' + str(event.packet.ip.get_ip_p())
    
    return [
        flow_id, event.trail_type, event.info, event.reference, event.accuracy, event.severity, event.packet.sec, 
        event.packet.usec, event.packet.ip.get_ip_src(), event.packet.ip.get_ip_dst(), src_port, dst_port, event.packet.ip.get_ip_p()
    ]

def worker():
    file_handlers = {}

    while True:
        try:
            event = q.get()
            entry = ' '.join([safe_value(s) for s in create_event_entry(event)]) + '\n'

            file_location = os.path.join(config.LOG_DIR, 'events-' + get_sec_timestamp(int(event.packet.sec)) + '.csv')
            
            if config.SHOW_DEBUG:
                logger.debug('Wrote event to csv log.')

            if file_location not in file_handlers:
                file_handlers[file_location] = get_write_handler(file_location)

            # TODO: Error handling & recovery
            os.write(file_handlers[file_location], entry)

            # TODO: Close inactive streams
            # os.close(file_handler)

            q.task_done()

        except KeyboardInterrupt:
            break

q = Queue()
t = Thread(target=worker)
t.daemon = True
t.start()

def trigger(event, config):
    print('Write event to csv')
    q.put(event)
    q.join()
