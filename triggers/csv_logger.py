import csv
import time
import socket

from core.settings import config
from threading import Thread
from Queue import Queue

def createEventCSVEntry(event):
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
    
    return [flow_id, event.trail_type, event.info, event.reference, event.accuracy, event.severity, event.packet.sec, event.packet.usec, event.packet.ip.get_ip_src(), event.packet.ip.get_ip_dst(), src_port, dst_port, event.packet.ip.get_ip_p()]

def worker():
    with open(config.LOG_DIR + '/events.csv', 'wb') as csvfile:
        eventWriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

        # Write column headers
        # SEC = UNIX TIMESTAMP
        # USEC = MICROSECONDS PAST TIMESTAMP
        eventWriter.writerow(['flow ID', 'trail_type', 'info', 'reference', 'accuracy', 'severity', 'sec', 'usec', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])

        while True:
            try:
                event = q.get()
                eventWriter.writerow(createEventCSVEntry(event))
                csvfile.flush()
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
