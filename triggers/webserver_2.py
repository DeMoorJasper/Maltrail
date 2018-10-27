import requests
import json
import socket

ENDPOINT = "http://localhost:3000/add_packet"

def trigger(event, config):
  try:
    packet_data = unicode(event.packet.ip.get_packet(), "latin-1")

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
    
    data={
      "json": json.dumps({
        "sensor_name": config.SENSOR_NAME,
        "event_data": {
          "trail_type": event.trail_type,
          "trail": event.trail,
          "info": event.info,
          "reference": event.reference,
          "accuracy": event.accuracy,
          "severity": event.severity,
          "packet": {
            "sec": event.packet.sec,
            "usec": event.packet.usec,
            "src_ip": event.packet.ip.get_ip_src(),
            "dst_ip": event.packet.ip.get_ip_dst(),
            "src_port": src_port,
            "dst_port": dst_port,
            "data": packet_data
          }
        }
      })
    }

    req = requests.post(url=ENDPOINT, data=data)

    if req.status_code == 200:
      print("Successfully sent data to web-api!")
    else:
      print("Could not send data to web-api: " + req.status_code)
  except Exception as e:
    print(e)
    print("Couldn't send data to server!")
    