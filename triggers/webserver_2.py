import requests
import json

ENDPOINT = "http://localhost:3000/add_packet"

def trigger(event, config):
  try:
    packet_data = unicode(event.packet.ip.get_packet(), "latin-1")
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
            "data": packet_data
          }
        }
      })
    }
    req = requests.post(url=ENDPOINT, data=data)
    print(req.status_code, req.reason)
  except Exception as e:
    print(e)
    print("Couldn't send data to server!")
    