#!/usr/bin/env bash

# Run with capture file, for debugging purposes
sudo python ./sensor.py -i ./captures/honeypot-1.pcap --no-updates --debug

# Run for production use
# sudo python ./sensor.py --no-updates
