import socket
import string

LOCALHOST_IP = { 4: "127.0.0.1", 6: "::1" }
IPPROTO_LUT = dict(((getattr(socket, _), _.replace("IPPROTO_", "")) for _ in dir(socket) if _.startswith("IPPROTO_")))
VALID_DNS_CHARS = string.letters + string.digits + '-' + '.'  # Reference: http://stackoverflow.com/a/3523068
