import re
import struct
import socket
import urlparse

from core.enums import PROTO
from core.process_package import result_cache
from core.check_domain import check_domain_whitelisted
from core.settings import trails
from core.settings import config
from core.settings import VALID_DNS_CHARS
from core.settings import SUSPICIOUS_CONTENT_TYPES
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import WHITELIST_LONG_DOMAIN_NAME_KEYWORDS
from core.enums import TRAIL
from core.log import log_event
from core.log import Event

def _check_domain(query, pkg):
    if query:
        query = query.lower()
        if ':' in query:
            query = query.split(':', 1)[0]

    if query.replace('.', "").isdigit():  # IP address
        return

    if result_cache.get(query) == False:
        return
    
    if not check_domain_whitelisted(query) and all(_ in VALID_DNS_CHARS for _ in query):
        parts = query.lower().split('.')

        for i in xrange(0, len(parts)):
            domain = '.'.join(parts[i:])
            if domain in trails:
                if domain == query:
                    trail = domain
                else:
                    _ = ".%s" % domain
                    trail = "(%s)%s" % (query[:-len(_)], _)

                if not (re.search(r"(?i)\Ad?ns\d*\.", query) and any(_ in trails.get(domain, " ")[0] for _ in ("suspicious", "sinkhole"))):  # e.g. ns2.nobel.su
                    log_event(Event(pkg, TRAIL.DNS, trail, trails[domain][0], trails[domain][1]))
                    return

        if config.USE_HEURISTICS:
            if len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
                trail = None

                if len(parts) > 2:
                    trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                elif len(parts) == 2:
                    trail = "(%s).%s" % (parts[0], parts[1])
                else:
                    trail = query

                if trail and not any(_ in trail for _ in WHITELIST_LONG_DOMAIN_NAME_KEYWORDS):
                    log_event(Event(pkg, TRAIL.DNS, trail, "long domain (suspicious)", "(heuristic)"))
                    return

    result_cache[query] = False

def plugin(pkg):
    if hasattr(pkg, 'tcp'):
        src_port, dst_port, _, _, doff_reserved, flags = pkg.tcp

        if flags != 2:
            tcph_length = doff_reserved >> 4
            h_size = pkg.iph_length + (tcph_length << 2)
            tcp_data = pkg.ip_data[h_size:]
            method, path = None, None
            
            if method and path:
                host = pkg.dst_ip
                first_index = tcp_data.find("\r\nHost:")
                path = path.lower()

                if first_index >= 0:
                    first_index = first_index + len("\r\nHost:")
                    last_index = tcp_data.find("\r\n", first_index)
                    if last_index >= 0:
                        host = tcp_data[first_index:last_index]
                        host = host.strip().lower()
                        if host.endswith(":80"):
                            host = host[:-3]
                        
                        if not (host and host[0].isalpha() and pkg.dst_ip in trails):
                            _check_domain(host, pkg)

                if config.USE_HEURISTICS and dst_port == 80 and path.startswith("http://") and not check_domain_whitelisted(urlparse.urlparse(path).netloc.split(':')[0]):
                    log_event(Event(pkg, TRAIL.HTTP, path, "potential proxy probe (suspicious)", "(heuristic)"))
                    return
                elif "://" in path:
                    url = path.split("://", 1)[1]

                    if '/' not in url:
                        url = "%s/" % url

                    host, path = url.split('/', 1)
                    if host.endswith(":80"):
                        host = host[:-3]
                    path = "/%s" % path
                    proxy_domain = host.split(':')[0]
                    _check_domain(proxy_domain, pkg)
                elif method == "CONNECT":
                    if '/' in path:
                        host, path = path.split('/', 1)
                        path = "/%s" % path
                    else:
                        host, path = path, '/'
                    if host.endswith(":80"):
                        host = host[:-3]
                    url = "%s%s" % (host, path)
                    proxy_domain = host.split(':')[0]
                    _check_domain(proxy_domain, pkg)
                else:
                    url = "%s%s" % (host, path)
