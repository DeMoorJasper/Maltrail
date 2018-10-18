import socket

# TODO: Fix this plugin
# TODO: Split this across multiple plugins

def plugin(pkg):
    if protocol == socket.IPPROTO_UDP:  # UDP
        _ = ip_data[iph_length:iph_length + 4]
        if len(_) < 4:
            return

        src_port, dst_port = struct.unpack("!HH", _)

        _ = _last_udp
        _last_udp = (sec, src_ip, src_port, dst_ip, dst_port)
        if _ == _last_udp:  # skip bursts
            return

        if src_port != 53 and dst_port != 53:  # not DNS
            if dst_ip in trails:
                trail = dst_ip
            elif src_ip in trails:
                trail = src_ip
            else:
                trail = None

            if trail:
                _ = _last_logged_udp
                _last_logged_udp = _last_udp
                if _ != _last_logged_udp:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP,
                               TRAIL.IP, trail, trails[trail][0], trails[trail][1]), packet)

        else:
            dns_data = ip_data[iph_length + 8:]

            # Reference: http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
            if len(dns_data) > 6:
                qdcount = struct.unpack("!H", dns_data[4:6])[0]
                if qdcount > 0:
                    offset = 12
                    query = ""

                    while len(dns_data) > offset:
                        length = ord(dns_data[offset])
                        if not length:
                            query = query[:-1]
                            break
                        query += dns_data[offset + 1:offset + length + 1] + '.'
                        offset += length + 1

                    query = query.lower()

                    if not query or '.' not in query or not all(_ in VALID_DNS_CHARS for _ in query) or any(_ in query for _ in (".intranet.",)) or any(query.endswith(_) for _ in IGNORE_DNS_QUERY_SUFFIXES):
                        return

                    parts = query.split('.')

                    # standard query (both recursive and non-recursive)
                    if ord(dns_data[2]) & 0xfe == 0x00:
                        type_, class_ = struct.unpack(
                            "!HH", dns_data[offset + 1:offset + 5])

                        if len(parts) > 2:
                            if len(parts) > 3 and len(parts[-2]) <= 3:
                                domain = '.'.join(parts[-3:])
                            else:
                                domain = '.'.join(parts[-2:])

                            # e.g. <hash>.hashserver.cs.trendmicro.com
                            if not _check_domain_whitelisted(domain):
                                if (sec - (_subdomains_sec or 0)) > DAILY_SECS:
                                    _subdomains.clear()
                                    _dns_exhausted_domains.clear()
                                    _subdomains_sec = sec

                                subdomains = _subdomains.get(domain)

                                if not subdomains:
                                    subdomains = _subdomains[domain] = set()

                                if not re.search(r"\A\d+\-\d+\-\d+\-\d+\Z", parts[0]):
                                    if len(subdomains) < DNS_EXHAUSTION_THRESHOLD:
                                        subdomains.add('.'.join(parts[:-2]))
                                    else:
                                        if (sec - (_last_dns_exhaustion or 0)) > 60:
                                            trail = "(%s).%s" % (
                                                '.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS,
                                                       trail, "potential dns exhaustion (suspicious)", "(heuristic)"), packet)
                                            _dns_exhausted_domains.add(domain)
                                            _last_dns_exhaustion = sec

                                        return

                        # Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
                        # Type not in (PTR, AAAA), Class IN
                        if type_ not in (12, 28) and class_ == 1:
                            if dst_ip in trails:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, "%s (%s)" % (
                                    dst_ip, query), trails[dst_ip][0], trails[dst_ip][1]), packet)
                            elif src_ip in trails:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP,
                                           TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]), packet)

                            _check_domain(
                                query, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, packet)

                    elif config.USE_HEURISTICS:
                        if ord(dns_data[2]) & 0x80:  # standard response
                            # recursion available, no error
                            if ord(dns_data[3]) == 0x80:
                                _ = offset + 5
                                try:
                                    while _ < len(dns_data):
                                        # Type A
                                        if ord(dns_data[_]) & 0xc0 != 0 and dns_data[_ + 2] == "\00" and dns_data[_ + 3] == "\x01":
                                            break
                                        else:
                                            _ += 12 + \
                                                struct.unpack(
                                                    "!H", dns_data[_ + 10: _ + 12])[0]

                                    _ = dns_data[_ + 12:_ + 16]
                                    if _:
                                        answer = socket.inet_ntoa(_)
                                        if answer in trails:
                                            _ = trails[answer]
                                            if "sinkhole" in _[0]:
                                                trail = "(%s).%s" % (
                                                    '.'.join(parts[:-1]), '.'.join(parts[-1:]))
                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "sinkholed by %s (malware)" % _[
                                                          0].split(" ")[1], "(heuristic)"), packet)  # (e.g. kitro.pl, devomchart.com, jebena.ananikolic.su, vuvet.cn)
                                            elif "parking" in _[0]:
                                                trail = "(%s).%s" % (
                                                    '.'.join(parts[:-1]), '.'.join(parts[-1:]))
                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP,
                                                           TRAIL.DNS, trail, "parked site (suspicious)", "(heuristic)"), packet)
                                except IndexError:
                                    pass

                            # recursion available, no such name
                            elif ord(dns_data[3]) == 0x83:
                                if '.'.join(parts[-2:]) not in _dns_exhausted_domains and not _check_domain_whitelisted(query) and not _check_domain_member(query, trails):
                                    if parts[-1].isdigit():
                                        return

                                    # generic check for DNSBL IP lookups
                                    if not (len(parts) > 4 and all(_.isdigit() and int(_) < 256 for _ in parts[:4])):
                                        for _ in filter(None, (query, "*.%s" % '.'.join(parts[-2:]) if query.count('.') > 1 else None)):
                                            if _ not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[_][0] != sec / 3600:
                                                NO_SUCH_NAME_COUNTERS[_] = [
                                                    sec / 3600, 1, set()]
                                            else:
                                                NO_SUCH_NAME_COUNTERS[_][1] += 1
                                                NO_SUCH_NAME_COUNTERS[_][2].add(
                                                    query)

                                                if NO_SUCH_NAME_COUNTERS[_][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD:
                                                    if _.startswith("*."):
                                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, "%s%s" % ("(%s)" % ','.join(item.replace(
                                                            _[1:], "") for item in NO_SUCH_NAME_COUNTERS[_][2]), _[1:]), "excessive no such domain (suspicious)", "(heuristic)"), packet)
                                                        for item in NO_SUCH_NAME_COUNTERS[_][2]:
                                                            try:
                                                                del NO_SUCH_NAME_COUNTERS[item]
                                                            except KeyError:
                                                                pass
                                                    else:
                                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS,
                                                                   _, "excessive no such domain (suspicious)", "(heuristic)"), packet)

                                                    try:
                                                        del NO_SUCH_NAME_COUNTERS[_]
                                                    except KeyError:
                                                        pass

                                                    break

                                        if len(parts) > 2:
                                            part = parts[0] if parts[0] != "www" else parts[1]
                                            trail = "(%s).%s" % (
                                                '.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                        elif len(parts) == 2:
                                            part = parts[0]
                                            trail = "(%s).%s" % (
                                                parts[0], parts[1])
                                        else:
                                            part = query
                                            trail = query

                                        if part and '-' not in part:
                                            result = _result_cache.get(part)

                                            if result is None:
                                                # Reference: https://github.com/exp0se/dga_detector
                                                probabilities = (
                                                    float(part.count(c)) / len(part) for c in set(_ for _ in part))
                                                entropy = - \
                                                    sum(p * math.log(p) / math.log(2.0)
                                                        for p in probabilities)
                                                if entropy > SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD:
                                                    result = "entropy threshold no such domain (suspicious)"

                                                if not result:
                                                    if sum(_ in CONSONANTS for _ in part) > SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD:
                                                        result = "consonant threshold no such domain (suspicious)"

                                                _result_cache[part] = result or False

                                            if result:
                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port,
                                                           PROTO.UDP, TRAIL.DNS, trail, result, "(heuristic)"), packet)
