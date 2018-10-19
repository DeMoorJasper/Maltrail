import re

from core.config.settings import WHITELIST

def check_domain_member(query, domains):
    parts = query.lower().split('.')

    for i in xrange(0, len(parts)):
        domain = '.'.join(parts[i:])
        if domain in domains:
            return True

    return False

def check_domain_whitelisted(query):
    return check_domain_member(re.split(r"(?i)[^A-Z0-9._-]", query or "")[0], WHITELIST)