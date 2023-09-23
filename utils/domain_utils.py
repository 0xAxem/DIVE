import re
import socket
import validators
import tld

def extract_domains(text):
    domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b"
    return re.findall(domain_pattern, text)

def validate_domains(domains):
    valid_domains = []  
    for domain in domains:
        if validators.domain(domain):
            try:
                current_tld = tld.get_tld(domain, fix_protocol=True, fail_silently=True)
                if tld.is_tld(current_tld):
                    valid_domains.append(domain)
            except:
                pass
            
    return valid_domains
    # return [domain for domain in domains if validators.domain(domain) and tld.is_tld(tld.get_tld(domain, fix_protocol=True, fail_silently=True))]

def filter_by_domain_lenght(domains, min_lenght):
    return [domain for domain in domains if len(domain) >= min_lenght]

def active_scan(domains):
    return [domain for domain in domains if socket.gethostbyname(domain)]
