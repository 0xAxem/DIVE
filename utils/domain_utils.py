import re
import validators
import tld
import dns.resolver
from threading import Thread
from concurrent.futures import ThreadPoolExecutor


def extract_domains(text):
    domain_pattern = r"\b((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b"
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

def filter_by_domain_lenght(domains, min_length):
    filtered_domains = []
    for domain in domains:
        try:
            domain_name = tld.get_fld(domain, fix_protocol=True, fail_silently=True)
            if domain_name and len(domain_name.split('.')[0]) >= min_length:
                filtered_domains.append(domain)
        except:
            pass
    return filtered_domains

def check_domain(domain, active_domains, record_types):
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            if answers:
                active_domains.append(domain)
                break
        except Exception as e:
            continue

def active_scan(domains, threads):
    active_domains = []
    record_types = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS']
    
    with ThreadPoolExecutor(max_workers=threads) as executor:  # You can adjust max_workers as needed
        futures = {executor.submit(check_domain, domain, active_domains, record_types): domain for domain in domains}
        
        for future in futures:
            future.result()

    return active_domains
