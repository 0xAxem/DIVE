import os
from utils.domain_utils import extract_domains
from utils.ip_utils import extract_ips

def process_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        ips = extract_ips(content)
        domains = extract_domains(content)
    return ips, domains

def process_directory(directory_path):
    all_ips = []
    all_domains = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            ips, domains = process_file(file_path)
            all_ips.extend(ips)
            all_domains.extend(domains)
    return all_ips, all_domains
