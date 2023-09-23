import re
from ipaddress import ip_address, ip_network


def extract_ips(text):
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return re.findall(ip_pattern, text)

def filter_by_private_ip(ips):
    """
    Filter out private ip addresses.
    """ 
    private_networks = [
        ip_network('10.0.0.0/8'),
        ip_network('172.16.0.0/12'),
        ip_network('192.168.0.0/16'),
        ip_network('127.0.0.0/8')
    ]
    filtered_ips = []

    for ip in ips:
        address = ip_address(ip)
        if any(address in network for network in private_networks) or ip == "0.0.0.0":
            continue 
        filtered_ips.append(ip)
    
    return filtered_ips
