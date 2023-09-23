import os, re, socket
import click, validators, tld
from ipaddress import ip_address, ip_network

def extract_ips_and_domains(text):
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b"
    
    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    
    return ips, domains

def process_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        ips, domains = extract_ips_and_domains(content)
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

def active_scan(domains):
    """ 
    Send a dns query to check for active domains.
    """  
    active_domains = []
    
    for domain in domains:
        try:
            address = socket.gethostbyname(domain)
            if address:
                active_domains.append(domain)
        except:
            pass
    
    return active_domains

def filter_by_domain_lenght(domains, min_lenght):
    """
    Filter domains by lenght.
    """
    filtered_domains = []
    
    for domain in domains:
        if len(domain) >= min_lenght:
            filtered_domains.append(domain)
    
    return filtered_domains
    
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

def validate_domains(domains):
    """ 
    Validate domains using validators and tldextract.
    This validation process does NOT prope any dns query.
    """
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

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--active', '-a', help="Perform active DNS validation scan", is_flag=True, default=False)
@click.option('--filter-lenght', '-fl', help="Minimum domain character lenght", type=int, default=0)
@click.option('--filter-private', '-fp', help="Filter out IPs in private ranges", is_flag=True, default=False)
def main(path, output, active, filter_lenght, filter_private):
    """
    Extract IP addresses and domain names from a file or directory.

    Arguments:
    path -- Path to file or directory
    """
    
    if os.path.isfile(path):
        ips, domains = process_file(path)
    elif os.path.isdir(path):
        ips, domains = process_directory(path)
    else:
        click.echo("Invalid path!")
        return
    
    domains = validate_domains(domains)
    
    if filter_lenght > 0:
        domains = filter_by_domain_lenght(domains, filter_lenght)
    
    if filter_private:
        ips = filter_by_private_ip(ips)
    
    if active:
        domains = active_scan(domains)
        
    
    for ip in set(ips):
        click.echo(ip)
    
    for domain in set(domains):
        if (active):
            
            click.echo(domain)

if __name__ == "__main__":
    main()
