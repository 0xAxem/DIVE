import os
import re
import click
import validators
import requests
import tld

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

def validate_domains( domains):


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
def main(path):
    """Extract IP addresses and domain names from a file or directory."""
    
    if os.path.isfile(path):
        ips, domains = process_file(path)
    elif os.path.isdir(path):
        ips, domains = process_directory(path)
    else:
        click.echo("Invalid path!")
        return
    
    domains = validate_domains(domains)
    
    click.echo("IP Addresses:")
    for ip in set(ips):
        click.echo(ip)
    
    click.echo("\nDomain Names:")
    for domain in set(domains):
        click.echo(domain)

if __name__ == "__main__":
    main()
