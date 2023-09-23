import click
import os
from utils.parser import process_file, process_directory
from utils.domain_utils import validate_domains, filter_by_domain_lenght, active_scan
from utils.ip_utils import filter_by_private_ip


@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--active', '-a', help="Perform active DNS validation scan", is_flag=True, default=False)
@click.option('--filter-lenght', '-fl', help="Minimum domain character lenght", type=int, default=0)
@click.option('--filter-private', '-fp', help="Filter out IPs in private ranges", is_flag=True, default=False)
@click.option('--threads', '-t', help="Number of threads to use for active scan", type=int, default=40)
def main(path, active, threads, filter_lenght, filter_private):
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
        domains = active_scan(domains, threads)
        
    for ip in set(ips):
        click.echo(ip)
    
    for domain in set(domains):
        click.echo(domain)

if __name__ == "__main__":
    main()
