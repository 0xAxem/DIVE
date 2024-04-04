import click
import os
from utils.parser import process_file, process_directory
from utils.domain_utils import validate_domains, filter_by_domain_lenght, active_scan
from utils.ip_utils import filter_by_private_ip


@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--active', '-a', help="Perform active DNS validation scan", is_flag=True, default=False, show_default=True)
@click.option('--dive-type', '-dt', help="Type of extraction to perform", default='both', type=click.Choice(['both', 'ips', 'domains']), show_default=True)
@click.option('--filter-lenght', '-fl', help="Minimum domain character lenght", type=int, default=3, show_default=True)
@click.option('--filter-private', '-fp', help="Filter out IPs in private ranges", is_flag=True, default=False, show_default=True)
@click.option('--filter-domains', '-fd', help="Output only specified domains (Comma seperated)", default=None, type=click.STRING)
@click.option('--threads', '-t', help="Number of threads to use for active scan", type=int, default=40, show_default=True)
def main(path, active, dive_type, filter_lenght, filter_private, filter_domains, threads):
    """
    Extract IP addresses and domain names from any file or directory.

    Arguments:
    path -- Path to file or directory
    """
    
    filter_domains = list(filter_domains.split(",")) if filter_domains else None    

    if os.path.isfile(path):
        ips, domains = process_file(path, dive_type, filter_domains)
    elif os.path.isdir(path):
        ips, domains = process_directory(path, dive_type,filter_domains)
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
