# DIVE (Domain and IP Validator Extractor)
## Overview
DIVE is a Python-based tool designed to extract and validate IP addresses and domain names from any type of file, including text, binary, and logs. It offers additional features such as active DNS scanning, domain length filtering, and private IP filtering.
### Application in C2 Detection
DIVE can be useful for cybersecurity professionals in identifying potential Command and Control (C2) servers statically. By extracting and validating IP addresses and domain names from network logs, system logs, malware executables and other artifacts, you can isolate suspicious or malicious traffic for further investigation.
## Features
- **Extract IP addresses and domain names from any file type and directories**
- **Validate extracted domains**
- **Filter domains by length**
- **Filter out private IP addresses**
- **Perform active DNS scanning to identify active domains**
## Known Limitations
- **The tool is resource intensive with large file (i.e. memory dumps, disk images) and still requires a lot of optimizations**
- **Subject to DNS rate limits**
- **May produce false positives in binary files**
- **DNS active scan does not cover all DNS record type to improve performance**
- **IPv6 is not supported**
## Installation
### Clone the repository:
```bash
git clone https://github.com/0xAxem/DIVE.git
```
### Navigate to the project directory:
```bash
cd DIVE
```
### Install the required packages:
```bash
pip install -r requirements.txt
```
## Usage
Run the script using the following command:
```bash
python dive.py [OPTIONS] PATH
```
### Options
- `--active, -a`: Perform an active DNS scan (default is `False`)
- `--dive-type -dt [both|ips|domains]`: Type of extraction to perform (default is `both`)
- `--filter-length, -fl`: Filter domains by minimum length (default is `3`)
- `--filter-private, -fp`: Filter out private IP addresses (default is `False`)
- `--filter-domains -fd`: Output only specified domains (default is all domains)
- `--threads, -t`: Number of threads to use for active scan (default is `40`)
### Examples
To extract IPs and domains from a single file:
```bash
python dive.py /path/to/file.txt
```
To extract IPs and domains from a directory:
```bash
python dive.py /path/to/directory/
```
To perform an active DNS scan:
```bash
python dive.py --active /path/to/file.txt
```
## Contributing
If you'd like to contribute, please fork the repository and make changes as you'd like. Pull requests are warmly welcome.
