# Sockit
The script scans IP addresses, domains, file hashes, SSL fingerprints and PCAP files against various threat intelligence feeds and APIs. It extracts MD5 hashes from PCAP files and checks them against VirusTotal. It also scans URLs using the URLScan.io API.

The script takes in arguments to specify the type of scan to perform - IP, domain, hash, PCAP file, URL or SSL fingerprint. It sends requests to the VirusTotal and URLScan APIs and parses the responses to provide a summary of results to the user including detection rates, last scan date, detected C2 servers and contacted URLs. For SSL fingerprints, it checks against the abuse.ch SSL blacklist.

For IP addresses, domains, hashes and PCAP files, it sends requests to the VirusTotal API and parses the response to provide a summary of results to the user including detection rates, last scan date, detected C2 servers (for domains) and contacted URLs. For PCAP files, it extracts MD5 hashes of files and checks them against VirusTotal.

For URLs, it uses the URLScan.io API to scan the URL and fetch scan results including screenshots, network information and anomaly detection.
This script would be useful for security analysts, threat hunters and malware researchers.

# The main point
•Scans IP addresses, domains, file hashes and PCAP files against VirusTotal.

•Extracts MD5 hashes from PCAP files and checks them against VirusTotal.

•Scans URLs using the URLScan.io API.

•Provides a summary of scan results including detection rates, last scan date, detected C2 servers and contacted URLs.

•Automates analysis of IOCs and suspicious files/PCAPs.

•Saves time by aggregating results from multiple scans in one place.

•Shows how malicious or clean an artifact is based on detection rates.

•Extracted MD5 hashes can be used for further analysis.

•SSL fingerprints, it checks against the abuse.ch SSL blacklist.
# Installation
Step 1:
```
git clone https://github.com/Hamoud-20/Sockit.git
```
Step 2:
```
pip install -r requirements.txt
```
Step 3:
Set up your VirusTotal API and urlscan.io API key:
```
API_KEY = "YOUR_API_KEY"
URLSCAN_API_KEY = "YOUR_API_KEY"
```

# Usage
```
python3 sockit.py -h
```
<img width="1138" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/d739a1ba-862a-48d2-ba09-97f4649251c6">

# This will display help for the tool. Here are all the switches it supports.

```console
options:
  -h, --help            show this help message and exit
  -i IP_ADDRESS, --ip_address IP_ADDRESS
                        IP address to check
  -d DOMAIN, --domain DOMAIN
                        Domain to check
  -H FILE_HASH, --file_hash FILE_HASH
                        File hash to check
  -p PCAP_FILE, --pcap_file PCAP_FILE
                        PCAP file to extract hashes from
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        Output file for extracted hashes
  -f HASH_FILE, --hash_file HASH_FILE
                        File containing list of file hashes to check
  -u SCAN, --scan SCAN  Domain/URL to scan and display the results
  -s SSL, --ssl SSL     Fingerprint to check
```
# Running sockit

# Scan IP addresse
```
python sockit.py -i 61.83.40.108
```

<img width="1078" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/e3aab0a4-06d3-448e-89b1-0c27c7fcaea2">

# Scan Domain
```
python3 sockit.py -d 4kqd3hmqgptupi3p.6ntrb6.top
```

# Scan hashe

```
python sockit.py -H 86b6c59aa48a69e16d3313d982791398
```

<img width="1248" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/3ca006b4-241b-4f0c-a099-236259db7895">

# Extracts MD5 hashes of files to pcap 

```
python  sockit.py -p malicious.pcap -o hashes.txt
```

<img width="631" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/945c2871-781f-4d99-ba4f-fffd1669bc74">

# Scan FILE Hash
```
python sockit.py -f hashes.txt
```
<img width="1351" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/7d2d687c-0e3d-4ff0-86d3-47b80d4d29e3">

# SSL fingerprints
```
python sockit.py -s d4fa6554b5f6243a50eb1453e440bba58da56f61
```
<img width="749" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/6a9d0c51-3927-41fe-83c7-5b7bcc6dd3d9">
<img width="809" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/a2d81965-0ad1-4e37-9e5e-0cacefc0e09d">

# Scan URL 
```
python sockit.py -u google.com
```
# Summary
This tool provides a way to quickly check IP addresses, domains, file hashes and PCAP files for maliciousness. Here are the main features:

- Checking IP addresses, domains and file hashes against VirusTotal's API. It will return a summary of detections, status (clean/suspicious/malicious), number of total/detected and last analysis date.

- Extracting file hashes from a PCAP file and saving them to a text file. 

- Scanning URLs using URLScan.io API and displaying a summary of the scan results including title, status code, load time, responses and verdicts. 

- Checking SSL fingerprints against an SSL blacklist to detect suspicious certificates.

- Automatically formatting the results in a pretty table for easy reading. Red color is used for malicious, yellow for suspicious and green for clean results.

- The tool is implemented using Python with libraries like requests, scapy and prettytable for nice output formatting. It requires an API key from VirusTotal and URLScan.io to function.

So in summary, it provides an easy way to check IPs, domains, files and URLs for signs of malware using various threat intelligence APIs. The color-coded table output makes it easy to quickly identify suspicious entities.

Happy threat hunting!
