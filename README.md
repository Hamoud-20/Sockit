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
Set up your VirusTotal API and urlscan.io key:
```

```

# Usage
```
python3 sockit.py -h
```
<img width="1062" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/978f1b3a-7ac0-49f4-9a47-b95609ee641b">

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
python3 sockit.py -i 61.83.40.108
```
<img width="1054" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/7dd45309-544f-42c4-b92e-e1c6aa28b4d1">

# Scan hashe

```
python3 sockit.py -H 86b6c59aa48a69e16d3313d982791398
```
<img width="1200" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/7224c1ac-46a8-4067-a730-59be9d4d8aa6">

# extracts MD5 hashes of files to pcap 

```
python script.py -p malicious.pcap -o hashes.txt
```

<img width="679" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/5d650881-ef8e-44d2-ac45-02c4fa4d5876">

# Scan FILE HASH
```
python script.py -f hashes.txt
```
<img width="902" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/e1e49be3-4674-458d-9020-50134566d766">

# SSL fingerprints
```
python3 sockit.py -s d4fa6554b5f6243a50eb1453e440bba58da56f61
```
<img width="712" alt="image" src="https://github.com/Hamoud-20/Sockit/assets/137123444/b74c27cf-3f99-4c00-8bc5-483b375fa12c">

# Scan URL 
```
python3 sockit.py -u google.com
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
