import argparse
import sys
import csv
import datetime
import hashlib
import os
import requests
from prettytable import PrettyTable 
from scapy.all import rdpcap
from colorama import Fore, Back, Style
from termcolor import colored
import prettytable

API_BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = "YOUR_API_KEY"
URLSCAN_API_KEY = "YOUR_API_KEY"

print('\033[34;1m' + """  




                    | 
____________    __ -+-  ____________ 
\_____     /   /_ \ |   \     _____/
 \_____    \____/  \____/    _____/
  \_____                    _____/
     \___________  ___________/
               /____\\
               
               
               
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   +        ..| Sockit v1.0 |..           +
                   -                                      -
                   -              By: Hamoud Alharbi      -
                   +         Twitter: @Hamoud__2          +
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
""" + '\033[0m')
          
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip_address', help='IP address to check')
    parser.add_argument('-d', '--domain', help='Domain to check')
    parser.add_argument('-H', '--file_hash', help='File hash to check')  
    parser.add_argument('-p', '--pcap_file', help='PCAP file to extract hashes from')
    parser.add_argument('-o', '--output_file', help='Output file for extracted hashes')  
    parser.add_argument('-f', '--hash_file', help='File containing list of file hashes to check') 
    parser.add_argument('-u', '--scan', help='Domain/URL to scan and display the results')
    parser.add_argument('-s', '--ssl', help='Fingerprint to check')
    return parser.parse_args()

def scan_urlscan(url):
    headers = {'API-Key': URLSCAN_API_KEY}
    data = {'url': url}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code == 200:
        response_json = response.json()
        return response_json
    else:
        print(f"Error scanning URL: {response.text}")
        return None 
        
def fetch_urlscan_results(api_key: str, uuid: str) -> dict:
    """Fetch the results from the URLScan.io API."""
    headers = {
        'API-Key': api_key,
    }
    url = f'https://urlscan.io/api/v1/result/{uuid}/'
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching results from API. Status code: {response.status_code}, Error message: {e}")
    except Exception as e:
        print(f"Error fetching results from API. Error message: {e}")

def get_scan_results(api_url):
    headers = {'API-Key': URLSCAN_API_KEY}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def print_urlscan_results(results: dict) -> None:
    """Print the results from the URLScan.io API."""
    if 'page' in results and 'task' in results and 'stats' in results:
        table = PrettyTable()
        table.field_names = ["Attribute", "Results"]
        table.align["Attribute"] = "l"
        table.align["Results"] = "l"
        
        
        table.field_names = [colored(field, 'cyan', attrs=['bold']) for field in table.field_names]

        
        table.hrules = prettytable.ALL
        table.vrules = prettytable.ALL

        
        attributes = [
            ('Title', results['page'].get('title', 'Not Available')),
            ('URL', results['task']['url']),
            ('Domain', results['page']['domain']),
            ('IP', results['page']['ip']),
            ('ASN', results['page']['asn']),
            ('Country', results['page']['country']),
            ('Status', results['stats'].get('responseCode', 'N/A')),
            ('Load Time', results['stats'].get('load', 'N/A')),
            ('Response Time', results['stats'].get('ttfb', 'N/A')),
            ('Screenshot', results['task']['screenshotURL']),
            ('Malicious', colored('Yes', 'red', attrs=['bold']) if results['verdicts']['overall']['malicious'] else colored('No', 'green', attrs=['bold'])),
            ('Score', results['verdicts']['overall']['score']),
            ('SSL Issuer', results['page'].get('sslIssuer', 'N/A')),
            ('SSL Subject', results['page'].get('sslSubject', 'N/A')),
            ('SSL Expires', results['page'].get('sslExpires', 'N/A')),
            ('Cert PEM', results['page'].get('sslCertPem', 'N/A')),
        ]
        
        for attribute, value in attributes:
            table.add_row([attribute, value])

        print(table)
    else:
        print("Error: Unable to display results. The expected keys are not present in the results.")



if __name__ == '__main__':
    args = get_args()
    
    if args.scan:
        url_to_scan = args.scan 
        scan_response = scan_urlscan(url_to_scan)
        if scan_response:
            api_url = scan_response['api']
            print("Scanning URL, please wait...")
            
            import time
            time.sleep(30)  
            
            results = get_scan_results(api_url)
            if results:
                print_urlscan_results(results)
            else:
                print("Error fetching results from API.")
        else:
            print("Error scanning URL.")
            
        sys.exit(0)  
    


def download_ssl_blacklist(url: str, file_name: str = 'sslblacklist.csv') -> None:
    response = requests.get(url)
    if response.status_code == 200:
        with open(file_name, 'wb') as f:
            f.write(response.content)
        print(f'Successfully downloaded {file_name}')
    else:
        print(f'Error downloading {file_name}: {response.status_code}')

if args.ssl:
    scan = True 
    fingerprint = args.ssl  
    
    download_ssl_blacklist('https://sslbl.abuse.ch/blacklist/sslblacklist.csv')
else:
    scan = False

 
if scan: 
    with open('sslblacklist.csv') as f: 
        reader = csv.reader(f)
        for row in reader:
            if fingerprint in row: 
                print('\033[91m' + f'The SSL fingerprint {fingerprint} is blacklisted.' + '\033[0m')
                exit()
        print('\033[92m' + f'The SSL fingerprint {fingerprint} is not blacklisted.' + '\033[0m')
    

    
def check_hash(file_hash):
    headers = {'x-apikey': API_KEY}
    url = f"{API_BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        file_type = result['data']['attributes']['type_description']
        result['file_type'] = file_type
        return result
    elif response.status_code == 404:
        return None
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
        
        headers = {'x-apikey': API_KEY}
        url = f"{API_BASE_URL}/domains/{domain}"
        response = requests.get(url, headers=headers)

def scan_ip(ip_address):
    headers = {'x-apikey': API_KEY}
    url = f"{API_BASE_URL}/ip_addresses/{ip_address}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def get_domain_report(domain):
    headers = {'x-apikey': API_KEY}
    url = f"{API_BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()['data']
        return {
            'domain': domain,
            'result': response.json()
        }
    elif response.status_code == 404:
        return None
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
        
def format_result(result):
    malicious = 0
    suspicious = 0
    clean = 0
    if result:
        for k, v in result['data']['attributes']['last_analysis_results'].items():
            if v['category'] == 'malicious':
                malicious += 1
            elif v['category'] == 'suspicious':
                suspicious += 1
            elif v['category'] == 'clean':
                clean += 1
    return [malicious, suspicious, clean]

def print_results(output_data):
    if output_data is None:
        print("No results found.")
        return
    
    table = PrettyTable(['Type', 'Attribute', 'Result', 'Detections', 'Total', 'Last Update', 'Detected C2 Server', 'Contacted URLs'])
    
    if 'ip' in output_data:
        result = scan_ip(output_data['ip'])
        if result:
            last_update = result['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result)
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            table.add_row(['ip', output_data['ip'], result_str, detections, total, last_update, '', ''])
        else:
            table.add_row(['ip', output_data['ip'], Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', ''])
            
    elif 'hash' in output_data:
        result = check_hash(output_data['hash'])
        if result:
            last_update = result['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result)
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            table.add_row(['file', output_data['hash'], result_str, detections, total, last_update, '', ''])
        else:
            table.add_row(['file', output_data['hash'], Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', ''])
            
    elif 'domain' in output_data:
        result = get_domain_report(output_data['domain'])
        if result:
            last_update = result['result']['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result['result'])
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            detected = result.get('detected', '')
            contacted_urls = result['result']['data']['attributes'].get('contacted-urls', '')
            if contacted_urls:
                table.add_row(['domain', output_data['domain'], result_str, detections, total, last_update, detected, contacted_urls])
            else:
                 table.add_row(['domain', output_data['domain'], result_str, detections, total, last_update, detected, ''])
    
    elif 'pcap' in output_data:
        file_hashes = extract_file_hashes(output_data['pcap'])
        if file_hashes:
            for file_hash in file_hashes:
                result = check_hash(file_hash)
                if result:
                    last_update = result['data']['attributes'].get('last_modification_date', '')
                    if last_update:
                        last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
                    malicious, suspicious, clean = format_result(result)
                    detections = malicious + suspicious
                    total = detections + clean
                    if detections == 0:
                        result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
                    elif suspicious > 0:
                        result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
                    elif malicious > 0:
                        result_str = Fore.RED + "Malicious" + Style.RESET_ALL
                    else:
                        result_str = f"{detections}/{total}"
                    table.add_row(['file', file_hash, result_str, detections, total, last_update, '', ''])
                else:
                    table.add_row(['file', file_hash, Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', ''])
        else:
            print("No file hashes found in PCAP file.")
            return
    else:
        print("Invalid input.")
        return
    
    print(table)
    
def print_results(output_data):
    if output_data is None:
        print("No results found.")
        return

    table = PrettyTable(['Type', 'Attribute', 'Result', 'Detections', 'Total', 'Last Update', 'Detected C2 Server', 'Contacted URLs', 'File Type'])

    if 'ip' in output_data:
        result = scan_ip(output_data['ip'])
        if result:
            last_update = result['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result)
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            table.add_row(['ip', output_data['ip'], result_str, detections, total, last_update, '', '', ''])
        else:
            table.add_row(['ip', output_data['ip'], Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', '', ''])

    elif 'hash' in output_data:
        result = check_hash(output_data['hash'])
        if result:
            last_update = result['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result)
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            file_type = result.get('file_type', '')
            table.add_row(['file', output_data['hash'], result_str, detections, total, last_update, '', '', file_type])
        else:
            table.add_row(['file', output_data['hash'], Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', '', ''])

    elif 'domain' in output_data:
        result = get_domain_report(output_data['domain'])
        if result:
            last_update = result['result']['data']['attributes'].get('last_modification_date', '')
            if last_update:
                last_update = datetime.datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
            malicious, suspicious, clean = format_result(result['result'])
            detections = malicious + suspicious
            total = detections + clean
            if detections == 0:
                result_str = Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL
            elif suspicious > 0:
                result_str = Fore.YELLOW + "Suspicious" + Style.RESET_ALL
            elif malicious > 0:
                result_str = Fore.RED + "Malicious" + Style.RESET_ALL
            else:
                result_str = f"{detections}/{total}"
            detected = result.get('detected', '')
            contacted_urls = result['result']['data']['attributes'].get('contacted-urls', '')
            if contacted_urls:
                table.add_row(['domain', output_data['domain'], result_str, detections,total, last_update, detected, contacted_urls, ''])
            else:
                table.add_row(['domain', output_data['domain'], result_str, detections, total, last_update, detected, '', ''])
        else:
            table.add_row(['domain', output_data['domain'], Back.BLACK + Fore.GREEN + "Clean" + Style.RESET_ALL, '', '', '', '', '', ''])

    print(table)

def extract_hashes(pcap_file, output_file):
    hashes = set()
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            payload = packet['Raw'].load
            if len(payload) > 0:
                hash_obj = hashlib.md5(payload)
                hash_value = hash_obj.hexdigest()
                hashes.add(hash_value)
    with open(output_file, 'w') as f:
        for hash_value in hashes:
            f.write(hash_value + '\n')
    print(Fore.GREEN + f"MD5 hashes extracted from {pcap_file} and saved to {output_file}")


if __name__ == '__main__':
    args = get_args()
    
    if args.hash_file:
        with open(args.hash_file) as f:
            for line in f:
                hash_value = line.strip()
                output_data = {'hash': hash_value}
                print_results(output_data) 
                
    if args.ip_address:
        output_data = {'ip': args.ip_address}
        print_results(output_data)        
    elif args.domain:
        output_data = {'domain': args.domain} 
        print_results(output_data)        
    elif args.file_hash:
        output_data = {'hash': args.file_hash}
        print_results(output_data)        
    elif args.pcap_file and args.output_file:
        extract_hashes(args.pcap_file, args.output_file)
