#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
from datetime import datetime
import os
import re
import signal
import sys
import time
from aiohttp_socks import ProxyConnector
import ssl
from datetime import datetime
from collections import defaultdict
import re
import signal
import json
import geoip2.database
import aiofiles
import random
from typing import List, Set, Dict, Any
from rich.console import Console
from rich.progress import Progress
from pathlib import Path
import hashlib
import shutil
import csv

class ProxyScraper:
    def __init__(self, args):
        """Initialize the proxy checker with command line arguments."""
        self.args = args
        self.proxies = set()
        self.proxy_types = defaultdict(set)
        self.proxy_count = defaultdict(int)
        self.running = True
        self.start_time = None
        
        # Convert protocols to list and validate
        self.protocols = [p.strip().lower() for p in args.protocols.split(',')]
        valid_protocols = {'http', 'socks4', 'socks5'}
        if not all(p in valid_protocols for p in self.protocols):
            raise ValueError(f"Invalid protocol specified. Valid protocols are: {', '.join(valid_protocols)}")
        
        # Validate anonymity level if specified
        if args.anonymity_level:
            valid_levels = {'transparent', 'anonymous', 'elite'}
            if args.anonymity_level not in valid_levels:
                raise ValueError(f"Invalid anonymity level. Valid levels are: {', '.join(valid_levels)}")
        
        # Set export format
        self.export_format = args.export_format.lower()
        
        # Setup output directory
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = args.output or 'output'
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create protocol directories and files
        for protocol in self.protocols:
            protocol_dir = os.path.join(self.output_dir, protocol)
            os.makedirs(protocol_dir, exist_ok=True)
            # Create or truncate protocol files
            with open(os.path.join(protocol_dir, f"{protocol}_{self.timestamp}.{self.export_format}"), 'w') as f:
                # JSON dosyası için boş array oluştur
                if self.export_format == 'json':
                    f.write('[]')
                # CSV dosyası için header oluştur
                elif self.export_format == 'csv':
                    f.write('proxy,protocol,response_time,anonymity,timestamp\n')
        
        # Test URLs for anonymity checking
        self.test_urls = [
            'http://httpbin.org/ip',
            'http://api.ipify.org?format=json',
            'http://ip-api.com/json/',
            'http://www.httpbin.org/ip'
        ]
        
        # Connection settings
        self.conn_timeout = min(self.args.timeout, 10)  # Max 10 seconds for initial connection
        self.read_timeout = max(self.args.timeout - self.conn_timeout, 5)  # Remaining time for reading
        
        # Retry settings
        self.max_retries = 2
        self.retry_delay = 1  # seconds
        
        # Parse protocols
        self.max_threads = args.threads
        self.timeout = args.timeout
        self.delay = args.delay  # Convert to seconds
        self.max_ms = args.max_ms
        self.verify_ssl = args.verify_ssl
        self.verbose = args.verbose
        self.quiet = args.quiet
        self.raw = args.raw
        
        # Progress tracking
        self.total_checked = 0
        self.total_failed = 0
        self.total_elite = 0
        self.pbar = None
        
        # Load configurations
        self.user_agents = self._load_file("config/user_agents.txt")
        self.proxy_sources = self._load_file("config/proxy_sources.txt")
        
        # Initialize proxy lists and counters
        self.response_times = {}
        self.anonymity_levels = {}
        
        # Get current timestamp for file naming
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create or truncate summary file
        with open(os.path.join(self.output_dir, f"summary_{self.timestamp}.txt"), 'w') as f:
            f.write("=== Proxy Scraper Results ===\n")
            f.write(f"Started at: {self.timestamp}\n")
            f.write("===========================\n\n")
        
        # Flag for graceful shutdown
        self.save_needed = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        if not self.quiet:
            print("\n\033[93m[!] Shutting down gracefully...\033[0m")
        self.running = False
        
        self.save_needed = True
        
        # Print results before exiting
        self._print_results()
        
        # Force exit after 5 seconds
        def force_exit():
            if not self.quiet:
                print("\n\033[91m[-] Force exiting...\033[0m")
            sys.exit(1)
        
        signal.signal(signal.SIGALRM, lambda s, f: force_exit())
        signal.alarm(5)

    def _export_results(self):
        """Export results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.args.output or 'output'
        
        # Her protokol için ayrı dosya oluştur
        for protocol in self.proxy_types:
            if self.proxy_types[protocol]:  # Eğer proxy varsa
                # Protokol için klasör oluştur
                protocol_dir = os.path.join(output_dir, protocol)
                os.makedirs(protocol_dir, exist_ok=True)
                
                # Dosya adını oluştur
                filename = f"{protocol}_{timestamp}.{self.args.export_format}"
                filepath = os.path.join(protocol_dir, filename)
                
                # Dosyaya yaz
                with open(filepath, 'w') as f:
                    if self.args.export_format == 'json':
                        json.dump(list(self.proxy_types[protocol]), f, indent=2)
                    elif self.args.export_format == 'csv':
                        writer = csv.writer(f)
                        writer.writerow(['proxy'])
                        for proxy in self.proxy_types[protocol]:
                            writer.writerow([proxy])
                    else:  # txt format
                        for proxy in self.proxy_types[protocol]:
                            f.write(f"{proxy}\n")

    @staticmethod
    def _load_file(filename: str) -> List[str]:
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: {filename} not found!")
            sys.exit(1)

    async def scrape_proxies(self):
        """Scrape proxies from various sources."""
        if not self.proxy_sources:
            if not self.quiet:
                print("\033[91m[-] No proxy sources found in config/proxy_sources.txt\033[0m")
            return
        
        # Create temporary directory for scraped files
        temp_dir = os.path.join(self.output_dir, 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for source in self.proxy_sources:
                if not self.running:
                    break
                    
                # Skip empty lines and comments
                if not source.strip() or source.strip().startswith('#'):
                    continue
                    
                # Create tasks for each source and protocol
                for protocol in self.protocols:
                    url = source.strip().format(protocol=protocol)
                    tasks.append(self._fetch_proxies(session, url, temp_dir))
            
            # Show progress bar
            if not self.quiet and not self.raw:
                with Progress() as progress:
                    task = progress.add_task("Scraping proxies...", total=len(tasks))
                    for coro in asyncio.as_completed(tasks):
                        await coro
                        progress.update(task, advance=1)
            else:
                await asyncio.gather(*tasks)
        
        # Process scraped files
        for filename in os.listdir(temp_dir):
            filepath = os.path.join(temp_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract proxies using regex
                    found = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+\b', content)
                    self.proxies.update(found)
            except Exception as e:
                if not self.quiet:
                    print(f"\033[91m[-] Error processing {filename}: {str(e)}\033[0m")
        
        # Clean up temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            if not self.quiet:
                print(f"\033[91m[-] Error cleaning up temp directory: {str(e)}\033[0m")
        
        if not self.proxies:
            if not self.quiet:
                print("\033[91m[-] No proxies found\033[0m")
            return
        
        if not self.quiet and not self.raw:
            print(f"\033[92m[+] Found {len(self.proxies)} unique proxies\033[0m")

    async def _fetch_proxies(self, session, url, temp_dir):
        """Fetch proxies from a single source."""
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Save to temporary file
                    filename = hashlib.md5(url.encode()).hexdigest() + '.txt'
                    filepath = os.path.join(temp_dir, filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                else:
                    if not self.quiet:
                        print(f"\033[91m[-] Error fetching from {url}: HTTP {response.status}\033[0m")
        except Exception as e:
            if not self.quiet:
                print(f"\033[91m[-] Error fetching from {url}: {str(e)}\033[0m")

    async def check_proxies(self):
        """Check all scraped proxies."""
        semaphore = asyncio.Semaphore(self.max_threads)
        completed = 0
        total = len(self.proxies)
        
        if self.raw:
            # Simple checking without progress bar in raw mode
            async def check_single_proxy(proxy_str):
                try:
                    host, port = proxy_str.split(':')
                    proxy = {
                        'protocol': 'http',  # Default to HTTP, will be updated during check
                        'host': host,
                        'port': int(port)
                    }
                    result = await self.check_proxy(proxy, semaphore)
                    if result:
                        # max_ms kontrolü
                        if not self.max_ms or result['response_time'] <= self.max_ms:
                            proxy_str = f"{result['host']}:{result['port']}"
                            self.proxy_types[result['protocol']].add(proxy_str)
                            # Ekrana yazdır
                            sys.stdout.write(f"{proxy_str}\n")
                            sys.stdout.flush()
                            # Dosyaya kaydet
                            await self._save_proxy(result, result['protocol'], result['response_time'], result['anonymity'])
                except Exception:
                    pass

            # Her proxy için ayrı task oluştur
            tasks = [check_single_proxy(proxy_str) for proxy_str in self.proxies]
            await asyncio.gather(*tasks)
        else:
            # Use progress bar in normal mode
            console = Console()
            with Progress(console=console, expand=True) as progress:
                task_id = progress.add_task(
                    "[cyan]Testing proxies...", 
                    total=total,
                    working=0,
                    failed=0
                )
                
                async def process_proxy(proxy_str):
                    nonlocal completed
                    try:
                        host, port = proxy_str.split(':')
                        proxy = {
                            'protocol': 'http',
                            'host': host,
                            'port': int(port)
                        }
                        result = await self.check_proxy(proxy, semaphore)
                        
                        if result:
                            proxy_str = f"{result['host']}:{result['port']}"
                            self.proxy_types[result['protocol']].add(proxy_str)
                            await self._save_proxy(result, result['protocol'], result['response_time'], result['anonymity'])
                            if self.verbose and not self.quiet and not self.raw:
                                print(f"\033[92m[+] Working {result['protocol']} proxy: {proxy_str} ({result['response_time']}ms, {result['anonymity']})\033[0m")
                            progress.update(task_id, working=len(self.proxy_types['http']) + len(self.proxy_types['socks4']) + len(self.proxy_types['socks5']))
                        else:
                            progress.update(task_id, failed=completed - (len(self.proxy_types['http']) + len(self.proxy_types['socks4']) + len(self.proxy_types['socks5'])))
                    except Exception as e:
                        if self.verbose:
                            print(f"\nError checking proxy {proxy_str}: {str(e)}")
                    finally:
                        completed += 1
                        progress.update(
                            task_id, 
                            completed=completed,
                            description=f"[cyan]Testing proxies... Working: {len(self.proxy_types['http']) + len(self.proxy_types['socks4']) + len(self.proxy_types['socks5'])}, Failed: {completed - (len(self.proxy_types['http']) + len(self.proxy_types['socks4']) + len(self.proxy_types['socks5']))}"
                        )
                
                # Create tasks for each proxy and wait for completion
                tasks = [process_proxy(proxy_str) for proxy_str in self.proxies]
                await asyncio.gather(*tasks)

    async def check_proxy(self, proxy, semaphore):
        """Check a single proxy"""
        async with semaphore:
            start_time = time.time()
            proxy_url = f"{proxy['protocol']}://{proxy['host']}:{proxy['port']}"
            proxy['anonymity'] = 'unknown'  # Initialize anonymity
            
            for attempt in range(self.max_retries):
                if not self.running:
                    return None
                    
                try:
                    async with aiohttp.ClientSession() as session:
                        # Configure proxy settings
                        if proxy['protocol'] in ['http', 'https']:
                            proxy_settings = {'http': proxy_url, 'https': proxy_url}
                        else:
                            proxy_settings = {
                                'proxy_type': proxy['protocol'],
                                'host': proxy['host'],
                                'port': proxy['port']
                            }
                        
                        # Perform initial connection test
                        async with session.get(
                            self.test_urls[0],
                            proxy=proxy_url if proxy['protocol'] in ['http', 'https'] else None,
                            proxy_auth=None,
                            ssl=self.verify_ssl,
                            timeout=aiohttp.ClientTimeout(
                                total=self.args.timeout,
                                connect=self.conn_timeout
                            )
                        ) as response:
                            if response.status != 200:
                                return None
                            
                            data = await response.json()
                            proxy_ip = self._extract_ip(data)
                            
                            if not proxy_ip:
                                return None
                            
                            # Only perform anonymity check if specifically requested
                            if self.args.anonymity_level:
                                # Fast header check first
                                headers = dict(response.headers)
                                proxy['anonymity'] = self._determine_anonymity_from_headers(headers, proxy_ip)
                                
                                # If we need more accurate check and current level doesn't match requested
                                if (self.args.anonymity_level != 'transparent' and 
                                    proxy['anonymity'] != self.args.anonymity_level):
                                    proxy['anonymity'] = await self._verify_anonymity_level(session, proxy_url, proxy_ip)
                                
                                if proxy['anonymity'] != self.args.anonymity_level:
                                    return None
                            else:
                                # If anonymity level not specified, do basic header check
                                headers = dict(response.headers)
                                proxy['anonymity'] = self._determine_anonymity_from_headers(headers, proxy_ip)
                            
                            proxy['response_time'] = int((time.time() - start_time) * 1000)
                            
                            # Check if response time exceeds max_ms
                            if self.max_ms and proxy['response_time'] > self.max_ms:
                                if self.verbose and not self.quiet:
                                    print(f"\033[93m[-] Proxy {proxy_url} response time ({proxy['response_time']}ms) exceeds maximum ({self.max_ms}ms)\033[0m")
                                return None
                                
                            return proxy
                            
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay)
                        continue
                    return None
                    
            return None

    def _extract_ip(self, data):
        """Extract IP from various API response formats"""
        if 'origin' in data:
            return data['origin'].split(',')[0].strip()
        elif 'ip' in data:
            return data['ip'].strip()
        elif 'query' in data:
            return data['query'].strip()
        return None

    def _determine_anonymity_from_headers(self, headers, proxy_ip):
        """Quick anonymity check based on headers"""
        proxy_headers = {
            'via', 'proxy-connection', 'x-forwarded-for',
            'proxy-authenticate', 'x-real-ip', 'forwarded'
        }
        
        # Check for proxy headers (case-insensitive)
        headers_lower = {k.lower(): v for k, v in headers.items()}
        has_proxy_headers = any(h in headers_lower for h in proxy_headers)
        
        if not has_proxy_headers:
            return 'elite'
        return 'transparent'

    async def _verify_anonymity_level(self, session, proxy_url, proxy_ip):
        """Detailed anonymity verification"""
        try:
            # Use a different test URL for secondary check
            async with session.get(
                self.test_urls[1],
                proxy=proxy_url,
                ssl=self.verify_ssl,
                timeout=aiohttp.ClientTimeout(total=self.args.timeout / 2)  # Shorter timeout for secondary check
            ) as response:
                if response.status != 200:
                    return 'transparent'
                    
                data = await response.json()
                secondary_ip = self._extract_ip(data)
                
                if not secondary_ip:
                    return 'transparent'
                
                headers = dict(response.headers)
                headers_lower = {k.lower(): v for k, v in headers.items()}
                
                # Elite: No proxy headers, consistent IP
                if not any(h in headers_lower for h in {'via', 'x-forwarded-for', 'proxy-connection'}):
                    if proxy_ip == secondary_ip:
                        return 'elite'
                        
                # Anonymous: May have some headers but IPs match
                if proxy_ip == secondary_ip:
                    return 'anonymous'
                    
                return 'transparent'
                
        except Exception:
            return 'transparent'

    async def _save_proxy(self, proxy, protocol, response_time, anonymity):
        """Save a single proxy as soon as it's found"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            protocol_dir = os.path.join(self.output_dir, protocol)
            file_path = os.path.join(protocol_dir, f"{protocol}_{self.timestamp}.{self.export_format}")
            
            # Prepare data based on format
            if self.export_format == 'json':
                data = {
                    'proxy': f"{proxy['host']}:{proxy['port']}",
                    'protocol': protocol,
                    'response_time': round(response_time, 2),
                    'anonymity': anonymity,
                    'timestamp': timestamp
                }
                # Append to JSON file
                try:
                    with open(file_path, 'r') as f:
                        proxies = json.load(f)
                except (FileNotFoundError, json.JSONDecodeError):
                    proxies = []
                
                proxies.append(data)
                
                with open(file_path, 'w') as f:
                    json.dump(proxies, f, indent=2)
                    
            elif self.export_format == 'csv':
                # Create CSV if doesn't exist
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write('proxy,protocol,response_time,anonymity,timestamp\n')
                
                # Append to CSV
                with open(file_path, 'a') as f:
                    f.write(f"{proxy['host']}:{proxy['port']},{protocol},{round(response_time, 2)},{anonymity},{timestamp}\n")
                    
            else:  # txt format
                # Simple text format
                with open(file_path, 'a') as f:
                    if self.raw:
                        f.write(f"{proxy['host']}:{proxy['port']}\n")
                    else:
                        f.write(f"{proxy['host']}:{proxy['port']} - {protocol} - {round(response_time, 2)}ms - {anonymity}\n")
            
            # Update proxy count
            self.proxy_count[protocol] += 1
            
        except Exception as e:
            if not self.quiet:
                print(f"\033[91m[-] Error saving proxy {proxy['host']}:{proxy['port']}: {str(e)}\033[0m")

    def _print_results(self):
        """Print scan results and statistics"""
        if self.raw:
            # In raw mode, just print working proxies
            for protocol in self.protocols:
                for proxy in self.proxy_types[protocol]:
                    print(proxy)
            return
        
        if not self.quiet:
            print("\n\033[92m=== Scan Results ===\033[0m")
            
            # Calculate total working proxies
            total_working = sum(len(proxies) for proxies in self.proxy_types.values())
            
            # Print statistics
            print(f"\n\033[97m[*] Total Proxies Found: {len(self.proxies)}")
            print(f"[*] Working Proxies: {total_working}")
            
            # Print protocol-specific results
            for protocol in self.protocols:
                working = len(self.proxy_types[protocol])
                if working > 0:
                    print(f"\n\033[96m[+] {protocol.upper()} Proxies: {working}\033[0m")
                    
                    # Get the output file path
                    output_file = os.path.join(self.output_dir, protocol, 
                                             f"{protocol}_{self.timestamp}.{self.export_format}")
                    
                    if os.path.exists(output_file):
                        print(f"\033[97m    └── Saved to: {output_file}\033[0m")
            
            # Print execution time
            duration = time.time() - self.start_time
            print(f"\n\033[97m[*] Execution time: {duration:.2f} seconds")
            
            # Print export format info
            print(f"[*] Export format: {self.export_format.upper()}")
            print(f"[*] Output directory: {self.output_dir}\033[0m")
            
            print("\n\033[92m[+] Done! Check the output directory for detailed results.\033[0m")

    async def run(self):
        """Main execution method"""
        try:
            self.start_time = time.time()
            
            # Scrape proxies
            if not self.quiet and not self.raw:
                print("\033[93m[*] Starting proxy scraper...\033[0m")
            
            await self.scrape_proxies()
            
            if not self.proxies:
                if not self.quiet:
                    print("\033[91m[-] No proxies found\033[0m")
                return
            
            if not self.quiet and not self.raw:
                print(f"\033[92m[+] Found {len(self.proxies)} unique proxies\033[0m")
            
            # Check proxies
            if not self.quiet and not self.raw:
                print("\n\033[93m[*] Starting proxy verification...\033[0m")
            
            await self.check_proxies()
            
            # Print results only if we haven't already printed them in signal handler
            if self.running:
                self._print_results()
                
        except Exception as e:
            if not self.quiet:
                print(f"\n\033[91m[-] Error during execution: {str(e)}\033[0m")
            
        finally:
            # Clean up temp directory if it exists
            temp_dir = os.path.join(self.output_dir, 'temp')
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    if not self.quiet:
                        print(f"\033[91m[-] Error cleaning up temp directory: {str(e)}\033[0m")
            
            if not self.running and not self.quiet and not self.raw:
                print("\033[92m[+] Proxy scraper shutdown complete\033[0m")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Proxy Scraper and Elite Proxy Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --threads 100 --timeout 5
  %(prog)s --output custom_output --max-ms 1000
  %(prog)s --protocols http,socks4 --anonymity-level elite
  %(prog)s --export-format json --verbose
  %(prog)s --verify-ssl true --protocols http
  %(prog)s --export-format csv --protocols http,socks4,socks5
        '''
    )

    # Required parameters group
    parser.add_argument('--threads', type=int, default=50,
                      help='Number of concurrent connections (default: 50)')
    parser.add_argument('--timeout', type=float, default=10,
                      help='Timeout in seconds for each request (default: 10)')
    parser.add_argument('--protocols', type=str, default='http,socks4,socks5',
                      help='Comma-separated list of protocols to check (default: http,socks4,socks5)')
    
    # Optional parameters group
    parser.add_argument('--output', type=str,
                      help='Output directory for results (default: output/)')
    parser.add_argument('--max-ms', type=int, default=10000,
                      help='Maximum response time in milliseconds (default: 10000)')
    parser.add_argument('--delay', type=float, default=0,
                      help='Delay between proxy checks in seconds (default: 0)')
    parser.add_argument('--anonymity-level', type=str,
                      choices=['transparent', 'anonymous', 'elite'],
                      help='Required anonymity level (transparent, anonymous, elite)')
    parser.add_argument('--verify-ssl', type=str, default='true', choices=['true', 'false'],
                      help='Verify SSL certificates (default: true)')
    parser.add_argument('--export-format', type=str, default='txt',
                      choices=['txt', 'json', 'csv'],
                      help='Export format for results (default: txt)')
    
    # Output control group
    parser.add_argument('--verbose', action='store_true',
                      help='Show detailed output')
    parser.add_argument('--quiet', action='store_true',
                      help='Show minimal output')
    parser.add_argument('--raw', action='store_true',
                      help='Output only IP:PORT format')
    
    args = parser.parse_args()

    # Validate arguments
    if args.verbose and args.quiet:
        parser.error("Cannot use both --verbose and --quiet")

    if args.delay < 0:
        parser.error("Delay must be non-negative")

    if args.threads < 1:
        parser.error("Thread count must be positive")

    if args.max_ms < 0:
        parser.error("Maximum response time must be non-negative")
        
    # Convert verify_ssl string to boolean
    args.verify_ssl = args.verify_ssl.lower() == 'true'

    # Create scraper instance and run
    scraper = ProxyScraper(args)
    asyncio.run(scraper.run())

if __name__ == "__main__":
    main()
