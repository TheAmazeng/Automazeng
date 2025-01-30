import requests
import asyncio
import aiohttp
import aiodns
import asyncio
import concurrent.futures
import socket
import ipaddress
import random
import re
import os
import json
from tqdm import tqdm
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup



class SubdomainTool:
    def __init__(self, domain, output_file=None):
        self.domain = domain
        self.output_file = output_file or f"output/{domain}_subdomains.txt"
        with open('config.json', 'r') as file:
            config = json.load(file)
        self.virustotal_api_key = config.get('VIRUSTOTAL_API_KEY')
        self.securitytrails_api_key = config.get('SECURITYTRAILS_API_KEY')
        self.dnsdumpster_api_key = config.get('DNSDUMPSTER_API_KEY')


    def skip_if_no_ptr(self, ip):
        """Check if the PTR record exists for an IP. If not, skip the lookup."""
        try:
            result = socket.gethostbyaddr(ip)
            print(f"[INFO] PTR record exists for {ip}: {result[0]}")
            return False  # Don't skip, PTR exists
        except (socket.herror, socket.gaierror):
            print(f"[INFO] Skipping IP {ip} (no PTR record)")
            return True  # Skip this IP
        
    def skip_cdn_ips(self, ip):
        """Check if an IP belongs to Cloudflare, AWS, etc., and skip it."""
        known_cdns = ["Cloudflare", "AWS", "Google Cloud", "Akamai"]
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                org = data.get('org', '')
                for cdn in known_cdns:
                    if cdn in org:
                        print(f"[INFO] Skipping CDN IP {ip} ({org})")
                        return True  # Skip this IP
        except Exception as e:
            print(f"[ERROR] Failed to check IP info for {ip}: {e}")
        return False



    def skip_large_asns(self, asn, max_cidr_limit=80):
        """Check if an ASN has too many CIDRs and skip it if necessary."""
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                cidrs = data.get('data', {}).get('prefixes', [])
                cidr_count = len(cidrs)
                
                if cidr_count > max_cidr_limit:  # Skip large ASN if too many CIDRs
                    print(f"[INFO] Skipping large ASN {asn} with {cidr_count} CIDRs (limit: {max_cidr_limit})")
                    return True
            
        except Exception as e:
            print(f"[ERROR] Failed to check CIDR count for ASN {asn}: {e}")
        
        return False
    

    def is_target_asn(self, ip, target_asns):
        """Check if the IP is part of the target's ASN."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                asn = data.get('asn', '')
                if asn in target_asns:
                    return True  # IP is in target ASN
        except Exception as e:
            print(f"[ERROR] Failed to get ASN info for {ip}: {e}")
        return False  # Not in target ASN




    def crtsh_query(self, pattern):
        url = f"https://crt.sh/?q={pattern}&output=json"
        subdomains = set()
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    subdomains.update(entry['name_value'].splitlines())
        except Exception as e:
            print(f"[ERROR] crt.sh failed: {e}")
        print(f"[crt.sh] Searching for subdomains... ({len(subdomains)} TOTAL FOUND)")
        return subdomains

    def virustotal_search(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": self.virustotal_api_key}
        subdomains = set()
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomains.add(item['id'])
        except Exception as e:
            print(f"[ERROR] VirusTotal failed: {e}")
        print(f"[VirusTotal] Searching for subdomains... ({len(subdomains)} TOTAL FOUND)")
        return subdomains
    
    def anubis_search(self):
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        subdomains = set()
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data:
                    subdomains.add(subdomain)
        except Exception as e:
            print(f"[ERROR] AnubisDB failed: {e}")
        print(f"[AnubisDB] Searching for subdomains... ({len(subdomains)} TOTAL FOUND)")
        return subdomains

    def securitytrails_search(self):
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": self.securitytrails_api_key}
        subdomains = set()
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for sub in data.get('subdomains', []):
                    subdomains.add(f"{sub}.{self.domain}")
        except Exception as e:
            print(f"[ERROR] SecurityTrails failed: {e}")
        print(f"[SecurityTrails] Searching for subdomains... ({len(subdomains)} TOTAL FOUND)")
        return subdomains
    

    def dnsdumpster_search(self):
        """Query DNSDumpster API for subdomains and ASN data (CIDRs, ASNs, etc.)."""
        url = f"https://api.dnsdumpster.com/domain/{self.domain}"
        subdomains = set()
        asn_data = set()
        cidrs = set()
        try:
            headers = {
                'X-API-Key': self.dnsdumpster_api_key,
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                
                # **Extract Subdomains from 'A' Records**
                for a_record in data.get('a', []):
                    subdomains.add(a_record.get('host'))
                    
                    # Extract ASN info for Broad Search
                    for ip_info in a_record.get('ips', []):
                        if 'asn' in ip_info:
                            asn_data.add(ip_info['asn'])
                        if 'asn_range' in ip_info:
                            cidrs.add(ip_info['asn_range'])

                # **Extract Subdomains from 'CNAME' Records**
                for cname_record in data.get('cname', []):
                    subdomains.add(cname_record.get('host'))
                
                # **Extract Subdomains from 'NS' Records**
                for ns_record in data.get('ns', []):
                    subdomains.add(ns_record.get('host'))
                    
                    # Extract ASN info for Broad Search
                    for ip_info in ns_record.get('ips', []):
                        if 'asn' in ip_info:
                            asn_data.add(ip_info['asn'])
                        if 'asn_range' in ip_info:
                            cidrs.add(ip_info['asn_range'])

                # **Extract Subdomains from 'MX' Records**
                for mx_record in data.get('mx', []):
                    subdomains.add(mx_record.get('host'))
                
            else:
                print(f"[ERROR] DNSDumpster API request failed with status {response.status_code}")
        
        except Exception as e:
            print(f"[ERROR] DNSDumpster API failed: {e}")

        print(f"[DNSDumpster] Subdomains found: {len(subdomains)}")
        print(f"[DNSDumpster] ASNs found: {len(asn_data)}")
        print(f"[DNSDumpster] CIDRs found: {len(cidrs)}")
        
        return subdomains, asn_data, cidrs
    


    def expand_cidr(self, cidr):
        """Expands a CIDR into a list of IP addresses, but limits the IP count to avoid hanging the script."""
        ip_list = []
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            if ':' in cidr:  # Skip IPv6 CIDRs
                print(f"[INFO] Skipping IPv6 CIDR {cidr}")
                return []

            if network.prefixlen < 22:  # Skip CIDRs larger than /22
                print(f"[INFO] Skipping large CIDR {cidr}")
                return []
            
            ip_list = [str(ip) for ip in network.hosts()][:100]  # Limit to 100 IPs
            print(f"[INFO] Expanded {cidr} to {len(ip_list)} IPs.")
        
        except Exception as e:
            print(f"[ERROR] Failed to expand CIDR {cidr}: {e}")
        
        return ip_list
    

    def is_private_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    
    async def reverse_lookup(self, ip):
        """Asynchronous reverse DNS lookup for an IP address."""
        if self.is_private_ip(ip):
            print(f"[INFO] Skipping private IP {ip}")
            return None
        try:
            resolver = aiodns.DNSResolver()
            result = await resolver.gethostbyaddr(ip)
            if self.domain in result.name:  # Filter for subdomains of the target
                print(f"[INFO] Reverse lookup {ip} = {result.name}")
                return result.name
        except aiodns.error.DNSError as e:
            if e.args[0] != 4:  # 4 means "Domain name not found"
                print(f"[ERROR] Reverse lookup failed for {ip}: {e}")
        except Exception as e:
            print(f"[ERROR] Reverse lookup failed for {ip}: {e}")
        return None



    async def lookup_all_ips(self, ip_list):
        """Run reverse DNS lookups in parallel for multiple IPs."""
        tasks = [self.reverse_lookup(ip) for ip in ip_list]
        return await asyncio.gather(*tasks)
    
    
    def parallel_expand_cidrs(self, cidrs):
        """Parallelize the expansion of CIDRs using concurrent.futures."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.expand_cidr, cidrs)
        expanded_ips = [ip for result in results for ip in result]  # Flatten list of IPs
        return expanded_ips



    def get_cidrs_from_ripe(self, asn):
        """Get CIDRs for an ASN from the RIPEstat API."""
        cidrs = set()
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for prefix in data.get('data', {}).get('prefixes', []):
                    cidr = prefix.get('prefix')
                    if cidr:
                        cidrs.add(cidr)
            
            print(f"[RIPE] CIDRs extracted for ASN {asn}: {len(cidrs)}")
        
        except Exception as e:
            print(f"[ERROR] RIPE lookup failed for ASN {asn}: {e}")
        
        return list(cidrs)



    def targeted_search(self):
        """Performs a targeted subdomain search using DNSDumpster, crt.sh, VirusTotal, and others."""
        print(f"[INFO] Starting Targeted Search for {self.domain}...")
        
        crtsh_results = self.crtsh_query(f"%25.{self.domain}")
        virustotal_results = self.virustotal_search()
        securitytrails_results = self.securitytrails_search()
        anubis_results = self.anubis_search()
        dnsdumpster_results, _, _ = self.dnsdumpster_search()  # Only use subdomains here
        
        all_subdomains = self.combine_results(
            crtsh_results, 
            virustotal_results, 
            securitytrails_results, 
            anubis_results, 
            dnsdumpster_results
        )
        
        self.save_to_file(all_subdomains)



    def broad_search(self):
            """Performs a broad subdomain search using ASN CIDRs from DNSDumpster, RIPE, and IPinfo."""
            print(f"[INFO] Starting Broad Search for {self.domain}...")
            
            crtsh_results = self.crtsh_query(f"%25.{self.domain}.%25")
            dnsdumpster_results, asn_data, dnsdumpster_cidrs = self.dnsdumpster_search()
            
            all_cidrs = set(dnsdumpster_cidrs)
            for asn in asn_data:
                if self.skip_large_asns(asn):
                    continue  # Skip large ASNs like AWS
                
                print(f"[INFO] Extracting CIDRs for ASN: {asn}")
                ripe_cidrs = self.get_cidrs_from_ripe(asn)
                
                if len(ripe_cidrs) > 50:  # Limit the number of CIDRs per ASN
                    print(f"[INFO] Limiting CIDRs for ASN {asn} to 50 (Total: {len(ripe_cidrs)})")
                    ripe_cidrs = ripe_cidrs[:50]
                
                all_cidrs.update(ripe_cidrs)
            
            # **Parallel expand CIDRs**
            ip_list = self.parallel_expand_cidrs(all_cidrs)
            
            # **Run reverse DNS lookups in parallel**
            loop = asyncio.get_event_loop()
            reverse_dns_results = loop.run_until_complete(self.lookup_all_ips(ip_list))
            
            all_results = self.combine_results(crtsh_results, dnsdumpster_results, reverse_dns_results)
            self.save_to_file(all_results)


    def combine_results(self, *results):
        combined = set()
        for result in results:
            combined.update(result)
        return combined

    def save_to_file(self, subdomains):
        try:
            with open(self.output_file, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[INFO] Saved {len(subdomains)} subdomains to {self.output_file}")
        except Exception as e:
            print(f"[ERROR] Unable to save subdomains to {self.output_file}: {e}")



class SubdomainBruteForce:
    """Handles Brute-force subdomain enumeration using a wordlist."""
    
    def __init__(self, domain, wordlist_path):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dns_only = f"output/{self.domain}_dns_only.txt"
        self.output_dns_and_http = f"output/{self.domain}_dns_and_http.txt"
        self.found_dns_only = set()
        self.found_dns_and_http = set()
        self.total_processed = 0

    async def initialize_resolver(self):
        """Attach resolver to the running event loop."""
        self.resolver = aiodns.DNSResolver(loop=asyncio.get_running_loop())

    async def resolve_subdomain(self, subdomain, retries=3):
        """Resolve DNS for a subdomain with retries."""
        for attempt in range(retries):
            try:
                await self.resolver.gethostbyname(subdomain, socket.AF_INET)
                return subdomain
            except (aiodns.error.DNSError, asyncio.TimeoutError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(1)
        return None

    async def check_http_live(self, subdomain, retries=3):
        """Check if the subdomain has an active HTTP server with retries."""
        for attempt in range(retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{subdomain}", timeout=5) as response:
                        if response.status in [200, 301, 302]:
                            return subdomain
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retries - 1:
                    await asyncio.sleep(1)
        return None

    async def process_subdomain(self, word, progress_bar):
        """Process a single subdomain: DNS check + HTTP check."""
        subdomain = f"{word}.{self.domain}"
        resolved_subdomain = await self.resolve_subdomain(subdomain)
        
        if resolved_subdomain:
            self.found_dns_only.add(resolved_subdomain)
            self.save_to_file(self.output_dns_only, resolved_subdomain)
            
            live_http_subdomain = await self.check_http_live(resolved_subdomain)
            if live_http_subdomain:
                self.found_dns_and_http.add(live_http_subdomain)
                self.save_to_file(self.output_dns_and_http, live_http_subdomain)
        
        self.total_processed += 1
        progress_bar.update(1)
        progress_bar.set_postfix(dns=len(self.found_dns_only), http=len(self.found_dns_and_http))

    async def run_bruteforce(self):
        """Run the brute-force process with a wordlist."""
        await self.initialize_resolver()
        
        open(self.output_dns_only, 'w').close()
        open(self.output_dns_and_http, 'w').close()
        
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f.readlines()]
        except Exception as e:
            print(f"[ERROR] Failed to load wordlist: {e}")
            return []

        with tqdm(total=len(words), desc="Brute-forcing subdomains", ncols=100) as progress_bar:
            tasks = []
            for word in words:
                tasks.append(self.process_subdomain(word, progress_bar))
                if len(tasks) >= 50:
                    await asyncio.gather(*tasks)
                    tasks.clear()

            if tasks:
                await asyncio.gather(*tasks)

    def save_to_file(self, subdomains):
        """Save discovered subdomains to an output file."""
        try:
            with open(self.output_file, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[INFO] Saved {len(subdomains)} subdomains to {self.output_file}")
        except Exception as e:
            print(f"[ERROR] Unable to save subdomains to {self.output_file}: {e}")


if __name__ == "__main__":
    print("Ultimate Subdomain Tool")
    print("--------------------------")
    print("1. Targeted Search")
    print("2. Broad Search")
    print("3. Brute-force Search")
    
    choice = input("Choose an option (1-3): ").strip()
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    
    if choice == "1":
        output_file = f"output/{domain}_targeted_subdomains.txt"
        subtool = SubdomainTool(domain, output_file)
        subtool.targeted_search()
    elif choice == "2":
        output_file = f"output/{domain}_broad_subdomains.txt"
        subtool = SubdomainTool(domain, output_file)
        subtool.broad_search()
    elif choice == "3":
        wordlist_path = "wordlists/brute_subdomains.txt"
        brute_force_tool = SubdomainBruteForce(domain, wordlist_path)
        asyncio.run(brute_force_tool.run_bruteforce())
    else:
        print("[ERROR] Invalid choice. Exiting.")

