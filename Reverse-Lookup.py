#!/usr/bin/env python3

import os
import sys
import socket
import requests
import dns.resolver
import whois
from urllib.parse import urlparse
import json
import time
from colorama import Fore, Style, init
import ipaddress

# Inicialização
init(autoreset=True)
os.system('clear')

class ReverseLookupTool:
    def __init__(self):
        self.version = "2.2"
        self.author = "Termux Tools"
        self.current_target = None
        self.results = {}
        self.haveibeenpwned_api_key = ""  # Adicione sua chave API aqui
        
    def banner(self):
        print(Fore.CYAN + r"""
  ____  _____ ____  _   _ _   _ _____ 
 |  _ \| ____|  _ \| | | | \ | |_   _|
 | |_) |  _| | |_) | | | |  \| | | |  
 |  _ <| |___|  _ <| |_| | |\  | | |  
 |_| \_\_____|_| \_\\___/|_| \_| |_|  
        """ + Style.RESET_ALL)
        print(Fore.GREEN + f"Reverse Lookup Tool v{self.version}".center(50))
        print(Fore.YELLOW + "="*50 + Style.RESET_ALL)
    
    def clear_screen(self):
        os.system('clear')
        self.banner()
    
    def check_internet(self):
        try:
            requests.get("https://google.com", timeout=5)
            return True
        except:
            return False
    
    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_domain(self, domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
    
    def dns_reverse_lookup(self, ip):
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except socket.herror:
            return None
        except Exception as e:
            print(Fore.RED + f"[!] Error in reverse lookup: {str(e)}" + Style.RESET_ALL)
            return None
    
    def whois_lookup(self, domain):
        try:
            # Usando a nova API do pacote whois
            w = whois.whois(domain)
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            print(Fore.RED + f"[!] WHOIS Error: {str(e)}" + Style.RESET_ALL)
            return None
    
    def email_lookup(self, email):
        if not self.haveibeenpwned_api_key:
            print(Fore.YELLOW + "[!] HaveIBeenPwned API key not set" + Style.RESET_ALL)
            return None
            
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                "User-Agent": "ReverseLookupTool",
                "hibp-api-key": self.haveibeenpwned_api_key
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                print(Fore.RED + f"[!] API Error: {response.status_code}" + Style.RESET_ALL)
                return None
        except Exception as e:
            print(Fore.RED + f"[!] Email lookup error: {str(e)}" + Style.RESET_ALL)
            return None
    
    def dns_enumeration(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                records[record] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                print(Fore.RED + f"[!] Domain {domain} does not exist" + Style.RESET_ALL)
                return None
            except Exception as e:
                print(Fore.RED + f"[!] DNS Error ({record}): {str(e)}" + Style.RESET_ALL)
                continue
        
        return records
    
    def run_full_scan(self, target):
        self.results = {}
        print(Fore.GREEN + f"\n[+] Analyzing: {target}" + Style.RESET_ALL)
        
        if self.is_valid_ip(target):
            print(Fore.CYAN + "\n[+] DNS Reverse Lookup..." + Style.RESET_ALL)
            hostname = self.dns_reverse_lookup(target)
            self.results['reverse_dns'] = hostname
            print(f"Result: {hostname or 'Not found'}")
            
            if hostname:
                print(Fore.CYAN + "\n[+] WHOIS lookup..." + Style.RESET_ALL)
                whois_data = self.whois_lookup(hostname)
                self.results['whois'] = whois_data
                if whois_data:
                    print(f"Registrar: {whois_data.get('registrar', 'N/A')}")
                    print(f"Organization: {whois_data.get('org', 'N/A')}")
        elif "@" in target:
            print(Fore.CYAN + "\n[+] Email lookup..." + Style.RESET_ALL)
            breaches = self.email_lookup(target)
            self.results['email_breaches'] = breaches
            
            if breaches:
                print(f"Breaches found: {len(breaches)}")
                for breach in breaches[:3]:
                    print(f"- {breach['Name']} ({breach['BreachDate']})")
            else:
                print("No breaches found or API key not set")
        elif self.is_valid_domain(target):
            print(Fore.CYAN + "\n[+] WHOIS lookup..." + Style.RESET_ALL)
            whois_data = self.whois_lookup(target)
            self.results['whois'] = whois_data
            if whois_data:
                print(f"Registrar: {whois_data.get('registrar', 'N/A')}")
                print(f"Creation Date: {whois_data.get('creation_date', 'N/A')}")
            
            print(Fore.CYAN + "\n[+] DNS records..." + Style.RESET_ALL)
            dns_records = self.dns_enumeration(target)
            self.results['dns_records'] = dns_records
            
            if dns_records:
                for record, values in dns_records.items():
                    print(f"{record}: {', '.join(values[:2])}" + ("..." if len(values) > 2 else ""))
        else:
            print(Fore.RED + "\n[!] Invalid target format" + Style.RESET_ALL)
    
    def save_results(self, filename):
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(Fore.GREEN + f"\n[+] Saved to {filename}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"\n[!] Error saving file: {str(e)}" + Style.RESET_ALL)
            return False
    
    def interactive_menu(self):
        while True:
            self.clear_screen()
            print(Fore.YELLOW + "\nMain Menu:" + Style.RESET_ALL)
            print("1. Set target")
            print("2. DNS Reverse Lookup")
            print("3. WHOIS Lookup")
            print("4. Email Breach Check")
            print("5. Full DNS Scan")
            print("6. Full Analysis")
            print("7. Save Results")
            print("8. Set HaveIBeenPwned API Key")
            print("0. Exit")
            
            choice = input("\nSelect option: ")
            
            if choice == "1":
                self.current_target = input("\nEnter target (IP/domain/email): ").strip()
                print(Fore.GREEN + f"\nTarget set: {self.current_target}" + Style.RESET_ALL)
                time.sleep(1)
            
            elif choice == "2":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    if self.is_valid_ip(self.current_target):
                        print(Fore.CYAN + f"\n[+] Reverse DNS for {self.current_target}..." + Style.RESET_ALL)
                        result = self.dns_reverse_lookup(self.current_target)
                        print(f"\nResult: {result or 'Not found'}")
                    else:
                        print(Fore.RED + "\n[!] Target is not a valid IP address" + Style.RESET_ALL)
                input("\nPress Enter...")
            
            elif choice == "3":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    if "@" in self.current_target:
                        print(Fore.RED + "\n[!] WHOIS not available for emails" + Style.RESET_ALL)
                    elif self.is_valid_ip(self.current_target):
                        print(Fore.RED + "\n[!] WHOIS not available for IPs in this version" + Style.RESET_ALL)
                    else:
                        print(Fore.CYAN + f"\n[+] WHOIS for {self.current_target}..." + Style.RESET_ALL)
                        result = self.whois_lookup(self.current_target)
                        if result:
                            print(f"\nRegistrar: {result.get('registrar', 'N/A')}")
                            print(f"Organization: {result.get('org', 'N/A')}")
                            print(f"Creation Date: {result.get('creation_date', 'N/A')}")
                        else:
                            print("\nNo WHOIS data found")
                input("\nPress Enter...")
            
            elif choice == "4":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                elif "@" not in self.current_target:
                    print(Fore.RED + "\n[!] Target is not an email address" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + f"\n[+] Email check for {self.current_target}..." + Style.RESET_ALL)
                    result = self.email_lookup(self.current_target)
                    if result:
                        print(f"\nBreaches found: {len(result)}")
                        for breach in result[:3]:
                            print(f"- {breach['Name']} ({breach['BreachDate']})")
                    else:
                        print("\nNo breaches found or API key not set")
                input("\nPress Enter...")
            
            elif choice == "5":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                elif "@" in self.current_target or self.is_valid_ip(self.current_target):
                    print(Fore.RED + "\n[!] DNS scan only available for domains" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + f"\n[+] DNS scan for {self.current_target}..." + Style.RESET_ALL)
                    result = self.dns_enumeration(self.current_target)
                    if result:
                        for record, values in result.items():
                            print(f"\n{record}:")
                            for value in values[:5]:
                                print(f"- {value}")
                    else:
                        print("\nNo DNS records found or invalid domain")
                input("\nPress Enter...")
            
            elif choice == "6":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    self.run_full_scan(self.current_target)
                input("\nPress Enter...")
            
            elif choice == "7":
                if not self.results:
                    print(Fore.RED + "\n[!] No results to save" + Style.RESET_ALL)
                else:
                    filename = input("\nFilename to save (ex: results.json): ").strip()
                    if filename:
                        if not filename.endswith('.json'):
                            filename += '.json'
                        self.save_results(filename)
                input("\nPress Enter...")
            
            elif choice == "8":
                api_key = input("\nEnter HaveIBeenPwned API key: ").strip()
                self.haveibeenpwned_api_key = api_key
                print(Fore.GREEN + "\nAPI key set" + Style.RESET_ALL)
                time.sleep(1)
            
            elif choice == "0":
                print(Fore.YELLOW + "\nExiting..." + Style.RESET_ALL)
                break
            
            else:
                print(Fore.RED + "\n[!] Invalid option" + Style.RESET_ALL)
                time.sleep(1)

if __name__ == "__main__":
    if not ReverseLookupTool().check_internet():
        print(Fore.RED + "\n[!] No internet connection" + Style.RESET_ALL)
        sys.exit(1)
    
    tool = ReverseLookupTool()
    tool.interactive_menu()
