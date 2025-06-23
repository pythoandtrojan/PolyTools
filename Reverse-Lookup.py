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

# Inicialização
init(autoreset=True)
os.system('clear')

class ReverseLookupTool:
    def __init__(self):
        self.version = "2.1"
        self.author = "Termux Tools"
        self.current_target = None
        self.results = {}
        
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
    
    def dns_reverse_lookup(self, ip):
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except:
            return None
    
    def whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            return w
        except Exception as e:
            return f"Error: {str(e)}"
    
    def email_lookup(self, email):
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"User-Agent": "ReverseLookupTool"}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return json.loads(response.text)
            return None
        except:
            return None
    
    def dns_enumeration(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                records[record] = [str(r) for r in answers]
            except:
                continue
        
        return records
    
    def run_full_scan(self, target):
        self.results = {}
        print(Fore.GREEN + f"\n[+] Analyzing: {target}" + Style.RESET_ALL)
        
        try:
            socket.inet_aton(target)
            is_ip = True
        except:
            is_ip = False
        
        if is_ip:
            print(Fore.CYAN + "\n[+] DNS Reverse Lookup..." + Style.RESET_ALL)
            hostname = self.dns_reverse_lookup(target)
            self.results['reverse_dns'] = hostname
            print(f"Result: {hostname or 'Not found'}")
            
            if hostname:
                print(Fore.CYAN + "\n[+] WHOIS lookup..." + Style.RESET_ALL)
                whois_data = self.whois_lookup(hostname)
                self.results['whois'] = whois_data
                print(f"Registrant: {getattr(whois_data, 'name', 'N/A')}")
        else:
            if "@" in target:
                print(Fore.CYAN + "\n[+] Email lookup..." + Style.RESET_ALL)
                breaches = self.email_lookup(target)
                self.results['email_breaches'] = breaches
                
                if breaches:
                    print(f"Breaches found: {len(breaches)}")
                    for breach in breaches[:3]:  # Mostra apenas 3 para não poluir
                        print(f"- {breach['Name']} ({breach['BreachDate']})")
                else:
                    print("No breaches found")
            else:
                print(Fore.CYAN + "\n[+] WHOIS lookup..." + Style.RESET_ALL)
                whois_data = self.whois_lookup(target)
                self.results['whois'] = whois_data
                print(f"Registrant: {getattr(whois_data, 'name', 'N/A')}")
                
                print(Fore.CYAN + "\n[+] DNS records..." + Style.RESET_ALL)
                dns_records = self.dns_enumeration(target)
                self.results['dns_records'] = dns_records
                
                for record, values in dns_records.items():
                    print(f"{record}: {', '.join(values[:2])}" + ("..." if len(values) > 2 else ""))
    
    def save_results(self, filename):
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(Fore.GREEN + f"\n[+] Saved to {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"\n[!] Error: {str(e)}" + Style.RESET_ALL)
    
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
                    print(Fore.CYAN + f"\n[+] Reverse DNS for {self.current_target}..." + Style.RESET_ALL)
                    result = self.dns_reverse_lookup(self.current_target)
                    print(f"\nResult: {result or 'Not found'}")
                input("\nPress Enter...")
            
            elif choice == "3":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + f"\n[+] WHOIS for {self.current_target}..." + Style.RESET_ALL)
                    result = self.whois_lookup(self.current_target)
                    print(f"\nRegistrant: {getattr(result, 'name', 'N/A')}")
                    print(f"Created: {getattr(result, 'creation_date', 'N/A')}")
                input("\nPress Enter...")
            
            elif choice == "4":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + f"\n[+] Email check for {self.current_target}..." + Style.RESET_ALL)
                    result = self.email_lookup(self.current_target)
                    if result:
                        print(f"\nBreaches found: {len(result)}")
                        for breach in result[:3]:
                            print(f"- {breach['Name']}")
                    else:
                        print("\nNo breaches found")
                input("\nPress Enter...")
            
            elif choice == "5":
                if not self.current_target:
                    print(Fore.RED + "\n[!] No target set" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + f"\n[+] DNS scan for {self.current_target}..." + Style.RESET_ALL)
                    result = self.dns_enumeration(self.current_target)
                    for record, values in result.items():
                        print(f"\n{record}:")
                        for value in values[:5]:  # Limita a 5 resultados por tipo
                            print(f"- {value}")
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
                        self.save_results(filename)
                input("\nPress Enter...")
            
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
