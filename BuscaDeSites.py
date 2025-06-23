#!/usr/bin/env python3

import requests
import json
import socket
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
import ssl
import sys
import os
from time import sleep
from colorama import Fore, Style, init

# Inicializa colorama
init(autoreset=True)

class SiteAnalyzer:
    def __init__(self):
        self.current_domain = None
        self.whois_data = None
        self.ssl_data = None
        self.tech_data = None
        self.dns_data = {}
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        self.clear_screen()
        print(Fore.GREEN + """
   ____            _      ____  _ _             
  | __ ) _   _ ___| |__  / ___|(_) |_ ___  ___ 
  |  _ \| | | / __| '_ \ \___ \| | __/ _ \/ __|
  | |_) | |_| \__ \ | | |___) | | ||  __/\__ \\
  |____/ \__,_|___/_| |_|____/|_|\__\___||___/
  """ + Fore.YELLOW + " Busca de Informações de Sites" + Style.RESET_ALL)
        print(Fore.CYAN + "="*60 + Style.RESET_ALL)
        print(Fore.GREEN + " Versão: 2.0 | Termux Compatível | Menu Interativo" + Style.RESET_ALL)
        print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")
    
    def check_internet(self):
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except:
            return False
    
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def get_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def get_whois(self, domain):
        try:
            self.whois_data = whois.whois(domain)
            return True
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro na consulta WHOIS: {str(e)}" + Style.RESET_ALL)
            return False
    
    def get_dns_info(self, domain):
        try:
            # Consulta A (IPv4)
            try:
                self.dns_data['A'] = [a.to_text() for a in dns.resolver.resolve(domain, 'A')]
            except:
                self.dns_data['A'] = None
            
            # Consulta MX (Email)
            try:
                self.dns_data['MX'] = [mx.to_text() for mx in dns.resolver.resolve(domain, 'MX')]
            except:
                self.dns_data['MX'] = None
            
            # Consulta NS (Nameservers)
            try:
                self.dns_data['NS'] = [ns.to_text() for ns in dns.resolver.resolve(domain, 'NS')]
            except:
                self.dns_data['NS'] = None
            
            # Consulta TXT
            try:
                self.dns_data['TXT'] = [txt.to_text() for txt in dns.resolver.resolve(domain, 'TXT')]
            except:
                self.dns_data['TXT'] = None
            
            return True
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro na consulta DNS: {str(e)}" + Style.RESET_ALL)
            return False
    
    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    self.ssl_data = {
                        'valid_until': cert['notAfter'],
                        'issuer': cert['issuer'][0][0][1],
                        'has_ssl': True
                    }
            return True
        except:
            self.ssl_data = {'has_ssl': False}
            return False
    
    def detect_tech(self, domain):
        try:
            url = f"https://api.wappalyzer.com/v2/lookup/?url=https://{domain}"
            headers = {'User-Agent': 'BuscaDeSites/2.0'}
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                self.tech_data = response.json().get('technologies', [])
                return True
            else:
                self.tech_data = None
                return False
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro na detecção de tecnologias: {str(e)}" + Style.RESET_ALL)
            return False
    
    def get_http_headers(self, domain):
        try:
            url = f"http://{domain}"  # Usamos HTTP para evitar redirecionamentos SSL
            response = requests.head(url, allow_redirects=True, timeout=10)
            return response.headers
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro ao obter headers HTTP: {str(e)}" + Style.RESET_ALL)
            return None
    
    def check_site_status(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url, timeout=10)
            return response.status_code
        except Exception as e:
            return f"Erro: {str(e)}"
    
    def show_whois_info(self):
        if not self.whois_data:
            print(Fore.RED + "\n[!] Nenhum dado WHOIS disponível. Execute a consulta primeiro." + Style.RESET_ALL)
            return
        
        print(Fore.YELLOW + "\n=== DADOS DE REGISTRO (WHOIS) ===" + Style.RESET_ALL)
        print(f"Domínio: {self.whois_data.domain_name}")
        print(f"Registrado em: {self.whois_data.creation_date}")
        print(f"Expira em: {self.whois_data.expiration_date}")
        print(f"Registrante: {self.whois_data.name}")
        print(f"Organização: {self.whois_data.org}")
        print(f"País: {self.whois_data.country}")
        print(f"Email do registrante: {self.whois_data.emails}")
        print(f"Servidores WHOIS: {self.whois_data.whois_server}")
    
    def show_dns_info(self):
        if not self.dns_data:
            print(Fore.RED + "\n[!] Nenhum dado DNS disponível. Execute a consulta primeiro." + Style.RESET_ALL)
            return
        
        print(Fore.YELLOW + "\n=== REGISTROS DNS ===" + Style.RESET_ALL)
        
        # Mostrar registros A
        if self.dns_data.get('A'):
            print("\nRegistros A (IPv4):")
            for a in self.dns_data['A']:
                print(f" - {a}")
        else:
            print(Fore.YELLOW + "\n - Nenhum registro A encontrado" + Style.RESET_ALL)
        
        # Mostrar registros MX
        if self.dns_data.get('MX'):
            print("\nRegistros MX (Email):")
            for mx in self.dns_data['MX']:
                print(f" - {mx}")
        else:
            print(Fore.YELLOW + "\n - Nenhum registro MX encontrado" + Style.RESET_ALL)
        
        # Mostrar nameservers
        if self.dns_data.get('NS'):
            print("\nNameservers (NS):")
            for ns in self.dns_data['NS']:
                print(f" - {ns}")
        else:
            print(Fore.YELLOW + "\n - Nenhum nameserver encontrado" + Style.RESET_ALL)
        
        # Mostrar registros TXT
        if self.dns_data.get('TXT'):
            print("\nRegistros TXT:")
            for txt in self.dns_data['TXT']:
                print(f" - {txt}")
        else:
            print(Fore.YELLOW + "\n - Nenhum registro TXT encontrado" + Style.RESET_ALL)
    
    def show_ssl_info(self):
        if not self.ssl_data:
            print(Fore.RED + "\n[!] Nenhum dado SSL disponível. Execute a consulta primeiro." + Style.RESET_ALL)
            return
        
        print(Fore.YELLOW + "\n=== CERTIFICADO SSL ===" + Style.RESET_ALL)
        if self.ssl_data['has_ssl']:
            print(f"Válido até: {self.ssl_data['valid_until']}")
            print(f"Emitido por: {self.ssl_data['issuer']}")
            print(f"Usa SSL/TLS: Sim")
        else:
            print(Fore.RED + "O site não usa SSL/TLS ou ocorreu um erro na verificação" + Style.RESET_ALL)
    
    def show_tech_info(self):
        if not self.tech_data:
            print(Fore.RED + "\n[!] Nenhum dado de tecnologias disponível. Execute a consulta primeiro." + Style.RESET_ALL)
            return
        
        print(Fore.YELLOW + "\n=== TECNOLOGIAS DETECTADAS ===" + Style.RESET_ALL)
        if self.tech_data:
            for tech in self.tech_data:
                print(f"{tech['name']} ({tech['categories'][0]['name']})")
        else:
            print(Fore.YELLOW + " - Nenhuma tecnologia detectada" + Style.RESET_ALL)
    
    def show_http_headers(self, headers):
        if not headers:
            print(Fore.RED + "\n[!] Não foi possível obter os headers HTTP" + Style.RESET_ALL)
            return
        
        print(Fore.YELLOW + "\n=== HEADERS HTTP ===" + Style.RESET_ALL)
        for key, value in headers.items():
            print(f"{key}: {value}")
    
    def show_site_status(self, status):
        print(Fore.YELLOW + "\n=== STATUS DO SITE ===" + Style.RESET_ALL)
        print(f"Status HTTP: {status}")
    
    def full_scan(self, domain):
        print(Fore.BLUE + f"\nIniciando análise completa do domínio: {domain}" + Style.RESET_ALL)
        
        print(Fore.CYAN + "\n[+] Consultando dados WHOIS..." + Style.RESET_ALL)
        self.get_whois(domain)
        
        print(Fore.CYAN + "\n[+] Consultando registros DNS..." + Style.RESET_ALL)
        self.get_dns_info(domain)
        
        print(Fore.CYAN + "\n[+] Verificando certificado SSL..." + Style.RESET_ALL)
        self.check_ssl(domain)
        
        print(Fore.CYAN + "\n[+] Detectando tecnologias usadas..." + Style.RESET_ALL)
        self.detect_tech(domain)
        
        print(Fore.CYAN + "\n[+] Verificando status do site..." + Style.RESET_ALL)
        status = self.check_site_status(domain)
        
        print(Fore.CYAN + "\n[+] Obtendo headers HTTP..." + Style.RESET_ALL)
        headers = self.get_http_headers(domain)
        
        # Mostrar resultados
        self.show_whois_info()
        self.show_dns_info()
        self.show_ssl_info()
        self.show_tech_info()
        self.show_site_status(status)
        self.show_http_headers(headers)
        
        print(Fore.GREEN + "\n[+] Análise completa concluída!" + Style.RESET_ALL)
    
    def show_menu(self):
        while True:
            self.show_banner()
            
            if self.current_domain:
                print(Fore.MAGENTA + f"Domínio atual: {self.current_domain}\n" + Style.RESET_ALL)
            else:
                print(Fore.RED + "Nenhum domínio definido. Use a opção 1 primeiro.\n" + Style.RESET_ALL)
            
            print(Fore.CYAN + "Menu Principal:" + Style.RESET_ALL)
            print("1. Definir/alterar domínio para análise")
            print("2. Análise completa do domínio")
            print("3. Consultar dados WHOIS")
            print("4. Consultar registros DNS")
            print("5. Verificar certificado SSL")
            print("6. Detectar tecnologias usadas")
            print("7. Verificar status do site")
            print("8. Obter headers HTTP")
            print("9. Sair")
            
            try:
                option = input("\nSelecione uma opção: ")
                
                if option == '1':
                    domain = input("\nDigite o domínio/URL para análise: ").strip()
                    if domain:
                        self.current_domain = self.get_domain(self.normalize_url(domain))
                        print(Fore.GREEN + f"\nDomínio definido como: {self.current_domain}" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + "\n[!] Domínio inválido." + Style.RESET_ALL)
                    input("\nPressione Enter para continuar...")
                
                elif option == '2':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    self.full_scan(self.current_domain)
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '3':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Consultando dados WHOIS..." + Style.RESET_ALL)
                    if self.get_whois(self.current_domain):
                        self.show_whois_info()
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '4':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Consultando registros DNS..." + Style.RESET_ALL)
                    if self.get_dns_info(self.current_domain):
                        self.show_dns_info()
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '5':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Verificando certificado SSL..." + Style.RESET_ALL)
                    if self.check_ssl(self.current_domain):
                        self.show_ssl_info()
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '6':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Detectando tecnologias usadas..." + Style.RESET_ALL)
                    if self.detect_tech(self.current_domain):
                        self.show_tech_info()
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '7':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Verificando status do site..." + Style.RESET_ALL)
                    status = self.check_site_status(self.current_domain)
                    self.show_site_status(status)
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '8':
                    if not self.current_domain:
                        print(Fore.RED + "\n[!] Nenhum domínio definido." + Style.RESET_ALL)
                        input("\nPressione Enter para continuar...")
                        continue
                    
                    print(Fore.CYAN + "\n[+] Obtendo headers HTTP..." + Style.RESET_ALL)
                    headers = self.get_http_headers(self.current_domain)
                    self.show_http_headers(headers)
                    input("\nPressione Enter para voltar ao menu...")
                
                elif option == '9':
                    print(Fore.YELLOW + "\nSaindo..." + Style.RESET_ALL)
                    break
                
                else:
                    print(Fore.RED + "\n[!] Opção inválida." + Style.RESET_ALL)
                    input("\nPressione Enter para continuar...")
            
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Interrompido pelo usuário." + Style.RESET_ALL)
                break

def main():
    if not SiteAnalyzer().check_internet():
        print(Fore.RED + "\n[!] Sem conexão com a internet. Verifique sua conexão." + Style.RESET_ALL)
        sys.exit(1)
    
    analyzer = SiteAnalyzer()
    analyzer.show_menu()

if __name__ == "__main__":
    main()
