#!/usr/bin/env python3

import requests
import socket
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
import ssl
import sys
import os
import json
from time import time
from colorama import Fore, Style, init
import random
import logging
from functools import lru_cache

init(autoreset=True)

class SiteInvestigator:
    def __init__(self):
        self.current_target = None
        self.results = {}
        self.timeout = 10  
        
      
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='site_investigator.log'
        )
        self.logger = logging.getLogger(__name__)
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        self.clear_screen()
        print(Fore.RED + """
   ██████╗ ██╗████████╗███████╗     ██████╗ ███████╗███╗   ██╗
  ██╔════╝ ██║╚══██╔══╝██╔════╝    ██╔═══██╗██╔════╝████╗  ██║
  ██║  ███╗██║   ██║   █████╗      ██║   ██║█████╗  ██╔██╗ ██║
  ██║   ██║██║   ██║   ██╔══╝      ██║   ██║██╔══╝  ██║╚██╗██║
  ╚██████╔╝██║   ██║   ███████╗    ╚██████╔╝███████╗██║ ╚████║
   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚══════╝╚═╝  ╚═══╝
  """ + Fore.YELLOW + "  Ferramenta de Investigação Digital" + Style.RESET_ALL)
        print(Fore.CYAN + "═"*70 + Style.RESET_ALL)
        print(Fore.GREEN + " Versão: 2.3 | Modo Forense | Análise Avançada" + Style.RESET_ALL)
        print(Fore.CYAN + "═"*70 + Style.RESET_ALL + "\n")
    
    def check_internet(self):
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except Exception as e:
            self.logger.error(f"Sem conexão com a internet: {str(e)}")
            return False
    
    def normalize_target(self, target):
        """Normaliza URLs e domínios para análise"""
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            if any(c in target for c in ['/', ':', '?', '=']):
                target = 'http://' + target
        return target
    
    def extract_domain(self, target):
        """Extrai o domínio principal de uma URL"""
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                domain = parsed.netloc
            else:
                domain = target.split('/')[0].split(':')[0]
            
          
            return domain.split(':')[0]
        except Exception as e:
            self.logger.error(f"Erro ao extrair domínio: {str(e)}")
            return target
    
    def is_valid_domain(self, domain):
        """Verifica se o domínio é válido"""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.error) as e:
            self.logger.warning(f"Domínio inválido: {domain} - {str(e)}")
            return False
    
    @lru_cache(maxsize=32)
    def get_ip_address(self, domain):
        """Obtém endereços IP com cache"""
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
            return ip_list or None
        except (socket.gaierror, UnicodeError) as e:
            self.logger.error(f"Erro ao obter IPs para {domain}: {str(e)}")
            return None
    
    def get_ip_geolocation(self, ip):
        """Obtém geolocalização do IP"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning(f"Erro na geolocalização do IP {ip}: {str(e)}")
        return None
    
    @lru_cache(maxsize=32)
    def get_whois_info(self, domain):
        """Obtém informações WHOIS com cache"""
        try:
            whois_data = whois.whois(domain)
            
            def normalize_field(field):
                if field is None:
                    return "N/A"
                if isinstance(field, list):
                    return [str(item) for item in field if item is not None]
                return str(field)
            
            def get_date(field):
                if not field:
                    return "N/A"
                if isinstance(field, list):
                    return field[0].isoformat() if field else "N/A"
                return field.isoformat() if hasattr(field, 'isoformat') else str(field)
            
            return {
                'domain_name': normalize_field(whois_data.domain_name),
                'registrar': normalize_field(whois_data.registrar),
                'creation_date': get_date(whois_data.creation_date),
                'expiration_date': get_date(whois_data.expiration_date),
                'last_updated': get_date(whois_data.last_updated),
                'name_servers': normalize_field(whois_data.name_servers),
                'registrant_name': normalize_field(whois_data.name),
                'registrant_organization': normalize_field(whois_data.org),
                'registrant_country': normalize_field(whois_data.country),
                'emails': normalize_field(whois_data.emails),  # Corrigido o typo
                'status': normalize_field(whois_data.status)
            }
        except Exception as e:
            self.logger.error(f"Erro WHOIS para {domain}: {str(e)}")
            return {'error': f"Erro WHOIS: {str(e)}"}
    
    def check_common_ports(self, domain):
        """Verifica portas comuns abertas"""
        common_ports = [21, 22, 80, 443, 3306, 3389]
        open_ports = []
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((domain, port))
                    open_ports.append(port)
            except:
                continue
        return open_ports
    
    def get_dns_records(self, domain):
        """Obtém registros DNS com tratamento de timeout"""
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5  
        resolver.lifetime = 5
        
        record_types = [
            ('A', 'IPv4'),
            ('AAAA', 'IPv6'),
            ('MX', 'Email'),
            ('NS', 'Nameservers'),
            ('TXT', 'TXT'),
            ('SOA', 'SOA'),
            ('CNAME', 'CNAME'),
            ('PTR', 'PTR')
        ]
        
        for rtype, name in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except dns.resolver.Timeout:
                records[rtype] = f"[Timeout] A consulta excedeu {resolver.timeout} segundos"
                self.logger.warning(f"Timeout DNS para {rtype} em {domain}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = None
            except dns.resolver.NoNameservers:
                records[rtype] = "[Erro] Todos os nameservers falharam"
                self.logger.error(f"Falha nos nameservers para {domain}")
            except Exception as e:
                records[rtype] = f"[Erro] {str(e)}"
                self.logger.error(f"Erro DNS {rtype} para {domain}: {str(e)}")
        
        return records
    
    def check_ssl_certificate(self, domain):
        """Verifica certificado SSL com fallback para HTTP"""
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {
                            'has_ssl': False,
                            'error': "Nenhum certificado encontrado",
                            'protocol': 'HTTPS (Sem certificado)'
                        }
                    return self._parse_ssl_cert(cert, True)
        except ssl.SSLCertVerificationError as e:
            self.logger.error(f"Erro de verificação SSL para {domain}: {str(e)}")
            return {
                'has_ssl': False,
                'error': f"Problema de validação SSL: {str(e)}",
                'protocol': 'HTTPS (Inválido)'
            }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError) as e:
            self.logger.warning(f"Falha SSL para {domain}, tentando HTTP: {str(e)}")
            try:
                with socket.create_connection((domain, 80), timeout=self.timeout) as sock:
                    return {
                        'has_ssl': False,
                        'error': f"Site usa HTTP apenas: {str(e)}",
                        'protocol': 'HTTP'
                    }
            except Exception as e:
                self.logger.error(f"Falha ao conectar em {domain}: {str(e)}")
                return {
                    'has_ssl': False,
                    'error': f"Falha ao conectar: {str(e)}",
                    'protocol': 'Indisponível'
                }
    
    def _parse_ssl_cert(self, cert, is_valid):
        """Analisa certificado SSL"""
        try:
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            remaining_days = (not_after - datetime.now()).days
            
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            
            return {
                'issued_by': issuer.get('organizationName', issuer.get('commonName', 'Desconhecido')),
                'valid_from': cert['notBefore'],
                'valid_to': cert['notAfter'],
                'is_valid': is_valid and (datetime.now() > not_before) and (datetime.now() < not_after),
                'days_remaining': remaining_days,
                'subject': subject,
                'version': cert.get('version', 'Desconhecido'),
                'serial_number': cert.get('serialNumber', 'Desconhecido'),
                'signature_algorithm': cert.get('signatureAlgorithm', 'Desconhecido'),
                'protocol': 'HTTPS',
                'has_ssl': True
            }
        except Exception as e:
            self.logger.error(f"Erro ao analisar certificado: {str(e)}")
            return {
                'has_ssl': False,
                'error': f"Erro ao analisar certificado: {str(e)}",
                'protocol': 'HTTPS (Inválido)'
            }
    
    def detect_cms(self, headers):
        """Detecta CMS baseado em headers"""
        server = headers.get('Server', '').lower()
        all_headers = str(headers).lower()
        
        if 'wordpress' in server or 'wp-content' in all_headers:
            return 'WordPress'
        if 'drupal' in server:
            return 'Drupal'
        if 'joomla' in server:
            return 'Joomla'
        return 'Desconhecido'
    
    def get_http_headers(self, url):
        """Obtém headers HTTP com tratamento de redirecionamentos e encoding"""
        user_agent = (
            f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{random.randint(80, 90)}.0.{random.randint(1000, 9999)}."
            f"{random.randint(10, 99)} Safari/537.36"
        )
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            response = requests.head(
                url, 
                allow_redirects=True, 
                timeout=self.timeout,
                headers={'User-Agent': user_agent}
            )
            
            def decode_header(h):
                if isinstance(h, bytes):
                    return h.decode('utf-8', errors='replace')
                return str(h)
            
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy'
            ]
            
            headers = {k: decode_header(v) for k, v in response.headers.items()}
            security_info = {h: headers.get(h, 'Não configurado') for h in security_headers}
            
            result = {
                'final_url': response.url,
                'status_code': response.status_code,
                'server': headers.get('Server', 'Desconhecido'),
                'content_type': headers.get('Content-Type', 'Desconhecido'),
                'security_headers': security_info,
                'all_headers': headers,
                'detected_cms': self.detect_cms(headers)
            }
            
            self.logger.info(f"Headers obtidos para {url}: {response.status_code}")
            return result
            
        except requests.exceptions.SSLError:
            try:
                response = requests.head(
                    url, 
                    allow_redirects=True, 
                    timeout=self.timeout,
                    headers={'User-Agent': user_agent},
                    verify=False
                )
                headers = dict(response.headers)
                return {
                    'final_url': response.url,
                    'status_code': response.status_code,
                    'server': headers.get('Server', 'Desconhecido'),
                    'content_type': headers.get('Content-Type', 'Desconhecido'),
                    'ssl_warning': 'Certificado SSL inválido/auto-assinado',
                    'all_headers': headers,
                    'detected_cms': self.detect_cms(headers)
                }
            except Exception as e:
                self.logger.error(f"Erro HTTPS (com fallback) para {url}: {str(e)}")
                return {'error': f"Erro HTTPS (com fallback): {str(e)}"}
        except Exception as e:
            self.logger.error(f"Erro HTTP para {url}: {str(e)}")
            return {'error': f"Erro HTTP: {str(e)}"}
    
    def scan_website(self, target):
        """Executa varredura completa no alvo"""
        start_time = time()
        
        try:
            normalized = self.normalize_target(target)
            domain = self.extract_domain(normalized)
            
            if not self.is_valid_domain(domain):
                print(Fore.RED + f"\n[!] Domínio inválido: {domain}" + Style.RESET_ALL)
                self.logger.error(f"Domínio inválido fornecido: {domain}")
                return None
            
            print(Fore.BLUE + f"\n[+] Iniciando investigação em: {domain}" + Style.RESET_ALL)
            self.logger.info(f"Iniciando investigação para {domain}")
            
            self.results = {
                'target': target,
                'normalized': normalized,
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'scan_duration': None
            }
            
            checks = [
                ('Endereços IP', self.get_ip_address, domain, 'ip_addresses'),
                ('WHOIS', self.get_whois_info, domain, 'whois'),
                ('Registros DNS', self.get_dns_records, domain, 'dns_records'),
                ('Certificado SSL', self.check_ssl_certificate, domain, 'ssl_certificate'),
                ('Portas comuns', self.check_common_ports, domain, 'open_ports'),
                ('Cabeçalhos HTTP', self.get_http_headers, normalized, 'http_headers')
            ]
            
            for name, func, arg, key in checks:
                try:
                    print(Fore.CYAN + f"\n[+] {name}..." + Style.RESET_ALL)
                    self.results[key] = func(arg)
                    
                
                    if key == 'ip_addresses' and self.results[key]:
                        self.results['ip_geolocation'] = [
                            self.get_ip_geolocation(ip) for ip in self.results[key]
                        ]
                except Exception as e:
                    self.results[key] = {'error': f"Erro inesperado: {str(e)}"}
                    self.logger.error(f"Erro durante {name.lower()} para {domain}: {str(e)}")
                    print(Fore.RED + f" [!] Erro durante {name.lower()}: {str(e)}" + Style.RESET_ALL)
            
            self.results['scan_duration'] = round(time() - start_time, 2)
            self.logger.info(f"Investigação concluída para {domain} em {self.results['scan_duration']}s")
            
            print(Fore.GREEN + f"\n[+] Investigação concluída em {self.results['scan_duration']} segundos" + Style.RESET_ALL)
            return self.results
        
        except Exception as e:
            self.logger.error(f"Erro fatal durante a investigação de {target}: {str(e)}")
            print(Fore.RED + f"\n[!] Erro fatal durante a investigação: {str(e)}" + Style.RESET_ALL)
            return None
    
    def display_results(self):
        """Exibe resultados formatados com cores"""
        if not self.results:
            print(Fore.RED + "\n[!] Nenhum resultado disponível. Execute uma investigação primeiro." + Style.RESET_ALL)
            return
        
        COLOR_TITLE = Fore.YELLOW
        COLOR_HEADER = Fore.CYAN
        COLOR_GOOD = Fore.GREEN
        COLOR_BAD = Fore.RED
        COLOR_WARN = Fore.MAGENTA
        COLOR_INFO = Fore.BLUE
        
        print(COLOR_TITLE + "\n═"*70 + Style.RESET_ALL)
        print(COLOR_TITLE + " RESUMO DA INVESTIGAÇÃO DIGITAL" + Style.RESET_ALL)
        print(COLOR_TITLE + "═"*70 + Style.RESET_ALL)
        
        print(f"\n{COLOR_HEADER}[ℹ] Alvo:{Style.RESET_ALL} {self.results['target']}")
        print(f"{COLOR_HEADER}[ℹ] Domínio normalizado:{Style.RESET_ALL} {self.results['normalized']}")
        print(f"{COLOR_HEADER}[ℹ] Data/hora:{Style.RESET_ALL} {self.results['timestamp']}")
        print(f"{COLOR_HEADER}[ℹ] Duração:{Style.RESET_ALL} {self.results['scan_duration']} segundos")
        
        
        print(f"\n{COLOR_HEADER}[🌐] Endereços IP:{Style.RESET_ALL}")
        if self.results['ip_addresses']:
            for ip in self.results['ip_addresses']:
                print(f" - {COLOR_INFO}{ip}{Style.RESET_ALL}")
                
            
                if 'ip_geolocation' in self.results:
                    geo = next((g for g in self.results['ip_geolocation'] if g and g.get('query') == ip), None)
                    if geo:
                        print(f"   → País: {geo.get('country', 'N/A')}")
                        print(f"   → Cidade: {geo.get('city', 'N/A')}")
                        print(f"   → ISP: {geo.get('isp', 'N/A')}")
        else:
            print(f" - {COLOR_BAD}Não encontrado{Style.RESET_ALL}")
        
    
        if 'open_ports' in self.results:
            print(f"\n{COLOR_HEADER}[🔌] Portas abertas:{Style.RESET_ALL}")
            if self.results['open_ports']:
                for port in self.results['open_ports']:
                    service = {
                        21: 'FTP',
                        22: 'SSH',
                        80: 'HTTP',
                        443: 'HTTPS',
                        3306: 'MySQL',
                        3389: 'RDP'
                    }.get(port, 'Desconhecido')
                    print(f" - {COLOR_INFO}Porta {port}{Style.RESET_ALL} ({service})")
            else:
                print(f" - {COLOR_INFO}Nenhuma porta comum aberta encontrada{Style.RESET_ALL}")
        
        
        print(f"\n{COLOR_HEADER}[📋] Informações WHOIS:{Style.RESET_ALL}")
        whois_data = self.results.get('whois', {})
        if 'error' in whois_data:
            print(f" - {COLOR_BAD}{whois_data['error']}{Style.RESET_ALL}")
        else:
            for key, value in whois_data.items():
                if value and value != "N/A":
                    print(f" - {COLOR_INFO}{key.replace('_', ' ').title()}:{Style.RESET_ALL} {value}")
        
        # DNS
        print(f"\n{COLOR_HEADER}[🔍] Registros DNS:{Style.RESET_ALL}")
        dns_data = self.results.get('dns_records', {})
        for rtype, records in dns_data.items():
            if records:
                print(f" - {COLOR_INFO}{rtype}:{Style.RESET_ALL}")
                if isinstance(records, list):
                    for r in records:
                        print(f"   * {r}")
                else:
                    print(f"   {records}")
        
        # SSL
        print(f"\n{COLOR_HEADER}[🔒] Certificado SSL:{Style.RESET_ALL}")
        ssl_data = self.results.get('ssl_certificate', {})
        if 'error' in ssl_data:
            print(f" - {COLOR_BAD}{ssl_data['error']}{Style.RESET_ALL}")
        else:
            for key, value in ssl_data.items():
                if key == 'is_valid':
                    status = COLOR_GOOD + "VÁLIDO" if value else COLOR_BAD + "INVÁLIDO/EXPIRADO"
                    print(f" - {COLOR_INFO}Status:{Style.RESET_ALL} {status}{Style.RESET_ALL}")
                elif key == 'days_remaining' and isinstance(value, int):
                    color = COLOR_GOOD if value > 30 else COLOR_WARN if value > 0 else COLOR_BAD
                    print(f" - {COLOR_INFO}Dias restantes:{Style.RESET_ALL} {color}{value}{Style.RESET_ALL}")
                elif key not in ('error', 'has_ssl'):
                    print(f" - {COLOR_INFO}{key.replace('_', ' ').title()}:{Style.RESET_ALL} {value}")
        
        # HTTP Headers
        print(f"\n{COLOR_HEADER}[📡] Cabeçalhos HTTP:{Style.RESET_ALL}")
        headers_data = self.results.get('http_headers', {})
        if 'error' in headers_data:
            print(f" - {COLOR_BAD}{headers_data['error']}{Style.RESET_ALL}")
        else:
            print(f" - {COLOR_INFO}URL final:{Style.RESET_ALL} {headers_data.get('final_url', 'N/A')}")
            
            status_code = headers_data.get('status_code', 0)
            if 200 <= status_code < 300:
                status_color = COLOR_GOOD
            elif 300 <= status_code < 400:
                status_color = COLOR_WARN
            else:
                status_color = COLOR_BAD
            print(f" - {COLOR_INFO}Status Code:{Style.RESET_ALL} {status_color}{status_code}{Style.RESET_ALL}")
            
            print(f" - {COLOR_INFO}Servidor:{Style.RESET_ALL} {headers_data.get('server', 'N/A')}")
            
            # CMS detectado
            if 'detected_cms' in headers_data:
                cms = headers_data['detected_cms']
                if cms != 'Desconhecido':
                    print(f" - {COLOR_INFO}CMS detectado:{Style.RESET_ALL} {COLOR_GOOD}{cms}{Style.RESET_ALL}")
            
            # Cabeçalhos de segurança
            print(f"\n   {COLOR_HEADER}🔐 Cabeçalhos de Segurança:{Style.RESET_ALL}")
            security = headers_data.get('security_headers', {})
            for header, value in security.items():
                if value != 'Não configurado':
                    print(f"   * {COLOR_GOOD}{header}:{Style.RESET_ALL} {value}")
                else:
                    print(f"   * {COLOR_BAD}{header}:{Style.RESET_ALL} {value}")
            
            if headers_data.get('ssl_warning'):
                print(f"\n   {COLOR_WARN}⚠ Aviso: {headers_data['ssl_warning']}{Style.RESET_ALL}")
    
    def save_results(self, filename):
        """Salva resultados em JSON com verificação de path"""
        if not self.results:
            print(Fore.RED + "\n[!] Nenhum resultado para salvar." + Style.RESET_ALL)
            return False
        
        try:
            dirname = os.path.dirname(filename)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
            
            if os.path.exists(filename):
                if not os.access(filename, os.W_OK):
                    print(Fore.RED + f"\n[!] Sem permissão para escrever em {filename}" + Style.RESET_ALL)
                    return False
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            print(Fore.GREEN + f"\n[✓] Resultados salvos em {os.path.abspath(filename)}" + Style.RESET_ALL)
            self.logger.info(f"Resultados salvos em {filename}")
            return True
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro ao salvar resultados: {str(e)}" + Style.RESET_ALL)
            self.logger.error(f"Erro ao salvar em {filename}: {str(e)}")
            return False
    
    def interactive_menu(self):
        """Menu interativo melhorado"""
        while True:
            self.show_banner()
            
            if self.results:
                last_target = self.results.get('domain', 'Nenhum')
                print(Fore.MAGENTA + f" Último alvo: {last_target}")
                print(Fore.CYAN + "═"*70 + Style.RESET_ALL)
            
            print(Fore.YELLOW + " MENU PRINCIPAL" + Style.RESET_ALL)
            print("1. 🔍 Investigar novo alvo (URL/Domínio)")
            print("2. 📊 Exibir resultados da última investigação")
            print("3. 💾 Salvar resultados em arquivo JSON")
            print("4. 🚪 Sair")
            
            try:
                choice = input("\n[?] Selecione uma opção (1-4): ").strip()
                
                if choice == '1':
                    target = input("\n[?] Digite a URL ou domínio para investigar: ").strip()
                    if target:
                        self.scan_website(target)
                    else:
                        print(Fore.RED + "\n[!] Alvo inválido." + Style.RESET_ALL)
                    input("\n↵ Pressione Enter para continuar...")
                
                elif choice == '2':
                    self.display_results()
                    input("\n↵ Pressione Enter para continuar...")
                
                elif choice == '3':
                    if not self.results:
                        print(Fore.RED + "\n[!] Nenhum resultado para salvar." + Style.RESET_ALL)
                        input("\n↵ Pressione Enter para continuar...")
                        continue
                    
                    default_file = f"resultados_{self.results['domain']}.json"
                    filename = input(f"\n[?] Nome do arquivo (Enter para '{default_file}'): ").strip()
                    filename = filename or default_file
                    
                    if not filename.endswith('.json'):
                        filename += '.json'
                    
                    self.save_results(filename)
                    input("\n↵ Pressione Enter para continuar...")
                
                elif choice == '4':
                    print(Fore.YELLOW + "\n[!] Encerrando ferramenta..." + Style.RESET_ALL)
                    break
                
                else:
                    print(Fore.RED + "\n[!] Opção inválida." + Style.RESET_ALL)
                    input("\n↵ Pressione Enter para continuar...")
            
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Interrompido pelo usuário." + Style.RESET_ALL)
                break

def main():
    
    if not SiteInvestigator().check_internet():
        print(Fore.RED + "\n[!] Sem conexão com a internet. Verifique sua conexão." + Style.RESET_ALL)
        sys.exit(1)
    
    
    try:
        import dns.resolver
        import whois
        import requests
    except ImportError as e:
        print(Fore.RED + f"\n[!] Erro: {str(e)}" + Style.RESET_ALL)
        print(Fore.YELLOW + "[!] Instale as dependências com: pip install -r requirements.txt" + Style.RESET_ALL)
        sys.exit(1)
    
    
    investigator = SiteInvestigator()
    investigator.interactive_menu()

if __name__ == "__main__":
    main()
