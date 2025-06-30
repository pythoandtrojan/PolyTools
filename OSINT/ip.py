#!/usr/bin/env python3

import requests
import sys
import json
import re
import socket
import time
from datetime import datetime
import os
import platform
import subprocess
from typing import Optional, Dict, List, Union

try:
    import nmap
except ImportError:
    nmap = None

try:
    import vulners
except ImportError:
    vulners = None

class Colors:
    """Melhorado: Cores ANSI com verificação de suporte a terminal"""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    BLACK_BG = "\033[40m"
    RED_BG = "\033[41m"

    @classmethod
    def disable_colors(cls):
        """Desativa cores se não suportadas"""
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith('_'):
                setattr(cls, attr, '')

if platform.system() == 'Windows':
    try:
        import colorama
        colorama.init()
    except ImportError:
        Colors.disable_colors()
elif not sys.stdout.isatty():
    Colors.disable_colors()

def clear_screen():
    """Limpa a tela de forma cross-platform"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def show_banner():
    try:
        columns = os.get_terminal_size().columns
    except:
        columns = 80

    clear_screen()
    banner = f"""
{Colors.BLUE}╔{'═' * (columns-2)}╗
║{'IP SCANNER COMPLETO'.center(columns-2)}║
║{'Consulta IP + Portas + Vulnerabilidades'.center(columns-2)}║
╚{'═' * (columns-2)}╝{Colors.RESET}
"""
    print(banner)

def show_menu():

    try:
        columns = os.get_terminal_size().columns
    except:
        columns = 80

    menu_width = min(40, columns - 4)
    border = f"╔{'═' * (menu_width-2)}╗"
    menu_line = f"║{' ' * (menu_width-2)}║"
    
    print(f"""
{Colors.CYAN}{border}
{menu_line}
║{'1. Consultar IP/ipv4/ipv6'.ljust(menu_width-2)}║
║{'2. Modo interativo'.ljust(menu_width-2)}║
║{'3. Scanner Completo (IP+Portas+Vuln)'.ljust(menu_width-2)}║
║{'4. Sair'.ljust(menu_width-2)}║
{menu_line}
{border}{Colors.RESET}
""")

def validate_ip(ip: str) -> bool:
    """Validação robusta de IPv4 e IPv6"""
    
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    
    ipv6_pattern = (
        r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'((?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::((?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|'
        r'::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1}(?::[0-9a-fA-F]{1,4}){1,5}|'
        r'(?:[0-9a-fA-F]{1,4}:){2}(?::[0-9a-fA-F]{1,4}){1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){3}(?::[0-9a-fA-F]{1,4}){1,3}|'
        r'(?:[0-9a-fA-F]{1,4}:){4}(?::[0-9a-fA-F]{1,4}){1,2}|'
        r'(?:[0-9a-fA-F]{1,4}:){5}(?::[0-9a-fA-F]{1,4})|'
        r'(?:[0-9a-fA-F]{1,4}:){6})$'
    )
    
    return re.match(ipv4_pattern, ip) is not None or re.match(ipv6_pattern, ip) is not None

def resolve_domain(domain: str) -> Optional[str]:
    """Resolução de domínio com tratamento robusto de erros"""
    try:
        if not domain:
            raise ValueError("Domínio não pode ser vazio")
            
        
        if validate_ip(domain):
            return domain
            
        
        start_time = time.time()
        ip = socket.gethostbyname(domain)
        resolve_time = time.time() - start_time
        
        print(f"{Colors.BLUE}[+] Domínio resolvido para {ip} em {resolve_time:.2f} segundos{Colors.RESET}")
        return ip
        
    except socket.gaierror as e:
        print(f"{Colors.RED}[-] Erro ao resolver domínio {domain}: {e}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[-] Erro inesperado ao resolver domínio: {e}{Colors.RESET}")
        return None

def check_tor_connection() -> bool:
    """Verifica se o Tor está funcionando corretamente"""
    try:
        response = requests.get(
            'https://check.torproject.org/api/ip',
            proxies={
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            },
            timeout=10
        )
        return response.json().get('IsTor', False)
    except:
        return False

def query_ip(ip: str, use_proxy: bool = False) -> Optional[Dict]:
    """Consulta informações de IP com tratamento robusto de erros"""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    
    proxies = None
    if use_proxy:
        if not check_tor_connection():
            print(f"{Colors.YELLOW}[!] Proxy Tor não está disponível, usando conexão direta{Colors.RESET}")
        else:
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
    
    try:
        start_time = time.time()
        response = requests.get(url, proxies=proxies, timeout=15)
        response_time = time.time() - start_time
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code} - {response.text}")
        
        data = response.json()
        data['response_time_ms'] = round(response_time * 1000, 2)
        
        if data.get('status') == 'fail':
            raise Exception(data.get('message', 'Erro desconhecido na API'))
        
        return data
    
    except requests.exceptions.Timeout:
        print(f"{Colors.RED}[-] Tempo de consulta excedido{Colors.RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[-] Erro na requisição: {e}{Colors.RESET}")
        return None
    except json.JSONDecodeError:
        print(f"{Colors.RED}[-] Resposta inválida da API{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao consultar o IP: {e}{Colors.RESET}")
        return None

def scan_ports(ip: str, port_range: str = "21-443", arguments: str = "-sV") -> Optional[Dict]:
    """Varredura de portas com Nmap com tratamento robusto de erros"""
    if not nmap:
        print(f"{Colors.RED}[-] Biblioteca nmap não instalada. Instale com: pip install python-nmap{Colors.RESET}")
        return None
    
    try:
        print(f"\n{Colors.BLUE}[+] Iniciando varredura de portas em {ip}...{Colors.RESET}")
        
        nm = nmap.PortScanner()
        start_time = time.time()
        

        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            if (end_port - start_port) > 1000:
                print(f"{Colors.YELLOW}[!] Limite de portas excedido. Reduzindo para 1000 portas{Colors.RESET}")
                port_range = f"{start_port}-{start_port + 999}"
        
        nm.scan(ip, port_range, arguments=arguments)
        
        scan_time = time.time() - start_time
        results = []
        
        if ip in nm.all_hosts():
            host = nm[ip]
            
            for proto in host.all_protocols():
                open_ports = host[proto].keys()
                
                for port in sorted(open_ports):
                    port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': host[proto][port]['state'],
                        'service': host[proto][port]['name'],
                        'version': host[proto][port].get('version', 'unknown'),
                        'product': host[proto][port].get('product', 'unknown')
                    }
                    results.append(port_info)
        
        return {
            'scan_time': round(scan_time, 2),
            'open_ports': results
        }
    
    except nmap.PortScannerError as e:
        print(f"{Colors.RED}[-] Erro no Nmap: {e}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[-] Erro durante o scan: {e}{Colors.RESET}")
        return None

def check_vulnerabilities(service: str, version: str, max_results: int = 5) -> Optional[List[Dict]]:
    """Verifica vulnerabilidades com tratamento robusto de erros"""
    if not vulners:
        print(f"{Colors.YELLOW}[!] Biblioteca vulners não instalada. Instale com: pip install vulners{Colors.RESET}")
        return None
    
    if not service or not version or version.lower() == 'unknown':
        return None
        
    try:
        vulners_api = vulners.VulnersApi()
        results = vulners_api.softwareVulnerabilities(service, version)
        
        vulnerabilities = []
        
        if results.get('cvelist'):
            for cve in results['cvelist']:
                vulnerabilities.append({
                    'id': cve.get('id'),
                    'type': cve.get('type'),
                    'title': cve.get('title'),
                    'severity': cve.get('cvss', {}).get('score', 0),
                    'description': cve.get('description'),
                    'reference': cve.get('href')
                })
        
    
        return sorted(vulnerabilities, key=lambda x: x['severity'], reverse=True)[:max_results]
    
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao verificar vulnerabilidades: {e}{Colors.RESET}")
        return None

def get_flag(country_code: str) -> str:
    """Retorna emoji de bandeira para código de país"""
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))
    except:
        return ""

def detect_device(isp: str) -> str:
    """Detecção melhorada de tipo de dispositivo"""
    if not isp:
        return "Unknown"
    
    isp_lower = isp.lower()
    
    
    mobile_keywords = ['mobile', 'celular', 'wireless', '3g', '4g', '5g', 'lte', 'vodafone', 'verizon', 'at&t', 't-mobile']
    if any(keyword in isp_lower for keyword in mobile_keywords):
        return "Mobile Device"
    

    hosting_keywords = ['host', 'server', 'data center', 'cloud', 'amazon', 'google cloud', 'azure', 'digitalocean', 'linode']
    if any(keyword in isp_lower for keyword in hosting_keywords):
        return "Server/Hosting"
    
    
    brands = {
        'apple': 'Apple Device',
        'samsung': 'Samsung Device',
        'xiaomi': 'Xiaomi Device',
        'huawei': 'Huawei Device',
        'motorola': 'Motorola Device',
        'google': 'Google Device',
        'oneplus': 'OnePlus Device',
        'microsoft': 'Microsoft Device'
    }
    
    for brand, name in brands.items():
        if brand in isp_lower:
            return name
    
    return "Unknown"

def format_data(ip_data: Dict, scan_results: Optional[Dict] = None) -> str:
    """Formata os dados de forma mais limpa e segura"""
    if not ip_data:
        return f"{Colors.RED}No data available.{Colors.RESET}"
    
    
    defaults = {
        'query': 'N/A',
        'continent': 'N/A',
        'country': 'N/A',
        'city': 'N/A',
        'isp': 'N/A',
        'org': 'N/A',
        'as': 'N/A',
        'asname': 'N/A',
        'reverse': 'N/A',
        'lat': 'N/A',
        'lon': 'N/A',
        'timezone': 'N/A',
        'currency': 'N/A',
        'regionName': 'N/A',
        'region': 'N/A',
        'district': 'N/A',
        'zip': 'N/A',
        'continentCode': 'N/A',
        'countryCode': 'N/A',
        'mobile': False,
        'proxy': False,
        'hosting': False,
        'response_time_ms': 'N/A'
    }
    

    for key, value in defaults.items():
        ip_data.setdefault(key, value)
    
    
    mobile = f"{Colors.RED}Yes{Colors.RESET}" if ip_data['mobile'] else f"{Colors.GREEN}No{Colors.RESET}"
    proxy = f"{Colors.RED}Yes{Colors.RESET}" if ip_data['proxy'] else f"{Colors.GREEN}No{Colors.RESET}"
    hosting = f"{Colors.RED}Yes{Colors.RESET}" if ip_data['hosting'] else f"{Colors.GREEN}No{Colors.RESET}"
    
    flag = get_flag(ip_data.get('countryCode'))
    device = detect_device(ip_data.get('isp'))
    
    
    output = f"""
{Colors.BLUE}┌───────────────────────────────┐
│{Colors.BOLD}  IP INFORMATION          {Colors.RESET}{Colors.BLUE}│
└───────────────────────────────┘{Colors.RESET}
{Colors.CYAN}• IP:{Colors.RESET} {ip_data['query']}
{Colors.CYAN}• Date/Time:{Colors.RESET} {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
{Colors.CYAN}• Response Time:{Colors.RESET} {ip_data['response_time_ms']} ms

{Colors.YELLOW}┌───────────────────────────────┐
│{Colors.BOLD}  LOCATION               {Colors.RESET}{Colors.YELLOW}│
└───────────────────────────────┘{Colors.RESET}
{Colors.CYAN}• Continent:{Colors.RESET} {ip_data['continent']} ({ip_data['continentCode']})
{Colors.CYAN}• Country:{Colors.RESET} {flag} {ip_data['country']} ({ip_data['countryCode']})
{Colors.CYAN}• Region:{Colors.RESET} {ip_data['regionName']} ({ip_data['region']})
{Colors.CYAN}• City:{Colors.RESET} {ip_data['city']}
{Colors.CYAN}• District:{Colors.RESET} {ip_data['district']}
{Colors.CYAN}• ZIP:{Colors.RESET} {ip_data['zip']}
{Colors.CYAN}• Coordinates:{Colors.RESET} Lat {ip_data['lat']}, Lon {ip_data['lon']}
{Colors.CYAN}• Timezone:{Colors.RESET} {ip_data['timezone']}
{Colors.CYAN}• Currency:{Colors.RESET} {ip_data['currency']}

{Colors.YELLOW}┌───────────────────────────────┐
│{Colors.BOLD}  NETWORK & DEVICE        {Colors.RESET}{Colors.YELLOW}│
└───────────────────────────────┘{Colors.RESET}
{Colors.CYAN}• ISP:{Colors.RESET} {ip_data['isp']}
{Colors.CYAN}• Organization:{Colors.RESET} {ip_data['org']}
{Colors.CYAN}• AS Number/Name:{Colors.RESET} {ip_data['as']} / {ip_data['asname']}
{Colors.CYAN}• Reverse DNS:{Colors.RESET} {ip_data['reverse']}
{Colors.CYAN}• Device Type:{Colors.RESET} {device}

{Colors.YELLOW}┌───────────────────────────────┐
│{Colors.BOLD}  SECURITY DETECTIONS    {Colors.RESET}{Colors.YELLOW}│
└───────────────────────────────┘{Colors.RESET}
{Colors.CYAN}• Mobile:{Colors.RESET} {mobile}
{Colors.CYAN}• Proxy/VPN:{Colors.RESET} {proxy}
{Colors.CYAN}• Hosting/Data Center:{Colors.RESET} {hosting}
"""
    
    
    if scan_results and scan_results.get('open_ports'):
        output += f"""
{Colors.RED}┌───────────────────────────────┐
│{Colors.BOLD}  OPEN PORTS             {Colors.RESET}{Colors.RED}│
└───────────────────────────────┘{Colors.RESET}
{Colors.CYAN}• Scan Time:{Colors.RESET} {scan_results.get('scan_time', 'N/A')} seconds
{Colors.CYAN}• Open Ports Found:{Colors.RESET} {len(scan_results['open_ports'])}
"""
        
        for port in scan_results['open_ports']:
            output += f"""
{Colors.CYAN}┌ Port:{Colors.RESET} {port['port']}/{port['protocol']} - {port['state']}
{Colors.CYAN}├ Service:{Colors.RESET} {port['service']}
{Colors.CYAN}├ Version:{Colors.RESET} {port['version']}
{Colors.CYAN}└ Product:{Colors.RESET} {port['product']}
"""
            
        
            if port['service'] != 'unknown' and port['version'] != 'unknown':
                vulnerabilities = check_vulnerabilities(port['service'], port['version'])
                if vulnerabilities:
                    output += f"    {Colors.RED}  ! Known Vulnerabilities !{Colors.RESET}\n"
                    for vuln in vulnerabilities:
                        severity = ""
                        if vuln['severity'] >= 7.5:
                            severity = f"{Colors.RED}CRITICAL{Colors.RESET}"
                        elif vuln['severity'] >= 5.0:
                            severity = f"{Colors.YELLOW}HIGH{Colors.RESET}"
                        else:
                            severity = f"{Colors.GREEN}MODERATE{Colors.RESET}"
                            
                        output += f"""
{Colors.CYAN}  ├─ {vuln['id']} ({severity})
{Colors.CYAN}  ├─ {vuln['title']}
{Colors.CYAN}  └─ {vuln['reference']}
"""
    
    return output

def save_results(ip_data: Dict, scan_results: Optional[Dict] = None, format_type: str = 'txt') -> bool:
    """Salva resultados com tratamento robusto de erros"""
    if not ip_data:
        return False
    
    ip = ip_data.get('query', 'result')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ip_scan_{ip}_{timestamp}.{format_type}"
    
    try:
    
        os.makedirs("scan_results", exist_ok=True)
        filename = os.path.join("scan_results", filename)
        
        with open(filename, 'w', encoding='utf-8') as f:
            if format_type == 'json':
                complete_result = {
                    'ip_information': ip_data,
                    'port_scan': scan_results
                }
                json.dump(complete_result, f, indent=2, ensure_ascii=False)
            else:
            
                cleaned_output = re.sub(r'\033\[[\d;]+m', '', format_data(ip_data, scan_results))
                f.write(cleaned_output)
        
        print(f"{Colors.GREEN}[+] Results saved to: {filename}{Colors.RESET}")
        return True
        
    except PermissionError:
        print(f"{Colors.RED}[-] Permission denied to save file{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving results: {e}{Colors.RESET}")
        return False

def full_scan():
    """Executa um scan completo com tratamento de erros"""
    target = input("Enter IP or domain for full scan: ").strip()
    if not target:
        print(f"{Colors.RED}[-] No target specified{Colors.RESET}")
        return
    
    ip = target if validate_ip(target) else resolve_domain(target)
    if not ip:
        print(f"{Colors.RED}[-] Invalid target{Colors.RESET}")
        return
    
    print(f"\n{Colors.BLUE}[+] Querying IP information...{Colors.RESET}")
    ip_data = query_ip(ip)
    
    if not ip_data:
        return
    
    print(f"\n{Colors.BLUE}[+] Starting port scan...{Colors.RESET}")
    scan_results = scan_ports(ip, port_range="1-1000", arguments="-sV -T4")
    
    if ip_data or scan_results:
        print(format_data(ip_data, scan_results))
        
        while True:
            save_option = input("\nSave results? (s/n/txt/json): ").lower().strip()
            if save_option in ['s', 'sim', 't', 'txt']:
                save_results(ip_data, scan_results, 'txt')
                break
            elif save_option in ['j', 'json']:
                save_results(ip_data, scan_results, 'json')
                break
            elif save_option in ['n', 'não', 'nao']:
                break
            else:
                print(f"{Colors.RED}Invalid option. Use s/n/txt/json{Colors.RESET}")

def single_query():
    """Consulta única com tratamento de erros"""
    target = input("Enter IP or domain: ").strip()
    if not target:
        print(f"{Colors.RED}[-] No target specified{Colors.RESET}")
        return
    
    ip = target if validate_ip(target) else resolve_domain(target)
    if not ip:
        print(f"{Colors.RED}[-] Invalid target{Colors.RESET}")
        return
    
    print(f"{Colors.BLUE}[+] Querying information...{Colors.RESET}")
    ip_data = query_ip(ip)
    
    if ip_data:
        print(format_data(ip_data))
        
        while True:
            save_option = input("Save results? (s/n/txt/json): ").lower().strip()
            if save_option in ['s', 'sim', 't', 'txt']:
                save_results(ip_data, None, 'txt')
                break
            elif save_option in ['j', 'json']:
                save_results(ip_data, None, 'json')
                break
            elif save_option in ['n', 'não', 'nao']:
                break
            else:
                print(f"{Colors.RED}Invalid option. Use s/n/txt/json{Colors.RESET}")

def interactive_mode():
    """Modo interativo melhorado"""
    while True:
        try:
            print(f"\n{Colors.CYAN}Interactive Mode (type 'exit' to quit){Colors.RESET}")
            target = input("Enter IP or domain (or 'scan' for full scan): ").strip()
            
            if target.lower() in ['exit', 'quit', 'q']:
                break
                
            if not target:
                continue
                
            if target.lower() == 'scan':
                full_scan()
                input("\nPress Enter to continue...")
                clear_screen()
                continue
                
            ip = target if validate_ip(target) else resolve_domain(target)
            if not ip:
                print(f"{Colors.RED}[-] Invalid target{Colors.RESET}")
                continue
            
            print(f"{Colors.BLUE}[+] Querying information...{Colors.RESET}")
            ip_data = query_ip(ip)
            
            if ip_data:
                print(format_data(ip_data))
                
                while True:
                    save_option = input("Save results? (s/n/txt/json): ").lower().strip()
                    if save_option in ['s', 'sim', 't', 'txt']:
                        save_results(ip_data, None, 'txt')
                        break
                    elif save_option in ['j', 'json']:
                        save_results(ip_data, None, 'json')
                        break
                    elif save_option in ['n', 'não', 'nao']:
                        break
                    else:
                        print(f"{Colors.RED}Invalid option. Use s/n/txt/json{Colors.RESET}")
            
            input("\nPress Enter to continue...")
            clear_screen()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Operation cancelled by user{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.RED}[-] Unexpected error: {e}{Colors.RESET}")
            continue

def check_dependencies():
    """Verifica dependências e mostra mensagens úteis"""
    missing = []
    
    if nmap is None:
        missing.append("python-nmap (required for port scanning)")
    
    if vulners is None:
        missing.append("vulners (optional for vulnerability checking)")
    
    if missing:
        print(f"{Colors.YELLOW}[!] Missing dependencies:{Colors.RESET}")
        for dep in missing:
            print(f"  - {dep}")
        print(f"\nInstall with: pip install {' '.join(missing)}\n")

def main():
    """Função principal"""
    check_dependencies()
    show_banner()
    
    
    if len(sys.argv) > 1:
        try:
            targets = []
            use_proxy = False
            save_json = False
            save_txt = False
            full_scan_mode = False
            
            for arg in sys.argv[1:]:
                if arg in ['-p', '--proxy']:
                    use_proxy = True
                elif arg in ['-j', '--json']:
                    save_json = True
                elif arg in ['-t', '--txt']:
                    save_txt = True
                elif arg in ['-s', '--scan']:
                    full_scan_mode = True
                elif arg in ['-h', '--help']:
                    print(f"""
Usage:
  {sys.argv[0]} [OPTIONS] <IP1 IP2...|domain>
  
Options:
  -p, --proxy    Use Tor proxy (requires running Tor)
  -j, --json     Save results as JSON
  -t, --txt      Save results as TXT
  -s, --scan     Perform full scan (IP + Ports + Vulnerabilities)
  -h, --help     Show this help
                    """)
                    sys.exit(0)
                elif validate_ip(arg) or '.' in arg or ':' in arg:
                    ip = arg if validate_ip(arg) else resolve_domain(arg)
                    if ip:
                        targets.append(ip)
                    else:
                        print(f"{Colors.RED}[-] Invalid target: {arg}{Colors.RESET}")
            
            if not targets:
                print(f"{Colors.RED}No valid targets specified.{Colors.RESET}")
                sys.exit(1)
            
            for ip in targets:
                if full_scan_mode:
                    print(f"\n{Colors.CYAN}Performing full scan on: {ip}{Colors.RESET}")
                    
                    ip_data = query_ip(ip, use_proxy)
                    scan_results = scan_ports(ip, port_range="1-1000", arguments="-sV -T4")
                    
                    print(format_data(ip_data, scan_results))
                    
                    if save_txt:
                        save_results(ip_data, scan_results, 'txt')
                    if save_json:
                        save_results(ip_data, scan_results, 'json')
                else:
                    print(f"\n{Colors.CYAN}Querying information for: {ip}{Colors.RESET}")
                    
                    ip_data = query_ip(ip, use_proxy)
                    if ip_data:
                        print(format_data(ip_data))
                        
                        if save_txt:
                            save_results(ip_data, None, 'txt')
                        if save_json:
                            save_results(ip_data, None, 'json')
            
            input("\nPress Enter to exit...")
            sys.exit(0)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Operation cancelled by user{Colors.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Unexpected error: {e}{Colors.RESET}")
            sys.exit(1)
    
    
    while True:
        show_banner()
        show_menu()
        option = input("Select an option: ")
    
        if option == '1':
            show_banner()
            single_query()
            input("\nPress Enter to continue...")
            clear_screen()
        elif option == '2':
            show_banner()
            interactive_mode()
        elif option == '3':
            show_banner()
            full_scan()
            input("\nPress Enter to continue...")
            clear_screen()
        elif option == '4':
            print(f"\n{Colors.GREEN}Exiting...{Colors.RESET}")
            break
        else:
            print(f"\n{Colors.RED}Invalid option!{Colors.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
