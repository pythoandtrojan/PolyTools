#!/usr/bin/env python3
import requests
import threading
import time
import os
import sys
from datetime import datetime
from colorama import Fore, Style, init
import argparse
from typing import List, Dict, Set
import json

# Inicialização do colorama
init(autoreset=True)

# Constantes de cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

class SubdomainScanner:
    def __init__(self, timeout: int = 5, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self.found_subdomains = []
        self.lock = threading.Lock()
        self.checked_count = 0
        self.total_count = 0
        
    def banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""
{CIANO}{NEGRITO}
   ____  _   _ ____  _____  _   _ ____  ____  
  / ___|| | | | __ )| ____|| | | |  _ \|  _ \ 
  \___ \| | | |  _ \|  _|  | | | | | | | | | |
   ___) | |_| | |_) | |___ | |_| | |_| | |_| |
  |____/ \___/|____/|_____| \___/|____/|____/ 
{RESET}
{VERDE}{NEGRITO}   SCANNER DE SUBDOMÍNIOS - PROFESSIONAL
   Versão 2.0 - Multi-threaded
{RESET}
{AMARELO}   Threads: {self.threads} | Timeout: {self.timeout}s
   Wordlists: wordlists/
{RESET}""")

    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Carrega a wordlist de subdomínios"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except FileNotFoundError:
            print(f"{VERMELHO}[!] Wordlist não encontrada: {wordlist_path}{RESET}")
            return []
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao carregar wordlist: {e}{RESET}")
            return []

    def check_subdomain(self, domain: str, subdomain: str):
        """Verifica se um subdomínio existe"""
        url = f"http://{subdomain}.{domain}"
        url_https = f"https://{subdomain}.{domain}"
        
        try:
            response = requests.get(url_https, timeout=self.timeout, verify=False)
            with self.lock:
                self.checked_count += 1
                if response.status_code < 400:
                    self.found_subdomains.append({
                        'subdomain': f"{subdomain}.{domain}",
                        'url': url_https,
                        'status_code': response.status_code,
                        'ip': response.raw._connection.sock.getpeername()[0] if response.raw else 'N/A'
                    })
                    print(f"{VERDE}[+] {subdomain}.{domain} - Status: {response.status_code}{RESET}")
                else:
                    print(f"{AMARELO}[-] {subdomain}.{domain} - Status: {response.status_code}{RESET}")
            return
        except requests.exceptions.SSLError:
            pass  # Tenta HTTP
        except:
            pass  # Subdomínio não existe
        
        try:
            response = requests.get(url, timeout=self.timeout)
            with self.lock:
                self.checked_count += 1
                if response.status_code < 400:
                    self.found_subdomains.append({
                        'subdomain': f"{subdomain}.{domain}",
                        'url': url,
                        'status_code': response.status_code,
                        'ip': response.raw._connection.sock.getpeername()[0] if response.raw else 'N/A'
                    })
                    print(f"{VERDE}[+] {subdomain}.{domain} - Status: {response.status_code}{RESET}")
                else:
                    print(f"{AMARELO}[-] {subdomain}.{domain} - Status: {response.status_code}{RESET}")
        except:
            with self.lock:
                self.checked_count += 1
                print(f"{VERMELHO}[-] {subdomain}.{domain} - Inacessível{RESET}")

    def scan_domain(self, domain: str, wordlist_path: str) -> List[Dict]:
        """Executa o scan de subdomínios"""
        print(f"\n{CIANO}[*] Carregando wordlist...{RESET}")
        subdomains = self.load_wordlist(wordlist_path)
        
        if not subdomains:
            return []
            
        self.total_count = len(subdomains)
        self.checked_count = 0
        self.found_subdomains = []
        
        print(f"{CIANO}[*] Iniciando scan em {domain}...{RESET}")
        print(f"{CIANO}[*] Total de subdomínios para testar: {self.total_count}{RESET}")
        print(f"{CIANO}[*] Usando {self.threads} threads{RESET}\n")
        
        start_time = time.time()
        
        # Dividir a wordlist em chunks para threading
        chunk_size = max(1, len(subdomains) // self.threads)
        threads = []
        
        for i in range(0, len(subdomains), chunk_size):
            chunk = subdomains[i:i + chunk_size]
            thread = threading.Thread(
                target=self._scan_chunk, 
                args=(domain, chunk)
            )
            threads.append(thread)
            thread.start()
        
        # Barra de progresso
        self._show_progress(start_time)
        
        # Aguardar todas as threads
        for thread in threads:
            thread.join()
        
        elapsed_time = time.time() - start_time
        print(f"\n{VERDE}[+] Scan concluído em {elapsed_time:.2f} segundos{RESET}")
        print(f"{VERDE}[+] Subdomínios encontrados: {len(self.found_subdomains)}{RESET}")
        
        return self.found_subdomains

    def _scan_chunk(self, domain: str, subdomains: List[str]):
        """Escaneia um chunk de subdomínios"""
        for subdomain in subdomains:
            self.check_subdomain(domain, subdomain)

    def _show_progress(self, start_time: float):
        """Mostra barra de progresso"""
        while self.checked_count < self.total_count:
            elapsed = time.time() - start_time
            progress = (self.checked_count / self.total_count) * 100
            print(f"\r{AZUL}[*] Progresso: {progress:.1f}% ({self.checked_count}/{self.total_count}) - Tempo: {elapsed:.1f}s", end="")
            time.sleep(0.5)
        
        print(f"\r{VERDE}[*] Progresso: 100.0% ({self.total_count}/{self.total_count}) - Concluído!{RESET}")

    def save_results(self, results: List[Dict], domain: str, format: str = 'txt'):
        """Salva os resultados em arquivo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"subdomains_{domain}_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        elif format == 'csv':
            filename = f"subdomains_{domain}_{timestamp}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['subdomain', 'url', 'status_code', 'ip'])
                writer.writeheader()
                writer.writerows(results)
        else:
            filename = f"subdomains_{domain}_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Subdomínios encontrados para {domain}\n")
                f.write(f"# Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total: {len(results)}\n\n")
                for result in results:
                    f.write(f"{result['subdomain']} | Status: {result['status_code']} | IP: {result['ip']}\n")
        
        print(f"{VERDE}[+] Resultados salvos em: {filename}{RESET}")
        return filename

    def list_wordlists(self):
        """Lista wordlists disponíveis"""
        wordlist_dir = "wordlists"
        if not os.path.exists(wordlist_dir):
            print(f"{AMARELO}[!] Diretório 'wordlists' não encontrado{RESET}")
            return []
        
        wordlists = []
        for file in os.listdir(wordlist_dir):
            if file.endswith('.txt'):
                file_path = os.path.join(wordlist_dir, file)
                size = os.path.getsize(file_path)
                wordlists.append({
                    'name': file,
                    'size': size,
                    'path': file_path
                })
        
        return wordlists

def menu_principal():
    """Menu principal"""
    scanner = SubdomainScanner()
    
    while True:
        scanner.banner()
        print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
        print(f"{VERDE}[1]{RESET} Escanear subdomínios")
        print(f"{VERDE}[2]{RESET} Listar wordlists disponíveis")
        print(f"{VERDE}[3]{RESET} Configurar parâmetros")
        print(f"{VERDE}[4]{RESET} Sobre")
        print(f"{VERDE}[5]{RESET} Sair")
        
        opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
        
        if opcao == '1':
            scan_subdomains(scanner)
        elif opcao == '2':
            list_wordlists(scanner)
        elif opcao == '3':
            configure_scanner(scanner)
        elif opcao == '4':
            sobre()
        elif opcao == '5':
            print(f"\n{VERDE}[+] Saindo...{RESET}")
            break
        else:
            print(f"{VERMELHO}[!] Opção inválida!{RESET}")
            input(f"{AMARELO}Pressione Enter para continuar...{RESET}")

def scan_subdomains(scanner: SubdomainScanner):
    """Interface para scan de subdomínios"""
    scanner.banner()
    
    domain = input(f"\n{CIANO}Digite o domínio (ex: exemplo.com.br): {RESET}").strip()
    if not domain:
        print(f"{VERMELHO}[!] Domínio não pode estar vazio{RESET}")
        input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
        return
    
    # Listar wordlists disponíveis
    wordlists = scanner.list_wordlists()
    if not wordlists:
        print(f"{VERMELHO}[!] Nenhuma wordlist encontrada{RESET}")
        input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
        return
    
    print(f"\n{CIANO}Wordlists disponíveis:{RESET}")
    for i, wl in enumerate(wordlists, 1):
        size_kb = wl['size'] / 1024
        print(f"{VERDE}[{i}]{RESET} {wl['name']} ({size_kb:.1f} KB)")
    
    try:
        choice = int(input(f"\n{CIANO}Selecione a wordlist: {RESET}")) - 1
        if choice < 0 or choice >= len(wordlists):
            print(f"{VERMELHO}[!] Seleção inválida{RESET}")
            return
        wordlist_path = wordlists[choice]['path']
    except ValueError:
        print(f"{VERMELHO}[!] Entrada inválida{RESET}")
        return
    
    # Executar scan
    results = scanner.scan_domain(domain, wordlist_path)
    
    if results:
        print(f"\n{CIANO}{NEGRITO}=== SUBDOMÍNIOS ENCONTRADOS ==={RESET}")
        for result in results:
            status_color = VERDE if result['status_code'] == 200 else AMARELO
            print(f"{VERDE}✓{RESET} {result['subdomain']}")
            print(f"   {AZUL}URL:{RESET} {result['url']}")
            print(f"   {AZUL}Status:{RESET} {status_color}{result['status_code']}{RESET}")
            print(f"   {AZUL}IP:{RESET} {result['ip']}\n")
        
        # Salvar resultados
        save = input(f"{CIANO}Salvar resultados? (s/n): {RESET}").lower()
        if save.startswith('s'):
            format_choice = input(f"{CIANO}Formato (txt/json/csv) [txt]: {RESET}").strip().lower()
            if not format_choice:
                format_choice = 'txt'
            scanner.save_results(results, domain, format_choice)
    
    input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")

def list_wordlists(scanner: SubdomainScanner):
    """Lista wordlists detalhadamente"""
    scanner.banner()
    wordlists = scanner.list_wordlists()
    
    if not wordlists:
        print(f"{VERMELHO}[!] Nenhuma wordlist encontrada{RESET}")
    else:
        print(f"\n{CIANO}{NEGRITO}=== WORDLISTS DISPONÍVEIS ==={RESET}")
        for wl in wordlists:
            # Contar linhas
            try:
                with open(wl['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    lines = sum(1 for _ in f)
            except:
                lines = 0
            
            size_mb = wl['size'] / 1024 / 1024
            print(f"{VERDE}📁 {wl['name']}{RESET}")
            print(f"   {AZUL}Tamanho:{RESET} {size_mb:.2f} MB")
            print(f"   {AZUL}Subdomínios:{RESET} {lines:,}")
            print(f"   {AZUL}Caminho:{RESET} {wl['path']}\n")
    
    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")

def configure_scanner(scanner: SubdomainScanner):
    """Configura parâmetros do scanner"""
    scanner.banner()
    print(f"\n{CIANO}{NEGRITO}=== CONFIGURAÇÕES ATUAIS ==={RESET}")
    print(f"{AZUL}Threads:{RESET} {scanner.threads}")
    print(f"{AZUL}Timeout:{RESET} {scanner.timeout}s")
    
    print(f"\n{CIANO}Novas configurações:{RESET}")
    try:
        threads = input(f"Threads [{scanner.threads}]: ").strip()
        if threads:
            scanner.threads = int(threads)
        
        timeout = input(f"Timeout (s) [{scanner.timeout}]: ").strip()
        if timeout:
            scanner.timeout = int(timeout)
        
        print(f"{VERDE}[+] Configurações atualizadas{RESET}")
    except ValueError:
        print(f"{VERMELHO}[!] Valores inválidos{RESET}")
    
    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")

def sobre():
    """Tela sobre"""
    scanner = SubdomainScanner()
    scanner.banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE O SUBDOMAIN SCANNER{RESET}

{AMARELO}Recursos:{RESET}
• Scan multi-threaded para performance
• Suporte a HTTP/HTTPS
• Vários formatos de exportação
• Barra de progresso em tempo real
• Wordlists customizáveis

{AMARELO}Wordlists:{RESET}
Coloque seus arquivos .txt na pasta 'wordlists/'

{AMARELO}Uso ético:{RESET}
Use apenas em domínios que você possui
ou tem permissão para testar.

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

if __name__ == "__main__":
    try:
        # Desabilitar warnings de SSL
        requests.packages.urllib3.disable_warnings()
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        sys.exit(1)
