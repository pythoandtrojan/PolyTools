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
import csv

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
        self.last_progress_len = 0
        
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
   Versão 2.1 - Interface Melhorada
{RESET}
{AMARELO}   Threads: {self.threads} | Timeout: {self.timeout}s
   Wordlists: wordlists/
{RESET}""")

    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Carrega a wordlist de subdomínios"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return subdomains
        except FileNotFoundError:
            print(f"{VERMELHO}[!] Wordlist não encontrada: {wordlist_path}{RESET}")
            return []
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao carregar wordlist: {e}{RESET}")
            return []

    def check_subdomain(self, domain: str, subdomain: str):
        """Verifica se um subdomínio existe"""
        full_subdomain = f"{subdomain}.{domain}"
        url_http = f"http://{full_subdomain}"
        url_https = f"https://{full_subdomain}"
        
        protocol = None
        status_code = None
        ip_address = 'N/A'
        
        # Primeiro tenta HTTPS
        try:
            response = requests.get(url_https, timeout=self.timeout, verify=False, allow_redirects=True)
            protocol = 'HTTPS'
            status_code = response.status_code
            try:
                ip_address = response.raw._connection.sock.getpeername()[0]
            except:
                ip_address = 'N/A'
                
        except requests.exceptions.SSLError:
            # SSL Error mas o subdomínio pode existir via HTTP
            protocol = 'HTTPS (SSL Error)'
            status_code = 'SSL Error'
        except:
            protocol = None
            status_code = None
        
        # Se HTTPS falhou, tenta HTTP
        if not protocol or 'Error' in str(protocol):
            try:
                response = requests.get(url_http, timeout=self.timeout, allow_redirects=True)
                protocol = 'HTTP'
                status_code = response.status_code
                try:
                    ip_address = response.raw._connection.sock.getpeername()[0]
                except:
                    ip_address = 'N/A'
            except:
                protocol = None
                status_code = None
        
        with self.lock:
            self.checked_count += 1
            
            if protocol and status_code and status_code < 400:
                result = {
                    'subdomain': full_subdomain,
                    'protocol': protocol,
                    'url': url_https if 'HTTPS' in protocol else url_http,
                    'status_code': status_code,
                    'ip': ip_address
                }
                self.found_subdomains.append(result)
                
                # Mostrar resultado formatado
                status_color = VERDE if status_code == 200 else AMARELO
                print(f"{VERDE}[+] {full_subdomain}")
                print(f"    {AZUL}URL:{RESET} {result['url']}")
                print(f"    {AZUL}Protocolo:{RESET} {protocol}")
                print(f"    {AZUL}Status:{RESET} {status_color}{status_code}{RESET}")
                print(f"    {AZUL}IP:{RESET} {ip_address}\n")
                
            else:
                # Apenas mostra falhas se não estiver mostrando progresso
                if self.checked_count % 10 == 0:  # Mostra apenas a cada 10 falhas
                    print(f"{VERMELHO}[-] {full_subdomain} - Inacessível{RESET}")

    def scan_domain(self, domain: str, wordlist_path: str) -> List[Dict]:
        """Executa o scan de subdomínios"""
        print(f"\n{CIANO}[*] Carregando wordlist...{RESET}")
        subdomains = self.load_wordlist(wordlist_path)
        
        if not subdomains:
            return []
            
        self.total_count = len(subdomains)
        self.checked_count = 0
        self.found_subdomains = []
        self.last_progress_len = 0
        
        print(f"{CIANO}[*] Iniciando scan em {domain}...{RESET}")
        print(f"{CIANO}[*] Total de subdomínios para testar: {self.total_count}{RESET}")
        print(f"{CIANO}[*] Usando {self.threads} threads{RESET}")
        print(f"{CIANO}[*] Mostrando apenas subdomínios ativos...{RESET}\n")
        
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
        
        # Barra de progresso em thread separada
        progress_thread = threading.Thread(target=self._show_progress, args=(start_time,))
        progress_thread.daemon = True
        progress_thread.start()
        
        # Aguardar todas as threads de scan
        for thread in threads:
            thread.join()
        
        # Garantir que a barra de progresso mostre 100%
        self._clear_progress_line()
        elapsed_time = time.time() - start_time
        print(f"{VERDE}[+] Scan concluído em {elapsed_time:.2f} segundos{RESET}")
        print(f"{VERDE}[+] Subdomínios encontrados: {len(self.found_subdomains)}{RESET}")
        
        return self.found_subdomains

    def _scan_chunk(self, domain: str, subdomains: List[str]):
        """Escaneia um chunk de subdomínios"""
        for subdomain in subdomains:
            if self.checked_count >= self.total_count:
                break
            self.check_subdomain(domain, subdomain)

    def _show_progress(self, start_time: float):
        """Mostra barra de progresso sem sobrepor resultados"""
        while self.checked_count < self.total_count:
            elapsed = time.time() - start_time
            progress = (self.checked_count / self.total_count) * 100
            
            # Limpa a linha anterior do progresso
            self._clear_progress_line()
            
            # Mostra nova linha de progresso
            progress_text = f"{AZUL}[*] Progresso: {progress:.1f}% ({self.checked_count}/{self.total_count}) - Tempo: {elapsed:.1f}s{RESET}"
            print(progress_text, end="", flush=True)
            self.last_progress_len = len(progress_text)
            
            time.sleep(0.5)
        
        # Limpa a última linha de progresso quando terminar
        self._clear_progress_line()

    def _clear_progress_line(self):
        """Limpa a linha de progresso anterior"""
        if self.last_progress_len > 0:
            print("\r" + " " * self.last_progress_len + "\r", end="", flush=True)
            self.last_progress_len = 0

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
                writer = csv.DictWriter(f, fieldnames=['subdomain', 'url', 'protocol', 'status_code', 'ip'])
                writer.writeheader()
                writer.writerows(results)
        else:
            filename = f"subdomains_{domain}_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Subdomínios encontrados para {domain}\n")
                f.write(f"# Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total: {len(results)}\n\n")
                for result in results:
                    f.write(f"Subdomínio: {result['subdomain']}\n")
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Protocolo: {result['protocol']}\n")
                    f.write(f"Status: {result['status_code']}\n")
                    f.write(f"IP: {result['ip']}\n")
                    f.write("-" * 50 + "\n")
        
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
    
    # Limpar www. se o usuário digitou
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
    
    # Listar wordlists disponíveis
    wordlists = scanner.list_wordlists()
    if not wordlists:
        print(f"{VERMELHO}[!] Nenhuma wordlist encontrada{RESET}")
        input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
        return
    
    print(f"\n{CIANO}Wordlists disponíveis:{RESET}")
    for i, wl in enumerate(wordlists, 1):
        size_kb = wl['size'] / 1024
        # Contar linhas reais
        try:
            with open(wl['path'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = sum(1 for line in f if line.strip() and not line.startswith('#'))
        except:
            lines = 0
        print(f"{VERDE}[{i}]{RESET} {wl['name']} ({size_kb:.1f} KB, {lines} subdomínios)")
    
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
        print(f"\n{CIANO}{NEGRITO}=== RESUMO DOS SUBDOMÍNIOS ENCONTRADOS ==={RESET}")
        for i, result in enumerate(results, 1):
            status_color = VERDE if result['status_code'] == 200 else AMARELO
            print(f"{VERDE}{i}. {result['subdomain']}{RESET}")
            print(f"   {AZUL}URL:{RESET} {result['url']}")
            print(f"   {AZUL}Protocolo:{RESET} {result['protocol']}")
            print(f"   {AZUL}Status:{RESET} {status_color}{result['status_code']}{RESET}")
            print(f"   {AZUL}IP:{RESET} {result['ip']}\n")
        
        # Salvar resultados
        save = input(f"{CIANO}Salvar resultados? (s/n): {RESET}").lower()
        if save.startswith('s'):
            format_choice = input(f"{CIANO}Formato (txt/json/csv) [txt]: {RESET}").strip().lower()
            if not format_choice:
                format_choice = 'txt'
            scanner.save_results(results, domain, format_choice)
    else:
        print(f"{AMARELO}[!] Nenhum subdomínio ativo encontrado{RESET}")
    
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
                    lines = sum(1 for line in f if line.strip() and not line.startswith('#'))
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
            scanner.threads = max(1, min(50, int(threads)))  # Limite de 1-50 threads
        
        timeout = input(f"Timeout (s) [{scanner.timeout}]: ").strip()
        if timeout:
            scanner.timeout = max(1, min(30, int(timeout)))  # Limite de 1-30 segundos
        
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
• Interface limpa e organizada

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
