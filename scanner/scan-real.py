#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import subprocess
import threading
import time
from datetime import datetime
from colorama import init, Fore, Back, Style

# Inicializar Colorama
init(autoreset=True)

# Banner do scanner
def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + r"""
     _____                           _             
    /  ___|                         | |            
    \ `--.  ___  ___ _ __ __ _ _ __ | |__          
     `--. \/ _ \/ __| '__/ _` | '_ \| '_ \         
    /\__/ /  __/ (__| | | (_| | |_) | | | |        
    \____/ \___|\___|_|  \__,_| .__/|_| |_|        
                              | |                  
                              |_|                  
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "         Scanner de Rede e Segurança")
    print(Fore.YELLOW + "         Versão 1.0 - Desenvolvido em Python\n")

# Função para verificar se um host está online
def ping_host(host):
    try:
        # Parâmetros para o comando ping (Windows e Linux)
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', host]
        
        # Executar o comando ping
        response = subprocess.run(command, stdout=subprocess.DEVNULL, 
                                stderr=subprocess.DEVNULL, timeout=2)
        
        return response.returncode == 0
    except:
        return False

# Função para escanear portas
def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return True
    except:
        pass
    return False

# Scanner de portas completo
def port_scanner():
    host = input(Fore.GREEN + "\n[+] Digite o host ou IP para escanear: " + Style.RESET_ALL)
    
    if not ping_host(host):
        print(Fore.RED + f"\n[!] Host {host} parece estar offline ou não responde a ping.")
        return
    
    print(Fore.GREEN + f"\n[+] Host {host} está online. Iniciando varredura de portas...")
    
    # Portas comuns para verificar
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    
    print(Fore.CYAN + f"\n[+] Escaneando {len(common_ports)} portas em {host}...")
    
    # Escanear portas com threads para maior velocidade
    threads = []
    results = {}
    
    def check_port(port):
        if scan_port(host, port):
            results[port] = True
    
    for port in common_ports:
        thread = threading.Thread(target=check_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    # Aguardar todas as threads terminarem
    for thread in threads:
        thread.join(timeout=0.5)
    
    # Coletar resultados
    open_ports = [port for port, is_open in results.items() if is_open]
    
    if open_ports:
        print(Fore.GREEN + f"\n[+] Portas abertas encontradas em {host}:")
        for port in sorted(open_ports):
            # Tentar obter o nome do serviço
            try:
                service = socket.getservbyport(port)
            except:
                service = "serviço desconhecido"
            print(Fore.YELLOW + f"    Porta {port}/TCP - {service}")
    else:
        print(Fore.RED + f"\n[-] Nenhuma porta aberta encontrada em {host}.")

# Scanner de rede local
def network_scanner():
    network = input(Fore.GREEN + "\n[+] Digite a rede (ex: 192.168.1.0/24): " + Style.RESET_ALL)
    
    # Extrair o prefixo da rede
    base_ip = network.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip = '.'.join(ip_parts[:3])
    
    print(Fore.CYAN + f"\n[+] Escaneando hosts ativos em {base_ip}.0/24...")
    print(Fore.CYAN + "[+] Isso pode levar alguns minutos...\n")
    
    active_hosts = []
    
    # Verificar hosts de 1 a 254
    for i in range(1, 255):
        host = f"{base_ip}.{i}"
        if ping_host(host):
            active_hosts.append(host)
            print(Fore.GREEN + f"[+] Host ativo encontrado: {host}")
    
    if active_hosts:
        print(Fore.GREEN + f"\n[+] Total de hosts ativos encontrados: {len(active_hosts)}")
    else:
        print(Fore.RED + "\n[-] Nenhum host ativo encontrado na rede.")

# Função para obter informações de um domínio
def domain_info():
    domain = input(Fore.GREEN + "\n[+] Digite o domínio: " + Style.RESET_ALL)
    
    try:
        print(Fore.CYAN + f"\n[+] Obtendo informações para {domain}...")
        
        # Obter IP
        ip = socket.gethostbyname(domain)
        print(Fore.YELLOW + f"[+] IP: {ip}")
        
        # Tentar obter informações de whois
        try:
            import whois
            domain_info = whois.whois(domain)
            print(Fore.YELLOW + f"[+] Registrado para: {domain_info.name}")
            print(Fore.YELLOW + f"[+] Data de criação: {domain_info.creation_date}")
            print(Fore.YELLOW + f"[+] Data de expiração: {domain_info.expiration_date}")
        except:
            print(Fore.RED + "[-] Não foi possível obter informações WHOIS completas.")
        
    except socket.gaierror:
        print(Fore.RED + f"[-] Não foi possível resolver o domínio {domain}")

# Menu principal
def main_menu():
    while True:
        display_banner()
        print(Fore.MAGENTA + "=" * 55)
        print(Fore.CYAN + "          MENU PRINCIPAL - SCANNER")
        print(Fore.MAGENTA + "=" * 55)
        print(Fore.GREEN + "[1]" + Fore.WHITE + " Scanner de Portas")
        print(Fore.GREEN + "[2]" + Fore.WHITE + " Scanner de Rede Local")
        print(Fore.GREEN + "[3]" + Fore.WHITE + " Informações de Domínio")
        print(Fore.GREEN + "[4]" + Fore.WHITE + " Teste de Conexão (Ping)")
        print(Fore.GREEN + "[5]" + Fore.WHITE + " Sair")
        print(Fore.MAGENTA + "=" * 55)
        
        choice = input(Fore.YELLOW + "\n[+] Selecione uma opção (1-5): " + Style.RESET_ALL)
        
        if choice == '1':
            port_scanner()
        elif choice == '2':
            network_scanner()
        elif choice == '3':
            domain_info()
        elif choice == '4':
            host = input(Fore.GREEN + "\n[+] Digite o host ou IP para testar: " + Style.RESET_ALL)
            if ping_host(host):
                print(Fore.GREEN + f"[+] {host} está online e respondendo.")
            else:
                print(Fore.RED + f"[-] {host} está offline ou não responde.")
        elif choice == '5':
            print(Fore.CYAN + "\n[+] Obrigado por usar o scanner. Até logo!")
            break
        else:
            print(Fore.RED + "\n[-] Opção inválida. Tente novamente.")
        
        input(Fore.YELLOW + "\n[+] Pressione Enter para continuar..." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[-] Scanner interrompido pelo usuário.")
        exit(0)
