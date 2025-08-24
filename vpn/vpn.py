#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import time
import signal
import threading
import subprocess
import json
from datetime import datetime

# Configurações avançadas
BACKGROUND_PID_FILE = "/data/data/com.termux/files/home/.anon_termux.pid"
IP_CHECK_INTERVAL = 30  # segundos

# Cores e estilos melhorados
class colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"

# Efeitos de animação
def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

spinner = spinning_cursor()

# Verificar root
def is_root():
    return os.geteuid() == 0

# Verificar dependências
def check_dependencies():
    required = ["tor", "proot-distro", "curl", "nmap", "openssh", "net-tools"]
    missing = []
    
    print(f"{colors.CYAN}[*] Verificando dependências...{colors.RESET}")
    for pkg in required:
        if not os.path.exists(f"/data/data/com.termux/files/usr/bin/{pkg}"):
            missing.append(pkg)
    
    if missing:
        print(f"{colors.YELLOW}[!] Pacotes faltando: {', '.join(missing)}{colors.RESET}")
        choice = input(f"{colors.CYAN}[?] Deseja instalar os pacotes faltantes? [S/n]: {colors.RESET}").lower()
        if choice in ['s', 'sim', '']:
            os.system("pkg update -y && pkg upgrade -y")
            for pkg in missing:
                os.system(f"pkg install -y {pkg}")
        else:
            print(f"{colors.RED}[!] Algumas funcionalidades podem não funcionar sem os pacotes{colors.RESET}")
            time.sleep(2)

# Banner animado
def animated_banner():
    os.system("clear")
    print(f"""{colors.RED}
   ⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣶⣿⣿⣿⣶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣿⣿⣿⣿⣿⣷⣶⣦⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⣾⣿⣿⣿⣿⣿⣿⣿⣯⣭⣙⡛⠻⠷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠾⠟⢛⣋⣭⣽⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀
⠀⠀⢀⡾⠿⠟⠛⠛⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠛⠛⠛⠛⠛⠛⠿⠿⣷⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⡟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠈⠻⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠟⠁⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⠿⠿⠛⠃⠀⠻⠷⢶⣤⣄⡀⠙⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡿⠁⢀⣤⣶⣶⠿⠟⠀⠘⠛⠛⠿⢷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢤⠀⠀⠀⠀⢀⣾⢟⣩⣶⣾⣿⣿⣿⣿⣿⣿⣷⣮⣿⣿⣦⠀⠙⠀⡆⠀⠀⠀⠀⠀⠀⢰⠀⠋⢀⣼⣿⣫⣵⣾⣿⣿⣿⣿⣿⣿⣷⣦⣌⠻⣷⡀⠀⠀⠀⠀⡄⠀
⠀⠈⢳⣤⣤⣶⣿⣇⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⡇⠀⠀⠀⠀⠀⠀⣸⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠷⣹⣿⣦⣤⣴⡞⠀⠀
⢀⢴⡫⠿⠿⠟⠻⠿⣷⣶⣦⣤⣭⣭⡍⠉⣭⣭⣽⣷⡾⠟⠋⠀⠀⢰⣿⠀⠀⠀⠀⠀⠀⣿⡆⠀⠀⠙⠿⣷⣾⣯⣭⣭⠉⢛⣯⣭⣭⣥⣶⣾⠿⠿⠿⠿⠿⣟⡦⡀
⠔⠋⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠛⠃⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⣼⣿⠀⠀⠀⠀⠀⠀⣿⣧⠀⠀⠀⠀⠀⠈⠉⠉⠉⠀⠘⠛⠛⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠙⠢
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠀⠀⠀⠀⠀⠀⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⡏⠀⠀⠀⠀⠀⠀⢻⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⢿⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⠿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠁⢸⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⡆⠈⠻⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣾⡆⢠⡟⠁⠀⠀⢸⣿⠃⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠈⢻⡄⠰⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀
⠀⢹⣷⣤⣀⡀⠀⠀⢀⣀⣀⣤⣴⣶⡿⠿⠛⠉⠀⢸⡀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠘⣿⡇⠀⠀⠀⢀⡇⠀⠈⠛⠿⢿⣶⣤⣄⣀⣀⡀⢀⣀⣀⣠⣴⣾⠃⠀
⠀⠀⢿⣿⣿⠛⣿⣿⣿⡛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠁⠀⢰⣦⣌⠻⣷⣤⣀⣀⣀⣠⣤⣾⠟⣠⣴⡆⠀⠈⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⢛⣿⣿⣿⠛⣿⣿⡟⠀⠀
⠀⠀⠈⢿⣿⣧⠈⢿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⣤⣤⣍⣉⡛⢛⣋⣩⣥⣤⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⡿⠁⣼⣿⣿⠁⠀⠀
⠀⠀⠀⠈⣿⣿⣆⠀⢻⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⡟⠁⣸⣿⣿⠃⠀⠀⠀
⠀⠀⠀⠀⠈⢿⣿⣦⠀⠹⣿⣿⣿⣦⣀⣀⣀⣀⣀⣠⣤⣴⣾⣿⣿⣿⣿⣿⠟⠁⠈⠻⣿⣿⣿⣿⣿⣷⣦⣤⣤⣄⣀⣀⣀⣀⣴⣿⣿⣿⠏⠀⣴⣿⡿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢿⣿⣷⡀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⢀⣼⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣦⡀⠉⠛⠛⠛⠛⠛⠛⠛⠛⠛⣛⣿⣿⣟⣀⣀⣀⣀⣀⣀⣀⣈⣻⣿⣿⣛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠉⢀⡴⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣧⠙⠢⣄⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠙⠛⠛⠛⠛⠛⠛⠋⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⣠⠖⠋⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⡀⠈⠉⠒⠦⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠖⠚⠉⠀⢀⣼⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⣤⣤⣤⣤⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    {colors.RESET}""")

# Funções do TOR
def start_tor_service():
    print(f"\n{colors.YELLOW}[*] Iniciando serviço TOR...{colors.RESET}")
    os.system("pkill tor 2>/dev/null")  # Garantir que não há instâncias anteriores
    os.system("tor > /dev/null 2>&1 &")
    time.sleep(5)
    
    # Verificar se o TOR está rodando
    tor_check = os.system("pgrep tor > /dev/null 2>&1")
    if tor_check == 0:
        print(f"{colors.GREEN}[+] TOR iniciado com sucesso!{colors.RESET}")
        print(f"{colors.CYAN}[*] Configurando proxy para porta 9050{colors.RESET}")
        os.environ['http_proxy'] = 'socks5://127.0.0.1:9050'
        os.environ['https_proxy'] = 'socks5://127.0.0.1:9050'
        print(f"{colors.GREEN}[+] Proxy configurado{colors.RESET}")
    else:
        print(f"{colors.RED}[!] Falha ao iniciar o TOR{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def stop_tor_service():
    print(f"\n{colors.YELLOW}[*] Parando serviço TOR...{colors.RESET}")
    os.system("pkill tor")
    
    # Verificar se o TOR foi parado
    tor_check = os.system("pgrep tor > /dev/null 2>&1")
    if tor_check != 0:
        print(f"{colors.GREEN}[+] TOR parado com sucesso!{colors.RESET}")
        print(f"{colors.CYAN}[*] Removendo configurações de proxy{colors.RESET}")
        if 'http_proxy' in os.environ:
            del os.environ['http_proxy']
        if 'https_proxy' in os.environ:
            del os.environ['https_proxy']
        print(f"{colors.GREEN}[+] Configurações removidas{colors.RESET}")
    else:
        print(f"{colors.RED}[!] Falha ao parar o TOR{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def edit_tor_config():
    print(f"\n{colors.YELLOW}[*] Editando configuração do TOR...{colors.RESET}")
    torrc_path = "/data/data/com.termux/files/usr/etc/tor/torrc"
    if os.path.exists(torrc_path):
        os.system(f"nano {torrc_path}")
        print(f"{colors.GREEN}[+] Configuração salva. Reinicie o TOR para aplicar.{colors.RESET}")
    else:
        print(f"{colors.RED}[!] Arquivo de configuração do TOR não encontrado!{colors.RESET}")
        print(f"{colors.YELLOW}[*] Criando arquivo de configuração básico...{colors.RESET}")
        os.system("tor --list-torrc-options > /dev/null 2>&1")  # Isso cria o arquivo padrão
        time.sleep(2)
        if os.path.exists(torrc_path):
            os.system(f"nano {torrc_path}")
        else:
            print(f"{colors.RED}[!] Falha ao criar arquivo de configuração{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def test_tor_connection():
    print(f"\n{colors.YELLOW}[*] Testando conexão TOR...{colors.RESET}")
    print(f"{colors.CYAN}[*] Isso pode levar alguns segundos{colors.RESET}")
    
    try:
        # Verificar se o TOR está rodando
        tor_check = os.system("pgrep tor > /dev/null 2>&1")
        if tor_check != 0:
            print(f"{colors.RED}[!] Serviço TOR não está rodando{colors.RESET}")
            input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")
            return
        
        # Testar conexão TOR
        result = subprocess.getoutput("curl --socks5 127.0.0.1:9050 -s https://check.torproject.org/api/ip")
        if "Congratulations" in result or "true" in result:
            print(f"{colors.GREEN}[+] Você está conectado através do TOR!{colors.RESET}")
        else:
            print(f"{colors.RED}[!] Conexão TOR não está funcionando corretamente{colors.RESET}")
            print(f"{colors.YELLOW}[*] Verifique se o serviço TOR está rodando{colors.RESET}")
    except Exception as e:
        print(f"{colors.RED}[!] Erro ao testar TOR: {e}{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de rede
def mac_spoofing():
    animated_banner()
    print(f"\n{colors.WHITE}Alteração de MAC Address:{colors.RESET}")
    
    if not is_root():
        print(f"{colors.YELLOW}[!] Esta função requer root{colors.RESET}")
        print(f"{colors.YELLOW}[!] Execute 'pkg install root-repo' e 'pkg install tsu'{colors.RESET}")
        print(f"{colors.YELLOW}[!] Depois execute o script com 'sudo'{colors.RESET}")
        input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")
        return
    
    if not os.path.exists("/data/data/com.termux/files/usr/bin/macchanger"):
        print(f"{colors.RED}[!] macchanger não está instalado{colors.RESET}")
        choice = input(f"{colors.CYAN}[?] Deseja instalar o macchanger? [S/n]: {colors.RESET}").lower()
        if choice in ['s', 'sim', '']:
            os.system("pkg install -y root-repo && pkg install -y macchanger")
        else:
            return
    
    print(f"\n{colors.GREEN}[1]{colors.RESET} Alterar MAC Address aleatório")
    print(f"{colors.GREEN}[2]{colors.RESET} Definir MAC Address específico")
    print(f"{colors.GREEN}[3]{colors.RESET} Resetar MAC Address original")
    print(f"{colors.GREEN}[4]{colors.RESET} Voltar")
    
    choice = input(f"\n{colors.CYAN}[?] Selecione uma opção (1-4): {colors.RESET}")
    
    if choice == "1":
        print(f"\n{colors.YELLOW}[*] Listando interfaces de rede...{colors.RESET}")
        os.system("ip link show")
        iface = input(f"\n{colors.CYAN}[?] Digite a interface (ex: wlan0): {colors.RESET}")
        os.system(f"macchanger -r {iface}")
    elif choice == "2":
        print(f"\n{colors.YELLOW}[*] Listando interfaces de rede...{colors.RESET}")
        os.system("ip link show")
        iface = input(f"\n{colors.CYAN}[?] Digite a interface (ex: wlan0): {colors.RESET}")
        new_mac = input(f"{colors.CYAN}[?] Digite o novo MAC (ex: 00:11:22:33:44:55): {colors.RESET}")
        os.system(f"macchanger -m {new_mac} {iface}")
    elif choice == "3":
        print(f"\n{colors.YELLOW}[*] Listando interfaces de rede...{colors.RESET}")
        os.system("ip link show")
        iface = input(f"\n{colors.CYAN}[?] Digite a interface (ex: wlan0): {colors.RESET}")
        os.system(f"macchanger -p {iface}")
    elif choice == "4":
        return
    else:
        print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
        time.sleep(1)
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def vpn_management():
    print(f"\n{colors.YELLOW}[*] Gerenciamento de VPN{colors.RESET}")
    print(f"{colors.GREEN}[1]{colors.RESET} Instalar OpenVPN")
    print(f"{colors.GREEN}[2]{colors.RESET} Instalar WireGuard")
    print(f"{colors.GREEN}[3]{colors.RESET} Conectar a VPN (requer arquivo de configuração)")
    print(f"{colors.GREEN}[4]{colors.RESET} Voltar")
    
    choice = input(f"\n{colors.CYAN}[?] Selecione uma opção (1-4): {colors.RESET}")
    
    if choice == "1":
        print(f"\n{colors.YELLOW}[*] Instalando OpenVPN...{colors.RESET}")
        os.system("pkg install -y openvpn")
        print(f"{colors.GREEN}[+] OpenVPN instalado{colors.RESET}")
    elif choice == "2":
        print(f"\n{colors.YELLOW}[*] Instalando WireGuard...{colors.RESET}")
        os.system("pkg install -y wireguard-tools")
        print(f"{colors.GREEN}[+] WireGuard instalado{colors.RESET}")
    elif choice == "3":
        print(f"\n{colors.YELLOW}[*] Conectando a VPN...{colors.RESET}")
        config_file = input(f"{colors.CYAN}[?] Caminho para o arquivo de configuração: {colors.RESET}")
        if os.path.exists(config_file):
            if config_file.endswith('.ovpn'):
                os.system(f"openvpn {config_file} &")
            elif config_file.endswith('.conf'):
                os.system(f"wg-quick up {config_file}")
            print(f"{colors.GREEN}[+] VPN conectada{colors.RESET}")
        else:
            print(f"{colors.RED}[!] Arquivo não encontrado{colors.RESET}")
    elif choice == "4":
        return
    else:
        print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
        time.sleep(1)
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def dns_protection():
    print(f"\n{colors.YELLOW}[*] Configurando proteção contra vazamento de DNS...{colors.RESET}")
    
    if not os.path.exists("/data/data/com.termux/files/usr/bin/dnscrypt-proxy"):
        print(f"{colors.RED}[!] dnscrypt-proxy não está instalado{colors.RESET}")
        choice = input(f"{colors.CYAN}[?] Deseja instalar o dnscrypt-proxy? [S/n]: {colors.RESET}").lower()
        if choice in ['s', 'sim', '']:
            os.system("pkg install -y dnscrypt-proxy")
        else:
            return
    
    os.system("pkill dnscrypt-proxy 2>/dev/null")
    os.system("dnscrypt-proxy -config /data/data/com.termux/files/usr/etc/dnscrypt-proxy.toml &")
    
    # Configurar DNS para localhost
    os.system("setprop net.dns1 127.0.0.1")
    os.system("setprop net.dns2 ::1")
    
    print(f"{colors.GREEN}[+] DNS criptografado configurado{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de comunicação segura
def secure_communication():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}FERRAMENTAS DE COMUNICAÇÃO SEGURA:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Conexão SSH Segura                        {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Configuração de Email Criptografado       {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Aplicativos de Mensagens Seguras          {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Voltar ao Menu Principal                 {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Selecione uma opção (1-4): {colors.RESET}")
        
        if choice == "1":
            secure_ssh()
        elif choice == "2":
            encrypted_email()
        elif choice == "3":
            secure_messaging()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
            time.sleep(1)

def secure_ssh():
    print(f"\n{colors.YELLOW}[*] Configurando SSH seguro...{colors.RESET}")
    
    if not os.path.exists("/data/data/com.termux/files/usr/bin/ssh"):
        os.system("pkg install -y openssh")
    
    if not os.path.exists("/data/data/com.termux/files/home/.ssh/id_rsa"):
        print(f"{colors.YELLOW}[*] Gerando chave SSH...{colors.RESET}")
        os.system("ssh-keygen -t rsa -b 4096 -f /data/data/com.termux/files/home/.ssh/id_rsa -N ''")
    
    print(f"{colors.GREEN}[+] Chave SSH gerada{colors.RESET}")
    print(f"{colors.YELLOW}[*] Chave pública:{colors.RESET}")
    os.system("cat /data/data/com.termux/files/home/.ssh/id_rsa.pub")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def encrypted_email():
    print(f"\n{colors.YELLOW}[*] Configuração de email criptografado...{colors.RESET}")
    print(f"{colors.GREEN}[1]{colors.RESET} Instalar e configurar Thunderbird com Enigmail")
    print(f"{colors.GREEN}[2]{colors.RESET} Configurar GPG para email")
    print(f"{colors.GREEN}[3]{colors.RESET} Voltar")
    
    choice = input(f"\n{colors.CYAN}[?] Selecione uma opção (1-3): {colors.RESET}")
    
    if choice == "1":
        print(f"\n{colors.YELLOW}[!] Thunderbird não está disponível no Termux{colors.RESET}")
        print(f"{colors.YELLOW}[*] Considere usar um cliente email web com criptografia{colors.RESET}")
    elif choice == "2":
        print(f"\n{colors.YELLOW}[*] Configurando GPG...{colors.RESET}")
        if not os.path.exists("/data/data/com.termux/files/usr/bin/gpg"):
            os.system("pkg install -y gnupg")
        os.system("gpg --gen-key")
        print(f"{colors.GREEN}[+] Chave GPG gerada{colors.RESET}")
    elif choice == "3":
        return
    else:
        print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
        time.sleep(1)
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def secure_messaging():
    print(f"\n{colors.YELLOW}[*] Aplicativos de mensagens seguras...{colors.RESET}")
    print(f"{colors.GREEN}[1]{colors.RESET} Instalar Signal (requer Google Play)")
    print(f"{colors.GREEN}[2]{colors.RESET} Instalar Telegram (requer Google Play)")
    print(f"{colors.GREEN}[3]{colors.RESET} Instalar Element (Matrix client)")
    print(f"{colors.GREEN}[4]{colors.RESET} Voltar")
    
    choice = input(f"\n{colors.CYAN}[?] Selecione uma opção (1-4): {colors.RESET}")
    
    if choice == "1":
        print(f"\n{colors.YELLOW}[*] Abrindo Signal na Play Store...{colors.RESET}")
        os.system("am start -a android.intent.action.VIEW -d 'market://details?id=org.thoughtcrime.securesms'")
    elif choice == "2":
        print(f"\n{colors.YELLOW}[*] Abrindo Telegram na Play Store...{colors.RESET}")
        os.system("am start -a android.intent.action.VIEW -d 'market://details?id=org.telegram.messenger'")
    elif choice == "3":
        print(f"\n{colors.YELLOW}[*] Instalando Element...{colors.RESET}")
        os.system("pkg install -y x11-repo")
        os.system("pkg install -y element-desktop")
        print(f"{colors.YELLOW}[!] Element Desktop instalado. Execute com 'element-desktop'{colors.RESET}")
    elif choice == "4":
        return
    else:
        print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
        time.sleep(1)
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de limpeza
def privacy_cleaner():
    print(f"\n{colors.YELLOW}[*] Limpando arquivos relacionados à privacidade...{colors.RESET}")
    
    # Limpar histórico do bash
    if os.path.exists("/data/data/com.termux/files/home/.bash_history"):
        os.remove("/data/data/com.termux/files/home/.bash_history")
    
    # Limpar cache
    os.system("rm -rf /data/data/com.termux/files/home/.cache/* 2>/dev/null")
    
    # Limpar thumbnails
    os.system("rm -rf /data/data/com.termux/files/home/.thumbnails/* 2>/dev/null")
    
    # Limpar logs do TOR
    os.system("rm -rf /data/data/com.termux/files/usr/var/log/tor/* 2>/dev/null")
    
    # Limpar histórico de comandos atual
    os.system("history -c")
    
    print(f"{colors.GREEN}[+] Limpeza de privacidade concluída{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de modo background
def background_mode_control():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}CONTROLE DE MODO EM SEGUNDO PLANO:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Iniciar em Modo Segundo Plano              {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Parar Modo Segundo Plano                   {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Verificar Status Segundo Plano             {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Voltar ao Menu Principal                 {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Selecione uma opção (1-4): {colors.RESET}")
        
        if choice == "1":
            start_background_mode()
        elif choice == "2":
            stop_background_mode()
        elif choice == "3":
            check_background_status()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
            time.sleep(1)

def start_background_mode():
    print(f"\n{colors.YELLOW}[*] Iniciando em modo segundo plano...{colors.RESET}")
    
    # Verificar se já está rodando
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        if os.path.exists(f"/proc/{pid}"):
            print(f"{colors.RED}[!] Já existe um processo em segundo plano rodando com PID: {pid}{colors.RESET}")
            input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")
            return
    
    # Iniciar em segundo plano
    pid = os.fork()
    if pid > 0:
        with open(BACKGROUND_PID_FILE, "w") as f:
            f.write(str(pid))
        print(f"{colors.GREEN}[+] Executando em segundo plano com PID: {pid}{colors.RESET}")
        print(f"{colors.YELLOW}[*] Use a opção 'Parar Modo Segundo Plano' para finalizar{colors.RESET}")
    else:
        # Este é o processo em segundo plano
        try:
            while True:
                # Manter o TOR rodando
                tor_check = os.system("pgrep tor > /dev/null 2>&1")
                if tor_check != 0:
                    os.system("tor > /dev/null 2>&1 &")
                
                time.sleep(60)
        except:
            pass
        finally:
            sys.exit(0)
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def stop_background_mode():
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        
        # Verificar se o processo ainda existe
        if os.path.exists(f"/proc/{pid}"):
            os.system(f"kill -9 {pid} 2>/dev/null")
            print(f"{colors.GREEN}[+] Modo segundo plano parado{colors.RESET}")
        else:
            print(f"{colors.YELLOW}[!] Processo não encontrado, limpando arquivo PID{colors.RESET}")
        
        os.remove(BACKGROUND_PID_FILE)
    else:
        print(f"{colors.RED}[!] Nenhum processo em segundo plano rodando{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def check_background_status():
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        
        if os.path.exists(f"/proc/{pid}"):
            print(f"\n{colors.GREEN}[+] Processo em segundo plano rodando com PID: {pid}{colors.RESET}")
        else:
            print(f"\n{colors.RED}[!] Processo não encontrado (PID: {pid}){colors.RESET}")
            os.remove(BACKGROUND_PID_FILE)
    else:
        print(f"\n{colors.RED}[!] Nenhum processo em segundo plano rodando{colors.RESET}")
    
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Monitor de IP em tempo real
class IPMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True
        self.current_ip = "Verificando..."
        self.current_country = "Verificando..."
        self.tor_enabled = False
        
    def run(self):
        while self.running:
            try:
                # Verifica se TOR está ativo
                self.tor_enabled = os.system("pgrep tor > /dev/null 2>&1") == 0
                
                if self.tor_enabled:
                    ip_info = subprocess.getoutput("curl --socks5 127.0.0.1:9050 -s https://ipinfo.io/json")
                else:
                    ip_info = subprocess.getoutput("curl -s https://ipinfo.io/json")
                
                if '"ip":' in ip_info:
                    try:
                        data = json.loads(ip_info)
                        self.current_ip = data.get('ip', 'Unable to determine')
                        self.current_country = data.get('country', 'Unknown')
                    except:
                        self.current_ip = "Erro ao analisar"
                        self.current_country = "Erro"
                else:
                    self.current_ip = "Não foi possível determinar"
                    self.current_country = "Desconhecido"
                
                time.sleep(IP_CHECK_INTERVAL)
            except Exception as e:
                self.current_ip = f"Erro: {str(e)}"
                self.current_country = "Erro"
                time.sleep(10)
    
    def stop(self):
        self.running = False

# Monitor de rede em tempo real
def network_monitor(ip_monitor):
    animated_banner()
    print(f"\n{colors.BOLD}{colors.WHITE}MONITOR DE REDE EM TEMPO REAL:{colors.RESET}")
    print(f"{colors.YELLOW}>>> Pressione CTRL+C para voltar ao menu <<<{colors.RESET}")
    
    try:
        while True:
            print(f"\n{colors.BLUE}╔══════════════════════════════════════════════════════════════╗")
            print(f"║ {colors.BOLD}STATUS DA REDE:{colors.RESET}{colors.BLUE} ", end="")
            status_color = colors.GREEN if ip_monitor.tor_enabled else colors.RED
            print(f"IP: {status_color}{ip_monitor.current_ip}{colors.BLUE}", end="")
            print(f" | País: {colors.CYAN}{ip_monitor.current_country}{colors.BLUE}", end="")
            print(f" | TOR: {'LIGADO' if ip_monitor.tor_enabled else 'DESLIGADO'}{' '*(18-len(ip_monitor.current_ip))}║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            
            # Mostrar conexões ativas
            print(f"║ {colors.BOLD}CONEXÕES ATIVAS:{colors.RESET}{colors.BLUE}{' '*36}║")
            try:
                connections = subprocess.getoutput("netstat -tun 2>/dev/null | grep -v '127.0.0.1' | head -n 5")
                if not connections:
                    connections = "Nenhuma conexão detectada"
            except:
                connections = "Erro ao obter conexões"
            
            for line in connections.split('\n'):
                if line:
                    print(f"║ {line[:56].ljust(56)}{colors.BLUE}║")
            
            print(f"╚══════════════════════════════════════════════════════════════╝{colors.RESET}")
            
            # Spinner de animação
            print(f"\n{colors.MAGENTA}Atualizando em {IP_CHECK_INTERVAL} segundos... {next(spinner)}{colors.RESET}", end="\r")
            time.sleep(1)
            
            # Limpar linhas para atualização
            print("\033[F" * 10, end="")
    except KeyboardInterrupt:
        return

# Função para limpeza e saída
def cleanup_and_exit(signal=None, frame=None):
    print(f"\n{colors.YELLOW}[*] Limpando e saindo...{colors.RESET}")
    
    # Verificar e matar processos em segundo plano
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        os.system(f"kill -9 {pid} 2>/dev/null")
        os.remove(BACKGROUND_PID_FILE)
    
    # Parar TOR
    os.system("pkill tor 2>/dev/null")
    
    # Limpar configurações temporárias
    if 'http_proxy' in os.environ:
        del os.environ['http_proxy']
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']
    
    print(f"{colors.GREEN}[+] Limpeza concluída. Até logo!{colors.RESET}")
    sys.exit(0)

# Menu principal
def show_menu(ip_monitor):
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}MENU PRINCIPAL ANON_TERMUX:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Gerenciamento TOR                         {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Ferramentas de Rede                       {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Comunicação Segura                        {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Monitor de Rede em Tempo Real             {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}5{colors.RESET}{colors.GREEN} │ Limpeza de Privacidade                    {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}6{colors.RESET}{colors.GREEN} │ Controle de Modo Segundo Plano            {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}0{colors.RESET}{colors.GREEN} │ Sair                                      {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        print(f"\n{colors.CYAN}Status: IP: {ip_monitor.current_ip} | País: {ip_monitor.current_country} | TOR: {'✅' if ip_monitor.tor_enabled else '❌'}{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Selecione uma opção (0-6): {colors.RESET}")
        
        if choice == "1":
            tor_management()
        elif choice == "2":
            network_tools()
        elif choice == "3":
            secure_communication()
        elif choice == "4":
            network_monitor(ip_monitor)
        elif choice == "5":
            privacy_cleaner()
        elif choice == "6":
            background_mode_control()
        elif choice == "0":
            cleanup_and_exit()
        else:
            print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
            time.sleep(1)

# Submenu TOR
def tor_management():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}GERENCIAMENTO TOR:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Iniciar Serviço TOR                       {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Parar Serviço TOR                         {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Editar Configuração TOR                   {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Testar Conexão TOR                        {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}5{colors.RESET}{colors.GREEN} │ Voltar ao Menu Principal                 {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Selecione uma opção (1-5): {colors.RESET}")
        
        if choice == "1":
            start_tor_service()
        elif choice == "2":
            stop_tor_service()
        elif choice == "3":
            edit_tor_config()
        elif choice == "4":
            test_tor_connection()
        elif choice == "5":
            return
        else:
            print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
            time.sleep(1)

# Submenu Ferramentas de Rede
def network_tools():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}FERRAMENTAS DE REDE:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Spoofing de MAC Address                   {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Gerenciamento de VPN                      {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Proteção contra Vazamento de DNS          {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Voltar ao Menu Principal                 {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Selecione uma opção (1-4): {colors.RESET}")
        
        if choice == "1":
            mac_spoofing()
        elif choice == "2":
            vpn_management()
        elif choice == "3":
            dns_protection()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Opção inválida!{colors.RESET}")
            time.sleep(1)

# Função principal
def main():
    # Verificar Termux
    if not os.path.exists("/data/data/com.termux/files/usr/bin"):
        print(f"{colors.RED}[!] Este script deve ser executado no Termux{colors.RESET}")
        sys.exit(1)
    
    # Verificar dependências
    check_dependencies()
    
    # Iniciar monitor de IP
    ip_monitor = IPMonitor()
    ip_monitor.start()
    
    # Configurar handler para CTRL+C
    signal.signal(signal.SIGINT, cleanup_and_exit)
    
    # Mostrar menu principal
    show_menu(ip_monitor)

if __name__ == "__main__":
    main()
