#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import time
import signal
import threading
import subprocess
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
    os.system("tor &")
    time.sleep(5)
    print(f"{colors.GREEN}[+] TOR iniciado com sucesso!{colors.RESET}")
    print(f"{colors.CYAN}[*] Configurando proxy para porta 9050{colors.RESET}")
    os.system("export http_proxy='socks5://127.0.0.1:9050'")
    os.system("export https_proxy='socks5://127.0.0.1:9050'")
    print(f"{colors.GREEN}[+] Proxy configurado{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def stop_tor_service():
    print(f"\n{colors.YELLOW}[*] Parando serviço TOR...{colors.RESET}")
    os.system("pkill tor")
    print(f"{colors.GREEN}[+] TOR parado com sucesso!{colors.RESET}")
    print(f"{colors.CYAN}[*] Removendo configurações de proxy{colors.RESET}")
    os.system("unset http_proxy")
    os.system("unset https_proxy")
    print(f"{colors.GREEN}[+] Configurações removidas{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def edit_tor_config():
    print(f"\n{colors.YELLOW}[*] Editando configuração do TOR...{colors.RESET}")
    torrc_path = "/data/data/com.termux/files/usr/etc/tor/torrc"
    if os.path.exists(torrc_path):
        os.system(f"nano {torrc_path}")
        print(f"{colors.GREEN}[+] Configuração salva. Reinicie o TOR para aplicar.{colors.RESET}")
    else:
        print(f"{colors.RED}[!] Arquivo de configuração do TOR não encontrado!{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

def test_tor_connection():
    print(f"\n{colors.YELLOW}[*] Testando conexão TOR...{colors.RESET}")
    print(f"{colors.CYAN}[*] Isso pode levar alguns segundos{colors.RESET}")
    try:
        result = subprocess.getoutput("curl --socks5 127.0.0.1:9050 -s https://check.torproject.org/api/ip")
        if "Congratulations" in result:
            print(f"{colors.GREEN}[+] Você está conectado através do TOR!{colors.RESET}")
        else:
            print(f"{colors.RED}[!] Conexão TOR não está funcionando corretamente{colors.RESET}")
    except Exception as e:
        print(f"{colors.RED}[!] Erro ao testar TOR: {e}{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de rede
def mac_spoofing():
    banner()
    print(f"\n{colors.WHITE}Alteração de MAC Address:{colors.RESET}")
    print(f"{colors.YELLOW}[!] Esta função requer root{colors.RESET}")
    
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
    print(f"\n{colors.YELLOW}[*] VPN management not fully implemented yet{colors.RESET}")
    print(f"{colors.CYAN}[*] You can manually configure OpenVPN or WireGuard{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

def dns_protection():
    print(f"\n{colors.YELLOW}[*] Configurando proteção contra vazamento de DNS...{colors.RESET}")
    os.system("pkg install -y dnscrypt-proxy")
    os.system("dnscrypt-proxy -config /data/data/com.termux/files/usr/etc/dnscrypt-proxy.toml &")
    print(f"{colors.GREEN}[+] DNS criptografado configurado{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Pressione Enter para continuar...{colors.RESET}")

# Funções de comunicação segura
def secure_communication():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}SECURE COMMUNICATION TOOLS:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Secure SSH Connection                     {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Encrypted Email Setup                    {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Secure Messaging Apps                    {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Back to Main Menu                       {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Select an option (1-4): {colors.RESET}")
        
        if choice == "1":
            secure_ssh()
        elif choice == "2":
            encrypted_email()
        elif choice == "3":
            secure_messaging()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Invalid option!{colors.RESET}")
            time.sleep(1)

def secure_ssh():
    print(f"\n{colors.YELLOW}[*] Configuring secure SSH...{colors.RESET}")
    os.system("pkg install -y openssh")
    if not os.path.exists("/data/data/com.termux/files/home/.ssh/id_rsa"):
        os.system("ssh-keygen -t rsa -b 4096")
    print(f"{colors.GREEN}[+] SSH key generated{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

def encrypted_email():
    print(f"\n{colors.YELLOW}[*] Encrypted email setup not implemented yet{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

def secure_messaging():
    print(f"\n{colors.YELLOW}[*] Secure messaging apps not implemented yet{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

# Funções de limpeza
def privacy_cleaner():
    print(f"\n{colors.YELLOW}[*] Cleaning privacy-related files...{colors.RESET}")
    os.system("rm -rf ~/.bash_history")
    os.system("history -c")
    os.system("rm -rf ~/.cache/*")
    os.system("rm -rf ~/.thumbnails/*")
    print(f"{colors.GREEN}[+] Privacy cleanup completed{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

# Funções de modo background
def background_mode_control():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}BACKGROUND MODE CONTROL:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Start in Background Mode                  {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Stop Background Mode                     {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Check Background Status                  {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Back to Main Menu                       {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Select an option (1-4): {colors.RESET}")
        
        if choice == "1":
            start_background_mode()
        elif choice == "2":
            stop_background_mode()
        elif choice == "3":
            check_background_status()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Invalid option!{colors.RESET}")
            time.sleep(1)

def start_background_mode():
    print(f"\n{colors.YELLOW}[*] Starting in background mode...{colors.RESET}")
    pid = os.fork()
    if pid > 0:
        with open(BACKGROUND_PID_FILE, "w") as f:
            f.write(str(pid))
        print(f"{colors.GREEN}[+] Running in background with PID: {pid}{colors.RESET}")
    else:
        # This is the background process
        while True:
            time.sleep(60)
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

def stop_background_mode():
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        os.system(f"kill -9 {pid}")
        os.remove(BACKGROUND_PID_FILE)
        print(f"{colors.GREEN}[+] Background mode stopped{colors.RESET}")
    else:
        print(f"{colors.RED}[!] No background process running{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

def check_background_status():
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        print(f"\n{colors.GREEN}[+] Background process running with PID: {pid}{colors.RESET}")
    else:
        print(f"\n{colors.RED}[!] No background process running{colors.RESET}")
    input(f"\n{colors.BLUE}[*] Press Enter to continue...{colors.RESET}")

# Monitor de IP em tempo real
class IPMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True
        self.current_ip = None
        self.current_country = None
        self.tor_enabled = False
        
    def run(self):
        while self.running:
            try:
                # Verifica se TOR está ativo
                self.tor_enabled = "tor" in subprocess.getoutput("ps -e")
                
                if self.tor_enabled:
                    ip_info = subprocess.getoutput("torsocks curl -s https://ipinfo.io/json")
                else:
                    ip_info = subprocess.getoutput("curl -s https://ipinfo.io/json")
                
                if '"ip":' in ip_info:
                    self.current_ip = ip_info.split('"ip": "')[1].split('"')[0]
                    self.current_country = ip_info.split('"country": "')[1].split('"')[0]
                else:
                    self.current_ip = "Unable to determine"
                    self.current_country = "Unknown"
                
                time.sleep(IP_CHECK_INTERVAL)
            except:
                self.current_ip = "Error"
                self.current_country = "Error"
                time.sleep(10)
    
    def stop(self):
        self.running = False

# Monitor de rede em tempo real
def network_monitor(ip_monitor):
    animated_banner()
    print(f"\n{colors.BOLD}{colors.WHITE}REAL-TIME NETWORK MONITOR:{colors.RESET}")
    print(f"{colors.YELLOW}>>> Press CTRL+C to return to menu <<<{colors.RESET}")
    
    try:
        while True:
            print(f"\n{colors.BLUE}╔══════════════════════════════════════════════════════════════╗")
            print(f"║ {colors.BOLD}NETWORK STATUS:{colors.RESET}{colors.BLUE} ", end="")
            print(f"IP: {colors.GREEN if ip_monitor.tor_enabled else colors.RED}{ip_monitor.current_ip}{colors.BLUE}", end="")
            print(f" | Country: {colors.CYAN}{ip_monitor.current_country}{colors.BLUE}", end="")
            print(f" | TOR: {'ON' if ip_monitor.tor_enabled else 'OFF'}{' '*(18-len(ip_monitor.current_ip))}║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            
            # Mostrar conexões ativas
            print(f"║ {colors.BOLD}ACTIVE CONNECTIONS:{colors.RESET}{colors.BLUE}{' '*36}║")
            connections = subprocess.getoutput("netstat -tunp 2>/dev/null | grep -v '127.0.0.1' | tail -n 5")
            for line in connections.split('\n'):
                print(f"║ {line[:56].ljust(56)}{colors.BLUE}║")
            
            print(f"╚══════════════════════════════════════════════════════════════╝{colors.RESET}")
            
            # Spinner de animação
            print(f"\n{colors.MAGENTA}Updating in {IP_CHECK_INTERVAL} seconds... {next(spinner)}{colors.RESET}", end="\r")
            time.sleep(1)
            
            # Limpar linhas para atualização
            print("\033[F" * 10, end="")
    except KeyboardInterrupt:
        return

# Função para limpeza e saída
def cleanup_and_exit(ip_monitor):
    print(f"\n{colors.YELLOW}[*] Cleaning up and exiting...{colors.RESET}")
    
    # Parar monitor de IP
    ip_monitor.stop()
    
    # Verificar e matar processos em segundo plano
    if os.path.exists(BACKGROUND_PID_FILE):
        with open(BACKGROUND_PID_FILE, "r") as f:
            pid = f.read().strip()
        os.system(f"kill -9 {pid} 2>/dev/null")
        os.remove(BACKGROUND_PID_FILE)
    
    # Limpar configurações temporárias
    os.system("unset http_proxy https_proxy 2>/dev/null")
    
    print(f"{colors.GREEN}[+] Cleanup complete. Goodbye!{colors.RESET}")
    sys.exit(0)

# Função principal
def main():
    # Verificar Termux
    if not os.path.exists("/data/data/com.termux/files/usr/bin"):
        print(f"{colors.RED}[!] This script must run on Termux{colors.RESET}")
        sys.exit(1)
    
    # Verificar dependências
    check_dependencies()
    
    # Iniciar monitor de IP
    ip_monitor = IPMonitor()
    ip_monitor.start()
    
    # Configurar handler para CTRL+C
    signal.signal(signal.SIGINT, lambda s, f: cleanup_and_exit(ip_monitor))
    
    # Mostrar menu principal
    show_menu(ip_monitor)

if __name__ == "__main__":
    main()
