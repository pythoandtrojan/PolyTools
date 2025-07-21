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
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    """)

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

# Menu interativo moderno
def show_menu(ip_monitor):
    while True:
        animated_banner()
        
        # Barra de status
        print(f"\n{colors.BLUE}╔══════════════════════════════════════════════════════════════╗")
        print(f"║ {colors.BOLD}STATUS:{colors.RESET}{colors.BLUE} ", end="")
        print(f"IP: {colors.GREEN if ip_monitor.tor_enabled else colors.RED}{ip_monitor.current_ip}{colors.BLUE}", end="")
        print(f" | Country: {colors.CYAN}{ip_monitor.current_country}{colors.BLUE}", end="")
        print(f" | TOR: {'ON' if ip_monitor.tor_enabled else 'OFF'}{' '*(18-len(ip_monitor.current_ip))}║")
        print(f"╚══════════════════════════════════════════════════════════════╝{colors.RESET}")
        
        # Opções do menu
        print(f"\n{colors.BOLD}{colors.WHITE}MAIN MENU:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ TOR Services Management                    {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Network Anonymization (MAC/VPN)           {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ Secure Communication Tools                {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Privacy Cleaner & Anti-Forensics          {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}5{colors.RESET}{colors.GREEN} │ Background Mode Control                   {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}6{colors.RESET}{colors.GREEN} │ Real-time Network Monitor                 {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}7{colors.RESET}{colors.GREEN} │ Exit & Cleanup                            {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        try:
            choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Select an option (1-7): {colors.RESET}")
            
            if choice == "1":
                tor_management()
            elif choice == "2":
                network_anonymization()
            elif choice == "3":
                secure_communication()
            elif choice == "4":
                privacy_cleaner()
            elif choice == "5":
                background_mode_control()
            elif choice == "6":
                network_monitor(ip_monitor)
            elif choice == "7":
                cleanup_and_exit(ip_monitor)
            else:
                print(f"\n{colors.RED}[!] Invalid option! Please try again.{colors.RESET}")
                time.sleep(1)
        except KeyboardInterrupt:
            cleanup_and_exit(ip_monitor)

# Função para gerenciamento do TOR
def tor_management():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}TOR SERVICES MANAGEMENT:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Start TOR Service                         {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Stop TOR Service                          {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ TOR Configuration Editor                  {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Test TOR Connection                      {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}5{colors.RESET}{colors.GREEN} │ Back to Main Menu                        {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Select an option (1-5): {colors.RESET}")
        
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
            print(f"\n{colors.RED}[!] Invalid option!{colors.RESET}")
            time.sleep(1)

# Funções para gerenciamento de rede
def network_anonymization():
    while True:
        animated_banner()
        print(f"\n{colors.BOLD}{colors.WHITE}NETWORK ANONYMIZATION:{colors.RESET}")
        print(f"  {colors.GREEN}┌───┬───────────────────────────────────────────────┐")
        print(f"  │ {colors.BOLD}1{colors.RESET}{colors.GREEN} │ Change MAC Address (Spoofing)             {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}2{colors.RESET}{colors.GREEN} │ Enable VPN Connection                     {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}3{colors.RESET}{colors.GREEN} │ DNS Leak Protection                      {colors.GREEN}│")
        print(f"  ├───┼───────────────────────────────────────────────┤")
        print(f"  │ {colors.BOLD}4{colors.RESET}{colors.GREEN} │ Back to Main Menu                        {colors.GREEN}│")
        print(f"  └───┴───────────────────────────────────────────────┘{colors.RESET}")
        
        choice = input(f"\n{colors.CYAN}{colors.BOLD}[?] Select an option (1-4): {colors.RESET}")
        
        if choice == "1":
            mac_spoofing()
        elif choice == "2":
            vpn_management()
        elif choice == "3":
            dns_protection()
        elif choice == "4":
            return
        else:
            print(f"\n{colors.RED}[!] Invalid option!{colors.RESET}")
            time.sleep(1)

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
