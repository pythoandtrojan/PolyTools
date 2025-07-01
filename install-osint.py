#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
import time
from colorama import Fore, Style, init

init(autoreset=True)


VERSAO = "1.1"
ESPERA_ENTER = 2  


BANNER = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
{Fore.BLUE}║ █████╗ ██████╗ ██╗     ███████╗██╗  ██╗███████╗██████╗  ║
{Fore.GREEN}║██╔══██╗██╔══██╗██║     ██╔════╝╚██╗██╔╝██╔════╝██╔══██╗ ║
{Fore.YELLOW}║███████║██████╔╝██║     █████╗   ╚███╔╝ █████╗  ██████╔╝ ║
{Fore.RED}║██╔══██║██╔═══╝ ██║     ██╔══╝   ██╔██╗ ██╔══╝  ██╔══██╗ ║
{Fore.MAGENTA}║██║  ██║██║     ███████╗███████╗██╔╝ ██╗███████╗██║  ██║ ║
{Fore.CYAN}╚════════════════════════════════════════════════════════════╝
{Fore.WHITE}{Style.BRIGHT}Instalador Termux - Dependências OSINT v{VERSAO}{Style.RESET_ALL}
"""


BIBLIOTECAS_PIP_TERMUX = [
    "requests",         
    "beautifulsoup4",   
    "python-whois",    
    "colorama",       
    "python-nmap",    
    "pyexiftool",      
    "selenium",         
    "scapy",          
    "shodan",        
    "censys",         
    "pyfiglet",       
    "tqdm",             
    "dnspython",       
            
   
]


PACOTES_PKG_TERMUX = [
    "nmap",           
    "whois",           
    "dnsutils",        
    "git",            
    "exiftool",        
    "ffmpeg",          
    "tcpdump",        
    "wget",            
    "curl",            
    "python",         
    "openssl",         
    "libffi",         
    "clang",           
    "make"             
]

def limpar_tela():
    """Limpa a tela do terminal"""
    os.system('clear')

def exibir_banner():
    """Exibe o banner do script"""
    limpar_tela()
    print(BANNER)
    print(f"{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║{Fore.WHITE} Termux | Python {platform.python_version()} | OS: {platform.system()} {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

def esperar_enter(tempo=ESPERA_ENTER):
    """Pausa e espera Enter para continuar"""
    input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
    time.sleep(tempo)

def verificar_instalacao_pip(pacote):
    """Verifica se um pacote Python está instalado via pip"""
    try:
        __import__(pacote)
        return True
    except ImportError:
        return False

def instalar_pacotes_pip():
    """Instala todos os pacotes Python necessários via pip no Termux"""
    print(f"\n{Fore.CYAN}[*] Instalando bibliotecas Python via pip...{Fore.RESET}")
    
    for biblioteca in BIBLIOTECAS_PIP_TERMUX:
        if verificar_instalacao_pip(biblioteca.split("==")[0]):
            print(f"{Fore.GREEN}[+] {biblioteca} já está instalado{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}[*] Instalando {biblioteca}...{Fore.RESET}")
            try:
            
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", biblioteca], check=True)
                print(f"{Fore.GREEN}[+] {biblioteca} instalado com sucesso!{Fore.RESET}")
            except subprocess.CalledProcessError:
                print(f"{Fore.RED}[-] Falha ao instalar {biblioteca}{Fore.RESET}")
    
    print(f"\n{Fore.GREEN}[✓] Todas as bibliotecas Python foram processadas{Fore.RESET}")

def instalar_pacotes_pkg():
    """Instala pacotes do sistema via pkg no Termux"""
    print(f"\n{Fore.CYAN}[*] Instalando pacotes do sistema via pkg...{Fore.RESET}")
    
   
    print(f"{Fore.YELLOW}[*] Atualizando lista de pacotes...{Fore.RESET}")
    subprocess.run(["pkg", "update", "-y"], check=True)
    
    for pacote in PACOTES_PKG_TERMUX:
        print(f"{Fore.YELLOW}[*] Verificando {pacote}...{Fore.RESET}")
        try:
       
            resultado = subprocess.run(["pkg", "list-installed"], capture_output=True, text=True)
            if pacote in resultado.stdout:
                print(f"{Fore.GREEN}[+] {pacote} já está instalado{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}[*] Instalando {pacote}...{Fore.RESET}")
                subprocess.run(["pkg", "install", "-y", pacote], check=True)
                print(f"{Fore.GREEN}[+] {pacote} instalado com sucesso!{Fore.RESET}")
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[-] Falha ao instalar {pacote}{Fore.RESET}")
    
    print(f"\n{Fore.GREEN}[✓] Todos os pacotes do sistema foram processados{Fore.RESET}")

def verificar_termux():
    """Verifica se estamos executando no Termux"""
    return os.path.exists('/data/data/com.termux/files/usr/bin/termux-setup-storage')

def main():
    """Função principal"""
    exibir_banner()
    
    if not verificar_termux():
        print(f"{Fore.RED}[-] Este script deve ser executado no Termux!{Fore.RESET}")
        sys.exit(1)
    
    print(f"{Fore.YELLOW}[!] Este instalador vai configurar seu Termux para ferramentas OSINT")
    print(f"{Fore.YELLOW}[!] Serão instalados {len(BIBLIOTECAS_PIP_TERMUX)} bibliotecas Python")
    print(f"{Fore.YELLOW}[!] e {len(PACOTES_PKG_TERMUX)} pacotes do sistema{Fore.RESET}")
    
    esperar_enter()
    instalar_pacotes_pkg()
    instalar_pacotes_pip()
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Instalação concluída com sucesso!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Agora você pode usar ferramentas como nmap e whois no Termux")
    print(f"{Fore.CYAN}[*] Lembre-se de configurar o storage com: termux-setup-storage{Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Instalação cancelada pelo usuário{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Erro durante a instalação: {str(e)}{Fore.RESET}")
        sys.exit(2)
