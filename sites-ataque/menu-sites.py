#!/usr/bin/env python3
import os
import sys
import socket
import subprocess
from time import sleep
from pyfiglet import Figlet
from termcolor import colored

# Configurações
SITES = {
    "1": {
        "name": "SQL Injection Lab",
        "path": "sql-inject-site",
        "file": "login.php",
        "port": 8000,
        "description": "Site vulnerável a SQL Injection (teste com SQLMap)"
    },
    "2": {
        "name": "XSS Vulnerable Site",
        "path": "xss-site",
        "file": "index.html",
        "port": 8001,
        "description": "Site com múltiplas vulnerabilidades XSS"
    },
    "3": {
        "name": "Spam Vulnerable Site",
        "path": "site-spam",
        "file": "index.html",
        "port": 8002,
        "description": "Site vulnerável a spam de formulários/comentários"
    },
    "4": {
        "name": "Brute Force Login",
        "path": "login-site",
        "file": "index.html",
        "port": 8003,
        "description": "Painel de login vulnerável a força bruta"
    },
    "5": {
        "name": "All Vulnerabilities",
        "path": None,
        "file": None,
        "port": None,
        "description": "Inicia todos os laboratórios simultaneamente"
    }
}

def clear_screen():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def check_ports():
    """Verifica se as portas estão disponíveis"""
    ports_in_use = []
    for site in SITES.values():
        if site["port"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', site["port"]))
            if result == 0:
                ports_in_use.append(site["port"])
            sock.close()
    return ports_in_use

def show_banner():
    """Exibe o banner do programa"""
    clear_screen()
    f = Figlet(font='slant')
    print(colored(f.renderText('VULN LAB'), '')
    print(colored("="*60, 'cyan'))
    print(colored("  Laboratório de Vulnerabilidades Web - By [Seu Nome]", 'yellow'))
    print(colored("="*60, 'cyan'))
    print()

def show_menu():
    """Mostra o menu de opções"""
    print(colored("Escolha um laboratório para iniciar:\n", 'green'))
    
    for key, site in SITES.items():
        print(colored(f"[{key}]", 'yellow'), colored(f"{site['name']}:", 'white'))
        print(f"    {site['description']}")
        if site['port']:
            print(colored(f"    URL: http://localhost:{site['port']}", 'blue'))
        print()
    
    print(colored("[0] Sair do programa\n", 'red'))
    print(colored("="*60, 'cyan'))

def start_server(site_info):
    """Inicia um servidor Python para o site escolhido"""
    try:
        path = os.path.join(os.path.dirname(__file__), site_info["path"])
        os.chdir(path)
        
        print(colored(f"\nIniciando {site_info['name']}...", 'green'))
        print(colored(f"Acesse: http://localhost:{site_info['port']}", 'blue'))
        
        if site_info["file"].endswith('.php'):
            # Para PHP, usamos o servidor embutido do PHP
            cmd = f"php -S localhost:{site_info['port']}"
        else:
            # Para HTML/JS, usamos o servidor Python
            cmd = f"python3 -m http.server {site_info['port']}"
        
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    
    except Exception as e:
        print(colored(f"\n[ERRO] Falha ao iniciar {site_info['name']}: {str(e)}", 'red'))
        return False

def stop_servers():
    """Para todos os servidores em execução"""
    try:
        print(colored("\nParando todos os servidores...", 'yellow'))
        if os.name == 'nt':  # Windows
            subprocess.run(["taskkill", "/F", "/IM", "php.exe"], stderr=subprocess.DEVNULL)
            subprocess.run(["taskkill", "/F", "/IM", "python.exe"], stderr=subprocess.DEVNULL)
        else:  # Unix/Linux/Mac
            subprocess.run(["pkill", "-f", "php -S"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "python3 -m http.server"], stderr=subprocess.DEVNULL)
        sleep(1)
    except:
        pass

def main():
    """Função principal"""
    try:
        while True:
            show_banner()
            
            # Verifica portas em uso
            ports_in_use = check_ports()
            if ports_in_use:
                print(colored(f"Aviso: Portas em uso: {ports_in_use}", 'yellow'))
                print(colored("Execute 'Parar todos os servidores' se necessário\n", 'yellow'))
            
            show_menu()
            
            choice = input(colored("Selecione uma opção: ", 'magenta'))
            
            if choice == "0":
                stop_servers()
                print(colored("\nSaindo do programa...", 'red'))
                sleep(1)
                break
            
            elif choice in SITES:
                site_info = SITES[choice]
                
                if choice == "5":  # Todos os laboratórios
                    stop_servers()
                    for key in [k for k in SITES.keys() if k != "5"]:
                        if not start_server(SITES[key]):
                            break
                    print(colored("\nTodos os laboratórios foram iniciados!", 'green'))
                else:
                    stop_servers()
                    if start_server(site_info):
                        print(colored(f"\n{site_info['name']} está rodando!", 'green'))
                
                input(colored("\nPressione Enter para voltar ao menu...", 'cyan'))
            
            else:
                print(colored("\nOpção inválida! Tente novamente.", 'red'))
                sleep(1)
    
    except KeyboardInterrupt:
        stop_servers()
        print(colored("\n\nPrograma interrompido pelo usuário", 'red'))
    
    except Exception as e:
        print(colored(f"\n[ERRO CRÍTICO] {str(e)}", 'red'))
        stop_servers()

if __name__ == "__main__":
    # Verifica dependências
    try:
        from pyfiglet import Figlet
        from termcolor import colored
    except ImportError:
        print("Instalando dependências necessárias...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyfiglet", "termcolor"])
    
    main()
