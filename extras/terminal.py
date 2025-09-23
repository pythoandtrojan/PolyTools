#!/usr/bin/env python3
import os
import subprocess
import sys
from datetime import datetime

# Cores para o terminal (estilo Kali)
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BLACK = '\033[90m'

def clear_screen():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Exibe o banner do PolyTools"""
    banner = f"""
{Colors.RED}{Colors.BOLD}
    ██████╗  ██████╗ ██╗  ██╗   ██╗████████╗ ██████╗  ██████╗ ██╗     ███████╗
    ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
    ██████╔╝██║   ██║██║   ╚████╔╝    ██║   ██║   ██║██║   ██║██║     ███████╗
    ██╔═══╝ ██║   ██║██║    ╚██╔╝     ██║   ██║   ██║██║   ██║██║     ╚════██║
    ██║     ╚██████╔╝███████╗██║      ██║   ╚██████╔╝╚██████╔╝███████╗███████║
    ╚═╝      ╚═════╝ ╚══════╝╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
{Colors.RESET}
    {Colors.CYAN}PolyTools Terminal v1.0{Colors.RESET}
    {Colors.YELLOW}Type 'help' for available commands{Colors.RESET}
    {Colors.GREEN}Type 'exit' to quit{Colors.RESET}
    """
    print(banner)

def get_prompt():
    """Retorna o prompt personalizado"""
    current_time = datetime.now().strftime("%H:%M:%S")
    username = os.getenv('USER') or os.getenv('USERNAME')
    hostname = os.uname().nodename if hasattr(os, 'uname') else os.getenv('COMPUTERNAME')
    
    return f"{Colors.RED}{Colors.BOLD}┌─[{Colors.GREEN}{username}{Colors.RED}@{Colors.BLUE}{hostname}{Colors.RED}]-[{Colors.YELLOW}{current_time}{Colors.RED}]\n{Colors.RED}└──╼ {Colors.MAGENTA}PolyTools{Colors.WHITE}@prompt{Colors.RED}${Colors.RESET} "

def execute_command(command):
    """Executa comandos do sistema operacional"""
    try:
        if command.lower() in ['exit', 'quit']:
            print(f"{Colors.YELLOW}Saindo do PolyTools...{Colors.RESET}")
            sys.exit(0)
            
        elif command.lower() in ['clear', 'cls']:
            clear_screen()
            print_banner()
            return
            
        elif command.lower() == 'help':
            show_help()
            return
            
        elif command.lower() == 'banner':
            print_banner()
            return
            
        # Executa o comando no sistema
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"{Colors.RED}{result.stderr}{Colors.RESET}")
            
    except Exception as e:
        print(f"{Colors.RED}Erro ao executar comando: {e}{Colors.RESET}")

def show_help():
    """Mostra os comandos disponíveis"""
    help_text = f"""
{Colors.CYAN}{Colors.BOLD}Comandos disponíveis no PolyTools:{Colors.RESET}

{Colors.GREEN}Comandos do sistema:{Colors.RESET}
    • Qualquer comando do sistema operacional (ls, dir, cd, etc.)
    • clear/cls - Limpa a tela
    • exit/quit - Sai do PolyTools

{Colors.YELLOW}Comandos especiais:{Colors.RESET}
    • help - Mostra esta ajuda
    • banner - Mostra o banner do PolyTools

{Colors.BLUE}Exemplos:{Colors.RESET}
    {Colors.WHITE}ls -la{Colors.RESET}          Lista arquivos detalhadamente
    {Colors.WHITE}cd Documents{Colors.RESET}    Muda para o diretório Documents
    {Colors.WHITE}pwd{Colors.RESET}            Mostra o diretório atual
    """
    print(help_text)

def main():
    """Função principal"""
    clear_screen()
    print_banner()
    
    print(f"{Colors.GREEN}PolyTools Terminal iniciado com sucesso!{Colors.RESET}\n")
    
    while True:
        try:
            command = input(get_prompt()).strip()
            
            if command:
                execute_command(command)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Use 'exit' ou 'quit' para sair.{Colors.RESET}")
        except EOFError:
            print(f"\n{Colors.YELLOW}Saindo...{Colors.RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}Erro: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
