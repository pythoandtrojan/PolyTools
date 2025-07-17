#!/usr/bin/env python3
import subprocess
import sys
import argparse
from termcolor import colored

def display_banner():
    banner = r"""
    ██╗  ██╗ ██████╗ ██╗     ███████╗██╗  ██╗███████╗
    ██║  ██║██╔═══██╗██║     ██╔════╝██║  ██║██╔════╝
    ███████║██║   ██║██║     █████╗  ███████║█████╗  
    ██╔══██║██║   ██║██║     ██╔══╝  ██╔══██║██╔══╝  
    ██║  ██║╚██████╔╝███████╗███████╗██║  ██║███████╗
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
    """
    print(colored(banner, 'cyan'))
    print(colored("Holehe Automator - ONLY EMAIL CHECKING", 'yellow'))
    print("="*55 + "\n")

def run_holehe(email):
    try:
        print(colored(f"\n[+] Verificando: {email}\n", 'blue'))
        
        cmd = ["holehe", email]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(colored_output(result.stdout))
        else:
            print(colored(f"[-] ERRO: {result.stderr}", 'red'))
            
    except FileNotFoundError:
        print(colored("[!] Holehe não está instalado. Instale com:", 'red'))
        print(colored("    pip install holehe", 'yellow'))
    except Exception as e:
        print(colored(f"[-] Falha crítica: {e}", 'red'))

def colored_output(output):
    """Coloriza a saída do Holehe de forma fiel"""
    lines = output.split('\n')
    for line in lines:
        if "[+]" in line:  # Existente (verde)
            print(colored(line, 'green'))
        elif "[-]" in line:  # Não existente (vermelho)
            print(colored(line, 'red'))
        elif "[!]" in line:  # Aviso (amarelo)
            print(colored(line, 'yellow'))
        elif "[x]" in line:  # Erro (magenta)
            print(colored(line, 'magenta'))
        else:
            print(line)  # Texto normal

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="Automator para Holehe (só verifica emails)")
    parser.add_argument("email", help="Email para investigar")
    args = parser.parse_args()
    
    if not args.email:
        print(colored("[!] Forneça um email válido.", 'red'))
        sys.exit(1)
    
    run_holehe(args.email)

if __name__ == "__main__":
    main()
