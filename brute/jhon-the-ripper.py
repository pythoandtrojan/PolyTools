#!/data/data/com.termux/files/usr/bin/python3
import os
import subprocess
import sys
from colorama import Fore, Style, init

# Configuração do Colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.GREEN}██████╗ ██╗  ██╗██████╗ ███╗   ██╗{Fore.RED} ██████╗██╗  ██╗███████╗
{Fore.GREEN}██╔══██╗╚██╗██╔╝██╔══██╗████╗  ██║{Fore.RED}██╔════╝██║  ██║██╔════╝
{Fore.GREEN}██████╔╝ ╚███╔╝ ██████╔╝██╔██╗ ██║{Fore.RED}██║     ███████║█████╗  
{Fore.GREEN}██╔═══╝  ██╔██╗ ██╔══██╗██║╚██╗██║{Fore.RED}██║     ██╔══██║██╔══╝  
{Fore.GREEN}██║     ██╔╝ ██╗██║  ██║██║ ╚████║{Fore.RED}╚██████╗██║  ██║███████╗
{Fore.GREEN}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.RED} ╚═════╝╚═╝  ╚═╝╚══════╝
{Fore.YELLOW}═══════════════════════════════════════════════
{Fore.CYAN}  John the Ripper Automatizado para Termux
{Fore.YELLOW}═══════════════════════════════════════════════
{Fore.BLUE}  [1] Ataque de Dicionário    [5] Ataque Incremental
{Fore.BLUE}  [2] Ataque com Máscara      [6] Ataque de Regras
{Fore.BLUE}  [3] Ataque Combinado        [7] Crack de Hash Único
{Fore.BLUE}  [4] Ataque Bruto            [8] Personalizado
{Fore.YELLOW}═══════════════════════════════════════════════
    """
    print(banner)

def check_dependencies():
    required = ['john', 'wget']
    missing = []
    
    for cmd in required:
        try:
            subprocess.run([cmd, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            missing.append(cmd)
    
    if missing:
        print(f"{Fore.RED}[!] Dependências faltando: {', '.join(missing)}")
        print(f"{Fore.YELLOW}[*] Instalando dependências...")
        try:
            subprocess.run(["pkg", "install", "-y"] + missing, check=True)
            print(f"{Fore.GREEN}[+] Dependências instaladas com sucesso!")
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[!] Falha ao instalar dependências")
            sys.exit(1)

def setup_wordlists():
    wordlists_dir = os.path.expanduser("~/storage/shared/wordlists")
    os.makedirs(wordlists_dir, exist_ok=True)
    
    wordlists = {
        "rockyou.txt": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "custom.txt": None
    }
    
    for name, url in wordlists.items():
        if not os.path.exists(f"{wordlists_dir}/{name}"):
            if url:
                print(f"{Fore.YELLOW}[*] Baixando {name}...")
                try:
                    subprocess.run(["wget", url, "-O", f"{wordlists_dir}/{name}"], check=True)
                    print(f"{Fore.GREEN}[+] {name} baixado com sucesso!")
                except subprocess.CalledProcessError:
                    print(f"{Fore.RED}[!] Falha ao baixar {name}")
            else:
                open(f"{wordlists_dir}/{name}", 'w').close()
                print(f"{Fore.GREEN}[+] Arquivo {name} criado")

def run_attack():
    try:
        attack_type = int(input(f"{Fore.CYAN}[?] Selecione o tipo de ataque (1-8): "))
        hash_file = input(f"{Fore.CYAN}[?] Caminho para o arquivo de hash: ")
        
        if not os.path.exists(hash_file):
            print(f"{Fore.RED}[!] Arquivo de hash não encontrado!")
            return
        
        wordlists_dir = os.path.expanduser("~/storage/shared/wordlists")
        
        if attack_type == 1:  # Dictionary
            wordlist = input(f"{Fore.CYAN}[?] Wordlist (padrão: rockyou.txt): ") or "rockyou.txt"
            subprocess.run(["john", "--wordlist", f"{wordlists_dir}/{wordlist}", hash_file])
        
        elif attack_type == 2:  # Mask
            mask = input(f"{Fore.CYAN}[?] Máscara (ex: ?l?l?l?l?d?d): ")
            subprocess.run(["john", "--mask", mask, hash_file])
        
        # Adicione outros tipos de ataque aqui...
        
        else:
            print(f"{Fore.RED}[!] Tipo de ataque inválido!")
            
    except ValueError:
        print(f"{Fore.RED}[!] Entrada inválida!")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operação cancelada pelo usuário")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {str(e)}")

def main():
    print_banner()
    check_dependencies()
    setup_wordlists()
    
    while True:
        print(f"\n{Fore.MAGENTA}[Menu Principal]")
        print(f"{Fore.CYAN}1. Executar Ataque")
        print(f"{Fore.CYAN}2. Gerenciar Wordlists")
        print(f"{Fore.CYAN}3. Sair")
        
        try:
            choice = int(input(f"{Fore.YELLOW}[?] Selecione uma opção: "))
            
            if choice == 1:
                run_attack()
            elif choice == 2:
                print(f"{Fore.GREEN}\n[+] Wordlists disponíveis em: ~/storage/shared/wordlists")
            elif choice == 3:
                print(f"{Fore.YELLOW}[*] Saindo...")
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!")
                
        except ValueError:
            print(f"{Fore.RED}[!] Entrada inválida!")

if __name__ == "__main__":
    main()
