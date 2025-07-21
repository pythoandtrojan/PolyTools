import os
import subprocess
from colorama import init, Fore, Back, Style
import json
import time

# Inicializa colorama
init(autoreset=True)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    banner = f"""
{Fore.GREEN}╔════════════════════════════════════════════════════════════╗
{Fore.GREEN}║{Fore.WHITE}{Back.GREEN}                   HOLEHE AUTOMATIZER v1.0                   {Back.RESET}{Fore.GREEN}║
{Fore.GREEN}║{Fore.WHITE}{Back.GREEN}         Verificação de contas em múltiplos serviços         {Back.RESET}{Fore.GREEN}║
{Fore.GREEN}╚════════════════════════════════════════════════════════════╝
{Fore.RESET}
    """
    print(banner)

def run_holehe(email):
    try:
        print(f"\n{Fore.CYAN}[*] Executando Holehe para {email}...{Fore.RESET}\n")
        
        # Executa o holehe e captura a saída JSON
        command = f"holehe {email} --only-used --no-color -o json"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"{Fore.RED}[!] Erro ao executar Holehe:{Fore.RESET}")
            print(result.stderr)
            return None
        
        # Tenta parsear o JSON
        try:
            data = json.loads(result.stdout)
            return data
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Não foi possível ler a saída do Holehe{Fore.RESET}")
            return None
            
    except Exception as e:
        print(f"{Fore.RED}[!] Erro:{Fore.RESET} {str(e)}")
        return None

def display_results(data, email):
    if not data:
        print(f"{Fore.RED}[!] Nenhum resultado encontrado{Fore.RESET}")
        return

    print(f"\n{Fore.YELLOW}══════════════════ RESULTADOS PARA {email.upper()} ══════════════════{Fore.RESET}\n")
    
    found = 0
    for service in data:
        if service['exists']:
            found += 1
            status = f"{Fore.GREEN}✔ ENCONTRADO{Fore.RESET}"
            print(f"{Fore.WHITE}[+] {service['name']:<25} {status}")
            print(f"    {Fore.CYAN}URL:{Fore.RESET} {service.get('url', 'N/A')}")
            print(f"    {Fore.CYAN}Método:{Fore.RESET} {service.get('method', 'N/A')}\n")
    
    print(f"\n{Fore.YELLOW}══════════════════════════════════════════════════════════{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Total de contas encontradas: {Fore.WHITE}{found}{Fore.RESET}")
    print(f"{Fore.YELLOW}══════════════════════════════════════════════════════════{Fore.RESET}\n")

def save_results(email, data):
    filename = f"holehe_results_{email.replace('@', '_at_')}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"{Fore.GREEN}[+] Resultados salvos em {filename}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao salvar resultados:{Fore.RESET} {str(e)}")

def main():
    clear_terminal()
    display_banner()
    
    while True:
        print(f"\n{Fore.YELLOW}╔════════════════════ MENU ═══════════════════╗")
        print(f"{Fore.YELLOW}║ {Fore.CYAN}1. Verificar email                      {Fore.YELLOW}║")
        print(f"{Fore.YELLOW}║ {Fore.CYAN}2. Sair                                {Fore.YELLOW}║")
        print(f"{Fore.YELLOW}╚══════════════════════════════════════════╝{Fore.RESET}")
        
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (1-2): {Fore.RESET}").strip()
        
        if choice == '1':
            email = input(f"\n{Fore.YELLOW}[?] Digite o email para verificar: {Fore.RESET}").strip().lower()
            
            if not '@' in email:
                print(f"{Fore.RED}[!] Por favor, insira um email válido{Fore.RESET}")
                time.sleep(1)
                continue
                
            data = run_holehe(email)
            display_results(data, email)
            
            if data:
                save = input(f"{Fore.YELLOW}[?] Deseja salvar os resultados? (s/n): {Fore.RESET}").lower()
                if save == 's':
                    save_results(email, data)
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
            clear_terminal()
            
        elif choice == '2':
            print(f"\n{Fore.CYAN}[*] Saindo... Obrigado por usar Holehe Automatizer!{Fore.RESET}")
            time.sleep(1)
            clear_terminal()
            break
            
        else:
            print(f"\n{Fore.RED}[!] Opção inválida. Por favor, escolha 1 ou 2.{Fore.RESET}")
            time.sleep(1)
            clear_terminal()

if __name__ == "__main__":
    # Verifica se o holehe está instalado
    try:
        subprocess.run(["holehe", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        print(f"{Fore.RED}[!] Holehe não está instalado. Instale com:{Fore.RESET}")
        print("pip install holehe")
        exit(1)
    
    main()
