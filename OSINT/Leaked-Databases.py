#!/usr/bin/env python3

import requests
import json
import sys
from time import sleep
from colorama import Fore, Style, init

init(autoreset=True)
def banner():
    print(Fore.RED + """
  ____  _             _      ____              _    
 |  _ \| | __ _ _ __ | | __ | __ )  ___   ___ | | __
 | |_) | |/ _` | '_ \| |/ / |  _ \ / _ \ / _ \| |/ /
 |  __/| | (_| | | | |   <  | |_) | (_) | (_) |   < 
 |_|   |_|\__,_|_| |_|_|\_\ |____/ \___/ \___/|_|\_\\
 
 """ + Fore.YELLOW + " Consulta de Vazamentos de Dados" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.GREEN + " GitHub: https://github.com/seu-usuario" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")


def check_internet():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except:
        return False


def check_hibp(email):
    try:
        headers = {
            'User-Agent': 'Python-LeakCheck/1.0',
            'hibp-api-key': 'sua-chave-api-hibp' 
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            breaches = json.loads(response.text)
            print(Fore.RED + f"\n[!] E-mail encontrado em {len(breaches)} vazamentos:" + Style.RESET_ALL)
            for breach in breaches:
                print(Fore.YELLOW + f"\nNome do vazamento: {breach['Name']}")
                print(f"Domínio: {breach['Domain']}")
                print(f"Data do vazamento: {breach['BreachDate']}")
                print(f"Descrição: {breach['Description']}")
                print(f"Classes de dados vazados: {', '.join(breach['DataClasses'])}")
            return True
        elif response.status_code == 404:
            print(Fore.GREEN + f"\n[+] E-mail não encontrado em vazamentos conhecidos (HIBP)." + Style.RESET_ALL)
            return False
        else:
            print(Fore.YELLOW + f"\n[!] Erro ao consultar HIBP: {response.status_code}" + Style.RESET_ALL)
            return False
    except Exception as e:
        print(Fore.RED + f"\n[!] Erro na consulta HIBP: {str(e)}" + Style.RESET_ALL)
        return False


def check_leakcheck(query):
    try:

        print(Fore.YELLOW + "\n[!] Consulta ao LeakCheck desativada (requer API key)" + Style.RESET_ALL)
        return False
        
        
    except Exception as e:
        print(Fore.RED + f"\n[!] Erro na consulta LeakCheck: {str(e)}" + Style.RESET_ALL)
        return False


def check_local_database(query):
    try:
    
        print(Fore.YELLOW + "\n[!] Banco de dados local não implementado neste exemplo" + Style.RESET_ALL)
        return False
    except Exception as e:
        print(Fore.RED + f"\n[!] Erro ao consultar banco local: {str(e)}" + Style.RESET_ALL)
        return False


def main():
    banner()
    
    if not check_internet():
        print(Fore.RED + "\n[!] Sem conexão com a internet. Verifique sua conexão." + Style.RESET_ALL)
        sys.exit(1)
    
    print(Fore.CYAN + "\nOpções de consulta:" + Style.RESET_ALL)
    print("1. Consultar por e-mail")
    print("2. Consultar por nome de usuário")
    print("3. Consultar por CPF")
    print("4. Sair")
    
    try:
        option = int(input("\nSelecione uma opção: "))
    except:
        print(Fore.RED + "\n[!] Opção inválida." + Style.RESET_ALL)
        sys.exit(1)
    
    if option == 4:
        print(Fore.YELLOW + "\nSaindo..." + Style.RESET_ALL)
        sys.exit(0)
    
    query = input("\nDigite o dado para consulta: ").strip()
    
    if not query:
        print(Fore.RED + "\n[!] Entrada vazia." + Style.RESET_ALL)
        sys.exit(1)
    
    print(Fore.BLUE + "\nIniciando consultas..." + Style.RESET_ALL)
    
    found = False
    
    if option == 1:  # 
        if "@" not in query or "." not in query:
            print(Fore.RED + "\n[!] E-mail inválido." + Style.RESET_ALL)
            sys.exit(1)
        
        print(Fore.CYAN + "\nConsultando Have I Been Pwned..." + Style.RESET_ALL)
        found = check_hibp(query) or found
        
        print(Fore.CYAN + "\nConsultando LeakCheck..." + Style.RESET_ALL)
        found = check_leakcheck(query) or found
        
        print(Fore.CYAN + "\nConsultando banco de dados local..." + Style.RESET_ALL)
        found = check_local_database(query) or found
    
    elif option == 2:  
        print(Fore.CYAN + "\nConsultando LeakCheck..." + Style.RESET_ALL)
        found = check_leakcheck(query) or found
        
        print(Fore.CYAN + "\nConsultando banco de dados local..." + Style.RESET_ALL)
        found = check_local_database(query) or found
    
    elif option == 3:  
        if not query.isdigit() or len(query) != 11:
            print(Fore.RED + "\n[!] CPF inválido. Deve conter 11 dígitos." + Style.RESET_ALL)
            sys.exit(1)
        
        print(Fore.CYAN + "\nConsultando LeakCheck..." + Style.RESET_ALL)
        found = check_leakcheck(query) or found
        
        print(Fore.CYAN + "\nConsultando banco de dados local..." + Style.RESET_ALL)
        found = check_local_database(query) or found
    
    if not found:
        print(Fore.GREEN + "\n[+] Nenhum vazamento encontrado para o dado consultado." + Style.RESET_ALL)
    else:
        print(Fore.RED + "\n[!] ATENÇÃO: Seus dados foram vazados. Tome medidas para proteger suas contas!" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nConsulta concluída." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrompido pelo usuário." + Style.RESET_ALL)
        sys.exit(0)
