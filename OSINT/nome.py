#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
import os
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL


API_URL = "https://api.encrypt.wtf/new/api.php"
TOKEN = "ifindy"
BASE = "nome_completo2"

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ███╗   ██╗ ██████╗ ███╗   ███╗███████╗
   ████╗  ██║██╔═══██╗████╗ ████║██╔════╝
   ██╔██╗ ██║██║   ██║██╔████╔██║█████╗  
   ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  
   ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗
   ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
{RESET}
{CIANO}{NEGRITO}   CONSULTA POR NOME - API DIRETA
{RESET}""")

def consultar_api(nome):
 
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    print(f"\n{AMARELO}[*] Fazendo consulta à API...{RESET}")
    print(f"{AZUL}[*] URL: {url}{RESET}")

    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        print(f"{AZUL}[*] Status HTTP: {resposta.status_code}{RESET}")

        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                print(f"{VERDE}[+] Dados recebidos com sucesso!{RESET}")
                return dados
            except json.JSONDecodeError:
                print(f"{VERMELHO}[!] Resposta não é JSON válido{RESET}")
                print(f"{AZUL}[*] Conteúdo bruto:{RESET}\n{resposta.text[:500]}")
                return None
        else:
            print(f"{VERMELHO}[!] Erro na API: {resposta.status_code}{RESET}")
            return None

    except requests.exceptions.SSLError:
        print(f"{VERMELHO}[!] Erro de SSL - Continuando mesmo assim{RESET}")
        return None
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de espera esgotado (15s){RESET}")
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro inesperado: {e}{RESET}")
        return None

def mostrar_resultados(dados):

    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    print(f"\n{VERDE}{NEGRITO}=== DADOS ENCONTRADOS ==={RESET}")
    
    # Exibe exatamente como no seu exemplo funcional
    if isinstance(dados, dict):
        for chave, valor in dados.items():
            print(f"  - {chave}: {valor}")
    elif isinstance(dados, list):
        for i, item in enumerate(dados, 1):
            print(f"\n{CIANO}{NEGRITO}--- Pessoa {i} ---{RESET}")
            for chave, valor in item.items():
                print(f"  - {chave}: {valor}")
    else:
        print(f"{AMARELO}[*] Tipo de resposta inesperado:{RESET}")
        print(dados)

def main():

    try:
        while True:
            banner()
            print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
            print(f"{VERDE}[1]{RESET} Consultar por Nome")
            print(f"{VERDE}[2]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                nome = input(f"\n{CIANO}Digite o nome completo: {RESET}").strip()
                
                if not nome or len(nome.split()) < 2:
                    print(f"{VERMELHO}[!] Digite um nome completo válido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                dados = consultar_api(nome)
                mostrar_resultados(dados)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                print(f"\n{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
