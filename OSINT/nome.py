#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
import os
import json
from datetime import datetime
from colorama import Fore, Style, init

# Configurações iniciais
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# Configurações da API (exatamente como no seu primeiro script)
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

def consultar_api_direta(nome):
    """Consulta a API exatamente como no seu primeiro script original"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    print(f"\n{AMARELO}[*] Fazendo consulta direta à API...{RESET}")
    print(f"{AZUL}[*] URL: {url}{RESET}")

    try:
        # Desativa verificação SSL e aumenta timeout
        resposta = requests.get(url, headers=headers, timeout=30, verify=False)
        
        print(f"{AZUL}[*] Status HTTP: {resposta.status_code}{RESET}")
        
        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                print(f"{VERDE}[+] Dados recebidos com sucesso!{RESET}")
                return dados
            except json.JSONDecodeError:
                print(f"{VERMELHO}[!] A resposta não é um JSON válido{RESET}")
                print(f"{AZUL}[*] Conteúdo bruto:{RESET}\n{resposta.text[:500]}...")
                return None
        else:
            print(f"{VERMELHO}[!] Erro na API: {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.SSLError:
        print(f"{VERMELHO}[!] Erro de SSL - Continuando mesmo assim{RESET}")
        try:
            resposta = requests.get(url, headers=headers, timeout=30, verify=False)
            return resposta.json() if resposta.status_code == 200 else None
        except Exception as e:
            print(f"{VERMELHO}[!] Falha na requisição: {e}{RESET}")
            return None
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de espera esgotado (30s){RESET}")
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro inesperado: {e}{RESET}")
        return None

def mostrar_resultados(dados):
    """Exibe os resultados de forma organizada"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    print(f"\n{VERDE}{NEGRITO}=== DADOS ENCONTRADOS ==={RESET}")
    
    # Se for uma lista de resultados
    if isinstance(dados, list):
        print(f"{AMARELO}[*] Total de registros: {len(dados)}{RESET}\n")
        for i, item in enumerate(dados[:5], 1):  # Mostra apenas os 5 primeiros
            print(f"{CIANO}{NEGRITO}--- Resultado {i} ---{RESET}")
            for chave, valor in item.items():
                print(f"{AZUL}{chave}:{RESET} {valor}")
            print()
        if len(dados) > 5:
            print(f"{AMARELO}[*] Mostrando 5 de {len(dados)} resultados{RESET}")
    else:
        # Se for um único dicionário
        for chave, valor in dados.items():
            # Mostra de forma organizada se for um dicionário aninhado
            if isinstance(valor, dict):
                print(f"\n{CIANO}{NEGRITO}--- {chave} ---{RESET}")
                for sub_chave, sub_valor in valor.items():
                    print(f"{AZUL}{sub_chave}:{RESET} {sub_valor}")
            elif isinstance(valor, list):
                print(f"\n{CIANO}{NEGRITO}--- {chave} ({len(valor)} itens) ---{RESET}")
                for item in valor[:3]:  # Mostra apenas os 3 primeiros
                    if isinstance(item, dict):
                        for k, v in item.items():
                            print(f"{AZUL}{k}:{RESET} {v}")
                        print()
                    else:
                        print(item)
                if len(valor) > 3:
                    print(f"{AMARELO}[...] {len(valor)-3} itens não mostrados{RESET}")
            else:
                print(f"{AZUL}{chave}:{RESET} {valor}")

def main():
    """Função principal"""
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
                
                dados = consultar_api_direta(nome)
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
