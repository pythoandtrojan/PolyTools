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
{CIANO}{NEGRITO}   CONSULTA POR NOME - API
{RESET}""")

def consultar_api(nome):
   
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    print(f"{AMARELO}[*] Consultando API direta para: {nome}{RESET}")
    print(f"{AZUL}[*] URL: {url}{RESET}")

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        print(f"{AZUL}[*] Status HTTP: {resposta.status_code}{RESET}")

        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                print(f"{VERDE}[+] Dados recebidos com sucesso!{RESET}")
                return dados
            except ValueError:
                print(f"{VERMELHO}[!] Resposta não é JSON. Conteúdo bruto:{RESET}")
                print(resposta.text[:500])
                return None
        else:
            print(f"{VERMELHO}[!] Erro na API: {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de consulta excedido (15s){RESET}")
        return None
    except requests.exceptions.SSLError:
        print(f"{VERMELHO}[!] Erro de SSL mesmo com verificação ignorada{RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{VERMELHO}[!] Erro na requisição: {e}{RESET}")
        return None

def mostrar_resultados(dados):
    """Exibe todos os resultados detalhadamente"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    print(f"\n{CIANO}{NEGRITO}=== DADOS COMPLETOS ==={RESET}")
    
 
    categorias = {
        'Pessoal': ['nome', 'nome_completo', 'cpf', 'rg', 'data_nascimento', 'idade', 'mae', 'pai'],
        'Contato': ['telefone', 'celular', 'email'],
        'Endereço': ['endereco', 'numero', 'complemento', 'bairro', 'cidade', 'estado', 'cep'],
        'Outros': []
    }

    for categoria, campos in categorias.items():
        print(f"\n{VERDE}{NEGRITO}=== {categoria.upper()} ==={RESET}")
        encontrados = False
        
        for campo in campos:
            if campo in dados:
                print(f"{AZUL}{campo.upper():<20}:{RESET} {dados[campo]}")
                encontrados = True
        
     
        if categoria == 'Outros':
            for chave, valor in dados.items():
                if not any(chave in cat for cat in categorias.values()):
                    print(f"{AZUL}{chave.upper():<20}:{RESET} {valor}")
                    encontrados = True
        
        if not encontrados and categoria != 'Outros':
            print(f"{AMARELO}Nenhum dado desta categoria encontrado{RESET}")

def salvar_resultado(dados, formato='json'):
  
    if not dados:
        return False

    nome = dados.get('nome', dados.get('name', 'sem_nome')).replace(' ', '_')[:30]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"consulta_{nome}_{timestamp}.{formato}"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DA CONSULTA ===\n")
                f.write(f"DATA: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
                
                for chave, valor in dados.items():
                    f.write(f"{chave.upper():<20}: {valor}\n")

        print(f"{VERDE}[+] Arquivo salvo: {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

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
                
                if dados:
                    op = input(f"\n{CIANO}Salvar resultados? (S/N): {RESET}").lower()
                    if op.startswith('s'):
                        fmt = input(f"{CIANO}Formato (JSON/TXT): {RESET}").lower()
                        if fmt.startswith('j'):
                            salvar_resultado(dados, 'json')
                        else:
                            salvar_resultado(dados, 'txt')
                
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
