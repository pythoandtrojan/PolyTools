#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
from colorama import Fore, Style, init

# Configurações iniciais
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
CIANO = Fore.CYAN
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# Configurações da API
API_URL = "https://api.encrypt.wtf/new/api.php"
TOKEN = "ifindy"
BASE = "nome_completo2"

def banner():
    print(f"""
{VERDE}{NEGRITO}
   ███╗   ██╗ ██████╗ ███╗   ███╗███████╗
   ████╗  ██║██╔═══██╗████╗ ████║██╔════╝
   ██╔██╗ ██║██║   ██║██╔████╔██║█████╗  
   ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  
   ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗
   ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
{RESET}
{CIANO}{NEGRITO}   CONSULTA DE PESSOAS - DADOS COMPLETOS
{RESET}""")

def consultar_api(nome):
    """Faz a consulta à API de forma segura"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    try:
        resposta = requests.get(url, headers=headers, timeout=20, verify=False)
        
        if resposta.status_code == 200:
            try:
                return resposta.json()
            except ValueError:
                print(f"{VERMELHO}[!] Resposta não é JSON válido{RESET}")
                print(f"Conteúdo bruto: {resposta.text[:200]}...")
                return None
        else:
            print(f"{VERMELHO}[!] Erro HTTP {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de consulta excedido{RESET}")
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro na requisição: {str(e)}{RESET}")
        return None

def mostrar_dados_organizados(dados):
    """Mostra TODOS os dados de forma organizada e categorizada"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado para exibir{RESET}")
        return

    # Se for uma lista de pessoas, mostra uma por uma
    if isinstance(dados, list):
        for i, pessoa in enumerate(dados, 1):
            print(f"\n{CIANO}{NEGRITO}=== PESSOA {i} ==={RESET}")
            mostrar_pessoa_organizada(pessoa)
            print("-"*50)
    else:
        mostrar_pessoa_organizada(dados)

def mostrar_pessoa_organizada(pessoa):
    """Organiza e exibe os dados de uma pessoa"""
    if not isinstance(pessoa, dict):
        print(f"{VERMELHO}[!] Dados inválidos{RESET}")
        return

    # Categorias para organização
    categorias = {
        'Identificação': ['nome', 'nome_completo', 'cpf', 'rg', 'data_nascimento', 'idade', 'sexo'],
        'Filiação': ['mae', 'pai'],
        'Contato': ['telefone', 'celular', 'email'],
        'Endereço': ['endereco', 'logradouro', 'numero', 'complemento', 'bairro', 'cidade', 'estado', 'cep'],
        'Documentos': ['titulo_eleitor', 'pis', 'ctps', 'cnh'],
        'Outros': []  # Campos não categorizados
    }

    # Processa cada categoria
    for categoria, campos in categorias.items():
        print(f"\n{VERDE}{NEGRITO}» {categoria.upper()}{RESET}")
        dados_exibidos = False
        
        for campo in campos:
            if campo in pessoa and pessoa[campo]:
                print(f"{AZUL}  {campo.replace('_', ' ').title():<20}:{RESET} {pessoa[campo]}")
                dados_exibidos = True
        
        # Mostra campos não categorizados
        if categoria == 'Outros':
            outros_dados = False
            for chave, valor in pessoa.items():
                if chave not in sum(categorias.values(), []) and valor:
                    print(f"{AZUL}  {chave.replace('_', ' ').title():<20}:{RESET} {valor}")
                    outros_dados = True
                    dados_exibidos = True
            
            if not outros_dados:
                print(f"{AMARELO}  Nenhum outro dado disponível{RESET}")
                dados_exibidos = True
        
        if not dados_exibidos:
            print(f"{AMARELO}  Nenhum dado disponível{RESET}")

def main():
    banner()
    
    while True:
        nome = input(f"\n{CIANO}Digite o nome completo (ou 'sair' para encerrar): {RESET}").strip()
        
        if nome.lower() == 'sair':
            print(f"\n{VERDE}[+] Encerrando...{RESET}")
            break
            
        if len(nome.split()) < 2:
            print(f"{VERMELHO}[!] Digite um nome completo válido{RESET}")
            continue
            
        dados = consultar_api(nome)
        
        if dados:
            print(f"\n{VERDE}{NEGRITO}=== RESULTADOS ENCONTRADOS ==={RESET}")
            mostrar_dados_organizados(dados)
        else:
            print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")

if __name__ == "__main__":
    main()
