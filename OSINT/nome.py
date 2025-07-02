#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
import os
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

# Configurações da API
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
{CIANO}{NEGRITO}   CONSULTA DE PESSOAS - API AVANÇADA
{RESET}""")

def consultar_api(nome):
    """Faz a consulta à API exatamente como no exemplo original"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        
        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                # Verifica se é uma lista de pessoas ou um único registro
                if isinstance(dados, list):
                    return dados[:10]  # Retorna no máximo 10 pessoas
                elif isinstance(dados, dict):
                    return [dados]  # Coloca em uma lista para padronizar
                return []
            except ValueError:
                print(f"{VERMELHO}[!] Resposta não é JSON válido{RESET}")
                return None
        else:
            print(f"{VERMELHO}[!] Erro HTTP {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de consulta excedido{RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{VERMELHO}[!] Erro na requisição: {e}{RESET}")
        return None

def formatar_dados(pessoa):
    """Organiza os dados de uma pessoa em categorias"""
    categorias = {
        'Identificação': ['nome', 'nome_completo', 'cpf', 'rg', 'data_nascimento'],
        'Filiação': ['mae', 'pai'],
        'Contato': ['telefone', 'celular', 'email'],
        'Endereço': ['endereco', 'logradouro', 'numero', 'complemento', 'bairro', 'cidade', 'estado', 'cep'],
        'Documentos': ['titulo_eleitor', 'pis', 'ctps'],
        'Outros': []  # Campos não categorizados
    }
    
    dados_formatados = {}
    for categoria, campos in categorias.items():
        dados_categoria = {}
        for campo in campos:
            if campo in pessoa:
                dados_categoria[campo] = pessoa[campo]
        if dados_categoria:
            dados_formatados[categoria] = dados_categoria
    
    # Adiciona campos não categorizados
    outros = {}
    for chave, valor in pessoa.items():
        if not any(chave in cat for cat in categorias.values()):
            outros[chave] = valor
    if outros:
        dados_formatados['Outros'] = outros
    
    return dados_formatados

def mostrar_pessoa(pessoa, numero):
    """Mostra os dados de uma pessoa de forma organizada"""
    dados = formatar_dados(pessoa)
    
    print(f"\n{CIANO}{NEGRITO}=== PESSOA {numero} ==={RESET}")
    
    for categoria, campos in dados.items():
        print(f"\n{VERDE}{NEGRITO}» {categoria.upper()}{RESET}")
        for chave, valor in campos.items():
            print(f"{AZUL}  {chave.replace('_', ' ').title():<20}:{RESET} {valor}")

def mostrar_resultados(pessoas):
    """Mostra até 10 pessoas com dados organizados"""
    if not pessoas:
        print(f"\n{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return
    
    print(f"\n{VERDE}{NEGRITO}=== RESULTADOS ENCONTRADOS ==={RESET}")
    print(f"{AMARELO}Total de registros: {len(pessoas)}{RESET}")
    
    for i, pessoa in enumerate(pessoas, 1):
        mostrar_pessoa(pessoa, i)
        if i >= 10:  # Limita a 10 pessoas
            break
    
    if len(pessoas) > 10:
        print(f"\n{AMARELO}[!] Mostrando apenas os primeiros 10 resultados de {len(pessoas)}{RESET}")

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
                
                pessoas = consultar_api(nome)
                mostrar_resultados(pessoas if pessoas else [])
                
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
