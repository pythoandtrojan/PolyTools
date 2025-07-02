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
MAGENTA = Fore.MAGENTA
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# Configurações da API
API_URL = "https://777apisss.vercel.app/consulta/telefone2/"
API_KEY = "firminoh7778"

def banner():
    print(f"""
{CIANO}{NEGRITO}
   ██████╗ ██████╗ ███████╗██╗  ██╗██╗   ██╗
  ██╔═══██╗██╔══██╗██╔════╝██║  ██║╚██╗ ██╔╝
  ██║   ██║██████╔╝███████╗███████║ ╚████╔╝ 
  ██║   ██║██╔═══╝ ╚════██║██╔══██║  ╚██╔╝  
  ╚██████╔╝██║     ███████║██║  ██║   ██║   
   ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   
{RESET}
{VERDE}{NEGRITO}   CONSULTA POR TELEFONE - API AVANÇADA
{RESET}""")

def formatar_telefone(numero):
    """Formata o número de telefone para exibição"""
    if len(numero) == 11:
        return f"({numero[:2]}) {numero[2:7]}-{numero[7:]}"
    return numero

def consultar_api(telefone):
    """Faz a consulta à API de telefone"""
    query = urllib.parse.quote(telefone)
    url = f"{API_URL}?query={query}&apikey={API_KEY}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    print(f"\n{AMARELO}[*] Consultando telefone: {formatar_telefone(telefone)}{RESET}")
    
    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        print(f"{AZUL}[*] Status HTTP: {resposta.status_code}{RESET}")

        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                print(f"{VERDE}[+] Dados recebidos com sucesso!{RESET}")
                return dados
            except ValueError:
                print(f"{VERMELHO}[!] Resposta não é JSON válido{RESET}")
                print(f"{AZUL}[*] Conteúdo bruto:{RESET}\n{resposta.text[:500]}")
                return None
        else:
            print(f"{VERMELHO}[!] Erro na API: {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de espera esgotado (15s){RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{VERMELHO}[!] Erro na requisição: {e}{RESET}")
        return None

def mostrar_resultados(dados):
    """Mostra os resultados de forma organizada"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    print(f"\n{VERDE}{NEGRITO}=== DADOS ENCONTRADOS ==={RESET}")
    
    # Organiza os dados em categorias
    categorias = {
        'Telefone': ['numero', 'telefone', 'celular'],
        'Proprietário': ['nome', 'cpf', 'data_nascimento'],
        'Endereço': ['endereco', 'cidade', 'estado', 'cep'],
        'Operadora': ['operadora', 'tipo_linha'],
        'Outros': []
    }
    
    for categoria, campos in categorias.items():
        print(f"\n{CIANO}{NEGRITO}» {categoria.upper()}{RESET}")
        encontrou = False
        
        for campo in campos:
            if campo in dados and dados[campo]:
                print(f"{AZUL}  {campo.replace('_', ' ').title():<20}:{RESET} {dados[campo]}")
                encontrou = True
                
        # Mostra campos não categorizados
        if categoria == 'Outros':
            outros_dados = False
            for chave, valor in dados.items():
                if chave not in sum(categorias.values(), []) and valor:
                    print(f"{AZUL}  {chave.replace('_', ' ').title():<20}:{RESET} {valor}")
                    outros_dados = True
                    encontrou = True
            
            if not outros_dados:
                print(f"{AMARELO}  Nenhum outro dado disponível{RESET}")
        
        if not encontrou and categoria != 'Outros':
            print(f"{AMARELO}  Nenhum dado disponível{RESET}")

def main():
    banner()
    
    while True:
        telefone = input(f"\n{CIANO}Digite o telefone (com DDD, sem formatação) ou 'sair': {RESET}").strip()
        
        if telefone.lower() == 'sair':
            print(f"\n{VERDE}[+] Encerrando...{RESET}")
            break
            
        if not telefone.isdigit() or len(telefone) < 10:
            print(f"{VERMELHO}[!] Telefone inválido. Use apenas números com DDD (ex: 11987654321){RESET}")
            continue
            
        dados = consultar_api(telefone)
        mostrar_resultados(dados)

if __name__ == "__main__":
    main()
