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

# Configurações da API DIRETA (ignorando intermediário com problema)
API_URL = "https://api.encrypt.wtf/new/api.php"
TOKEN = "ifindy"
BASE = "telefone2"  # Base específica para consulta por telefone

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
{VERDE}{NEGRITO}   CONSULTA POR TELEFONE - DIRETO NA FONTE
{RESET}""")

def formatar_telefone(numero):
    """Formata o número para exibição amigável"""
    if len(numero) == 11:
        return f"({numero[:2]}) {numero[2:7]}-{numero[7:]}"
    return numero

def consultar_direto(telefone):
    """Consulta DIRETAMENTE a API principal, ignorando SSL"""
    query = urllib.parse.quote(telefone)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    print(f"\n{AMARELO}[*] Consultando DIRETAMENTE a API...{RESET}")
    print(f"{AZUL}[*] URL: {url}{RESET}")

    try:
        resposta = requests.get(url, headers=headers, timeout=20, verify=False)
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
        print(f"{VERMELHO}[!] Tempo de espera esgotado (20s){RESET}")
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro inesperado: {str(e)}{RESET}")
        return None

def mostrar_resultados(dados):
    """Mostra todos os dados de forma organizada"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado para exibir{RESET}")
        return

    print(f"\n{VERDE}{NEGRITO}=== DADOS COMPLETOS ==={RESET}")
    
    # Categorias para melhor organização
    categorias = {
        'Telefone': ['numero', 'telefone', 'celular', 'ddd'],
        'Proprietário': ['nome', 'nome_completo', 'cpf', 'rg', 'data_nascimento'],
        'Endereço': ['endereco', 'logradouro', 'numero', 'bairro', 'cidade', 'estado', 'cep'],
        'Operadora': ['operadora', 'tipo_linha', 'porte'],
        'Documentos': ['titulo_eleitor', 'pis', 'ctps'],
        'Outros': []
    }

    for categoria, campos in categorias.items():
        print(f"\n{CIANO}{NEGRITO}» {categoria.upper()}{RESET}")
        dados_exibidos = False
        
        for campo in campos:
            if campo in dados and dados[campo]:
                print(f"{AZUL}  {campo.replace('_', ' ').title():<20}:{RESET} {dados[campo]}")
                dados_exibidos = True
        
        # Campos não categorizados
        if categoria == 'Outros':
            outros_dados = False
            for chave, valor in dados.items():
                if not any(chave in cat for cat in categorias.values()) and valor:
                    print(f"{AZUL}  {chave.replace('_', ' ').title():<20}:{RESET} {valor}")
                    outros_dados = True
                    dados_exibidos = True
            
            if not outros_dados:
                print(f"{AMARELO}  Nenhum outro dado disponível{RESET}")
        
        if not dados_exibidos and categoria != 'Outros':
            print(f"{AMARELO}  Nenhum dado nesta categoria{RESET}")

def main():
    banner()
    
    while True:
        telefone = input(f"\n{CIANO}Digite o telefone com DDD (ex: 11987654321) ou 'sair': {RESET}").strip()
        
        if telefone.lower() == 'sair':
            print(f"\n{VERDE}[+] Encerrando...{RESET}")
            break
            
        if not telefone.isdigit() or len(telefone) < 10 or len(telefone) > 11:
            print(f"{VERMELHO}[!] Formato inválido. Use 10 ou 11 dígitos (com DDD){RESET}")
            continue
            
        dados = consultar_direto(telefone)
        mostrar_resultados(dados)

if __name__ == "__main__":
    main()
