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
{CIANO}{NEGRITO}   CONSULTA POR NOME - API
{RESET}""")

def consultar_api(nome):
    """Consulta a API exatamente como no primeiro script"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    print(f"{AMARELO}[*] Consultando API para: {nome}{RESET}")

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        
        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                # Verifica se a resposta contém a estrutura esperada
                if isinstance(dados, dict) and 'DADOSCPF' in dados:
                    return [dados]  # Retorna como lista de 1 item para padronização
                elif isinstance(dados, list):
                    return dados[:10]  # Limita a 10 resultados
                return [dados] if dados else []
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

def mostrar_resultados(resultados):
    """Exibe os resultados de forma organizada"""
    if not resultados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    print(f"\n{VERDE}{NEGRITO}=== RESULTADOS ENCONTRADOS ==={RESET}")
    print(f"{AMARELO}Total de registros: {len(resultados)}{RESET}\n")

    for i, pessoa in enumerate(resultados, 1):
        print(f"{CIANO}{NEGRITO}--- Pessoa {i} ---{RESET}")
        
        # Dados básicos
        dados_cpf = pessoa.get('DADOSCPF', {})
        print(f"{AZUL}Nome:{RESET} {VERDE}{dados_cpf.get('NOME', 'N/A')}{RESET}")
        print(f"{AZUL}CPF:{RESET} {dados_cpf.get('CPF', 'N/A')}")
        print(f"{AZUL}Nascimento:{RESET} {dados_cpf.get('NASC', 'N/A')}")
        print(f"{AZUL}Mãe:{RESET} {dados_cpf.get('NOME_MAE', 'N/A')}")
        print(f"{AZUL}Pai:{RESET} {dados_cpf.get('NOME_PAI', 'N/A')}")
        
        # Endereços
        enderecos = pessoa.get('DROP', [])
        if enderecos:
            print(f"\n{AZUL}Endereços:{RESET}")
            for end in enderecos:
                print(f"  {end.get('LOGR_TIPO', '')} {end.get('LOGR_NOME', '')}, {end.get('LOGR_NUMERO', '')}")
                print(f"  {end.get('BAIRRO', '')} - {end.get('CIDADE', '')}/{end.get('UF', '')}")
                print(f"  CEP: {end.get('CEP', '')}\n")
        
        # Telefones (se houver estrutura separada)
        telefones = pessoa.get('TELEFONE', {})
        if telefones and isinstance(telefones, dict):
            print(f"{AZUL}Telefone:{RESET} {telefones.get('NUMERO', 'N/A')}")
        
        print("\n" + "-"*50 + "\n")

def salvar_resultado(resultados, formato='json'):
    """Salva os resultados em arquivo"""
    if not resultados:
        return False

    nome = resultados[0].get('DADOSCPF', {}).get('NOME', 'consulta').replace(' ', '_')[:30]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"consulta_{nome}_{timestamp}.{formato}"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if formato == 'json':
                json.dump(resultados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== RESULTADOS DA CONSULTA ===\n")
                f.write(f"DATA: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write(f"TERMO BUSCADO: {nome}\n")
                f.write(f"TOTAL DE REGISTROS: {len(resultados)}\n\n")
                
                for i, pessoa in enumerate(resultados, 1):
                    dados_cpf = pessoa.get('DADOSCPF', {})
                    f.write(f"\n--- Pessoa {i} ---\n")
                    f.write(f"Nome: {dados_cpf.get('NOME', 'N/A')}\n")
                    f.write(f"CPF: {dados_cpf.get('CPF', 'N/A')}\n")
                    f.write(f"Nascimento: {dados_cpf.get('NASC', 'N/A')}\n")
                    f.write(f"Mãe: {dados_cpf.get('NOME_MAE', 'N/A')}\n")
                    f.write(f"Pai: {dados_cpf.get('NOME_PAI', 'N/A')}\n")
                    
                    enderecos = pessoa.get('DROP', [])
                    if enderecos:
                        f.write("\nEndereços:\n")
                        for end in enderecos:
                            f.write(f"  {end.get('LOGR_TIPO', '')} {end.get('LOGR_NOME', '')}, {end.get('LOGR_NUMERO', '')}\n")
                            f.write(f"  {end.get('BAIRRO', '')} - {end.get('CIDADE', '')}/{end.get('UF', '')}\n")
                            f.write(f"  CEP: {end.get('CEP', '')}\n\n")

        print(f"{VERDE}[+] Arquivo salvo: {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

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
                
                resultados = consultar_api(nome)
                mostrar_resultados(resultados)
                
                if resultados:
                    op = input(f"\n{CIANO}Salvar resultados? (S/N): {RESET}").lower()
                    if op.startswith('s'):
                        fmt = input(f"{CIANO}Formato (JSON/TXT): {RESET}").lower()
                        if fmt.startswith('j'):
                            salvar_resultado(resultados, 'json')
                        else:
                            salvar_resultado(resultados, 'txt')
                
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
