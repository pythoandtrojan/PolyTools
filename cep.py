#!/usr/bin/env python3

import requests
import re
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

API_URL = "https://brasilapi.com.br/api/cep/v1/"

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ____ ____ ____  
   | __|  __|  __| 
   |__||____|____| 
{RESET}
{CIANO}{NEGRITO}   CONSULTA CEP - BRASIL API
   Versão 2.0 - Terminal Avançado
{RESET}
{AMARELO}   API: brasilapi.com.br
   Dados: Correios e IBGE
{RESET}""")

def validar_cep(cep):
    """Valida o formato do CEP"""
    padrao = r'^\d{5}-?\d{3}$'
    return re.match(padrao, cep) is not None

def formatar_cep(cep):
    """Formata o CEP para o padrão 00000-000"""
    cep = re.sub(r'[^0-9]', '', cep)
    return f"{cep[:5]}-{cep[5:]}" if len(cep) == 8 else cep

def consultar_api(cep):
    """Consulta a BrasilAPI para obter dados do CEP"""
    try:
        response = requests.get(f"{API_URL}{cep}", timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"{VERMELHO}[!] CEP não encontrado{RESET}")
        else:
            print(f"{VERMELHO}[!] Erro na API: HTTP {response.status_code}{RESET}")
        
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro de conexão: {e}{RESET}")
        return None

def mostrar_resultados(dados):
    """Exibe os resultados formatados e coloridos"""
    if not dados:
        return

    print(f"\n{CIANO}{NEGRITO}=== DADOS DO CEP ==={RESET}")
    print(f"{AZUL}CEP:{RESET} {dados.get('cep', 'N/A')}")
    print(f"{AZUL}Logradouro:{RESET} {dados.get('street', 'N/A')}")
    print(f"{AZUL}Bairro:{RESET} {dados.get('neighborhood', 'N/A')}")
    print(f"{AZUL}Cidade:{RESET} {dados.get('city', 'N/A')}")
    print(f"{AZUL}Estado:{RESET} {dados.get('state', 'N/A')}")
    print(f"{AZUL}Fonte:{RESET} {dados.get('service', 'N/A')}")

def salvar_resultado(dados, formato='json'):
    """Salva os resultados em arquivo"""
    if not dados:
        return False

    cep = re.sub(r'[^0-9]', '', dados.get('cep', 'sem_cep'))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cep_{cep}_{timestamp}.{formato}"

    try:
        with open(filename, 'w') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DO CEP {dados.get('cep', 'N/A')} ===\n\n")
                f.write(f"LOGRADOURO: {dados.get('street', 'N/A')}\n")
                f.write(f"BAIRRO:     {dados.get('neighborhood', 'N/A')}\n")
                f.write(f"CIDADE:     {dados.get('city', 'N/A')}\n")
                f.write(f"ESTADO:     {dados.get('state', 'N/A')}\n")
                f.write(f"FONTE:      {dados.get('service', 'N/A')}\n")

        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    """Exibe o menu principal"""
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} Consultar CEP")
    print(f"{VERDE}[2]{RESET} Sobre")
    print(f"{VERDE}[3]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def sobre():
    """Exibe informações sobre o programa"""
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE ESTA FERRAMENTA{RESET}

{AMARELO}Desenvolvido para:{RESET}
- Consultas rápidas de CEP no Terminal
- Dados precisos dos Correios e IBGE
- Uso em sistemas postais e logísticos

{AMARELO}Fonte dos dados:{RESET}
BrasilAPI (brasilapi.com.br)

{AMARELO}Características:{RESET}
- Consultas ilimitadas
- Dados oficiais e atualizados
- Interface otimizada para Termux

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    """Função principal do programa"""
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                cep = input(f"\n{CIANO}Digite o CEP (com ou sem hífen): {RESET}").strip()
                
                if not validar_cep(cep):
                    print(f"{VERMELHO}[!] CEP inválido. Formato esperado: 00000-000 ou 00000000{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                cep_formatado = formatar_cep(cep)
                print(f"\n{AMARELO}[*] Consultando CEP {cep_formatado}...{RESET}")
                
                dados = consultar_api(cep)
                
                if dados:
                    mostrar_resultados(dados)
                    
                    exportar = input(f"\n{CIANO}Exportar resultado? (JSON/TXT/Não): {RESET}").lower()
                    if exportar.startswith('j'):
                        salvar_resultado(dados, 'json')
                    elif exportar.startswith('t'):
                        salvar_resultado(dados, 'txt')
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                sobre()
            
            elif opcao == '3':
                print(f"\n{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida!{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    import json  
    main()
