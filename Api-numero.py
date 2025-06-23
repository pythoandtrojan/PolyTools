#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import re
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Configurações
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
CIANO = Fore.CYAN
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# APIs atualizadas
APIS = {
    "BrasilAPI (DDD)": {
        "url": "https://brasilapi.com.br/api/ddd/v1/{ddd}",
        "campos": {
            "estado": "state",
            "cidades": "cities"
        },
        "method": "GET"
    },
    "Intelbrás WebFone": {
        "url": "https://webfone.intelbras.com.br/consultanumero?numero=55{numero}",
        "campos": {
            "operadora": "operadora",
            "cidade": "cidade",
            "uf": "uf"
        },
        "headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        },
        "method": "GET",
        "timeout": 5
    }
}

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
{VERDE}{NEGRITO}   CONSULTA DE TELEFONE - VERSÃO 3.0
   APIs: BrasilAPI (DDD) + Intelbrás WebFone
{RESET}""")

def validar_numero(numero):
    """Valida e limpa o número"""
    numero = re.sub(r'[^0-9]', '', numero)
    return (len(numero) in [10, 11], numero[:2], numero

def consultar_api(nome_api, params):
    """Faz a requisição à API"""
    config = APIS[nome_api]
    try:
        url = config["url"].format(**params)
        kwargs = {
            "headers": config.get("headers", {}),
            "timeout": config.get("timeout", 3)
        }
        
        if config["method"] == "GET":
            response = requests.get(url, **kwargs)
        else:
            response = requests.post(url, **kwargs)
            
        if response.status_code == 200:
            return response.json()
        else:
            print(f"{VERMELHO}[!] {nome_api} - Status: {response.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{AMARELO}[!] {nome_api} - Timeout{RESET}")
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] {nome_api} - Erro: {str(e)}{RESET}")
        return None

def processar_dados(api_name, dados):
    """Processa a resposta da API"""
    if not dados:
        return None
        
    campos = APIS[api_name]["campos"]
    resultado = {}
    
    for campo, caminho in campos.items():
        try:
            valor = dados
            for parte in caminho.split('.'):
                valor = valor.get(parte, {})
                
            if valor:
                resultado[campo] = valor
        except:
            continue
            
    return resultado if resultado else None

def main():
    banner()
    
    while True:
        entrada = input(f"\n{AMARELO}Digite o número (DDD + número) ou 'sair': {RESET}").strip()
        
        if entrada.lower() == 'sair':
            break
            
        valido, ddd, numero = validar_numero(entrada)
        if not valido:
            print(f"{VERMELHO}[!] Número inválido. Formato esperado: DDD + 8 ou 9 dígitos{RESET}")
            continue
            
        consolidado = {}
        print(f"\n{VERDE}[*] Consultando APIs para DDD {ddd}...{RESET}")
        
        # Consulta BrasilAPI (DDD)
        params = {"ddd": ddd}
        dados = consultar_api("BrasilAPI (DDD)", params)
        if dados:
            processado = processar_dados("BrasilAPI (DDD)", dados)
            if processado:
                consolidado.update(processado)
                print(f"{AZUL}[+] BrasilAPI: Dados de DDD obtidos{RESET}")
        
        # Consulta Intelbrás (número completo)
        params = {"numero": numero}
        dados = consultar_api("Intelbrás WebFone", params)
        if dados:
            processado = processar_dados("Intelbrás WebFone", dados)
            if processado:
                consolidado.update(processado)
                print(f"{AZUL}[+] Intelbrás: Dados de operadora obtidos{RESET}")
        
        # Exibe resultados
        if consolidado:
            print(f"\n{CIANO}{NEGRITO}=== RESULTADOS ==={RESET}")
            for chave, valor in consolidado.items():
                print(f"{AMARELO}{chave.title()}:{RESET} {valor}")
            
            if input(f"\n{AMARELO}Salvar resultados? (s/n): {RESET}").lower() == 's':
                filename = f"tel_{numero}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(consolidado, f, indent=2)
                print(f"{VERDE}[+] Salvo em {filename}{RESET}")
        else:
            print(f"{VERMELHO}[!] Nenhum dado obtido das APIs{RESET}")

if __name__ == "__main__":
    main()
