#!/usr/bin/env python3

import requests
import json
import re
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
CIANO = Fore.CYAN
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

APIS = {
    "Intelbrás WebFone": {
        "url": "https://webfone.intelbras.com.br/consultanumero?numero=55{numero}",
        "campos": {
            "operadora": "operadora",
            "cidade": "cidade",
            "uf": "uf",
            "tipo": "tipo"
        }
    },
    "Twilio Lookup (Demo)": {
        "url": "https://lookups.twilio.com/v1/PhoneNumbers/+55{numero}",
        "auth": ("ACXXXXXXXXXXXXXXXX", "your_auth_token"),  # Substitua por credenciais demo
        "campos": {
            "operadora": "carrier.name",
            "tipo": "carrier.type",
            "país": "country_code"
        }
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
{VERDE}{NEGRITO}   CONSULTA AVANÇADA DE TELEFONE
   Versão 2.0 - Dados Combinados
{RESET}
{AMARELO}   APIs: Intelbrás + Twilio (demo)
   Limites: Gratuitos com restrições
{RESET}""")

def validar_numero(numero):
    """Remove formatação e valida DDD"""
    numero = re.sub(r'[^0-9]', '', numero)
    return len(numero) in [10, 11]  # Com ou sem 9º dígito

def consultar_api(nome_api, numero):
    """Consulta uma API específica"""
    config = APIS[nome_api]
    try:
        url = config["url"].format(numero=numero)
        auth = config.get("auth")
        
        response = requests.get(
            url,
            auth=auth if auth else None,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"{VERMELHO}[!] {nome_api}: Erro {response.status_code}{RESET}")
            return None
            
    except Exception as e:
        print(f"{VERMELHO}[!] {nome_api}: Falha na conexão{RESET}")
        return None

def extrair_dados(api_name, dados):
    """Extrai campos relevantes da resposta"""
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
    
    return resultado

def mostrar_resultado(consolidado):
    """Exibe os dados consolidados"""
    print(f"\n{CIANO}{NEGRITO}=== DADOS CONSOLIDADOS ==={RESET}")
    
    categorias = {
        "Localização": ["cidade", "uf", "país"],
        "Operadora": ["operadora", "tipo"],
    }
    
    for categoria, campos in categorias.items():
        print(f"\n{AZUL}{NEGRITO}[ {categoria.upper()} ]{RESET}")
        for campo in campos:
            if campo in consolidado:
                print(f"{AMARELO}{campo.capitalize()}:{RESET} {consolidado[campo]}")

def salvar_resultado(dados, numero):
    """Salva em JSON"""
    filename = f"telefone_{numero}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)
    print(f"{VERDE}[+] Dados salvos em {filename}{RESET}")

def main():
    banner()
    
    while True:
        numero = input(f"\n{AMARELO}Digite o número (DDD + número): {RESET}").strip()
        
        if not validar_numero(numero):
            print(f"{VERMELHO}[!] Número inválido. Use DDD + 8 ou 9 dígitos{RESET}")
            continue
        
        numero_limpo = re.sub(r'[^0-9]', '', numero)
        consolidado = {}
        
        print(f"\n{VERDE}[*] Consultando APIs...{RESET}")
        
        for api_name in APIS:
            print(f"{AZUL}[>] {api_name}{RESET}", end=' ', flush=True)
            dados = consultar_api(api_name, numero_limpo)
            
            if dados:
                extraidos = extrair_dados(api_name, dados)
                consolidado.update(extraidos)
                print(f"{VERDE}✓{RESET}")
            else:
                print(f"{VERMELHO}✗{RESET}")
        
        if consolidado:
            mostrar_resultado(consolidado)
            if input(f"\n{AMARELO}Salvar resultados? (s/n): {RESET}").lower() == 's':
                salvar_resultado(consolidado, numero_limpo)
        else:
            print(f"{VERMELHO}[!] Nenhum dado obtido{RESET}")
        
        if input(f"\n{AMARELO}Nova consulta? (s/n): {RESET}").lower() != 's':
            break

if __name__ == "__main__":
    main()
