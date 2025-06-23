#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import requests
import holehe
import webbrowser
from datetime import datetime
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

# Configurações de cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# Limite de threads para consultas paralelas
MAX_THREADS = 10

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ██████╗ ███╗   ███╗ █████╗ ██╗██╗      ██████╗ ███████╗
  ██╔════╝ ████╗ ████║██╔══██╗██║██║     ██╔═══██╗██╔════╝
  ██║  ███╗██╔████╔██║███████║██║██║     ██║   ██║███████╗
  ██║   ██║██║╚██╔╝██║██╔══██║██║██║     ██║   ██║╚════██║
  ╚██████╔╝██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝███████║
   ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚══════╝
{RESET}
{CIANO}{NEGRITO}   FERRAMENTA DE INVESTIGAÇÃO DE GMAIL
   Versão 3.0 - Máximo de Dados Possíveis
{RESET}
{AMARELO}   Integrações: Holehe + APIs Externas
   Modo: Pesquisa Agressiva
{RESET}""")

def verificar_dependencias():
    try:
        import holehe
        import requests
    except ImportError:
        print(f"{VERMELHO}[!] Instalando dependências...{RESET}")
        os.system("pip install holehe requests colorama")
        print(f"{VERDE}[+] Dependências instaladas com sucesso!{RESET}")

def validar_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def consulta_holehe(email):
    print(f"\n{CIANO}[+] Verificando em 150+ serviços com Holehe...{RESET}")
    resultados = {}
    
    try:
        # Consulta agressiva com Holehe
        modulos = holehe.import_submodules("holehe.modules")
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for module in modules:
                futures.append(executor.submit(
                    modulos[module].check,
                    email
                ))
            
            for future in futures:
                try:
                    resultado = future.result()
                    if resultado.get("exists"):
                        resultados[resultado["name"]] = resultado
                except:
                    continue
        
        return resultados
    except Exception as e:
        print(f"{VERMELHO}[!] Erro no Holehe: {e}{RESET}")
        return {}

def consulta_breaches(email):
    print(f"{CIANO}[+] Verificando vazamentos de dados...{RESET}")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        return []
    except:
        return []

def consulta_social_media(email):
    apis = {
        "SocialSearcher": f"https://www.socialsearcher.com/api/v1/search/byemail/?q={email}&key=DEMO_KEY",
        "EmailRep": f"https://emailrep.io/{email}",
        "Hunter.io": f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=DEMO_KEY"
    }
    
    resultados = {}
    for nome, url in apis.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                resultados[nome] = response.json()
        except:
            continue
    
    return resultados

def consulta_gravatar(email):
    try:
        hash_email = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        response = requests.get(f"https://www.gravatar.com/{hash_email}.json")
        if response.status_code == 200:
            return response.json()
    except:
        return None

def gerar_relatorio(email, dados):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"relatorio_gmail_{email}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(dados, f, indent=4)
    
    print(f"\n{VERDE}[+] Relatório salvo em {filename}{RESET}")
    return filename

def mostrar_resultados(dados):
    # Resultados do Holehe
    if dados.get("holehe"):
        print(f"\n{CIANO}{NEGRITO}=== SERVIÇOS ENCONTRADOS ==={RESET}")
        for servico, info in dados["holehe"].items():
            print(f"{VERDE}+ {servico}{RESET}")
            if info.get("url"): print(f"   URL: {info['url']}")
    
    # Vazamentos de dados
    if dados.get("breaches"):
        print(f"\n{CIANO}{NEGRITO}=== VAZAMENTOS ENCONTRADOS ==={RESET}")
        for vazamento in dados["breaches"]:
            print(f"{VERMELHO}! {vazamento['Name']} ({vazamento['BreachDate']}){RESET}")
            print(f"   Dados vazados: {', '.join(vazamento['DataClasses'])}")
    
    # Mídias sociais
    if dados.get("social"):
        print(f"\n{CIANO}{NEGRITO}=== MÍDIAS SOCIAIS ==={RESET}")
        for plataforma, info in dados["social"].items():
            if info:
                print(f"{AZUL}* {plataforma}{RESET}")
                if plataforma == "EmailRep":
                    print(f"   Reputação: {info.get('reputation')}")
                    print(f"   Suspeito: {'Sim' if info.get('suspicious') else 'Não'}")
    
    # Gravatar
    if dados.get("gravatar"):
        print(f"\n{CIANO}{NEGRITO}=== PERFIL GRAVATAR ==={RESET}")
        gravatar = dados["gravatar"]
        if gravatar.get("entry"):
            perfil = gravatar["entry"][0]
            print(f"{AZUL}Nome: {perfil.get('displayName', 'N/A')}{RESET}")
            print(f"Foto: https://www.gravatar.com/{hashlib.md5(email.lower().encode('utf-8')).hexdigest()}")

def main():
    banner()
    verificar_dependencias()
    
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input(f"{AMARELO}[*] Digite o email alvo: {RESET}").strip()
    
    if not validar_email(email):
        print(f"{VERMELHO}[!] Email inválido!{RESET}")
        return
    
    print(f"\n{CIANO}[*] Iniciando investigação para {email}{RESET}")
    
    dados = {
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "holehe": consulta_holehe(email),
        "breaches": consulta_breaches(email),
        "social": consulta_social_media(email),
        "gravatar": consulta_gravatar(email)
    }
    
    mostrar_resultados(dados)
    relatorio = gerar_relatorio(email, dados)
    
    # Abre o relatório no navegador
    if input(f"\n{AMARELO}[?] Abrir relatório no navegador? (s/n): {RESET}").lower() == 's':
        webbrowser.open(f"file://{os.path.abspath(relatorio)}")

if __name__ == "__main__":
    import hashlib
    import re
    main()
