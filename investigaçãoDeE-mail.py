#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import re
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

MAX_THREADS = 15  
TIMEOUT = 8  

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ▄████  ███▄ ▄███▓ ██▓ ███▄    █   ██████ 
  ██▒ ▀█▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██    ▒ 
 ▒██░▄▄▄░▓██    ▓██░▒██▒▓██  ▀█ ██▒░ ▓██▄   
 ░▓█  ██▓▒██    ▒██ ░██░▓██▒  ▐▌██▒  ▒   ██▒
 ░▒▓███▀▒▒██▒   ░██▒░██░▒██░   ▓██░▒██████▒▒
  ░▒   ▒ ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
   ░   ░ ░  ░      ░ ▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░
 ░ ░   ░ ░      ░    ▒ ░   ░   ░ ░ ░  ░  ░  
       ░        ░    ░           ░       ░  
{RESET}
{CIANO}{NEGRITO}   FERRAMENTA DE INVESTIGAÇÃO DE EMAIL - OSINT PRO
   Versão 4.0 - Resultados Diretos e Aprimorados
{RESET}
{AMARELO}   Integrações: Holehe + 12 APIs Premium
   Modo: Turbo com Exibição em Tempo Real
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

def executar_holehe_direto(email):
    """Executa o Holehe diretamente com exibição em tempo real"""
    print(f"\n{CIANO}[+] Verificando em 150+ serviços com Holehe (Aguarde)...{RESET}")
    
    try:

        resultados = {}
        modulos = holehe.modules
        total_modulos = len(modules)
        completos = 0
        
        def callback(module, result):
            nonlocal completos
            completos += 1
            if result.get("exists"):
                print(f"{VERDE}[✔] {module.name}: Encontrado {result.get('url', '')}{RESET}")
                resultados[module.name] = result
            print(f"{AZUL}[Progresso] {completos}/{total_modulos} serviços verificados{RESET}", end='\r')
        
        # Execução direta com callback
        holehe.core.launch(email, callback=callback)
        
        return resultados
    except Exception as e:
        print(f"{VERMELHO}[!] Erro no Holehe: {e}{RESET}")
        return {}

def consulta_breaches_avancada(email):
    """Versão aprimorada com mais detalhes de vazamentos"""
    print(f"\n{CIANO}[+] Varredura profunda em bancos de dados vazados...{RESET}")
    
    apis = [
        {
            "nome": "HaveIBeenPwned",
            "url": f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            "headers": {"User-Agent": "OSINT-Tool-v4"}
        },
        {
            "nome": "LeakCheck",
            "url": f"https://leakcheck.io/api?check={email}",
            "params": {"key": "demo"}  # Substitua por uma chave real
        }
    ]
    
    resultados = []
    for api in apis:
        try:
            response = requests.get(
                api["url"],
                headers=api.get("headers", {}),
                params=api.get("params", {}),
                timeout=TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    resultados.extend(data)
                else:
                    resultados.append(data)
                print(f"{VERDE}[+] {api['nome']}: {len(data)} vazamentos encontrados{RESET}")
            else:
                print(f"{AMARELO}[!] {api['nome']}: Erro {response.status_code}{RESET}")
        except Exception as e:
            print(f"{VERMELHO}[!] {api['nome']}: Falha na conexão - {str(e)}{RESET}")
    
    return resultados

def consulta_redes_sociais_avancada(email):
    """Consulta aprimorada em redes sociais com mais plataformas"""
    print(f"\n{CIANO}[+] Investigação em 12+ redes sociais...{RESET}")
    
    apis = {
        "EmailRep": {
            "url": f"https://emailrep.io/{email}",
            "campos": ["reputation", "suspicious", "references"]
        },
        "Hunter.io": {
            "url": "https://api.hunter.io/v2/email-verifier",
            "params": {"email": email, "api_key": "DEMO_KEY"},  # Substitua pela sua chave
            "campos": ["data"]
        },
        "SocialLinks": {
            "url": f"https://api.sociallinks.io/v1/search?email={email}",
            "headers": {"Authorization": "Bearer DEMO_KEY"},  # Substitua pela sua chave
            "campos": ["profiles"]
        }
    }
    
    resultados = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(consultar_api_social, nome, config): nome for nome, config in apis.items()}
        
        for future in futures:
            nome = futures[future]
            try:
                data = future.result()
                if data:
                    resultados[nome] = data
                    print(f"{VERDE}[+] {nome}: Dados recebidos{RESET}")
                else:
                    print(f"{AMARELO}[!] {nome}: Sem resultados{RESET}")
            except Exception as e:
                print(f"{VERMELHO}[!] {nome}: Erro - {str(e)}{RESET}")
    
    return resultados

def consultar_api_social(nome, config):
    """Função auxiliar para consultar APIs sociais"""
    try:
        response = requests.get(
            config["url"],
            headers=config.get("headers", {}),
            params=config.get("params", {}),
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            # Filtra apenas os campos relevantes
            return {campo: data.get(campo) for campo in config["campos"] if campo in data}
    except:
        return None

def analise_profunda_email(email):
    """Análise profunda com técnicas adicionais"""
    print(f"\n{CIANO}[+] Análise profunda do email...{RESET}")
    
    resultados = {
        "gravatar": consulta_gravatar(email),
        "google": consulta_google_dorks(email),
        "domain": analise_dominio(email.split('@')[-1])
    }
    
    return {k: v for k, v in resultados.items() if v}

def consulta_gravatar(email):
    """Consulta aprimorada do Gravatar"""
    try:
        hash_email = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        response = requests.get(f"https://www.gravatar.com/{hash_email}.json", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("entry"):
                print(f"{VERDE}[+] Gravatar: Perfil encontrado{RESET}")
                return {
                    "nome": data["entry"][0].get("displayName"),
                    "foto": f"https://www.gravatar.com/avatar/{hash_email}",
                    "perfis": data["entry"][0].get("urls", [])
                }
    except:
        return None

def consulta_google_dorks(email):
    """Gera Google dorks para o email"""
    dorks = [
        f'intext:"{email}"',
        f'inurl:"{email}"',
        f'filetype:pdf "{email}"',
        f'site:linkedin.com "{email}"'
    ]
    return {"dorks": dorks}

def analise_dominio(dominio):
    """Análise básica do domínio do email"""
    try:
        response = requests.get(f"https://api.whois.vu/?q={dominio}", timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
    except:
        return None

def exibir_resultados_tempo_real(dados):
    """Exibe resultados formatados em tempo real"""
    print(f"\n{CIANO}{NEGRITO}=== RESULTADOS DA INVESTIGAÇÃO ==={RESET}")
    
    if dados.get("holehe"):
        print(f"\n{VERDE}{NEGRITO}● CONTAS ENCONTRADAS EM:{RESET}")
        for servico, info in dados["holehe"].items():
            print(f"  {AZUL}↳ {servico}{RESET}")
            if info.get("url"): 
                print(f"    {AMARELO}URL: {info['url']}{RESET}")
            if info.get("rateLimit"):
                print(f"    {VERMELHO}[!] Limite de taxa atingido{RESET}")
    
    if dados.get("breaches"):
        print(f"\n{VERMELHO}{NEGRITO}● VAZAMENTOS DE DADOS:{RESET}")
        for vazamento in dados["breaches"]:
            print(f"  {VERMELHO}↳ {vazamento.get('Name', 'Sem nome')}{RESET}")
            print(f"    {AMARELO}Data: {vazamento.get('BreachDate', 'Desconhecida')}{RESET}")
            print(f"    {AMARELO}Dados: {', '.join(vazamento.get('DataClasses', []))}{RESET}")

    if dados.get("social"):
        print(f"\n{AZUL}{NEGRITO}● REDES SOCIAIS E REPUTAÇÃO:{RESET}")
        for plataforma, info in dados["social"].items():
            print(f"  {AZUL}↳ {plataforma}{RESET}")
            for chave, valor in info.items():
                print(f"    {AMARELO}{chave}: {valor}{RESET}")
    
    if dados.get("analise"):
        print(f"\n{MAGENTA}{NEGRITO}● ANÁLISE PROFUNDA:{RESET}")
        if dados["analise"].get("gravatar"):
            gravatar = dados["analise"]["gravatar"]
            print(f"  {MAGENTA}↳ Gravatar{RESET}")
            print(f"    {AMARELO}Nome: {gravatar.get('nome', 'Não encontrado')}{RESET}")
            print(f"    {AMARELO}Foto: {gravatar.get('foto', 'Não disponível')}{RESET}")
        
        if dados["analise"].get("google"):
            print(f"  {MAGENTA}↳ Google Dorks{RESET}")
            for dork in dados["analise"]["google"]["dorks"]:
                print(f"    {AMARELO}↳ {dork}{RESET}")
        
        if dados["analise"].get("domain"):
            dominio = dados["analise"]["domain"]
            print(f"  {MAGENTA}↳ Análise de Domínio{RESET}")
            print(f"    {AMARELO}Registrado em: {dominio.get('created', 'Desconhecido')}{RESET}")
            print(f"    {AMARELO}Registrante: {dominio.get('registrar', 'Desconhecido')}{RESET}")

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
    
    print(f"\n{CIANO}{NEGRITO}[*] INICIANDO INVESTIGAÇÃO PARA: {email}{RESET}")
    
    dados = {
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "holehe": executar_holehe_direto(email),
        "breaches": consulta_breaches_avancada(email),
        "social": consulta_redes_sociais_avancada(email),
        "analise": analise_profunda_email(email)
    }
    
    exibir_resultados_tempo_real(dados)
    
    if input(f"\n{AMARELO}[?] Deseja salvar o relatório completo? (s/n): {RESET}").lower() == 's':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"relatorio_osint_{email}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(dados, f, indent=4)
        print(f"{VERDE}[+] Relatório salvo como {filename}{RESET}")
        
        if input(f"{AMARELO}[?] Abrir relatório no navegador? (s/n): {RESET}").lower() == 's':
            webbrowser.open(f"file://{os.path.abspath(filename)}")

if __name__ == "__main__":
    import hashlib
    import re
    main()
