#!/usr/bin/env python3

import os
import sys
import json
import asyncio
from datetime import datetime
from colorama import Fore, Style, init

# Configurações iniciais
init(autoreset=True)

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

try:
    import holehe
except ImportError:
    print(f"{VERMELHO}[!] holehe não está instalado. Instalando...{RESET}")
    os.system("pip install holehe")
    import holehe

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
██╗  ██╗ ██████╗ ██╗     ███████╗██╗  ██╗███████╗
██║  ██║██╔═══██╗██║     ██╔════╝██║  ██║██╔════╝
███████║██║   ██║██║     █████╗  ███████║█████╗  
██╔══██║██║   ██║██║     ██╔══╝  ██╔══██║██╔══╝  
██║  ██║╚██████╔╝███████╗███████╗██║  ██║███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
{RESET}
{CIANO}{NEGRITO}   EMAIL OSINT - HOLEHE TURBO+
{RESET}""")

def validar_email(email):
    """Valida se o email tem formato válido"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

async def consultar_holehe(email):
    """Executa a consulta holehe para um email"""
    if not validar_email(email):
        return None, "Email inválido"
    
    print(f"{AMARELO}Consultando email {email}... ⏳{RESET}")
    
    try:
        # Executa a consulta holehe
        resultados = []
        sites_verificados = 0
        
        for site in holehe.modules:
            try:
                mod = getattr(holehe, site)
                out = await mod(email)
                resultados.append(out)
                sites_verificados += 1
                
                if out['exists']:
                    print(f"{VERDE}[+] {site}: ENCONTRADO{RESET}")
                else:
                    print(f"{VERMELHO}[-] {site}: não encontrado{RESET}")
                    
            except Exception as e:
                continue
        
        return resultados, f"Verificação concluída ({sites_verificados} sites)"
        
    except Exception as e:
        return None, f"Erro na consulta: {str(e)}"

def mostrar_resultados(resultados, email):
    """Exibe os resultados da consulta holehe"""
    if not resultados:
        print(f"{VERMELHO}[!] Nenhum resultado encontrado{RESET}")
        return
    
    print(f"\n{VERDE}{NEGRITO}=== RESULTADOS PARA {email.upper()} ===")
    
    encontrados = []
    nao_encontrados = []
    
    for resultado in resultados:
        if resultado['exists']:
            encontrados.append({
                'site': resultado['name'],
                'url': resultado['domain'],
                'categoria': resultado.get('category', 'N/A')
            })
        else:
            nao_encontrados.append(resultado['name'])
    
    print(f"\n{CIANO}{NEGRITO}CONTAS ENCONTRADAS ({len(encontrados)}):{RESET}")
    for conta in encontrados:
        print(f"{VERDE}✓ {conta['site']} ({conta['categoria']})")
        print(f"  {AZUL}URL: {conta['url']}{RESET}")
    
    print(f"\n{AMARELO}{NEGRITO}NÃO ENCONTRADOS ({len(nao_encontrados)} sites):{RESET}")
    if nao_encontrados:
        print(f"{AMARELO}{', '.join(nao_encontrados[:10])}{RESET}")
        if len(nao_encontrados) > 10:
            print(f"{AMARELO}... e mais {len(nao_encontrados) - 10} sites{RESET}")

def salvar_resultados(resultados, email):
    """Salva os resultados em arquivo JSON"""
    if not resultados:
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"holehe_{email.replace('@', '_at_')}_{timestamp}.json"
    
    try:
        # Preparar dados para salvar
        dados_salvar = {
            'email': email,
            'data_consulta': datetime.now().isoformat(),
            'resultados': resultados
        }
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            json.dump(dados_salvar, f, indent=4, ensure_ascii=False)
        
        print(f"{VERDE}[+] Resultados salvos em: {nome_arquivo}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar arquivo: {e}{RESET}")
        return False

def log_consulta(email, status):
    """Registra a consulta em arquivo de log"""
    with open("holehe_consultas.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] - {email} | Status: {status}\n")

def mostrar_log():
    
    if os.path.exists("holehe_consultas.log"):
        with open("holehe_consultas.log", "r", encoding="utf-8") as f:
            print(f"\n{VERDE}{NEGRITO}=== LOG DE CONSULTAS HOLEHE ===")
            print(f.read())
    else:
        print(f"{VERMELHO}[!] Nenhum log encontrado{RESET}")

async def main():
    
    try:
        
        if len(sys.argv) > 1:
            email = sys.argv[1]
            if not validar_email(email):
                print(f"{VERMELHO}[!] Email inválido: {email}{RESET}")
                sys.exit(1)
            
            banner()
            resultados, status = await consultar_holehe(email)
            
            if resultados:
                mostrar_resultados(resultados, email)
                salvar_resultados(resultados, email)
            else:
                print(f"{VERMELHO}[!] {status}{RESET}")
            
            log_consulta(email, status)
            sys.exit(0)
        
        # Modo interativo
        while True:
            banner()
            print(f"\n{AMARELO}{NEGRITO}MENU HOLEHE{RESET}")
            print(f"{VERDE}[1]{RESET} Consultar email")
            print(f"{VERDE}[2]{RESET} Ver log de consultas")
            print(f"{VERDE}[3]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                email = input(f"\n{CIANO}Digite o email para consulta: {RESET}").strip().lower()
                
                if not validar_email(email):
                    print(f"{VERMELHO}[!] Email inválido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                resultados, status = await consultar_holehe(email)
                
                if resultados:
                    mostrar_resultados(resultados, email)
                    
                    # Perguntar se deseja salvar
                    salvar = input(f"\n{CIANO}Deseja salvar o resultado? (s/N): {RESET}").strip().lower()
                    if salvar in ['s', 'sim', 'y', 'yes']:
                        salvar_resultados(resultados, email)
                else:
                    print(f"{VERMELHO}[!] {status}{RESET}")
                
                log_consulta(email, status)
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                banner()
                mostrar_log()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':
                print(f"\n{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        sys.exit()

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())
