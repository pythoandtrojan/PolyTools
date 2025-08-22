#!/usr/bin/env python3

import os
import sys
import json
import asyncio
import re
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
    from holehe import modules
except ImportError:
    print(f"{VERMELHO}[!] holehe não está instalado. Instalando...{RESET}")
    os.system("pip install holehe")
    import holehe
    from holehe import modules

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
        
        for site in modules:
            try:
                # Importar o módulo dinamicamente
                module = getattr(holehe, site)
                # Executar a função assíncrona
                out = await module(email)
                
                # Adicionar nome do site se não estiver presente
                if 'name' not in out:
                    out['name'] = site
                    
                resultados.append(out)
                sites_verificados += 1
                
                if out['exists']:
                    print(f"{VERDE}[+] {site}: ENCONTRADO{RESET}")
                else:
                    print(f"{VERMELHO}[-] {site}: não encontrado{RESET}")
                    
            except Exception as e:
                # Ignorar erros em módulos específicos e continuar
                print(f"{AMARELO}[!] Erro em {site}: {str(e)[:50]}...{RESET}")
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
        site_name = resultado.get('name', 'Desconhecido')
        if resultado.get('exists', False):
            encontrados.append({
                'site': site_name,
                'url': resultado.get('domain', 'N/A'),
                'categoria': resultado.get('category', 'N/A'),
                'email_recovery': resultado.get('emailrecovery', 'N/A'),
                'phone_number': resultado.get('phoneNumber', 'N/A')
            })
        else:
            nao_encontrados.append(site_name)
    
    print(f"\n{CIANO}{NEGRITO}CONTAS ENCONTRADAS ({len(encontrados)}):{RESET}")
    for conta in encontrados:
        print(f"{VERDE}✓ {conta['site']} ({conta['categoria']})")
        print(f"  {AZUL}URL: {conta['url']}{RESET}")
        if conta['email_recovery'] != 'N/A':
            print(f"  {AZUL}Email de recuperação: {conta['email_recovery']}{RESET}")
        if conta['phone_number'] != 'N/A':
            print(f"  {AZUL}Telefone: {conta['phone_number']}{RESET}")
        print()
    
    print(f"\n{AMARELO}{NEGRITO}NÃO ENCONTRADOS ({len(nao_encontrados)} sites):{RESET}")
    if nao_encontrados:
        # Mostrar apenas os primeiros 10 para não poluir a tela
        for i, site in enumerate(nao_encontrados[:10]):
            print(f"{AMARELO}  {i+1}. {site}{RESET}")
            
        if len(nao_encontrados) > 10:
            print(f"{AMARELO}  ... e mais {len(nao_encontrados) - 10} sites{RESET}")

def salvar_resultados(resultados, email):
    """Salva os resultados em arquivo JSON"""
    if not resultados:
        return False
    
    # Criar diretório de resultados se não existir
    if not os.path.exists("resultados"):
        os.makedirs("resultados")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"resultados/holehe_{email.replace('@', '_at_')}_{timestamp}.json"
    
    try:
        # Preparar dados para salvar
        dados_salvar = {
            'email': email,
            'data_consulta': datetime.now().isoformat(),
            'total_sites_verificados': len(resultados),
            'contas_encontradas': sum(1 for r in resultados if r.get('exists', False)),
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
    # Criar diretório de logs se não existir
    if not os.path.exists("logs"):
        os.makedirs("logs")
        
    with open("logs/holehe_consultas.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] - {email} | Status: {status}\n")

def mostrar_log():
    """Mostra o histórico de consultas"""
    log_path = "logs/holehe_consultas.log"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            print(f"\n{VERDE}{NEGRITO}=== LOG DE CONSULTAS HOLEHE ===")
            print(f.read())
    else:
        print(f"{VERMELHO}[!] Nenhum log encontrado{RESET}")

async def main():
    """Função principal"""
    try:
        # Verificar se foi passado um email como argumento
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
        sys.exit(0)
    except Exception as e:
        print(f"{VERMELHO}[!] Erro inesperado: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    # Configuração para Windows
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # Executar o programa
    asyncio.run(main())
