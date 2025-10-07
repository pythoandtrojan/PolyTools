#!/usr/bin/env python3

import os
import sys
import json
import subprocess
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

def verificar_instalacao_holehe():
    """Verifica se o holehe está instalado e instalado se necessário"""
    try:
        result = subprocess.run(['holehe', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"{VERDE}[+] Holehe está instalado{RESET}")
            return True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    print(f"{AMARELO}[!] Holehe não encontrado. Instalando...{RESET}")
    try:
        # Tentar instalar via pip
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'holehe'], 
                      check=True, capture_output=True)
        print(f"{VERDE}[+] Holehe instalado com sucesso{RESET}")
        return True
    except subprocess.CalledProcessError:
        print(f"{VERMELHO}[!] Falha ao instalar holehe{RESET}")
        return False

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
{AMARELO}   Modo: Comando Terminal{RESET}""")

def validar_email(email):
    """Valida se o email tem formato válido"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def executar_holehe_terminal(email):
    """Executa holehe via comando de terminal"""
    if not validar_email(email):
        return None, "Email inválido"
    
    print(f"{AMARELO}Executando holehe para: {email}{RESET}")
    print(f"{AMARELO}Isso pode levar alguns minutos... ⏳{RESET}")
    
    try:
        # Comando holehe com timeout de 5 minutos
        comando = f"holehe {email} --no-color"
        
        resultado = subprocess.run(
            comando, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=300,  # 5 minutos
            encoding='utf-8',
            errors='ignore'
        )
        
        if resultado.returncode == 0:
            return processar_saida_holehe(resultado.stdout), "Sucesso"
        else:
            print(f"{VERMELHO}Erro no holehe: {resultado.stderr}{RESET}")
            return None, f"Erro: {resultado.stderr}"
            
    except subprocess.TimeoutExpired:
        return None, "Timeout - A consulta demorou muito"
    except Exception as e:
        return None, f"Erro na execução: {str(e)}"

def processar_saida_holehe(saida):
    """Processa a saída do comando holehe"""
    linhas = saida.strip().split('\n')
    resultados = []
    
    for linha in linhas:
        linha = linha.strip()
        if not linha or '[+]' not in linha and '[-]' not in linha:
            continue
            
        # Processar linha de resultado
        if '[+]' in linha:
            # Site onde o email foi encontrado
            partes = linha.split('[+]')
            if len(partes) > 1:
                site_info = partes[1].strip()
                # Extrair nome do site (até os dois pontos)
                if ':' in site_info:
                    site_nome = site_info.split(':')[0].strip()
                    resultados.append({
                        'name': site_nome,
                        'exists': True,
                        'domain': f"https://{site_nome.lower().replace(' ', '')}.com",
                        'category': 'Desconhecida'
                    })
        elif '[-]' in linha:
            # Site onde o email não foi encontrado
            partes = linha.split('[-]')
            if len(partes) > 1:
                site_info = partes[1].strip()
                if ':' in site_info:
                    site_nome = site_info.split(':')[0].strip()
                    resultados.append({
                        'name': site_nome,
                        'exists': False,
                        'domain': f"https://{site_nome.lower().replace(' ', '')}.com",
                        'category': 'Desconhecida'
                    })
    
    return resultados

def executar_holehe_json(email):
    """Tenta executar holehe com saída JSON (versões mais recentes)"""
    try:
        comando = f"holehe {email} --json"
        resultado = subprocess.run(
            comando, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=300,
            encoding='utf-8',
            errors='ignore'
        )
        
        if resultado.returncode == 0 and resultado.stdout.strip():
            try:
                dados = json.loads(resultado.stdout)
                return dados, "Sucesso (JSON)"
            except json.JSONDecodeError:
                # Fallback para processamento textual
                return processar_saida_holehe(resultado.stdout), "Sucesso (Texto)"
        else:
            return executar_holehe_terminal(email)
            
    except Exception as e:
        print(f"{AMARELO}[!] Fallback para modo texto: {e}{RESET}")
        return executar_holehe_terminal(email)

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
        print(f"{VERDE}✓ {conta['site']}")
        print(f"  {AZUL}URL: {conta['url']}{RESET}")
        if conta.get('email_recovery') and conta['email_recovery'] != 'N/A':
            print(f"  {AZUL}Email de recuperação: {conta['email_recovery']}{RESET}")
        if conta.get('phone_number') and conta['phone_number'] != 'N/A':
            print(f"  {AZUL}Telefone: {conta['phone_number']}{RESET}")
        print()
    
    print(f"\n{AMARELO}{NEGRITO}NÃO ENCONTRADOS ({len(nao_encontrados)} sites):{RESET}")
    if nao_encontrados:
        # Mostrar em colunas para melhor visualização
        for i in range(0, len(nao_encontrados), 3):
            linha = nao_encontrados[i:i+3]
            print("  " + " | ".join(f"{site:<20}" for site in linha))
            
        if len(nao_encontrados) > 15:
            print(f"{AMARELO}  ... e mais {len(nao_encontrados) - 15} sites{RESET}")

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

def modo_rapido(email):
    """Modo rápido usando comando holehe direto"""
    print(f"{CIANO}Executando modo rápido para: {email}{RESET}")
    print(f"{AMARELO}Aguarde...{RESET}")
    
    # Executar holehe diretamente no terminal
    comando = f"holehe {email}"
    os.system(comando)
    
    # Perguntar se quer processar resultados
    processar = input(f"\n{CIANO}Deseja processar e salvar os resultados? (s/N): {RESET}").strip().lower()
    if processar in ['s', 'sim', 'y', 'yes']:
        resultados, status = executar_holehe_terminal(email)
        if resultados:
            salvar_resultados(resultados, email)
        log_consulta(email, "Modo rápido")

def main():
    """Função principal"""
    try:
        # Verificar instalação do holehe
        if not verificar_instalacao_holehe():
            print(f"{VERMELHO}[!] Não é possível continuar sem holehe{RESET}")
            sys.exit(1)
        
        # Verificar se foi passado um email como argumento
        if len(sys.argv) > 1:
            email = sys.argv[1]
            if not validar_email(email):
                print(f"{VERMELHO}[!] Email inválido: {email}{RESET}")
                sys.exit(1)
            
            banner()
            
            # Opção de modo rápido
            if len(sys.argv) > 2 and sys.argv[2] == '--rapido':
                modo_rapido(email)
            else:
                resultados, status = executar_holehe_json(email)
                
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
            print(f"\n{AMARELO}{NEGRITO}MENU HOLEHE TURBO+{RESET}")
            print(f"{VERDE}[1]{RESET} nao funciona")
            print(f"{VERDE}[2]{RESET} Modo rápido (terminal direto)")
            print(f"{VERDE}[3]{RESET} Ver log de consultas")
            print(f"{VERDE}[4]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                email = input(f"\n{CIANO}Digite o email para consulta: {RESET}").strip().lower()
                
                if not validar_email(email):
                    print(f"{VERMELHO}[!] Email inválido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                resultados, status = executar_holehe_json(email)
                
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
                email = input(f"\n{CIANO}Digite o email para consulta rápida: {RESET}").strip().lower()
                
                if not validar_email(email):
                    print(f"{VERMELHO}[!] Email inválido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                modo_rapido(email)
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':
                banner()
                mostrar_log()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':
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
    main()
