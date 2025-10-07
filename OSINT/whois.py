#!/usr/bin/env python3

import os
import subprocess
import sys
import platform
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

def verificar_instalacao_whois():
    """Verifica se o whois está instalado"""
    try:
        # Tentar executar whois com um domínio de teste
        resultado = subprocess.run(
            ['whois', 'example.com'], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False

def instalar_whois():
    """Tenta instalar o whois automaticamente"""
    print(f"{AMARELO}[!] Tentando instalar whois automaticamente...{RESET}")
    
    sistema = platform.system().lower()
    
    try:
        if sistema == "linux":
            # Detectar distribuição
            if os.path.exists("/etc/debian_version"):
                print(f"{AZUL}[*] Detectado Ubuntu/Debian, instalando whois...{RESET}")
                subprocess.run(['sudo', 'apt', 'update'], check=True, capture_output=True)
                subprocess.run(['sudo', 'apt', 'install', '-y', 'whois'], check=True, capture_output=True)
            elif os.path.exists("/etc/redhat-release"):
                print(f"{AZUL}[*] Detectado RedHat/CentOS, instalando whois...{RESET}")
                subprocess.run(['sudo', 'yum', 'install', '-y', 'whois'], check=True, capture_output=True)
            elif os.path.exists("/etc/arch-release"):
                print(f"{AZUL}[*] Detectado Arch Linux, instalando whois...{RESET}")
                subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm', 'whois'], check=True, capture_output=True)
            else:
                print(f"{VERMELHO}[!] Distribuição não suportada para instalação automática{RESET}")
                return False
                
        elif sistema == "darwin":  # macOS
            print(f"{AZUL}[*] Detectado macOS, instalando whois via Homebrew...{RESET}")
            subprocess.run(['brew', 'install', 'whois'], check=True, capture_output=True)
            
        elif sistema == "windows":
            print(f"{VERMELHO}[!] Instalação automática não disponível para Windows{RESET}")
            print(f"{AMARELO}[*] Instale manualmente:")
            print("  1. Baixe do Cygwin: https://cygwin.com/install.html")
            print("  2. Ou use o Windows Sysinternals WhoIs")
            print("  3. Ou instale via Chocolatey: choco install whois{RESET}")
            return False
            
        print(f"{VERDE}[+] whois instalado com sucesso!{RESET}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"{VERMELHO}[!] Falha na instalação automática{RESET}")
        print(f"{AMARELO}[*] Instale manualmente:")
        if sistema == "linux":
            print("  Ubuntu/Debian: sudo apt install whois")
            print("  CentOS/RHEL: sudo yum install whois")
            print("  Arch: sudo pacman -S whois")
        elif sistema == "darwin":
            print("  macOS: brew install whois")
        return False

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
██╗    ██╗██╗  ██╗ ██████╗ ██╗███████╗
██║    ██║██║  ██║██╔═══██╗██║██╔════╝
██║ █╗ ██║███████║██║   ██║██║███████╗
██║███╗██║██╔══██║██║   ██║██║╚════██║
╚███╔███╔╝██║  ██║╚██████╔╝██║███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝
{RESET}
{CIANO}{NEGRITO}   CONSULTA WHOIS - TURBO+
{AMARELO}   Modo: Comando Terminal{RESET}""")

def executar_whois_terminal(dominio):
    """Executa whois via comando de terminal"""
    if not dominio or len(dominio) < 3:
        return None, "Domínio inválido"
    
    print(f"{AMARELO}Executando whois para: {dominio}{RESET}")
    print(f"{AMARELO}Aguarde... ⏳{RESET}")
    
    try:
        # Comando whois com timeout
        comando = f"whois {dominio}"
        
        resultado = subprocess.run(
            comando, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=60,  # 1 minuto timeout
            encoding='utf-8',
            errors='ignore'
        )
        
        if resultado.returncode == 0:
            return resultado.stdout.strip(), "Sucesso"
        else:
            # Muitos servidores whois retornam códigos de erro mesmo com dados válidos
            if resultado.stdout.strip():
                return resultado.stdout.strip(), "Sucesso (com avisos)"
            else:
                return None, f"Erro: {resultado.stderr}"
            
    except subprocess.TimeoutExpired:
        return None, "Timeout - A consulta demorou muito"
    except Exception as e:
        return None, f"Erro na execução: {str(e)}"

def extrair_informacoes_chave(resultado):
    """Extrai informações importantes do resultado whois"""
    linhas = resultado.split('\n')
    informacoes = {}
    
    campos_chave = [
        'domain name:', 'registrar:', 'creation date:', 'updated date:',
        'expiration date:', 'name server:', 'status:', 'registrant:',
        'admin:', 'tech:', 'owner:', 'country:', 'organization:',
        'domain:', 'created:', 'changed:', 'registrar:'
    ]
    
    for linha in linhas:
        linha_lower = linha.lower().strip()
        for campo in campos_chave:
            if linha_lower.startswith(campo):
                valor = linha.split(':', 1)[1].strip() if ':' in linha else linha
                chave = campo.replace(':', '').replace(' ', '_').title()
                informacoes[chave] = valor
                break
    
    return informacoes

def mostrar_informacoes_chave(informacoes, dominio):
    """Exibe informações chave do whois de forma organizada"""
    print(f"\n{VERDE}{NEGRITO}=== INFORMAÇÕES PRINCIPAIS PARA {dominio.upper()} ===")
    
    if not informacoes:
        print(f"{AMARELO}[!] Nenhuma informação chave encontrada{RESET}")
        return
    
    # Categorias de informações
    categorias = {
        'Informações do Domínio': ['Domain_Name', 'Domain', 'Registrar', 'Status'],
        'Datas Importantes': ['Creation_Date', 'Created', 'Updated_Date', 'Changed', 'Expiration_Date'],
        'Servidores DNS': ['Name_Server'],
        'Contatos': ['Registrant', 'Admin', 'Tech', 'Owner', 'Organization', 'Country']
    }
    
    for categoria, campos in categorias.items():
        print(f"\n{CIANO}{NEGRITO}{categoria}:{RESET}")
        encontrou_info = False
        
        for campo in campos:
            if campo in informacoes:
                valor = informacoes[campo]
                # Limitar linhas muito longas
                if len(valor) > 100:
                    valor = valor[:100] + "..."
                print(f"  {AZUL}{campo.replace('_', ' ')}: {VERDE}{valor}{RESET}")
                encontrou_info = True
        
        if not encontrou_info:
            print(f"  {AMARELO}Nenhuma informação disponível{RESET}")

def salvar_resultado(resultado, dominio):
    """Salva o resultado em um arquivo"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"whois_{dominio}_{timestamp}.txt"
    
    try:
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(f"Resultado da consulta WHOIS para: {dominio}\n")
            f.write(f"Data da consulta: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(resultado)
        
        print(f"{VERDE}[+] Resultado salvo em: {nome_arquivo}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar arquivo: {e}{RESET}")
        return False

def log_consulta(dominio, status):
    """Registra a consulta em arquivo de log"""
    try:
        with open("whois_consultas.log", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] - {dominio} | Status: {status}\n")
    except Exception:
        pass  # Ignorar erros de log

def modo_rapido(dominio):
    """Modo rápido usando comando whois direto"""
    print(f"{CIANO}Executando modo rápido para: {dominio}{RESET}")
    print(f"{AMARELO}Aguarde...{RESET}")
    
    # Executar whois diretamente no terminal
    comando = f"whois {dominio}"
    os.system(comando)
    
    # Perguntar se quer processar resultados
    processar = input(f"\n{CIANO}Deseja processar e salvar os resultados? (s/N): {RESET}").strip().lower()
    if processar in ['s', 'sim', 'y', 'yes']:
        resultado, status = executar_whois_terminal(dominio)
        if resultado:
            salvar_resultado(resultado, dominio)
        log_consulta(dominio, "Modo rápido")

def main():
    """Função principal"""
    try:
        # Verificar instalação do whois
        if not verificar_instalacao_whois():
            print(f"{VERMELHO}[!] Comando whois não encontrado{RESET}")
            if not instalar_whois():
                print(f"{VERMELHO}[!] Não é possível continuar sem whois{RESET}")
                print(f"{AMARELO}[*] Instale manualmente o whois para seu sistema operacional{RESET}")
                sys.exit(1)
        
        # Verificar se foi passado um domínio como argumento
        if len(sys.argv) > 1:
            dominio = sys.argv[1]
            
            banner()
            
            # Opção de modo rápido
            if len(sys.argv) > 2 and sys.argv[2] == '--rapido':
                modo_rapido(dominio)
            else:
                resultado, status = executar_whois_terminal(dominio)
                
                if resultado:
                    print(f"\n{VERDE}{NEGRITO}=== RESULTADO COMPLETO WHOIS ===")
                    print(f"{AZUL}{resultado}{RESET}")
                    
                    # Extrair e mostrar informações chave
                    informacoes = extrair_informacoes_chave(resultado)
                    mostrar_informacoes_chave(informacoes, dominio)
                    
                    # Salvar automaticamente
                    salvar_resultado(resultado, dominio)
                else:
                    print(f"{VERMELHO}[!] {status}{RESET}")
                
                log_consulta(dominio, status)
            
            sys.exit(0)
        
        # Modo interativo
        while True:
            banner()
            print(f"\n{AMARELO}{NEGRITO}MENU WHOIS TURBO+{RESET}")
            print(f"{VERDE}[1]{RESET} Consulta completa (com processamento)")
            print(f"{VERDE}[2]{RESET} Modo rápido (terminal direto)")
            print(f"{VERDE}[3]{RESET} Ver log de consultas")
            print(f"{VERDE}[4]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                dominio = input(f"\n{CIANO}Digite o domínio para consulta whois: {RESET}").strip().lower()
                
                if not dominio or len(dominio) < 3:
                    print(f"{VERMELHO}[!] Domínio inválido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                resultado, status = executar_whois_terminal(dominio)
                
                if resultado:
                    print(f"\n{VERDE}{NEGRITO}=== RESULTADO COMPLETO WHOIS ===")
                    print(f"{AZUL}{resultado}{RESET}")
                    
                    # Extrair informações chave
                    informacoes = extrair_informacoes_chave(resultado)
                    mostrar_informacoes_chave(informacoes, dominio)
                    
                    # Perguntar se deseja salvar
                    salvar = input(f"\n{CIANO}Deseja salvar o resultado? (s/N): {RESET}").strip().lower()
                    if salvar in ['s', 'sim', 'y', 'yes']:
                        salvar_resultado(resultado, dominio)
                else:
                    print(f"{VERMELHO}[!] {status}{RESET}")
                
                log_consulta(dominio, status)
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                banner()
                dominio = input(f"\n{CIANO}Digite o domínio para consulta rápida: {RESET}").strip().lower()
                
                if not dominio or len(dominio) < 3:
                    print(f"{VERMELHO}[!] Domínio inválido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                modo_rapido(dominio)
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':
                banner()
                if os.path.exists("whois_consultas.log"):
                    with open("whois_consultas.log", "r", encoding="utf-8") as f:
                        print(f"\n{VERDE}{NEGRITO}=== LOG DE CONSULTAS WHOIS ==={RESET}")
                        print(f.read())
                else:
                    print(f"{VERMELHO}[!] Nenhum log encontrado{RESET}")
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
