#!/usr/bin/env python3

import os
import subprocess
import sys
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
{RESET}""")

def executar_whois(dominio):
    """Executa o comando whois e retorna o resultado"""
    try:
        resultado = subprocess.check_output(
            ['whois', dominio], 
            stderr=subprocess.STDOUT, 
            text=True,
            timeout=30
        )
        return resultado.strip()
    except subprocess.CalledProcessError as e:
        return f"Erro ao executar whois: {e.output}"
    except subprocess.TimeoutExpired:
        return "Timeout: A consulta whois excedeu o tempo limite de 30 segundos"
    except FileNotFoundError:
        return "Erro: Comando whois não encontrado. Instale o whois primeiro."
    except Exception as e:
        return f"Erro inesperado: {str(e)}"

def mostrar_loading():
    """Animação de loading"""
    print(f"{AMARELO}Consultando whois... ⏳{RESET}", end='\r')

def salvar_resultado(resultado, dominio):
    """Salva o resultado em um arquivo"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"whois_{dominio}_{timestamp}.txt"
    
    try:
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(f"Resultado da consulta WHOIS para: {dominio}\n")
            f.write(f"Data da consulta: {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")
            f.write(resultado)
        
        print(f"{VERDE}[+] Resultado salvo em: {nome_arquivo}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar arquivo: {e}{RESET}")
        return False

def log_consulta(dominio, status):
    """Registra a consulta em arquivo de log"""
    with open("whois_consultas.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] - {dominio} | Status: {status}\n")

def consultar_dominio(dominio):
    """Realiza a consulta whois para um domínio"""
    if not dominio or len(dominio) < 3:
        print(f"{VERMELHO}[!] Domínio inválido{RESET}")
        return None
    
    mostrar_loading()
    inicio = datetime.now()
    
    resultado = executar_whois(dominio)
    tempo_resposta = (datetime.now() - inicio).total_seconds()
    
    print(f"{AZUL}[*] Tempo de resposta: {tempo_resposta:.2f}s{RESET}")
    
    if "Erro" in resultado or "Timeout" in resultado:
        print(f"{VERMELHO}[!] {resultado}{RESET}")
        log_consulta(dominio, "ERRO")
        return None
    else:
        print(f"{VERDE}[+] Consulta whois concluída!{RESET}")
        log_consulta(dominio, "SUCESSO")
        return resultado

def mostrar_resultado(resultado, dominio):
    """Exibe o resultado da consulta whois"""
    if not resultado:
        return
    
    print(f"\n{VERDE}{NEGRITO}=== RESULTADO WHOIS PARA {dominio.upper()} ==={RESET}")
    print(f"{AZUL}{resultado}{RESET}")

def main():
    """Função principal"""
    try:
        # Verificar se o comando whois está disponível
        try:
            subprocess.run(['whois', '--help'], 
                         capture_output=True, 
                         text=True, 
                         timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"{VERMELHO}[!] Comando whois não encontrado ou não acessível{RESET}")
            print(f"{AMARELO}[*] Instale o whois primeiro:")
            if os.name == 'posix':
                print("  Ubuntu/Debian: sudo apt install whois")
                print("  CentOS/RHEL: sudo yum install whois")
                print("  macOS: brew install whois")
            else:
                print("  Windows: Baixe e instale o whois do Cygwin ou Windows Sysinternals")
            sys.exit(1)
        
        while True:
            banner()
            print(f"\n{AMARELO}{NEGRITO}MENU WHOIS{RESET}")
            print(f"{VERDE}[1]{RESET} Consultar")
            print(f"{VERDE}[2]{RESET} Visualizar log de consultas")
            print(f"{VERDE}[3]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                dominio = input(f"\n{CIANO}Digite o domínio para consulta whois: {RESET}").strip().lower()
                
                resultado = consultar_dominio(dominio)
                if resultado:
                    mostrar_resultado(resultado, dominio)
                    
                    # Perguntar se deseja salvar
                    salvar = input(f"\n{CIANO}Deseja salvar o resultado? (s/N): {RESET}").strip().lower()
                    if salvar in ['s', 'sim', 'y', 'yes']:
                        salvar_resultado(resultado, dominio)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                banner()
                if os.path.exists("whois_consultas.log"):
                    with open("whois_consultas.log", "r", encoding="utf-8") as f:
                        print(f"\n{VERDE}{NEGRITO}=== LOG DE CONSULTAS WHOIS ==={RESET}")
                        print(f.read())
                else:
                    print(f"{VERMELHO}[!] Nenhum log encontrado{RESET}")
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
    # Modo de uso direto: whois <domínio>
    if len(sys.argv) > 1:
        dominio = sys.argv[1]
        resultado = consultar_dominio(dominio)
        if resultado:
            print(resultado)
            # Salvar automaticamente em modo comando
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_arquivo = f"whois_{dominio}_{timestamp}.txt"
            with open(nome_arquivo, "w", encoding="utf-8") as f:
                f.write(resultado)
            print(f"\nResultado salvo em: {nome_arquivo}")
        else:
            sys.exit(1)
    else:
        main()
