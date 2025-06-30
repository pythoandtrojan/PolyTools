#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import platform
from colorama import Fore, Back, Style, init
from datetime import datetime


init(autoreset=True)


PASTA_FERRAMENTAS = "OSINT"
ESPERA_ENTER = 2  
VERSAO = "2.0"

BANNER = f"""
{Fore.RED}╔════════════════════════════════════════════════════════════╗
{Fore.YELLOW}║██████╗ ███████╗██╗  ██╗██╗███╗   ██╗████████╗███████╗{Fore.GREEN}║
{Fore.YELLOW}║██╔══██╗██╔════╝██║  ██║██║████╗  ██║╚══██╔══╝██╔════╝{Fore.GREEN}║
{Fore.YELLOW}║██████╔╝███████╗███████║██║██╔██╗ ██║   ██║   █████╗  {Fore.GREEN}║
{Fore.YELLOW}║██╔═══╝ ╚════██║██╔══██║██║██║╚██╗██║   ██║   ██╔══╝  {Fore.GREEN}║
{Fore.YELLOW}║██║     ███████║██║  ██║██║██║ ╚████║   ██║   ███████╗{Fore.GREEN}║
{Fore.RED}╚════════════════════════════════════════════════════════════╝
{Fore.WHITE}{Style.BRIGHT}Versão {VERSAO} | Ferramentas OSINT | {datetime.now().year}{Style.RESET_ALL}
"""

FERRAMENTAS = {
    '1': {'nome': 'Busca de Sites', 'arquivo': 'BuscaDeSites.py', 'categoria': 'Web'},
    '2': {'nome': 'Geolocalização e Metadados', 'arquivo': 'Geolocalização-Metadados.py', 'categoria': 'Imagens'},
    '3': {'nome': 'Bancos de Dados Vazados', 'arquivo': 'Bancos de dados vazados.py', 'categoria': 'Dados'},
    '4': {'nome': 'Bin Checker', 'arquivo': 'bin.py', 'categoria': 'Financeiro'},
    '5': {'nome': 'Busca por Usuário', 'arquivo': 'busca-usuario.py', 'categoria': 'Redes Sociais'},
    '6': {'nome': 'Consulta CEP', 'arquivo': 'cep.py', 'categoria': 'Localização'},
    '7': {'nome': 'Consulta CNPJ', 'arquivo': 'cnpj.py', 'categoria': 'Empresas'},
    '8': {'nome': 'Consulta CPF', 'arquivo': 'cpf.py', 'categoria': 'Pessoas'},
    '9': {'nome': 'Dados Instagram', 'arquivo': 'insta-dados.py', 'categoria': 'Redes Sociais'},
    '10': {'nome': 'Investigação de G-mail', 'arquivo': 'investigaçãoDeG-mail.py', 'categoria': 'Email'},
    '11': {'nome': 'Consulta IP', 'arquivo': 'ip.py', 'categoria': 'Rede'},
    '12': {'nome': 'Busca por Nome', 'arquivo': 'nome.py', 'categoria': 'Pessoas'},
    '13': {'nome': 'Informações de País', 'arquivo': 'pais.py', 'categoria': 'Geografia'},
    '14': {'nome': 'Rastreador Bitcoin', 'arquivo': 'rastreador-bitcoin.py', 'categoria': 'Criptomoedas'},
    '15': {'nome': 'Verificar Atualizações', 'arquivo': None, 'categoria': 'Sistema'},
    '0': {'nome': 'Sair', 'arquivo': None, 'categoria': 'Sistema'}
}

def limpar_tela():
    sistema = platform.system()
    if sistema == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def exibir_banner():
    limpar_tela()
    print(BANNER)
    print(f"{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║{Fore.WHITE} Sistema: {platform.system()} {platform.release()} | Python {platform.python_version()} | CPU: {platform.processor()[:20]} {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

def esperar_enter(tempo=ESPERA_ENTER):
    """Pausa e espera Enter para continuar com temporizador opcional"""
    input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
    time.sleep(tempo)

def verificar_atualizacoes():
    """Verifica se há atualizações disponíveis"""
    print(f"\n{Fore.CYAN}[*] Verificando atualizações...{Fore.RESET}")
    time.sleep(1)
    print(f"{Fore.GREEN}[+] Sistema está atualizado (v{VERSAO}){Fore.RESET}")
    esperar_enter()

def listar_ferramentas():
    """Lista todas as ferramentas disponíveis organizadas por categoria"""
    categorias = {}
    for key, tool in FERRAMENTAS.items():
        if tool['categoria'] not in categorias:
            categorias[tool['categoria']] = []
        categorias[tool['categoria']].append((key, tool['nome']))
    for categoria, tools in categorias.items():
        print(f"\n{Fore.MAGENTA}=== {categoria.upper()} ===")
        for key, nome in tools:
            print(f"{Fore.GREEN}[{key.zfill(2)}]{Fore.RESET} {nome}")

def verificar_dependencias():
    """Verifica se as dependências necessárias estão instaladas"""
    print(f"\n{Fore.CYAN}[*] Verificando dependências...{Fore.RESET}")
    try:
        import colorama
        print(f"{Fore.GREEN}[+] Colorama instalado{Fore.RESET}")
        return True
    except ImportError:
        print(f"{Fore.RED}[-] Colorama não instalado{Fore.RESET}")
        print(f"{Fore.YELLOW}[!] Execute: pip install colorama{Fore.RESET}")
        return False

def executar_ferramenta(arquivo):
    """Executa uma ferramenta específica com tratamento de erros"""
    if arquivo is None:
        return
    
    caminho = os.path.join(PASTA_FERRAMENTAS, arquivo)
    
    if not os.path.exists(PASTA_FERRAMENTAS):
        print(f"{Fore.RED}[-] Erro: Pasta de ferramentas não encontrada ({PASTA_FERRAMENTAS}){Fore.RESET}")
        esperar_enter()
        return
    
    if not os.path.exists(caminho):
        print(f"{Fore.RED}[-] Erro: Arquivo não encontrado - {caminho}{Fore.RESET}")
        esperar_enter()
        return
    
    try:
        print(f"\n{Fore.YELLOW}[*] Executando {arquivo}...{Fore.RESET}")
        print(f"{Fore.CYAN}{'-'*60}{Fore.RESET}")
        
        inicio = time.time()
        subprocess.run(['python3', caminho], check=True)
        tempo_execucao = time.time() - inicio
        
        print(f"{Fore.CYAN}{'-'*60}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Execução concluída em {tempo_execucao:.2f} segundos{Fore.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] Erro ao executar a ferramenta (Código {e.returncode}){Fore.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Execução interrompida pelo usuário{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Erro inesperado: {str(e)}{Fore.RESET}")
    
    esperar_enter()

def menu_principal():
    """Exibe o menu principal e processa as escolhas"""
    if not verificar_dependencias():
        esperar_enter()
        return
    
    while True:
        exibir_banner()
        
        print(f"{Fore.CYAN}{Style.BRIGHT}>>> MENU PRINCIPAL <<<{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Selecione uma ferramenta ou ação:{Fore.RESET}")
        
        listar_ferramentas()
        
        escolha = input(f"\n{Fore.BLUE}[?] Selecione uma opção (0-15): {Fore.RESET}").strip()
        
        if escolha in FERRAMENTAS:
            ferramenta = FERRAMENTAS[escolha]
            
            if escolha == '0':
                print(f"\n{Fore.MAGENTA}[*] Saindo... Até logo!{Fore.RESET}")
                time.sleep(1)
                limpar_tela()
                sys.exit(0)
            elif escolha == '15':
                verificar_atualizacoes()
            else:
                executar_ferramenta(ferramenta['arquivo'])
        else:
            print(f"\n{Fore.RED}[-] Opção inválida! Tente novamente.{Fore.RESET}")
            time.sleep(ESPERA_ENTER)

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Operação interrompida pelo usuário.{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Erro crítico: {str(e)}{Fore.RESET}")
        sys.exit(2)
