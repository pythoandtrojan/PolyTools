#!/usr/bin/env python3

import os
import sys
import time
import subprocess
from datetime import datetime
import signal
import threading
from typing import Dict, List, Optional, Tuple

# Configurações globais
CONFIG = {
    'WORDLIST_COMMON': '/usr/share/dirb/wordlists/common.txt',
    'WORDLIST_BIG': '/usr/share/dirb/wordlists/big.txt',
    'DEFAULT_OUTPUT_DIR': os.path.join(os.getcwd(), 'dirb_scans'),
    'TIMEOUT': 10,
    'DELAY': 1
}

# Cores para o terminal
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

def show_banner() -> None:
    """Mostra o banner estilizado do programa"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{Colors.CYAN}
╔══════════════════════════════════════════╗
║  ██████╗ ██╗██████╗ ██████╗  ██████╗    ║
║  ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝    ║
║  ██║  ██║██║██████╔╝██████╔╝██║         ║
║  ██║  ██║██║██╔══██╗██╔══██╗██║         ║
║  ██████╔╝██║██║  ██║██████╔╝╚██████╗    ║
║  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝    ║
╠══════════════════════════════════════════╣
║  SCANNER DE DIRETÓRIOS - DIRB AUTOMÁTICO ║
╚══════════════════════════════════════════╝{Colors.NC}""")
    print(f"{Colors.YELLOW}Versão: 2.0 | Autor: Seu Nome{Colors.NC}")
    print(f"{Colors.BLUE}Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{Colors.NC}")
    print(f"{Colors.GREEN}======================================{Colors.NC}\n")

def check_dependencies() -> bool:
    """Verifica se todas as dependências estão instaladas"""
    commands = ['dirb', 'curl']
    missing = False
    
    print(f"{Colors.YELLOW}[*] Verificando dependências...{Colors.NC}")
    
    for cmd in commands:
        try:
            subprocess.run(['which', cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"{Colors.GREEN}[+] {cmd} instalado{Colors.NC}")
        except subprocess.CalledProcessError:
            print(f"{Colors.RED}[ERRO] Comando '{cmd}' não encontrado!{Colors.NC}")
            missing = True
    
    if missing:
        print(f"\n{Colors.YELLOW}Instale as dependências faltantes:{Colors.NC}")
        print("sudo apt-get install dirb curl")
        return False
    
    return True

def setup_output_dir() -> bool:
    """Configura o diretório de saída para os relatórios"""
    print(f"{Colors.YELLOW}[*] Configurando diretório de saída...{Colors.NC}")
    
    try:
        os.makedirs(CONFIG['DEFAULT_OUTPUT_DIR'], exist_ok=True)
        print(f"{Colors.GREEN}[+] Diretório criado: {CONFIG['DEFAULT_OUTPUT_DIR']}{Colors.NC}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao criar diretório de saída: {e}{Colors.NC}")
        return False

def check_target(target: str) -> Tuple[bool, str]:
    """Verifica se o alvo está acessível"""
    print(f"{Colors.YELLOW}[*] Verificando alvo: {target}{Colors.NC}")
    
    # Verifica se o alvo começa com http:// ou https://
    if not target.startswith(('http://', 'https://')):
        print(f"{Colors.YELLOW}[*] Tentando com http://...{Colors.NC}")
        target = f"http://{target}"
    
    try:
        result = subprocess.run(
            ['curl', '--head', '--silent', '--fail', '--max-time', str(CONFIG['TIMEOUT']), target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[+] Alvo acessível!{Colors.NC}")
            return True, target
        else:
            print(f"{Colors.RED}[ERRO] Não foi possível conectar ao alvo!{Colors.NC}")
            return False, target
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Erro ao verificar alvo: {e}{Colors.NC}")
        return False, target

def select_wordlist() -> str:
    """Permite ao usuário selecionar uma wordlist"""
    print(f"\n{Colors.YELLOW}Selecione a wordlist:{Colors.NC}")
    print("1. Comum (common.txt)")
    print("2. Grande (big.txt)")
    print("3. Personalizada")
    
    while True:
        try:
            wl_choice = input("Opção [1-3]: ").strip()
            
            if wl_choice == '1':
                if os.path.isfile(CONFIG['WORDLIST_COMMON']):
                    return CONFIG['WORDLIST_COMMON']
                else:
                    print(f"{Colors.RED}[ERRO] Wordlist comum não encontrada!{Colors.NC}")
            elif wl_choice == '2':
                if os.path.isfile(CONFIG['WORDLIST_BIG']):
                    return CONFIG['WORDLIST_BIG']
                else:
                    print(f"{Colors.RED}[ERRO] Wordlist grande não encontrada!{Colors.NC}")
            elif wl_choice == '3':
                custom_wl = input("Caminho completo para wordlist: ").strip()
                if os.path.isfile(custom_wl):
                    return custom_wl
                else:
                    print(f"{Colors.RED}[ERRO] Arquivo não encontrado!{Colors.NC}")
            else:
                print(f"{Colors.RED}Opção inválida! Tente novamente.{Colors.NC}")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(1)

def select_extensions() -> str:
    """Permite ao usuário selecionar extensões para verificar"""
    print(f"\n{Colors.YELLOW}Selecione extensões:{Colors.NC}")
    print("1. .php,.html,.js,.txt")
    print("2. .php,.php3,.php4,.php5")
    print("3. .asp,.aspx,.ashx")
    print("4. .jsp,.do,.action")
    print("5. .bak,.old,.backup")
    print("6. Nenhuma extensão especial")
    
    while True:
        try:
            ext_choice = input("Opção [1-6]: ").strip()
            
            if ext_choice == '1':
                return "-X .php,.html,.js,.txt"
            elif ext_choice == '2':
                return "-X .php,.php3,.php4,.php5"
            elif ext_choice == '3':
                return "-X .asp,.aspx,.ashx"
            elif ext_choice == '4':
                return "-X .jsp,.do,.action"
            elif ext_choice == '5':
                return "-X .bak,.old,.backup"
            elif ext_choice == '6':
                return ""
            else:
                print(f"{Colors.RED}Opção inválida! Tente novamente.{Colors.NC}")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(1)

def show_progress(process: subprocess.Popen) -> None:
    """Mostra uma animação de progresso enquanto o DIRB está rodando"""
    spinner = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    i = 0
    
    while process.poll() is None:
        i = (i + 1) % 8
        print(f"{Colors.BLUE}Varredura em andamento {spinner[i]}{Colors.NC}", end='\r')
        time.sleep(0.1)
    
    print(f"{Colors.GREEN}✓ Varredura concluída!{Colors.NC}")

def generate_report(output_file: str, url: str) -> None:
    """Gera um relatório com os resultados da varredura"""
    print(f"\n{Colors.GREEN}╔══════════════════════════════════════════╗")
    print(f"║             RELATÓRIO FINALIZADO           ║")
    print(f"╚══════════════════════════════════════════╝{Colors.NC}")
    
    print(f"\n{Colors.CYAN}Alvo:{Colors.NC} {url}")
    print(f"{Colors.CYAN}Arquivo de saída:{Colors.NC} {output_file}")
    
    if not os.path.isfile(output_file):
        print(f"{Colors.RED}[ERRO] Arquivo de resultados não encontrado!{Colors.NC}")
        return
    
    try:
        with open(output_file, 'r') as f:
            content = f.readlines()
        
        total_lines = len(content)
        found_dirs = sum(1 for line in content if line.startswith('+ ') and any(c.isdigit() for c in line))
        found_files = sum(1 for line in content if line.startswith('==> DIRECTORY:'))
        
        print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
        print(f"║               ESTATÍSTICAS              ║")
        print(f"╚══════════════════════════════════════════╝{Colors.NC}")
        print(f"{Colors.MAGENTA}Total de linhas:{Colors.NC} {total_lines}")
        print(f"{Colors.MAGENTA}Diretórios encontrados:{Colors.NC} {found_dirs}")
        print(f"{Colors.MAGENTA}Arquivos encontrados:{Colors.NC} {found_files}")
        
        if found_dirs > 0 or found_files > 0:
            print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
            print(f"║           ITENS INTERESSANTES           ║")
            print(f"╚══════════════════════════════════════════╝{Colors.NC}")
            
            interesting = [line for line in content if line.startswith('+ ') or line.startswith('==> DIRECTORY:')]
            for line in interesting[:10]:  # Mostra apenas os 10 primeiros
                print(f"{Colors.CYAN}{line.strip()}{Colors.NC}")
            
            print(f"\n{Colors.GREEN}Dica:{Colors.NC} Verifique o arquivo completo para mais resultados:")
            print(f"{Colors.BLUE}{output_file}{Colors.NC}")
        else:
            print(f"\n{Colors.RED}Nenhum resultado relevante encontrado.{Colors.NC}")
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao ler arquivo de resultados: {e}{Colors.NC}")

def run_dirb(url: str, wordlist: str, output_filename: str, extensions: str, options: str) -> None:
    """Executa o comando DIRB com os parâmetros fornecidos"""
    output_file = os.path.join(CONFIG['DEFAULT_OUTPUT_DIR'], output_filename)
    
    print(f"\n{Colors.GREEN}╔══════════════════════════════════════════╗")
    print(f"║          INICIANDO VARREDURA DIRB        ║")
    print(f"╚══════════════════════════════════════════╝{Colors.NC}")
    
    print(f"{Colors.CYAN}Alvo:{Colors.NC} {url}")
    print(f"{Colors.CYAN}Wordlist:{Colors.NC} {wordlist}")
    if extensions:
        print(f"{Colors.CYAN}Extensões:{Colors.NC} {extensions.replace('-X ', '')}")
    if options:
        print(f"{Colors.CYAN}Opções:{Colors.NC} {options}")
    print(f"{Colors.CYAN}Saída:{Colors.NC} {output_file}")
    
    # Sanitizar opções para evitar injeção de comandos
    options = options.translate(str.maketrans('', '', ';&|<>()$`'))
    
    cmd = ['dirb', url, wordlist, '-o', output_file]
    
    if extensions:
        cmd.extend(extensions.split())
    
    if options:
        cmd.extend(options.split())
    
    print(f"\n{Colors.YELLOW}[*] Comando executado:{Colors.NC}")
    print(f"{Colors.BLUE}{' '.join(cmd)}{Colors.NC}")
    
    print(f"\n{Colors.MAGENTA}Iniciando varredura...{Colors.NC}")
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Mostra o spinner de progresso em uma thread separada
        progress_thread = threading.Thread(target=show_progress, args=(process,))
        progress_thread.start()
        
        # Espera o processo terminar
        process.wait()
        progress_thread.join()
        
        generate_report(output_file, url)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Varredura interrompida pelo usuário.{Colors.NC}")
        try:
            process.terminate()
        except:
            pass
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao executar DIRB: {e}{Colors.NC}")

def predefined_scans(url: str, scan_type: int) -> None:
    """Executa varreduras pré-definidas baseadas no tipo"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if scan_type == 1:  # Básica
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_basic_{timestamp}.txt", "", "")
    elif scan_type == 2:  # Com extensões
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_ext_{timestamp}.txt", "-X .php,.html,.js,.txt", "")
    elif scan_type == 3:  # Agressiva
        run_dirb(url, CONFIG['WORDLIST_BIG'], f"dirb_aggressive_{timestamp}.txt", "", "")
    elif scan_type == 4:  # PHP
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_php_{timestamp}.txt", "-X .php,.php3,.php4,.php5,.phtml", "")
    elif scan_type == 5:  # ASP
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_asp_{timestamp}.txt", "-X .asp,.aspx,.ashx,.asmx", "")
    elif scan_type == 6:  # JSP
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_jsp_{timestamp}.txt", "-X .jsp,.jspx,.do,.action", "")
    elif scan_type == 7:  # Backup
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_backup_{timestamp}.txt", "-X .bak,.old,.backup,.swp,.sav", "")

def main_menu() -> None:
    """Exibe o menu principal e gerencia a interação do usuário"""
    while True:
        print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
        print(f"║          MENU PRINCIPAL - DIRB SCANNER      ║")
        print(f"╚══════════════════════════════════════════╝{Colors.NC}")
        print(f"{Colors.CYAN}1. Varredura Básica{Colors.NC}")
        print(f"{Colors.CYAN}2. Varredura com Extensões Comuns{Colors.NC}")
        print(f"{Colors.CYAN}3. Varredura Agressiva{Colors.NC}")
        print(f"{Colors.CYAN}4. Varredura para Arquivos PHP{Colors.NC}")
        print(f"{Colors.CYAN}5. Varredura para Arquivos ASP/ASPX{Colors.NC}")
        print(f"{Colors.CYAN}6. Varredura para Arquivos JSP{Colors.NC}")
        print(f"{Colors.CYAN}7. Varredura para Arquivos de Backup{Colors.NC}")
        print(f"{Colors.CYAN}8. Varredura Personalizada{Colors.NC}")
        print(f"{Colors.RED}9. Sair{Colors.NC}")
        
        try:
            choice = input("Opção [1-9]: ").strip()
            
            if choice in ['1', '2', '3', '4', '5', '6', '7']:
                url = input("Digite a URL alvo (ex: http://example.com): ").strip()
                accessible, final_url = check_target(url)
                if accessible:
                    predefined_scans(final_url, int(choice))
            elif choice == '8':
                url = input("Digite a URL alvo (ex: http://example.com): ").strip()
                accessible, final_url = check_target(url)
                if accessible:
                    wordlist = select_wordlist()
                    extensions = select_extensions()
                    
                    print(f"\n{Colors.YELLOW}Opções adicionais do DIRB:{Colors.NC}")
                    print(f"{Colors.BLUE}Exemplos:{Colors.NC}")
                    print(f" - {Colors.CYAN}-N 404{Colors.NC} (ignorar código 404)")
                    print(f" - {Colors.CYAN}-r{Colors.NC} (não buscar recursivamente)")
                    print(f" - {Colors.CYAN}-z 100{Colors.NC} (delay de 100ms entre requisições)")
                    print(f" - {Colors.CYAN}-p http://proxy:8080{Colors.NC} (usar proxy)")
                    options = input("Digite opções adicionais: ").strip()
                    
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    run_dirb(final_url, wordlist, f"dirb_custom_{timestamp}.txt", extensions, options)
            elif choice == '9':
                print(f"\n{Colors.GREEN}Encerrando o DIRB Scanner...{Colors.NC}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}Opção inválida! Tente novamente.{Colors.NC}")
            
            input("Pressione Enter para continuar...")
            show_banner()
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}Erro: {e}{Colors.NC}")

def main() -> None:
    """Função principal"""
    show_banner()
    
    if not check_dependencies():
        sys.exit(1)
    
    if not setup_output_dir():
        sys.exit(1)
    
    main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript interrompido pelo usuário.")
        sys.exit(0)
