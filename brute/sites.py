#!/usr/bin/env python3

import os
import sys
import time
import subprocess
from datetime import datetime
import signal
import threading
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import argparse
import json

# Configurações globais
CONFIG = {
    'WORDLIST_COMMON': '/usr/share/dirb/wordlists/common.txt',
    'WORDLIST_BIG': '/usr/share/dirb/wordlists/big.txt', 
    'WORDLIST_ADMIN': '/usr/share/dirb/wordlists/admin.txt',
    'DEFAULT_OUTPUT_DIR': os.path.join(os.getcwd(), 'dirb_scans'),
    'TIMEOUT': 10,
    'DELAY': 1,
    'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# Wordlists embutidas para fallback
EMBEDDED_WORDLISTS = {
    'admin': [
        'admin', 'administrator', 'login', 'panel', 'cp', 'control', 'dashboard',
        'manager', 'sysadmin', 'root', 'backend', 'webadmin', 'admin1', 'admin2',
        'admin/login', 'admin/panel', 'admin/cp', 'admin/control', 'admin/dashboard',
        'administrator/login', 'administrator/panel', 'wp-admin', 'wp-login',
        'user/login', 'user/admin', 'admin_area', 'admin123', 'adminarea',
        'admin-login', 'adminpanel', 'adminportal', 'adminconsole', 'admincp',
        'admincenter', 'administer', 'administration', 'administer/login',
        'moderator', 'moderator/login', 'moderator/panel', 'staff', 'staff/login',
        'staff/panel', 'support', 'support/login', 'sysadmin/login', 'sysadmin/panel',
        'system', 'system/login', 'webmaster', 'webmaster/login', 'operator',
        'operator/login', 'config', 'configuration', 'setup', 'install', 'debug',
        'test', 'demo', 'backup', 'backups', 'db', 'database', 'sql', 'mysql',
        'oracle', 'postgres', 'mongodb', 'redis', 'phpmyadmin', 'phppgadmin',
        'pma', 'myadmin', 'pgadmin', 'redis-admin', 'memadmin', 'webmin',
        'cpanel', 'whm', 'plesk', 'directadmin', 'vesta', 'virtualmin',
        'manager/html', 'jmx-console', 'web-console', 'console', 'api',
        'api/admin', 'api/login', 'oauth', 'oauth/admin', 'graphql', 'graphql/admin'
    ],
    'common_dirs': [
        'images', 'img', 'css', 'js', 'assets', 'static', 'media', 'uploads',
        'downloads', 'files', 'docs', 'documents', 'backup', 'backups', 'tmp',
        'temp', 'cache', 'logs', 'config', 'configuration', 'setup', 'install',
        'include', 'includes', 'inc', 'lib', 'library', 'libraries', 'src',
        'source', 'sources', 'vendor', 'vendors', 'plugins', 'plugin', 'modules',
        'module', 'components', 'component', 'themes', 'theme', 'templates',
        'template', 'views', 'view', 'controllers', 'controller', 'models',
        'model', 'api', 'apis', 'rest', 'soap', 'xmlrpc', 'json', 'ajax',
        'webservices', 'web-services', 'ws', 'wss', 'rpc', 'graphql',
        'oauth', 'auth', 'authentication', 'sso', 'single-sign-on',
        'signin', 'signout', 'logout', 'register', 'registration', 'signup',
        'account', 'accounts', 'profile', 'profiles', 'user', 'users', 'member',
        'members', 'customer', 'customers', 'client', 'clients', 'partner',
        'partners', 'admin', 'administrator', 'moderator', 'staff', 'support',
        'sysadmin', 'webmaster', 'operator', 'root', 'superuser', 'supervisor'
    ]
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
║           VERSÃO MELHORADA              ║
╚══════════════════════════════════════════╝{Colors.NC}""")
    print(f"{Colors.YELLOW}Versão: 3.0 | Busca Avançada de URLs Administrativas{Colors.NC}")
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
        print(f"{Colors.YELLOW}[*] Tentando com https://...{Colors.NC}")
        target = f"https://{target}"
    
    try:
        # Primeiro tenta com requests para mais informações
        headers = {'User-Agent': CONFIG['USER_AGENT']}
        response = requests.head(target, headers=headers, timeout=CONFIG['TIMEOUT'], verify=False)
        
        if response.status_code < 400:
            print(f"{Colors.GREEN}[+] Alvo acessível! Status: {response.status_code}{Colors.NC}")
            print(f"{Colors.BLUE}[+] Servidor: {response.headers.get('Server', 'Desconhecido')}{Colors.NC}")
            return True, target
        else:
            print(f"{Colors.YELLOW}[!] Alvo retornou status: {response.status_code}{Colors.NC}")
            return True, target
            
    except requests.exceptions.SSLError:
        print(f"{Colors.YELLOW}[!] Erro SSL, tentando HTTP...{Colors.NC}")
        target = target.replace('https://', 'http://')
        try:
            response = requests.head(target, headers={'User-Agent': CONFIG['USER_AGENT']}, 
                                   timeout=CONFIG['TIMEOUT'])
            if response.status_code < 400:
                print(f"{Colors.GREEN}[+] Alvo acessível via HTTP! Status: {response.status_code}{Colors.NC}")
                return True, target
        except:
            pass
    
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Não foi possível conectar ao alvo: {e}{Colors.NC}")
        return False, target
    
    return False, target

def create_custom_wordlist(wordlist_type: str) -> str:
    """Cria uma wordlist customizada baseada no tipo"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(CONFIG['DEFAULT_OUTPUT_DIR'], f"wordlist_{wordlist_type}_{timestamp}.txt")
    
    try:
        with open(filename, 'w') as f:
            if wordlist_type == 'admin':
                words = EMBEDDED_WORDLISTS['admin']
            elif wordlist_type == 'common':
                words = EMBEDDED_WORDLISTS['common_dirs']
            else:
                words = EMBEDDED_WORDLISTS['admin'] + EMBEDDED_WORDLISTS['common_dirs']
            
            for word in words:
                f.write(word + '\n')
        
        print(f"{Colors.GREEN}[+] Wordlist criada: {filename} ({len(words)} palavras){Colors.NC}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao criar wordlist: {e}{Colors.NC}")
        return ""

def select_wordlist() -> str:
    """Permite ao usuário selecionar uma wordlist"""
    print(f"\n{Colors.YELLOW}Selecione a wordlist:{Colors.NC}")
    print("1. Comum (common.txt)")
    print("2. Grande (big.txt)")
    print("3. Administrativa (admin.txt)")
    print("4. Wordlist Customizada - URLs Admin")
    print("5. Wordlist Customizada - Diretórios Comuns")
    print("6. Wordlist Combinada")
    
    while True:
        try:
            wl_choice = input("Opção [1-6]: ").strip()
            
            if wl_choice == '1':
                if os.path.isfile(CONFIG['WORDLIST_COMMON']):
                    return CONFIG['WORDLIST_COMMON']
                else:
                    print(f"{Colors.YELLOW}[!] Wordlist comum não encontrada, criando customizada...{Colors.NC}")
                    return create_custom_wordlist('common')
            elif wl_choice == '2':
                if os.path.isfile(CONFIG['WORDLIST_BIG']):
                    return CONFIG['WORDLIST_BIG']
                else:
                    print(f"{Colors.RED}[ERRO] Wordlist grande não encontrada!{Colors.NC}")
            elif wl_choice == '3':
                if os.path.isfile(CONFIG['WORDLIST_ADMIN']):
                    return CONFIG['WORDLIST_ADMIN']
                else:
                    print(f"{Colors.YELLOW}[!] Wordlist admin não encontrada, criando customizada...{Colors.NC}")
                    return create_custom_wordlist('admin')
            elif wl_choice == '4':
                return create_custom_wordlist('admin')
            elif wl_choice == '5':
                return create_custom_wordlist('common')
            elif wl_choice == '6':
                return create_custom_wordlist('combined')
            else:
                print(f"{Colors.RED}Opção inválida! Tente novamente.{Colors.NC}")
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(1)

def select_extensions() -> str:
    """Permite ao usuário selecionar extensões para verificar"""
    print(f"\n{Colors.YELLOW}Selecione extensões:{Colors.NC}")
    print("1. .php,.html,.js,.txt")
    print("2. .php,.php3,.php4,.php5,.phtml")
    print("3. .asp,.aspx,.ashx,.asmx")
    print("4. .jsp,.do,.action")
    print("5. .bak,.old,.backup,.swp")
    print("6. .xml,.json,.yml,.yaml")
    print("7. .sql,.db,.mdb,.sqlite")
    print("8. Nenhuma extensão especial")
    
    while True:
        try:
            ext_choice = input("Opção [1-8]: ").strip()
            
            extensions_map = {
                '1': ".php,.html,.js,.txt,.css,.xml",
                '2': ".php,.php3,.php4,.php5,.phtml,.phar",
                '3': ".asp,.aspx,.ashx,.asmx,.ascx,.config",
                '4': ".jsp,.jspx,.do,.action,.struts",
                '5': ".bak,.old,.backup,.swp,.sav,.tmp",
                '6': ".xml,.json,.yml,.yaml,.conf,.config",
                '7': ".sql,.db,.mdb,.sqlite,.dbf,.mdf"
            }
            
            if ext_choice in extensions_map:
                return f"-X {extensions_map[ext_choice]}"
            elif ext_choice == '8':
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

def analyze_results(output_file: str) -> Dict:
    """Analisa os resultados e categoriza as descobertas"""
    categories = {
        'admin_panels': [],
        'login_pages': [],
        'backup_files': [],
        'config_files': [],
        'api_endpoints': [],
        'interesting_dirs': [],
        'other_found': []
    }
    
    admin_keywords = ['admin', 'login', 'panel', 'dashboard', 'cp', 'control', 'manager']
    login_keywords = ['login', 'signin', 'auth', 'authentication']
    backup_keywords = ['.bak', '.old', '.backup', '.swp', '.sav']
    config_keywords = ['config', 'configuration', '.conf', '.ini', '.yml', '.yaml']
    api_keywords = ['api', 'rest', 'graphql', 'soap', 'json', 'xml']
    
    try:
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('+ ') or line.startswith('==> DIRECTORY:'):
                    item = line.replace('+ ', '').replace('==> DIRECTORY: ', '')
                    item_lower = item.lower()
                    
                    # Categorização
                    if any(keyword in item_lower for keyword in admin_keywords):
                        categories['admin_panels'].append(item)
                    elif any(keyword in item_lower for keyword in login_keywords):
                        categories['login_pages'].append(item)
                    elif any(keyword in item_lower for keyword in backup_keywords):
                        categories['backup_files'].append(item)
                    elif any(keyword in item_lower for keyword in config_keywords):
                        categories['config_files'].append(item)
                    elif any(keyword in item_lower for keyword in api_keywords):
                        categories['api_endpoints'].append(item)
                    elif '/admin' in item_lower or '/login' in item_lower:
                        categories['interesting_dirs'].append(item)
                    else:
                        categories['other_found'].append(item)
                        
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao analisar resultados: {e}{Colors.NC}")
    
    return categories

def generate_report(output_file: str, url: str, categories: Dict) -> None:
    """Gera um relatório detalhado com os resultados da varredura"""
    print(f"\n{Colors.GREEN}╔══════════════════════════════════════════╗")
    print(f"║             RELATÓRIO FINALIZADO           ║")
    print(f"╚══════════════════════════════════════════╝{Colors.NC}")
    
    print(f"\n{Colors.CYAN}Alvo:{Colors.NC} {url}")
    print(f"{Colors.CYAN}Arquivo de saída:{Colors.NC} {output_file}")
    
    if not os.path.isfile(output_file):
        print(f"{Colors.RED}[ERRO] Arquivo de resultados não encontrado!{Colors.NC}")
        return
    
    # Estatísticas
    total_found = sum(len(items) for items in categories.values())
    
    print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
    print(f"║               ESTATÍSTICAS              ║")
    print(f"╚══════════════════════════════════════════╝{Colors.NC}")
    print(f"{Colors.MAGENTA}Total de itens encontrados:{Colors.NC} {total_found}")
    print(f"{Colors.MAGENTA}Painéis administrativos:{Colors.NC} {len(categories['admin_panels'])}")
    print(f"{Colors.MAGENTA}Páginas de login:{Colors.NC} {len(categories['login_pages'])}")
    print(f"{Colors.MAGENTA}Arquivos de backup:{Colors.NC} {len(categories['backup_files'])}")
    print(f"{Colors.MAGENTA}Arquivos de configuração:{Colors.NC} {len(categories['config_files'])}")
    print(f"{Colors.MAGENTA}Endpoints API:{Colors.NC} {len(categories['api_endpoints'])}")
    print(f"{Colors.MAGENTA}Diretórios interessantes:{Colors.NC} {len(categories['interesting_dirs'])}")
    
    # Mostrar itens mais importantes
    important_categories = ['admin_panels', 'login_pages', 'backup_files', 'config_files']
    
    for category in important_categories:
        if categories[category]:
            print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
            print(f"║           {category.upper().replace('_', ' '):<16}        ║")
            print(f"╚══════════════════════════════════════════╝{Colors.NC}")
            for item in categories[category][:10]:  # Mostra apenas os 10 primeiros
                print(f"{Colors.GREEN}✓ {item}{Colors.NC}")
    
    # Salvar relatório detalhado
    report_file = output_file.replace('.txt', '_report.json')
    try:
        with open(report_file, 'w') as f:
            json.dump({
                'target': url,
                'scan_date': datetime.now().isoformat(),
                'results_file': output_file,
                'categories': categories,
                'statistics': {
                    'total_found': total_found,
                    'admin_panels': len(categories['admin_panels']),
                    'login_pages': len(categories['login_pages']),
                    'backup_files': len(categories['backup_files']),
                    'config_files': len(categories['config_files']),
                    'api_endpoints': len(categories['api_endpoints']),
                    'interesting_dirs': len(categories['interesting_dirs'])
                }
            }, f, indent=2)
        print(f"\n{Colors.GREEN}[+] Relatório detalhado salvo: {report_file}{Colors.NC}")
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao salvar relatório: {e}{Colors.NC}")

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
    
    cmd = ['dirb', url, wordlist, '-o', output_file, '-S', '-r']  # -S para mostrar não encontrados, -r para não recursivo
    
    if extensions:
        cmd.extend(extensions.split())
    
    if options:
        cmd.extend(options.split())
    
    print(f"\n{Colors.YELLOW}[*] Comando executado:{Colors.NC}")
    print(f"{Colors.BLUE}{' '.join(cmd)}{Colors.NC}")
    
    print(f"\n{Colors.MAGENTA}Iniciando varredura...{Colors.NC}")
    print(f"{Colors.YELLOW}[!] Esta operação pode levar vários minutos...{Colors.NC}")
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Mostra o spinner de progresso em uma thread separada
        progress_thread = threading.Thread(target=show_progress, args=(process,))
        progress_thread.start()
        
        # Espera o processo terminar
        process.wait()
        progress_thread.join()
        
        # Analisa e gera relatório
        categories = analyze_results(output_file)
        generate_report(output_file, url, categories)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Varredura interrompida pelo usuário.{Colors.NC}")
        try:
            process.terminate()
        except:
            pass
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao executar DIRB: {e}{Colors.NC}")

def quick_admin_scan(url: str) -> None:
    """Executa uma varredura rápida focada em URLs administrativas"""
    print(f"\n{Colors.YELLOW}[*] Iniciando varredura rápida para URLs administrativas...{Colors.NC}")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    admin_wordlist = create_custom_wordlist('admin')
    
    if admin_wordlist:
        run_dirb(url, admin_wordlist, f"quick_admin_scan_{timestamp}.txt", 
                "-X .php,.html,.asp,.aspx,.jsp", "-z 100")

def deep_scan(url: str) -> None:
    """Executa uma varredura completa e profunda"""
    print(f"\n{Colors.YELLOW}[*] Iniciando varredura profunda...{Colors.NC}")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    combined_wordlist = create_custom_wordlist('combined')
    
    if combined_wordlist:
        run_dirb(url, combined_wordlist, f"deep_scan_{timestamp}.txt",
                "-X .php,.html,.asp,.aspx,.jsp,.bak,.old,.backup,.sql,.xml,.json,.conf,.config,.ini,.yml,.yaml",
                "-z 50")

def predefined_scans(url: str, scan_type: int) -> None:
    """Executa varreduras pré-definidas baseadas no tipo"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if scan_type == 1:  # Rápida Admin
        quick_admin_scan(url)
    elif scan_type == 2:  # Básica
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_basic_{timestamp}.txt", "", "-z 100")
    elif scan_type == 3:  # Com extensões
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_ext_{timestamp}.txt", "-X .php,.html,.js,.txt,.asp,.aspx", "-z 100")
    elif scan_type == 4:  # Agressiva
        run_dirb(url, CONFIG['WORDLIST_BIG'], f"dirb_aggressive_{timestamp}.txt", "", "-z 50")
    elif scan_type == 5:  # PHP
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_php_{timestamp}.txt", "-X .php,.php3,.php4,.php5,.phtml,.phar", "-z 100")
    elif scan_type == 6:  # ASP
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_asp_{timestamp}.txt", "-X .asp,.aspx,.ashx,.asmx,.ascx", "-z 100")
    elif scan_type == 7:  # Backup
        run_dirb(url, CONFIG['WORDLIST_COMMON'], f"dirb_backup_{timestamp}.txt", "-X .bak,.old,.backup,.swp,.sav,.tmp", "-z 100")
    elif scan_type == 8:  # Profunda
        deep_scan(url)

def main_menu() -> None:
    """Exibe o menu principal e gerencia a interação do usuário"""
    while True:
        print(f"\n{Colors.YELLOW}╔══════════════════════════════════════════╗")
        print(f"║          MENU PRINCIPAL - DIRB SCANNER      ║")
        print(f"╚══════════════════════════════════════════╝{Colors.NC}")
        print(f"{Colors.CYAN}1. Varredura Rápida (Admin/Login){Colors.NC}")
        print(f"{Colors.CYAN}2. Varredura Básica{Colors.NC}")
        print(f"{Colors.CYAN}3. Varredura com Extensões Comuns{Colors.NC}")
        print(f"{Colors.CYAN}4. Varredura Agressiva{Colors.NC}")
        print(f"{Colors.CYAN}5. Varredura para Arquivos PHP{Colors.NC}")
        print(f"{Colors.CYAN}6. Varredura para Arquivos ASP/ASPX{Colors.NC}")
        print(f"{Colors.CYAN}7. Varredura para Arquivos de Backup{Colors.NC}")
        print(f"{Colors.CYAN}8. Varredura Profunda Completa{Colors.NC}")
        print(f"{Colors.CYAN}9. Varredura Personalizada{Colors.NC}")
        print(f"{Colors.RED}0. Sair{Colors.NC}")
        
        try:
            choice = input("Opção [0-9]: ").strip()
            
            if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
                url = input("Digite a URL alvo (ex: example.com): ").strip()
                accessible, final_url = check_target(url)
                if accessible:
                    predefined_scans(final_url, int(choice))
            elif choice == '9':
                url = input("Digite a URL alvo (ex: example.com): ").strip()
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
                    print(f" - {Colors.CYAN}-H 'User-Agent: Custom'{Colors.NC} (customizar User-Agent)")
                    options = input("Digite opções adicionais: ").strip()
                    
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    run_dirb(final_url, wordlist, f"dirb_custom_{timestamp}.txt", extensions, options)
            elif choice == '0':
                print(f"\n{Colors.GREEN}Encerrando o DIRB Scanner...{Colors.NC}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}Opção inválida! Tente novamente.{Colors.NC}")
            
            input("\nPressione Enter para continuar...")
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
    
    # Desativar warnings de SSL para requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript interrompido pelo usuário.")
        sys.exit(0)
