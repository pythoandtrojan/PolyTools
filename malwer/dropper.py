#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import time
from typing import Tuple
from pathlib import Path

class FileSender:
    DEFAULT_IP = "192.168.1.100"
    DEFAULT_PORT = 5555
    BUFFER_SIZE = 4096  
    
    def __init__(self):
        self.ip = self.DEFAULT_IP
        self.port = self.DEFAULT_PORT
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura os elementos visuais e cores"""
        self.colors = {
            'header': '\033[1;35m',
            'option': '\033[1;36m',
            'input': '\033[1;37m',
            'success': '\033[1;32m',
            'error': '\033[1;31m',
            'warning': '\033[1;33m',
            'info': '\033[1;34m',
            'reset': '\033[0m'
        }
        
        self.banner = f"""
        {self.colors['header']}
   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣴⣶⣾⡿⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠿⢿⣷⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⢟⡽⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⡿⣿⣷⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⠟⣱⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡌⢻⣿⣿⣦⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⠏⣰⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⢹⣿⣿⣷⡄⠀
⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⡗⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠀⢻⣿⣿⣷⡄
⠀⠀⠀⠀⠀⠀⣼⣿⣯⣿⠉⠁⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⢩⣿⣾⣿⡇
⠀⠀⠀⠀⠀⠀⣿⣿⠿⠟⠂⠀⢹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡇⠀⢚⡿⢿⣿⣿
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣦⡤⠞⢻⣦⡀⠀⠀⠀⠀⣀⣤⣤⠖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠶⣤⣄⡀⠀⠀⠀⠀⢀⣼⠏⠐⢤⣼⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⢿⣿⣿⣯⣥⡀⣠⠔⠛⢿⣦⣤⣴⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⣦⣤⣴⠿⠋⠣⣄⢠⣬⣿⣿⣿⡏
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⠟⣁⠀⢀⡄⠈⠛⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⡿⠛⠁⢦⠀⠀⣙⢿⣿⣿⣿⣿⠃
⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣷⣿⣿⣷⠞⠀⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⠀⠈⠳⣾⣿⣿⣾⣿⡿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣟⣥⣾⣿⡖⣰⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣄⣶⣿⣷⣽⣿⣿⣿⡿⠃⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣯⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣯⣻⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟⠿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⠿⢻⣧⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⢠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠄⢸⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠇⠀⠀⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠘⣧⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡟⠀⠀⠀⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣷⠀⣈⣇⣿⠈⢷⣄⠀⠀⠀⠀⠀⠠⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠀⠀⠀⠀⠀⢀⣠⠟⢸⣧⡖⡀⢰⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡀⢸⣿⡿⠀⠈⠻⣷⣶⣤⣄⣀⡀⠈⠙⣷⣶⣀⠀⠀⠀⠀⣠⣶⡿⠋⠀⣀⣀⣤⣴⣶⣿⠋⠀⠸⣿⣿⠃⢸⡏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠃⢈⣴⣿⣿⣿⣿⣿⣿⣿⣶⣄⠈⠿⣿⠃⠀⠀⠸⣿⠋⢀⣤⣾⣿⣿⣿⣿⣿⣿⣷⣦⠀⢹⣿⠀⣸⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⢸⣇⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠷⡁⠁⠀⠀⠀⠀⠉⣠⠾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠆⢀⣿⢠⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠇⢻⡆⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⢸⠏⠾⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠃⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⣰⣿⣿⡀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠹⠄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠀⠀⠀⠀⠀⠙⠿⠿⠿⠿⠿⠟⠁⠀⠀⢀⣿⣿⣿⣷⠀⠀⠀⠙⠿⠿⠿⠿⠿⠟⠉⠀⠀⠀⠀⠰⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⡿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⡇⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣦⣤⣄⣀⣤⣤⣄⡀⠀⠀⠀⠀⠈⠻⣿⡿⠁⢹⣿⡿⠋⠀⠀⠀⠀⠀⣀⣤⣤⣤⣀⣤⣤⣾⡿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠋⣿⣿⣿⣿⣿⡛⠢⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠚⢻⣿⣿⣿⣿⣟⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢹⢹⢻⣿⣷⣰⢠⠀⠀⠀⡄⠀⠀⠀⠀⡄⠀⠀⠀⡄⣤⣿⣿⠁⢹⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣸⡘⢸⣿⣿⣿⡟⠳⣧⣤⣿⠒⣾⡶⠚⣿⠤⣿⠛⣷⣿⣿⣿⠀⢸⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⠀⠋⠃⠘⣿⡟⢿⣧⠀⡇⠀⣧⡀⢸⠀⠀⣿⠀⣿⠀⣿⡿⣿⣿⠀⠋⠋⠀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣄⠀⠀⠀⠙⢷⣴⡉⣛⠻⠿⢿⣧⡼⢷⣤⠿⠿⠿⠛⠸⣤⠟⠃⠀⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣆⠀⠀⠀⠀⠋⠛⢿⣤⣾⣠⣇⣸⣄⣷⣀⣷⣤⢷⠚⠛⠀⠀⠀⢀⣴⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⣦⣄⠀⠀⠀⠀⠘⠁⠘⠉⠉⠉⠙⠀⠈⠀⠀⠀⠀⠀⣤⡶⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣧⣀⣠⣶⣶⣶⣦⣄⣠⡾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                                           
        >> Envio Seguro de Arquivos <<
        >>   Termux | No Root       <<
        {self.colors['reset']}
        """
        
        self.menu_options = [
            ("Enviar Arquivo", self.send_file),
            ("Configurar IP e Porta", self.configure_network),
            ("Sobre", self.show_about),
            ("Sair", self.exit_app)
        ]

    def clear_screen(self):
        """Limpa a tela de forma multiplataforma"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        """Exibe o banner centralizado"""
        self.clear_screen()
        print(self.banner)
    
    def show_menu(self) -> int:
        """Exibe o menu principal e retorna a escolha do usuário"""
        self.show_banner()
        
        for i, (option, _) in enumerate(self.menu_options, 1):
            print(f"{self.colors['option']}[{i}]{self.colors['reset']} {option}")
        
        try:
            choice = int(input(f"\n{self.colors['input']}FileSender>{self.colors['reset']} "))
            if 1 <= choice <= len(self.menu_options):
                return choice
            raise ValueError
        except ValueError:
            self.show_error("Opção inválida! Por favor, tente novamente.")
            return self.show_menu()
    
    def configure_network(self):
        """Configura o endereço IP e porta de destino"""
        self.show_banner()
        print(f"{self.colors['info']}Configurações atuais:")
        print(f"IP: {self.ip}")
        print(f"Porta: {self.port}{self.colors['reset']}\n")
        
        try:
            self.ip = input(f"{self.colors['input']}[+] Novo IP ({self.ip}): {self.colors['reset']}") or self.ip
            port_input = input(f"{self.colors['input']}[+] Nova Porta ({self.port}): {self.colors['reset']}")
            self.port = int(port_input) if port_input else self.port
            
            self.show_success("Configurações atualizadas com sucesso!")
        except ValueError:
            self.show_error("Porta deve ser um número inteiro!")
    
    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """Valida se o arquivo existe e é acessível"""
        path = Path(file_path)
        if not path.exists():
            return False, "Arquivo não encontrado!"
        if not path.is_file():
            return False, "O caminho especificado não é um arquivo!"
        if not os.access(file_path, os.R_OK):
            return False, "Permissão negada para ler o arquivo!"
        return True, ""
    
    def send_file(self):
        """Envia o arquivo para o destino configurado"""
        self.show_banner()
        print(f"{self.colors['info']}Configuração atual:")
        print(f"Destino: {self.ip}:{self.port}{self.colors['reset']}\n")
        
        file_path = input(f"{self.colors['input']}[+] Caminho do arquivo: {self.colors['reset']}")
        valid, message = self.validate_file(file_path)
        
        if not valid:
            self.show_error(message)
            return
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)  # Timeout de 10 segundos
                
                try:
                    s.connect((self.ip, self.port))
                except socket.error as e:
                    self.show_error(f"Não foi possível conectar ao destino: {e}")
                    return
                
                # Envia metadados
                s.sendall(f"{file_name}\n{file_size}\n".encode())
                
                # Barra de progresso
                self.show_progress(0, file_size)
                
                # Envia o arquivo
                sent_bytes = 0
                with open(file_path, 'rb') as f:
                    while True:
                        data = f.read(self.BUFFER_SIZE)
                        if not data:
                            break
                        s.sendall(data)
                        sent_bytes += len(data)
                        self.show_progress(sent_bytes, file_size)
                
                self.show_success(f"\nArquivo '{file_name}' ({self._human_readable_size(file_size)}) enviado com sucesso!")
        
        except Exception as e:
            self.show_error(f"Erro durante o envio: {str(e)}")
    
    def show_progress(self, sent: int, total: int):
        """Exibe uma barra de progresso"""
        percent = (sent / total) * 100
        bar_length = 30
        filled_length = int(bar_length * sent // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        sys.stdout.write(f"\r{self.colors['info']}[{bar}] {percent:.1f}% ({self._human_readable_size(sent)}/{self._human_readable_size(total)}){self.colors['reset']}")
        sys.stdout.flush()
    
    def _human_readable_size(self, size: int) -> str:
        """Converte bytes para formato legível"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def show_about(self):
        """Exibe informações sobre o aplicativo"""
        self.show_banner()
        about_text = f"""
        {self.colors['info']}FileSender - Versão 2.0{self.colors['reset']}
        
        Uma ferramenta simples para envio seguro de arquivos via rede.
        Compatível com Termux e não requer root.
        
        Desenvolvido por: [Seu Nome]
        GitHub: [Seu Repositório]
        """
        print(about_text)
        input(f"\n{self.colors['input']}Pressione Enter para voltar...{self.colors['reset']}")
    
    def show_success(self, message: str):
        """Exibe uma mensagem de sucesso"""
        print(f"\n{self.colors['success']}[✓] {message}{self.colors['reset']}")
        time.sleep(1.5)
    
    def show_error(self, message: str):
        """Exibe uma mensagem de erro"""
        print(f"\n{self.colors['error']}[!] {message}{self.colors['reset']}")
        time.sleep(2)
    
    def exit_app(self):
        """Encerra o aplicativo"""
        self.show_banner()
        print(f"\n{self.colors['info']}Obrigado por usar o FileSender!{self.colors['reset']}\n")
        sys.exit(0)
    
    def run(self):
        """Loop principal da aplicação"""
        while True:
            try:
                choice = self.show_menu()
                _, action = self.menu_options[choice - 1]
                action()
            except KeyboardInterrupt:
                self.exit_app()
            except Exception as e:
                self.show_error(f"Erro inesperado: {str(e)}")
                time.sleep(2)

if __name__ == "__main__":
    try:
        app = FileSender()
        app.run()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Interrompido pelo usuário.\033[0m")
        sys.exit(0)
