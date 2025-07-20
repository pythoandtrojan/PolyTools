#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
from colorama import init, Fore, Back, Style
import webbrowser

init()  # Inicializa o Colorama

class SpamToolkit:
    def __init__(self):
        self.tools = {
            "1": {
                "name": "TBomb",
                "repo": "https://github.com/TheSpeedX/TBomb",
                "description": "SMS/call bomber para números internacionais"
            },
            "2": {
                "name": "SpamX",
                "repo": "https://github.com/kartikeyvinayak/SpamX",
                "description": "Spammer para WhatsApp e SMS"
            },
            "3": {
                "name": "SpamCall",
                "repo": "https://github.com/siput12/SpamCall",
                "description": "Ferramenta de spam de chamadas"
            },
            "4": {
                "name": "SpamSMS",
                "repo": "https://github.com/SpamX/SpamSMS",
                "description": "Bombardeio de SMS com múltiplos gateways"
            },
            "5": {
                "name": "WhatsApp-Spammer",
                "repo": "https://github.com/Shinobi8894/WhatsApp-Spammer",
                "description": "Spam automatizado para WhatsApp"
            },
            "6": {
                "name": "Email-Spammer",
                "repo": "https://github.com/Juniorn1003/Email-Spammer",
                "description": "Ferramenta de spam por e-mail"
            },
            "7": {
                "name": "SpamBot",
                "repo": "https://github.com/SpamBot/SpamBot",
                "description": "Bot de spam para redes sociais"
            },
            "8": {
                "name": "SMS-Bomber",
                "repo": "https://github.com/An0nUD4Y/SMS-bomber",
                "description": "Bombardeio de SMS com API rotativa"
            },
            "9": {
                "name": "PySpam",
                "repo": "https://github.com/MatrixTM/PySpam",
                "description": "Kit de spam completo em Python"
            },
            "10": {
                "name": "SpamTools",
                "repo": "https://github.com/SpamX/SpamTools",
                "description": "Coleção de ferramentas de spam"
            },
            "11": {
                "name": "CallBomber",
                "repo": "https://github.com/SpamX/CallBomber",
                "description": "Bombardeio de chamadas telefônicas"
            },
            "12": {
                "name": "WhatsBomber",
                "repo": "https://github.com/SpamX/WhatsBomber",
                "description": "Bombardeio de mensagens no WhatsApp"
            },
            "13": {
                "name": "Telegram-Spam",
                "repo": "https://github.com/SpamX/Telegram-Spam",
                "description": "Spam para Telegram"
            },
            "14": {
                "name": "Instagram-Spammer",
                "repo": "https://github.com/SpamX/Instagram-Spammer",
                "description": "Ferramenta de spam para Instagram"
            },
            "15": {
                "name": "Facebook-Spammer",
                "repo": "https://github.com/SpamX/Facebook-Spammer",
                "description": "Ferramenta de spam para Facebook"
            },
            "16": {
                "name": "Twitter-Spammer",
                "repo": "https://github.com/SpamX/Twitter-Spammer",
                "description": "Ferramenta de spam para Twitter"
            },
            "17": {
                "name": "Discord-Spammer",
                "repo": "https://github.com/SpamX/Discord-Spammer",
                "description": "Ferramenta de spam para Discord"
            },
            "18": {
                "name": "SMS-Spam",
                "repo": "https://github.com/SpamX/SMS-Spam",
                "description": "Ferramenta de spam por SMS"
            },
            "19": {
                "name": "Email-Bomber",
                "repo": "https://github.com/SpamX/Email-Bomber",
                "description": "Bombardeio de e-mails"
            },
            "20": {
                "name": "Ultimate-Spammer",
                "repo": "https://github.com/SpamX/Ultimate-Spammer",
                "description": "Ferramenta de spam completa"
            }
        }
        self.installed_tools = []

    def _clear_screen(self):
        """Limpa a tela do terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _print_banner(self):
        """Exibe o banner estilizado"""
        self._clear_screen()
        print(Fore.RED + r"""
   _____                       _____ _____          
  / ____|                     / ____|  __ \         
 | (___  _ __   __ _ _ __ ___| (___ | |__) |        
  \___ \| '_ \ / _` | '_ ` _ \\___ \|  ___/         
  ____) | |_) | (_| | | | | | |___) | |            
 |_____/| .__/ \__,_|_| |_| |_|_____/|_|            
        | |                                         
        |_|                                         
""" + Style.RESET_ALL)
        print(Fore.YELLOW + "="*60 + Style.RESET_ALL)
        print(Fore.CYAN + "       FERRAMENTAS DE SPAM - USE COM RESPONSABILIDADE")
        print(Fore.YELLOW + "="*60 + Style.RESET_ALL)

    def _print_menu(self):
        """Exibe o menu de ferramentas"""
        print(Fore.GREEN + "\n[+] MENU DE FERRAMENTAS [+]" + Style.RESET_ALL)
        print(Fore.YELLOW + "|" + "-"*58 + "|" + Style.RESET_ALL)
        
        for key, tool in self.tools.items():
            print(Fore.YELLOW + "|" + Fore.WHITE + f" {key}. {tool['name']}".ljust(30) + 
                  Fore.CYAN + f" {tool['description']}".ljust(28) + Fore.YELLOW + "|" + Style.RESET_ALL)
        
        print(Fore.YELLOW + "|" + "-"*58 + "|" + Style.RESET_ALL)
        print(Fore.YELLOW + "|" + Fore.WHITE + " 0. Sair".ljust(58) + Fore.YELLOW + "|" + Style.RESET_ALL)
        print(Fore.YELLOW + "|" + "-"*58 + "|" + Style.RESET_ALL)

    def _install_tool(self, tool_num):
        """Instala a ferramenta selecionada"""
        try:
            tool = self.tools.get(tool_num)
            if not tool:
                print(Fore.RED + "\n[!] Ferramenta inválida!" + Style.RESET_ALL)
                return
            
            print(Fore.CYAN + f"\n[+] Instalando {tool['name']}..." + Style.RESET_ALL)
            
            # Abre o repositório no navegador para download
            webbrowser.open(tool['repo'])
            
            print(Fore.GREEN + f"\n[✓] {tool['name']} pronto para instalação!" + Style.RESET_ALL)
            print(Fore.YELLOW + f"[i] Visite: {tool['repo']}" + Style.RESET_ALL)
            
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro ao instalar: {str(e)}" + Style.RESET_ALL)

    def run(self):
        """Executa o menu principal"""
        while True:
            try:
                self._print_banner()
                self._print_menu()
                
                choice = input(Fore.BLUE + "\n[?] Selecione uma ferramenta (0-20): " + Style.RESET_ALL)
                
                if choice == "0":
                    print(Fore.GREEN + "\n[+] Saindo..." + Style.RESET_ALL)
                    break
                
                self._install_tool(choice)
                input(Fore.YELLOW + "\n[i] Pressione Enter para continuar..." + Style.RESET_ALL)
                
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Operação cancelada pelo usuário" + Style.RESET_ALL)
                break
            except Exception as e:
                print(Fore.RED + f"\n[!] Erro: {str(e)}" + Style.RESET_ALL)
                time.sleep(2)

if __name__ == '__main__':
    toolkit = SpamToolkit()
    toolkit.run()
