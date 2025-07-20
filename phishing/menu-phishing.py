#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import subprocess
import zipfile
from io import BytesIO
from colorama import init, Fore, Style

init(autoreset=True)

class PhishingToolkit:
    def __init__(self):
        self.repo_dir = "PhishingTools"
        self.tools = {
            "1": {"name": "SocialFish", "repo": "https://github.com/UndeadSec/SocialFish"},
            "2": {"name": "HiddenEye", "repo": "https://github.com/DarkSecDevelopers/HiddenEye"},
            "3": {"name": "Zphisher", "repo": "https://github.com/htr-tech/zphisher"},
            "4": {"name": "BlackPhish", "repo": "https://github.com/iinc0gnit0/BlackPhish"},
            "5": {"name": "PhishX", "repo": "https://github.com/RevengeComing/PhishX"},
            "6": {"name": "PyPhisher", "repo": "https://github.com/KasRoudra/PyPhisher"},
            "7": {"name": "ShellPhish", "repo": "https://github.com/thelinuxchoice/shellphish"},
            "8": {"name": "NexPhisher", "repo": "https://github.com/htr-tech/nexphisher"},
            "9": {"name": "AnglerPhish", "repo": "https://github.com/DeepSociety/AnglerPhish"},
            "10": {"name": "Evilginx2", "repo": "https://github.com/kgretzky/evilginx2"},
            "11": {"name": "Modlishka", "repo": "https://github.com/drk1wi/Modlishka"},
            "12": {"name": "Gophish", "repo": "https://github.com/gophish/gophish"},
            "13": {"name": "KingPhisher", "repo": "https://github.com/rsmusllp/king-phisher"},
            "14": {"name": "PhishLulz", "repo": "https://github.com/PHISHSECURITY/PhishLulz"},
            "15": {"name": "iPhish", "repo": "https://github.com/UndeadSec/iPhish"},
            "16": {"name": "PhishBait", "repo": "https://github.com/An0nUD4Y/PhishBait"},
            "17": {"name": "PhishMailer", "repo": "https://github.com/BiZken/PhishMailer"},
            "18": {"name": "PhishX", "repo": "https://github.com/tatanus/PhishX"},
            "19": {"name": "PhishTales", "repo": "https://github.com/azizaltuntas/PhishTales"},
            "20": {"name": "PhishStorm", "repo": "https://github.com/An0nUD4Y/PhishStorm"}
        }
        self._setup_repository()

    def _setup_repository(self):
        """Cria a estrutura de diretórios"""
        if not os.path.exists(self.repo_dir):
            os.makedirs(self.repo_dir)
            print(Fore.GREEN + "[+] Diretório criado: " + self.repo_dir)

    def _print_banner(self):
        """Exibe o banner minimalista"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.GREEN + r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
""" + Style.RESET_ALL)

    def _download_tool(self, tool):
        """Baixa e instala a ferramenta"""
        try:
            tool_dir = os.path.join(self.repo_dir, tool["name"])
            if not os.path.exists(tool_dir):
                os.makedirs(tool_dir)

            print(Fore.CYAN + f"\n[+] Baixando {tool['name']}...")
            
            # Tenta baixar via git clone
            if self._git_clone(tool["repo"], tool_dir):
                print(Fore.GREEN + f"[✓] {tool['name']} instalado com sucesso!")
                self._run_tool(tool_dir)
            else:
                # Fallback para download ZIP
                self._download_zip(tool["repo"], tool_dir)
                
        except Exception as e:
            print(Fore.RED + f"[!] Erro: {str(e)}")

    def _git_clone(self, repo_url, target_dir):
        """Tenta clonar via git"""
        try:
            subprocess.run(["git", "clone", repo_url, target_dir], check=True)
            return True
        except:
            return False

    def _download_zip(self, repo_url, target_dir):
        """Fallback para download ZIP"""
        try:
            zip_url = repo_url + "/archive/master.zip"
            response = requests.get(zip_url)
            
            if response.status_code == 200:
                with zipfile.ZipFile(BytesIO(response.content)) as zip_ref:
                    zip_ref.extractall(target_dir)
                print(Fore.GREEN + f"[✓] {os.path.basename(repo_url)} baixado!")
                self._run_tool(target_dir)
            else:
                print(Fore.RED + "[!] Falha no download. Abrindo navegador...")
                webbrowser.open(repo_url)
        except:
            print(Fore.RED + "[!] Erro no download ZIP. Abrindo navegador...")
            webbrowser.open(repo_url)

    def _run_tool(self, tool_dir):
        """Tenta executar a ferramenta após instalação"""
        print(Fore.YELLOW + "\n[i] Procurando arquivo de instalação...")
        
        # Verifica arquivos comuns de instalação
        possible_files = ["install.sh", "setup.py", "tool.py", "main.py"]
        
        for file in possible_files:
            file_path = os.path.join(tool_dir, file)
            if os.path.exists(file_path):
                print(Fore.GREEN + f"[+] Arquivo encontrado: {file}")
                try:
                    os.chdir(tool_dir)
                    if file.endswith(".sh"):
                        subprocess.run(["bash", file])
                    elif file.endswith(".py"):
                        subprocess.run(["python3", file])
                    return
                except Exception as e:
                    print(Fore.RED + f"[!] Erro ao executar: {str(e)}")
        
        print(Fore.YELLOW + "[i] Nenhum script de instalação encontrado.")
        print(Fore.CYAN + "[i] Verifique o README.md para instruções.")

    def _show_menu(self):
        """Exibe o menu de ferramentas"""
        print(Fore.GREEN + "\n[+] FERRAMENTAS DISPONÍVEIS [+]\n")
        
        # Menu em 2 colunas
        for i in range(0, 20, 2):
            left = f"{Fore.YELLOW}[{i+1}] {self.tools[str(i+1)]['name']}"
            right = f"{Fore.YELLOW}[{i+2}] {self.tools[str(i+2)]['name']}" if i+2 <= 20 else ""
            print(f"{left.ljust(30)}{right}")
        
        print(Fore.RED + "\n[0] Sair" + Style.RESET_ALL)

    def run(self):
        """Executa o menu principal"""
        while True:
            self._print_banner()
            self._show_menu()
            
            choice = input(Fore.BLUE + "\n[?] Selecione uma ferramenta (1-20): " + Style.RESET_ALL)
            
            if choice == "0":
                print(Fore.GREEN + "\n[+] Saindo..." + Style.RESET_ALL)
                break
                
            if choice in self.tools:
                self._download_tool(self.tools[choice])
            else:
                print(Fore.RED + "[!] Opção inválida!")
            
            input(Fore.YELLOW + "\n[i] Pressione Enter para continuar..." + Style.RESET_ALL)

if __name__ == '__main__':
    toolkit = PhishingToolkit()
    toolkit.run()
