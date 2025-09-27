#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

class OSINTMenu:
    def __init__(self):
        self.base_dir = "osint_tools"
        self.tools_installed = False
        self.check_installation()
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""
{Fore.RED}
▓█████▄  ██▀███   █    ██  ███▄    █ ▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    
 ░ ░  ░   ░░   ░  ░░░ ░ ░    ░   ░ ░   ░      
   ░       ░        ░              ░          
 ░                                          
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    MENU HACKER OSINT v2.0                    ║
║                 Ferramentas de Inteligência                  ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def create_base_dir(self):
        """Cria o diretório base para as ferramentas"""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
            print(f"{Fore.GREEN}[+] Diretório {self.base_dir} criado!{Style.RESET_ALL}")
    
    def check_installation(self):
        """Verifica se as ferramentas já estão instaladas"""
        self.create_base_dir()
        
        tools_dirs = [
            os.path.join(self.base_dir, "mosint"),
            os.path.join(self.base_dir, "IP-Tracer"), 
            os.path.join(self.base_dir, "Mr.Holmes"),
            os.path.join(self.base_dir, "Zehef"),
            os.path.join(self.base_dir, "yesitsme"),
            os.path.join(self.base_dir, "Eyes")
        ]
        
        all_installed = all(os.path.exists(dir_path) for dir_path in tools_dirs)
        self.tools_installed = all_installed
    
    def run_command(self, command, tool_name):
        """Executa um comando e trata erros"""
        try:
            print(f"{Fore.YELLOW}[*] Executando: {command}{Style.RESET_ALL}")
            process = subprocess.run(command, shell=True, cwd=self.base_dir, 
                                   capture_output=True, text=True, timeout=300)
            
            if process.returncode == 0:
                print(f"{Fore.GREEN}[+] {tool_name} - Comando executado com sucesso!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] {tool_name} - Erro no comando:{Style.RESET_ALL}")
                print(f"{Fore.RED}Erro: {process.stderr}{Style.RESET_ALL}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] {tool_name} - Timeout no comando{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] {tool_name} - Erro: {e}{Style.RESET_ALL}")
            return False
    
    def install_tools(self):
        """Instala todas as ferramentas necessárias"""
        if self.tools_installed:
            print(f"{Fore.GREEN}[+] Todas as ferramentas já estão instaladas!{Style.RESET_ALL}")
            return True
        
        print(f"{Fore.YELLOW}[!] Instalando ferramentas OSINT em {self.base_dir}/...{Style.RESET_ALL}")
        
        tools = [
            {
                "name": "mosint",
                "url": "https://github.com/alpkeskin/mosint.git",
                "commands": [
                    "git clone https://github.com/alpkeskin/mosint.git",
                    "cd mosint && pip3 install -r requirements.txt"
                ]
            },
            {
                "name": "IP-Tracer",
                "url": "https://github.com/rajkumardusad/IP-Tracer.git",
                "commands": [
                    "git clone https://github.com/rajkumardusad/IP-Tracer.git",
                    "cd IP-Tracer && chmod +x install && bash install"
                ]
            },
            {
                "name": "Mr.Holmes",
                "url": "https://github.com/Lucksi/Mr.Holmes.git",
                "commands": [
                    "git clone https://github.com/Lucksi/Mr.Holmes.git",
                    "cd Mr.Holmes && pip3 install -r requirements.txt"
                ]
            },
            {
                "name": "Zehef",
                "url": "https://github.com/N0rz3/Zehef.git",
                "commands": [
                    "git clone https://github.com/N0rz3/Zehef.git",
                    "cd Zehef && pip3 install -r requirements.txt"
                ]
            },
            {
                "name": "yesitsme",
                "url": "https://github.com/blackeko/yesitsme.git",
                "commands": [
                    "git clone https://github.com/blackeko/yesitsme.git",
                    "cd yesitsme && pip3 install -r requirements.txt"
                ]
            },
            {
                "name": "Eyes",
                "url": "https://github.com/N0rz3/Eyes.git",
                "commands": [
                    "git clone https://github.com/N0rz3/Eyes.git",
                    "cd Eyes && pip3 install -r requirements.txt"
                ]
            }
        ]
        
        for tool in tools:
            tool_path = os.path.join(self.base_dir, tool["name"])
            if not os.path.exists(tool_path):
                print(f"\n{Fore.CYAN}[*] Instalando {tool['name']}...{Style.RESET_ALL}")
                
                success = True
                for cmd in tool["commands"]:
                    if not self.run_command(cmd, tool["name"]):
                        success = False
                        break
                
                if success:
                    print(f"{Fore.GREEN}[+] {tool['name']} instalado com sucesso!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Falha na instalação de {tool['name']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] {tool['name']} já está instalado.{Style.RESET_ALL}")
        
        self.tools_installed = True
        print(f"\n{Fore.GREEN}[+] Instalação concluída!{Style.RESET_ALL}")
    
    def run_mosint(self):
        """Executa a ferramenta mosint"""
        tool_path = os.path.join(self.base_dir, "mosint")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] mosint não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando mosint...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Comandos disponíveis:{Style.RESET_ALL}")
        print("1. Verificação básica de email")
        print("2. Verificação completa de email") 
        print("3. Verificação com validação")
        print("4. Verificação com todas as fontes")
        
        choice = input(f"\n{Fore.GREEN}Escolha uma opção (1-4): {Style.RESET_ALL}")
        email = input(f"{Fore.GREEN}Digite o email alvo: {Style.RESET_ALL}")
        
        commands = {
            "1": f"cd {tool_path} && python3 mosint.py {email}",
            "2": f"cd {tool_path} && python3 mosint.py {email} --all",
            "3": f"cd {tool_path} && python3 mosint.py {email} --validate",
            "4": f"cd {tool_path} && python3 mosint.py {email} --full"
        }
        
        if choice in commands:
            os.system(commands[choice])
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
    
    def run_ip_tracer(self):
        """Executa a ferramenta IP-Tracer"""
        tool_path = os.path.join(self.base_dir, "IP-Tracer")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] IP-Tracer não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando IP-Tracer...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Comandos disponíveis:{Style.RESET_ALL}")
        print("1. Trace IP (trace -m)")
        print("2. Trace IP específico (trace -p IP)")
        print("3. Iniciar modo interativo (trace start)")
        
        choice = input(f"\n{Fore.GREEN}Escolha uma opção (1-3): {Style.RESET_ALL}")
        
        if choice == "1":
            os.system(f"cd {tool_path} && trace -m")
        elif choice == "2":
            ip = input(f"{Fore.GREEN}Digite o IP: {Style.RESET_ALL}")
            os.system(f"cd {tool_path} && trace -p {ip}")
        elif choice == "3":
            os.system(f"cd {tool_path} && trace start")
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
    
    def run_mr_holmes(self):
        """Executa a ferramenta Mr.Holmes"""
        tool_path = os.path.join(self.base_dir, "Mr.Holmes")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] Mr.Holmes não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando Mr.Holmes...{Style.RESET_ALL}")
        os.system(f"cd {tool_path} && python3 mrholmes.py")
    
    def run_zehef(self):
        """Executa a ferramenta Zehef"""
        tool_path = os.path.join(self.base_dir, "Zehef")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] Zehef não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando Zehef...{Style.RESET_ALL}")
        email = input(f"{Fore.GREEN}Digite o email para investigação: {Style.RESET_ALL}")
        os.system(f"cd {tool_path} && python3 zehef.py {email}")
    
    def run_yesitsme(self):
        """Executa a ferramenta yesitsme"""
        tool_path = os.path.join(self.base_dir, "yesitsme")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] yesitsme não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando yesitsme...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Parâmetros necessários:{Style.RESET_ALL}")
        
        session_id = input("SESSION_ID (ou Enter para pular): ")
        name = input("NAME (ou Enter para pular): ")
        email = input("EMAIL (ou Enter para pular): ")
        phone = input("PHONE (ou Enter para pular): ")
        timeout = input("TIMEOUT (padrão: 10): ") or "10"
        
        cmd = f"cd {tool_path} && python3 yesitsme.py"
        if session_id: cmd += f" -s {session_id}"
        if name: cmd += f" -n '{name}'"
        if email: cmd += f" -e {email}"
        if phone: cmd += f" -p {phone}"
        cmd += f" -t {timeout}"
        
        os.system(cmd)
    
    def run_eyes(self):
        """Executa a ferramenta Eyes"""
        tool_path = os.path.join(self.base_dir, "Eyes")
        if not os.path.exists(tool_path):
            print(f"{Fore.RED}[!] Eyes não encontrado! Instale primeiro.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Executando Eyes...{Style.RESET_ALL}")
        print("1. Pesquisar email")
        print("2. Listar módulos")
        
        choice = input(f"\n{Fore.GREEN}Escolha uma opção (1-2): {Style.RESET_ALL}")
        
        if choice == "1":
            email = input(f"{Fore.GREEN}Digite o email: {Style.RESET_ALL}")
            os.system(f"cd {tool_path} && python3 eyes.py {email}")
        elif choice == "2":
            os.system(f"cd {tool_path} && python3 eyes.py -m")
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
    
    def show_status(self):
        """Mostra status das instalações"""
        print(f"\n{Fore.CYAN}[*] Status das ferramentas:{Style.RESET_ALL}")
        
        tools = [
            ("mosint", "Mosint - Email Intelligence"),
            ("IP-Tracer", "IP-Tracer - Rastreamento de IP"),
            ("Mr.Holmes", "Mr.Holmes - Painel OSINT"),
            ("Zehef", "Zehef - Investigação de Email"),
            ("yesitsme", "YesItsMe - Investigação de Perfis"),
            ("Eyes", "Eyes - Análise de Email")
        ]
        
        for tool_dir, tool_name in tools:
            tool_path = os.path.join(self.base_dir, tool_dir)
            if os.path.exists(tool_path):
                print(f"{Fore.GREEN}[✓] {tool_name} - Instalado{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[✗] {tool_name} - Não instalado{Style.RESET_ALL}")
    
    def show_menu(self):
        """Exibe o menu principal"""
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                         MENU PRINCIPAL                         ║
╠══════════════════════════════════════════════════════════════╣
║ {Fore.GREEN}1.{Fore.CYAN}  Instalar/Atualizar Ferramentas               {Fore.CYAN}        ║
║ {Fore.GREEN}2.{Fore.CYAN}  Mosint - Email Intelligence                  {Fore.CYAN}        ║
║ {Fore.GREEN}3.{Fore.CYAN}  IP-Tracer - Rastreamento de IP               {Fore.CYAN}        ║
║ {Fore.GREEN}4.{Fore.CYAN}  Mr.Holmes - Painel OSINT                     {Fore.CYAN}        ║
║ {Fore.GREEN}5.{Fore.CYAN}  Zehef - Investigação de Email                {Fore.CYAN}        ║
║ {Fore.GREEN}6.{Fore.CYAN}  YesItsMe - Investigação de Perfis            {Fore.CYAN}        ║
║ {Fore.GREEN}7.{Fore.CYAN}  Eyes - Análise Completa de Email             {Fore.CYAN}        ║
║ {Fore.GREEN}8.{Fore.CYAN}  Status das Instalações                       {Fore.CYAN}        ║
║ {Fore.GREEN}9.{Fore.CYAN}  Sair                                        {Fore.CYAN}        ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(menu)
    
    def main(self):
        """Função principal"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_menu()
            
            choice = input(f"{Fore.GREEN}Escolha uma opção (1-9): {Style.RESET_ALL}")
            
            if choice == "1":
                self.install_tools()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "2":
                self.run_mosint()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "3":
                self.run_ip_tracer()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "4":
                self.run_mr_holmes()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "5":
                self.run_zehef()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "6":
                self.run_yesitsme()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "7":
                self.run_eyes()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "8":
                self.show_status()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "9":
                print(f"{Fore.RED}\n[!] Saindo... Até logo!{Style.RESET_ALL}")
                break
            
            else:
                print(f"{Fore.RED}[!] Opção inválida! Tente novamente.{Style.RESET_ALL}")
                time.sleep(2)

if __name__ == "__main__":
    # Verificar se o Python3 está instalado
    try:
        subprocess.run(["python3", "--version"], capture_output=True, check=True)
    except:
        print(f"{Fore.RED}[!] Python3 não encontrado! Instale primeiro.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Verificar se o git está instalado
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except:
        print(f"{Fore.RED}[!] Git não encontrado! Instale primeiro.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Instalar colorama se necessário
    try:
        import colorama
    except ImportError:
        print(f"{Fore.YELLOW}[!] Instalando colorama...{Style.RESET_ALL}")
        subprocess.run(["pip3", "install", "colorama"], check=True)
        import colorama
    
    menu = OSINTMenu()
    menu.main()
