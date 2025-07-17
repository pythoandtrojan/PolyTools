#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import time
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
import webbrowser

console = Console()

class Banners:
    @staticmethod
    def main_menu():
        return """[bold red]
              :-====--:.            .:-=====-.              
           :+************+=-:  :-=+************=.           
         .+****++************.-************++****+.         
        .*+-.     .+*********.-*********=.     .-**.        
        +:          -********.-********-          -=        
       :=            =*******.-*******-            =:       
      ***+            *******.-******+            ****      
      -++:            -++++++.:++++++:            -++:      
                      :==============:                      
                        =.        --                        
                      .-*+:     .:++:.                      
                        :         ..                        
                            -**=           -**=                 
                       =:   =**=   -=                       
                       -*+-.    .-**:                       
                         :=+***++=:                         
        [/bold red]"""

    @staticmethod
    def osint():
        return """
    ██████╗ ███████╗██╗███╗   ██╗████████╗
    ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
    ██║  ██║███████╗██║██╔██╗ ██║   ██║   
    ██║  ██║╚════██║██║██║╚██╗██║   ██║   
    ██████╔╝███████║██║██║ ╚████║   ██║   
    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  
        """

    @staticmethod
    def malware():
        return """
        01101101 01100001 01101100 01110111 01100001 01110010 01100101 00100000 01100001 01100011 01110100 01101001 01110110 01100001 01110100 01100101 01100100
        01011001 01101111 01110101 01110010 00100000 01110011 01111001 01110011 01110100 01100101 01101101 00100000 01101001 01110011 00100000 01101101 01101001 01101110 01100101 00100000 01101110 01101111 01110111
        01010100 01101000 01100101 00100000 01100100 01100001 01110010 01101011 01101110 01100101 01110011 01110011 00100000 01101001 01110011 00100000 01110100 01100001 01101011 01101001 01101110 01100111 00100000 01101111 01110110 01100101 01110010
        """

    @staticmethod
    def scanner():
        return """
        01010011 01000011 01000001 01001110 01001110 01001001 01001110 01000111 00100000 01010000 01001111 01010010 01010100 01010011
        01001001 00100111 01101101 00100000 01110111 01100001 01110100 01100011 01101000 01101001 01101110 01100111 00100000 01111001 01101111 01110101
        01011001 01101111 01110101 00100000 01100011 01100001 01101110 00100111 01110100 00100000 01101000 01101001 01100100 01100101
        """
        
    @staticmethod
    def brute_force():
        return """
        01000010 01010010 01010101 01010100 01000101 00100000 01000110 01001111 01010010 01000011 01000101
        01000011 01010010 01000001 01000011 01001011 01001001 01001110 01000111 00100000 01010000 01000001 01010011 01010011 01010111 01001111 01010010 01000100 01010011
        01010100 01001000 01000101 00100000 01000010 01010010 01010101 01010100 01000101 00100000 01010011 01001000 01000001 01001100 01001100 00100000 01010010 01000101 01001001 01000111 01001110
        """
        
    @staticmethod
    def sql_inject():
        return """
        01010011 01010001 01001100 00100000 01001001 01001110 01001010 01000101 01000011 01010100 01001001 01001111 01001110
        01000100 01000001 01000100 01001111 01010011 00100000 01010011 01000001 01001110 01000111 01010010 01000001 01000100 01001111 01010011
        01010000 01000001 01010011 01010011 01010111 01001111 01010010 01000100 01010011 00100000 01000101 01001101 00100000 01010000 01001100 01000001 01001001 01001110 01010100 01000101 01011000 01010100
        """
        
    @staticmethod
    def span():
        return """
        01010011 01010000 01000001 01001101 00100000 01010100 01001111 01001111 01001100 01010011
        01001001 00100000 01010111 01001001 01001100 01001100 00100000 01010011 01010000 01000001 01001101 00100000 01011001 01001111 01010101
        01011001 01001111 01010101 00100000 01100011 01100001 01101110 00100111 01110100 00100000 01100101 01110011 01100011 01100001 01110000 01100101
        """
        
    @staticmethod
    def phishing():
        return """
        01010000 01001000 01001001 01010011 01001001 01001110 01000111 00100000 01010100 01001111 01001111 01001100 01010011
        01011001 01001111 01010101 01010010 00100000 01000011 01010010 01000101 01000100 01000101 01001110 01010100 01001001 01000001 01001100 01010011 00100000 01000001 01010010 01000101 00100000 01001101 01001001 01001110 01000101
        01010100 01010010 01010101 01010011 01010100 00100000 01001110 01001111 00100000 01001111 01001110 01000101
        """
        
    @staticmethod
    def xss():
        return """
        01011000 01010011 01010011 00100000 01000001 01010100 01010100 01000001 01000011 01001011 01010011
        01001001 01001110 01001010 01000101 01000011 01010100 01001001 01001110 01000111 00100000 01001101 01000001 01001100 01001001 01000011 01001001 01001111 01010101 01010011 00100000 01010011 01000011 01010010 01001001 01010000 01010100 01010011
        01000011 01010010 01001111 01010011 01010011 00100000 01010011 01001001 01010100 01000101 00100000 01010011 01000011 01010010 01001001 01010000 01010100 01001001 01001110 01000111
        """
        
    @staticmethod
    def git_exposto():
        return """
        01000111 01001001 01010100 00100000 01000101 01011000 01010000 01001111 01010011 01000101 01000100
        01000110 01001001 01001110 01000100 01001001 01001110 01000111 00100000 01010011 01000101 01000011 01010010 01000101 01010100 01010011 00100000 01001001 01001110 00100000 01010010 01000101 01010000 01001111 01010011 01001001 01010100 01001111 01010010 01001001 01000101 01010011
        01011001 01001111 01010101 01010010 00100000 01000011 01001111 01000100 01000101 00100000 01001001 01010011 00100000 01001110 01001111 01010100 00100000 01010011 01000001 01000110 01000101
        """
        
    @staticmethod
    def zero_day():
        return """
        01011010 01000101 01010010 01001111 01000100 01000001 01011001 00100000 01000101 01011000 01010000 01001100 01001111 01001001 01010100 01010011
        01010101 01001110 01001011 01001110 01001111 01010111 01001110 00100000 01010110 01010101 01001100 01001110 01000101 01010010 01000001 01000010 01001001 01001100 01001001 01010100 01001001 01000101 01010011
        01010100 01001000 01000101 00100000 01010101 01001100 01010100 01001001 01001101 01000001 01010100 01000101 00100000 01010111 01000101 01000001 01010000 01001111 01001110
        """
        
    @staticmethod
    def dos():
        return """
        01000100 01000101 01001110 01001001 01000001 01001100 00100000 01001111 01000110 00100000 01010011 01000101 01010010 01010110 01001001 01000011 01000101
        01001111 01010110 01000101 01010010 01010111 01001000 01000101 01001100 01001101 01001001 01001110 01000111 00100000 01010100 01001000 01000101 00100000 01010100 01000001 01010010 01000111 01000101 01010100
        01010100 01001000 01000101 00100000 01010011 01011001 01010011 01010100 01000101 01001101 00100000 01010011 01001000 01000001 01001100 01001100 00100000 01000110 01000001 01001100 01001100
        """
        
    @staticmethod
    def ddos():
        return """
        01000100 01000100 01001111 01010011 00100000 01000001 01010100 01010100 01000001 01000011 01001011 01010011
        01000100 01001001 01010011 01010100 01010010 01001001 01000010 01010101 01010100 01000101 01000100 00100000 01000100 01000101 01001110 01001001 01000001 01001100 00100000 01001111 01000110 00100000 01010011 01000101 01010010 01010110 01001001 01000011 01000101
        01010100 01001000 01000101 00100000 01001110 01000101 01010100 01010111 01001111 01010010 01001011 00100000 01010011 01001000 01000001 01001100 01001100 00100000 01000010 01000101 00100000 01001111 01010110 01000101 01010010 01010111 01001000 01000101 01001100 01001101 01000101 01000100
        """
        
    @staticmethod
    def dox():
        return """
        01000100 01001111 01011000 01001001 01001110 01000111 00100000 01010100 01001111 01001111 01001100 01010011
        01000110 01001001 01001110 01000100 00100000 01000001 01001100 01001100 00100000 01010000 01000101 01010010 01010011 01001111 01001110 01000001 01001100 00100000 01001001 01001110 01000110 01001111 01010010 01001101 01000001 01010100 01001001 01001111 01001110
        01011001 01001111 01010101 00100000 01000011 01000001 01001110 00100111 01010100 00100000 01001000 01001001 01000100 01000101
        """

class HackerMenu:
    def __init__(self):
        self.tools = {
            "OSINT": {
                "BuscaDeSites.py": "Busca informações em sites",
                "Geolocalização-Metadados.py": "Extrai metadados de geolocalização",
                "Leaked-Databases.py": "Consulta bancos de dados vazados",
                "busca-usuario.py": "Busca por usuários em redes sociais",
                "cep.py": "Consulta informações por CEP",
                "cnpj.py": "Consulta dados de CNPJ",
                "cpf.py": "Consulta dados de CPF",
                "insta-dados.py": "Coleta dados do Instagram",
                "investigaçãoDeG-mail.py": "Investiga contas de Gmail",
                "ip.py": "Rastreamento de IP",
                "nome.py": "Busca por nomes",
                "pais.py": "Consulta informações de países",
                "rastreador-bitcoin.py": "Rastreia transações Bitcoin",
                "rg.py": "Consulta dados de RG",
                "telefone.py": "Busca por números de telefone",
                "bin.py": "Consulta informações de BIN (cartões)",
                "placa.py": "Consulta informações de placas de veículos",
                "sherlock.py": "Busca por nomes de usuário em redes sociais",
                "pix.py": "Consulta informações de chaves PIX"
            },
            "malwer": {
                "c2.py": "Servidor de Comando e Controle",
                "malwer.py": "Ferramentas de malware",
                "dependencias.py": "Instalador de dependências",
                "malwer-assembly": "Malware em Assembly",
                "malwer-c.py": "Malware em C",
                "malwerPowerShell.py": "Malware em PowerShell",
                "mawer.go.py": "Malware em Go",
                "Pos-Exploracao.py": "Ferramentas de pós-exploração",
                "dropper.py": "Dropper para implantação de malware",
                "menu-metasplit.py": "Interface para Metasploit Framework",
                "netcat-c2.py": "Netcat como servidor C2"
            },
            "scanner": {
                "scanner.py": "Ferramenta de varredura de portas e redes",
                "vulnerabilidade.py": "Scanner de vulnerabilidades"
            },
            "brute": {
                "dictionary-attack.py": "Ataque de dicionário a senhas",
                "hash-cracker.c": "Quebrador de hashes em C",
                "puro.py": "Força bruta pura",
                "sites.py": "Força bruta em sites",
                "hydra.py": "Ferramenta Hydra para força bruta"
            },
            "sql-inject": {
                "sqlmap.py": "Ferramenta automatizada de SQL injection",
                "sql-inject.py": "Ferramenta manual de SQL injection",
                "sql-scaner.py": "Scanner de vulnerabilidades SQL"
            },
            "span": {
                "fim-link.py": "Ferramenta de spam por links",
                "social-span.py": "Spam em redes sociais",
                "span-gmail.py": "Spam por e-mail (Gmail)",
                "span-sms.py": "Spam por SMS",
                "trolar-amigo.py": "Ferramenta para trollar amigos"
            },
            "phishing": {
                "menu-phishing.py": "Menu completo de ferramentas de phishing",
                "rede-val.py": "Validador de redes de phishing",
                "site-clone.py": "Clonador de sites para phishing",
                "info-phishing.py": "Ferramenta de phishing com informações",
                "mascara.py": "Mascaramento de URLs para phishing",
                "Clickjacking.py": "Ataques de Clickjacking"
            },
            "xss": {
                "xss.py": "Ferramenta de ataque XSS",
                "xss-scan.py": "Scanner de vulnerabilidades XSS"
            },
            "git-exposto": {
                "git.py": "Scanner de repositórios Git expostos"
            },
            "dos": {
                "dos.py": "Ferramentas de Denial of Service",
                "dos-ataque.py": "Ataques DoS específicos"
            },
            "ddos": {
                "ddos.py": "Ferramentas de Distributed Denial of Service",
                "ddos-ataque.py": "Ataques DDoS específicos"
            },
            "dox": {
                "dox.py": "Ferramentas de coleta de informações pessoais",
                "dox-toolkit.py": "Kit completo para doxing"
            },
            "zero-day": {
                "zero-day.py": "Exploits de dia zero",
                "zero-day-scanner.py": "Scanner de vulnerabilidades zero-day"
            }
        }

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def show_main_menu(self):
        self.clear_screen()
        console.print(Panel.fit(Banners.main_menu(), style="bold red"))
        console.print("\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Opção", style="cyan", width=10)
        table.add_column("Categoria", style="green")
        table.add_column("Descrição", style="yellow")

        table.add_row("1", "OSINT", "Ferramentas de coleta de informações")
        table.add_row("2", "MALWER", "Ferramentas ofensivas")
        table.add_row("3", "SCANNER", "Ferramentas de varredura")
        table.add_row("4", "FORÇA BRUTA", "Ataques de força bruta")
        table.add_row("5", "SQL INJECTION", "Injeção de SQL em bancos de dados")
        table.add_row("6", "SPAN", "Ferramentas de envio em massa")
        table.add_row("7", "PHISHING", "Ferramentas de engenharia social")
        table.add_row("8", "XSS", "Ataques Cross-Site Scripting")
        table.add_row("9", "GIT EXPOSTO", "Busca por repositórios Git expostos")
        table.add_row("10", "DoS", "Ataques de Denial of Service")
        table.add_row("11", "DDoS", "Ataques Distribuídos de Denial of Service")
        table.add_row("12", "DOX", "Ferramentas de coleta de informações pessoais")
        table.add_row("13", "ZERO-DAY", "Exploits de dia zero")
        table.add_row("0", "SAIR", "Sair do sistema")

        console.print(table)

        choice = console.input("\n[bold red]>>> [/bold red]")
        return choice

    def show_category_menu(self, category):
        while True:
            self.clear_screen()
            
            if category == "OSINT":
                console.print(Panel.fit(Banners.osint(), style="bold green"))
            elif category == "malwer":
                console.print(Panel.fit(Banners.malware(), style="bold red"))
            elif category == "scanner":
                console.print(Panel.fit(Banners.scanner(), style="bold blue"))
            elif category == "brute":
                console.print(Panel.fit(Banners.brute_force(), style="bold magenta"))
            elif category == "sql-inject":
                console.print(Panel.fit(Banners.sql_inject(), style="bold cyan"))
            elif category == "span":
                console.print(Panel.fit(Banners.span(), style="bold yellow"))
            elif category == "phishing":
                console.print(Panel.fit(Banners.phishing(), style="bold purple"))
            elif category == "xss":
                console.print(Panel.fit(Banners.xss(), style="bold orange3"))
            elif category == "git-exposto":
                console.print(Panel.fit(Banners.git_exposto(), style="bold dark_green"))
            elif category == "dos":
                console.print(Panel.fit(Banners.dos(), style="bold dark_red"))
            elif category == "ddos":
                console.print(Panel.fit(Banners.ddos(), style="bold dark_orange"))
            elif category == "dox":
                console.print(Panel.fit(Banners.dox(), style="bold dark_blue"))
            elif category == "zero-day":
                console.print(Panel.fit(Banners.zero_day(), style="bold dark_purple"))
            
            console.print(f"\n[bold]{category.upper()} TOOLS[/bold]\n")
            
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Nº", style="cyan", width=5)
            table.add_column("Ferramenta", style="green")
            table.add_column("Descrição", style="yellow")
            
            tools = self.tools[category]
            for i, (tool, desc) in enumerate(tools.items(), 1):
                table.add_row(str(i), tool, desc)
            
            table.add_row("0", "VOLTAR", "Retornar ao menu principal")
            
            console.print(table)
            
            choice = console.input("\n[bold red]>>> [/bold red]")
            
            if choice == "0":
                return
            elif choice.isdigit() and 1 <= int(choice) <= len(tools):
                tool_name = list(tools.keys())[int(choice)-1]
                self.run_tool(category, tool_name)
            else:
                console.print("[bold red]Opção inválida![/bold red]")
                time.sleep(1)

    def compile_c_file(self, file_path):
        try:
            output_file = file_path[:-2]  
            console.print(f"[bold yellow]Compilando {file_path}...[/bold yellow]")
            
            result = subprocess.run(
                ["gcc", file_path, "-o", output_file],
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            if result.returncode != 0:
                console.print(f"[bold red]Erro na compilação:[/bold red]")
                console.print(result.stderr)
                return None
                
            console.print(f"[bold green]Compilação bem-sucedida! Arquivo gerado: {output_file}[/bold green]")
            return output_file
            
        except Exception as e:
            console.print(f"[bold red]Erro ao compilar: {str(e)}[/bold red]")
            return None

    def run_tool(self, category, tool_name):
        self.clear_screen()
        console.print(f"[bold yellow]Executando {tool_name}...[/bold yellow]\n")
        
        try:
            # Verifica se a pasta existe
            if not os.path.exists(category):
                console.print(f"[bold red]Erro: Pasta '{category}' não encontrada![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
                
            script_path = os.path.join(category, tool_name)
            if not os.path.exists(script_path):
                console.print(f"[bold red]Erro: Arquivo '{tool_name}' não encontrado em '{category}'![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
        
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            if tool_name.endswith('.c'):
                compiled_path = self.compile_c_file(script_path)
                if not compiled_path:
                    console.input("\nPressione Enter para continuar...")
                    return
                
                # Executa o arquivo compilado
                process = subprocess.Popen(
                    [f"./{compiled_path}"],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=category  # Executa na pasta da categoria
                )
            elif tool_name.endswith('.py'):
                # Executa o script Python
                process = subprocess.Popen(
                    [sys.executable, tool_name],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=category  # Executa na pasta da categoria
                )
            else:
                console.print("[bold red]Tipo de arquivo não suportado![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
                
            process.wait()
            
            if process.returncode != 0:
                console.print(f"[bold red]Erro ao executar (código {process.returncode})[/bold red]")
        
        except Exception as e:
            console.print(f"[bold red]Erro ao executar: {str(e)}[/bold red]")
        
        console.input("\nPressione Enter para continuar...")

    def run(self):
        while True:
            choice = self.show_main_menu()
            
            if choice == "1":
                self.show_category_menu("OSINT")
            elif choice == "2":
                self.show_category_menu("malwer")
            elif choice == "3":
                self.show_category_menu("scanner")
            elif choice == "4":
                self.show_category_menu("brute")
            elif choice == "5":
                self.show_category_menu("sql-inject")
            elif choice == "6":
                self.show_category_menu("span")
            elif choice == "7":
                self.show_category_menu("phishing")
            elif choice == "8":
                self.show_category_menu("xss")
            elif choice == "9":
                self.show_category_menu("git-exposto")
            elif choice == "10":
                self.show_category_menu("dos")
            elif choice == "11":
                self.show_category_menu("ddos")
            elif choice == "12":
                self.show_category_menu("dox")
            elif choice == "13":
                self.show_category_menu("zero-day")
            elif choice == "0":
                console.print("[bold red]Saindo do sistema...[/bold red]")
                time.sleep(1)
                sys.exit(0)
            else:
                console.print("[bold red]Opção inválida![/bold red]")
                time.sleep(1)

if __name__ == "__main__":
    try:
        menu = HackerMenu()
        menu.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrompido pelo usuário[/bold red]")
        sys.exit(0)
