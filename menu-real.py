#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

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
        ███╗   ███╗███████╗███╗   ██╗██╗   ██╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
        ████╗ ████║██╔════╝████╗  ██║██║   ██║    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
        ██╔████╔██║█████╗  ██╔██╗ ██║██║   ██║    ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
        ██║╚██╔╝██║██╔══╝  ██║╚██╗██║██║   ██║    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
        ██║ ╚═╝ ██║███████╗██║ ╚████║╚██████╔╝    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
        ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        [/bold red]"""

    @staticmethod
    def osint():
        return """
        01010100 01101000 01100101 00100000 01001111 01010011 01001001 01001110 01010100 00100000 01000111 01100001 01110100 01101000 01100101 01110010 01101001 01101110 01100111
        01100111 01101111 01100100 00100000 01101001 01110011 00100000 01110111 01100001 01110100 01100011 01101000 01101001 01101110 01100111 00100000 01111001 01101111 01110101
        01001001 00100000 01101011 01101110 01101111 01110111 00100000 01110111 01101000 01100101 01110010 01100101 00100000 01111001 01101111 01110101 00100000 01101100 01101001 01110110 01100101
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

class HackerMenu:
    def __init__(self):
        self.tools = {
            "OSINT": {
                "BuscaDeSites.py": "Busca informações em sites",
                "Geolocalização-Metadados.py": "Extrai metadados de geolocalização",
                "Bancos de dados vazados.py": "Consulta bancos de dados vazados",
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
                "telefone.py": "Busca por números de telefone"
            },
            "malwer": {
                "c2.py": "Command and Control server",
                "malwer.py": "Ferramentas de malware",
                "dependencias.py": "Instalador de dependências"
            },
            "scanner": {
                "scanner.py": "Ferramenta de varredura de portas e redes",
                "vulnerabilidade.py": "Scanner de vulnerabilidades"
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
        table.add_row("3", "SCANNER", "Ferramentas de varredura")  # Nova opção
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
            
            console.print(f"\n[bold]{category} TOOLS[/bold]\n")
            
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

    def run_tool(self, category, tool_name):
        self.clear_screen()
        console.print(f"[bold yellow]Executando {tool_name}...[/bold yellow]\n")
        
        try:
            # Verifica se o arquivo existe
            script_path = os.path.join(category, tool_name)
            if not os.path.exists(script_path):
                console.print(f"[bold red]Erro: Arquivo {script_path} não encontrado![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
            
            # Configura o ambiente para execução interativa
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'  # Para evitar buffering da saída
            
            # Executa o script de forma interativa
            if tool_name.endswith('.py'):
                # Usamos sys.executable para garantir que usará o mesmo interpretador Python
                process = subprocess.Popen(
                    [sys.executable, script_path],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Aguarda o processo terminar
                process.wait()
                
                # Verifica se houve erro
                if process.returncode != 0:
                    console.print(f"[bold red]Erro ao executar o script (código {process.returncode})[/bold red]")
            else:
                console.print("[bold red]Arquivo não é um script Python![/bold red]")
        
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
                self.show_category_menu("scanner")  # Nova categoria
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
