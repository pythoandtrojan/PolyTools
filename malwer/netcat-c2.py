#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import threading
from typing import List, Dict, Optional
from datetime import datetime

# Configuração de rich para interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text

console = Console()

class NetcatListener:
    def __init__(self):
        self.themes = {
            "dark": {
                "primary": "bold red",
                "secondary": "bold black on red",
                "warning": "blink bold red",
                "info": "bold white on red",
                "banner": self._generate_dark_banner()
            },
            "kwaii": {
                "primary": "bold #FF9FF3",
                "secondary": "bold #FECA57",
                "warning": "bold #FF6B6B",
                "info": "bold #1DD1A1",
                "banner": self._generate_kwaii_banner()
            },
            "generic": {
                "primary": "bold blue",
                "secondary": "bold white on blue",
                "warning": "bold yellow",
                "info": "bold green",
                "banner": self._generate_generic_banner()
            }
        }
        self.current_theme = "dark"
        self.active_listeners = []
        self.saved_profiles = {}
        self._load_profiles()

    def _generate_dark_banner(self) -> str:
        return """
[bold red]
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
                                 -**=                           
                       =:       =**=-=                       
                       -*+-.    .-**:                       
                         :=+***++=:                         
        █▀▀ █▀▀ █▀▄▀█ █▀▀ █▀▀ ▀█▀ █▀▀ █▀▄ █ █▀█ █▀▀ █▀
        █▄█ ██▄ █░▀░█ ██▄ █▄▄ ░█░ ██▄ █▄▀ █ █▀▀ ██▄ ▄█
         ╔══════════════════════════════════════════════════╗
         ║    AUTOMATED NETCAT LISTENER - MULTI-PORT        ║
         ║      RECEIVE FILES & COMMANDS - DARK MODE        ║
         ╚══════════════════════════════════════════════════╝
  [/bold red]
  [bold white on red]       LISTENER AUTOMATOR - MULTI-PORT NETCAT LISTENER[/bold white on red]
  [blink bold red]⚠️ ATENÇÃO: FERRAMENTA PARA USO ÉTICO E LEGAL APENAS! ⚠️[/blink bold red]
"""

    def _generate_kwaii_banner(self) -> str:
        return """
[bold #FF9FF3]
  ∧,,,∧
 ( ̳• · • ̳)
 /    づ♡  [bold #FECA57]Nyaa~ Netcat Listener[/bold #FECA57]
[/bold #FF9FF3]
[bold #1DD1A1]✧･ﾟ: *✧･ﾟ:*  [bold #FECA57]Multi-port listener with file transfer![/bold #FECA57] *:･ﾟ✧*:･ﾟ✧
[blink bold #FF6B6B]✧･ﾟ: *✧･ﾟ:* Warning: Use responsibly! *:･ﾟ✧*:･ﾟ✧[/blink bold #FF6B6B]
"""

    def _generate_generic_banner(self) -> str:
        return """
[bold blue]
 ███╗   ██╗███████╗████████╗ ██████╗ █████╗ ████████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
 ██╔██╗ ██║█████╗     ██║   ██║     ███████║   ██║   
 ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║   ██║   
 ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║   ██║   
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝   
[/bold blue]
[bold white on blue]       NETCAT LISTENER AUTOMATION TOOL - v2.0[/bold white on blue]
[bold yellow]⚠️ WARNING: FOR LEGAL AND ETHICAL USE ONLY! ⚠️[/bold yellow]
"""

    def _load_profiles(self):
        """Carrega os perfis salvos"""
        try:
            with open('nc_profiles.json', 'r') as f:
                self.saved_profiles = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.saved_profiles = {}

    def _save_profiles(self):
        """Salva os perfis"""
        with open('nc_profiles.json', 'w') as f:
            json.dump(self.saved_profiles, f)

    def show_banner(self):
        theme = self.themes[self.current_theme]
        console.print(theme["banner"])
        time.sleep(0.5)

    def change_theme(self):
        console.clear()
        console.print(Panel.fit("[bold]Selecione um Tema[/bold]"))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Opção", style="cyan", width=10)
        table.add_column("Tema", style="green")
        table.add_column("Descrição")

        table.add_row("1", "Dark", "Tema vermelho intenso para uso noturno")
        table.add_row("2", "Kwaii", "Tema fofo com cores pastel")
        table.add_row("3", "Genérico", "Tema neutro para uso profissional")

        console.print(table)

        choice = Prompt.ask("Selecione um tema", choices=["1", "2", "3"])
        
        if choice == "1":
            self.current_theme = "dark"
        elif choice == "2":
            self.current_theme = "kwaii"
        elif choice == "3":
            self.current_theme = "generic"
        
        console.print(f"[green]Tema alterado para {self.current_theme}![/green]")
        time.sleep(1)

    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()

            theme = self.themes[self.current_theme]
            
            table = Table(title="Menu Principal", show_header=True, header_style=theme["primary"])
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")

            table.add_row("1", "Iniciar listener em portas específicas")
            table.add_row("2", "Iniciar listener em range de portas")
            table.add_row("3", "Gerenciar perfis salvos")
            table.add_row("4", "Visualizar listeners ativos")
            table.add_row("5", "Parar listeners")
            table.add_row("6", "Alterar tema")
            table.add_row("9", "Sair")

            console.print(table)

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4", "5", "6", "9"])

            if choice == "1":
                self.start_specific_listeners()
            elif choice == "2":
                self.start_range_listeners()
            elif choice == "3":
                self.manage_profiles()
            elif choice == "4":
                self.show_active_listeners()
            elif choice == "5":
                self.stop_listeners()
            elif choice == "6":
                self.change_theme()
            elif choice == "9":
                self._exit()

    def start_specific_listeners(self):
        console.clear()
        theme = self.themes[self.current_theme]
        console.print(Panel.fit("[bold]Iniciar Listeners em Portas Específicas[/bold]", style=theme["primary"]))
        
        ports_input = Prompt.ask("Digite as portas (separadas por vírgula)")
        ports = [p.strip() for p in ports_input.split(",") if p.strip().isdigit()]
        
        if not ports:
            console.print("[red]Nenhuma porta válida informada![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        receive_files = Confirm.ask("Deseja configurar para receber arquivos?", default=False)
        output_dir = ""
        if receive_files:
            output_dir = Prompt.ask("Diretório para salvar arquivos (deixe em branco para ./nc_files)")
            if not output_dir:
                output_dir = "./nc_files"
                os.makedirs(output_dir, exist_ok=True)
        
        save_profile = Confirm.ask("Deseja salvar esta configuração como perfil?", default=False)
        profile_name = ""
        if save_profile:
            profile_name = Prompt.ask("Nome do perfil")
            self.saved_profiles[profile_name] = {
                "ports": ports,
                "receive_files": receive_files,
                "output_dir": output_dir
            }
            self._save_profiles()
            console.print(f"[green]Perfil '{profile_name}' salvo com sucesso![/green]")
        
        self._start_listeners(ports, receive_files, output_dir)
        input("\nPressione Enter para continuar...")

    def start_range_listeners(self):
        console.clear()
        theme = self.themes[self.current_theme]
        console.print(Panel.fit("[bold]Iniciar Listeners em Range de Portas[/bold]", style=theme["primary"]))
        
        start_port = IntPrompt.ask("Porta inicial", default=8000)
        end_port = IntPrompt.ask("Porta final", default=8010)
        
        if start_port > end_port:
            console.print("[red]Porta inicial deve ser menor que porta final![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        ports = [str(p) for p in range(start_port, end_port + 1)]
        
        receive_files = Confirm.ask("Deseja configurar para receber arquivos?", default=False)
        output_dir = ""
        if receive_files:
            output_dir = Prompt.ask("Diretório para salvar arquivos (deixe em branco para ./nc_files)")
            if not output_dir:
                output_dir = "./nc_files"
                os.makedirs(output_dir, exist_ok=True)
        
        save_profile = Confirm.ask("Deseja salvar esta configuração como perfil?", default=False)
        profile_name = ""
        if save_profile:
            profile_name = Prompt.ask("Nome do perfil")
            self.saved_profiles[profile_name] = {
                "ports": ports,
                "receive_files": receive_files,
                "output_dir": output_dir
            }
            self._save_profiles()
            console.print(f"[green]Perfil '{profile_name}' salvo com sucesso![/green]")
        
        self._start_listeners(ports, receive_files, output_dir)
        input("\nPressione Enter para continuar...")

    def _start_listeners(self, ports: List[str], receive_files: bool, output_dir: str):
        theme = self.themes[self.current_theme]
        
        console.print(f"\n[bold]Iniciando listeners nas portas:[/bold] {', '.join(ports)}")
        if receive_files:
            console.print(f"[bold]Diretório de saída:[/bold] {output_dir}")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Iniciando listeners...", total=len(ports))
            
            for port in ports:
                try:
                    if receive_files:
                        cmd = f"nc -lvnp {port} > {os.path.join(output_dir, 'file_'+port+'_'+datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    else:
                        cmd = f"nc -lvnp {port}"
                    
                    # Usamos um thread para cada listener para não bloquear
                    thread = threading.Thread(
                        target=self._run_listener,
                        args=(cmd, port),
                        daemon=True
                    )
                    thread.start()
                    self.active_listeners.append((port, thread))
                    
                    progress.update(task, advance=1)
                    time.sleep(0.2)
                except Exception as e:
                    console.print(f"[red]Erro ao iniciar listener na porta {port}: {str(e)}[/red]")
        
        console.print(f"\n[green]{len(ports)} listeners iniciados com sucesso![/green]")

    def _run_listener(self, cmd: str, port: str):
        """Executa o comando netcat em um subprocesso"""
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            process.communicate()
        except Exception as e:
            console.print(f"[red]Erro no listener da porta {port}: {str(e)}[/red]")

    def manage_profiles(self):
        while True:
            console.clear()
            theme = self.themes[self.current_theme]
            console.print(Panel.fit("[bold]Gerenciamento de Perfis Salvos[/bold]", style=theme["primary"]))
            
            if not self.saved_profiles:
                console.print("[yellow]Nenhum perfil salvo.[/yellow]")
                input("\nPressione Enter para voltar...")
                return
            
            table = Table(title="Perfis Salvos", show_header=True, header_style=theme["primary"])
            table.add_column("Nome", style="cyan")
            table.add_column("Portas", style="green")
            table.add_column("Recebe Arquivos?", style="magenta")
            table.add_column("Diretório", style="yellow")

            for name, profile in self.saved_profiles.items():
                table.add_row(
                    name,
                    ", ".join(profile["ports"]),
                    "Sim" if profile["receive_files"] else "Não",
                    profile.get("output_dir", "N/A")
                )

            console.print(table)

            console.print("\n[bold]Opções:[/bold]")
            console.print("1. Carregar perfil")
            console.print("2. Excluir perfil")
            console.print("3. Voltar")

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3"])

            if choice == "1":
                profile_name = Prompt.ask("Nome do perfil para carregar", choices=list(self.saved_profiles.keys()))
                profile = self.saved_profiles[profile_name]
                self._start_listeners(
                    profile["ports"],
                    profile["receive_files"],
                    profile.get("output_dir", "")
                )
                input("\nPressione Enter para continuar...")

            elif choice == "2":
                profile_name = Prompt.ask("Nome do perfil para excluir", choices=list(self.saved_profiles.keys()))
                if Confirm.ask(f"[red]Tem certeza que deseja excluir o perfil '{profile_name}'?[/red]"):
                    del self.saved_profiles[profile_name]
                    self._save_profiles()
                    console.print(f"[green]Perfil '{profile_name}' excluído![/green]")
                    time.sleep(1)

            elif choice == "3":
                return

    def show_active_listeners(self):
        console.clear()
        theme = self.themes[self.current_theme]
        console.print(Panel.fit("[bold]Listeners Ativos[/bold]", style=theme["primary"]))
        
        if not self.active_listeners:
            console.print("[yellow]Nenhum listener ativo no momento.[/yellow]")
        else:
            table = Table(show_header=True, header_style=theme["primary"])
            table.add_column("Porta", style="cyan")
            table.add_column("Status", style="green")

            for port, thread in self.active_listeners:
                table.add_row(port, "Ativo" if thread.is_alive() else "Inativo")

            console.print(table)
        
        input("\nPressione Enter para continuar...")

    def stop_listeners(self):
        console.clear()
        theme = self.themes[self.current_theme]
        console.print(Panel.fit("[bold]Parar Listeners[/bold]", style=theme["primary"]))
        
        if not self.active_listeners:
            console.print("[yellow]Nenhum listener ativo para parar.[/yellow]")
            input("\nPressione Enter para continuar...")
            return
        
        # Encerra todos os processos netcat
        os.system("pkill -f 'nc -lvnp'")
        
        # Limpa a lista de listeners ativos
        self.active_listeners = []
        
        console.print("[green]Todos os listeners foram parados![/green]")
        input("\nPressione Enter para continuar...")

    def _exit(self):
        theme = self.themes[self.current_theme]
        console.print(Panel.fit(
            f"[{theme['warning']}]⚠️ AVISO: FERRAMENTA PARA USO ÉTICO E LEGAL APENAS! ⚠️[/{theme['warning']}]",
            style=theme["primary"]
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

if __name__ == '__main__':
    try:
        listener = NetcatListener()
        listener.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
        sys.exit(1)
