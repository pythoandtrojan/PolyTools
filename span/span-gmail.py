#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from typing import List, Dict, Optional
import json

# Configuração de rich para interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

class GmailSpammer:
    def __init__(self):
        self.banners = [
            self._generate_banner_red(),
            self._generate_banner_blue(),
            self._generate_banner_green()
        ]
        self.smtp_servers = [
            {"host": "smtp.gmail.com", "port": 587},
            {"host": "smtp-relay.gmail.com", "port": 587},
            {"host": "aspmx.l.google.com", "port": 25}
        ]
        self.current_server = 0
        self.api_keys = []
        self._load_config()

    def _generate_banner_red(self) -> str:
        return """
[bold red]
 ██████╗ ███╗   ███╗ █████╗ ██╗██╗         ███████╗██████╗  █████╗ ███╗   ███╗
██╔════╝ ████╗ ████║██╔══██╗██║██║         ██╔════╝██╔══██╗██╔══██╗████╗ ████║
██║  ███╗██╔████╔██║███████║██║██║         ███████╗██████╔╝███████║██╔████╔██║
██║   ██║██║╚██╔╝██║██╔══██║██║██║         ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║
╚██████╔╝██║ ╚═╝ ██║██║  ██║██║███████╗    ███████║██║     ██║  ██║██║ ╚═╝ ██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝    ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝
[/bold red]
[bold white on red]       FERRAMENTA DE SPAM PARA GMAIL - USE COM MODERAÇÃO![/bold white on red]
"""

    def _generate_banner_blue(self) -> str:
        return """
[bold blue]
  ________                       _____                 __  .__               
 /  _____/_____    _____   _____/ ____\____   _______/  |_|__| ____   ____  
/   \  ___\__  \  /     \_/ __ \   __\/ __ \ /  ___/\   __\  |/  _ \ /    \ 
\    \_\  \/ __ \|  Y Y  \  ___/|  | \  ___/ \___ \  |  | |  (  <_> )   |  \
 \______  (____  /__|_|  /\___  >__|  \___  >____  > |__| |__|\____/|___|  /
        \/     \/      \/     \/          \/     \/                      \/ 
[/bold blue]
[bold white on blue]       SPAMMER DE GMAIL VIA APIS PÚBLICAS - VERSION 2.1[/bold white on blue]
"""

    def _generate_banner_green(self) -> str:
        return """
[bold green]
   ____ _   _    _    ____ _  __    _    ____ _____ _   _ _____ ____  
  / ___| | | |  / \  / ___| |/ /   / \  / ___| ____| \ | | ____|  _ \ 
 | |  _| |_| | / _ \| |   | ' /   / _ \| |  _|  _| |  \| |  _| | |_) |
 | |_| |  _  |/ ___ \ |___| . \  / ___ \ |_| | |___| |\  | |___|  _ < 
  \____|_| |_/_/   \_\____|_|\_\/_/   \_\____|_____|_| \_|_____|_| \_\
[/bold green]
[bold black on green]       FERRAMENTA AVANÇADA DE ENVIO EM MASSA - GMAIL API[/bold black on green]
"""

    def _load_config(self):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
                self.api_keys = config.get('api_keys', [])
        except FileNotFoundError:
            self.api_keys = []

    def _save_config(self):
        with open('config.json', 'w') as f:
            json.dump({'api_keys': self.api_keys}, f)

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: USO INADEQUADO PODE VIOLAR TERMOS DE SERVIÇO! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def rotate_smtp_server(self):
        self.current_server = (self.current_server + 1) % len(self.smtp_servers)
        return self.smtp_servers[self.current_server]

    def send_via_smtp(self, sender: str, password: str, recipient: str, subject: str, body: str) -> bool:
        server = self.rotate_smtp_server()
        try:
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))

            with smtplib.SMTP(server['host'], server['port']) as smtp:
                smtp.starttls()
                smtp.login(sender, password)
                smtp.send_message(msg)
            return True
        except Exception as e:
            console.print(f"[red]Erro SMTP ({server['host']}): {str(e)}[/red]")
            return False

    def send_via_api(self, sender: str, api_key: str, recipient: str, subject: str, body: str) -> bool:
        endpoint = "https://www.googleapis.com/gmail/v1/users/me/messages/send"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        message = MIMEMultipart()
        message['to'] = recipient
        message['from'] = sender
        message['subject'] = subject
        message.attach(MIMEText(body, 'html'))
        
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        payload = {'raw': raw_message}

        try:
            response = requests.post(endpoint, headers=headers, json=payload)
            if response.status_code == 200:
                return True
            console.print(f"[red]Erro API: {response.status_code} - {response.text}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Erro na requisição API: {str(e)}[/red]")
            return False

    def check_api_key(self, api_key: str) -> bool:
        endpoint = "https://www.googleapis.com/gmail/v1/users/me/profile"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            response = requests.get(endpoint, headers=headers)
            return response.status_code == 200
        except:
            return False

    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()

            table = Table(title="Menu Principal", show_header=True, header_style="bold magenta")
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")

            table.add_row("1", "Configurar contas e chaves API")
            table.add_row("2", "Enviar emails individuais")
            table.add_row("3", "Campanha de spam em massa")
            table.add_row("4", "Verificar contas/API válidas")
            table.add_row("9", "Sair")

            console.print(table)

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4", "9"])

            if choice == "1":
                self.configure_accounts()
            elif choice == "2":
                self.send_single_email()
            elif choice == "3":
                self.mass_campaign()
            elif choice == "4":
                self.check_valid_accounts()
            elif choice == "9":
                self._exit()

    def configure_accounts(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]Configuração de Contas e Chaves API[/bold]"))

            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Tipo", style="cyan")
            table.add_column("Quantidade", style="green")

            table.add_row("Chaves API Gmail", str(len(self.api_keys)))

            console.print(table)

            console.print("\n[bold]Opções:[/bold]")
            console.print("1. Adicionar chave API")
            console.print("2. Remover chave API")
            console.print("3. Voltar")

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3"])

            if choice == "1":
                api_key = Prompt.ask("Digite a chave API do Gmail")
                if self.check_api_key(api_key):
                    self.api_keys.append(api_key)
                    self._save_config()
                    console.print("[green]Chave API válida e adicionada com sucesso![/green]")
                else:
                    console.print("[red]Chave API inválida ou sem permissões suficientes[/red]")
                input("\nPressione Enter para continuar...")
            elif choice == "2":
                if not self.api_keys:
                    console.print("[yellow]Não há chaves API para remover[/yellow]")
                    input("\nPressione Enter para continuar...")
                    continue

                for i, key in enumerate(self.api_keys, 1):
                    console.print(f"{i}. {key[:10]}...{key[-6:]}")
                
                try:
                    index = IntPrompt.ask("Digite o número da chave para remover", default=0) - 1
                    if 0 <= index < len(self.api_keys):
                        removed = self.api_keys.pop(index)
                        self._save_config()
                        console.print(f"[green]Chave {removed[:10]}...{removed[-6:]} removida![/green]")
                except:
                    console.print("[red]Seleção inválida[/red]")
                input("\nPressione Enter para continuar...")
            elif choice == "3":
                return

    def send_single_email(self):
        console.clear()
        console.print(Panel.fit("[bold]Envio de Email Individual[/bold]"))

        if not self.api_keys:
            console.print("[red]Nenhuma chave API configurada![/red]")
            input("\nPressione Enter para voltar...")
            return

        sender = Prompt.ask("Email remetente")
        recipient = Prompt.ask("Email destinatário")
        subject = Prompt.ask("Assunto do email")
        body = Prompt.ask("Corpo do email (HTML suportado)")

        use_api = Confirm.ask("Usar API Gmail? (SMTP será usado se não)")

        success = False
        if use_api:
            api_key = random.choice(self.api_keys)
            success = self.send_via_api(sender, api_key, recipient, subject, body)
        else:
            password = Prompt.ask("Senha do email remetente", password=True)
            success = self.send_via_smtp(sender, password, recipient, subject, body)

        if success:
            console.print("[green]Email enviado com sucesso![/green]")
        else:
            console.print("[red]Falha ao enviar email[/red]")
        
        input("\nPressione Enter para voltar...")

    def mass_campaign(self):
        console.clear()
        console.print(Panel.fit("[bold]Campanha de Spam em Massa[/bold]"))

        if not self.api_keys:
            console.print("[red]Nenhuma chave API configurada![/red]")
            input("\nPressione Enter para voltar...")
            return

        sender = Prompt.ask("Email remetente principal")
        recipients_file = Prompt.ask("Arquivo com lista de emails (um por linha)")
        subject = Prompt.ask("Assunto do email")
        body_file = Prompt.ask("Arquivo com corpo do email (HTML suportado)")

        try:
            with open(recipients_file, 'r') as f:
                recipients = [line.strip() for line in f if line.strip()]
            
            with open(body_file, 'r') as f:
                body = f.read()
        except Exception as e:
            console.print(f"[red]Erro ao ler arquivos: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")
            return

        use_api = Confirm.ask("Usar API Gmail? (SMTP será usado se não)")
        if not use_api:
            password = Prompt.ask("Senha do email remetente", password=True)

        delay = IntPrompt.ask("Atraso entre emails (segundos)", default=5)
        max_emails = IntPrompt.ask("Número máximo de emails para enviar", default=100)

        sent = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Enviando emails...", total=min(len(recipients), max_emails))

            for recipient in recipients[:max_emails]:
                try:
                    if use_api:
                        api_key = random.choice(self.api_keys)
                        success = self.send_via_api(sender, api_key, recipient, subject, body)
                    else:
                        success = self.send_via_smtp(sender, password, recipient, subject, body)

                    if success:
                        sent += 1
                        progress.update(task, advance=1, description=f"[cyan]Enviando emails... ({sent} enviados)")
                    else:
                        progress.update(task, description=f"[yellow]Problema no envio, tentando próximo...")

                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper o envio?[/red]"):
                        break
                    continue
                except Exception as e:
                    console.print(f"[red]Erro: {str(e)}[/red]")
                    continue

        console.print(f"[green]Campanha concluída! {sent} emails enviados.[/green]")
        input("\nPressione Enter para voltar...")

    def check_valid_accounts(self):
        console.clear()
        console.print(Panel.fit("[bold]Verificar Contas/Chaves API[/bold]"))

        if not self.api_keys:
            console.print("[yellow]Nenhuma chave API para verificar[/yellow]")
            input("\nPressione Enter para voltar...")
            return

        valid_keys = []
        with Progress() as progress:
            task = progress.add_task("[cyan]Verificando chaves API...", total=len(self.api_keys))

            for api_key in self.api_keys:
                if self.check_api_key(api_key):
                    valid_keys.append(api_key)
                    progress.update(task, advance=1, description=f"[cyan]Verificando... ({len(valid_keys)} válidas)")
                else:
                    progress.update(task, advance=1)

        console.print(f"\n[green]Chaves válidas: {len(valid_keys)}/{len(self.api_keys)}[/green]")
        for key in valid_keys:
            console.print(f"[cyan]{key[:10]}...{key[-6:]}[/cyan]")

        if len(valid_keys) < len(self.api_keys) and Confirm.ask("\nRemover chaves inválidas?"):
            self.api_keys = valid_keys
            self._save_config()
            console.print("[green]Chaves inválidas removidas![/green]")

        input("\nPressione Enter para voltar...")

    def _exit(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: SPAM É ILEGAL EM MUITOS PAÍSES! USE APENAS PARA TESTES AUTORIZADOS ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

if __name__ == '__main__':
    try:
        spammer = GmailSpammer()
        spammer.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
        sys.exit(1)
