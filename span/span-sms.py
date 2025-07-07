#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import requests
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta

# Configuração de rich para interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

class SMSSpammer:
    def __init__(self):
        self.banners = [
            self._generate_banner_red(),
            self._generate_banner_blue(),
            self._generate_banner_green()
        ]
        self.services = self._load_services()
        self.used_services = []
        self._load_config()
        
    def _generate_banner_red(self) -> str:
        return """
[bold red]
 ███████╗██████╗  █████╗ ███╗   ███╗    ███████╗██╗  ██╗███████╗
 ██╔════╝██╔══██╗██╔══██╗████╗ ████║    ██╔════╝██║  ██║██╔════╝
 ███████╗██████╔╝███████║██╔████╔██║    ███████╗███████║███████╗
 ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║    ╚════██║██╔══██║╚════██║
 ███████║██║     ██║  ██║██║ ╚═╝ ██║    ███████║██║  ██║███████║
 ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝
[/bold red]
[bold white on red]       FERRAMENTA DE SPAM SMS - USE COM RESPONSABILIDADE![/bold white on red]
"""

    def _generate_banner_blue(self) -> str:
        return """
[bold blue]
   _____ __  __ ____    _____ _____ ____ _____     _______ _______ ______ _____  
  / ____|  \/  |___ \  / ____/ ____/ __ \_   _|   / / ___|__   __|  ____|  __ \ 
 | (___ | \  / | __) | | (___| (___| |  | || |    / /\___ \ | |  | |__  | |__) |
  \___ \| |\/| |__ <   \___ \\___ \| |  | || |   / /  ___) || |  |  __| |  _  / 
 ____) | |  | |___) | ____) |___) | |__| || |_ / /  /____/ | |  | |____| | \ \ 
|_____/|_|  |_|____/ |_____/_____/ \____/_____/_/          |_|  |______|_|  \_\
[/bold blue]
[bold white on blue]       SPAMMER SMS VIA MÚLTIPLAS APIS - VERSION 3.0[/bold white on blue]
"""

    def _generate_banner_green(self) -> str:
        return """
[bold green]
  ________ _______ ________  ___  ___  _______   ___       ___  ________  ________     
 |\   ____\\  ___ \\\_____  \|\  \|\  \|\  ___ \ |\  \     |\  \|\   __  \|\   ___ \    
 \ \  \___|\ \   __/|/ ___/\ \  \ \  \ \   __/|\ \  \    \ \  \ \  \|\  \ \  \_|\ \   
  \ \  \  __\ \  \_|/ /___/_\ \  \ \  \ \  \_|/_\ \  \    \ \  \ \  \\\  \ \  \ \\ \  
   \ \  \|\  \ \  \_|\ \  \|\  \ \  \ \  \ \  \_|\ \ \  \____\ \  \ \  \\\  \ \  \_\\ \ 
    \ \_______\ \__\ \ \_______\ \__\ \__\ \_______\ \_______\ \__\ \_______\ \_______\
     \|_______|\|__|  \|_______|\|__|\|__|\|_______|\|_______|\|__|\|_______|\|_______|
[/bold green]
[bold black on green]       FERRAMENTA AVANÇADA DE ENVIO EM MASSA - SMS BOMBER[/bold black on green]
"""

    def _load_services(self) -> List[Dict]:
        """Carrega os serviços de API de SMS disponíveis"""
        return [
            {
                "name": "Twilio",
                "url": "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Basic {auth_token}"
                },
                "data": {
                    "From": "{from_number}",
                    "To": "{to_number}",
                    "Body": "{message}"
                },
                "auth_required": True,
                "auth_params": ["account_sid", "auth_token", "from_number"]
            },
            {
                "name": "Nexmo (Vonage)",
                "url": "https://rest.nexmo.com/sms/json",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json"
                },
                "data": {
                    "api_key": "{api_key}",
                    "api_secret": "{api_secret}",
                    "from": "{from_number}",
                    "to": "{to_number}",
                    "text": "{message}"
                },
                "auth_required": True,
                "auth_params": ["api_key", "api_secret", "from_number"]
            },
            {
                "name": "Plivo",
                "url": "https://api.plivo.com/v1/Account/{auth_id}/Message/",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Basic {auth_token}"
                },
                "data": {
                    "src": "{from_number}",
                    "dst": "{to_number}",
                    "text": "{message}"
                },
                "auth_required": True,
                "auth_params": ["auth_id", "auth_token", "from_number"]
            },
            {
                "name": "MessageBird",
                "url": "https://rest.messagebird.com/messages",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "AccessKey {api_key}"
                },
                "data": {
                    "originator": "{from_number}",
                    "recipients": ["{to_number}"],
                    "body": "{message}"
                },
                "auth_required": True,
                "auth_params": ["api_key", "from_number"]
            },
            {
                "name": "ClickSend",
                "url": "https://rest.clicksend.com/v3/sms/send",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Basic {api_key}"
                },
                "data": {
                    "messages": [
                        {
                            "source": "php",
                            "from": "{from_number}",
                            "body": "{message}",
                            "to": "{to_number}"
                        }
                    ]
                },
                "auth_required": True,
                "auth_params": ["api_key", "from_number"]
            },
            {
                "name": "TextLocal",
                "url": "https://api.textlocal.in/send/",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json"
                },
                "data": {
                    "apikey": "{api_key}",
                    "message": "{message}",
                    "sender": "{from_number}",
                    "numbers": "{to_number}"
                },
                "auth_required": True,
                "auth_params": ["api_key", "from_number"]
            },
            {
                "name": "Free SMS API 1",
                "url": "https://api.example1.com/send",
                "method": "GET",
                "headers": {},
                "params": {
                    "number": "{to_number}",
                    "message": "{message}",
                    "key": "{api_key}"
                },
                "auth_required": True,
                "auth_params": ["api_key"]
            },
            {
                "name": "Free SMS API 2",
                "url": "https://api.example2.com/sms",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json"
                },
                "data": {
                    "recipient": "{to_number}",
                    "text": "{message}",
                    "api_token": "{api_key}"
                },
                "auth_required": True,
                "auth_params": ["api_key"]
            }
        ]

    def _load_config(self):
        """Carrega as configurações salvas"""
        try:
            with open('sms_config.json', 'r') as f:
                config = json.load(f)
                self.api_keys = config.get('api_keys', {})
                self.service_configs = config.get('service_configs', {})
        except FileNotFoundError:
            self.api_keys = {}
            self.service_configs = {}

    def _save_config(self):
        """Salva as configurações"""
        with open('sms_config.json', 'w') as f:
            json.dump({
                'api_keys': self.api_keys,
                'service_configs': self.service_configs
            }, f)

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: SPAM SMS É ILEGAL EM MUITOS PAÍSES! USE APENAS PARA TESTES AUTORIZADOS ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def rotate_service(self):
        """Rotaciona entre os serviços disponíveis"""
        available_services = [s for s in self.services 
                            if s['name'] not in self.used_services 
                            and all(k in self.api_keys for k in s.get('auth_params', []))]
        
        if not available_services:
            # Reseta se todas foram usadas
            self.used_services = []
            available_services = [s for s in self.services 
                                 if all(k in self.api_keys for k in s.get('auth_params', []))]
            if not available_services:
                return None

        service = random.choice(available_services)
        self.used_services.append(service['name'])
        return service

    def send_sms(self, to_number: str, message: str) -> bool:
        service = self.rotate_service()
        if not service:
            console.print("[red]Nenhum serviço configurado corretamente![/red]")
            return False

        try:
            # Prepara os dados da requisição
            endpoint = service['url']
            headers = {}
            data = {}
            params = {}

            # Substitui placeholders nos headers
            for key, value in service['headers'].items():
                headers[key] = value.format(**self.api_keys)

            # Prepara o corpo ou parâmetros da requisição
            request_data = {
                'to_number': to_number,
                'message': message,
                **self.api_keys
            }

            if service['method'] == 'GET':
                for key, value in service.get('params', {}).items():
                    params[key] = value.format(**request_data)
            else:
                if 'data' in service:
                    if isinstance(service['data'], dict):
                        data = {k: v.format(**request_data) for k, v in service['data'].items()}
                    else:
                        data = service['data'].format(**request_data)
                elif 'json' in service:
                    data = {k: v.format(**request_data) for k, v in service['json'].items()}

            # Faz a requisição
            if service['method'] == 'GET':
                response = requests.get(endpoint, headers=headers, params=params)
            elif service['method'] == 'POST':
                if 'Content-Type' in headers and 'application/json' in headers['Content-Type']:
                    response = requests.post(endpoint, headers=headers, json=data)
                else:
                    response = requests.post(endpoint, headers=headers, data=data)
            else:
                console.print(f"[red]Método {service['method']} não suportado para {service['name']}[/red]")
                return False

            # Verifica a resposta
            if response.status_code in [200, 201]:
                console.print(f"[green]SMS enviado via {service['name']}![/green]")
                return True
            else:
                console.print(f"[red]Erro {response.status_code} com {service['name']}: {response.text}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Erro ao usar {service['name']}: {str(e)}[/red]")
            return False

    def configure_services(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]Configuração de Serviços SMS[/bold]"))

            table = Table(title="Serviços Disponíveis", show_header=True, header_style="bold blue")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Serviço", style="green")
            table.add_column("Configurado", style="yellow")

            for i, service in enumerate(self.services, 1):
                configured = all(k in self.api_keys for k in service.get('auth_params', []))
                table.add_row(
                    str(i),
                    service['name'],
                    "✅" if configured else "❌"
                )

            console.print(table)

            console.print("\n[bold]Opções:[/bold]")
            console.print("1. Configurar serviço")
            console.print("2. Remover configuração")
            console.print("3. Voltar")

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3"])

            if choice == "1":
                service_num = IntPrompt.ask("Digite o número do serviço para configurar", 
                                          default=1, 
                                          show_default=False) - 1
                
                if 0 <= service_num < len(self.services):
                    service = self.services[service_num]
                    console.print(f"\n[bold]Configurando {service['name']}[/bold]")
                    
                    config = {}
                    for param in service['auth_params']:
                        value = Prompt.ask(f"Digite o valor para {param}", password="api_key" in param or "auth" in param)
                        config[param] = value
                    
                    self.api_keys.update(config)
                    self._save_config()
                    console.print("[green]Configuração salva com sucesso![/green]")
                else:
                    console.print("[red]Número de serviço inválido![/red]")
                
                input("\nPressione Enter para continuar...")
            
            elif choice == "2":
                if not self.api_keys:
                    console.print("[yellow]Nenhuma configuração para remover[/yellow]")
                    input("\nPressione Enter para continuar...")
                    continue
                
                console.print("\n[bold]Configurações atuais:[/bold]")
                for i, key in enumerate(self.api_keys.keys(), 1):
                    console.print(f"{i}. {key}: {self.api_keys[key][:3]}...{self.api_keys[key][-2:]}")
                
                try:
                    key_num = IntPrompt.ask("\nDigite o número da chave para remover", default=0) - 1
                    keys = list(self.api_keys.keys())
                    if 0 <= key_num < len(keys):
                        removed = keys[key_num]
                        self.api_keys.pop(removed)
                        self._save_config()
                        console.print(f"[green]Chave {removed} removida![/green]")
                except:
                    console.print("[red]Seleção inválida[/red]")
                
                input("\nPressione Enter para continuar...")
            
            elif choice == "3":
                return

    def send_single_sms(self):
        console.clear()
        console.print(Panel.fit("[bold]Envio de SMS Individual[/bold]"))

        if not any(all(k in self.api_keys for k in s.get('auth_params', [])) for s in self.services):
            console.print("[red]Nenhum serviço configurado corretamente![/red]")
            input("\nPressione Enter para voltar...")
            return

        to_number = Prompt.ask("Número de telefone destinatário (com código do país)")
        message = Prompt.ask("Mensagem SMS")
        repeat = IntPrompt.ask("Quantidade de envios", default=1)

        sent = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Enviando SMS...", total=repeat)

            for _ in range(repeat):
                if self.send_sms(to_number, message):
                    sent += 1
                progress.update(task, advance=1)
                time.sleep(random.uniform(1, 3))  # Atraso aleatório entre 1-3 segundos

        console.print(f"\n[green]{sent} de {repeat} SMS enviados com sucesso![/green]")
        input("\nPressione Enter para voltar...")

    def mass_sms_campaign(self):
        console.clear()
        console.print(Panel.fit("[bold]Campanha de SMS em Massa[/bold]"))

        if not any(all(k in self.api_keys for k in s.get('auth_params', [])) for s in self.services):
            console.print("[red]Nenhum serviço configurado corretamente![/red]")
            input("\nPressione Enter para voltar...")
            return

        numbers_file = Prompt.ask("Arquivo com números de telefone (um por linha)")
        message_file = Prompt.ask("Arquivo com mensagem SMS")

        try:
            with open(numbers_file, 'r') as f:
                numbers = [line.strip() for line in f if line.strip()]
            
            with open(message_file, 'r') as f:
                message = f.read().strip()
        except Exception as e:
            console.print(f"[red]Erro ao ler arquivos: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")
            return

        delay = IntPrompt.ask("Atraso entre envios (segundos)", default=5)
        max_sms = IntPrompt.ask("Número máximo de SMS para enviar", default=100)

        sent = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Enviando SMS...", total=min(len(numbers), max_sms))

            for number in numbers[:max_sms]:
                try:
                    if self.send_sms(number, message):
                        sent += 1
                    progress.update(task, advance=1, description=f"[cyan]Enviando... ({sent} enviados)")
                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper o envio?[/red]"):
                        break
                    continue
                except Exception as e:
                    console.print(f"[red]Erro: {str(e)}[/red]")
                    continue

        console.print(f"\n[green]Campanha concluída! {sent} SMS enviados.[/green]")
        input("\nPressione Enter para voltar...")

    def check_services(self):
        console.clear()
        console.print(Panel.fit("[bold]Verificar Serviços Configurados[/bold]"))

        working_services = []
        for service in self.services:
            if all(k in self.api_keys for k in service.get('auth_params', [])):
                working_services.append(service)

        if not working_services:
            console.print("[red]Nenhum serviço configurado corretamente![/red]")
            input("\nPressione Enter para voltar...")
            return

        console.print("\n[bold]Testando serviços...[/bold]")
        working = 0
        for service in working_services:
            console.print(f"\n[cyan]Testando {service['name']}...[/cyan]")
            try:
                # Teste simplificado - verifica apenas se as credenciais são válidas
                test_number = "1234567890"  # Número falso para teste
                test_message = "Teste de conexão - " + datetime.now().strftime("%H:%M:%S")
                
                request_data = {
                    'to_number': test_number,
                    'message': test_message,
                    **self.api_keys
                }

                endpoint = service['url']
                headers = {}
                for key, value in service['headers'].items():
                    headers[key] = value.format(**request_data)

                if service['method'] == 'GET':
                    params = {k: v.format(**request_data) for k, v in service.get('params', {}).items()}
                    response = requests.get(endpoint, headers=headers, params=params)
                else:
                    data = {k: v.format(**request_data) for k, v in service.get('data', {}).items()}
                    response = requests.post(endpoint, headers=headers, json=data)

                if response.status_code in [200, 201]:
                    console.print(f"[green]✅ {service['name']} funcionando![/green]")
                    working += 1
                else:
                    console.print(f"[yellow]⚠️ {service['name']} retornou código {response.status_code}[/yellow]")
                    console.print(f"Resposta: {response.text[:200]}...")

            except Exception as e:
                console.print(f"[red]❌ Erro com {service['name']}: {str(e)}[/red]")

        console.print(f"\n[bold]Resultado:[/bold] {working}/{len(working_services)} serviços funcionando")
        input("\nPressione Enter para voltar...")

    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()

            table = Table(title="Menu Principal", show_header=True, header_style="bold magenta")
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")

            table.add_row("1", "Configurar serviços de SMS")
            table.add_row("2", "Enviar SMS individual")
            table.add_row("3", "Campanha de SMS em massa")
            table.add_row("4", "Verificar serviços configurados")
            table.add_row("9", "Sair")

            console.print(table)

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4", "9"])

            if choice == "1":
                self.configure_services()
            elif choice == "2":
                self.send_single_sms()
            elif choice == "3":
                self.mass_sms_campaign()
            elif choice == "4":
                self.check_services()
            elif choice == "9":
                self._exit()

    def _exit(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: SPAM SMS É ILEGAL E PODE RESULTAR EM PESADAS MULTAS E PENALIDADES! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

if __name__ == '__main__':
    try:
        spammer = SMSSpammer()
        spammer.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
        sys.exit(1)
