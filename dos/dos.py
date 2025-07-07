#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import threading
from queue import Queue
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

class WebSpammer:
    def __init__(self):
        self.banners = [
            self._generate_banner_red(),
            self._generate_banner_blue(),
            self._generate_banner_green()
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        self.proxies = []
        self._load_config()

    def _generate_banner_red(self) -> str:
        return """
[bold red]
 ██╗    ██╗███████╗██████╗     ███████╗██████╗  █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ 
 ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔══██╗██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██████╔╝███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝    ███████║██║     ██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold white on red]       FERRAMENTA DE SPAM PARA WEB - USE COM RESPONSABILIDADE![/bold white on red]
"""

    def _generate_banner_blue(self) -> str:
        return """
[bold blue]
  _____          _       _____                       _       _       
 / ____|        | |     / ____|                     (_)     (_)      
| (___    ___   | | __ | (___   ___  _ __ ___  _ __  _ _ __  _  ___ 
 \___ \  / _ \  | |/ /  \___ \ / _ \| '_ ` _ \| '_ \| | '_ \| |/ __|
 ____) || (_) | |   <   ____) | (_) | | | | | | |_) | | | | | | (__ 
|_____/  \___/  |_|\_\ |_____/ \___/|_| |_| |_| .__/|_|_| |_|_|\___|
                                               | |                  
                                               |_|                  
[/bold blue]
[bold white on blue]       WEB SPAMMER TOOL - MULTI-MÉTODOS v3.0[/bold white on blue]
"""

    def _generate_banner_green(self) -> str:
        return """
[bold green]
  ________ _______ ________  ___  ___  _______   ________  _______   ________  ___       ___  ________     
 |\   ____\\  ___ \\\_____  \|\  \|\  \|\  ___ \ |\   __  \|\  ___ \ |\   __  \|\  \     |\  \|\   __  \    
 \ \  \___|\ \   __/|/ ___/\ \  \ \  \ \   __/|\ \  \|\  \ \   __/|\ \  \|\  \ \  \    \ \  \ \  \|\  \   
  \ \  \  __\ \  \_|/ /___/_\ \  \ \  \ \  \_|/_\ \  \\\  \ \  \_|/_\ \  \\\  \ \  \    \ \  \ \  \\\  \  
   \ \  \|\  \ \  \_|\ \  \|\  \ \  \ \  \ \  \_|\ \ \  \\\  \ \  \_|\ \ \  \\\  \ \  \____\ \  \ \  \\\  \ 
    \ \_______\ \__\ \ \_______\ \__\ \__\ \_______\ \_______\ \_______\ \_______\ \_______\ \__\ \_______\
     \|_______|\|__|  \|_______|\|__|\|__|\|_______|\|_______|\|_______|\|_______|\|_______|\|__|\|_______|
[/bold green]
[bold black on green]       FERRAMENTA DE AUTOMAÇÃO WEB - SPAM AVANÇADO[/bold black on green]
"""

    def _load_config(self):
        """Carrega configurações de proxies se existirem"""
        try:
            with open('proxies.txt', 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.proxies = []

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: SPAM WEB É ILEGAL E PODE RESULTAR EM AÇÕES JUDICIAIS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def show_main_menu(self):
        while True:
            console.clear()
            self.show_banner()

            table = Table(title="Menu Principal", show_header=True, header_style="bold magenta")
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")

            table.add_row("1", "Spam de Formulários Web")
            table.add_row("2", "Spam de Comentários")
            table.add_row("3", "Spam de Contato (Email/Telefone)")
            table.add_row("4", "Spam de Registros")
            table.add_row("5", "Configurar Proxies")
            table.add_row("9", "Sair")

            console.print(table)

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4", "5", "9"])

            if choice == "1":
                self.form_spam()
            elif choice == "2":
                self.comment_spam()
            elif choice == "3":
                self.contact_spam()
            elif choice == "4":
                self.registration_spam()
            elif choice == "5":
                self.configure_proxies()
            elif choice == "9":
                self._exit()

    def configure_proxies(self):
        console.clear()
        console.print(Panel.fit("[bold]Configuração de Proxies[/bold]"))

        if self.proxies:
            console.print("\n[bold]Proxies atuais:[/bold]")
            for i, proxy in enumerate(self.proxies, 1):
                console.print(f"{i}. {proxy}")
        else:
            console.print("\n[yellow]Nenhum proxy configurado[/yellow]")

        console.print("\n[bold]Opções:[/bold]")
        console.print("1. Adicionar proxy")
        console.print("2. Remover proxy")
        console.print("3. Carregar de arquivo")
        console.print("4. Voltar")

        choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4"])

        if choice == "1":
            proxy = Prompt.ask("Digite o proxy (formato: ip:porta ou user:pass@ip:porta)")
            self.proxies.append(proxy)
            with open('proxies.txt', 'w') as f:
                f.write("\n".join(self.proxies))
            console.print("[green]Proxy adicionado com sucesso![/green]")
            input("\nPressione Enter para continuar...")

        elif choice == "2":
            if not self.proxies:
                console.print("[yellow]Nenhum proxy para remover[/yellow]")
                input("\nPressione Enter para continuar...")
                return

            proxy_num = IntPrompt.ask("Digite o número do proxy para remover", default=1) - 1
            if 0 <= proxy_num < len(self.proxies):
                removed = self.proxies.pop(proxy_num)
                with open('proxies.txt', 'w') as f:
                    f.write("\n".join(self.proxies))
                console.print(f"[green]Proxy {removed} removido![/green]")
            else:
                console.print("[red]Número inválido[/red]")
            input("\nPressione Enter para continuar...")

        elif choice == "3":
            file_path = Prompt.ask("Caminho do arquivo com proxies (um por linha)")
            try:
                with open(file_path, 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                with open('proxies.txt', 'w') as f:
                    f.write("\n".join(self.proxies))
                console.print(f"[green]{len(self.proxies)} proxies carregados![/green]")
            except Exception as e:
                console.print(f"[red]Erro ao carregar arquivo: {str(e)}[/red]")
            input("\nPressione Enter para continuar...")

    def form_spam(self):
        console.clear()
        console.print(Panel.fit("[bold]Spam de Formulários Web[/bold]"))

        url = Prompt.ask("URL do formulário")
        threads = IntPrompt.ask("Número de threads", default=5)
        submissions = IntPrompt.ask("Total de envios", default=100)
        delay = IntPrompt.ask("Atraso entre envios (segundos)", default=1)

        # Detectar campos do formulário
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            if not forms:
                console.print("[red]Nenhum formulário encontrado na página![/red]")
                input("\nPressione Enter para voltar...")
                return

            form = forms[0]
            form_action = form.get('action', url)
            form_method = form.get('method', 'post').lower()
            form_url = urljoin(url, form_action)

            fields = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name and not input_tag.get('type') in ['submit', 'button']:
                    fields[name] = input_tag.get('value', '')

            console.print("\n[bold]Campos detectados:[/bold]")
            for field in fields:
                console.print(f"- {field}")

            if not fields:
                console.print("[red]Nenhum campo detectado no formulário![/red]")
                input("\nPressione Enter para voltar...")
                return

            # Configurar valores para spam
            for field in fields:
                if 'email' in field.lower():
                    fields[field] = f"user{random.randint(1, 10000)}@example.com"
                elif 'name' in field.lower():
                    fields[field] = f"User{random.randint(1, 1000)}"
                elif 'phone' in field.lower():
                    fields[field] = f"55{random.randint(11, 99)}9{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
                else:
                    fields[field] = f"spam_value_{random.randint(1, 10000)}"

            console.print("\n[bold]Valores de exemplo:[/bold]")
            for field, value in fields.items():
                console.print(f"- {field}: {value}")

            if not Confirm.ask("\nDeseja continuar com esses valores?"):
                return

            # Iniciar envio
            q = Queue()
            for _ in range(submissions):
                q.put({**fields})  # Cria uma cópia para cada envio

            def worker():
                while not q.empty():
                    data = q.get()
                    try:
                        proxy = random.choice(self.proxies) if self.proxies else None
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        
                        headers = {
                            "User-Agent": random.choice(self.user_agents),
                            "Referer": url
                        }

                        if form_method == 'post':
                            response = requests.post(form_url, data=data, headers=headers, proxies=proxies)
                        else:
                            response = requests.get(form_url, params=data, headers=headers, proxies=proxies)

                        if response.status_code == 200:
                            console.print(f"[green]Envio #{submissions - q.qsize() + 1} realizado![/green]")
                        else:
                            console.print(f"[yellow]Falha no envio #{submissions - q.qsize() + 1}: {response.status_code}[/yellow]")

                        time.sleep(delay)
                    except Exception as e:
                        console.print(f"[red]Erro: {str(e)}[/red]")
                    finally:
                        q.task_done()

            with Progress() as progress:
                task = progress.add_task("[cyan]Enviando formulários...", total=submissions)
                
                for _ in range(threads):
                    t = threading.Thread(target=worker, daemon=True)
                    t.start()

                while not q.empty():
                    progress.update(task, completed=submissions - q.qsize())
                    time.sleep(0.1)

            console.print("\n[green]Campanha de spam concluída![/green]")
            input("\nPressione Enter para voltar...")

        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")

    def comment_spam(self):
        console.clear()
        console.print(Panel.fit("[bold]Spam de Comentários[/bold]"))

        url = Prompt.ask("URL da página com comentários")
        threads = IntPrompt.ask("Número de threads", default=3)
        comments = IntPrompt.ask("Total de comentários", default=50)
        delay = IntPrompt.ask("Atraso entre comentários (segundos)", default=2)

        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Tentar encontrar formulário de comentários
            comment_form = None
            possible_selectors = [
                'form[action*="comment"]', 
                'form[id*="comment"]',
                'form[class*="comment"]'
            ]

            for selector in possible_selectors:
                if soup.select_one(selector):
                    comment_form = soup.select_one(selector)
                    break

            if not comment_form:
                console.print("[red]Nenhum formulário de comentários detectado![/red]")
                input("\nPressione Enter para voltar...")
                return

            form_action = comment_form.get('action', url)
            form_method = comment_form.get('method', 'post').lower()
            form_url = urljoin(url, form_action)

            fields = {}
            for input_tag in comment_form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and not input_tag.get('type') in ['submit', 'button']:
                    fields[name] = input_tag.get('value', '')

            console.print("\n[bold]Campos detectados:[/bold]")
            for field in fields:
                console.print(f"- {field}")

            # Configurar valores para spam
            sample_comments = [
                "Ótimo post! Muito útil.",
                "Obrigado por compartilhar!",
                "Isso é spam? Não, claro que não!",
                "Comentário automático de teste",
                "Estou aprendendo muito com este site",
                "Quando será a próxima atualização?",
                "Excelente conteúdo, parabéns!",
                "Poderia fazer um tutorial sobre isso?"
            ]

            for field in fields:
                if 'comment' in field.lower() or 'message' in field.lower():
                    fields[field] = random.choice(sample_comments)
                elif 'name' in field.lower():
                    fields[field] = f"User{random.randint(1, 1000)}"
                elif 'email' in field.lower():
                    fields[field] = f"user{random.randint(1, 10000)}@example.com"
                else:
                    fields[field] = f"value_{random.randint(1, 1000)}"

            if not Confirm.ask("\nDeseja continuar com esses valores?"):
                return

            q = Queue()
            for _ in range(comments):
                q.put({**fields})  # Cria uma cópia para cada comentário

            def worker():
                while not q.empty():
                    data = q.get()
                    try:
                        proxy = random.choice(self.proxies) if self.proxies else None
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        
                        headers = {
                            "User-Agent": random.choice(self.user_agents),
                            "Referer": url
                        }

                        if form_method == 'post':
                            response = requests.post(form_url, data=data, headers=headers, proxies=proxies)
                        else:
                            response = requests.get(form_url, params=data, headers=headers, proxies=proxies)

                        if response.status_code == 200:
                            console.print(f"[green]Comentário #{comments - q.qsize() + 1} postado![/green]")
                        else:
                            console.print(f"[yellow]Falha no comentário #{comments - q.qsize() + 1}: {response.status_code}[/yellow]")

                        time.sleep(delay)
                    except Exception as e:
                        console.print(f"[red]Erro: {str(e)}[/red]")
                    finally:
                        q.task_done()

            with Progress() as progress:
                task = progress.add_task("[cyan]Postando comentários...", total=comments)
                
                for _ in range(threads):
                    t = threading.Thread(target=worker, daemon=True)
                    t.start()

                while not q.empty():
                    progress.update(task, completed=comments - q.qsize())
                    time.sleep(0.1)

            console.print("\n[green]Spam de comentários concluído![/green]")
            input("\nPressione Enter para voltar...")

        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")

    def contact_spam(self):
        console.clear()
        console.print(Panel.fit("[bold]Spam de Formulários de Contato[/bold]"))

        url = Prompt.ask("URL da página de contato")
        threads = IntPrompt.ask("Número de threads", default=3)
        messages = IntPrompt.ask("Total de mensagens", default=50)
        delay = IntPrompt.ask("Atraso entre mensagens (segundos)", default=3)

        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            contact_form = None
            possible_selectors = [
                'form[action*="contact"]', 
                'form[id*="contact"]',
                'form[class*="contact"]'
            ]

            for selector in possible_selectors:
                if soup.select_one(selector):
                    contact_form = soup.select_one(selector)
                    break

            if not contact_form:
                console.print("[red]Nenhum formulário de contato detectado![/red]")
                input("\nPressione Enter para voltar...")
                return

            form_action = contact_form.get('action', url)
            form_method = contact_form.get('method', 'post').lower()
            form_url = urljoin(url, form_action)

            fields = {}
            for input_tag in contact_form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and not input_tag.get('type') in ['submit', 'button']:
                    fields[name] = input_tag.get('value', '')

            console.print("\n[bold]Campos detectados:[/bold]")
            for field in fields:
                console.print(f"- {field}")

            # Configurar valores para spam
            sample_messages = [
                "Olá, gostaria de mais informações!",
                "Quando terão novas vagas?",
                "Preciso de suporte técnico urgente!",
                "Quero fazer uma reclamação",
                "Seu produto é excelente, parabéns!",
                "Poderia me enviar um orçamento?",
                "Estou interessado em parceria",
                "Como faço para cancelar minha conta?"
            ]

            for field in fields:
                if 'message' in field.lower() or 'content' in field.lower():
                    fields[field] = random.choice(sample_messages)
                elif 'name' in field.lower():
                    fields[field] = f"User{random.randint(1, 1000)}"
                elif 'email' in field.lower():
                    fields[field] = f"user{random.randint(1, 10000)}@example.com"
                elif 'phone' in field.lower():
                    fields[field] = f"55{random.randint(11, 99)}9{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
                else:
                    fields[field] = f"data_{random.randint(1, 1000)}"

            if not Confirm.ask("\nDeseja continuar com esses valores?"):
                return

            q = Queue()
            for _ in range(messages):
                q.put({**fields})  # Cria uma cópia para cada mensagem

            def worker():
                while not q.empty():
                    data = q.get()
                    try:
                        proxy = random.choice(self.proxies) if self.proxies else None
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        
                        headers = {
                            "User-Agent": random.choice(self.user_agents),
                            "Referer": url
                        }

                        if form_method == 'post':
                            response = requests.post(form_url, data=data, headers=headers, proxies=proxies)
                        else:
                            response = requests.get(form_url, params=data, headers=headers, proxies=proxies)

                        if response.status_code == 200:
                            console.print(f"[green]Mensagem #{messages - q.qsize() + 1} enviada![/green]")
                        else:
                            console.print(f"[yellow]Falha na mensagem #{messages - q.qsize() + 1}: {response.status_code}[/yellow]")

                        time.sleep(delay)
                    except Exception as e:
                        console.print(f"[red]Erro: {str(e)}[/red]")
                    finally:
                        q.task_done()

            with Progress() as progress:
                task = progress.add_task("[cyan]Enviando mensagens...", total=messages)
                
                for _ in range(threads):
                    t = threading.Thread(target=worker, daemon=True)
                    t.start()

                while not q.empty():
                    progress.update(task, completed=messages - q.qsize())
                    time.sleep(0.1)

            console.print("\n[green]Spam de contato concluído![/green]")
            input("\nPressione Enter para voltar...")

        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")

    def registration_spam(self):
        console.clear()
        console.print(Panel.fit("[bold]Spam de Registros[/bold]"))

        url = Prompt.ask("URL da página de registro")
        threads = IntPrompt.ask("Número de threads", default=3)
        registrations = IntPrompt.ask("Total de registros", default=30)
        delay = IntPrompt.ask("Atraso entre registros (segundos)", default=5)

        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            register_form = None
            possible_selectors = [
                'form[action*="register"]', 
                'form[id*="register"]',
                'form[class*="register"]',
                'form[action*="signup"]',
                'form[id*="signup"]'
            ]

            for selector in possible_selectors:
                if soup.select_one(selector):
                    register_form = soup.select_one(selector)
                    break

            if not register_form:
                console.print("[red]Nenhum formulário de registro detectado![/red]")
                input("\nPressione Enter para voltar...")
                return

            form_action = register_form.get('action', url)
            form_method = register_form.get('method', 'post').lower()
            form_url = urljoin(url, form_action)

            fields = {}
            for input_tag in register_form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and not input_tag.get('type') in ['submit', 'button']:
                    fields[name] = input_tag.get('value', '')

            console.print("\n[bold]Campos detectados:[/bold]")
            for field in fields:
                console.print(f"- {field}")

            # Configurar valores para spam
            domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]
            
            for field in fields:
                if 'email' in field.lower():
                    fields[field] = f"user{random.randint(1, 10000)}@{random.choice(domains)}"
                elif 'user' in field.lower():
                    fields[field] = f"user{random.randint(1, 1000)}"
                elif 'name' in field.lower():
                    fields[field] = f"User{random.randint(1, 1000)}"
                elif 'pass' in field.lower():
                    fields[field] = f"Password{random.randint(1000, 9999)}!"
                elif 'phone' in field.lower():
                    fields[field] = f"55{random.randint(11, 99)}9{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
                else:
                    fields[field] = f"data_{random.randint(1, 1000)}"

            if not Confirm.ask("\nDeseja continuar com esses valores?"):
                return

            q = Queue()
            for _ in range(registrations):
                q.put({**fields})  # Cria uma cópia para cada registro

            def worker():
                while not q.empty():
                    data = q.get()
                    try:
                        proxy = random.choice(self.proxies) if self.proxies else None
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        
                        headers = {
                            "User-Agent": random.choice(self.user_agents),
                            "Referer": url
                        }

                        if form_method == 'post':
                            response = requests.post(form_url, data=data, headers=headers, proxies=proxies)
                        else:
                            response = requests.get(form_url, params=data, headers=headers, proxies=proxies)

                        if response.status_code == 200:
                            console.print(f"[green]Registro #{registrations - q.qsize() + 1} criado![/green]")
                        else:
                            console.print(f"[yellow]Falha no registro #{registrations - q.qsize() + 1}: {response.status_code}[/yellow]")

                        time.sleep(delay)
                    except Exception as e:
                        console.print(f"[red]Erro: {str(e)}[/red]")
                    finally:
                        q.task_done()

            with Progress() as progress:
                task = progress.add_task("[cyan]Criando registros...", total=registrations)
                
                for _ in range(threads):
                    t = threading.Thread(target=worker, daemon=True)
                    t.start()

                while not q.empty():
                    progress.update(task, completed=registrations - q.qsize())
                    time.sleep(0.1)

            console.print("\n[green]Spam de registros concluído![/green]")
            input("\nPressione Enter para voltar...")

        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
            input("\nPressione Enter para voltar...")

    def _exit(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: SPAM WEB PODE SER ILEGAL E RESULTAR EM BLOQUEIOS OU AÇÕES JUDICIAIS! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

if __name__ == '__main__':
    try:
        spammer = WebSpammer()
        spammer.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
        sys.exit(1) 
