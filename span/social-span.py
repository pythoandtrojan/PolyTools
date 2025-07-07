#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import requests
import json
from typing import List, Dict, Optional
from datetime import datetime

# Configuração de rich para interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

class SocialSpammer:
    def __init__(self):
        self.banners = [
            self._generate_banner_red(),
            self._generate_banner_blue(),
            self._generate_banner_green()
        ]
        self.platforms = {
            "Twitter/X": {
                "post_url": "https://api.twitter.com/2/tweets",
                "like_url": "https://api.twitter.com/2/users/{user_id}/likes",
                "follow_url": "https://api.twitter.com/2/users/{user_id}/following",
                "auth_method": "Bearer Token",
                "required_auth": ["bearer_token"]
            },
            "Instagram": {
                "post_url": "https://graph.instagram.com/me/media",
                "like_url": "https://graph.instagram.com/{media_id}/likes",
                "comment_url": "https://graph.instagram.com/{media_id}/comments",
                "auth_method": "OAuth Token",
                "required_auth": ["access_token"]
            },
            "Facebook": {
                "post_url": "https://graph.facebook.com/v18.0/me/feed",
                "comment_url": "https://graph.facebook.com/v18.0/{post_id}/comments",
                "react_url": "https://graph.facebook.com/v18.0/{post_id}/reactions",
                "auth_method": "OAuth Token",
                "required_auth": ["access_token"]
            },
            "LinkedIn": {
                "post_url": "https://api.linkedin.com/v2/ugcPosts",
                "comment_url": "https://api.linkedin.com/v2/socialActions/{post_urn}/comments",
                "react_url": "https://api.linkedin.com/v2/socialActions/{post_urn}/reactions",
                "auth_method": "OAuth Token",
                "required_auth": ["access_token"]
            },
            "Reddit": {
                "post_url": "https://oauth.reddit.com/api/submit",
                "comment_url": "https://oauth.reddit.com/api/comment",
                "upvote_url": "https://oauth.reddit.com/api/vote",
                "auth_method": "OAuth Token",
                "required_auth": ["access_token", "user_agent"]
            }
        }
        self.accounts = {}
        self._load_config()

    def _generate_banner_red(self) -> str:
        return """
[bold red]
 ███████╗ ██████╗  ██████╗██╗ █████╗ ██╗      ███████╗███████╗██████╗ ███████╗██████╗ 
 ██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║      ██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
 ███████╗██║   ██║██║     ██║███████║██║█████╗███████╗█████╗  ██████╔╝█████╗  ██████╔╝
 ╚════██║██║   ██║██║     ██║██╔══██║██║╚════╝╚════██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
 ███████║╚██████╔╝╚██████╗██║██║  ██║██║      ███████║███████╗██║  ██║███████╗██║  ██║
 ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚═╝      ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold white on red]       FERRAMENTA DE SPAM PARA REDES SOCIAIS - USE COM RESPONSABILIDADE![/bold white on red]
"""

    def _generate_banner_blue(self) -> str:
        return """
[bold blue]
  _____          _       _ _   _____                       _       _       
 / ____|        | |     (_) | / ____|                     (_)     (_)      
| (___    ___   | | __ _ _| || (___   ___  _ __ ___  _ __  _ _ __  _  ___ 
 \___ \  / _ \  | |/ _` | | | \___ \ / _ \| '_ ` _ \| '_ \| | '_ \| |/ __|
 ____) || (_) | | | (_| | | | ____) | (_) | | | | | | |_) | | | | | | (__ 
|_____/  \___/  |_|\__,_|_|_||_____/ \___/|_| |_| |_| .__/|_|_| |_|_|\___|
                                                     | |                  
                                                     |_|                  
[/bold blue]
[bold white on blue]       SOCIAL-SPAM TOOL - MULTIPLATAFORMA v2.0[/bold white on blue]
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
[bold black on green]       FERRAMENTA DE AUTOMAÇÃO PARA REDES SOCIAIS - SPAM CONTROLADO[/bold black on green]
"""

    def _load_config(self):
        """Carrega as configurações salvas"""
        try:
            with open('social_config.json', 'r') as f:
                config = json.load(f)
                self.accounts = config.get('accounts', {})
        except FileNotFoundError:
            self.accounts = {}

    def _save_config(self):
        """Salva as configurações"""
        with open('social_config.json', 'w') as f:
            json.dump({'accounts': self.accounts}, f)

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: SPAM EM REDES SOCIAIS PODE RESULTAR EM BANIMENTO E AÇÕES JUDICIAIS! ⚠️[/blink bold red]",
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

            table.add_row("1", "Gerenciar contas de redes sociais")
            table.add_row("2", "Postar em massa (Twitter, Facebook, etc.)")
            table.add_row("3", "Comentar em massa")
            table.add_row("4", "Curtir/Reagir em massa")
            table.add_row("5", "Seguir usuários em massa (Twitter/Instagram)")
            table.add_row("9", "Sair")

            console.print(table)

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3", "4", "5", "9"])

            if choice == "1":
                self.manage_accounts()
            elif choice == "2":
                self.mass_post()
            elif choice == "3":
                self.mass_comment()
            elif choice == "4":
                self.mass_like()
            elif choice == "5":
                self.mass_follow()
            elif choice == "9":
                self._exit()

    def manage_accounts(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]Gerenciamento de Contas[/bold]"))

            table = Table(title="Contas Configuradas", show_header=True, header_style="bold blue")
            table.add_column("Plataforma", style="cyan")
            table.add_column("Contas", style="green")

            for platform, accounts in self.accounts.items():
                table.add_row(platform, str(len(accounts)))

            console.print(table)

            console.print("\n[bold]Opções:[/bold]")
            console.print("1. Adicionar conta")
            console.print("2. Remover conta")
            console.print("3. Voltar")

            choice = Prompt.ask("Selecione uma opção", choices=["1", "2", "3"])

            if choice == "1":
                platform = Prompt.ask("Plataforma (Twitter, Instagram, Facebook, LinkedIn, Reddit)", 
                                    choices=["Twitter", "Instagram", "Facebook", "LinkedIn", "Reddit"])
                
                if platform not in self.accounts:
                    self.accounts[platform] = []

                auth_fields = self.platforms[platform]["required_auth"]
                account_data = {}
                for field in auth_fields:
                    account_data[field] = Prompt.ask(f"Digite o {field}", password="token" in field or "secret" in field)

                self.accounts[platform].append(account_data)
                self._save_config()
                console.print("[green]Conta adicionada com sucesso![/green]")
                input("\nPressione Enter para continuar...")

            elif choice == "2":
                if not self.accounts:
                    console.print("[yellow]Nenhuma conta para remover[/yellow]")
                    input("\nPressione Enter para continuar...")
                    continue

                platform = Prompt.ask("Plataforma para remover conta", 
                                    choices=list(self.accounts.keys()))
                
                if not self.accounts[platform]:
                    console.print(f"[yellow]Nenhuma conta no {platform}[/yellow]")
                    input("\nPressione Enter para continuar...")
                    continue

                console.print(f"\n[bold]Contas no {platform}:[/bold]")
                for i, acc in enumerate(self.accounts[platform], 1):
                    console.print(f"{i}. {acc.get('username', 'No username')}")

                try:
                    index = IntPrompt.ask("Digite o número da conta para remover", default=0) - 1
                    if 0 <= index < len(self.accounts[platform]):
                        removed = self.accounts[platform].pop(index)
                        self._save_config()
                        console.print(f"[green]Conta removida![/green]")
                except:
                    console.print("[red]Seleção inválida[/red]")
                
                input("\nPressione Enter para continuar...")

            elif choice == "3":
                return

    def mass_post(self):
        console.clear()
        console.print(Panel.fit("[bold]Postagem em Massa[/bold]"))

        platform = Prompt.ask("Plataforma", choices=list(self.platforms.keys()))
        
        if platform not in self.accounts or not self.accounts[platform]:
            console.print("[red]Nenhuma conta configurada para esta plataforma![/red]")
            input("\nPressione Enter para voltar...")
            return

        message = Prompt.ask("Mensagem para postar")
        repeat = IntPrompt.ask("Quantidade de postagens", default=1)
        delay = IntPrompt.ask("Atraso entre postagens (segundos)", default=10)

        success = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Postando...", total=repeat)

            for _ in range(repeat):
                account = random.choice(self.accounts[platform])
                try:
                    if self._post_to_platform(platform, account, message):
                        success += 1
                    progress.update(task, advance=1)
                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper?[/red]"):
                        break
                    continue

        console.print(f"\n[green]{success}/{repeat} postagens realizadas com sucesso![/green]")
        input("\nPressione Enter para voltar...")

    def _post_to_platform(self, platform: str, account: Dict, message: str) -> bool:
        """Posta em uma plataforma específica"""
        try:
            if platform == "Twitter":
                headers = {"Authorization": f"Bearer {account['bearer_token']}"}
                data = {"text": message}
                response = requests.post(
                    self.platforms["Twitter"]["post_url"],
                    headers=headers,
                    json=data
                )
                return response.status_code == 201

            elif platform == "Instagram":
                params = {
                    "access_token": account["access_token"],
                    "caption": message
                }
                response = requests.post(
                    self.platforms["Instagram"]["post_url"],
                    params=params
                )
                return response.status_code == 200

            elif platform == "Facebook":
                params = {
                    "access_token": account["access_token"],
                    "message": message
                }
                response = requests.post(
                    self.platforms["Facebook"]["post_url"],
                    params=params
                )
                return response.status_code == 200

            elif platform == "Reddit":
                headers = {
                    "Authorization": f"bearer {account['access_token']}",
                    "User-Agent": account["user_agent"]
                }
                data = {
                    "title": message[:50],
                    "text": message,
                    "sr": "all",  # Subreddit padrão
                    "kind": "self"
                }
                response = requests.post(
                    self.platforms["Reddit"]["post_url"],
                    headers=headers,
                    data=data
                )
                return response.status_code == 200

            else:
                console.print(f"[red]Plataforma {platform} não suportada ainda.[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Erro ao postar: {str(e)}[/red]")
            return False

    def mass_comment(self):
        console.clear()
        console.print(Panel.fit("[bold]Comentários em Massa[/bold]"))

        platform = Prompt.ask("Plataforma", choices=["Twitter", "Instagram", "Facebook", "Reddit"])
        
        if platform not in self.accounts or not self.accounts[platform]:
            console.print("[red]Nenhuma conta configurada para esta plataforma![/red]")
            input("\nPressione Enter para voltar...")
            return

        target_url = Prompt.ask("URL do post para comentar")
        message = Prompt.ask("Mensagem para comentar")
        repeat = IntPrompt.ask("Quantidade de comentários", default=1)
        delay = IntPrompt.ask("Atraso entre comentários (segundos)", default=5)

        success = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Comentando...", total=repeat)

            for _ in range(repeat):
                account = random.choice(self.accounts[platform])
                try:
                    if self._comment_on_platform(platform, account, target_url, message):
                        success += 1
                    progress.update(task, advance=1)
                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper?[/red]"):
                        break
                    continue

        console.print(f"\n[green]{success}/{repeat} comentários postados com sucesso![/green]")
        input("\nPressione Enter para voltar...")

    def _comment_on_platform(self, platform: str, account: Dict, target_url: str, message: str) -> bool:
        """Comenta em um post específico"""
        try:
            if platform == "Twitter":
                # Extrai o tweet_id da URL (ex: https://twitter.com/user/status/1234567890)
                tweet_id = target_url.split("/")[-1]
                headers = {"Authorization": f"Bearer {account['bearer_token']}"}
                data = {"text": message, "reply": {"in_reply_to_tweet_id": tweet_id}}
                response = requests.post(
                    self.platforms["Twitter"]["post_url"],
                    headers=headers,
                    json=data
                )
                return response.status_code == 201

            elif platform == "Reddit":
                # Extrai o post_id da URL (ex: https://reddit.com/r/subreddit/comments/abc123/post_title/)
                post_id = target_url.split("/comments/")[1].split("/")[0]
                headers = {
                    "Authorization": f"bearer {account['access_token']}",
                    "User-Agent": account["user_agent"]
                }
                data = {
                    "thing_id": f"t3_{post_id}",
                    "text": message
                }
                response = requests.post(
                    self.platforms["Reddit"]["comment_url"],
                    headers=headers,
                    data=data
                )
                return response.status_code == 200

            else:
                console.print(f"[red]Comentários automáticos em {platform} ainda não suportados.[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Erro ao comentar: {str(e)}[/red]")
            return False

    def mass_like(self):
        console.clear()
        console.print(Panel.fit("[bold]Curtidas/Reações em Massa[/bold]"))

        platform = Prompt.ask("Plataforma", choices=["Twitter", "Instagram", "Facebook", "Reddit"])
        
        if platform not in self.accounts or not self.accounts[platform]:
            console.print("[red]Nenhuma conta configurada para esta plataforma![/red]")
            input("\nPressione Enter para voltar...")
            return

        target_url = Prompt.ask("URL do post para curtir")
        repeat = IntPrompt.ask("Quantidade de curtidas", default=1)
        delay = IntPrompt.ask("Atraso entre curtidas (segundos)", default=3)

        success = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Curtindo...", total=repeat)

            for _ in range(repeat):
                account = random.choice(self.accounts[platform])
                try:
                    if self._like_on_platform(platform, account, target_url):
                        success += 1
                    progress.update(task, advance=1)
                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper?[/red]"):
                        break
                    continue

        console.print(f"\n[green]{success}/{repeat} curtidas realizadas com sucesso![/green]")
        input("\nPressione Enter para voltar...")

    def _like_on_platform(self, platform: str, account: Dict, target_url: str) -> bool:
        """Curtir/Reagir a um post"""
        try:
            if platform == "Twitter":
                tweet_id = target_url.split("/")[-1]
                headers = {"Authorization": f"Bearer {account['bearer_token']}"}
                data = {"tweet_id": tweet_id}
                response = requests.post(
                    self.platforms["Twitter"]["like_url"].format(user_id=account.get("user_id", "me")),
                    headers=headers,
                    json=data
                )
                return response.status_code == 200

            elif platform == "Reddit":
                post_id = target_url.split("/comments/")[1].split("/")[0]
                headers = {
                    "Authorization": f"bearer {account['access_token']}",
                    "User-Agent": account["user_agent"]
                }
                data = {
                    "dir": 1,  # 1 = upvote, -1 = downvote
                    "id": f"t3_{post_id}"
                }
                response = requests.post(
                    self.platforms["Reddit"]["upvote_url"],
                    headers=headers,
                    data=data
                )
                return response.status_code == 200

            else:
                console.print(f"[red]Curtidas automáticas em {platform} ainda não suportadas.[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Erro ao curtir: {str(e)}[/red]")
            return False

    def mass_follow(self):
        console.clear()
        console.print(Panel.fit("[bold]Seguir Usuários em Massa[/bold]"))

        platform = Prompt.ask("Plataforma", choices=["Twitter", "Instagram"])
        
        if platform not in self.accounts or not self.accounts[platform]:
            console.print("[red]Nenhuma conta configurada para esta plataforma![/red]")
            input("\nPressione Enter para voltar...")
            return

        target_user = Prompt.ask("Usuário para seguir (ou arquivo .txt com lista)")
        repeat = IntPrompt.ask("Quantidade de seguidores", default=1)
        delay = IntPrompt.ask("Atraso entre seguidores (segundos)", default=5)

        if os.path.exists(target_user) and target_user.endswith(".txt"):
            with open(target_user, "r") as f:
                users = [line.strip() for line in f if line.strip()]
        else:
            users = [target_user]

        success = 0
        with Progress() as progress:
            task = progress.add_task("[cyan]Seguindo...", total=min(repeat, len(users)))

            for user in users[:repeat]:
                account = random.choice(self.accounts[platform])
                try:
                    if self._follow_on_platform(platform, account, user):
                        success += 1
                    progress.update(task, advance=1)
                    time.sleep(delay)
                except KeyboardInterrupt:
                    if Confirm.ask("\n[red]Deseja interromper?[/red]"):
                        break
                    continue

        console.print(f"\n[green]{success}/{min(repeat, len(users))} usuários seguidos com sucesso![/green]")
        input("\nPressione Enter para voltar...")

    def _follow_on_platform(self, platform: str, account: Dict, target_user: str) -> bool:
        """Segue um usuário específico"""
        try:
            if platform == "Twitter":
                headers = {"Authorization": f"Bearer {account['bearer_token']}"}
                data = {"target_user_id": target_user}
                response = requests.post(
                    self.platforms["Twitter"]["follow_url"].format(user_id=account.get("user_id", "me")),
                    headers=headers,
                    json=data
                )
                return response.status_code == 200

            else:
                console.print(f"[red]Follow automático em {platform} ainda não suportado.[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Erro ao seguir: {str(e)}[/red]")
            return False

    def _exit(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: AUTOMAÇÃO EM REDES SOCIAIS PODE VIOLAR TERMOS DE SERVIÇO! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

if __name__ == '__main__':
    try:
        spammer = SocialSpammer()
        spammer.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
        sys.exit(1)
