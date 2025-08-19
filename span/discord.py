#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import discord
import asyncio
import os
import sys
from colorama import Fore, Style, init
import random
import time
import aiohttp

# Inicializar colorama
init(autoreset=True)

class DiscordSpammer:
    def __init__(self):
        self.client = discord.Client(intents=discord.Intents.all())
        self.token = ""
        self.target_channel_id = None
        self.message = ""
        self.delay = 1
        self.spam_count = 0
        self.is_running = False
        
    def print_random_banner(self):
        banners = [
            f"""
{Fore.RED}
██████╗ ██╗███████╗ ██████╗ ██████╗ ██████╗ ██████╗     ███████╗██████╗  █████╗ ███╗   ███╗
██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔══██╗████╗ ████║
██║  ██║██║███████╗██║     ██║   ██║██████╔╝██║  ██║    ███████╗██████╔╝███████║██╔████╔██║
██║  ██║██║╚════██║██║     ██║   ██║██╔══██╗██║  ██║    ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║
██████╔╝██║███████║╚██████╗╚██████╔╝██║  ██║██████╔╝    ███████║██║     ██║  ██║██║ ╚═╝ ██║
╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝     ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}                           Discord Spam Testing Tool - PentestGPT
{Fore.YELLOW}                      ⚠️  Apenas para testes autorizados  ⚠️
{Style.RESET_ALL}
""",
            f"""
{Fore.MAGENTA}
╔╦╗╔═╗╔═╗╔═╗╦╔═╗  ╔═╗╔═╗╔═╗╔═╗╦  ╔═╗  ╔═╗╔═╗╔═╗╔╦╗╔═╗╦═╗
 ║║║╣ ╚═╗╚═╗║║╣   ╠═╝║ ║║ ╦║╣ ║  ║╣   ║  ║ ║╠═╝ ║║║╣ ╠╦╝
═╩╝╚═╝╚═╝╚═╝╩╚═╝  ╩  ╚═╝╚═╝╚═╝╩═╝╚═╝  ╚═╝╚═╝╩  ═╩╝╚═╝╩╚═
{Style.RESET_ALL}
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                   DISCORD SPAM TESTING TOOL                        ║
{Fore.CYAN}║                   PentestGPT Security Suite                        ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════╝
{Fore.YELLOW}                      ⚠️  Apenas para testes autorizados  ⚠️
{Style.RESET_ALL}
""",
            f"""
{Fore.GREEN}
▓█████▄  ██▀███   ▄▄▄       ██▓     ██▓    ▄▄▄      ▓█████▄  ▄▄▄       ██▀███  
▒██▀ ██▌▓██ ▒ ██▒▒████▄    ▓██▒    ▓██▒   ▒████▄    ▒██▀ ██▌▒████▄    ▓██ ▒ ██▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░    ▒██░   ▒██  ▀█▄  ░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ▒██░    ▒██░   ░██▄▄▄▄██ ░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░██████▒░██████▒▓█   ▓██▒░▒████▓  ▓█   ▓██▒░██▓ ▒██▒
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░▒▒   ▓▒█░ ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░ ▒   ▒▒ ░ ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░
 ░ ░  ░   ░░   ░   ░   ▒     ░ ░     ░ ░    ░   ▒    ░ ░  ░   ░   ▒     ░░   ░ 
   ░       ░           ░  ░    ░  ░    ░  ░     ░  ░   ░          ░  ░   ░     
 ░                                                          ░                   
{Style.RESET_ALL}
{Fore.CYAN}                           Advanced Testing Framework
{Fore.YELLOW}                      ⚠️  Apenas para testes autorizados  ⚠️
{Style.RESET_ALL}
"""
        ]
        
        print(random.choice(banners))
        
    def print_menu(self):
        menu = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════╗
{Fore.GREEN}║{Fore.YELLOW}                         MENU PRINCIPAL                          {Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════════════════════════╣
{Fore.GREEN}║  {Fore.CYAN}[1]{Fore.GREEN} Configurar Token do Bot                                    {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[2]{Fore.GREEN} Definir Canal Alvo                                         {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[3]{Fore.GREEN} Configurar Mensagem de Spam                               {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[4]{Fore.GREEN} Definir Delay entre Mensagens                             {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[5]{Fore.GREEN} Mostrar Configurações Atuais                              {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[6]{Fore.GREEN} Iniciar Spam Simples                                      {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[7]{Fore.GREEN} Spam com Múltiplas Mensagens                              {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[8]{Fore.GREEN} Spam com Embeds                                           {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[9]{Fore.GREEN} Testar Conexão                                            {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[10]{Fore.GREEN} Spam com Anexos/Imagens                                  {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[11]{Fore.GREEN} Spam Randomizado                                         {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[12]{Fore.GREEN} Limpar Terminal                                          {Fore.GREEN}║
{Fore.GREEN}║  {Fore.CYAN}[0]{Fore.GREEN} Sair                                                       {Fore.GREEN}║
{Fore.GREEN}╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)
        
    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_random_banner()
        
    def print_status(self, message, status="info"):
        if status == "success":
            print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")
        elif status == "error":
            print(f"{Fore.RED}[✗] {message}{Style.RESET_ALL}")
        elif status == "warning":
            print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")
            
    def configure_token(self):
        self.print_status("Configuração do Token", "info")
        token = input(f"{Fore.YELLOW}» Digite o token do bot Discord: {Style.RESET_ALL}")
        if token.strip():
            self.token = token.strip()
            self.print_status("Token configurado com sucesso!", "success")
        else:
            self.print_status("Token inválido!", "error")
            
    def configure_channel(self):
        self.print_status("Configuração do Canal", "info")
        try:
            channel_id = int(input(f"{Fore.YELLOW}» Digite o ID do canal alvo: {Style.RESET_ALL}"))
            self.target_channel_id = channel_id
            self.print_status(f"Canal configurado: {channel_id}", "success")
        except ValueError:
            self.print_status("ID do canal deve ser um número!", "error")
            
    def configure_message(self):
        self.print_status("Configuração da Mensagem", "info")
        message = input(f"{Fore.YELLOW}» Digite a mensagem de spam: {Style.RESET_ALL}")
        if message.strip():
            self.message = message
            self.print_status("Mensagem configurada!", "success")
        else:
            self.print_status("Mensagem não pode estar vazia!", "error")
            
    def configure_delay(self):
        self.print_status("Configuração do Delay", "info")
        try:
            delay = float(input(f"{Fore.YELLOW}» Digite o delay entre mensagens (segundos): {Style.RESET_ALL}"))
            if delay >= 0:
                self.delay = delay
                self.print_status(f"Delay configurado: {delay}s", "success")
            else:
                self.print_status("Delay deve ser um valor positivo!", "error")
        except ValueError:
            self.print_status("Delay deve ser um número!", "error")
            
    def show_config(self):
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════╗")
        print(f"║{Fore.YELLOW}               CONFIGURAÇÕES ATUAIS               {Fore.CYAN}║")
        print(f"╠══════════════════════════════════════════════════════╣")
        print(f"║ {Fore.GREEN}Token:{Fore.WHITE} {'Configurado' if self.token else 'Não configurado':<38} {Fore.CYAN}║")
        print(f"║ {Fore.GREEN}Canal:{Fore.WHITE} {str(self.target_channel_id) if self.target_channel_id else 'Não configurado':<38} {Fore.CYAN}║")
        print(f"║ {Fore.GREEN}Mensagem:{Fore.WHITE} {('Configurada' if self.message else 'Não configurada'):<34} {Fore.CYAN}║")
        print(f"║ {Fore.GREEN}Delay:{Fore.WHITE} {str(self.delay) + 's':<40} {Fore.CYAN}║")
        print(f"║ {Fore.GREEN}Msgs Enviadas:{Fore.WHITE} {str(self.spam_count):<32} {Fore.CYAN}║")
        print(f"╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
    async def test_connection(self):
        if not self.token:
            self.print_status("Configure o token primeiro!", "error")
            return
            
        self.print_status("Testando conexão...", "info")
        try:
            @self.client.event
            async def on_ready():
                self.print_status(f"Conectado como {self.client.user}!", "success")
                self.print_status(f"ID: {self.client.user.id}", "info")
                self.print_status(f"Servidores: {len(self.client.guilds)}", "info")
                await self.client.close()
                
            await self.client.start(self.token)
        except discord.LoginFailure:
            self.print_status("Token inválido!", "error")
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def start_spam(self):
        if not all([self.token, self.target_channel_id, self.message]):
            self.print_status("Configure todas as opções antes de iniciar!", "error")
            return
            
        print(f"\n{Fore.YELLOW}» Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        self.print_status("Iniciando spam...", "info")
        self.print_status("Pressione Ctrl+C para parar", "warning")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                self.print_status("Canal não encontrado!", "error")
                await self.client.close()
                return
                
            sent = 0
            self.is_running = True
            start_time = time.time()
            
            try:
                while (count == 0 or sent < count) and self.is_running:
                    await channel.send(self.message)
                    sent += 1
                    self.spam_count += 1
                    
                    elapsed = time.time() - start_time
                    rate = sent / elapsed if elapsed > 0 else 0
                    print(f"{Fore.GREEN}[{sent}] ✓ Mensagem enviada | Taxa: {rate:.2f} msg/s{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                self.print_status("Spam interrompido pelo usuário", "warning")
            except discord.HTTPException as e:
                if "rate limited" in str(e).lower():
                    self.print_status("Rate limit detectado! Aguardando...", "warning")
                    await asyncio.sleep(10)
                else:
                    self.print_status(f"Erro HTTP: {e}", "error")
            except Exception as e:
                self.print_status(f"Erro: {e}", "error")
            finally:
                self.is_running = False
                self.print_status(f"Total enviado: {sent} mensagens", "info")
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def multi_message_spam(self):
        if not all([self.token, self.target_channel_id]):
            self.print_status("Configure token e canal primeiro!", "error")
            return
            
        self.print_status("Configuração de Múltiplas Mensagens", "info")
        print(f"{Fore.YELLOW}» Digite as mensagens (digite 'FIM' para terminar):{Style.RESET_ALL}")
        
        messages = []
        while True:
            msg = input(f"{Fore.CYAN}→ Mensagem {len(messages) + 1}: {Style.RESET_ALL}")
            if msg.upper() == 'FIM':
                break
            if msg.strip():
                messages.append(msg)
                
        if not messages:
            self.print_status("Nenhuma mensagem configurada!", "error")
            return
            
        print(f"\n{Fore.YELLOW}» Quantos ciclos? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            cycles = int(input())
        except ValueError:
            cycles = 0
            
        self.print_status(f"Iniciando spam com {len(messages)} mensagens...", "info")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                self.print_status("Canal não encontrado!", "error")
                await self.client.close()
                return
                
            cycle_count = 0
            self.is_running = True
            
            try:
                while (cycles == 0 or cycle_count < cycles) and self.is_running:
                    for i, msg in enumerate(messages):
                        if not self.is_running:
                            break
                            
                        await channel.send(msg)
                        self.spam_count += 1
                        print(f"{Fore.GREEN}[{cycle_count + 1}.{i + 1}] ✓ {msg[:30]}...{Style.RESET_ALL}")
                        
                        if self.delay > 0:
                            await asyncio.sleep(self.delay)
                            
                    cycle_count += 1
                    
            except KeyboardInterrupt:
                self.print_status("Spam interrompido", "warning")
            except discord.HTTPException as e:
                self.print_status(f"Erro HTTP: {e}", "error")
            except Exception as e:
                self.print_status(f"Erro: {e}", "error")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def embed_spam(self):
        if not all([self.token, self.target_channel_id]):
            self.print_status("Configure token e canal primeiro!", "error")
            return
            
        self.print_status("Configuração de Embed", "info")
        title = input(f"{Fore.YELLOW}» Título do embed: {Style.RESET_ALL}")
        description = input(f"{Fore.YELLOW}» Descrição do embed: {Style.RESET_ALL}")
        color = input(f"{Fore.YELLOW}» Cor do embed (hexadecimal, ex: FF0000): {Style.RESET_ALL}")
        
        try:
            color = int(color, 16) if color else 0x00FF00
        except ValueError:
            color = 0x00FF00
            self.print_status("Cor inválida, usando verde padrão", "warning")
            
        print(f"\n{Fore.YELLOW}» Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        self.print_status("Iniciando spam com embed...", "info")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                self.print_status("Canal não encontrado!", "error")
                await self.client.close()
                return
                
            sent = 0
            self.is_running = True
            
            try:
                while (count == 0 or sent < count) and self.is_running:
                    embed = discord.Embed(
                        title=title,
                        description=description,
                        color=color
                    )
                    await channel.send(embed=embed)
                    sent += 1
                    self.spam_count += 1
                    print(f"{Fore.GREEN}[{sent}] ✓ Embed enviado{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                self.print_status("Spam interrompido", "warning")
            except discord.HTTPException as e:
                self.print_status(f"Erro HTTP: {e}", "error")
            except Exception as e:
                self.print_status(f"Erro: {e}", "error")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def attachment_spam(self):
        if not all([self.token, self.target_channel_id]):
            self.print_status("Configure token e canal primeiro!", "error")
            return
            
        self.print_status("Configuração de Anexos", "info")
        file_path = input(f"{Fore.YELLOW}» Caminho do arquivo/imagem: {Style.RESET_ALL}")
        
        if not os.path.exists(file_path):
            self.print_status("Arquivo não encontrado!", "error")
            return
            
        print(f"\n{Fore.YELLOW}» Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        self.print_status("Iniciando spam com anexo...", "info")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                self.print_status("Canal não encontrado!", "error")
                await self.client.close()
                return
                
            sent = 0
            self.is_running = True
            
            try:
                while (count == 0 or sent < count) and self.is_running:
                    with open(file_path, 'rb') as f:
                        file = discord.File(f)
                        await channel.send(file=file)
                        
                    sent += 1
                    self.spam_count += 1
                    print(f"{Fore.GREEN}[{sent}] ✓ Anexo enviado{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                self.print_status("Spam interrompido", "warning")
            except discord.HTTPException as e:
                self.print_status(f"Erro HTTP: {e}", "error")
            except Exception as e:
                self.print_status(f"Erro: {e}", "error")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def random_spam(self):
        if not all([self.token, self.target_channel_id]):
            self.print_status("Configure token e canal primeiro!", "error")
            return
            
        self.print_status("Configuração de Spam Randomizado", "info")
        print(f"{Fore.YELLOW}» Digite as mensagens (digite 'FIM' para terminar):{Style.RESET_ALL}")
        
        messages = []
        while True:
            msg = input(f"{Fore.CYAN}→ Mensagem {len(messages) + 1}: {Style.RESET_ALL}")
            if msg.upper() == 'FIM':
                break
            if msg.strip():
                messages.append(msg)
                
        if not messages:
            self.print_status("Nenhuma mensagem configurada!", "error")
            return
            
        print(f"\n{Fore.YELLOW}» Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        self.print_status("Iniciando spam randomizado...", "info")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                self.print_status("Canal não encontrado!", "error")
                await self.client.close()
                return
                
            sent = 0
            self.is_running = True
            
            try:
                while (count == 0 or sent < count) and self.is_running:
                    msg = random.choice(messages)
                    await channel.send(msg)
                    sent += 1
                    self.spam_count += 1
                    print(f"{Fore.GREEN}[{sent}] ✓ {msg[:30]}...{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                self.print_status("Spam interrompido", "warning")
            except discord.HTTPException as e:
                self.print_status(f"Erro HTTP: {e}", "error")
            except Exception as e:
                self.print_status(f"Erro: {e}", "error")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            self.print_status(f"Erro na conexão: {e}", "error")
            
    async def run(self):
        self.clear_terminal()
        
        while True:
            self.print_menu()
            choice = input(f"{Fore.YELLOW}» Selecione uma opção: {Style.RESET_ALL}")
            
            try:
                choice = int(choice)
            except ValueError:
                self.print_status("Opção inválida!", "error")
                continue
                
            if choice == 0:
                self.print_status("Saindo...", "info")
                break
            elif choice == 1:
                self.configure_token()
            elif choice == 2:
                self.configure_channel()
            elif choice == 3:
                self.configure_message()
            elif choice == 4:
                self.configure_delay()
            elif choice == 5:
                self.show_config()
            elif choice == 6:
                await self.start_spam()
            elif choice == 7:
                await self.multi_message_spam()
            elif choice == 8:
                await self.embed_spam()
            elif choice == 9:
                await self.test_connection()
            elif choice == 10:
                await self.attachment_spam()
            elif choice == 11:
                await self.random_spam()
            elif choice == 12:
                self.clear_terminal()
            else:
                self.print_status("Opção inválida!", "error")
                
            if choice != 12:  # Don't prompt if we just cleared the terminal
                input(f"\n{Fore.YELLOW}» Pressione Enter para continuar...{Style.RESET_ALL}")
                self.clear_terminal()

if __name__ == "__main__":
    spammer = DiscordSpammer()
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(spammer.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[✗] Programa interrompido pelo usuário{Style.RESET_ALL}")
    finally:
        loop.close()
