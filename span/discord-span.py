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
        
    def print_banner(self):
        banner = f"""
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
"""
        print(banner)
        
    def print_menu(self):
        menu = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════╗
║                              MENU PRINCIPAL                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}[1]{Fore.GREEN} Configurar Token do Bot                                    ║
║  {Fore.YELLOW}[2]{Fore.GREEN} Definir Canal Alvo                                         ║
║  {Fore.YELLOW}[3]{Fore.GREEN} Configurar Mensagem de Spam                               ║
║  {Fore.YELLOW}[4]{Fore.GREEN} Definir Delay entre Mensagens                             ║
║  {Fore.YELLOW}[5]{Fore.GREEN} Mostrar Configurações Atuais                              ║
║  {Fore.YELLOW}[6]{Fore.GREEN} Iniciar Spam Simples                                      ║
║  {Fore.YELLOW}[7]{Fore.GREEN} Spam com Múltiplas Mensagens                              ║
║  {Fore.YELLOW}[8]{Fore.GREEN} Spam com Embeds                                           ║
║  {Fore.YELLOW}[9]{Fore.GREEN} Testar Conexão                                            ║
║  {Fore.YELLOW}[10]{Fore.GREEN} Spam com Anexos/Imagens                                  ║
║  {Fore.YELLOW}[11]{Fore.GREEN} Spam Randomizado                                         ║
║  {Fore.YELLOW}[0]{Fore.GREEN} Sair                                                       ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)
        
    def configure_token(self):
        print(f"\n{Fore.CYAN}[INFO] Configuração do Token{Style.RESET_ALL}")
        token = input(f"{Fore.YELLOW}Digite o token do bot Discord: {Style.RESET_ALL}")
        if token.strip():
            self.token = token.strip()
            print(f"{Fore.GREEN}[✓] Token configurado com sucesso!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] Token inválido!{Style.RESET_ALL}")
            
    def configure_channel(self):
        print(f"\n{Fore.CYAN}[INFO] Configuração do Canal{Style.RESET_ALL}")
        try:
            channel_id = int(input(f"{Fore.YELLOW}Digite o ID do canal alvo: {Style.RESET_ALL}"))
            self.target_channel_id = channel_id
            print(f"{Fore.GREEN}[✓] Canal configurado: {channel_id}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[✗] ID do canal deve ser um número!{Style.RESET_ALL}")
            
    def configure_message(self):
        print(f"\n{Fore.CYAN}[INFO] Configuração da Mensagem{Style.RESET_ALL}")
        message = input(f"{Fore.YELLOW}Digite a mensagem de spam: {Style.RESET_ALL}")
        if message.strip():
            self.message = message
            print(f"{Fore.GREEN}[✓] Mensagem configurada!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] Mensagem não pode estar vazia!{Style.RESET_ALL}")
            
    def configure_delay(self):
        print(f"\n{Fore.CYAN}[INFO] Configuração do Delay{Style.RESET_ALL}")
        try:
            delay = float(input(f"{Fore.YELLOW}Digite o delay entre mensagens (segundos): {Style.RESET_ALL}"))
            if delay >= 0:
                self.delay = delay
                print(f"{Fore.GREEN}[✓] Delay configurado: {delay}s{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[✗] Delay deve ser um valor positivo!{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[✗] Delay deve ser um número!{Style.RESET_ALL}")
            
    def show_config(self):
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════╗")
        print(f"║          CONFIGURAÇÕES ATUAIS            ║")
        print(f"╠══════════════════════════════════════════╣")
        print(f"║ Token: {'Configurado' if self.token else 'Não configurado':<29} ║")
        print(f"║ Canal: {str(self.target_channel_id) if self.target_channel_id else 'Não configurado':<29} ║")
        print(f"║ Mensagem: {('Configurada' if self.message else 'Não configurada'):<25} ║")
        print(f"║ Delay: {str(self.delay) + 's':<29} ║")
        print(f"║ Msgs Enviadas: {str(self.spam_count):<19} ║")
        print(f"╚══════════════════════════════════════════╝{Style.RESET_ALL}")
        
    async def test_connection(self):
        if not self.token:
            print(f"{Fore.RED}[✗] Configure o token primeiro!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[INFO] Testando conexão...{Style.RESET_ALL}")
        try:
            @self.client.event
            async def on_ready():
                print(f"{Fore.GREEN}[✓] Conectado como {self.client.user}!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] ID: {self.client.user.id}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] Servidores: {len(self.client.guilds)}{Style.RESET_ALL}")
                await self.client.close()
                
            await self.client.start(self.token)
        except discord.LoginFailure:
            print(f"{Fore.RED}[✗] Token inválido!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def start_spam(self):
        if not all([self.token, self.target_channel_id, self.message]):
            print(f"{Fore.RED}[✗] Configure todas as opções antes de iniciar!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        print(f"\n{Fore.CYAN}[INFO] Iniciando spam...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Pressione Ctrl+C para parar{Style.RESET_ALL}")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                print(f"{Fore.RED}[✗] Canal não encontrado!{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}[{sent}] Mensagem enviada | Taxa: {rate:.2f} msg/s{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Spam interrompido pelo usuário{Style.RESET_ALL}")
            except discord.HTTPException as e:
                if "rate limited" in str(e).lower():
                    print(f"{Fore.RED}[✗] Rate limit detectado! Aguardando...{Style.RESET_ALL}")
                    await asyncio.sleep(10)
                else:
                    print(f"{Fore.RED}[✗] Erro HTTP: {e}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Erro: {e}{Style.RESET_ALL}")
            finally:
                self.is_running = False
                print(f"{Fore.CYAN}[INFO] Total enviado: {sent} mensagens{Style.RESET_ALL}")
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def multi_message_spam(self):
        if not all([self.token, self.target_channel_id]):
            print(f"{Fore.RED}[✗] Configure token e canal primeiro!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[INFO] Configuração de Múltiplas Mensagens{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Digite as mensagens (digite 'FIM' para terminar):{Style.RESET_ALL}")
        
        messages = []
        while True:
            msg = input(f"{Fore.CYAN}Mensagem {len(messages) + 1}: {Style.RESET_ALL}")
            if msg.upper() == 'FIM':
                break
            if msg.strip():
                messages.append(msg)
                
        if not messages:
            print(f"{Fore.RED}[✗] Nenhuma mensagem configurada!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}Quantos ciclos? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            cycles = int(input())
        except ValueError:
            cycles = 0
            
        print(f"\n{Fore.CYAN}[INFO] Iniciando spam com {len(messages)} mensagens...{Style.RESET_ALL}")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                print(f"{Fore.RED}[✗] Canal não encontrado!{Style.RESET_ALL}")
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
                        print(f"{Fore.GREEN}[{cycle_count + 1}.{i + 1}] {msg[:30]}...{Style.RESET_ALL}")
                        
                        if self.delay > 0:
                            await asyncio.sleep(self.delay)
                            
                    cycle_count += 1
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Spam interrompido{Style.RESET_ALL}")
            except discord.HTTPException as e:
                print(f"{Fore.RED}[✗] Erro HTTP: {e}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Erro: {e}{Style.RESET_ALL}")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def embed_spam(self):
        if not all([self.token, self.target_channel_id]):
            print(f"{Fore.RED}[✗] Configure token e canal primeiro!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[INFO] Configuração de Embed{Style.RESET_ALL}")
        title = input(f"{Fore.YELLOW}Título do embed: {Style.RESET_ALL}")
        description = input(f"{Fore.YELLOW}Descrição do embed: {Style.RESET_ALL}")
        color = input(f"{Fore.YELLOW}Cor do embed (hexadecimal, ex: FF0000): {Style.RESET_ALL}")
        
        try:
            color = int(color, 16) if color else 0x00FF00
        except ValueError:
            color = 0x00FF00
            print(f"{Fore.YELLOW}[!] Cor inválida, usando verde padrão{Style.RESET_ALL}")
            
        print(f"\n{Fore.YELLOW}Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        print(f"\n{Fore.CYAN}[INFO] Iniciando spam com embed...{Style.RESET_ALL}")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                print(f"{Fore.RED}[✗] Canal não encontrado!{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}[{sent}] Embed enviado{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Spam interrompido{Style.RESET_ALL}")
            except discord.HTTPException as e:
                print(f"{Fore.RED}[✗] Erro HTTP: {e}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Erro: {e}{Style.RESET_ALL}")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def attachment_spam(self):
        if not all([self.token, self.target_channel_id]):
            print(f"{Fore.RED}[✗] Configure token e canal primeiro!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[INFO] Configuração de Anexos{Style.RESET_ALL}")
        file_path = input(f"{Fore.YELLOW}Caminho do arquivo/imagem: {Style.RESET_ALL}")
        
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[✗] Arquivo não encontrado!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        print(f"\n{Fore.CYAN}[INFO] Iniciando spam com anexo...{Style.RESET_ALL}")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                print(f"{Fore.RED}[✗] Canal não encontrado!{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}[{sent}] Anexo enviado{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Spam interrompido{Style.RESET_ALL}")
            except discord.HTTPException as e:
                print(f"{Fore.RED}[✗] Erro HTTP: {e}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Erro: {e}{Style.RESET_ALL}")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def random_spam(self):
        if not all([self.token, self.target_channel_id]):
            print(f"{Fore.RED}[✗] Configure token e canal primeiro!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[INFO] Configuração de Spam Randomizado{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Digite as mensagens (digite 'FIM' para terminar):{Style.RESET_ALL}")
        
        messages = []
        while True:
            msg = input(f"{Fore.CYAN}Mensagem {len(messages) + 1}: {Style.RESET_ALL}")
            if msg.upper() == 'FIM':
                break
            if msg.strip():
                messages.append(msg)
                
        if not messages:
            print(f"{Fore.RED}[✗] Nenhuma mensagem configurada!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}Quantas mensagens enviar? (0 = infinito): {Style.RESET_ALL}", end="")
        try:
            count = int(input())
        except ValueError:
            count = 0
            
        print(f"\n{Fore.CYAN}[INFO] Iniciando spam randomizado...{Style.RESET_ALL}")
        
        @self.client.event
        async def on_ready():
            channel = self.client.get_channel(self.target_channel_id)
            if not channel:
                print(f"{Fore.RED}[✗] Canal não encontrado!{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}[{sent}] {msg[:30]}...{Style.RESET_ALL}")
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                        
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Spam interrompido{Style.RESET_ALL}")
            except discord.HTTPException as e:
                print(f"{Fore.RED}[✗] Erro HTTP: {e}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Erro: {e}{Style.RESET_ALL}")
            finally:
                self.is_running = False
                await self.client.close()
                
        try:
            await self.client.start(self.token)
        except Exception as e:
            print(f"{Fore.RED}[✗] Erro na conexão: {e}{Style.RESET_ALL}")
            
    async def run(self):
        self.print_banner()
        
        while True:
            self.print_menu()
            choice = input(f"{Fore.YELLOW}Selecione uma opção: {Style.RESET_ALL}")
            
            try:
                choice = int(choice)
            except ValueError:
                print(f"{Fore.RED}[✗] Opção inválida!{Style.RESET_ALL}")
                continue
                
            if choice == 0:
                print(f"{Fore.CYAN}[INFO] Saindo...{Style.RESET_ALL}")
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
            else:
                print(f"{Fore.RED}[✗] Opção inválida!{Style.RESET_ALL}")
                
            input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    spammer = DiscordSpammer()
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(spammer.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[✗] Programa interrompido pelo usuário{Style.RESET_ALL}")
    finally:
        loop.close()
