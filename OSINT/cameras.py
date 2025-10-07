#!/usr/bin/env python3
"""
PolyTools - Sistema Completo de Monitoramento de Câmeras
Autor: Assistente AI
Descrição: Sistema web para monitoramento de câmeras com interface moderna
"""

import os
import json
import sqlite3
import threading
import time
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error
from io import BytesIO

# Flask para servidor web
from flask import (Flask, render_template, request, jsonify, 
                   redirect, url_for, session, send_file, Response)

# Inicialização do Flask
app = Flask(__name__)
app.secret_key = 'polytools_camera_monitor_secret_key_2024'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PolyTools')

# Banco de dados SQLite
class CameraDatabase:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        """Inicializa o banco de dados SQLite"""
        conn = sqlite3.connect('camera_monitor.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Tabela de usuários (versão simplificada)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de câmeras
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cameras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                type TEXT NOT NULL,
                location TEXT,
                latitude REAL,
                longitude REAL,
                status TEXT DEFAULT 'unknown',
                last_check DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de atividades
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                camera_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # Tabela de screenshots
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                camera_id INTEGER,
                image_data BLOB,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER
            )
        ''')
        
        # Inserir usuário admin padrão se não existir
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:
            admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
            cursor.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                ('admin', admin_hash, 'admin')
            )
        
        # Inserir câmeras de exemplo se não existirem
        cursor.execute('SELECT COUNT(*) FROM cameras')
        if cursor.fetchone()[0] == 0:
            sample_cameras = [
                ('Camera Entrada Principal', 'http://example.com/cam1', 'http', 'Entrada Principal', -23.5505, -46.6333),
                ('Camera Estacionamento', 'rtsp://example.com/cam2', 'rtsp', 'Estacionamento', -23.5506, -46.6334),
                ('Camera Recepção', 'http://example.com/cam3', 'mjpeg', 'Recepção', -23.5507, -46.6335),
                ('Camera Corredor A', 'http://example.com/cam4', 'http', 'Corredor A', -23.5508, -46.6336),
            ]
            
            for cam in sample_cameras:
                cursor.execute(
                    'INSERT INTO cameras (name, url, type, location, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)',
                    cam
                )
        
        conn.commit()
        conn.close()
        logger.info("Banco de dados inicializado com sucesso!")
    
    def get_connection(self):
        """Retorna conexão com o banco de dados"""
        return sqlite3.connect('camera_monitor.db', check_same_thread=False)

# Gerenciador de câmeras
class CameraManager:
    def __init__(self, db: CameraDatabase):
        self.db = db
        self.camera_status = {}
        self.screenshot_cache = {}
        self._lock = threading.Lock()
        
        # Iniciar thread de monitoramento
        self.monitor_thread = threading.Thread(target=self._monitor_cameras, daemon=True)
        self.monitor_thread.start()
        logger.info("Sistema de monitoramento de câmeras iniciado")
    
    def _monitor_cameras(self):
        """Thread para monitorar status das câmeras"""
        while True:
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                # Buscar todas as câmeras
                cursor.execute('SELECT id, url, type FROM cameras')
                cameras = cursor.fetchall()
                
                for cam_id, url, cam_type in cameras:
                    status = self._check_camera_status(url, cam_type)
                    with self._lock:
                        self.camera_status[cam_id] = status
                    
                    # Atualizar no banco
                    cursor.execute(
                        'UPDATE cameras SET status = ?, last_check = ? WHERE id = ?',
                        (status, datetime.now(), cam_id)
                    )
                
                conn.commit()
                conn.close()
                
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
                time.sleep(10)  # Espera menor em caso de erro
            
            time.sleep(30)  # Verificar a cada 30 segundos
    
    def _check_camera_status(self, url: str, cam_type: str) -> str:
        """Verifica o status de uma câmera"""
        try:
            if cam_type in ['http', 'mjpeg']:
                # Para demonstração, vamos simular status
                # Em produção, você usaria a URL real
                return 'online' if 'example.com' in url else 'offline'
            elif cam_type == 'rtsp':
                return 'online'
            
            return 'offline'
        except Exception as e:
            logger.debug(f"Câmera {url} offline: {e}")
            return 'offline'
    
    def get_camera_status(self, cam_id: int) -> str:
        """Retorna status da câmera"""
        with self._lock:
            return self.camera_status.get(cam_id, 'unknown')
    
    def take_screenshot(self, cam_id: int, user_id: int) -> Optional[int]:
        """Tira screenshot de uma câmera"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT name, type FROM cameras WHERE id = ?', (cam_id,))
            result = cursor.fetchone()
            
            if not result:
                return None
            
            cam_name, cam_type = result
            
            # Criar screenshot fake (em produção, capturaria frame real)
            try:
                from PIL import Image, ImageDraw, ImageFont
                import random
                
                # Criar imagem
                img = Image.new('RGB', (640, 480), color=(random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)))
                d = ImageDraw.Draw(img)
                
                # Adicionar texto
                try:
                    font = ImageFont.load_default()
                except:
                    font = None
                
                text = f"Camera: {cam_name}\nTipo: {cam_type}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                d.text((50, 50), text, fill=(255, 255, 255), font=font)
                
                # Adicionar borda
                d.rectangle([0, 0, 639, 479], outline=(255, 255, 255), width=2)
                
                # Converter para bytes
                img_byte_arr = BytesIO()
                img.save(img_byte_arr, format='JPEG', quality=85)
                img_byte_arr = img_byte_arr.getvalue()
                
            except ImportError:
                # Se PIL não estiver disponível, criar imagem simples em base64
                img_data = base64.b64decode(
                    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
                )
                img_byte_arr = img_data
            
            # Salvar no banco
            cursor.execute(
                'INSERT INTO screenshots (camera_id, image_data, user_id) VALUES (?, ?, ?)',
                (cam_id, img_byte_arr, user_id)
            )
            screenshot_id = cursor.lastrowid
            
            # Registrar atividade
            cursor.execute(
                'INSERT INTO activities (user_id, action, camera_id, details) VALUES (?, ?, ?, ?)',
                (user_id, 'screenshot', cam_id, f'Screenshot da câmera {cam_name}')
            )
            
            conn.commit()
            logger.info(f"Screenshot capturada para câmera {cam_id} pelo usuário {user_id}")
            return screenshot_id
            
        except Exception as e:
            logger.error(f"Erro ao tirar screenshot: {e}")
            return None
        finally:
            conn.close()

# Sistema de autenticação
class AuthSystem:
    def __init__(self, db: CameraDatabase):
        self.db = db
    
    def login(self, username: str, password: str) -> Optional[Dict]:
        """Realiza login do usuário"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Query simplificada sem full_name
        cursor.execute(
            'SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'full_name': result[1],  # Usar username como full_name
                'role': result[2]
            }
        
        return None
    
    def log_activity(self, user_id: int, action: str, camera_id: Optional[int] = None, details: str = ""):
        """Registra atividade do usuário"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO activities (user_id, action, camera_id, details) VALUES (?, ?, ?, ?)',
                (user_id, action, camera_id, details)
            )
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Erro ao registrar atividade: {e}")

# Inicialização dos componentes
db = CameraDatabase()
camera_manager = CameraManager(db)
auth_system = AuthSystem(db)

# Templates HTML embutidos
LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo { 
            text-align: center; 
            margin-bottom: 30px;
            color: #333;
        }
        .logo h1 { 
            font-size: 28px; 
            margin-bottom: 5px;
        }
        .form-group { 
            margin-bottom: 20px; 
        }
        label { 
            display: block; 
            margin-bottom: 5px; 
            color: #555;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5a6fd8;
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-bottom: 15px;
            padding: 10px;
            background: #ffeaea;
            border-radius: 5px;
        }
        .demo-info {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            text-align: center;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 PolyTools</h1>
            <p>Sistema de Monitoramento</p>
        </div>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label>👤 Usuário:</label>
                <input type="text" name="username" required value="admin">
            </div>
            <div class="form-group">
                <label>🔒 Senha:</label>
                <input type="password" name="password" required value="admin123">
            </div>
            <button type="submit" class="btn">🚀 Entrar no Sistema</button>
        </form>
        <div class="demo-info">
            <strong>💡 Login de Demonstração:</strong><br>
            Usuário: <strong>admin</strong><br>
            Senha: <strong>admin123</strong>
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #f5f6fa;
            color: #333;
        }
        .header {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo { 
            font-size: 24px; 
            font-weight: bold;
            color: #667eea;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .nav {
            background: #2c3e50;
            padding: 0;
        }
        .nav ul {
            list-style: none;
            display: flex;
        }
        .nav li a {
            color: white;
            text-decoration: none;
            padding: 15px 20px;
            display: block;
            transition: background 0.3s;
        }
        .nav li a:hover, .nav li a.active {
            background: #34495e;
        }
        .container {
            padding: 30px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card h3 {
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
        }
        .online { color: #27ae60; }
        .offline { color: #e74c3c; }
        .total { color: #3498db; }
        .cameras-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .camera-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .camera-card:hover {
            transform: translateY(-5px);
        }
        .camera-preview {
            height: 200px;
            background: #ecf0f1;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #7f8c8d;
        }
        .camera-info {
            padding: 15px;
        }
        .camera-name {
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 16px;
        }
        .camera-location {
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 8px;
        }
        .camera-status {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-online { background: #d5f4e6; color: #27ae60; }
        .status-offline { background: #fdeaea; color: #e74c3c; }
        .status-unknown { background: #fcf3cf; color: #f39c12; }
        .last-check {
            font-size: 12px;
            color: #95a5a6;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">📹 PolyTools Monitor</div>
        <div class="user-info">
            <span>👋 Olá, {{ full_name }}</span>
            <a href="/logout" style="color: #e74c3c; text-decoration: none;">🚪 Sair</a>
        </div>
    </div>
    
    <nav class="nav">
        <ul>
            <li><a href="/dashboard" class="active">📊 Dashboard</a></li>
            <li><a href="/search">🔍 Buscar Câmeras</a></li>
            <li><a href="/map">🗺️ Mapa</a></li>
        </ul>
    </nav>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>📹 Total de Câmeras</h3>
                <div class="stat-number total">{{ total_cameras }}</div>
            </div>
            <div class="stat-card">
                <h3>✅ Câmeras Online</h3>
                <div class="stat-number online">{{ online_cameras }}</div>
            </div>
            <div class="stat-card">
                <h3>❌ Câmeras Offline</h3>
                <div class="stat-number offline">{{ offline_cameras }}</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px;">🎥 Câmeras do Sistema</h2>
        
        <div class="cameras-grid">
            {% for camera in cameras %}
            <div class="camera-card">
                <a href="/camera/{{ camera[0] }}" style="text-decoration: none; color: inherit;">
                    <div class="camera-preview">
                        {% if camera[5] == 'online' %}
                        <div style="text-align: center;">
                            <div style="font-size: 48px;">📹</div>
                            <div style="color: #27ae60; font-weight: bold;">ONLINE</div>
                        </div>
                        {% elif camera[5] == 'offline' %}
                        <div style="text-align: center;">
                            <div style="font-size: 48px;">❌</div>
                            <div style="color: #e74c3c; font-weight: bold;">OFFLINE</div>
                        </div>
                        {% else %}
                        <div style="text-align: center;">
                            <div style="font-size: 48px;">❓</div>
                            <div style="color: #f39c12; font-weight: bold;">DESCONHECIDO</div>
                        </div>
                        {% endif %}
                    </div>
                    <div class="camera-info">
                        <div class="camera-name">{{ camera[1] }}</div>
                        <div class="camera-location">📍 {{ camera[4] or 'Localização não definida' }}</div>
                        <div class="camera-status {% if camera[5] == 'online' %}status-online{% elif camera[5] == 'offline' %}status-offline{% else %}status-unknown{% endif %}">
                            {{ camera[5]|upper if camera[5] else 'DESCONHECIDO' }}
                        </div>
                        <div class="last-check">
                            ⏰ {{ camera[6][:19] if camera[6] else 'Nunca verificado' }}
                        </div>
                    </div>
                </a>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
'''

CAMERA_VIEW_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ camera[1] }} - PolyTools</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #f5f6fa;
        }
        .header {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo { font-size: 24px; font-weight: bold; color: #667eea; }
        .video-container {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            height: 60vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            margin: 20px;
            border-radius: 10px;
            position: relative;
        }
        .camera-info-panel {
            position: absolute;
            top: 20px;
            left: 20px;
            background: rgba(0,0,0,0.8);
            padding: 15px;
            border-radius: 8px;
            color: white;
            max-width: 300px;
        }
        .controls {
            background: white;
            margin: 0 20px 20px;
            padding: 20px;
            border-radius: 10px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary { background: #3498db; color: white; }
        .btn-primary:hover { background: #2980b9; transform: translateY(-2px); }
        .btn-success { background: #27ae60; color: white; }
        .btn-success:hover { background: #219a52; transform: translateY(-2px); }
        .screenshots {
            background: white;
            margin: 0 20px 20px;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .screenshot-item {
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            transition: transform 0.3s;
        }
        .screenshot-item:hover {
            transform: scale(1.05);
        }
        .screenshot-item img {
            width: 100%;
            height: 150px;
            object-fit: cover;
        }
        .no-screenshots {
            text-align: center;
            color: #7f8c8d;
            padding: 40px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">📹 PolyTools Monitor</div>
        <div>
            <a href="/dashboard" style="color: #3498db; text-decoration: none;">← Voltar ao Dashboard</a>
        </div>
    </div>
    
    <div class="video-container">
        <div class="camera-info-panel">
            <h2>{{ camera[1] }}</h2>
            <p>📍 {{ camera[4] or 'Localização não definida' }}</p>
            <p>🎥 Tipo: {{ camera[3]|upper }}</p>
            <p>🔗 URL: {{ camera[2] }}</p>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 72px; margin-bottom: 20px;">📹</div>
            <h2>Visualização da Câmera</h2>
            <p style="margin-top: 10px; color: #bbb;">Streaming: {{ camera[3]|upper }}</p>
            <div style="margin-top: 20px; padding: 15px; background: rgba(39, 174, 96, 0.2); border-radius: 5px; display: inline-block;">
                <p style="margin: 0;">Status: <strong style="color: #27ae60;">ONLINE</strong></p>
            </div>
        </div>
    </div>
    
    <div class="controls">
        <button class="btn btn-success" onclick="takeScreenshot()">
            📸 Capturar Screenshot
        </button>
        <button class="btn btn-primary">⏯️ Play/Pause</button>
        <button class="btn btn-primary">📺 Fullscreen</button>
        <button class="btn btn-primary">🔊 Som</button>
        <button class="btn btn-primary">⏺️ Gravar Vídeo</button>
    </div>
    
    <div class="screenshots">
        <h3>📷 Screenshots Recentes</h3>
        {% if screenshots %}
        <div class="screenshot-grid">
            {% for screenshot in screenshots %}
            <div class="screenshot-item">
                <a href="/screenshot/{{ screenshot[0] }}" target="_blank">
                    <img src="/screenshot/{{ screenshot[0] }}" alt="Screenshot">
                </a>
                <div style="padding: 8px; font-size: 12px; text-align: center; background: #f8f9fa;">
                    {{ screenshot[1][:19] }}
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="no-screenshots">
            <div style="font-size: 48px; margin-bottom: 10px;">📷</div>
            <p>Nenhuma screenshot capturada ainda</p>
            <p>Clique no botão "Capturar Screenshot" para começar</p>
        </div>
        {% endif %}
    </div>

    <script>
        function takeScreenshot() {
            fetch(`/api/camera/{{ camera[0] }}/screenshot`, {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Screenshot capturada com sucesso!');
                    location.reload();
                } else {
                    alert('❌ Erro ao capturar screenshot: ' + (data.error || 'Erro desconhecido'));
                }
            })
            .catch(error => {
                alert('❌ Erro de conexão ao capturar screenshot');
                console.error('Error:', error);
            });
        }
    </script>
</body>
</html>
'''

SEARCH_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Buscar Câmeras - PolyTools</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #f5f6fa;
        }
        .header {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo { font-size: 24px; font-weight: bold; color: #667eea; }
        .container {
            padding: 30px;
        }
        .search-form {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
        }
        .btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
            font-size: 16px;
        }
        .btn:hover {
            background: #2980b9;
        }
        .results-count {
            margin-bottom: 15px;
            color: #7f8c8d;
            padding: 15px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .cameras-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .camera-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .camera-card:hover {
            transform: translateY(-5px);
        }
        .camera-preview {
            height: 150px;
            background: #ecf0f1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .camera-info {
            padding: 15px;
        }
        .camera-name {
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 16px;
        }
        .camera-details {
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 8px;
        }
        .camera-status {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-online { background: #d5f4e6; color: #27ae60; }
        .status-offline { background: #fdeaea; color: #e74c3c; }
        .status-unknown { background: #fcf3cf; color: #f39c12; }
        .no-results {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🔍 PolyTools Monitor</div>
        <div>
            <a href="/dashboard" style="color: #3498db; text-decoration: none;">← Voltar ao Dashboard</a>
        </div>
    </div>
    
    <div class="container">
        <div class="search-form">
            <form method="GET">
                <div class="form-grid">
                    <div class="form-group">
                        <label>🔍 Buscar:</label>
                        <input type="text" name="q" value="{{ search_query }}" placeholder="Nome ou localização...">
                    </div>
                    <div class="form-group">
                        <label>📍 Localização:</label>
                        <select name="location">
                            <option value="">Todas as localizações</option>
                            {% for location in locations %}
                            <option value="{{ location }}" {% if location == selected_location %}selected{% endif %}>
                                {{ location }}
                            </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>📊 Status:</label>
                        <select name="status">
                            <option value="">Todos os status</option>
                            <option value="online" {% if selected_status == 'online' %}selected{% endif %}>Online</option>
                            <option value="offline" {% if selected_status == 'offline' %}selected{% endif %}>Offline</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>🎥 Tipo:</label>
                        <select name="type">
                            <option value="">Todos os tipos</option>
                            <option value="http" {% if selected_type == 'http' %}selected{% endif %}>HTTP</option>
                            <option value="rtsp" {% if selected_type == 'rtsp' %}selected{% endif %}>RTSP</option>
                            <option value="mjpeg" {% if selected_type == 'mjpeg' %}selected{% endif %}>MJPEG</option>
                        </select>
                    </div>
                </div>
                <button type="submit" class="btn">🔍 Buscar Câmeras</button>
                {% if search_query or selected_location or selected_status or selected_type %}
                <a href="/search" style="margin-left: 10px; color: #666; text-decoration: none;">🔄 Limpar filtros</a>
                {% endif %}
            </form>
        </div>
        
        <div class="results-count">
            📊 {{ cameras|length }} câmera(s) encontrada(s)
            {% if search_query or selected_location or selected_status or selected_type %}
            com os filtros aplicados
            {% endif %}
        </div>
        
        {% if cameras %}
        <div class="cameras-grid">
            {% for camera in cameras %}
            <div class="camera-card">
                <a href="/camera/{{ camera[0] }}" style="text-decoration: none; color: inherit;">
                    <div class="camera-preview">
                        {% if camera[5] == 'online' %}
                        <div style="text-align: center; color: #333;">
                            <div style="font-size: 36px;">📹</div>
                            <div style="color: #27ae60; font-weight: bold;">ONLINE</div>
                        </div>
                        {% elif camera[5] == 'offline' %}
                        <div style="text-align: center; color: #333;">
                            <div style="font-size: 36px;">❌</div>
                            <div style="color: #e74c3c; font-weight: bold;">OFFLINE</div>
                        </div>
                        {% else %}
                        <div style="text-align: center; color: #333;">
                            <div style="font-size: 36px;">❓</div>
                            <div style="color: #f39c12; font-weight: bold;">DESCONHECIDO</div>
                        </div>
                        {% endif %}
                    </div>
                    <div class="camera-info">
                        <div class="camera-name">{{ camera[1] }}</div>
                        <div class="camera-details">
                            <div>📍 Local: {{ camera[4] or 'N/A' }}</div>
                            <div>🎥 Tipo: {{ camera[3]|upper }}</div>
                            <div>⏰ Última verificação: {{ camera[6][:19] if camera[6] else 'N/A' }}</div>
                        </div>
                        <div class="camera-status {% if camera[5] == 'online' %}status-online{% elif camera[5] == 'offline' %}status-offline{% else %}status-unknown{% endif %}">
                            {{ camera[5]|upper if camera[5] else 'DESCONHECIDO' }}
                        </div>
                    </div>
                </a>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="no-results">
            <div style="font-size: 72px; margin-bottom: 20px;">🔍</div>
            <h3>Nenhuma câmera encontrada</h3>
            <p>Tente ajustar os filtros de busca</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

MAP_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mapa de Câmeras - PolyTools</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #f5f6fa;
        }
        .header {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo { font-size: 24px; font-weight: bold; color: #667eea; }
        .container {
            padding: 20px;
            height: calc(100vh - 140px);
        }
        .map-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        .map-placeholder {
            text-align: center;
            color: #7f8c8d;
            padding: 20px;
            width: 100%;
        }
        .cameras-list {
            margin-top: 30px;
            max-height: 400px;
            overflow-y: auto;
            padding: 0 20px;
        }
        .camera-item {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            transition: transform 0.2s;
        }
        .camera-item:hover {
            transform: translateX(5px);
        }
        .camera-item.online { border-left-color: #27ae60; }
        .camera-item.offline { border-left-color: #e74c3c; }
        .camera-item.unknown { border-left-color: #f39c12; }
        .status-online { background: #d5f4e6; color: #27ae60; }
        .status-offline { background: #fdeaea; color: #e74c3c; }
        .status-unknown { background: #fcf3cf; color: #f39c12; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🗺️ PolyTools Monitor</div>
        <div>
            <a href="/dashboard" style="color: #3498db; text-decoration: none;">← Voltar ao Dashboard</a>
        </div>
    </div>
    
    <div class="container">
        <div class="map-container" id="map">
            <div class="map-placeholder">
                <div style="font-size: 72px; margin-bottom: 20px;">🗺️</div>
                <h2>Mapa de Câmeras</h2>
                <p>Visualização geográfica das câmeras do sistema</p>
                
                <div class="cameras-list">
                    {% for camera in cameras %}
                    <div class="camera-item {% if camera[5] == 'online' %}online{% elif camera[5] == 'offline' %}offline{% else %}unknown{% endif %}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1;">
                                <strong>{{ camera[1] }}</strong>
                                <div style="font-size: 14px; color: #666; margin-top: 5px;">
                                    📍 {{ camera[2] }} 
                                    {% if camera[3] and camera[4] %}
                                    - Coord: {{ "%.4f"|format(camera[3]) }}, {{ "%.4f"|format(camera[4]) }}
                                    {% else %}
                                    - Coordenadas não definidas
                                    {% endif %}
                                </div>
                            </div>
                            <div style="margin-left: 15px;">
                                <span style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; 
                                      {% if camera[5] == 'online' %}background: #d5f4e6; color: #27ae60;
                                      {% elif camera[5] == 'offline' %}background: #fdeaea; color: #e74c3c;
                                      {% else %}background: #fcf3cf; color: #f39c12;{% endif %}">
                                    {{ camera[5]|upper if camera[5] else 'DESCONHECIDO' }}
                                </span>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

# Função para renderizar templates
def render_template_string(template, **context):
    """Renderiza template string com contexto"""
    from flask import render_template_string as flask_render_template_string
    return flask_render_template_string(template, **context)

# Rotas da aplicação
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = auth_system.login(username, password)
        if user:
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            
            auth_system.log_activity(user['id'], 'login')
            logger.info(f"Usuário {username} fez login com sucesso")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Tentativa de login falhou para usuário {username}")
            return render_template_string(LOGIN_HTML, error='Credenciais inválidas')
    
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        auth_system.log_activity(session['user_id'], 'logout')
        logger.info(f"Usuário {session['username']} fez logout")
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Estatísticas
    cursor.execute('SELECT COUNT(*) FROM cameras')
    total_cameras = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM cameras WHERE status = "online"')
    online_cameras = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM cameras WHERE status = "offline"')
    offline_cameras = cursor.fetchone()[0]
    
    # Câmeras para o grid
    cursor.execute('''
        SELECT id, name, url, type, location, status, last_check 
        FROM cameras 
        ORDER BY name
    ''')
    cameras = cursor.fetchall()
    
    conn.close()
    
    auth_system.log_activity(session['user_id'], 'view_dashboard')
    
    return render_template_string(DASHBOARD_HTML,
        full_name=session.get('full_name'),
        total_cameras=total_cameras,
        online_cameras=online_cameras,
        offline_cameras=offline_cameras,
        cameras=cameras
    )

@app.route('/camera/<int:camera_id>')
def camera_view(camera_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, url, type, location FROM cameras WHERE id = ?', (camera_id,))
    camera = cursor.fetchone()
    
    if not camera:
        conn.close()
        return "Câmera não encontrada", 404
    
    # Screenshots recentes
    cursor.execute('''
        SELECT id, timestamp FROM screenshots 
        WHERE camera_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 5
    ''', (camera_id,))
    screenshots = cursor.fetchall()
    
    conn.close()
    
    auth_system.log_activity(session['user_id'], 'view_camera', camera_id)
    
    return render_template_string(CAMERA_VIEW_HTML, camera=camera, screenshots=screenshots)

@app.route('/search')
def search_cameras():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    location_filter = request.args.get('location', '')
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Construir query dinâmica
    sql = 'SELECT id, name, url, type, location, status, last_check FROM cameras'
    params = []
    
    conditions = []
    
    if query:
        conditions.append('(name LIKE ? OR location LIKE ?)')
        params.extend([f'%{query}%', f'%{query}%'])
    
    if location_filter:
        conditions.append('location = ?')
        params.append(location_filter)
    
    if status_filter:
        conditions.append('status = ?')
        params.append(status_filter)
    
    if type_filter:
        conditions.append('type = ?')
        params.append(type_filter)
    
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    
    sql += ' ORDER BY name'
    
    cursor.execute(sql, params)
    cameras = cursor.fetchall()
    
    # Localizações únicas para filtro
    cursor.execute('SELECT DISTINCT location FROM cameras WHERE location IS NOT NULL AND location != ""')
    locations = [loc[0] for loc in cursor.fetchall()]
    
    conn.close()
    
    auth_system.log_activity(session['user_id'], 'search', details=f"Query: {query}")
    
    return render_template_string(SEARCH_HTML,
        cameras=cameras,
        search_query=query,
        locations=locations,
        selected_location=location_filter,
        selected_status=status_filter,
        selected_type=type_filter
    )

@app.route('/map')
def camera_map():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, location, latitude, longitude, status FROM cameras')
    cameras = cursor.fetchall()
    
    conn.close()
    
    auth_system.log_activity(session['user_id'], 'view_map')
    
    return render_template_string(MAP_HTML, cameras=cameras)

@app.route('/api/camera/<int:camera_id>/screenshot', methods=['POST'])
def take_screenshot(camera_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    screenshot_id = camera_manager.take_screenshot(camera_id, session['user_id'])
    
    if screenshot_id:
        return jsonify({'success': True, 'screenshot_id': screenshot_id})
    else:
        return jsonify({'error': 'Falha ao capturar screenshot'}), 500

@app.route('/screenshot/<int:screenshot_id>')
def get_screenshot(screenshot_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT image_data FROM screenshots WHERE id = ?', (screenshot_id,))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return send_file(BytesIO(result[0]), mimetype='image/jpeg')
    else:
        return "Screenshot não encontrada", 404

@app.route('/api/cameras/status')
def cameras_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, status, last_check FROM cameras')
    cameras = [
        {
            'id': row[0],
            'name': row[1],
            'status': row[2],
            'last_check': row[3]
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    return jsonify(cameras)

@app.route('/api/system/health')
def system_health():
    """Endpoint de saúde do sistema"""
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Estatísticas do sistema
    cursor.execute('SELECT COUNT(*) FROM cameras')
    total_cameras = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM cameras WHERE status = "online"')
    online_cameras = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM screenshots')
    total_screenshots = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'statistics': {
            'total_cameras': total_cameras,
            'online_cameras': online_cameras,
            'total_users': total_users,
            'total_screenshots': total_screenshots
        }
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🎥 PolyTools - Sistema de Monitoramento de Câmeras")
    print("=" * 60)
    print("✅ Banco de dados inicializado")
    print("✅ Sistema de monitoramento ativo")
    print("✅ Servidor web pronto")
    print("=" * 60)
    print("🌐 Acesse: http://localhost:5000")
    print("👤 Login: admin")
    print("🔒 Senha: admin123")
    print("=" * 60)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"❌ Erro ao iniciar servidor: {e}")
        print("🔧 Verifique se a porta 5000 está disponível")
