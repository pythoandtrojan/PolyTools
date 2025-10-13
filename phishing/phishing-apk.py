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
import json
import zipfile
import tempfile
import shutil
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from typing import Dict, List, Optional
from datetime import datetime

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

# ==================== CONFIGURAÇÕES ====================
TEMPLATES_DIR = "templates"
APK_OUTPUT_DIR = "dist"
WEB_ROOT = "web_content"
UPLOADS_DIR = "uploads"

# Garantir que os diretórios existam
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(APK_OUTPUT_DIR, exist_ok=True)
os.makedirs(WEB_ROOT, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

# ==================== GERENCIADOR DE ARQUIVOS REAIS ====================
class RealFileManager:
    def __init__(self):
        self.supported_extensions = ['.apk', '.exe', '.py', '.sh', '.bat', '.deb', '.rpm']
        self.uploaded_files = {}
    
    def validate_file(self, file_path):
        """Valida se o arquivo existe e é suportado"""
        if not os.path.exists(file_path):
            return False, "Arquivo não encontrado"
        
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in self.supported_extensions:
            return False, f"Extensão não suportada: {file_ext}"
        
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # 100MB limite
            return False, "Arquivo muito grande (máximo 100MB)"
        
        return True, "Arquivo válido"
    
    def copy_file_to_server(self, file_path, custom_name=None):
        """Copia o arquivo para o diretório de uploads do servidor"""
        try:
            # Validar arquivo
            is_valid, message = self.validate_file(file_path)
            if not is_valid:
                return None, message
            
            # Gerar nome único para o arquivo
            original_name = os.path.basename(file_path)
            if custom_name:
                file_name = custom_name + os.path.splitext(original_name)[1]
            else:
                file_name = original_name
            
            # Garantir nome único
            counter = 1
            base_name, ext = os.path.splitext(file_name)
            while os.path.exists(os.path.join(UPLOADS_DIR, file_name)):
                file_name = f"{base_name}_{counter}{ext}"
                counter += 1
            
            destination = os.path.join(UPLOADS_DIR, file_name)
            
            # Copiar arquivo
            shutil.copy2(file_path, destination)
            
            # Registrar arquivo
            file_id = hashlib.md5(file_name.encode()).hexdigest()[:8]
            self.uploaded_files[file_id] = {
                'original_path': file_path,
                'server_path': destination,
                'file_name': file_name,
                'file_size': os.path.getsize(destination),
                'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'download_count': 0
            }
            
            return file_id, f"Arquivo copiado com sucesso: {file_name}"
            
        except Exception as e:
            return None, f"Erro ao copiar arquivo: {str(e)}"
    
    def get_file_info(self, file_id):
        """Obtém informações do arquivo"""
        return self.uploaded_files.get(file_id)
    
    def increment_download_count(self, file_id):
        """Incrementa contador de downloads"""
        if file_id in self.uploaded_files:
            self.uploaded_files[file_id]['download_count'] += 1
    
    def list_uploaded_files(self):
        """Lista todos os arquivos carregados"""
        return self.uploaded_files
    
    def delete_file(self, file_id):
        """Remove arquivo do servidor"""
        try:
            if file_id in self.uploaded_files:
                file_info = self.uploaded_files[file_id]
                os.remove(file_info['server_path'])
                del self.uploaded_files[file_id]
                return True, "Arquivo removido com sucesso"
            else:
                return False, "Arquivo não encontrado"
        except Exception as e:
            return False, f"Erro ao remover arquivo: {str(e)}"

# ==================== SERVIDOR WEB PARA DISTRIBUIÇÃO REAL ====================
class RealFileServerHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.file_manager = kwargs.pop('file_manager', None)
        self.site_config = kwargs.pop('site_config', {})
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Customiza logging do servidor"""
        client_ip = self.client_address[0]
        console.print(f"[cyan]🌐 {client_ip} - {format % args}[/cyan]")
    
    def do_GET(self):
        """Manipula requisições GET"""
        client_ip = self.client_address[0]
        
        if self.path == '/':
            self.serve_main_page()
        elif self.path == '/downloads':
            self.serve_downloads_page()
        elif self.path.startswith('/download/'):
            self.serve_file_download()
        elif self.path == '/about':
            self.serve_about_page()
        elif self.path == '/stats':
            self.serve_stats_page()
        else:
            self.serve_404()
    
    def serve_main_page(self):
        """Serve página principal"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = self.generate_main_page()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_downloads_page(self):
        """Serve página de downloads"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = self.generate_downloads_page()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_file_download(self):
        """Serve download de arquivo real"""
        try:
            # Extrair file_id da URL
            file_id = self.path.split('/')[-1]
            
            file_info = self.file_manager.get_file_info(file_id)
            if not file_info:
                self.serve_404()
                return
            
            file_path = file_info['server_path']
            file_name = file_info['file_name']
            
            if not os.path.exists(file_path):
                self.serve_404()
                return
            
            # Incrementar contador de downloads
            self.file_manager.increment_download_count(file_id)
            
            # Determinar tipo MIME
            ext = os.path.splitext(file_name)[1].lower()
            mime_types = {
                '.apk': 'application/vnd.android.package-archive',
                '.exe': 'application/x-msdownload',
                '.py': 'text/x-python',
                '.sh': 'application/x-shellscript',
                '.bat': 'application/x-msdownload',
                '.deb': 'application/x-debian-package',
                '.rpm': 'application/x-rpm'
            }
            
            content_type = mime_types.get(ext, 'application/octet-stream')
            
            # Enviar arquivo
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Disposition', f'attachment; filename="{file_name}"')
            self.send_header('Content-Length', str(os.path.getsize(file_path)))
            self.end_headers()
            
            with open(file_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
            
            console.print(f"[green]✅ Download realizado: {file_name} por {self.client_address[0]}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Erro no download: {str(e)}[/red]")
            self.serve_500()
    
    def serve_about_page(self):
        """Serve página sobre"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = self.generate_about_page()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_stats_page(self):
        """Serve página de estatísticas"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = self.generate_stats_page()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_404(self):
        """Serve página 404"""
        self.send_response(404)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Não Encontrado</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                h1 { color: #d32f2f; }
            </style>
        </head>
        <body>
            <h1>404 - Página Não Encontrada</h1>
            <p>A página que você está procurando não existe.</p>
            <a href="/">Voltar à Página Principal</a>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_500(self):
        """Serve erro 500"""
        self.send_response(500)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>500 - Erro Interno</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                h1 { color: #d32f2f; }
            </style>
        </head>
        <body>
            <h1>500 - Erro Interno do Servidor</h1>
            <p>Ocorreu um erro interno no servidor.</p>
            <a href="/">Voltar à Página Principal</a>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
    
    def generate_main_page(self):
        """Gera página principal do site"""
        site_title = self.site_config.get('title', 'Portal de Downloads')
        site_description = self.site_config.get('description', 'Downloads seguros e confiáveis')
        
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site_title}</title>
    <style>
        :root {{
            --primary: #2196F3;
            --secondary: #1976D2;
            --accent: #FF4081;
            --dark: #263238;
            --light: #ECEFF1;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
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
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }}
        
        nav {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .logo {{
            font-size: 28px;
            font-weight: bold;
            color: white;
            display: flex;
            align-items: center;
        }}
        
        .nav-links {{
            display: flex;
            list-style: none;
        }}
        
        .nav-links li {{
            margin-left: 30px;
        }}
        
        .nav-links a {{
            color: white;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }}
        
        .nav-links a:hover {{
            color: var(--accent);
        }}
        
        .hero {{
            padding: 160px 0 80px;
            text-align: center;
            color: white;
        }}
        
        .hero h1 {{
            font-size: 48px;
            margin-bottom: 20px;
        }}
        
        .hero p {{
            font-size: 20px;
            margin-bottom: 40px;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }}
        
        .btn {{
            display: inline-block;
            background: var(--accent);
            color: white;
            padding: 15px 30px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: bold;
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        
        .btn:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }}
        
        .features {{
            padding: 80px 0;
            background: white;
        }}
        
        .section-title {{
            text-align: center;
            margin-bottom: 60px;
        }}
        
        .section-title h2 {{
            font-size: 36px;
            color: var(--dark);
            margin-bottom: 20px;
        }}
        
        .features-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 40px;
        }}
        
        .feature-card {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .feature-card:hover {{
            transform: translateY(-10px);
        }}
        
        .feature-icon {{
            font-size: 48px;
            margin-bottom: 20px;
        }}
        
        footer {{
            background: var(--dark);
            color: white;
            padding: 40px 0;
            text-align: center;
        }}
        
        @media (max-width: 768px) {{
            .nav-links {{
                display: none;
            }}
            
            .hero h1 {{
                font-size: 36px;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <div class="logo">
                    <span>📥</span>
                    {site_title}
                </div>
                <ul class="nav-links">
                    <li><a href="/">Início</a></li>
                    <li><a href="/downloads">Downloads</a></li>
                    <li><a href="/about">Sobre</a></li>
                    <li><a href="/stats">Estatísticas</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <section class="hero">
        <div class="container">
            <h1>{site_title}</h1>
            <p>{site_description}</p>
            <a href="/downloads" class="btn">Ver Downloads Disponíveis</a>
        </div>
    </section>

    <section class="features">
        <div class="container">
            <div class="section-title">
                <h2>Por que Escolher Nosso Portal?</h2>
                <p>Segurança, confiabilidade e velocidade</p>
            </div>
            
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <h3>Segurança Garantida</h3>
                    <p>Todos os arquivos são verificados e seguros para download.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Alta Velocidade</h3>
                    <p>Downloads rápidos sem limitações de velocidade.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">📱</div>
                    <h3>Multiplataforma</h3>
                    <p>Arquivos para Windows, Android, Linux e mais.</p>
                </div>
            </div>
        </div>
    </section>

    <footer>
        <div class="container">
            <p>&copy; 2024 {site_title}. Todos os direitos reservados.</p>
        </div>
    </footer>
</body>
</html>
"""
    
    def generate_downloads_page(self):
        """Gera página de downloads com arquivos reais"""
        files = self.file_manager.list_uploaded_files()
        
        files_html = ""
        if files:
            for file_id, file_info in files.items():
                file_size_mb = file_info['file_size'] / (1024 * 1024)
                files_html += f"""
                <div class="file-card">
                    <div class="file-icon">📄</div>
                    <div class="file-info">
                        <h3>{file_info['file_name']}</h3>
                        <p>Tamanho: {file_size_mb:.2f} MB • Downloads: {file_info['download_count']}</p>
                        <p>Upload: {file_info['upload_time']}</p>
                    </div>
                    <a href="/download/{file_id}" class="download-btn">Download</a>
                </div>
                """
        else:
            files_html = "<p class='no-files'>Nenhum arquivo disponível para download.</p>"
        
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Downloads - {self.site_config.get('title', 'Portal de Downloads')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 80px 20px 20px;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
        }}
        
        .page-title {{
            text-align: center;
            color: #333;
            margin-bottom: 40px;
        }}
        
        .files-list {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .file-card {{
            display: flex;
            align-items: center;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 15px;
            transition: background 0.3s;
        }}
        
        .file-card:hover {{
            background: #f8f9fa;
        }}
        
        .file-icon {{
            font-size: 32px;
            margin-right: 20px;
        }}
        
        .file-info {{
            flex: 1;
        }}
        
        .file-info h3 {{
            margin: 0 0 5px 0;
            color: #333;
        }}
        
        .file-info p {{
            margin: 0;
            color: #666;
            font-size: 14px;
        }}
        
        .download-btn {{
            background: #2196F3;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: bold;
            transition: background 0.3s;
        }}
        
        .download-btn:hover {{
            background: #1976D2;
        }}
        
        .no-files {{
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 40px;
        }}
        
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            color: #2196F3;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="page-title">Downloads Disponíveis</h1>
        
        <div class="files-list">
            {files_html}
        </div>
        
        <a href="/" class="back-link">← Voltar à Página Principal</a>
    </div>
</body>
</html>
"""
    
    def generate_about_page(self):
        """Gera página sobre"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sobre - Portal de Downloads</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 80px 20px 20px;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        
        p {
            line-height: 1.6;
            color: #666;
            margin-bottom: 15px;
        }
        
        .back-link {
            display: inline-block;
            margin-top: 20px;
            color: #2196F3;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Sobre o Portal de Downloads</h1>
        
        <p>Este é um portal seguro para distribuição de arquivos e aplicativos. 
        Todos os arquivos disponíveis para download passam por verificações de segurança 
        para garantir a proteção dos nossos usuários.</p>
        
        <p><strong>Recursos:</strong></p>
        <ul>
            <li>Downloads seguros e verificados</li>
            <li>Suporte a múltiplas plataformas</li>
            <li>Alta velocidade de download</li>
            <li>Interface amigável e responsiva</li>
        </ul>
        
        <a href="/" class="back-link">← Voltar à Página Principal</a>
    </div>
</body>
</html>
"""
    
    def generate_stats_page(self):
        """Gera página de estatísticas"""
        files = self.file_manager.list_uploaded_files()
        total_downloads = sum(file_info['download_count'] for file_info in files.values())
        total_files = len(files)
        
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Estatísticas - Portal de Downloads</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 80px 20px 20px;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            color: #2196F3;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 14px;
        }}
        
        .files-list {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .file-stat {{
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }}
        
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            color: #2196F3;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Estatísticas do Portal</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_files}</div>
                <div class="stat-label">Arquivos Disponíveis</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{total_downloads}</div>
                <div class="stat-label">Total de Downloads</div>
            </div>
        </div>
        
        <div class="files-list">
            <h2>Estatísticas por Arquivo</h2>
            {"".join(f'<div class="file-stat"><span>{info["file_name"]}</span><span>{info["download_count"]} downloads</span></div>' 
                    for info in files.values())}
        </div>
        
        <a href="/" class="back-link">← Voltar à Página Principal</a>
    </div>
</body>
</html>
"""

# ==================== PAINEL PRINCIPAL AVANÇADO ====================
class AdvancedFileServerPanel:
    def __init__(self):
        self.file_manager = RealFileManager()
        self.server = None
        self.server_thread = None
        self.server_port = 8080
        self.site_config = {
            'title': 'Portal de Downloads Premium',
            'description': 'Downloads seguros para todas as plataformas'
        }
        
        self.banner = """
[bold blue]
   ███████████████████████████
   ███████▀▀▀░░░░░░░▀▀▀███████
   ████▀░░░░░░░░░░░░░░░░░▀████
   ███│░░░░░░░░░░░░░░░░░░░│███
   ██▌│░░░░░░░░░░░░░░░░░░░│▐██
   ██░└┐░░░░░░░░░░░░░░░░░┌┘░██
   ██░░└┐░░░░░░░░░░░░░░░┌┘░░██
   ██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██
   ██▌░│██████▌░░░▐██████│░▐██
   ███░│▐███▀▀░░▄░░▀▀███▌│░███
   ██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██
   ██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██
   ████▄─┘██▌░░░░░░░▐██└─▄████
   █████░░▐█─┬┬┬┬┬┬┬─█▌░░█████
   ████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████
   █████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████
   ███████▄░░░░░░░░░░░▄███████
   ██████████▄▄▄▄▄▄▄██████████
   ███████████████████████████
[/bold blue]
[bold white on blue]        SERVIDOR DE ARQUIVOS MALWARES - DISTRIBUIÇÃO DE MALWARES PROFISSIONAL[/bold white on blue]
"""
    
    def show_menu(self):
        """Mostra o menu principal"""
        while True:
            console.clear()
            console.print(self.banner)
            
            # Status do servidor
            server_status = "[red]❌ PARADO[/red]" if not self.server else "[green]✅ RODANDO[/green]"
            files_count = len(self.file_manager.list_uploaded_files())
            
            status_panel = Panel.fit(
                f"[cyan]🌐 Servidor:[/cyan] {server_status}\n"
                f"[cyan]📂 Arquivos:[/cyan] {files_count} carregados\n"
                f"[cyan]🔌 Porta:[/cyan] {self.server_port}",
                title="[bold]Status do Sistema[/bold]",
                border_style="blue"
            )
            console.print(status_panel)
            
            table = Table(
                title="[bold cyan]🎛️  MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Carregar Arquivo Real", "📁")
            table.add_row("2", "Iniciar Servidor Web", "🌐")
            table.add_row("3", "Gerenciar Arquivos", "📊")
            table.add_row("4", "Configurar Site", "⚙️")
            table.add_row("5", "Estatísticas", "📈")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if choice == "1":
                self.upload_real_file()
            elif choice == "2":
                self.start_real_web_server()
            elif choice == "3":
                self.manage_files()
            elif choice == "4":
                self.configure_site()
            elif choice == "5":
                self.show_statistics()
            elif choice == "0":
                self.exit_program()
    
    def upload_real_file(self):
        """Carrega um arquivo real para distribuição"""
        console.print(Panel.fit(
            "[bold]📁 CARREGAR ARQUIVO REAL[/bold]",
            border_style="blue"
        ))
        
        while True:
            file_path = Prompt.ask(
                "[yellow]?[/yellow] Caminho completo do arquivo",
                default=""
            )
            
            if not file_path:
                if Confirm.ask("[yellow]?[/yellow] Cancelar operação?"):
                    return
            
            # Expandir ~ para home directory
            file_path = os.path.expanduser(file_path)
            
            # Validar arquivo
            is_valid, message = self.file_manager.validate_file(file_path)
            if is_valid:
                break
            else:
                console.print(f"[red]❌ {message}[/red]")
                if not Confirm.ask("[yellow]?[/yellow] Tentar outro arquivo?"):
                    return
        
        # Perguntar por nome personalizado
        custom_name = Prompt.ask(
            "[yellow]?[/yellow] Nome personalizado (opcional)",
            default=""
        )
        
        if not custom_name:
            custom_name = None
        
        console.print("[yellow]⏳ Copiando arquivo para o servidor...[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processando...", total=100)
            
            for i in range(100):
                time.sleep(0.02)
                progress.update(task, advance=1)
        
        # Copiar arquivo
        file_id, message = self.file_manager.copy_file_to_server(file_path, custom_name)
        
        if file_id:
            file_info = self.file_manager.get_file_info(file_id)
            console.print(Panel.fit(
                f"[green]✅ Arquivo carregado com sucesso![/green]\n"
                f"[cyan]Nome:[/cyan] {file_info['file_name']}\n"
                f"[cyan]Tamanho:[/cyan] {file_info['file_size'] / 1024 / 1024:.2f} MB\n"
                f"[cyan]ID:[/cyan] {file_id}\n"
                f"[yellow]⚠️ Pronto para distribuição via servidor web[/yellow]",
                title="[green]SUCESSO[/green]",
                border_style="green"
            ))
        else:
            console.print(f"[red]❌ {message}[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def start_real_web_server(self):
        """Inicia servidor web real para distribuição"""
        console.print(Panel.fit(
            "[bold]🌐 SERVIDOR WEB REAL[/bold]",
            border_style="blue"
        ))
        
        # Verificar se há arquivos carregados
        if not self.file_manager.list_uploaded_files():
            console.print("[red]❌ Nenhum arquivo carregado. Carregue arquivos primeiro.[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        # Configurar porta
        self.server_port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta do servidor",
            default=self.server_port
        )
        
        # Verificar se porta está disponível
        if not self.check_port_available(self.server_port):
            console.print("[red]❌ Porta já em uso! Escolha outra porta.[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        # Iniciar servidor
        try:
            def handler(*args):
                RealFileServerHandler(*args, 
                                   file_manager=self.file_manager,
                                   site_config=self.site_config)
            
            self.server = HTTPServer(('0.0.0.0', self.server_port), handler)
            
            # Iniciar em thread separada
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Obter IP local
            local_ip = self.get_local_ip()
            
            console.print(Panel.fit(
                f"[green]✅ Servidor web iniciado com sucesso![/green]\n"
                f"[cyan]URL Local:[/cyan] http://localhost:{self.server_port}\n"
                f"[cyan]URL Rede:[/cyan] http://{local_ip}:{self.server_port}\n"
                f"[cyan]Arquivos:[/cyan] {len(self.file_manager.list_uploaded_files())} disponíveis\n"
                f"[yellow]⚠️ Site profissional com HTML/CSS real[/yellow]\n"
                f"[yellow]⚠️ Suporte total a APK, EXE, PY e outros[/yellow]",
                title="[green]SERVIDOR ATIVO[/green]",
                border_style="green"
            ))
            
            console.print("[yellow]⚠️ Pressione Ctrl+C para parar o servidor[/yellow]")
            
            # Manter thread principal ativa
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]⏹️ Parando servidor...[/yellow]")
                self.stop_web_server()
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao iniciar servidor: {e}[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def manage_files(self):
        """Gerencia arquivos carregados"""
        console.print(Panel.fit(
            "[bold]📊 GERENCIAR ARQUIVOS[/bold]",
            border_style="blue"
        ))
        
        files = self.file_manager.list_uploaded_files()
        
        if not files:
            console.print("[yellow]⚠️ Nenhum arquivo carregado.[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=10)
        table.add_column("Nome", style="green")
        table.add_column("Tamanho", style="yellow")
        table.add_column("Downloads", style="blue")
        table.add_column("Upload", style="white")
        
        for file_id, file_info in files.items():
            file_size_mb = file_info['file_size'] / (1024 * 1024)
            table.add_row(
                file_id,
                file_info['file_name'],
                f"{file_size_mb:.2f} MB",
                str(file_info['download_count']),
                file_info['upload_time']
            )
        
        console.print(table)
        
        # Opções de gerenciamento
        console.print("\n[bold]Opções:[/bold]")
        console.print("[1] Remover arquivo")
        console.print("[2] Voltar")
        
        choice = Prompt.ask(
            "[blink yellow]➤[/blink yellow] Selecione",
            choices=["1", "2"],
            show_choices=False
        )
        
        if choice == "1":
            file_id = Prompt.ask("[yellow]?[/yellow] ID do arquivo para remover")
            if file_id in files:
                success, message = self.file_manager.delete_file(file_id)
                if success:
                    console.print(f"[green]✅ {message}[/green]")
                else:
                    console.print(f"[red]❌ {message}[/red]")
            else:
                console.print("[red]❌ ID inválido[/red]")
            
            input("\nPressione Enter para voltar...")
    
    def configure_site(self):
        """Configura o site do servidor"""
        console.print(Panel.fit(
            "[bold]⚙️ CONFIGURAR SITE[/bold]",
            border_style="blue"
        ))
        
        console.print(f"[cyan]Configuração atual:[/cyan]")
        console.print(f"Título: {self.site_config['title']}")
        console.print(f"Descrição: {self.site_config['description']}")
        
        new_title = Prompt.ask(
            "[yellow]?[/yellow] Novo título",
            default=self.site_config['title']
        )
        
        new_description = Prompt.ask(
            "[yellow]?[/yellow] Nova descrição", 
            default=self.site_config['description']
        )
        
        self.site_config['title'] = new_title
        self.site_config['description'] = new_description
        
        console.print("[green]✅ Configurações atualizadas![/green]")
        input("\nPressione Enter para voltar...")
    
    def show_statistics(self):
        """Mostra estatísticas detalhadas"""
        console.print(Panel.fit(
            "[bold]📈 ESTATÍSTICAS DETALHADAS[/bold]",
            border_style="blue"
        ))
        
        files = self.file_manager.list_uploaded_files()
        total_downloads = sum(file_info['download_count'] for file_info in files.values())
        total_size = sum(file_info['file_size'] for file_info in files.values())
        
        stats_table = Table(show_header=True, header_style="bold magenta")
        stats_table.add_column("Métrica", style="cyan")
        stats_table.add_column("Valor", style="green")
        
        stats_table.add_row("Total de Arquivos", str(len(files)))
        stats_table.add_row("Total de Downloads", str(total_downloads))
        stats_table.add_row("Espaço Total", f"{total_size / 1024 / 1024:.2f} MB")
        stats_table.add_row("Servidor Ativo", "Sim" if self.server else "Não")
        
        console.print(stats_table)
        
        if files:
            console.print("\n[bold]📊 Downloads por Arquivo:[/bold]")
            for file_id, file_info in files.items():
                console.print(f"  {file_info['file_name']}: {file_info['download_count']} downloads")
        
        input("\nPressione Enter para voltar...")
    
    def check_port_available(self, port):
        """Verifica se a porta está disponível"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return True
        except:
            return False
    
    def get_local_ip(self):
        """Obtém IP local"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def stop_web_server(self):
        """Para o servidor web"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            console.print("[green]✅ Servidor parado[/green]")
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO LEGAL: USE COM RESPONSABILIDADE! ⚠️[/blink bold red]",
            border_style="red"
        ))
        self.stop_web_server()
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        # Verificar se está no Termux
        if not os.path.exists('/data/data/com.termux/files/usr'):
            console.print("[yellow]⚠️ Script otimizado para Termux[/yellow]")
        
        panel = AdvancedFileServerPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
