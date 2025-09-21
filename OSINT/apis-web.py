#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import requests
import ipaddress
from flask import Flask, render_template, request, jsonify, send_from_directory
import threading
import webbrowser
from rich.console import Console
from rich.panel import Panel
import time

# Inicialização do Flask e Rich Console
app = Flask(__name__, template_folder='templates', static_folder='static')
console = Console()

class PolyTools:
    def __init__(self):
        self.name = "PolyTools"
        self.version = "2.0"
        self.author = "Lone Wolf Security"
        self.port = 8080
        self.host = "0.0.0.0"
        self.running = False
        
    def show_banner(self):
        banner = f"""
        🐺 POLYTOOLS - FERRAMENTAS DE CONSULTA 🐺
        
        [bold blue]Version: {self.version}[/bold blue] | [bold green]Author: {self.author}[/bold green]
        [bold yellow]Servidor Web: http://{self.host}:{self.port}[/bold yellow]
        """
        console.print(Panel.fit(banner, style="bold purple"))
        
    def consulta_cep(self, cep):
        """Consulta informações de CEP"""
        try:
            cep = cep.replace("-", "").replace(".", "").strip()
            if len(cep) != 8:
                return {"error": "CEP deve ter 8 dígitos"}
                
            url = f"https://viacep.com.br/ws/{cep}/json/"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "erro" not in data:
                    return {
                        "cep": data.get("cep", ""),
                        "logradouro": data.get("logradouro", ""),
                        "complemento": data.get("complemento", ""),
                        "bairro": data.get("bairro", ""),
                        "cidade": data.get("localidade", ""),
                        "estado": data.get("uf", ""),
                        "ibge": data.get("ibge", ""),
                        "ddd": data.get("ddd", "")
                    }
                else:
                    return {"error": "CEP não encontrado"}
            else:
                return {"error": "Erro na consulta do CEP"}
                
        except Exception as e:
            return {"error": f"Erro na consulta: {str(e)}"}
    
    def consulta_cnpj(self, cnpj):
        """Consulta informações de CNPJ"""
        try:
            cnpj = cnpj.replace(".", "").replace("/", "").replace("-", "").strip()
            if len(cnpj) != 14:
                return {"error": "CNPJ deve ter 14 dígitos"}
                
            url = f"https://receitaws.com.br/v1/cnpj/{cnpj}"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "OK":
                    return {
                        "cnpj": data.get("cnpj", ""),
                        "nome": data.get("nome", ""),
                        "fantasia": data.get("fantasia", ""),
                        "situacao": data.get("situacao", ""),
                        "tipo": data.get("tipo", ""),
                        "porte": data.get("porte", ""),
                        "abertura": data.get("abertura", ""),
                        "atividade_principal": data.get("atividade_principal", [{}])[0].get("text", ""),
                        "logradouro": data.get("logradouro", ""),
                        "numero": data.get("numero", ""),
                        "complemento": data.get("complemento", ""),
                        "bairro": data.get("bairro", ""),
                        "municipio": data.get("municipio", ""),
                        "uf": data.get("uf", ""),
                        "cep": data.get("cep", ""),
                        "email": data.get("email", ""),
                        "telefone": data.get("telefone", ""),
                        "data_situacao": data.get("data_situacao", ""),
                        "ultima_atualizacao": data.get("ultima_atualizacao", "")
                    }
                else:
                    return {"error": data.get("message", "CNPJ não encontrado")}
            else:
                return {"error": "Erro na consulta do CNPJ"}
                
        except Exception as e:
            return {"error": f"Erro na consulta: {str(e)}"}
    
    def consulta_ip(self, ip):
        """Consulta informações de IP"""
        try:
            # Validar se é um IP válido
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return {"error": "Endereço IP inválido"}
                
            url = f"http://ip-api.com/json/{ip}?fields=66846719"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", ""),
                        "pais": data.get("country", ""),
                        "codigo_pais": data.get("countryCode", ""),
                        "regiao": data.get("region", ""),
                        "nome_regiao": data.get("regionName", ""),
                        "cidade": data.get("city", ""),
                        "cep": data.get("zip", ""),
                        "lat": data.get("lat", ""),
                        "lon": data.get("lon", ""),
                        "fuso_horario": data.get("timezone", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                        "reverse_dns": data.get("reverse", "")
                    }
                else:
                    return {"error": data.get("message", "IP não encontrado")}
            else:
                return {"error": "Erro na consulta do IP"}
                
        except Exception as e:
            return {"error": f"Erro na consulta: {str(e)}"}
    
    def consulta_bin(self, bin):
        """Consulta informações de BIN (Bank Identification Number)"""
        try:
            bin = bin.strip()
            if len(bin) < 6:
                return {"error": "BIN deve ter pelo menos 6 dígitos"}
                
            # Usar apenas os primeiros 6 dígitos
            bin = bin[:6]
            
            url = f"https://lookup.binlist.net/{bin}"
            headers = {"Accept-Version": "3"}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "bin": bin,
                    "bandeira": data.get("scheme", ""),
                    "tipo": data.get("type", ""),
                    "categoria": data.get("brand", ""),
                    "prepaid": data.get("prepaid", ""),
                    "pais": data.get("country", {}).get("name", ""),
                    "codigo_pais": data.get("country", {}).get("alpha2", ""),
                    "moeda": data.get("country", {}).get("currency", ""),
                    "banco": data.get("bank", {}).get("name", ""),
                    "url_banco": data.get("bank", {}).get("url", ""),
                    "telefone_banco": data.get("bank", {}).get("phone", "")
                }
            else:
                return {"error": "BIN não encontrado ou erro na consulta"}
                
        except Exception as e:
            return {"error": f"Erro na consulta: {str(e)}"}
    
    def start_web_interface(self):
        """Inicia a interface web"""
        self.show_banner()
        console.print(f"[bold green]🚀 Iniciando servidor web em http://{self.host}:{self.port}[/bold green]")
        console.print("[bold yellow]📱 Acesse pelo navegador em qualquer dispositivo da rede[/bold yellow]")
        console.print("[bold red]⏹️  Pressione Ctrl+C para parar o servidor[/bold red]")
        
        # Iniciar servidor em thread separada
        def run_server():
            app.run(host=self.host, port=self.port, debug=False, threaded=True)
        
        self.running = True
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Aguardar um pouco e abrir no navegador
        time.sleep(2)
        webbrowser.open(f"http://localhost:{self.port}")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("[bold red]🛑 Parando servidor...[/bold red]")
            self.running = False

# Rotas da API Flask
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/cep/<cep>')
def api_cep(cep):
    tools = PolyTools()
    result = tools.consulta_cep(cep)
    return jsonify(result)

@app.route('/api/cnpj/<cnpj>')
def api_cnpj(cnpj):
    tools = PolyTools()
    result = tools.consulta_cnpj(cnpj)
    return jsonify(result)

@app.route('/api/ip/<ip>')
def api_ip(ip):
    tools = PolyTools()
    result = tools.consulta_ip(ip)
    return jsonify(result)

@app.route('/api/bin/<bin>')
def api_bin(bin):
    tools = PolyTools()
    result = tools.consulta_bin(bin)
    return jsonify(result)

@app.route('/health')
def health_check():
    return jsonify({"status": "online", "service": "PolyTools"})

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# Criar diretórios necessários
def setup_directories():
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)

# Criar arquivos HTML, CSS e JS melhorados
def create_html_files():
    # Página principal melhorada
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools - Ferramentas de Consulta Profissional</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🐺</text></svg>">
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="logo-container">
                <div class="logo">
                    <i class="fas fa-paw"></i>
                    <h1>PolyTools</h1>
                </div>
                <span class="version">v2.0</span>
            </div>
            <p class="tagline">Ferramentas profissionais de consulta em tempo real</p>
        </header>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Tabs Navigation -->
            <div class="tabs">
                <button class="tab-button active" data-tab="cep">
                    <i class="fas fa-map-marker-alt"></i>
                    <span>CEP</span>
                </button>
                <button class="tab-button" data-tab="cnpj">
                    <i class="fas fa-building"></i>
                    <span>CNPJ</span>
                </button>
                <button class="tab-button" data-tab="ip">
                    <i class="fas fa-globe"></i>
                    <span>IP</span>
                </button>
                <button class="tab-button" data-tab="bin">
                    <i class="fas fa-credit-card"></i>
                    <span>BIN</span>
                </button>
            </div>

            <!-- Tab Content -->
            <div class="tab-content">
                <!-- CEP Tab -->
                <div id="cep" class="tab-pane active">
                    <div class="input-container">
                        <div class="input-group">
                            <input type="text" id="cep-input" placeholder="Digite o CEP (ex: 01001000)" maxlength="9">
                            <button class="consult-btn" onclick="consultar('cep')">
                                <i class="fas fa-search"></i>
                                Consultar
                            </button>
                        </div>
                        <div class="examples">
                            <small>Exemplos: 01001000, 22041011, 30130005</small>
                        </div>
                    </div>
                    <div id="cep-result" class="result-container"></div>
                </div>

                <!-- CNPJ Tab -->
                <div id="cnpj" class="tab-pane">
                    <div class="input-container">
                        <div class="input-group">
                            <input type="text" id="cnpj-input" placeholder="Digite o CNPJ (ex: 00.000.000/0001-91)" maxlength="18">
                            <button class="consult-btn" onclick="consultar('cnpj')">
                                <i class="fas fa-search"></i>
                                Consultar
                            </button>
                        </div>
                        <div class="examples">
                            <small>Exemplos: 00.000.000/0001-91, 33.000.167/0001-01</small>
                        </div>
                    </div>
                    <div id="cnpj-result" class="result-container"></div>
                </div>

                <!-- IP Tab -->
                <div id="ip" class="tab-pane">
                    <div class="input-container">
                        <div class="input-group">
                            <input type="text" id="ip-input" placeholder="Digite o IP (ex: 8.8.8.8)">
                            <button class="consult-btn" onclick="consultar('ip')">
                                <i class="fas fa-search"></i>
                                Consultar
                            </button>
                        </div>
                        <div class="examples">
                            <small>Exemplos: 8.8.8.8, 200.160.2.3, 187.332.84.1</small>
                        </div>
                    </div>
                    <div id="ip-result" class="result-container"></div>
                </div>

                <!-- BIN Tab -->
                <div id="bin" class="tab-pane">
                    <div class="input-container">
                        <div class="input-group">
                            <input type="text" id="bin-input" placeholder="Digite o BIN (ex: 424242)" maxlength="6">
                            <button class="consult-btn" onclick="consultar('bin')">
                                <i class="fas fa-search"></i>
                                Consultar
                            </button>
                        </div>
                        <div class="examples">
                            <small>Exemplos: 424242, 517805, 401658</small>
                        </div>
                    </div>
                    <div id="bin-result" class="result-container"></div>
                </div>
            </div>
        </main>

        <!-- Footer -->
        <footer class="footer">
            <div class="footer-content">
                <p>&copy; 2024 PolyTools - <i class="fas fa-paw"></i> Lone Wolf Security Tools</p>
                <div class="footer-links">
                    <span id="status" class="status-online">
                        <i class="fas fa-circle"></i> Online
                    </span>
                </div>
            </div>
        </footer>
    </div>

    <!-- Loading Animation -->
    <div id="loading" class="loading-overlay">
        <div class="loading-spinner">
            <i class="fas fa-paw"></i>
            <p>Consultando...</p>
        </div>
    </div>

    <script src="{{ url_for('static', filename='js/script.js') }}"></script>
</body>
</html>''')

    # Arquivo CSS melhorado
    with open('static/css/style.css', 'w', encoding='utf-8') as f:
        f.write('''* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --primary: #667eea;
    --primary-dark: #5a67d8;
    --secondary: #764ba2;
    --accent: #f093fb;
    --success: #10b981;
    --warning: #f59e0b;
    --error: #ef4444;
    --dark: #1f2937;
    --light: #f8fafc;
    --gray: #64748b;
    --gray-light: #e2e8f0;
}

body {
    font-family: 'Inter', sans-serif;
    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
    min-height: 100vh;
    padding: 20px;
    color: var(--dark);
}

.container {
    max-width: 1000px;
    margin: 0 auto;
    background: white;
    border-radius: 20px;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
    overflow: hidden;
    min-height: 90vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.header {
    background: linear-gradient(135deg, var(--dark) 0%, #2d3748 100%);
    color: white;
    padding: 40px;
    text-align: center;
    position: relative;
}

.logo-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 15px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}

.logo {
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo i {
    font-size: 2.8rem;
    color: var(--accent);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.1); }
}

.logo h1 {
    font-size: 2.8rem;
    font-weight: 800;
    background: linear-gradient(135deg, var(--accent) 0%, #667eea 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.version {
    background: var(--accent);
    color: white;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.9rem;
    font-weight: 600;
}

.tagline {
    color: var(--gray-light);
    font-size: 1.2rem;
    font-weight: 300;
}

/* Main Content */
.main-content {
    flex: 1;
    padding: 0;
}

/* Tabs */
.tabs {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    background: var(--gray-light);
    border-bottom: 2px solid var(--gray-light);
}

.tab-button {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 20px;
    border: none;
    background: none;
    cursor: pointer;
    font-size: 1rem;
    font-weight: 500;
    color: var(--gray);
    transition: all 0.3s ease;
    border-bottom: 3px solid transparent;
}

.tab-button:hover {
    background: white;
    color: var(--primary);
}

.tab-button.active {
    background: white;
    color: var(--primary);
    border-bottom-color: var(--primary);
}

.tab-button i {
    font-size: 1.5rem;
    margin-bottom: 5px;
}

/* Tab Content */
.tab-content {
    padding: 40px;
}

.tab-pane {
    display: none;
}

.tab-pane.active {
    display: block;
    animation: fadeIn 0.5s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.input-container {
    margin-bottom: 30px;
}

.input-group {
    display: flex;
    gap: 15px;
    margin-bottom: 10px;
}

input {
    flex: 1;
    padding: 16px 20px;
    border: 2px solid var(--gray-light);
    border-radius: 12px;
    font-size: 1.1rem;
    transition: all 0.3s ease;
    background: var(--light);
}

input:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

input::placeholder {
    color: var(--gray);
}

.consult-btn {
    padding: 16px 30px;
    background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
    color: white;
    border: none;
    border-radius: 12px;
    cursor: pointer;
    font-size: 1.1rem;
    font-weight: 600;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 8px;
}

.consult-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
}

.examples {
    text-align: center;
}

.examples small {
    color: var(--gray);
    font-size: 0.9rem;
}

/* Results */
.result-container {
    background: var(--light);
    border-radius: 15px;
    padding: 30px;
    border-left: 5px solid var(--primary);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
}

.result-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}

.result-item {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.result-key {
    font-weight: 600;
    color: var(--dark);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.result-value {
    color: var(--gray);
    font-size: 1rem;
    word-break: break-word;
}

.error-box {
    background: #fee2e2;
    color: var(--error);
    padding: 20px;
    border-radius: 12px;
    text-align: center;
    border-left: 5px solid var(--error);
}

.success-box {
    background: #d1fae5;
    color: var(--success);
    padding: 20px;
    border-radius: 12px;
    text-align: center;
    border-left: 5px solid var(--success);
}

/* Loading */
.loading-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: none;
    justify-content: center;
    align-items: center;
    z-index: 1000;
}

.loading-spinner {
    text-align: center;
    color: white;
}

.loading-spinner i {
    font-size: 3rem;
    margin-bottom: 15px;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.loading-spinner p {
    font-size: 1.2rem;
}

/* Footer */
.footer {
    background: var(--gray-light);
    padding: 25px 40px;
    border-top: 1px solid var(--gray-light);
}

.footer-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
}

.footer p {
    color: var(--gray);
}

.status-online {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--success);
    font-weight: 500;
}

.status-online i {
    font-size: 0.7rem;
    animation: blink 2s infinite;
}

@keyframes blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0.3; }
}

.footer-links {
    display: flex;
    gap: 20px;
}

/* Responsive */
@media (max-width: 768px) {
    body {
        padding: 10px;
    }
    
    .container {
        border-radius: 15px;
    }
    
    .header {
        padding: 30px 20px;
    }
    
    .logo h1 {
        font-size: 2.2rem;
    }
    
    .tabs {
        grid-template-columns: 1fr;
    }
    
    .tab-button {
        padding: 15px;
    }
    
    .tab-content {
        padding: 25px;
    }
    
    .input-group {
        flex-direction: column;
    }
    
    .consult-btn {
        width: 100%;
        justify-content: center;
    }
    
    .footer-content {
        flex-direction: column;
        text-align: center;
    }
    
    .result-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 480px) {
    .header {
        padding: 25px 15px;
    }
    
    .logo h1 {
        font-size: 1.8rem;
    }
    
    .tab-content {
        padding: 20px 15px;
    }
    
    input {
        padding: 14px;
    }
}

/* Dark mode support */
@media (prefers-color-scheme: dark) {
    body {
        background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
    }
    
    .container {
        background: #2d3748;
        color: white;
    }
    
    input {
        background: #4a5568;
        color: white;
        border-color: #4a5568;
    }
    
    input::placeholder {
        color: #a0aec0;
    }
    
    .result-container {
        background: #4a5568;
    }
    
    .result-key {
        color: white;
    }
    
    .result-value {
        color: #e2e8f0;
    }
}''')

    # Arquivo JavaScript melhorado
    with open('static/js/script.js', 'w', encoding='utf-8') as f:
        f.write('''document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tabs
    initTabs();
    
    // Initialize input masks
    initInputMasks();
    
    // Check server status
    checkServerStatus();
    
    // Add event listeners for Enter key
    initEnterKeySupport();
}

function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // Remove active class from all buttons and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked button and pane
            this.classList.add('active');
            document.getElementById(tabId).classList.add('active');
            
            // Clear previous results
            clearResults();
        });
    });
}

function initInputMasks() {
    const cepInput = document.getElementById('cep-input');
    const cnpjInput = document.getElementById('cnpj-input');
    
    // CEP mask: 00000-000
    cepInput.addEventListener('input', function(e) {
        let value = e.target.value.replace(/\D/g, '');
        if (value.length > 5) {
            value = value.replace(/^(\d{5})(\d)/, '$1-$2');
        }
        if (value.length > 9) {
            value = value.slice(0, 9);
        }
        e.target.value = value;
    });
    
    // CNPJ mask: 00.000.000/0000-00
    cnpjInput.addEventListener('input', function(e) {
        let value = e.target.value.replace(/\D/g, '');
        if (value.length > 2) {
            value = value.replace(/^(\d{2})(\d)/, '$1.$2');
        }
        if (value.length > 6) {
            value = value.replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3');
        }
        if (value.length > 10) {
            value = value.replace(/\.(\d{3})(\d)/, '.$1/$2');
        }
        if (value.length > 15) {
            value = value.replace(/(\d{4})(\d)/, '$1-$2');
        }
        if (value.length > 18) {
            value = value.slice(0, 18);
        }
        e.target.value = value;
    });
}

function initEnterKeySupport() {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const activeTab = document.querySelector('.tab-button.active').getAttribute('data-tab');
                consultar(activeTab);
            }
        });
    });
}

function checkServerStatus() {
    fetch('/health')
        .then(response => response.json())
        .then(data => {
            const statusElement = document.getElementById('status');
            if (data.status === 'online') {
                statusElement.innerHTML = '<i class="fas fa-circle"></i> Online';
                statusElement.className = 'status-online';
            }
        })
        .catch(() => {
            const statusElement = document.getElementById('status');
            statusElement.innerHTML = '<i class="fas fa-circle"></i> Offline';
            statusElement.style.color = '#ef4444';
        });
}

function showLoading() {
    document.getElementById('loading').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loading').style.display = 'none';
}

function clearResults() {
    const resultContainers = document.querySelectorAll('.result-container');
    resultContainers.forEach(container => {
        container.innerHTML = '';
    });
}

function consultar(tipo) {
    const inputMap = {
        'cep': 'cep-input',
        'cnpj': 'cnpj-input',
        'ip': 'ip-input',
        'bin': 'bin-input'
    };
    
    const resultMap = {
        'cep': 'cep-result',
        'cnpj': 'cnpj-result',
        'ip': 'ip-result',
        'bin': 'bin-result'
    };
    
    const input = document.getElementById(inputMap[tipo]);
    const resultDiv = document.getElementById(resultMap[tipo]);
    let valor = input.value.replace(/\D/g, '');
    
    // Special handling for IP addresses
    if (tipo === 'ip') {
        valor = input.value.trim();
    }
    
    if (!valor) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <i class="fas fa-exclamation-circle"></i>
                <p>Por favor, digite um valor válido</p>
            </div>
        `;
        return;
    }
    
    showLoading();
    
    fetch(`/api/${tipo}/${encodeURIComponent(valor)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading();
            
            if (data.error) {
                resultDiv.innerHTML = `
                    <div class="error-box">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>${data.error}</p>
                    </div>
                `;
            } else {
                displayResults(data, tipo, resultDiv);
            }
        })
        .catch(error => {
            hideLoading();
            resultDiv.innerHTML = `
                <div class="error-box">
                    <i class="fas fa-times-circle"></i>
                    <p>Erro na consulta: ${error.message}</p>
                </div>
            `;
        });
}

function displayResults(data, tipo, resultDiv) {
    let html = `
        <div class="success-box">
            <i class="fas fa-check-circle"></i>
            <p>Consulta realizada com sucesso!</p>
        </div>
        <div class="result-grid">
    `;
    
    for (const [key, value] of Object.entries(data)) {
        if (value !== null && value !== undefined && value !== '') {
            const formattedKey = formatKey(key);
            const formattedValue = formatValue(key, value);
            
            html += `
                <div class="result-item">
                    <span class="result-key">${formattedKey}</span>
                    <span class="result-value">${formattedValue}</span>
                </div>
            `;
        }
    }
    
    html += '</div>';
    resultDiv.innerHTML = html;
}

function formatKey(key) {
    const translations = {
        'cep': 'CEP',
        'logradouro': 'Logradouro',
        'complemento': 'Complemento',
        'bairro': 'Bairro',
        'cidade': 'Cidade',
        'estado': 'Estado',
        'ibge': 'Código IBGE',
        'ddd': 'DDD',
        'cnpj': 'CNPJ',
        'nome': 'Nome',
        'fantasia': 'Nome Fantasia',
        'situacao': 'Situação',
        'tipo': 'Tipo',
        'porte': 'Porte',
        'abertura': 'Data de Abertura',
        'atividade_principal': 'Atividade Principal',
        'numero': 'Número',
        'municipio': 'Município',
        'uf': 'UF',
        'email': 'Email',
        'telefone': 'Telefone',
        'data_situacao': 'Data da Situação',
        'ultima_atualizacao': 'Última Atualização',
        'ip': 'Endereço IP',
        'pais': 'País',
        'codigo_pais': 'Código do País',
        'regiao': 'Região',
        'nome_regiao': 'Nome da Região',
        'lat': 'Latitude',
        'lon': 'Longitude',
        'fuso_horario': 'Fuso Horário',
        'isp': 'ISP',
        'org': 'Organização',
        'as': 'ASN',
        'reverse_dns': 'DNS Reverso',
        'bin': 'BIN',
        'bandeira': 'Bandeira',
        'categoria': 'Categoria',
        'prepaid': 'Pré-pago',
        'moeda': 'Moeda',
        'banco': 'Banco',
        'url_banco': 'URL do Banco',
        'telefone_banco': 'Telefone do Banco'
    };
    
    return translations[key] || key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ');
}

function formatValue(key, value) {
    // Format specific values
    if (key === 'prepaid') {
        return value ? 'Sim' : 'Não';
    }
    
    if (key === 'lat' || key === 'lon') {
        return Number(value).toFixed(6);
    }
    
    return value;
}''')

def main():
    # Configurar diretórios e arquivos
    setup_directories()
    create_html_files()
    
    # Iniciar aplicação
    tools = PolyTools()
    tools.start_web_interface()

if __name__ == "__main__":
    main()
