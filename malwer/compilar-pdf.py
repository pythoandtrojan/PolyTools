#!/usr/bin/env python3
"""
Web PDF Compressor - Server Launcher
Terminal para configurar e iniciar o servidor web
"""

import os
import sys
import time
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class WebServer:
    def __init__(self):
        self.server = None
        self.port = 8000
        self.host = 'localhost'
        self.is_running = False
        
    def create_website_files(self):
        """Cria todos os arquivos necessários para o website"""
        # Criar diretório se não existir
        if not os.path.exists('web_content'):
            os.makedirs('web_content')
        
        # Arquivo HTML principal
        html_content = '''<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Compressor - Terminal Web</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1 class="title">PDF COMPRESSOR TERMINAL</h1>
            <p class="subtitle">Compacte seus arquivos com segurança e eficiência</p>
        </header>

        <div class="main-content">
            <div class="terminal">
                <div class="terminal-header">
                    <div class="terminal-title">terminal@pdf-compressor:~</div>
                    <div class="terminal-controls">
                        <button class="control-btn close" onclick="closeTerminal()"></button>
                        <button class="control-btn minimize" onclick="minimizeTerminal()"></button>
                        <button class="control-btn maximize" onclick="maximizeTerminal()"></button>
                    </div>
                </div>
                <div class="terminal-body" id="terminalOutput">
                    <div class="output">Bem-vindo ao PDF Compressor Terminal v1.0</div>
                    <div class="output">Sistema inicializado em: <span id="currentDate"></span></div>
                    <div class="output">Digite "help" para ver os comandos disponíveis</div>
                    <br>
                    <div class="output">[SISTEMA] Aguardando upload de arquivos...</div>
                    <div class="output">[COMPRESSÃO] Pronto para otimizar seus PDFs</div>
                    <br>
                    <div class="prompt">user@pdf-compressor:~$ <span class="command"></span><span class="cursor"></span></div>
                </div>
            </div>

            <div class="upload-section">
                <h2 class="upload-title">UPLOAD DE ARQUIVOS</h2>
                <input type="file" id="fileInput" class="file-input" accept=".pdf,.txt,.jpg,.jpeg,.png,.doc,.docx" multiple>
                <div class="progress-container">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
                <button class="compress-btn" id="compressBtn">INICIAR COMPRESSÃO</button>
                <div class="download-section" id="downloadSection">
                    <p class="success">Compressão concluída com sucesso!</p>
                    <a href="#" class="download-btn" id="downloadLink">BAIXAR PDF COMPACTADO</a>
                </div>
                <div style="margin-top: 20px; text-align: center;">
                    <p style="color: #00ff88; font-size: 0.9rem;">Formatos suportados: PDF, TXT, JPG, PNG, DOC, DOCX</p>
                </div>
            </div>
        </div>

        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <h3 class="feature-title">COMPRESSÃO RÁPIDA</h3>
                <p class="feature-desc">Algoritmos otimizados para máxima velocidade</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3 class="feature-title">SEGURANÇA</h3>
                <p class="feature-desc">Seus arquivos são processados localmente</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3 class="feature-title">ALTA QUALIDADE</h3>
                <p class="feature-desc">Mantém a qualidade com tamanho reduzido</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🆓</div>
                <h3 class="feature-title">GRATUITO</h3>
                <p class="feature-desc">Sem custos ou limitações de uso</p>
            </div>
        </div>

        <footer class="footer">
            <p>PDF Compressor Terminal © 2024 - Desenvolvido com ❤️ para a comunidade</p>
            <p style="margin-top: 10px; font-size: 0.8rem;">Sistema: Online | Status: Operacional | Versão: 1.0.0</p>
        </footer>
    </div>

    <script src="script.js"></script>
</body>
</html>'''
        
        # Arquivo CSS
        css_content = '''* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Courier New', monospace;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    color: #00ff00;
    min-height: 100vh;
    overflow-x: hidden;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    text-align: center;
    padding: 20px 0;
    border-bottom: 2px solid #00ff00;
    margin-bottom: 30px;
}

.title {
    font-size: 2.5rem;
    color: #00ff00;
    text-shadow: 0 0 10px #00ff00;
    margin-bottom: 10px;
}

.subtitle {
    font-size: 1.2rem;
    color: #00ff88;
    opacity: 0.8;
}

.main-content {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-bottom: 30px;
}

@media (max-width: 768px) {
    .main-content {
        grid-template-columns: 1fr;
    }
}

.terminal {
    background: #000000;
    border: 2px solid #00ff00;
    border-radius: 10px;
    padding: 20px;
    height: 400px;
    overflow-y: auto;
    box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
}

.terminal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 1px solid #00ff00;
}

.terminal-title {
    font-size: 1.2rem;
    color: #00ff00;
}

.terminal-controls {
    display: flex;
    gap: 10px;
}

.control-btn {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: none;
    cursor: pointer;
}

.close { background: #ff5f56; }
.minimize { background: #ffbd2e; }
.maximize { background: #27ca3f; }

.terminal-body {
    font-family: 'Courier New', monospace;
    line-height: 1.4;
}

.prompt { color: #00ff00; }
.command { color: #ffffff; }
.output { color: #00ff88; margin: 5px 0; }
.error { color: #ff4444; }
.success { color: #00ff00; }

.upload-section {
    background: rgba(0, 0, 0, 0.7);
    border: 2px solid #00ff00;
    border-radius: 10px;
    padding: 25px;
    box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
}

.upload-title {
    font-size: 1.5rem;
    color: #00ff00;
    margin-bottom: 20px;
    text-align: center;
}

.file-input {
    width: 100%;
    padding: 15px;
    margin-bottom: 20px;
    background: rgba(0, 255, 0, 0.1);
    border: 1px solid #00ff00;
    border-radius: 5px;
    color: #ffffff;
    font-family: 'Courier New', monospace;
}

.file-input::file-selector-button {
    background: #00ff00;
    color: #000000;
    border: none;
    padding: 8px 15px;
    border-radius: 3px;
    cursor: pointer;
    font-family: 'Courier New', monospace;
    font-weight: bold;
}

.compress-btn {
    width: 100%;
    padding: 15px;
    background: #00ff00;
    color: #000000;
    border: none;
    border-radius: 5px;
    font-size: 1.1rem;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.3s ease;
    font-family: 'Courier New', monospace;
}

.compress-btn:hover {
    background: #00cc00;
    box-shadow: 0 0 15px rgba(0, 255, 0, 0.5);
}

.compress-btn:disabled {
    background: #666666;
    cursor: not-allowed;
}

.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-top: 40px;
}

.feature-card {
    background: rgba(0, 0, 0, 0.7);
    border: 1px solid #00ff00;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    transition: transform 0.3s ease;
}

.feature-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 5px 15px rgba(0, 255, 0, 0.3);
}

.feature-icon {
    font-size: 2rem;
    margin-bottom: 10px;
}

.feature-title {
    font-size: 1.2rem;
    color: #00ff00;
    margin-bottom: 10px;
}

.feature-desc {
    color: #00ff88;
    font-size: 0.9rem;
}

.footer {
    text-align: center;
    padding: 20px;
    margin-top: 40px;
    border-top: 1px solid #00ff00;
    color: #00ff88;
    opacity: 0.7;
}

.cursor {
    display: inline-block;
    width: 8px;
    height: 16px;
    background: #00ff00;
    margin-left: 5px;
    animation: blink 1s infinite;
}

@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
}

.progress-container {
    width: 100%;
    height: 20px;
    background: rgba(0, 255, 0, 0.1);
    border-radius: 10px;
    margin: 20px 0;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #00ff00, #00ff88);
    border-radius: 10px;
    transition: width 0.3s ease;
    width: 0%;
}

.download-section {
    text-align: center;
    margin-top: 20px;
    padding: 15px;
    background: rgba(0, 255, 0, 0.1);
    border-radius: 5px;
    display: none;
}

.download-btn {
    display: inline-block;
    padding: 12px 25px;
    background: #00ff00;
    color: #000000;
    text-decoration: none;
    border-radius: 5px;
    font-weight: bold;
    transition: all 0.3s ease;
}

.download-btn:hover {
    background: #00cc00;
    box-shadow: 0 0 15px rgba(0, 255, 0, 0.5);
}'''
        
        # Arquivo JavaScript
        js_content = '''// Inicialização
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('currentDate').textContent = new Date().toLocaleString();
    
    // Configurar event listeners
    document.getElementById('compressBtn').addEventListener('click', compressFiles);
    document.getElementById('fileInput').addEventListener('change', handleFileSelect);
    
    // Adicionar mensagem inicial
    addTerminalOutput('output', '[SISTEMA] Sistema de compressão PDF inicializado');
});

// Variáveis globais
const terminalOutput = document.getElementById('terminalOutput');

// Função principal de compressão
function compressFiles() {
    const fileInput = document.getElementById('fileInput');
    const compressBtn = document.getElementById('compressBtn');
    const progressBar = document.getElementById('progressBar');
    const downloadSection = document.getElementById('downloadSection');
    const downloadLink = document.getElementById('downloadLink');

    if (!fileInput.files.length) {
        addTerminalOutput('error', 'Erro: Nenhum arquivo selecionado');
        return;
    }

    // Desabilitar botão e mostrar progresso
    compressBtn.disabled = true;
    compressBtn.textContent = 'COMPACTANDO...';
    progressBar.style.width = '0%';
    downloadSection.style.display = 'none';

    addTerminalOutput('output', '[SISTEMA] Iniciando compressão de ' + fileInput.files.length + ' arquivo(s)');

    // Simular processo de compressão
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            
            // Compressão completa
            progressBar.style.width = '100%';
            compressBtn.textContent = 'COMPRESSÃO CONCLUÍDA';
            downloadSection.style.display = 'block';
            
            // Criar PDF simulado
            createCompressedPDF(fileInput.files);
            
            addTerminalOutput('success', '[SISTEMA] Compressão concluída com sucesso!');
            addTerminalOutput('output', '[RESULTADO] Arquivo compactado: documento_compactado.pdf');
            
            // Re-habilitar botão após um delay
            setTimeout(() => {
                compressBtn.disabled = false;
                compressBtn.textContent = 'INICIAR COMPRESSÃO';
            }, 2000);
        } else {
            progressBar.style.width = progress + '%';
            addTerminalOutput('output', '[PROGRESSO] Compactando... ' + Math.floor(progress) + '%');
        }
    }, 200);
}

// Criar PDF comprimido (simulação)
function createCompressedPDF(files) {
    const downloadLink = document.getElementById('downloadLink');
    
    // Criar conteúdo do PDF simulado
    let pdfContent = 'PDF COMPRIMIDO\\\\n\\\\n';
    pdfContent += 'Arquivos processados:\\\\n';
    
    for (let file of files) {
        pdfContent += '- ' + file.name + ' (' + formatFileSize(file.size) + ')\\\\n';
    }
    
    pdfContent += '\\\\nCompressão realizada em: ' + new Date().toLocaleString();
    pdfContent += '\\\\nTamanho reduzido: ' + Math.floor(Math.random() * 70 + 30) + '%';
    
    // Criar blob e link de download
    const blob = new Blob([pdfContent], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    downloadLink.href = url;
    downloadLink.download = 'documento_compactado.pdf';
}

// Manipular seleção de arquivos
function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        addTerminalOutput('output', '[UPLOAD] ' + e.target.files.length + ' arquivo(s) selecionado(s)');
        
        let totalSize = 0;
        for (let file of e.target.files) {
            addTerminalOutput('output', '[ARQUIVO] ' + file.name + ' (' + formatFileSize(file.size) + ')');
            totalSize += file.size;
        }
        
        addTerminalOutput('output', '[TOTAL] Tamanho total: ' + formatFileSize(totalSize));
    }
}

// Formatar tamanho do arquivo
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Adicionar saída ao terminal
function addTerminalOutput(type, message) {
    const outputDiv = document.createElement('div');
    outputDiv.className = type;
    outputDiv.textContent = message;
    terminalOutput.insertBefore(outputDiv, terminalOutput.lastElementChild);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

// Funções dos controles do terminal
function closeTerminal() {
    addTerminalOutput('error', '[SISTEMA] Terminal fechado. Recarregue a página para reiniciar.');
}

function minimizeTerminal() {
    addTerminalOutput('output', '[SISTEMA] Terminal minimizado');
    // Em uma implementação real, você minimizaria a janela do terminal
}

function maximizeTerminal() {
    addTerminalOutput('output', '[SISTEMA] Terminal maximizado');
    // Em uma implementação real, você maximizaria a janela do terminal
}

// Comandos do terminal (para futura expansão)
function executeCommand(command) {
    const commands = {
        'help': 'Comandos disponíveis: help, status, clear, about',
        'status': 'Sistema: Online | Compressão: Disponível | Arquivos: ' + document.getElementById('fileInput').files.length,
        'about': 'PDF Compressor Terminal v1.0 - Sistema de compressão avançado',
        'clear': function() { 
            terminalOutput.innerHTML = '<div class="prompt">user@pdf-compressor:~$ <span class="command"></span><span class="cursor"></span></div>';
        }
    };
    
    if (commands[command]) {
        if (typeof commands[command] === 'function') {
            commands[command]();
        } else {
            addTerminalOutput('output', commands[command]);
        }
    } else {
        addTerminalOutput('error', 'Comando não encontrado: ' + command);
    }
}'''
        
        # Escrever arquivos
        with open('web_content/index.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        with open('web_content/style.css', 'w', encoding='utf-8') as f:
            f.write(css_content)
        
        with open('web_content/script.js', 'w', encoding='utf-8') as f:
            f.write(js_content)
        
        print(f"{Colors.GREEN}✅ Arquivos do website criados em: web_content/{Colors.RESET}")

    def find_available_port(self, start_port=8000):
        """Encontra uma porta disponível"""
        port = start_port
        while port < 65535:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                port += 1
        return None

    def start_server(self):
        """Inicia o servidor web"""
        # Criar arquivos do website
        self.create_website_files()
        
        # Encontrar porta disponível
        self.port = self.find_available_port()
        if not self.port:
            print(f"{Colors.RED}❌ Não foi possível encontrar uma porta disponível{Colors.RESET}")
            return False

        # Mudar para o diretório do conteúdo web
        os.chdir('web_content')

        # Iniciar servidor em thread separada
        def run_server():
            handler = SimpleHTTPRequestHandler
            self.server = HTTPServer(('localhost', self.port), handler)
            print(f"{Colors.GREEN}✅ Servidor iniciado em http://localhost:{self.port}{Colors.RESET}")
            self.is_running = True
            self.server.serve_forever()

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        # Aguardar servidor iniciar
        time.sleep(2)
        return True

    def stop_server(self):
        """Para o servidor web"""
        if self.server:
            self.server.shutdown()
            self.is_running = False
            # Voltar ao diretório original
            os.chdir('..')
            print(f"{Colors.YELLOW}🛑 Servidor parado{Colors.RESET}")

class TerminalInterface:
    def __init__(self):
        self.web_server = WebServer()
        self.commands = {
            'start': self.cmd_start,
            'stop': self.cmd_stop,
            'status': self.cmd_status,
            'open': self.cmd_open,
            'config': self.cmd_config,
            'help': self.cmd_help,
            'exit': self.cmd_exit,
            'clear': self.cmd_clear
        }

    def print_banner(self):
        """Imprime o banner do sistema"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                   PDF COMPRESSOR TERMINAL                     ║
║                     SERVER LAUNCHER v1.0                      ║
║                                                                ║
║    Inicie seu servidor web local para compressão de PDFs      ║
╚════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)

    def print_help(self):
        """Mostra ajuda dos comandos"""
        help_text = f"""
{Colors.GREEN}{Colors.BOLD}COMANDOS DISPONÍVEIS:{Colors.RESET}

{Colors.YELLOW}start{Colors.RESET}    - Inicia o servidor web
{Colors.YELLOW}stop{Colors.RESET}     - Para o servidor web  
{Colors.YELLOW}status{Colors.RESET}   - Mostra status do servidor
{Colors.YELLOW}open{Colors.RESET}     - Abre no navegador
{Colors.YELLOW}config{Colors.RESET}   - Configurações do servidor
{Colors.YELLOW}clear{Colors.RESET}    - Limpa a tela
{Colors.YELLOW}help{Colors.RESET}     - Mostra esta ajuda
{Colors.YELLOW}exit{Colors.RESET}     - Sai do programa

{Colors.CYAN}Exemplo: {Colors.WHITE}start{Colors.RESET} → Inicia servidor na porta 8000
"""
        print(help_text)

    def cmd_start(self, args=None):
        """Comando para iniciar servidor"""
        if self.web_server.is_running:
            print(f"{Colors.YELLOW}⚠️  Servidor já está em execução{Colors.RESET}")
            return
        
        print(f"{Colors.BLUE}🚀 Iniciando servidor web...{Colors.RESET}")
        if self.web_server.start_server():
            url = f"http://localhost:{self.web_server.port}"
            print(f"{Colors.GREEN}✅ Servidor rodando em: {Colors.BOLD}{url}{Colors.RESET}")
            print(f"{Colors.CYAN}📁 Página: {Colors.WHITE}index.html{Colors.RESET}")
            print(f"{Colors.CYAN}🎨 CSS: {Colors.WHITE}style.css{Colors.RESET}")
            print(f"{Colors.CYAN}⚡ JavaScript: {Colors.WHITE}script.js{Colors.RESET}")
            print(f"{Colors.CYAN}🛑 Use 'stop' para parar o servidor{Colors.RESET}")
            print(f"{Colors.CYAN}🌐 Use 'open' para abrir no navegador{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Falha ao iniciar servidor{Colors.RESET}")

    def cmd_stop(self, args=None):
        """Comando para parar servidor"""
        if not self.web_server.is_running:
            print(f"{Colors.YELLOW}⚠️  Servidor não está em execução{Colors.RESET}")
            return
        
        self.web_server.stop_server()
        print(f"{Colors.GREEN}✅ Servidor parado com sucesso{Colors.RESET}")

    def cmd_status(self, args=None):
        """Comando para mostrar status"""
        if self.web_server.is_running:
            status = f"{Colors.GREEN}✅ ONLINE{Colors.RESET}"
            port_info = f"{Colors.CYAN}Porta: {Colors.WHITE}{self.web_server.port}{Colors.RESET}"
            url = f"{Colors.BLUE}URL: {Colors.WHITE}http://localhost:{self.web_server.port}{Colors.RESET}"
            print(f"Status: {status} | {port_info} | {url}")
        else:
            print(f"Status: {Colors.RED}❌ OFFLINE{Colors.RESET}")

    def cmd_open(self, args=None):
        """Comando para abrir no navegador"""
        if not self.web_server.is_running:
            print(f"{Colors.RED}❌ Servidor não está rodando. Use 'start' primeiro.{Colors.RESET}")
            return
        
        url = f"http://localhost:{self.web_server.port}"
        print(f"{Colors.BLUE}🌐 Abrindo {url} no navegador...{Colors.RESET}")
        webbrowser.open(url)

    def cmd_config(self, args=None):
        """Comando para mostrar configurações"""
        config_text = f"""
{Colors.CYAN}{Colors.BOLD}CONFIGURAÇÕES DO SERVIDOR:{Colors.RESET}

{Colors.YELLOW}Host:{Colors.RESET} {self.web_server.host}
{Colors.YELLOW}Porta:{Colors.RESET} {self.web_server.port}
{Colors.YELLOW}Status:{Colors.RESET} {'🟢 ONLINE' if self.web_server.is_running else '🔴 OFFLINE'}
{Colors.YELLOW}Arquivos:{Colors.RESET} index.html, style.css, script.js
{Colors.YELLOW}Descrição:{Colors.RESET} Servidor local para compressão de PDFs
"""
        print(config_text)

    def cmd_help(self, args=None):
        """Comando de ajuda"""
        self.print_help()

    def cmd_exit(self, args=None):
        """Comando para sair"""
        if self.web_server.is_running:
            self.web_server.stop_server()
        print(f"{Colors.CYAN}👋 Saindo... Até logo!{Colors.RESET}")
        sys.exit(0)

    def cmd_clear(self, args=None):
        """Comando para limpar tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()

    def run(self):
        """Loop principal do terminal"""
        self.print_banner()
        self.print_help()

        while True:
            try:
                # Prompt colorido
                prompt = f"{Colors.GREEN}pdf-compressor{Colors.WHITE}@{Colors.BLUE}terminal{Colors.WHITE}:{Colors.MAGENTA}~{Colors.WHITE}$ {Colors.RESET}"
                command = input(prompt).strip().split()
                
                if not command:
                    continue

                cmd = command[0].lower()
                args = command[1:] if len(command) > 1 else None

                if cmd in self.commands:
                    self.commands[cmd](args)
                else:
                    print(f"{Colors.RED}❌ Comando não encontrado: {cmd}{Colors.RESET}")
                    print(f"{Colors.YELLOW}💡 Use 'help' para ver comandos disponíveis{Colors.RESET}")

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}⚠️  Use 'exit' para sair do programa{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}❌ Erro: {str(e)}{Colors.RESET}")

def main():
    """Função principal"""
    try:
        terminal = TerminalInterface()
        terminal.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}👋 Programa interrompido pelo usuário{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Erro fatal: {str(e)}{Colors.RESET}")

if __name__ == "__main__":
    main()
