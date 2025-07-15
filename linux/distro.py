#!/usr/bin/env python3
import os
import sys
import time
import webbrowser
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer

# Configurações globais
PORT = 8080
WEB_TIMEOUT = 300  # 5 minutos

# Cores para o terminal
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Banner estilizado
BANNER = f"""
{colors.RED}╔╦╗┬ ┬┌─┐┌─┐┬┌─  {colors.GREEN}┌─┐┌┬┐┌─┐┬─┐┌┬┐┌─┐┬─┐┬ ┬
{colors.RED} ║ ├─┤├─┤│  ├┴┐  {colors.GREEN}└─┐ │ ├─┤├┬┘ │ ├┤ ├┬┘└┬┘
{colors.RED} ╩ ┴ ┴┴ ┴└─┘┴ ┴  {colors.GREEN}└─┘ ┴ ┴ ┴┴└─ ┴ └─┘┴└─ ┴ 
{colors.CYAN}==================================================================
{colors.YELLOW}   Gerenciador Avançado de Distros Linux (Termux/Proot/NetHunter)
{colors.PURPLE}▶ Instalar ▶ Remover ▶ Atualizar ▶ Página Web Interativa
{colors.CYAN}==================================================================
{colors.END}"""

# Dados completos das 10 distribuições
DISTROS = {
    "Kali Linux (NetHunter)": {
        "install": "pkg install wget -y && wget -O install-nethunter-termux https://offs.ec/2MceZWr && chmod +x install-nethunter-termux && ./install-nethunter-termux",
        "remove": "rm -rf ~/kali-fs ~/kali-binds ~/start-kali.sh",
        "update": "apt update && apt full-upgrade -y",
        "descricao": "Distribuição líder em segurança cibernética e pentesting.",
        "simbolo": "🐉",
        "significado": "Dragão representa ferramentas poderosas de hacking",
        "requires_root": True
    },
    "Ubuntu": {
        "install": "pkg install proot-distro -y && proot-distro install ubuntu",
        "remove": "proot-distro remove ubuntu",
        "update": "proot-distro login ubuntu -- apt update && apt upgrade -y",
        "descricao": "Distro popular baseada em Debian para uso geral.",
        "simbolo": "🦬",
        "significado": "Búfalo simboliza comunidade e força",
        "requires_root": False
    },
    "Debian": {
        "install": "pkg install proot-distro -y && proot-distro install debian",
        "remove": "proot-distro remove debian",
        "update": "proot-distro login debian -- apt update && apt upgrade -y",
        "descricao": "Base estável para muitas distribuições Linux.",
        "simbolo": "🌀",
        "significado": "Espiral representa estabilidade e confiabilidade",
        "requires_root": False
    },
    "Arch Linux": {
        "install": "pkg install proot-distro -y && proot-distro install archlinux",
        "remove": "proot-distro remove archlinux",
        "update": "proot-distro login archlinux -- pacman -Syu --noconfirm",
        "descricao": "Distro rolling-release para usuários avançados.",
        "simbolo": "⛰️",
        "significado": "Montanha representa desafio técnico",
        "requires_root": False
    },
    "Fedora": {
        "install": "pkg install proot-distro -y && proot-distro install fedora",
        "remove": "proot-distro remove fedora",
        "update": "proot-distro login fedora -- dnf upgrade -y",
        "descricao": "Distro com tecnologias de ponta da Red Hat.",
        "simbolo": "🎩",
        "significado": "Chapéu referencia o Red Hat",
        "requires_root": False
    },
    "Alpine Linux": {
        "install": "pkg install proot-distro -y && proot-distro install alpine",
        "remove": "proot-distro remove alpine",
        "update": "proot-distro login alpine -- apk update && apk upgrade",
        "descricao": "Distro ultra-leve focada em segurança e containers.",
        "simbolo": "🏔️",
        "significado": "Montanha alpina representa leveza",
        "requires_root": False
    },
    "OpenSUSE": {
        "install": "pkg install proot-distro -y && proot-distro install opensuse",
        "remove": "proot-distro remove opensuse",
        "update": "proot-distro login opensuse -- zypper update -y",
        "descricao": "Distro poderosa com ferramentas de sysadmin avançadas.",
        "simbolo": "🦎",
        "significado": "Camaleão representa adaptabilidade",
        "requires_root": False
    },
    "Parrot OS": {
        "install": "pkg install wget -y && wget -qO- https://raw.githubusercontent.com/ParrotSec/parrot-installer/main/termux/install.sh | bash",
        "remove": "rm -rf ~/parrot-fs ~/parrot-binds ~/start-parrot.sh",
        "update": "apt update && apt full-upgrade -y",
        "descricao": "Distro de segurança com foco em privacidade e anonimato.",
        "simbolo": "🦜",
        "significado": "Papagaio representa liberdade digital",
        "requires_root": True
    },
    "Gentoo": {
        "install": "pkg install proot-distro -y && proot-distro install gentoo",
        "remove": "proot-distro remove gentoo",
        "update": "proot-distro login gentoo -- emerge --sync && emerge -uDU @world",
        "descricao": "Distro onde tudo é compilado do código-fonte.",
        "simbolo": "🦬",
        "significado": "Búfalo representa resistência",
        "requires_root": False
    },
    "Manjaro": {
        "install": "pkg install proot-distro -y && proot-distro install manjaro-aarch64",
        "remove": "proot-distro remove manjaro-aarch64",
        "update": "proot-distro login manjaro-aarch64 -- pacman -Syu --noconfirm",
        "descricao": "Arch Linux simplificada para iniciantes.",
        "simbolo": "🦎",
        "significado": "Lagarto representa adaptabilidade",
        "requires_root": False
    }
}

# Servidor Web
class WebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.getcwd(), **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.path = '/distros.html'
        return super().do_GET()

def start_web_server():
    generate_web_page()
    server = HTTPServer(('localhost', PORT), WebHandler)
    print(f"\n{colors.GREEN}[+] Servidor web iniciado: http://localhost:{PORT}{colors.END}")
    print(f"{colors.YELLOW}[!] Pressione Ctrl+C no terminal para parar o servidor{colors.END}")
    
    def server_thread():
        server.serve_forever()
    
    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    
    try:
        webbrowser.open(f"http://localhost:{PORT}")
        time.sleep(WEB_TIMEOUT)
    except:
        pass
    finally:
        server.shutdown()

def generate_web_page():
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciador de Distros Linux</title>
    <style>
        :root {{
            --primary: #2c3e50;
            --secondary: #3498db;
            --accent: #e74c3c;
            --light: #ecf0f1;
            --dark: #1a252f;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: var(--dark);
            line-height: 1.6;
            padding: 20px;
        }}
        header {{
            background: var(--primary);
            color: white;
            padding: 2rem;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        .distro-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 1.5rem;
            padding: 1rem;
        }}
        .distro-card {{
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }}
        .distro-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
        }}
        .distro-header {{
            background: var(--secondary);
            color: white;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .distro-symbol {{
            font-size: 2.5rem;
            flex-shrink: 0;
        }}
        .distro-title {{
            font-size: 1.5rem;
            font-weight: bold;
        }}
        .distro-body {{
            padding: 1.5rem;
        }}
        .distro-description {{
            margin-bottom: 1rem;
            color: #555;
        }}
        .distro-command {{
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            font-family: monospace;
            margin-bottom: 1rem;
            overflow-x: auto;
        }}
        .meaning {{
            background: #e8f4fc;
            padding: 1rem;
            border-radius: 5px;
            border-left: 4px solid var(--secondary);
            font-style: italic;
        }}
        .badge {{
            display: inline-block;
            background: var(--accent);
            color: white;
            padding: 0.3rem 0.6rem;
            border-radius: 20px;
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }}
        footer {{
            text-align: center;
            margin-top: 2rem;
            padding: 1.5rem;
            color: #666;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .tab-buttons {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .tab-button {{
            padding: 0.5rem 1rem;
            background: var(--secondary);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        .tab-button.active {{
            background: var(--primary);
        }}
        @media (max-width: 768px) {{
            .distro-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>🐧 Gerenciador de Distros Linux</h1>
        <p class="subtitle">Instale, remova ou atualize distribuições no Termux</p>
    </header>

    <div class="tab-buttons">
        <button class="tab-button active" data-tab="info">Informações</button>
        <button class="tab-button" data-tab="commands">Comandos</button>
    </div>

    <div id="info" class="tab-content active">
        <div class="distro-grid">
            {''.join([f"""
            <div class="distro-card">
                <div class="distro-header">
                    <div class="distro-symbol">{data['simbolo']}</div>
                    <div class="distro-title">{name}</div>
                </div>
                <div class="distro-body">
                    <p class="distro-description">{data['descricao']}</p>
                    <div class="meaning">
                        <strong>{data['simbolo']} Significado:</strong> {data['significado']}
                    </div>
                    {'''<div class="badge">Requer Root</div>''' if data['requires_root'] else ''}
                </div>
            </div>
            """ for name, data in DISTROS.items()])}
        </div>
    </div>

    <div id="commands" class="tab-content">
        <div class="distro-grid">
            {''.join([f"""
            <div class="distro-card">
                <div class="distro-header">
                    <div class="distro-symbol">{data['simbolo']}</div>
                    <div class="distro-title">{name}</div>
                </div>
                <div class="distro-body">
                    <h3>Instalação:</h3>
                    <div class="distro-command">{data['install']}</div>
                    
                    <h3>Remoção:</h3>
                    <div class="distro-command">{data['remove']}</div>
                    
                    <h3>Atualização:</h3>
                    <div class="distro-command">{data['update']}</div>
                </div>
            </div>
            """ for name, data in DISTROS.items()])}
        </div>
    </div>

    <footer>
        <p>🛠️ Gerado automaticamente pelo LinuxDistroManager</p>
        <p>⏰ Última atualização: {time.strftime("%d/%m/%Y %H:%M:%S")}</p>
    </footer>

    <script>
        // Sistema de tabs
        document.querySelectorAll('.tab-button').forEach(button => {{
            button.addEventListener('click', () => {{
                const tabName = button.getAttribute('data-tab');
                
                // Esconde todos os conteúdos
                document.querySelectorAll('.tab-content').forEach(content => {{
                    content.classList.remove('active');
                }});
                
                // Desativa todos os botões
                document.querySelectorAll('.tab-button').forEach(btn => {{
                    btn.classList.remove('active');
                }});
                
                // Ativa o selecionado
                document.getElementById(tabName).classList.add('active');
                button.classList.add('active');
            }});
        }});

        // Animação de entrada
        document.addEventListener('DOMContentLoaded', () => {{
            const cards = document.querySelectorAll('.distro-card');
            cards.forEach((card, index) => {{
                setTimeout(() => {{
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }}, index * 100);
            }});
        }});
    </script>
</body>
</html>
    """
    
    with open("distros.html", "w") as f:
        f.write(html)

# Funções de gerenciamento
def install_distro(name):
    distro = DISTROS[name]
    print(f"\n{colors.YELLOW}[*] Iniciando instalação do {name}...{colors.END}")
    
    if distro["requires_root"] and not os.geteuid() == 0:
        print(f"{colors.RED}[ERRO] Esta distro requer root! Use 'sudo' ou 'su'{colors.END}")
        return False
    
    try:
        for cmd in distro["install"].split(" && "):
            print(f"{colors.BLUE}[+] Executando: {cmd}{colors.END}")
            result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                print(f"{colors.RED}[ERRO] Falha no comando: {result.stderr}{colors.END}")
                return False
            
            time.sleep(1)
        
        print(f"{colors.GREEN}[✔] {name} instalado com sucesso!{colors.END}")
        return True
    except Exception as e:
        print(f"{colors.RED}[ERRO] Falha na instalação: {str(e)}{colors.END}")
        return False

def remove_distro(name):
    distro = DISTROS[name]
    print(f"\n{colors.YELLOW}[*] Iniciando remoção do {name}...{colors.END}")
    
    if distro["requires_root"] and not os.geteuid() == 0:
        print(f"{colors.RED}[ERRO] Esta distro requer root! Use 'sudo' ou 'su'{colors.END}")
        return False
    
    try:
        for cmd in distro["remove"].split(" && "):
            print(f"{colors.BLUE}[+] Executando: {cmd}{colors.END}")
            result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                print(f"{colors.RED}[ERRO] Falha no comando: {result.stderr}{colors.END}")
                return False
            
            time.sleep(1)
        
        print(f"{colors.GREEN}[✔] {name} removido com sucesso!{colors.END}")
        return True
    except Exception as e:
        print(f"{colors.RED}[ERRO] Falha na remoção: {str(e)}{colors.END}")
        return False

def update_distro(name):
    distro = DISTROS[name]
    print(f"\n{colors.YELLOW}[*] Iniciando atualização do {name}...{colors.END}")
    
    if distro["requires_root"] and not os.geteuid() == 0:
        print(f"{colors.RED}[ERRO] Esta distro requer root! Use 'sudo' ou 'su'{colors.END}")
        return False
    
    try:
        for cmd in distro["update"].split(" && "):
            print(f"{colors.BLUE}[+] Executando: {cmd}{colors.END}")
            result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                print(f"{colors.RED}[ERRO] Falha no comando: {result.stderr}{colors.END}")
                return False
            
            time.sleep(1)
        
        print(f"{colors.GREEN}[✔] {name} atualizado com sucesso!{colors.END}")
        return True
    except Exception as e:
        print(f"{colors.RED}[ERRO] Falha na atualização: {str(e)}{colors.END}")
        return False

# Menu principal
def main_menu():
    while True:
        limpar_tela()
        print(BANNER)
        
        # Lista de distros
        print(f"\n{colors.BOLD}Distribuições disponíveis:{colors.END}")
        for i, (name, data) in enumerate(DISTROS.items(), 1):
            root_flag = f"{colors.RED} (root){colors.END}" if data["requires_root"] else ""
            print(f"{colors.CYAN}{i:2}. {name.ljust(22)}{data['simbolo']}{root_flag}{colors.END}")
        
        # Opções gerais
        print(f"\n{colors.PURPLE}I. Instalar Distro       R. Remover Distro")
        print(f"U. Atualizar Distro     W. Abrir Guia Web")
        print(f"{colors.RED}0. Sair{colors.END}")
        
        choice = input(f"\n{colors.YELLOW}Escolha uma opção: {colors.END}").strip().upper()
        
        try:
            if choice == "0":
                sys.exit(0)
            elif choice == "W":
                start_web_server()
                input(f"\n{colors.GREEN}Pressione Enter para continuar...{colors.END}")
            elif choice in ["I", "R", "U"]:
                action = {
                    "I": ("Instalar", install_distro),
                    "R": ("Remover", remove_distro),
                    "U": ("Atualizar", update_distro)
                }[choice]
                
                distro_num = input(f"{colors.YELLOW}Número da distro para {action[0]}: {colors.END}").strip()
                if distro_num.isdigit() and 1 <= int(distro_num) <= len(DISTROS):
                    distro_name = list(DISTROS.keys())[int(distro_num)-1]
                    if action[1](distro_name):
                        time.sleep(2)
                else:
                    print(f"{colors.RED}Número inválido!{colors.END}")
                    time.sleep(1)
            else:
                print(f"{colors.RED}Opção inválida!{colors.END}")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{colors.RED}Operação cancelada pelo usuário{colors.END}")
            time.sleep(1)
        except Exception as e:
            print(f"{colors.RED}Erro: {str(e)}{colors.END}")
            time.sleep(2)

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    try:
        # Verifica dependências básicas
        if not subprocess.run("command -v proot-distro", shell=True, capture_output=True).returncode == 0:
            print(f"{colors.YELLOW}[!] Instalando proot-distro...{colors.END}")
            subprocess.run("pkg install proot-distro -y", shell=True, check=True)
        
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{colors.RED}Script encerrado pelo usuário{colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{colors.RED}Erro crítico: {str(e)}{colors.END}")
        sys.exit(1)
