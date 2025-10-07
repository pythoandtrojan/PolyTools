#!/usr/bin/env python3
"""
Script de Instalação de Dependências para Ferramentas de Segurança
Autor: Security Toolbox
Descrição: Instala todas as dependências necessárias para ferramentas de pentest
"""

import os
import sys
import time
import subprocess
import platform
from typing import List, Dict

# Verificar se estamos no Python correto
if sys.version_info < (3, 6):
    print("❌ Python 3.6 ou superior é necessário!")
    sys.exit(1)

# Banner ASCII Art
BANNER = r"""
██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
"""

def print_banner():
    """Exibe o banner personalizado"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[1;32m")  # Cor verde
    print(BANNER)
    print("\033[0m")  # Reset cor
    print("📦 Iniciando instalação de dependências...")
    print("⏳ Isso pode levar alguns minutos...\n")

def check_pip():
    """Verifica se pip está instalado"""
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def install_pip():
    """Instala o pip se não estiver disponível"""
    print("🔧 Instalando pip...")
    try:
        subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], 
                      check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        print("❌ Falha ao instalar pip!")
        return False

def run_command(command: List[str], description: str) -> bool:
    """Executa um comando com tratamento de erro"""
    print(f"📥 {description}...")
    
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos timeout
        )
        print(f"✅ {description} - Concluído!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao {description.lower()}: {e}")
        if e.stderr:
            print(f"   Detalhes: {e.stderr[:200]}...")
        return False
    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout ao {description.lower()}!")
        return False

def install_dependencies():
    """Instala todas as dependências"""
    
    # Lista de categorias e pacotes atualizada
    categories = {
        "📊 Interface e Cores": [
            "rich", "colorama", "pyfiglet", "termcolor", 
            "tqdm", "progress", "alive-progress"
        ],
        
        "🕵️‍♂️ OSINT e Reconhecimento": [
            "holehe", "sherlock", "twint", "social-analyzer",
            "maigret", "photon", "theHarvester", "recon-ng",
            "snscrape", "instagram-scraper", "twitter-scraper",
            "instaloader", "reverse-geocoder", "folium"
        ],
        
        "🌐 Requests e Web Scraping": [
            "requests", "requests[socks]", "bs4", "beautifulsoup4",
            "lxml", "html5lib", "scrapy", "selenium", "urllib3",
            "cloudscraper", "httpx", "aiohttp"
        ],
        
        "🔧 Utilitários Gerais": [
            "fake-useragent", "user-agents", "python-dotenv",
            "pyyaml", "click", "argparse", "pathlib", "mechanize",
            "psutil", "uuid", "python-dateutil", "watchdog"
        ],
        
        "🔒 Criptografia e Segurança": [
            "cryptography", "pycryptodome", "hashlib", "passlib",
            "bcrypt", "paramiko", "scapy", "impacket"
        ],
        
        "🗄️ Banco de Dados e Cache": [
            "redis", "pymongo", "sqlalchemy", "psycopg2-binary",
            "mysql-connector-python", "celery", "dataset", "peewee"
        ],
        
        "📧 Spam e Email": [
            "yagmail", "smtplib", "email-validator"
        ],
        
        "⚡ Ferramentas de Rede": [
            "sockets", "socket", "socks", "pysocks", "pydivert",
            "netifaces", "pyroute2", "scapy"
        ],
        
        "📷 Processamento de Imagens": [
            "pillow", "opencv-python", "imageio", "matplotlib",
            "scikit-image", "pygame"
        ],
        
        "📈 Análise de Dados": [
            "pandas", "numpy", "scipy", "matplotlib", "seaborn",
            "plotly", "bokeh", "jupyter", "openpyxl"
        ],
        
        "🌐 Desenvolvimento Web": [
            "flask", "flask-socketio", "flask-sqlalchemy", "django",
            "fastapi", "uvicorn", "jinja2", "werkzeug", "gunicorn"
        ],
        
        "🔍 Processamento e Utilitários Avançados": [
            "regex", "pygments", "pytest", "black", "flake8",
            "mypy", "pylint", "pre-commit", "faker", "factory-boy"
        ],
        
        "🧮 Matemática e Ciência": [
            "numpy", "scipy", "sympy", "pandas", "statistics"
        ]
    }
    
    # Pacotes que podem ter problemas de instalação
    problematic_packages = {
        "impacket": "pip install impacket",
        "recon-ng": "pip install recon-ng",
        "theHarvester": "pip install theHarvester",
        "opencv-python": "pip install opencv-python",
        "twint": "pip install --user --upgrade git+https://github.com/twintproject/twint.git@origin/master#egg=twint",
    }
    
    total_packages = sum(len(packages) for packages in categories.values())
    installed_count = 0
    
    print(f"📦 Total de pacotes a instalar: {total_packages}\n")
    
    for category, packages in categories.items():
        print(f"\n{category}")
        print("=" * 50)
        
        for package in packages:
            # Pular pacotes duplicados
            if installed_count > 0 and package in [p for cat in categories.values() for p in cat][:installed_count]:
                continue
                
            installed_count += 1
            progress = f"[{installed_count}/{total_packages}]"
            
            if package in problematic_packages:
                print(f"⚠️  {progress} {package} - Instalação especial necessária")
                cmd = problematic_packages[package]
                cmd_parts = cmd.split()
                run_command(cmd_parts, f"{progress} Instalando {package} (método especial)")
                continue
            
            success = run_command(
                [sys.executable, "-m", "pip", "install", package, "--upgrade"],
                f"{progress} Instalando {package}"
            )
            
            if not success:
                print(f"   Tentando instalação alternativa para {package}...")
                # Tentativa alternativa sem upgrade
                run_command(
                    [sys.executable, "-m", "pip", "install", package],
                    f"{progress} Instalação alternativa de {package}"
                )
            
            time.sleep(0.5)  # Pequena pausa entre instalações
    
    return installed_count

def install_specific_tools():
    """Instala ferramentas específicas que requerem abordagens diferentes"""
    
    tools = {
        "sherlock": "pip install sherlock-project",
        "holehe": "pip install holehe",
        "maigret": "pip install maigret",
        "social-analyzer": "pip install social-analyzer",
        "reverse-geocoder": "pip install reverse-geocoder",
        "folium": "pip install folium",
        "flask-socketio": "pip install flask-socketio",
        "opencv-python": "pip install opencv-python-headless",  # Versão mais leve
    }
    
    print("\n🔧 Instalando ferramentas específicas...")
    print("=" * 50)
    
    for tool, command in tools.items():
        cmd_parts = command.split()
        success = run_command(cmd_parts, f"Instalando {tool}")
        
        if not success:
            print(f"   Tentando instalação direta do {tool}...")
            run_command(
                [sys.executable, "-m", "pip", "install", tool],
                f"Instalação direta de {tool}"
            )

def install_system_specific():
    """Instala pacotes específicos do sistema operacional"""
    
    system = platform.system().lower()
    
    print(f"\n💻 Instalando dependências específicas do {system}...")
    print("=" * 50)
    
    if system == "linux":
        linux_packages = [
            "python3-dev", "build-essential", "libssl-dev", 
            "libffi-dev", "libxml2-dev", "libxslt1-dev",
            "libjpeg-dev", "zlib1g-dev", "libnetfilter-queue-dev"
        ]
        
        # Detectar gerenciador de pacotes
        if os.path.exists("/etc/debian_version"):
            # Debian/Ubuntu
            run_command(
                ["sudo", "apt", "update"],
                "Atualizando repositórios APT"
            )
            for pkg in linux_packages:
                run_command(
                    ["sudo", "apt", "install", "-y", pkg],
                    f"Instalando {pkg}"
                )
        elif os.path.exists("/etc/redhat-release"):
            # RedHat/CentOS
            for pkg in linux_packages:
                run_command(
                    ["sudo", "yum", "install", "-y", pkg],
                    f"Instalando {pkg}"
                )
    
    elif system == "windows":
        print("📝 No Windows, certifique-se de ter o Microsoft C++ Build Tools instalado")
    
    elif system == "darwin":  # macOS
        run_command(
            ["brew", "install", "libmagic", "geoip", "imagesnap"],
            "Instalando dependências via Homebrew"
        )

def post_installation_check():
    """Verifica as instalações após a conclusão"""
    
    print("\n🔍 Verificando instalações...")
    print("=" * 50)
    
    check_packages = [
        "requests", "rich", "colorama", "bs4", "selenium",
        "fake-useragent", "cryptography", "redis", "pandas",
        "flask", "pillow", "folium", "psutil", "numpy"
    ]
    
    for package in check_packages:
        try:
            # Remover colchetes para verificação
            clean_package = package.split('[')[0]
            subprocess.run(
                [sys.executable, "-c", f"import {clean_package}; print('✅ {clean_package} OK')"],
                check=True, capture_output=True, timeout=10
            )
        except subprocess.CalledProcessError:
            print(f"❌ {package} - Falha na verificação")
        except subprocess.TimeoutExpired:
            print(f"⏰ {package} - Timeout na verificação")

def create_requirements_file():
    """Cria um arquivo requirements.txt com todas as dependências"""
    
    requirements = [
        "# Dependências para Ferramentas de Segurança",
        "# Gerado automaticamente pelo script de instalação",
        "",
        "# Interface e Cores",
        "rich>=13.0.0",
        "colorama>=0.4.6",
        "pyfiglet>=0.8.post1",
        "termcolor>=2.3.0",
        "tqdm>=4.65.0",
        "alive-progress>=3.1.4",
        "",
        "# OSINT e Reconhecimento", 
        "holehe>=0.4.5",
        "sherlock-project>=0.14.0",
        "social-analyzer>=0.45",
        "maigret>=0.5.0",
        "theHarvester>=4.4.0",
        "reverse-geocoder>=1.5.1",
        "folium>=0.14.0",
        "",
        "# Web Scraping",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "selenium>=4.15.0",
        "cloudscraper>=1.2.71",
        "httpx>=0.25.2",
        "aiohttp>=3.9.1",
        "",
        "# Utilitários Gerais",
        "fake-useragent>=1.4.0",
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "psutil>=5.9.6",
        "python-dateutil>=2.8.2",
        "",
        "# Segurança e Criptografia",
        "cryptography>=41.0.7",
        "pycryptodome>=3.19.0",
        "paramiko>=3.3.1",
        "scapy>=2.5.0",
        "",
        "# Análise de Dados",
        "pandas>=2.1.3",
        "numpy>=1.25.2",
        "matplotlib>=3.8.2",
        "seaborn>=0.13.0",
        "",
        "# Desenvolvimento Web",
        "flask>=3.0.0",
        "flask-socketio>=5.3.6",
        "jinja2>=3.1.2",
        "",
        "# Processamento de Imagens",
        "pillow>=10.1.0",
        "opencv-python-headless>=4.8.1",
        "",
        "# Banco de Dados",
        "sqlalchemy>=2.0.23",
        "pymongo>=4.5.0",
        "redis>=5.0.1",
    ]
    
    with open("requirements_security.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(requirements))
    
    print("📄 Arquivo requirements_security.txt criado!")

def main():
    """Função principal"""
    
    # Exibir banner
    print_banner()
    
    # Verificar e instalar pip
    if not check_pip():
        if not install_pip():
            print("❌ Não é possível continuar sem pip!")
            sys.exit(1)
    
    # Atualizar pip primeiro
    run_command(
        [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
        "Atualizando pip"
    )
    
    # Instalar dependências
    installed_count = install_dependencies()
    
    # Instalar ferramentas específicas
    install_specific_tools()
    
    # Instalar dependências do sistema
    install_system_specific()
    
    # Verificação final
    post_installation_check()
    
    # Criar arquivo de requirements
    create_requirements_file()
    
    # Mensagem final
    print("\n" + "=" * 60)
    print("🎉 INSTALAÇÃO CONCLUÍDA!")
    print("=" * 60)
    print(f"📦 Total de pacotes processados: {installed_count}")
    print("\n📚 Principais categorias instaladas:")
    print("   • Ferramentas de OSINT (holehe, sherlock, maigret, etc.)")
    print("   • Bibliotecas de interface (rich, colorama, etc.)")
    print("   • Ferramentas de rede e segurança (scapy, cryptography)")
    print("   • Utilitários de scraping e automação (selenium, requests)")
    print("   • Análise de dados (pandas, numpy, matplotlib)")
    print("   • Desenvolvimento web (flask, flask-socketio)")
    print("   • Processamento de imagens (pillow, opencv)")
    print("   • Sistema e utilitários (psutil, platform, socket)")
    print("\n⚠️  Algumas ferramentas podem requer configuração adicional.")
    print("📖 Consulte a documentação de cada ferramenta para uso correto.")
    print("📄 Arquivo requirements_security.txt gerado para uso futuro.")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Instalação interrompida pelo usuário!")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Erro inesperado: {e}")
        sys.exit(1)
