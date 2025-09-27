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
    
    # Lista de categorias e pacotes
    categories = {
        "📊 Interface e Cores": [
            "rich", "colorama", "pyfiglet", "termcolor", 
            "tqdm", "progress", "alive-progress"
        ],
        
        "🕵️‍♂️ OSINT e Reconhecimento": [
            "holehe", "sherlock", "twint", "social-analyzer",
            "maigret", "photon", "theHarvester", "recon-ng",
            "snscrape", "instagram-scraper", "twitter-scraper"
        ],
        
        "🌐 Requests e Web Scraping": [
            "requests", "requests[socks]", "bs4", "beautifulsoup4",
            "lxml", "html5lib", "scrapy", "selenium", "urllib3",
            "cloudscraper", "httpx", "aiohttp"
        ],
        
        "🔧 Utilitários Gerais": [
            "fake-useragent", "user-agents", "python-dotenv",
            "pyyaml", "click", "argparse", "pathlib"
        ],
        
        "🔒 Criptografia e Segurança": [
            "cryptography", "pycryptodome", "hashlib", "passlib",
            "bcrypt", "paramiko", "scapy", "impacket"
        ],
        
        "🗄️ Banco de Dados e Cache": [
            "redis", "pymongo", "sqlalchemy", "psycopg2-binary",
            "mysql-connector-python", "celery"
        ],
        
        "📧 Spam e Email": [
            "yagmail", "smtplib", "email-validator"
        ],
        
        "⚡ Ferramentas de Rede": [
            "sockets", "socket", "socks", "pysocks", "pydivert"
        ]
    }
    
    # Pacotes que podem ter problemas de instalação
    problematic_packages = {
        "impacket": "pip install impacket",
        "recon-ng": "pip install recon-ng",
        "theHarvester": "pip install theHarvester",
    }
    
    total_packages = sum(len(packages) for packages in categories.values())
    installed_count = 0
    
    print(f"📦 Total de pacotes a instalar: {total_packages}\n")
    
    for category, packages in categories.items():
        print(f"\n{category}")
        print("=" * 50)
        
        for package in packages:
            installed_count += 1
            progress = f"[{installed_count}/{total_packages}]"
            
            if package in problematic_packages:
                print(f"⚠️  {progress} {package} - Instalação manual recomendada")
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
            
            time.sleep(1)  # Pequena pausa entre instalações
    
    return installed_count

def install_specific_tools():
    """Instala ferramentas específicas que requerem abordagens diferentes"""
    
    tools = {
        "sherlock": "pip install sherlock-project",
        "holehe": "pip install holehe",
        "maigret": "pip install maigret",
        "social-analyzer": "pip install social-analyzer",
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

def post_installation_check():
    """Verifica as instalações após a conclusão"""
    
    print("\n🔍 Verificando instalações...")
    print("=" * 50)
    
    check_packages = [
        "requests", "rich", "colorama", "bs4", "selenium",
        "fake-useragent", "cryptography", "redis"
    ]
    
    for package in check_packages:
        try:
            subprocess.run(
                [sys.executable, "-c", f"import {package.split('[')[0]}; print('✅ {package} OK')"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError:
            print(f"❌ {package} - Falha na verificação")

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
    
    # Verificação final
    post_installation_check()
    
    # Mensagem final
    print("\n" + "=" * 60)
    print("🎉 INSTALAÇÃO CONCLUÍDA!")
    print("=" * 60)
    print(f"📦 Total de pacotes processados: {installed_count}")
    print("\n📚 Recursos instalados:")
    print("   • Ferramentas de OSINT (holehe, sherlock, etc.)")
    print("   • Bibliotecas de interface (rich, colorama, etc.)")
    print("   • Ferramentas de rede e segurança")
    print("   • Utilitários de scraping e automação")
    print("   • Bibliotecas de criptografia")
    print("\n⚠️  Algumas ferramentas podem requer configuração adicional.")
    print("📖 Consulte a documentação de cada ferramenta para uso correto.")
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
