#!/usr/bin/env python3
"""
Script de Instalação de Dependências para Ferramentas de Segurança - TERMUX
Autor: Security Toolbox
Descrição: Instala dependências para ferramentas de pentest no Termux
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

# Detectar se está no Termux
IS_TERMUX = "com.termux" in os.environ.get('PREFIX', '')

# Banner ASCII Art
BANNER = r"""
████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗███████╗
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║██╔════╝
   ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║███████╗
   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║╚════██║
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝███████║
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝
"""

def print_banner():
    """Exibe o banner personalizado"""
    os.system('clear')
    print("\033[1;32m")  # Cor verde
    print(BANNER)
    print("\033[0m")  # Reset cor
    print("📦 Instalação de Dependências para Termux")
    print("🔧 Otimizado para Android/Termux")
    if IS_TERMUX:
        print("✅ Executando no TERMUX")
    else:
        print("⚠️  Executando em outro ambiente")
    print("⏳ Isso pode levar vários minutos...\n")

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
        if IS_TERMUX:
            # No Termux, usar pkg para instalar pip
            subprocess.run(["pkg", "install", "-y", "python-pip"], 
                          check=True)
        else:
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
            timeout=600  # 10 minutos timeout para Termux
        )
        print(f"✅ {description} - Concluído!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao {description.lower()}")
        if e.stderr:
            error_msg = e.stderr[:200]
            if "memory" in error_msg.lower():
                print("   💡 Dica: Termux pode estar com pouca memória")
            elif "storage" in error_msg.lower() or "space" in error_msg.lower():
                print("   💡 Dica: Verifique o espaço em disco")
        return False
    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout ao {description.lower()}!")
        return False

def install_system_dependencies():
    """Instala dependências do sistema via pkg"""
    if not IS_TERMUX:
        return
    
    print("🔧 Instalando dependências do sistema Termux...")
    print("=" * 50)
    
    termux_packages = [
        "python", "python-pip", "git", "wget", "curl",
        "libxml2", "libxslt", "libjpeg-turbo", "openssl",
        "clang", "make", "pkg-config", "libffi", "zlib"
    ]
    
    for pkg in termux_packages:
        run_command(
            ["pkg", "install", "-y", pkg],
            f"Instalando {pkg}"
        )

def install_dependencies():
    """Instala todas as dependências Python"""
    
    # Categorias otimizadas para Termux
    categories = {
        "📊 Interface e Utilitários": [
            "rich", "colorama", "termcolor", "tqdm", 
            "progress", "alive-progress", "click", "pyyaml",
            "python-dotenv", "psutil", "watchdog"
        ],
        
        "🌐 Web e Scraping": [
            "requests", "requests[socks]", "bs4", "beautifulsoup4",
            "lxml", "html5lib", "urllib3", "cloudscraper",
            "httpx", "aiohttp", "fake-useragent", "user-agents"
        ],
        
        "🕵️‍♂️ OSINT Básico": [
            "holehe", "sherlock-project", "maigret", 
            "social-analyzer", "photon", "snscrape",
            "reverse-geocoder", "folium"
        ],
        
        "🔒 Segurança": [
            "cryptography", "pycryptodome", "passlib",
            "bcrypt", "paramiko", "scapy"
        ],
        
        "📊 Análise de Dados": [
            "pandas", "numpy", "matplotlib", "seaborn",
            "plotly", "openpyxl", "scipy"
        ],
        
        "📷 Processamento": [
            "pillow", "imageio", "pygame"
        ],
        
        "🗄️ Banco de Dados": [
            "redis", "pymongo", "sqlalchemy", "dataset",
            "peewee"
        ],
        
        "⚡ Desenvolvimento": [
            "flask", "jinja2", "werkzeug", "pygments",
            "pytest", "black", "flake8"
        ]
    }
    
    # Pacotes problemáticos no Termux - tentar métodos alternativos
    problematic_packages = {
        "opencv-python": "pip install opencv-python-headless",
        "scapy": "pip install scapy",
        "impacket": "pip install impacket",
        "twint": "pip install twint",
    }
    
    # Pacotes que geralmente falham no Termux
    termux_problematic = [
        "selenium", "scrapy", "celery", "opencv-python",
        "django", "fastapi", "gunicorn", "theHarvester",
        "recon-ng", "instagram-scraper", "twitter-scraper"
    ]
    
    total_packages = sum(len(packages) for packages in categories.values())
    installed_count = 0
    failed_packages = []
    
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
            
            # Verificar se é problemático no Termux
            if IS_TERMUX and package in termux_problematic:
                print(f"⚠️  {progress} {package} - Pular (problemático no Termux)")
                failed_packages.append(package)
                continue
            
            if package in problematic_packages:
                print(f"⚠️  {progress} {package} - Método especial")
                cmd = problematic_packages[package]
                cmd_parts = cmd.split()
                success = run_command(cmd_parts, f"{progress} Instalando {package}")
                if not success:
                    failed_packages.append(package)
                continue
            
            # Instalação normal
            pip_command = [
                sys.executable, "-m", "pip", "install", 
                "--no-cache-dir",  # Economizar espaço
                package
            ]
            
            success = run_command(pip_command, f"{progress} Instalando {package}")
            
            if not success:
                print(f"   Tentando instalação alternativa para {package}...")
                # Tentar sem dependências extras
                pip_command_alt = [
                    sys.executable, "-m", "pip", "install",
                    "--no-deps", package
                ]
                alt_success = run_command(pip_command_alt, f"{progress} Instalação alternativa")
                if not alt_success:
                    failed_packages.append(package)
            
            time.sleep(1)  # Pausa maior para Termux
    
    return installed_count, failed_packages

def install_lightweight_alternatives():
    """Instala versões leves de pacotes problemáticos"""
    
    lightweight_packages = {
        "opencv-python": "opencv-python-headless",
        "tensorflow": "tflite-runtime",
        "django": "flask",  # Alternativa mais leve
    }
    
    print("\n💡 Instalando alternativas leves...")
    print("=" * 50)
    
    for original, alternative in lightweight_packages.items():
        run_command(
            [sys.executable, "-m", "pip", "install", alternative],
            f"Instalando {alternative} (alternativa para {original})"
        )

def manual_installation_guide():
    """Exibe guia para instalação manual de pacotes problemáticos"""
    
    print("\n📚 GUIA DE INSTALAÇÃO MANUAL")
    print("=" * 60)
    
    manual_packages = {
        "selenium": {
            "description": "Necessita do Chrome/WebDriver",
            "commands": [
                "pkg install chromium-chromedriver",
                "pip install selenium"
            ],
            "notes": "Configurar PATH para chromedriver"
        },
        "scrapy": {
            "description": "Pode ter problemas de compilação",
            "commands": [
                "pkg install python rust",
                "pip install scrapy"
            ],
            "notes": "Pode requerer muita memória"
        },
        "theHarvester": {
            "description": "Melhor instalar via git",
            "commands": [
                "git clone https://github.com/laramies/theHarvester",
                "cd theHarvester && pip install -r requirements.txt"
            ],
            "notes": "Algumas dependências podem falhar"
        },
        "recon-ng": {
            "description": "Ferramenta completa de reconhecimento",
            "commands": [
                "git clone https://github.com/lanmaster53/recon-ng",
                "cd recon-ng && pip install -r REQUIREMENTS"
            ],
            "notes": "Requer várias dependências do sistema"
        },
        "instagram-scraper": {
            "description": "Problemas com dependências",
            "commands": [
                "pip install instagram-scraper --no-deps",
                "# Instalar dependências manualmente se necessário"
            ],
            "notes": "Pode não funcionar corretamente"
        }
    }
    
    for pkg, info in manual_packages.items():
        print(f"\n🔧 {pkg}")
        print(f"   📝 {info['description']}")
        print("   💻 Comandos:")
        for cmd in info['commands']:
            print(f"      {cmd}")
        print(f"   💡 {info['notes']}")

def post_installation_check():
    """Verifica as instalações após a conclusão"""
    
    print("\n🔍 Verificando instalações...")
    print("=" * 50)
    
    # Pacotes básicos para verificar
    check_packages = [
        "requests", "rich", "colorama", "bs4", 
        "fake-useragent", "cryptography", "pandas",
        "flask", "pillow", "psutil", "numpy"
    ]
    
    verified = []
    failed = []
    
    for package in check_packages:
        try:
            # Remover colchetes para verificação
            clean_package = package.split('[')[0]
            subprocess.run(
                [sys.executable, "-c", f"import {clean_package}"],
                check=True, capture_output=True, timeout=30
            )
            verified.append(package)
            print(f"✅ {clean_package} - OK")
        except subprocess.CalledProcessError:
            failed.append(package)
            print(f"❌ {package} - Falha")
        except subprocess.TimeoutExpired:
            failed.append(package)
            print(f"⏰ {package} - Timeout")
    
    return verified, failed

def create_requirements_file():
    """Cria um arquivo requirements.txt otimizado para Termux"""
    
    requirements = [
        "# Dependências para Termux - Security Tools",
        "# Gerado automaticamente",
        "",
        "# Core",
        "rich>=13.0.0",
        "colorama>=0.4.6",
        "termcolor>=2.3.0",
        "tqdm>=4.65.0",
        "",
        "# Web",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2", 
        "cloudscraper>=1.2.71",
        "httpx>=0.25.2",
        "fake-useragent>=1.4.0",
        "",
        "# OSINT",
        "holehe>=0.4.5",
        "sherlock-project>=0.14.0",
        "maigret>=0.5.0",
        "social-analyzer>=0.45",
        "",
        "# Security",
        "cryptography>=41.0.7",
        "pycryptodome>=3.19.0",
        "paramiko>=3.3.1",
        "",
        "# Data",
        "pandas>=2.1.3",
        "numpy>=1.25.2",
        "matplotlib>=3.8.2",
        "",
        "# Utilities", 
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "psutil>=5.9.6",
        "pillow>=10.1.0",
    ]
    
    filename = "requirements_termux.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(requirements))
    
    print(f"📄 Arquivo {filename} criado!")

def main():
    """Função principal"""
    
    # Exibir banner
    print_banner()
    
    # Instalar dependências do sistema no Termux
    if IS_TERMUX:
        install_system_dependencies()
    
    # Verificar e instalar pip
    if not check_pip():
        if not install_pip():
            print("❌ Não é possível continuar sem pip!")
            sys.exit(1)
    
    # Atualizar pip
    run_command(
        [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
        "Atualizando pip"
    )
    
    # Instalar dependências
    installed_count, failed_packages = install_dependencies()
    
    # Instalar alternativas leves
    install_lightweight_alternatives()
    
    # Verificação final
    verified, check_failed = post_installation_check()
    
    # Criar arquivo de requirements
    create_requirements_file()
    
    # Mensagem final detalhada
    print("\n" + "=" * 60)
    print("🎉 INSTALAÇÃO CONCLUÍDA!")
    print("=" * 60)
    print(f"📦 Pacotes processados: {installed_count}")
    print(f"✅ Verificados com sucesso: {len(verified)}")
    print(f"❌ Falhas na verificação: {len(check_failed)}")
    
    if failed_packages:
        print(f"⚠️  Pacotes problemáticos: {len(failed_packages)}")
    
    # Avisos importantes para Termux
    if IS_TERMUX:
        print("\n⚠️  AVISOS IMPORTANTES PARA TERMUX:")
        print("   • Algumas ferramentas podem não funcionar completamente")
        print("   • Selenium requer chromedriver (pode ser complexo)")
        print("   • Ferramentas pesadas podem travar o dispositivo")
        print("   • Sempre teste as ferramentas individualmente")
        
        print("\n📋 PACOTES RECOMENDADOS PARA INSTALAÇÃO MANUAL:")
        problematic_tools = ["selenium", "scrapy", "theHarvester", "recon-ng"]
        for tool in problematic_tools:
            print(f"   • {tool}")
    
    # Guia de instalação manual
    manual_installation_guide()
    
    # Dicas finais
    print("\n💡 DICAS FINAIS:")
    print("   1. Sempre faça backup dos seus dados")
    print("   2. Teste cada ferramenta individualmente") 
    print("   3. Considere usar um VPS para ferramentas pesadas")
    print("   4. Mantenho o Termux e pip atualizados")
    print("   5. Use 'pip install --user' para evitar problemas")
    
    print("\n🔧 PRÓXIMOS PASSOS:")
    print("   1. Execute 'python -c \"import nome_pacote\"' para testar")
    print("   2. Consulte a documentação de cada ferramenta")
    print("   3. Use o arquivo requirements_termux.txt para reinstalar")
    
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Instalação interrompida pelo usuário!")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Erro inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
