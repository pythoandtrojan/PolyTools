#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
from time import sleep
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

console = Console()

def show_banner():
    banner = """
[bold red]
 ██████╗ ███████╗██████╗ ███████╗██╗   ██╗██╗██████╗ 
██╔════╝ ██╔════╝██╔══██╗██╔════╝██║   ██║██║██╔══██╗
██║  ███╗█████╗  ██║  ██║█████╗  ██║   ██║██║██████╔╝
██║   ██║██╔══╝  ██║  ██║██╔══╝  ╚██╗ ██╔╝██║██╔═══╝ 
╚██████╔╝███████╗██████╔╝███████╗ ╚████╔╝ ██║██║     
 ╚═════╝ ╚══════╝╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝     
[/bold red]
[bold white on red] INSTALADOR DE DEPENDÊNCIAS PARA HACKER TOOLS [/bold white on red]
"""
    console.print(Panel.fit(banner, padding=(1, 2)))

def check_pip():
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'])
        return True
    except:
        return False

def install_pip():
    console.print("[yellow]▶ Instalando pip...[/yellow]")
    try:
        subprocess.check_call([sys.executable, '-m', 'ensurepip', '--upgrade'])
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        return True
    except Exception as e:
        console.print(f"[red]✗ Erro ao instalar pip: {e}[/red]")
        return False

def get_requirements():
    return {
        'rich': 'rich',
        'cryptography': 'cryptography',
        'pycryptodome': 'pycryptodomex',
        'pygments': 'pygments',
        'requests': 'requests',
        'socket': 'python-socketio',
        'webbrowser': 'pywebview',
        'scapy': 'scapy',  
        'python-nmap': 'python-nmap',  
        'beautifulsoup4': 'beautifulsoup4',  
        'lxml': 'lxml',
        'http.server': '',  # Parte da biblioteca padrão
        'urllib.parse': '',  # Parte da biblioteca padrão
        'typing': '',  # Parte da biblioteca padrão
        'datetime': '',  # Parte da biblioteca padrão
        'json': '',  # Parte da biblioteca padrão
        'base64': '',  # Parte da biblioteca padrão
        'hashlib': '',  # Parte da biblioteca padrão
        'zipfile': '',  # Parte da biblioteca padrão
        'tempfile': '',  # Parte da biblioteca padrão
        'shutil': '',  # Parte da biblioteca padrão
        'threading': '',  # Parte da biblioteca padrão
        'random': '',  # Parte da biblioteca padrão
        'socket': '',  # Parte da biblioteca padrão
        'subprocess': '',  # Parte da biblioteca padrão
        'time': '',  # Parte da biblioteca padrão
        'os': '',  # Parte da biblioteca padrão
        'sys': ''  # Parte da biblioteca padrão
    }

def install_termux_dependencies():
    console.print("[yellow]▶ Instalando dependências do Termux...[/yellow]")
    termux_pkgs = [
        'python', 'clang', 'libxml2', 'libxslt', 'openssl',
        'libffi', 'zlib', 'nmap', 'git', 'wget', 'curl',
        'proot', 'root-repo', 'unstable-repo', 'x11-repo'
    ]
    
    try:
        subprocess.run(['pkg', 'update', '-y'], check=True)
        subprocess.run(['pkg', 'install', '-y'] + termux_pkgs, check=True)
        return True
    except Exception as e:
        console.print(f"[red]✗ Erro ao instalar pacotes Termux: {e}[/red]")
        return False

def install_python_packages():
    requirements = get_requirements()
    total = len([pkg for pkg, install_name in requirements.items() if install_name])
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Instalando pacotes Python...", total=total)
        
        for pkg, install_name in requirements.items():
            if not install_name:  # Pular módulos da biblioteca padrão
                continue
                
            progress.update(task, description=f"[cyan]Instalando {pkg}...")
            
            try:
                subprocess.check_call(
                    [sys.executable, '-m', 'pip', 'install', '--user', install_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                progress.update(task, advance=1, description=f"[green]✓ {pkg} instalado")
            except Exception as e:
                progress.update(task, advance=1, description=f"[red]✗ Falha ao instalar {pkg}")
                console.print(f"[red]  Detalhes: {str(e)}[/red]")
            
            sleep(0.1)

def verify_installation():
    console.print("\n[yellow]▶ Verificando instalações...[/yellow]")
    requirements = get_requirements()
    all_ok = True
    
    for pkg in requirements.keys():
        try:
            __import__(pkg)
            console.print(f"[green]✓ {pkg: <15} [white]→ OK[/white]")
        except ImportError as e:
            # Verificar se é um módulo da biblioteca padrão que deveria estar disponível
            if not requirements[pkg]:  # Se é um módulo padrão (string vazia)
                console.print(f"[yellow]? {pkg: <15} [white]→ Módulo padrão (pode não estar disponível no Termux)[/white]")
            else:
                console.print(f"[red]✗ {pkg: <15} [white]→ FALHA: {e}[/white]")
                all_ok = False
    
    return all_ok

def setup_directories():
    console.print("\n[yellow]▶ Configurando estrutura de diretórios...[/yellow]")
    dirs = ['OSINT', 'malwer', 'scanner', 'collected_data', 'templates', 'dist', 'web_content']
    
    for dir_name in dirs:
        try:
            os.makedirs(dir_name, exist_ok=True)
            console.print(f"[green]✓ Diretório {dir_name} criado/verificado")
        except Exception as e:
            console.print(f"[red]✗ Erro ao criar diretório {dir_name}: {e}[/red]")

def install_additional_tools():
    console.print("\n[yellow]▶ Instalando ferramentas adicionais...[/yellow]")
    
    # Verificar e instalar ferramentas úteis
    tools = [
        {'name': 'nmap', 'test_cmd': ['nmap', '--version']},
        {'name': 'git', 'test_cmd': ['git', '--version']},
        {'name': 'wget', 'test_cmd': ['wget', '--version']},
        {'name': 'curl', 'test_cmd': ['curl', '--version']}
    ]
    
    for tool in tools:
        try:
            subprocess.run(tool['test_cmd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            console.print(f"[green]✓ {tool['name']} já está instalado")
        except:
            console.print(f"[yellow]! {tool['name']} não encontrado, tentando instalar...")
            try:
                subprocess.run(['pkg', 'install', '-y', tool['name']], check=True)
                console.print(f"[green]✓ {tool['name']} instalado com sucesso")
            except Exception as e:
                console.print(f"[red]✗ Falha ao instalar {tool['name']}: {e}[/red]")

def main():
    show_banner()
    
    # Verificar se estamos no Termux
    is_termux = os.path.exists('/data/data/com.termux/files/usr')
    
    if is_termux:
        console.print("[bold green]▶ Ambiente Termux detectado[/bold green]")
        if not install_termux_dependencies():
            console.print("[red]✗ Falha ao instalar dependências do Termux[/red]")
            sys.exit(1)
    
    # Verificar e instalar pip se necessário
    if not check_pip():
        console.print("[yellow]! Pip não encontrado[/yellow]")
        if not install_pip():
            console.print("[red]✗ Falha crítica: pip é necessário[/red]")
            sys.exit(1)
    
    # Instalar pacotes Python
    install_python_packages()
    
    # Instalar ferramentas adicionais se estiver no Termux
    if is_termux:
        install_additional_tools()
    
    # Verificar instalação
    if not verify_installation():
        console.print("\n[bold yellow]! Algumas dependências falharam ao instalar[/bold yellow]")
        console.print("[yellow]Tente instalar manualmente com:[/yellow]")
        console.print("[white]pip install --user NOME_DO_PACOTE[/white]\n")
    else:
        console.print("\n[bold green]✓ Todas dependências verificadas com sucesso![/bold green]")
    
    # Configurar diretórios
    setup_directories()
    
    # Mensagem final
    console.print(Panel.fit(
        "[bold green]INSTALAÇÃO COMPLETA![/bold green]\n"
        "Você já pode executar os scripts normalmente.\n\n"
        "[yellow]Scripts disponíveis:[/yellow]\n"
        "- Gerador de APKs maliciosos avançados\n"
        "- Ferramentas de phishing e engenharia social\n"
        "- Scanners de rede e vulnerabilidades\n\n"
        "[yellow]Dica:[/yellow] Execute os scripts com python3 script.py",
        border_style="green"
    ))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Instalação cancelada pelo usuário[/red]")
        sys.exit(0)
