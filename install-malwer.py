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
        'lxml': 'lxml'  
    }

def install_termux_dependencies():
    console.print("[yellow]▶ Instalando dependências do Termux...[/yellow]")
    termux_pkgs = [
        'python', 'clang', 'libxml2', 'libxslt', 'openssl',
        'libffi', 'zlib', 'nmap', 'git'
    ]
    
    try:
        subprocess.run(['pkg', 'install', '-y'] + termux_pkgs, check=True)
        return True
    except Exception as e:
        console.print(f"[red]✗ Erro ao instalar pacotes Termux: {e}[/red]")
        return False

def install_python_packages():
    requirements = get_requirements()
    total = len(requirements)
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Instalando pacotes Python...", total=total)
        
        for pkg, install_name in requirements.items():
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
        except ImportError:
            console.print(f"[red]✗ {pkg: <15} [white]→ FALHA[/white]")
            all_ok = False
    
    return all_ok

def setup_directories():
    console.print("\n[yellow]▶ Configurando estrutura de diretórios...[/yellow]")
    dirs = ['OSINT', 'malwer', 'scanner', 'collected_data']
    
    for dir_name in dirs:
        try:
            os.makedirs(dir_name, exist_ok=True)
            console.print(f"[green]✓ Diretório {dir_name} criado/verificado")
        except Exception as e:
            console.print(f"[red]✗ Erro ao criar diretório {dir_name}: {e}[/red]")

def main():
    show_banner()
    

    is_termux = os.path.exists('/data/data/com.termux/files/usr')
    
    if is_termux:
        console.print("[bold green]▶ Ambiente Termux detectado[/bold green]")
        if not install_termux_dependencies():
            console.print("[red]✗ Falha ao instalar dependências do Termux[/red]")
            sys.exit(1)
    
  
    if not check_pip():
        console.print("[yellow]! Pip não encontrado[/yellow]")
        if not install_pip():
            console.print("[red]✗ Falha crítica: pip é necessário[/red]")
            sys.exit(1)
    
  
    install_python_packages()
    
  
    if not verify_installation():
        console.print("\n[bold yellow]! Algumas dependências falharam ao instalar[/bold yellow]")
        console.print("[yellow]Tente instalar manualmente com:[/yellow]")
        console.print("[white]pip install --user NOME_DO_PACOTE[/white]\n")
    else:
        console.print("\n[bold green]✓ Todas dependências verificadas com sucesso![/bold green]")
    
   
    setup_directories()
    

    console.print(Panel.fit(
        "[bold green]INSTALAÇÃO COMPLETA![/bold green]\n"
        "Você já pode executar os scripts normalmente.\n\n"
        "[yellow]Dica:[/yellow] Execute os scripts com python3 script.py",
        border_style="green"
    ))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Instalação cancelada pelo usuário[/red]")
        sys.exit(0)
