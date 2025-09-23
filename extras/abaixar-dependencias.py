#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform
from time import sleep
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.prompt import Confirm, Prompt

console = Console()

def show_banner():
    banner = """
[bold red]
██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
                                                           
[/bold red]
[bold white on red] INSTALADOR UNIVERSAL DE DEPENDÊNCIAS HACKER [/bold white on red]
"""
    console.print(Panel.fit(banner, padding=(1, 2)))

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def check_pip():
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def install_pip():
    console.print("[yellow]▶ Instalando/Atualizando pip...[/yellow]")
    try:
        if os.path.exists('/data/data/com.termux/files/usr'):
            subprocess.run(['pkg', 'install', '-y', 'python-pip'], check=True)
        else:
            subprocess.check_call([sys.executable, '-m', 'ensurepip', '--upgrade'])
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        return True
    except Exception as e:
        console.print(f"[red]✗ Erro ao instalar pip: {e}[/red]")
        return False

def get_all_dependencies():
    return {
        # Ferramentas de rede e scanning
        'nmap': {'type': 'system', 'termux': 'nmap', 'linux': 'nmap'},
        'sqlmap': {'type': 'python', 'package': 'sqlmap'},
        'hydra': {'type': 'system', 'termux': 'hydra', 'linux': 'hydra'},
        
        # OSINT e reconhecimento
        'sherlock': {'type': 'python', 'package': 'sherlock-project'},
        'theHarvester': {'type': 'python', 'package': 'theharvester'},
        'recon-ng': {'type': 'python', 'package': 'recon-ng'},
        
        # Web hacking
        'requests': {'type': 'python', 'package': 'requests'},
        'flask': {'type': 'python', 'package': 'flask'},
        'django': {'type': 'python', 'package': 'django'},
        'beautifulsoup4': {'type': 'python', 'package': 'beautifulsoup4'},
        'lxml': {'type': 'python', 'package': 'lxml'},
        'selenium': {'type': 'python', 'package': 'selenium'},
        'scrapy': {'type': 'python', 'package': 'scrapy'},
        'urllib3': {'type': 'python', 'package': 'urllib3'},
        
        # Cryptografia
        'cryptography': {'type': 'python', 'package': 'cryptography'},
        'pycryptodome': {'type': 'python', 'package': 'pycryptodomex'},
        'pycrypto': {'type': 'python', 'package': 'pycrypto'},
        
        # Wi-Fi hacking
        'scapy': {'type': 'python', 'package': 'scapy'},
        'pywifi': {'type': 'python', 'package': 'pywifi'},
        
        # Bluetooth
        'pybluez': {'type': 'python', 'package': 'pybluez'},
        'lightblue': {'type': 'python', 'package': 'lightblue'},
        
        # Força bruta
        'paramiko': {'type': 'python', 'package': 'paramiko'},
        'ftplib': {'type': 'python', 'package': ''},  # Built-in
        'pexpect': {'type': 'python', 'package': 'pexpect'},
        
        # DDoS/DoS
        'socket': {'type': 'python', 'package': ''},  # Built-in
        'threading': {'type': 'python', 'package': ''},  # Built-in
        'multiprocessing': {'type': 'python', 'package': ''},  # Built-in
        
        # APIs e automação
        'python-nmap': {'type': 'python', 'package': 'python-nmap'},
        'shodan': {'type': 'python', 'package': 'shodan'},
        'censys': {'type': 'python', 'package': 'censys'},
        
        # Utilitários gerais
        'rich': {'type': 'python', 'package': 'rich'},
        'colorama': {'type': 'python', 'package': 'colorama'},
        'progress': {'type': 'python', 'package': 'progress'},
        'pyfiglet': {'type': 'python', 'package': 'pyfiglet'},
        
        # Segurança e anonimato
        'tor': {'type': 'system', 'termux': 'tor', 'linux': 'tor'},
        'proxychains': {'type': 'system', 'termux': 'proxychains-ng', 'linux': 'proxychains'},
        
        # Engenharia social
        'social-analyzer': {'type': 'python', 'package': 'social-analyzer'},
        
        # Malware analysis
        'yara-python': {'type': 'python', 'package': 'yara-python'},
        'pefile': {'type': 'python', 'package': 'pefile'},
        
        # Exploitation
        'pwntools': {'type': 'python', 'package': 'pwntools'},
        'ropgadget': {'type': 'python', 'package': 'ropgadget'},
    }

def install_system_package(package_name, is_termux):
    try:
        if is_termux:
            subprocess.run(['pkg', 'install', '-y', package_name], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            if subprocess.run(['which', 'apt-get'], capture_output=True).returncode == 0:
                subprocess.run(['sudo', 'apt-get', 'install', '-y', package_name], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif subprocess.run(['which', 'yum'], capture_output=True).returncode == 0:
                subprocess.run(['sudo', 'yum', 'install', '-y', package_name], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif subprocess.run(['which', 'pacman'], capture_output=True).returncode == 0:
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', package_name], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def install_python_package(package_name):
    try:
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', '--upgrade', package_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except:
        return False

def check_installed(dependency, is_termux):
    name = dependency.lower()
    if dependency == 'nmap':
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    elif dependency == 'sqlmap':
        try:
            subprocess.run(['sqlmap', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    elif dependency == 'hydra':
        try:
            subprocess.run(['hydra', '-h'], capture_output=True, check=True)
            return True
        except:
            return False
    else:
        try:
            __import__(name.replace('-', '_'))
            return True
        except ImportError:
            return False

def show_installation_progress(is_termux):
    clear_screen()
    show_banner()
    
    dependencies = get_all_dependencies()
    total = len(dependencies)
    installed = 0
    failed = []
    
    console.print(f"[bold cyan]📦 Instalando {total} dependências...[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        transient=True,
    ) as progress:
        
        task = progress.add_task("Preparando instalação...", total=total)
        
        for dep_name, dep_info in dependencies.items():
            progress.update(task, description=f"Verificando {dep_name}...")
            
            # Verificar se já está instalado
            if check_installed(dep_name, is_termux):
                progress.update(task, advance=1, description=f"[green]✓ {dep_name}")
                installed += 1
                sleep(0.3)
                continue
            
            # Instalar dependência
            progress.update(task, description=f"Instalando {dep_name}...")
            
            success = False
            if dep_info['type'] == 'system':
                package_name = dep_info['termux'] if is_termux else dep_info.get('linux', dep_name)
                success = install_system_package(package_name, is_termux)
            else:  # Python package
                if dep_info['package']:  # Se não for built-in
                    success = install_python_package(dep_info['package'])
                else:
                    success = True  # Built-in, considerado instalado
            
            if success:
                progress.update(task, advance=1, description=f"[green]✓ {dep_name} instalado")
                installed += 1
            else:
                progress.update(task, advance=1, description=f"[red]✗ {dep_name} falhou")
                failed.append(dep_name)
            
            sleep(0.5)
    
    return installed, total, failed

def show_summary(installed, total, failed):
    console.print("\n" + "="*60)
    console.print("[bold]📊 RESUMO DA INSTALAÇÃO[/bold]")
    console.print("="*60)
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Status", width=12)
    table.add_column("Quantidade", justify="center")
    table.add_column("Porcentagem", justify="center")
    
    table.add_row(
        "[green]✓ Instalados",
        f"[green]{installed}",
        f"[green]{((installed/total)*100):.1f}%"
    )
    
    if failed:
        table.add_row(
            "[red]✗ Falharam",
            f"[red]{len(failed)}",
            f"[red]{((len(failed)/total)*100):.1f}%"
        )
    
    table.add_row(
        "[blue]📦 Total",
        f"[blue]{total}",
        "[blue]100%"
    )
    
    console.print(table)
    
    if failed:
        console.print("\n[bold yellow]⚠ Dependências que falharam:[/bold yellow]")
        for fail in failed:
            console.print(f"  [red]• {fail}[/red]")
        
        console.print("\n[yellow]💡 Dica: Tente instalar manualmente com:[/yellow]")
        console.print("[white]pip install NOME_DA_DEPENDENCIA[/white]")
        console.print("[white]ou[/white]")
        console.print("[white]pkg install NOME_DA_DEPENDENCIA (Termux)[/white]")

def ask_custom_installation():
    console.print("\n[bold cyan]🎯 INSTALAÇÃO PERSONALIZADA[/bold cyan]")
    console.print("[yellow]Você pode escolher categorias específicas para instalar:[/yellow]")
    
    categories = {
        '1': {'name': '🔍 Reconhecimento/OSINT', 'deps': ['sherlock', 'theHarvester', 'recon-ng', 'shodan', 'censys']},
        '2': {'name': '🌐 Web Hacking', 'deps': ['sqlmap', 'requests', 'flask', 'beautifulsoup4', 'selenium', 'scrapy']},
        '3': {'name': '🔒 Cryptografia', 'deps': ['cryptography', 'pycryptodome', 'pycrypto']},
        '4': {'name': '📡 Wi-Fi/Bluetooth', 'deps': ['scapy', 'pywifi', 'pybluez', 'lightblue']},
        '5': {'name': '💣 Força Bruta/DDoS', 'deps': ['hydra', 'paramiko', 'pexpect']},
        '6': {'name': '🛠️ Ferramentas Gerais', 'deps': ['nmap', 'python-nmap', 'rich', 'colorama', 'pyfiglet']},
        '7': {'name': '🕵️ Anonimato', 'deps': ['tor', 'proxychains']},
    }
    
    for key, category in categories.items():
        console.print(f"[cyan]{key}. {category['name']}[/cyan]")
    
    console.print("[cyan]8. 🚀 TODAS as dependências[/cyan]")
    
    choice = Prompt.ask(
        "\n[bold]Selecione as categorias (ex: 1,3,5 ou 'all')[/bold]",
        choices=['1', '2', '3', '4', '5', '6', '7', '8', 'all'],
        default='8'
    )
    
    if choice == '8' or choice == 'all':
        return get_all_dependencies()
    
    selected_deps = {}
    all_deps = get_all_dependencies()
    
    for cat_num in choice.split(','):
        if cat_num in categories:
            for dep in categories[cat_num]['deps']:
                if dep in all_deps:
                    selected_deps[dep] = all_deps[dep]
    
    return selected_deps

def setup_environment():
    console.print("\n[bold yellow]⚙️ Configurando ambiente...[/bold yellow]")
    
    # Criar diretórios essenciais
    directories = [
        'tools', 'scripts', 'output', 'wordlists', 'logs',
        'web_apps', 'exploits', 'payloads', 'reports'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            console.print(f"[green]✓ Diretório {directory}/ criado[/green]")
        except Exception as e:
            console.print(f"[red]✗ Erro ao criar {directory}/: {e}[/red]")
    
    # Criar arquivo de configuração básico
    config_content = """# Configurações do Ambiente Hacker
[directories]
tools = ./tools
scripts = ./scripts
output = ./output
wordlists = ./wordlists

[settings]
auto_update = true
log_level = info
"""
    
    try:
        with open('hacker_config.ini', 'w') as f:
            f.write(config_content)
        console.print("[green]✓ Arquivo de configuração criado[/green]")
    except Exception as e:
        console.print(f"[red]✗ Erro ao criar arquivo de configuração: {e}[/red]")

def main():
    clear_screen()
    show_banner()
    
    # Detectar ambiente
    is_termux = os.path.exists('/data/data/com.termux/files/usr')
    system_name = platform.system()
    
    console.print(f"[bold blue]🌍 Sistema detectado: {system_name}[/bold blue]")
    if is_termux:
        console.print("[bold green]📱 Ambiente Termux detectado[/bold green]")
    
    # Verificar pip
    if not check_pip():
        console.print("[yellow]⚠ Pip não encontrado. Instalando...[/yellow]")
        if not install_pip():
            console.print("[red]❌ Falha crítica: não foi possível instalar o pip[/red]")
            sys.exit(1)
    
    # Perguntar sobre instalação personalizada
    if Confirm.ask("\n[bold]Deseja escolher categorias específicas?[/bold]", default=False):
        dependencies = ask_custom_installation()
    else:
        dependencies = get_all_dependencies()
    
    # Mostrar resumo do que será instalado
    console.print(f"\n[bold cyan]📦 Serão instaladas {len(dependencies)} dependências:[/bold cyan]")
    deps_list = list(dependencies.keys())
    for i in range(0, len(deps_list), 4):
        console.print("  " + "  ".join(f"• {dep}" for dep in deps_list[i:i+4]))
    
    if not Confirm.ask("\n[bold]Continuar com a instalação?[/bold]", default=True):
        console.print("[yellow]Instalação cancelada pelo usuário[/yellow]")
        sys.exit(0)
    
    # Instalação principal
    installed, total, failed = show_installation_progress(is_termux)
    
    # Resumo
    show_summary(installed, total, failed)
    
    # Configuração do ambiente
    setup_environment()
    
    # Mensagem final
    console.print(Panel.fit(
        "[bold green]🎉 INSTALAÇÃO COMPLETA![/bold green]\n\n"
        "[yellow]📚 Recursos instalados:[/yellow]\n"
        "• Ferramentas de OSINT e reconhecimento\n"
        "• Scanner de vulnerabilidades web\n"
        "• Ferramentas de criptografia\n"
        "• Utilitários Wi-Fi e Bluetooth\n"
        "• Ferramentas de força bruta\n"
        "• Bibliotecas para DDoS/DoS\n"
        "• APIs para automação\n\n"
        "[yellow]🚀 Próximos passos:[/yellow]\n"
        "1. Explore os diretórios criados\n"
        "2. Execute suas ferramentas favoritas\n"
        "3. Consulte a documentação de cada ferramenta\n\n"
        "[red]⚠ Use o conhecimento com responsabilidade![/red]",
        border_style="green",
        padding=(1, 2)
    ))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]❌ Instalação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]💥 Erro crítico: {e}[/red]")
        sys.exit(1)
