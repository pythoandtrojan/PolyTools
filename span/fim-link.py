import os
import time
import random
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.text import Text
from rich.layout import Layout
from rich.columns import Columns
from rich.align import Align
from rich.style import Style

console = Console()


matrix_style = Style(color="green", blink=True, bold=True)


MATRIX_BANNER = """
[green]╔═╗┬ ┬┌─┐┌┬┐┌─┐  ╔╦╗┌─┐┌┬┐┌─┐┬─┐┌┬┐
║  ├─┤├┤ │││├┤   ║ │ │ ││├┤ ├┬┘ │ 
╚═╝┴ ┴└─┘┴ ┴└─┘   ╩ └─┘─┴┘└─┘┴└─ ┴ 
┌───────────────────────────────────┐
│  M A L W A R E   A N A L Y Z E R  │
└───────────────────────────────────┘[/green]
"""


VIRUS_ART = r"""
[red]    _    ____  ____  _____ ____  
   / \  |  _ \|  _ \| ____/ ___| 
  / _ \ | |_) | |_) |  _| \___ \ 
 / ___ \|  _ <|  _ <| |___ ___) |
/_/   \_\_| \_\_| \_\_____|____/ 
[/red]"""


MALWARE_URLS = [
    {
        "url": "https://github.com/pythoandtrojan/termux-malwer.py",
        "nivel": "⚠️ Nível de Perigo: Baixo (Fake)",
        "descricao": "Ferramenta falsa para susto - não contém código malicioso real",
        "dicas": "Engenharia Social: Cria senso de urgência e medo para induzir ações precipitadas"
    },
    {
        "url": "https://github.com/pythoandtrojan/malwer",
        "nivel": "🔥 Nível de Perigo: Alto (Ransomware)",
        "descricao": "Possível ransomware para Windows - criptografa arquivos",
        "dips": "Engenharia Social: Promete funcionalidades úteis para esconder payload malicioso"
    },
    {
        "url": "https://github.com/pythoandtrojan/whatsapp-hacker",
        "nivel": "💀 Nível de Perigo: Crítico (Spyware)",
        "descricao": "Falso hacker de WhatsApp que pode roubar credenciais",
        "dicas": "Engenharia Social: Aproveita-se da curiosidade sobre mensagens alheias"
    },
    {
        "url": "https://github.com/pythoandtrojan/insta-ataque",
        "nivel": "🔴 Nível de Perigo: Extremo (Keylogger + Ransomware)",
        "descricao": "Combo perigoso de keylogger e ransomware direcionado",
        "dicas": "Engenharia Social: Oferece ferramentas 'profissionais' para ganhar confiança"
    }
]

def clear_screen():
    
    os.system('cls' if os.name == 'nt' else 'clear')

def matrix_effect(lines=30):
    """Efeito de chuva Matrix"""
    chars = "01"
    for _ in range(lines):
        console.print("".join(random.choice(chars) for _ in range(80)), style=matrix_style)
        time.sleep(0.05)

def show_scan_animation():
    """Animação de varredura estilo Matrix"""
    with Progress(transient=True) as progress:
        task = progress.add_task("[green]Varrendo URLs...", total=100)
        
        for i in range(100):
            progress.update(task, advance=1, 
                          description=f"[green]Analisando setor {random.randint(1, 256)}...")
            time.sleep(0.03)
            
            if random.random() > 0.8:
                console.print(f"[green]Detectado: Pacote suspeito 0x{random.randint(1000, 9999):X}[/green]")

def show_malware_details(url_info):
   
    console.print(Panel.fit(
        f"[red]URL MALICIOSA DETECTADA![/red]\n\n"
        f"[yellow]URL:[/yellow] [white]{url_info['url']}[/white]\n"
        f"[yellow]Nível:[/yellow] {url_info['nivel']}\n"
        f"[yellow]Descrição:[/yellow] [white]{url_info['descricao']}[/white]\n"
        f"[yellow]Dicas de Eng. Social:[/yellow] [white]{url_info['dicas']}[/white]",
        border_style="red",
        title="⚠️ ALERTA DE SEGURANÇA ⚠️"
    ))

def main_menu():
    
    while True:
        clear_screen()
        console.print(Align.center(MATRIX_BANNER))
        console.print(Align.center(VIRUS_ART))
        
        console.print("\n[bold green]1. Analisar URLs de Malware")
        console.print("[bold green]2. Mostrar Técnicas de Engenharia Social")
        console.print("[bold green]3. Simular Ataque (Demonstração)")
        console.print("[bold green]4. Sair")
        
        try:
            choice = console.input("\n[bold white]Selecione uma opção: [/bold white]")
            
            if choice == "1":
                analyze_urls()
            elif choice == "2":
                show_social_engineering()
            elif choice == "3":
                simulate_attack()
            elif choice == "4":
                console.print("\n[green]Encerrando sistema...[/green]")
                time.sleep(1)
                break
            else:
                console.print("\n[red]Opção inválida! Pressione Enter para continuar...[/red]")
                input()
                
        except Exception as e:
            console.print(f"\n[red]Erro: {str(e)}[/red]")
            console.print("[red]Pressione Enter para continuar...[/red]")
            input()

def analyze_urls():
    """Menu de análise de URLs"""
    while True:
        clear_screen()
        console.print(Align.center("[green]ANÁLISE DE URLS MALICIOSAS[/green]"))
        
        for i, url_info in enumerate(MALWARE_URLS, 1):
            console.print(f"[bold green]{i}. {url_info['url']}[/bold green]")
        
        console.print("\n[bold green]0. Voltar ao menu principal")
        
        try:
            choice = console.input("\n[bold white]Selecione uma URL para análise: [/bold white]")
            
            if choice == "0":
                break
                
            elif choice.isdigit() and 1 <= int(choice) <= len(MALWARE_URLS):
                selected = MALWARE_URLS[int(choice)-1]
                
                clear_screen()
                matrix_effect(10)
                show_scan_animation()
                show_malware_details(selected)
                
                console.print("\n[red]Pressione Enter para continuar...[/red]")
                input()
                
            else:
                console.print("\n[red]Opção inválida![/red]")
                time.sleep(1)
                
        except Exception as e:
            console.print(f"\n[red]Erro: {str(e)}[/red]")
            console.print("[red]Pressione Enter para continuar...[/red]")
            input()

def show_social_engineering():
    """Mostra técnicas de engenharia social"""
    techniques = [
        {
            "nome": "Phishing",
            "descricao": "Imitação de entidades confiáveis para roubo de credenciais",
            "exemplo": "E-mails falsos de bancos ou redes sociais"
        },
        {
            "nome": "Pretexting",
            "descricao": "Criação de cenários falsos para ganhar confiança",
            "exemplo": "Fingir ser do suporte técnico para obter acesso"
        },
        {
            "nome": "Scareware",
            "descricao": "Cria medo ou senso de urgência para ação imediata",
            "exemplo": "Alertas falsos de vírus para instalar malware"
        },
        {
            "nome": "Baiting",
            "descricao": "Oferece algo tentador em troca de informações",
            "exemplo": "Downloads gratuitos de software pirata contendo malware"
        }
    ]
    
    clear_screen()
    console.print(Align.center("[green]TÉCNICAS DE ENGENHARIA SOCIAL[/green]"))
    
    for tech in techniques:
        console.print(Panel.fit(
            f"[yellow]Técnica:[/yellow] [bold white]{tech['nome']}[/bold white]\n"
            f"[yellow]Descrição:[/yellow] [white]{tech['descricao']}[/white]\n"
            f"[yellow]Exemplo:[/yellow] [white]{tech['exemplo']}[/white]",
            border_style="green"
        ))
    
    console.print("\n[red]Pressione Enter para continuar...[/red]")
    input()

def simulate_attack():
    """Simula um ataque de malware"""
    clear_screen()
    console.print(Align.center("[red]SIMULAÇÃO DE ATAQUE MALICIOSO[/red]"))
    
    with Progress() as progress:
        tasks = [
            progress.add_task("[red]Explorando vulnerabilidades...", total=100),
            progress.add_task("[red]Bypassando segurança...", total=100),
            progress.add_task("[red]Injetando payload...", total=100)
        ]
        
        while not all(task.completed for task in progress.tasks):
            for task in tasks:
                progress.update(task, advance=random.uniform(0.5, 3))
            time.sleep(0.05)
    
    console.print(Panel.fit(
        "[blink red]SISTEMA COMPROMETIDO![/blink red]\n\n"
        "[white]Esta foi apenas uma demonstração educacional.[/white]",
        border_style="red",
        title="⚠️ ALERTA DE SEGURANÇA ⚠️"
    ))
    
    console.print("\n[red]Pressione Enter para continuar...[/red]")
    input()

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Interrompido pelo usuário[/red]")
    except Exception as e:
        console.print(f"\n[red]Erro fatal: {str(e)}[/red]")
    finally:
        clear_screen()
        console.print(Align.center("[green]Sistema encerrado com segurança[/green]"))
