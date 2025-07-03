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
from rich.table import Table

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
        "nome": "Termux Malware Fake",
        "nivel": "⚠️ Nível de Perigo: Baixo (Fake)",
        "descricao": "Ferramenta falsa para susto - não contém código malicioso real",
        "tecnica": "Engenharia Social: Cria senso de urgência e medo para induzir ações precipitadas",
        "funcionamento": "O script exibe mensagens assustadoras sobre infecção do dispositivo, mas não executa ações maliciosas reais.",
        "prevencao": "Verificar sempre a autenticidade das ferramentas e não executar scripts de fontes desconhecidas."
    },
    {
        "url": "https://github.com/pythoandtrojan/malwer",
        "nome": "Ransomware Simples",
        "nivel": "🔥 Nível de Perigo: Alto (Ransomware)",
        "descricao": "Possível ransomware para Windows - criptografa arquivos",
        "tecnica": "Engenharia Social: Promete funcionalidades úteis para esconder payload malicioso",
        "funcionamento": "Após execução, varre diretórios específicos criptografando arquivos com extensões comuns (.doc, .jpg, etc.) usando AES.",
        "prevencao": "Manter backups regulares e não executar arquivos .exe de fontes não confiáveis."
    },
    {
        "url": "https://github.com/pythoandtrojan/whatsapp-hacker",
        "nome": "WhatsApp Hacker Fake",
        "nivel": "💀 Nível de Perigo: Crítico (Spyware)",
        "descricao": "Falso hacker de WhatsApp que pode roubar credenciais",
        "tecnica": "Engenharia Social: Aproveita-se da curiosidade sobre mensagens alheias",
        "funcionamento": "Script Python que solicita login e senha do WhatsApp Web, enviando para um servidor remoto.",
        "prevencao": "Nunca fornecer credenciais a aplicativos de terceiros e habilitar autenticação de dois fatores."
    },
    {
        "url": "https://github.com/pythoandtrojan/insta-ataque",
        "nome": "Instagram Attack Combo",
        "nivel": "🔴 Nível de Perigo: Extremo (Keylogger + Ransomware)",
        "descricao": "Combo perigoso de keylogger e ransomware direcionado",
        "tecnica": "Engenharia Social: Oferece ferramentas 'profissionais' para ganhar confiança",
        "funcionamento": "1. Keylogger registra todas as teclas digitadas\n2. Coleta credenciais de redes sociais\n3. Criptografa arquivos exigindo resgate",
        "prevencao": "Usar antivírus atualizado, desconfiar de ferramentas 'milagrosas' e verificar reputação do software."
    },
    {
        "url": "https://github.com/pythoandtrojan/ataque-banco/blob/main/ataque.py",
        "nome": "Bank Attack Malware",
        "nivel": "☠️ Nível de Perigo: Extremo (Banking Trojan + Ransomware)",
        "descricao": "Malware bancário avançado com capacidade de ransomware",
        "tecnica": "Engenharia Social: Simula ferramenta de pentest para ganhar confiança",
        "funcionamento": "1. Coleta dados bancários da vítima\n2. Executa ransomware nos arquivos pessoais\n3. Cria backdoors ocultos no sistema\n4. Simula ataques a bancos\n5. Rouba credenciais financeiras",
        "prevencao": "1. Nunca executar ferramentas de 'pentest' desconhecidas\n2. Usar soluções de segurança endpoint\n3. Monitorar processos suspeitos\n4. Manter sistemas atualizados\n5. Usar autenticação multifator em contas bancárias"
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
    """Exibe detalhes organizados do malware em painéis"""
    # Painel superior com informações básicas
    console.print(Panel.fit(
        f"[bold red]{url_info['nome']}[/bold red]\n"
        f"[yellow]URL:[/yellow] [white]{url_info['url']}[/white]\n"
        f"[yellow]Nível de Perigo:[/yellow] {url_info['nivel']}\n"
        f"[yellow]Descrição:[/yellow] [white]{url_info['descricao']}[/white]",
        border_style="red",
        title="📌 INFORMAÇÕES BÁSICAS"
    ))
    
    # Painel de funcionamento técnico
    console.print(Panel.fit(
        f"[yellow]Método de Operação:[/yellow]\n[white]{url_info['funcionamento']}[/white]",
        border_style="yellow",
        title="⚙️ FUNCIONAMENTO TÉCNICO"
    ))
    
    # Painel de técnicas de engenharia social
    console.print(Panel.fit(
        f"[yellow]Técnicas de Engenharia Social:[/yellow]\n[white]{url_info['tecnica']}[/white]",
        border_style="cyan",
        title="🎭 TÉCNICAS SOCIAIS"
    ))
    
    # Painel de prevenção
    console.print(Panel.fit(
        f"[yellow]Medidas de Prevenção:[/yellow]\n[white]{url_info['prevencao']}[/white]",
        border_style="green",
        title="🛡️ COMO SE PROTEGER"
    ))

def main_menu():
    while True:
        clear_screen()
        console.print(Align.center(MATRIX_BANNER))
        console.print(Align.center(VIRUS_ART))
        
        console.print("\n[bold green]1. Analisar URLs de Malware")
        console.print("[bold green]2. Mostrar Técnicas de Engenharia Social")
        console.print("[bold green]3. Simular Ataque (Demonstração)")
        console.print("[bold green]4. Listar Todos os Malwares")
        console.print("[bold green]5. Sair")
        
        try:
            choice = console.input("\n[bold white]Selecione uma opção: [/bold white]")
            
            if choice == "1":
                analyze_urls()
            elif choice == "2":
                show_social_engineering()
            elif choice == "3":
                simulate_attack()
            elif choice == "4":
                list_all_malwares()
            elif choice == "5":
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
        
        # Tabela com opções numeradas
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Nº", style="dim", width=4)
        table.add_column("Nome do Malware")
        table.add_column("Nível de Perigo")
        
        for i, url_info in enumerate(MALWARE_URLS, 1):
            table.add_row(str(i), url_info['nome'], url_info['nivel'])
        
        console.print(table)
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

def list_all_malwares():
    """Mostra todos os malwares em uma tabela organizada"""
    clear_screen()
    console.print(Align.center("[red]LISTA COMPLETA DE MALWARES ANALISADOS[/red]"))
    
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Nome", style="bold")
    table.add_column("URL", style="dim")
    table.add_column("Nível")
    table.add_column("Técnica Principal")
    
    for malware in MALWARE_URLS:
        table.add_row(
            malware['nome'],
            malware['url'],
            malware['nivel'],
            malware['tecnica'].split(":")[0]
        )
    
    console.print(table)
    
    console.print("\n[yellow]Use a opção 1 no menu principal para ver detalhes completos de cada malware.[/yellow]")
    console.print("\n[red]Pressione Enter para continuar...[/red]")
    input()

def show_social_engineering():
    """Mostra técnicas de engenharia social em colunas"""
    techniques = [
        {
            "nome": "Phishing",
            "descricao": "Imitação de entidades confiáveis para roubo de credenciais",
            "exemplo": "E-mails falsos de bancos ou redes sociais",
            "prevencao": "Verificar URLs e não clicar em links suspeitos"
        },
        {
            "nome": "Pretexting",
            "descricao": "Criação de cenários falsos para ganhar confiança",
            "exemplo": "Fingir ser do suporte técnico para obter acesso",
            "prevencao": "Sempre verificar identidade antes de fornecer informações"
        },
        {
            "nome": "Scareware",
            "descricao": "Cria medo ou senso de urgência para ação imediata",
            "exemplo": "Alertas falsos de vírus para instalar malware",
            "prevencao": "Manter a calma e verificar informações com fontes oficiais"
        },
        {
            "nome": "Baiting",
            "descricao": "Oferece algo tentador em troca de informações",
            "exemplo": "Downloads gratuitos de software pirata contendo malware",
            "prevencao": "Evitar downloads de fontes não confiáveis"
        }
    ]
    
    clear_screen()
    console.print(Align.center("[green]TÉCNICAS DE ENGENHARIA SOCIAL[/green]"))
    
    # Criar painéis para cada técnica
    panels = []
    for tech in techniques:
        panel = Panel(
            f"[bold]{tech['nome']}[/bold]\n\n"
            f"[yellow]Descrição:[/yellow] {tech['descricao']}\n"
            f"[yellow]Exemplo:[/yellow] {tech['exemplo']}\n"
            f"[green]Prevenção:[/green] {tech['prevencao']}",
            border_style="blue"
        )
        panels.append(panel)
    
    # Mostrar em colunas (2x2)
    console.print(Columns(panels, width=40, equal=True))
    
    console.print("\n[red]Pressione Enter para continuar...[/red]")
    input()

def simulate_attack():
    """Simula um ataque de malware com mais detalhes"""
    clear_screen()
    console.print(Align.center("[red]SIMULAÇÃO DE ATAQUE MALICIOSO[/red]"))
    
    # Etapas do ataque
    steps = [
        ("Reconhecimento", "Varrendo sistema por vulnerabilidades..."),
        ("Exploração", "Explorando falhas conhecidas..."),
        ("Injeção", "Injetando código malicioso..."),
        ("Privilege Escalation", "Elevando privilégios..."),
        ("Exfiltração", "Roubando dados sensíveis..."),
        ("Impacto", "Criptografando arquivos...")
    ]
    
    with Progress() as progress:
        tasks = {}
        for step in steps:
            tasks[step[0]] = progress.add_task(f"[red]{step[1]}", total=100)
        
        while not all(task.completed for task in progress.tasks):
            for step_name, task in tasks.items():
                if not progress.tasks[task].completed:
                    progress.update(task, advance=random.uniform(0.5, 3))
            time.sleep(0.05)
    
    console.print(Panel.fit(
        "[blink red]SISTEMA COMPROMETIDO![/blink red]\n\n"
        "[white]Esta foi apenas uma demonstração educacional de como um ataque real poderia ocorrer.[/white]\n"
        "[yellow]Todas as etapas simuladas são comuns em ataques reais de malware.[/yellow]",
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
