import os
import time
import random
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.box import DOUBLE
from rich.align import Align
from rich.style import Style
from rich.layout import Layout
from rich.columns import Columns

console = Console()


danger_style = Style(color="red", blink=True, bold=True)
warning_style = Style(color="yellow", bold=True)
fake_safe_style = Style(color="green", bold=True)
matrix_style = Style(color="bright_green", bold=True)


DEVIL_BANNER = r"""
[red]▓█████▄  ▒█████   ███▄ ▄███▓ █    ██  ███▄    █ 
▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒ ██  ▓██▒ ██ ▀█   █ 
░██   █▌▒██░  ██▒▓██    ▓██░▓██  ▒██░▓██  ▀█ ██▒
░▓█▄   ▌▒██   ██░▒██    ▒██ ▓▓█  ░██░▓██▒  ▐▌██▒
░▒████▓ ░ ████▓▒░▒██▒   ░██▒▒▒█████▓ ▒██░   ▓██░
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒ 
 ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░░░▒░ ░ ░ ░ ░░   ░ ▒░
 ░ ░  ░ ░ ░ ░ ▒  ░      ░    ░░░ ░ ░    ░   ░ ░ 
   ░        ░ ░         ░      ░              ░ 
 ░                                              
[white]╔════════════════════════════════════════════╗
║                                            ║
║  [blink red]🔥  SUPREME HACKER TOOLS v6.66  🔥[/blink red]  ║
║                                            ║
╚════════════════════════════════════════════╝[/white]"""

# 👺 Arte ASCII do Diabo
DEVIL_ART = r"""
[red]                      ,-.
                     / \  `.  __..-,O
                    :   \ --''_..-'.'
                    |    . .-' `. '.
                    :     .     .`.'
                     \     `.  /  ..
                      \      `.   ' .
                       `,       `.   \
                      ,|,`.        `-.\
                     '.||  ``-...__..-`
                      |  |
                      |__|
                      /||\
                     //||\\
                    // || \\ [blink white]😈[/blink white]
                 __//__||__\\__
                '--------------'[/red]"""


def show_fake_proofs():
    """Provas sociais falsas mais convincentes"""
    table = Table(title="👥 Últimos Usuários (Hoje)", box=DOUBLE)
    table.add_column("ID", style="cyan")
    table.add_column("Ação", style="green")
    table.add_column("Resultado", style="yellow")
    table.add_column("Ganho", style="red")
    
    fake_actions = [
        ("DarkHacker42", "WhatsApp Hack", "Sucesso", "$1,200"),
        ("AnonGhost", "Instagram Spy", "Sucesso", "Dados Vendidos"),
        ("CyberDemon", "Ransomware", "Pago", "2.5 BTC"),
        ("ZeroCool", "Keylogger", "Sucesso", "Credenciais"),
        ("BlackHat99", "Bank Hack", "Sucesso", "$8,750")
    ]
    
    for action in fake_actions:
        table.add_row(*action)
    
    console.print(table)

def fake_antivirus_check():
   
    with Progress() as progress:
        task = progress.add_task("[green]Verificando segurança...", total=100)
        for i in range(100):
            progress.update(task, advance=1)
            time.sleep(0.02)
    
    console.print(Panel.fit(
        "[green]✅ VERIFICAÇÃO COMPLETA[/green]\n\n"
        "• 0 Vírus Detectados\n"
        "• 0 Arquivos Maliciosos\n"
        "• Assinatura Digital: [green]VERIFICADA[/green]\n"
        "• Certificado: [green]Thawte Code Signing[/green]\n"
        "• Reputação: ★★★★★ (4987 avaliações)\n\n"
        "[white]Este software é 100% seguro e legítimo![/white]",
        border_style="green"
    ))

def countdown_scam():
    
    for i in range(10, 0, -1):
        console.print(f"[blink red]🚨 OFERTA ACABA EM {i}s! APENAS HOJE: TODAS FERRAMENTAS GRÁTIS![/blink red]")
        time.sleep(0.3)


MALWARE_OPTIONS = [
    {
        "name": "WhatsApp Ultimate Hack",
        "desc": "Acesse TODAS as mensagens de qualquer WhatsApp!",
        "risk": "🔴 Extremo",
        "fake_stats": "98% Sucesso",
        "price": "GRÁTIS (Oferta Limitada)",
        "tutorial": """
[red]📌 COMO USAR PARA ENGANAR:[/red]
1. Crie um site fake oferecendo "hack de WhatsApp grátis"
2. Quando a vítima baixar, peça para desativar o antivírus
3. O arquivo contém um keylogger e RAT
4. Use as credenciais coletadas para acessar a conta
5. Chantageie ou venda os dados no fórum underground"""
    },
    {
        "name": "Instagram Password Cracker",
        "desc": "Recupere qualquer senha do Instagram em minutos!",
        "risk": "🔴 Extremo",
        "fake_stats": "95% Sucesso",
        "price": "GRÁTIS (Últimos 10)",
        "tutorial": """
[red]📌 COMO USAR PARA ENGANAR:[/red]
1. Monte um perfil fake de "suporte do Instagram"
2. Ofereça verificação de conta hackada
3. Direcione para um phishing page idêntico ao Instagram
4. Colete as credenciais digitadas
5. Acesse a conta e ative 2FA para bloquear o dono"""
    },
    {
        "name": "Bank Account Exploit",
        "desc": "Acesso completo a contas bancárias (NOVO)!",
        "risk": "💀 Perigoso",
        "fake_stats": "92% Sucesso",
        "price": "$99 (HOJE GRÁTIS)",
        "tutorial": """
[red]📌 COMO USAR PARA ENGANAR:[/red]
1. Envie e-mails de "atualização cadastral" do banco
2. Use domínios parecidos (ex: banco-oficial.com)
3. O exploit vem como "atualizador de segurança.exe"
4. Quando executado, instala um bancário trojan
5. Capture tokens e senhas de internet banking"""
    }
]


def main_menu():
    while True:
        clear_screen()
        console.print(Align.center(DEVIL_BANNER))
        console.print(Align.center(DEVIL_ART))
        
        
        console.print(f"[yellow]👥 {random.randint(5000, 10000)} usuários ativos agora![/yellow]")
        console.print(f"[cyan]💻 {random.randint(200, 500)} downloads nas últimas horas![/cyan]")
        
       
        show_fake_proofs()
       
        console.print("\n[red]1. 😈 Ferramentas de Hacking VIP (Com Tutoriais)")
        console.print("[red]2. 🔑 Gerador de Licenças Gratuitas (Fake)")
        console.print("[red]3. 🛡️ Verificador de Segurança (Falso)")
        console.print("[red]4. 💰 Ganhe Dinheiro com Hacking (Scam)")
        console.print("[red]5. 📚 Guia de Engenharia Social")
        console.print("[red]6. ❌ Sair")
        
        choice = console.input("\n[blink white]👉 SELECIONE UMA OPÇÃO: [/blink white]")
        
        if choice == "1":
            show_hacking_tools()
        elif choice == "2":
            fake_license_generator()
        elif choice == "3":
            fake_security_check()
        elif choice == "4":
            money_scam()
        elif choice == "5":
            social_engineering_guide()
        elif choice == "6":
            exit_program()
        else:
            console.print("[red]Opção inválida! Tente novamente.[/red]", style=danger_style)
            time.sleep(1)


def show_hacking_tools():
    clear_screen()
    console.print(Panel.fit("[red]🔥 FERRAMENTAS DE HACKING VIP[/red]", border_style="red"))
    
    for i, tool in enumerate(MALWARE_OPTIONS, 1):
        console.print(Panel.fit(
            f"[yellow]🔧 {tool['name']}[/yellow]\n"
            f"[white]{tool['desc']}[/white]\n"
            f"[red]Risco: {tool['risk']} | Taxa de Sucesso: {tool['fake_stats']}[/red]\n"
            f"[green]Preço: {tool['price']}[/green]",
            border_style="yellow"
        ))
    
    choice = console.input("\n[blink white]👉 SELECIONE UMA FERRAMENTA (1-3) OU VOLTE (0): [/blink white]")
    
    if choice in ["1", "2", "3"]:
        show_tool_tutorial(int(choice) - 1)
    elif choice == "0":
        return
    else:
        console.print("[red]Opção inválida![/red]", style=danger_style)
        time.sleep(1)

def show_tool_tutorial(index):
    tool = MALWARE_OPTIONS[index]
    clear_screen()
    
    console.print(Panel.fit(
        f"[red]🔥 {tool['name']}[/red]\n"
        f"[yellow]{tool['desc']}[/yellow]",
        border_style="red"
    ))
    
    console.print(Panel.fit(
        tool['tutorial'],
        border_style="yellow"
    ))
    
    console.print("\n[red]⚠️ AVISO: Este conteúdo é apenas para fins educacionais de segurança cibernética.[/red]")
    input("\nPressione Enter para voltar...")

def fake_license_generator():
    clear_screen()
    console.print(Panel.fit("[green]🔑 GERADOR DE LICENÇAS VIP[/green]", border_style="green"))
    
    with Progress() as progress:
        task = progress.add_task("[yellow]Gerando licença...", total=100)
        for i in range(100):
            progress.update(task, advance=1)
            time.sleep(0.03)
    
    fake_license = f"LIC-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
    console.print(Panel.fit(
        f"[green]✅ LICENÇA GERADA COM SUCESSO![/green]\n\n"
        f"[white]Sua licença VIP:[/white] [yellow]{fake_license}[/yellow]\n\n"
        f"[red]⚠️ ATENÇÃO: Esta licença é falsa e serve apenas como isca para phishing.[/red]\n"
        f"Use em páginas de ativação fake para coletar dados de vítimas.",
        border_style="green"
    ))
    
    input("\nPressione Enter para voltar...")

def social_engineering_guide():
    clear_screen()
    console.print(Panel.fit("[red]📚 GUIA DE ENGENHARIA SOCIAL[/red]", border_style="red"))
    
    techniques = [
        {
            "name": "Phishing Avançado",
            "desc": "Como criar páginas de login idênticas às reais",
            "steps": [
                "1. Use o Inspect Element para copiar o CSS do site alvo",
                "2. Registre um domínio parecido (ex: faceb00k-login.com)",
                "3. Adicione um certificado SSL gratuito para parecer seguro",
                "4. Use redirecionamentos para evitar detecção"
            ]
        },
        {
            "name": "Scam de Suporte Técnico",
            "desc": "Enganar vítimas para dar acesso remoto",
            "steps": [
                "1. Ligar fingindo ser do suporte da Microsoft/Apple",
                "2. Dizer que detectaram vírus no computador",
                "3. Pedir para acessar um site de suporte remoto",
                "4. Usar AnyDesk/TeamViewer para controle total"
            ]
        }
    ]
    
    for tech in techniques:
        console.print(Panel.fit(
            f"[yellow]🔧 {tech['name']}[/yellow]\n"
            f"[white]{tech['desc']}[/white]\n\n"
            + "\n".join(tech['steps']),
            border_style="yellow"
        ))
    
    console.print("\n[red]⚠️ AVISO: Este guia é apenas para fins educacionais de defesa cibernética.[/red]")
    input("\nPressione Enter para voltar...")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def exit_program():
    console.print("\n[red]Saindo do Diablo Hacker Tools...[/red]")
    time.sleep(1)
    console.print("[blink red]⚠️ Seus dados NÃO foram rastreados... ou foram? 😈[/blink red]")
    time.sleep(2)
    exit()

if __name__ == "__main__":
    try:
       
        console.print(Panel.fit(
            "[blink red]⚠️ ALERTA DE SEGURANÇA: SEU IP ESTÁ VAZADO![/blink red]\n"
            "Hackers podem estar acessando seus dados AGORA!\n"
            "Execute esta ferramenta para proteção imediata!",
            border_style="red"
        ))
        time.sleep(3)
        
        
        fake_antivirus_check()
        time.sleep(2)
        
       
        countdown_scam()
        
      
        main_menu()
        
    except KeyboardInterrupt:
        console.print("\n[red]Sessão encerrada pelo usuário[/red]")
    except Exception as e:
        console.print(f"\n[red]Erro demoníaco: {str(e)}[/red]")
main_menu()
