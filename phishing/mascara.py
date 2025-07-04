import random
import string
import base64
import time
from urllib.parse import urlparse, urlunparse, quote
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
import pyperclip
import qrcode
from rich.qr_code import QRCode
import darkdetect

# Configuração inicial
console = Console()
THEME = "dark" if darkdetect.theme() == "Dark" else "light"

# Cores baseadas no tema
COLORS = {
    "dark": {
        "primary": "bold cyan",
        "secondary": "bold magenta",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "info": "bold blue"
    },
    "light": {
        "primary": "bold blue",
        "secondary": "bold violet",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold orange3",
        "info": "bold dodger_blue1"
    }
}

def gerar_chave_criptografia():
    """Gera e retorna uma chave de criptografia Fernet"""
    return Fernet.generate_key()

def criptografar_url(url, chave):
    """Criptografa a URL usando Fernet"""
    fernet = Fernet(chave)
    return fernet.encrypt(url.encode()).decode()

def ofuscar_url(url, tecnica="base64"):
    """Aplica técnicas de ofuscação na URL"""
    if tecnica == "base64":
        # Base64 com salt
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return base64.urlsafe_b64encode(f"{salt}{url}".encode()).decode()
    elif tecnica == "dupla":
        # Codificação dupla
        encoded = base64.urlsafe_b64encode(url.encode()).decode()
        return quote(encoded[::-1])  # Inverte a string e aplica URL encoding
    else:
        return url

def gerar_dominio_aleatorio():
    """Gera um domínio aleatório convincente"""
    prefixos = ["go", "link", "secure", "access", "redirect", "gate", "portal"]
    tlds = [".com", ".net", ".org", ".io", ".info", ".xyz", ".online"]
    nome = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))
    return f"{random.choice(prefixos)}{nome}{random.choice(tlds)}"

def gerar_rota_dinamica(url_ofuscada):
    """Gera uma rota dinâmica para a URL"""
    prefixos = ["path", "route", "go", "redirect", "access"]
    return f"/{random.choice(prefixos)}/{url_ofuscada}"

def gerar_url_mascarada(url_original, dominio_personalizado=None, tecnica="base64"):
    """Gera uma URL mascarada avançada"""
    # Gera chave de criptografia
    chave = gerar_chave_criptografia()
    
    # Criptografa a URL original
    url_criptografada = criptografar_url(url_original, chave)
    
    # Ofusca a URL criptografada
    url_ofuscada = ofuscar_url(url_criptografada, tecnica)
    
    # Define o domínio
    dominio = dominio_personalizado if dominio_personalizado else gerar_dominio_aleatorio()
    
    # Gera a rota dinâmica
    rota = gerar_rota_dinamica(url_ofuscada)
    
    # Cria a URL mascarada final
    return f"https://{dominio}{rota}", chave.decode()

def exibir_banner():
    """Exibe um banner estilizado"""
    banner_text = "🔗 URL Masker Pro"
    console.print(
        Panel.fit(
            banner_text,
            title="[b]Bem-vindo[/]",
            border_style=COLORS[THEME]["primary"],
            padding=(1, 4)
        )
    )
    console.print(
        Panel.fit(
            "[i]Ferramenta avançada de mascaramento e ofuscação de URLs[/i]",
            border_style=COLORS[THEME]["secondary"],
            style=COLORS[THEME]["info"]
        )
    )

def mostrar_historico(historico):
    """Exibe o histórico de URLs mascaradas"""
    table = Table(title="📋 Histórico de URLs", show_lines=True)
    table.add_column("Data", style="dim")
    table.add_column("Domínio", style=COLORS[THEME]["primary"])
    table.add_column("URL Original", style=COLORS[THEME]["info"])
    
    for item in historico[-5:]:  # Mostra apenas os 5 últimos
        table.add_row(
            item['data'],
            item['dominio'],
            item['original'][:30] + "..." if len(item['original']) > 30 else item['original']
        )
    
    console.print(table)

def mostrar_qrcode(url):
    """Exibe um QR Code para a URL"""
    console.print("\n" + Panel.fit(
        QRCode(url),
        title="📲 QR Code",
        border_style=COLORS[THEME]["secondary"]
    ))

def main():
    """Função principal da aplicação"""
    historico = []
    exibir_banner()
    
    while True:
        console.print("\n" + Panel.fit(
            "[1] Mascarar URL\n[2] Ver Histórico\n[3] Sair",
            title="Menu Principal",
            border_style=COLORS[THEME]["primary"]
        ))
        
        opcao = Prompt.ask(
            "[b]Escolha uma opção[/]",
            choices=["1", "2", "3"],
            default="1"
        )
        
        if opcao == "1":
            # Mascarar URL
            url_original = Prompt.ask(
                "[b]Insira a URL que deseja mascarar[/]",
                default="https://"
            ).strip()
            
            if not url_original.startswith(('http://', 'https://')):
                url_original = 'https://' + url_original
            
            dominio_personalizado = Prompt.ask(
                "[b]Domínio personalizado (deixe em branco para gerar aleatório)[/]",
                default=""
            ).strip()
            
            tecnica = Prompt.ask(
                "[b]Técnica de ofuscação[/]",
                choices=["base64", "dupla", "nenhuma"],
                default="base64"
            )
            
            # Simula processamento com barra de progresso
            with Progress(transient=True) as progress:
                task = progress.add_task("[cyan]Gerando URL mascarada...", total=100)
                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.02)
            
            # Gera a URL mascarada
            url_mascarada, chave = gerar_url_mascarada(
                url_original,
                dominio_personalizado if dominio_personalizado else None,
                tecnica
            )
            
            # Adiciona ao histórico
            historico.append({
                'data': time.strftime("%Y-%m-%d %H:%M"),
                'dominio': urlparse(url_mascarada).netloc,
                'original': url_original,
                'mascarada': url_mascarada,
                'chave': chave
            })
            
            # Exibe resultados
            console.print("\n" + Panel.fit(
                f"[b]URL Original:[/]\n[white]{url_original}[/]\n\n"
                f"[b]URL Mascarada:[/]\n[yellow]{url_mascarada}[/]\n\n"
                f"[b]Chave de Descriptografia:[/]\n[dim]{chave}[/]",
                title="✅ Resultado",
                border_style=COLORS[THEME]["success"],
                padding=(1, 2)
            ))
            
            # Copia para área de transferência
            pyperclip.copy(url_mascarada)
            console.print("\n📋 [green]URL mascarada copiada para a área de transferência!")
            
            # Mostra QR Code
            if Confirm.ask("\n[b]Deseja gerar um QR Code para esta URL?"):
                mostrar_qrcode(url_mascarada)
        
        elif opcao == "2":
            # Mostrar histórico
            if historico:
                mostrar_historico(historico)
                
                # Opção para ver detalhes de um item
                if Confirm.ask("\n[b]Deseja ver detalhes de alguma URL?"):
                    indice = Prompt.ask(
                        "[b]Digite o número do item (1-5)[/]",
                        choices=["1", "2", "3", "4", "5"],
                        default="1"
                    )
                    item = historico[-int(indice)]
                    
                    console.print("\n" + Panel.fit(
                        f"[b]Data:[/] {item['data']}\n"
                        f"[b]Domínio:[/] {item['dominio']}\n"
                        f"[b]Original:[/] {item['original']}\n"
                        f"[b]Mascarada:[/] {item['mascarada']}\n"
                        f"[b]Chave:[/] [dim]{item['chave']}[/]",
                        title="🔍 Detalhes",
                        border_style=COLORS[THEME]["info"],
                        padding=(1, 2)
                    ))
            else:
                console.print("\n" + Panel.fit(
                    "[red]Nenhum item no histórico ainda!",
                    border_style=COLORS[THEME]["error"]
                ))
        
        elif opcao == "3":
            # Sair
            console.print("\n" + Panel.fit(
                "[green]Obrigado por usar o URL Masker Pro!",
                border_style=COLORS[THEME]["success"]
            ))
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n" + Panel.fit(
            "[red]Operação cancelada pelo usuário.",
            border_style=COLORS[THEME]["error"]
        ))
    except Exception as e:
        console.print("\n" + Panel.fit(
            f"[red]Erro: {str(e)}",
            border_style=COLORS[THEME]["error"],
            title="⚠️ Erro"
        ))
