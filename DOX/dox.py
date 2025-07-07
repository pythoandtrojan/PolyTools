import os
import sys
import socket
import webbrowser
from time import sleep
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress
import requests

console = Console()

class ValkiriaTool:
    def __init__(self):
        self.web_dir = "valkiria_web"
        self.telegram_link = "n tem ainda porra"
        self.discord_link = "https://discord.gg/ESDFpyyj"
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    
    def generate_blood_banner(self):
        return """
[bold red]
          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'          `98v8P'          `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
[bold white]╔═════════════════════════════════════════════════════════════════════════╗
║[bold red]    R E D E   V A L K I R I A  -  C A Ç A N D O   O S   M A L D I T O S    [bold white]║
╚═════════════════════════════════════════════════════════════════════════╝
"""
    
    def create_web_interface(self):
        if not os.path.exists(self.web_dir):
            os.makedirs(self.web_dir)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valkiria - Justiça nas Sombras</title>
    <style>
        body {{
            background-color: #000;
            color: #c00;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 0;
            background-image: url('https://i.imgur.com/X9Q6ZQj.jpg');
            background-size: cover;
            background-attachment: fixed;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: rgba(0, 0, 0, 0.8);
            border: 1px solid #300;
            box-shadow: 0 0 20px #f00;
            margin-top: 50px;
        }}
        h1 {{
            color: #f00;
            text-shadow: 0 0 10px #f00;
            text-align: center;
            border-bottom: 1px solid #f00;
            padding-bottom: 10px;
        }}
        .warning {{
            background-color: #300;
            border-left: 5px solid #f00;
            padding: 15px;
            margin: 20px 0;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.7); }}
            70% {{ box-shadow: 0 0 0 10px rgba(255, 0, 0, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); }}
        }}
        .links {{
            display: flex;
            justify-content: space-around;
            margin-top: 30px;
        }}
        a {{
            color: #f00;
            text-decoration: none;
            font-weight: bold;
            padding: 10px 20px;
            border: 1px solid #f00;
            transition: all 0.3s;
        }}
        a:hover {{
            background-color: #f00;
            color: #000;
        }}
        .counter {{
            text-align: center;
            font-size: 24px;
            margin: 20px 0;
        }}
        .quote {{
            font-style: italic;
            text-align: center;
            margin: 30px 0;
            color: #900;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>REDE VALKIRIA - JUSTIÇA NAS SOMBRAS</h1>
        
        <div class="warning">
            <h2>AVISO AOS PEDÓFILOS E CRIMINOSOS</h2>
            <p>Nós sabemos quem você é. Nós sabemos o que você fez. Seu tempo está acabando.</p>
            <p>A Valkiria não esquece, não perdoa e não para. Você será exposto e enfrentará as consequências.</p>
        </div>
        
        <div class="quote">
            "O mal triunfa quando os bons não fazem nada. Nós não somos bons. Nós somos piores."
        </div>
        
        <p>A Rede Valkiria é um coletivo dedicado a identificar, expor e neutralizar pedófilos, criminosos sexuais e outros elementos perigosos da sociedade. Operamos nas sombras, mas nosso impacto é sentido na luz.</p>
        
        <h2>COMO FUNCIONAMOS:</h2>
        <ul>
            <li>Coletamos e analisamos dados de fontes abertas e fechadas</li>
            <li>Investigamos profundamente suspeitos</li>
            <li>Compartilhamos informações com autoridades e comunidades</li>
            <li>Aplicamos pressão social e digital sobre os culpados</li>
        </ul>
        
        <div class="counter">
            PEDÓFILOS EXPOSTOS: <span id="counter">1278</span>
        </div>
        
        <div class="links">
            <a href="{self.telegram_link}" target="_blank">TELEGRAM</a>
            <a href="{self.discord_link}" target="_blank">DISCORD</a>
            <a href="#" onclick="alert('Acesso negado. Você não tem permissão.')">RELATÓRIOS</a>
        </div>
    </div>
    
    <script>
        // Contador animado
        let count = 1278;
        setInterval(() => {{
            count++;
            document.getElementById('counter').innerText = count;
        }}, 60000);
        
        // Efeito de digitação
        const elements = document.querySelectorAll('p, li');
        elements.forEach(el => {{
            const text = el.innerText;
            el.innerText = '';
            let i = 0;
            const typing = setInterval(() => {{
                if (i < text.length) {{
                    el.innerText += text.charAt(i);
                    i++;
                }} else {{
                    clearInterval(typing);
                }}
            }}, 20);
        }});
    </script>
</body>
</html>
"""
        
        with open(f"{self.web_dir}/index.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # Adicionar alguns arquivos de exemplo de "relatórios"
        report_content = """
=== RELATÓRIO VALKIRIA - CONFIDENCIAL ===
ID: VP-2023-0472
STATUS: ATIVO
ALVO: [REDACTED]
CRIMES: PEDOFILIA, TRÁFICO DE IMAGENS
LOCALIZAÇÃO: [REDACTED]
EVIDÊNCIAS COLETADAS: 127 arquivos, 23 conversas, 8 vítimas identificadas
PRÓXIMOS PASSOS: EXPOSIÇÃO PÚBLICA MARCADA PARA 12/11/2023
"""
        with open(f"{self.web_dir}/report_sample.txt", "w", encoding="utf-8") as f:
            f.write(report_content)
    
    def start_web_server(self):
        try:
            console.print("\n[bold red]Iniciando servidor web local...[/bold red]")
            console.print(f"[bold white]Acesse: [bold green]http://{self.local_ip}:8000[/bold green][/bold white]")
            
            # Verificar se python3 está disponível
            if os.system("which python3 > /dev/null") == 0:
                os.system(f"cd {self.web_dir} && python3 -m http.server 8000 &")
            else:
                os.system(f"cd {self.web_dir} && python -m http.server 8000 &")
            
            sleep(2)
            webbrowser.open(f"http://{self.local_ip}:8000")
        except Exception as e:
            console.print(f"[bold red]Erro ao iniciar servidor: {e}[/bold red]")
    
    def show_menu(self):
        console.print(Panel.fit(Text("""
1 - INICIAR SERVIDOR WEB
2 - COMPARTILHAR RELATÓRIO
3 - ACESSAR GRUPO TELEGRAM
4 - ENTRAR NO DISCORD
5 - SOBRE A VALKIRIA
0 - SAIR
""", justify="center"), title="[bold red]MENU PRINCIPAL[/bold red]"))
    
    def about_valkiria(self):
        console.print(Panel.fit(Text("""
[bold red]REDE VALKIRIA[/bold red]

Nós somos os caçadores das sombras. Operamos onde a lei não alcança, 
onde a justiça falha. Nossa rede é composta por hackers, investigadores 
e informantes dedicados a uma única missão: erradicar a escória da humanidade.

[bold white]NOSSOS ALVOS:[/bold white]
- Pedófilos e predadores sexuais
- Criminosos de guerra
- Traficantes de seres humanos
- Corruptos que destroem vidas

[bold red]NÃO SOMOS JUSTICEIROS[/bold red]
Somos piores. Não acreditamos em redenção para certos crimes.
Acreditamos em exposição, em vergonha, em consequências permanentes.

[bold white]MÉTODOS:[/bold white]
- Doxxing estratégico
- Exposição pública
- Coleta massiva de evidências
- Parcerias com organizações de direitos humanos

[bold red]AVISO:[/bold red]
Não somos heróis. Não queremos ser. 
Somos o pesadelo daqueles que destroem vidas inocentes.
""", justify="left"), title="[bold red]SOBRE NÓS[/bold red]"))
    
    def share_report(self):
        with Progress() as progress:
            task = progress.add_task("[red]Preparando relatório...", total=100)
            
            for i in range(100):
                sleep(0.02)
                progress.update(task, advance=1)
        
        console.print("\n[bold red]RELATÓRIO PRONTO PARA COMPARTILHAMENTO[/bold red]")
        console.print(f"[bold white]Envie para o Telegram: [bold green]{self.telegram_link}[/bold green][/bold white]")
        console.print(f"[bold white]Ou para o Discord: [bold green]{self.discord_link}[/bold green][/bold white]\n")
        
        console.print(Panel.fit(Text("""
[bold red]ATENÇÃO:[/bold red]
- Verifique todas as informações antes de compartilhar
- Certifique-se de ter evidências concretas
- Nunca exponha informações de vítimas
- A Valkiria não se responsabiliza por falsas acusações
""", justify="center"), title="[bold red]DIRETRIZES[/bold red]"))
    
    def run(self):
        console.print(self.generate_blood_banner())
        self.create_web_interface()
        
        while True:
            self.show_menu()
            choice = console.input("[bold red]Valkiria> [/bold red]")
            
            if choice == "1":
                self.start_web_server()
            elif choice == "2":
                self.share_report()
            elif choice == "3":
                console.print(f"\n[bold white]Acesse nosso Telegram: [bold green]{self.telegram_link}[/bold green][/bold white]\n")
                webbrowser.open(self.telegram_link)
            elif choice == "4":
                console.print(f"\n[bold white]Junte-se ao nosso Discord: [bold green]{self.discord_link}[/bold green][/bold white]\n")
                webbrowser.open(self.discord_link)
            elif choice == "5":
                self.about_valkiria()
            elif choice == "0":
                console.print("\n[bold red]Saindo... A escuridão aguarda.[/bold red]\n")
                sys.exit(0)
            else:
                console.print("\n[bold red]Opção inválida. Tente novamente.[/bold red]\n")

if __name__ == "__main__":
    try:
        tool = ValkiriaTool()
        tool.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrompido. A caça continua.[/bold red]\n")
        sys.exit(0)
