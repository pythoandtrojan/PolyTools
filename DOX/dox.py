import os
import sys
import socket
import webbrowser
import json
import platform
import subprocess
from time import sleep
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress
import requests
import discord
from discord_webhook import DiscordWebhook

console = Console()

class ValkiriaTool:
    def __init__(self):
        self.web_dir = "valkiria_web"
        self.reports_dir = "valkiria_reports"
        self.telegram_link = "https://t.me/valkiria_network"
        self.discord_link = "https://discord.gg/ESDFpyyj"
        self.webhook_url = "https://discord.com/api/webhooks/your_webhook_here"
        self.local_ip = self.get_local_ip()
        self.system_info = self.get_system_info()
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
            s.close()
            return IP
        except Exception:
            return '127.0.0.1'
    
    def get_system_info(self):
        return {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "local_ip": self.local_ip
        }

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
    
    def create_directories(self):
        if not os.path.exists(self.web_dir):
            os.makedirs(self.web_dir)
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def create_web_interface(self):
        self.create_directories()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valkiria - Justiça nas Sombras</title>
    <style>
        /* (O estilo permanece o mesmo da versão anterior) */
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
        
        <h2>ENVIAR RELATÓRIO</h2>
        <form id="reportForm">
            <div>
                <label for="target_name">Nome do Alvo:</label>
                <input type="text" id="target_name" name="target_name" required>
            </div>
            <div>
                <label for="target_info">Informações:</label>
                <textarea id="target_info" name="target_info" rows="4" required></textarea>
            </div>
            <div>
                <label for="evidence">Evidências (links):</label>
                <input type="text" id="evidence" name="evidence">
            </div>
            <button type="submit">ENVIAR PARA A VALKIRIA</button>
        </form>
        
        <div class="counter">
            PEDÓFILOS EXPOSTOS: <span id="counter">1872</span>
        </div>
        
        <div class="links">
            <a href="{self.telegram_link}" target="_blank">TELEGRAM</a>
            <a href="{self.discord_link}" target="_blank">DISCORD</a>
            <a href="#" onclick="alert('Acesso apenas para membros verificados')">RELATÓRIOS COMPLETOS</a>
        </div>
    </div>
    
    <script>
        // Contador animado
        let count = 1872;
        setInterval(() => {{
            count++;
            document.getElementById('counter').innerText = count;
        }}, 60000);
        
        // Form submission
        document.getElementById('reportForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            
            const formData = {{
                target_name: document.getElementById('target_name').value,
                target_info: document.getElementById('target_info').value,
                evidence: document.getElementById('evidence').value,
                reporter_ip: await fetch('https://api.ipify.org?format=json').then(res => res.json()).then(data => data.ip)
            }};
            
            fetch('/submit_report', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                }},
                body: JSON.stringify(formData)
            }})
            .then(response => response.json())
            .then(data => {{
                alert('Relatório enviado! ID: ' + data.report_id);
                document.getElementById('reportForm').reset();
            }})
            .catch(error => {{
                console.error('Error:', error);
                alert('Erro ao enviar relatório');
            }});
        }});
    </script>
</body>
</html>
"""
        
        with open(f"{self.web_dir}/index.html", "w", encoding="utf-8") as f:
            f.write(html_content)
    
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
2 - CRIAR RELATÓRIO DOX
3 - ENVIAR RELATÓRIO PARA O DISCORD
4 - ACESSAR GRUPO TELEGRAM
5 - ENTRAR NO DISCORD
6 - SOBRE A VALKIRIA
0 - SAIR
""", justify="center"), title="[bold red]MENU PRINCIPAL[/bold red]"))
    
    def about_valkiria(self):
        console.print(Panel.fit(Text("""
[bold red]REDE VALKIRIA[/bold red]

Nós somos os caçadores das sombras. Operamos onde a lei não alcança, 
onde a justiça falha. Nossa rede é composta por hackers, investigadores 
e informantes dedicados a uma única missão: erradicar a escória da humanidade.

[bold white]MÉTODOS DE COLETA:[/bold white]
- Análise de metadados
- Engenharia social reversa
- Busca em bancos de dados vazados
- Rastreamento de transações digitais
- Geolocalização de imagens

[bold red]AVISO:[/bold red]
Toda informação coletada é verificada por nossa equipe antes 
de ser publicada. Falsas acusações são punidas.
""", justify="left"), title="[bold red]SOBRE NÓS[/bold red]"))
    
    def create_dox_report(self):
        console.print("\n[bold red]CRIAR NOVO RELATÓRIO DOX[/bold red]")
        
        target_name = console.input("[bold red]Nome do Alvo: [/bold red]")
        target_aliases = console.input("[bold white]Apelidos/Alias (separados por vírgula): [/bold white]")
        target_location = console.input("[bold white]Localização conhecida: [/bold white]")
        target_online = console.input("[bold white]Perfis online (redes sociais, fóruns): [/bold white]")
        target_ips = console.input("[bold white]IPs conhecidos (se houver): [/bold white]")
        evidence = console.input("[bold white]Evidências (links, prints, etc): [/bold white]")
        additional_info = console.input("[bold white]Informações adicionais: [/bold white]")
        
        report_data = {
            "target": {
                "name": target_name,
                "aliases": [a.strip() for a in target_aliases.split(",")],
                "location": target_location,
                "online_profiles": target_online,
                "ips": target_ips,
                "evidence": evidence,
                "info": additional_info,
                "reporter_system": self.system_info,
                "timestamp": str(datetime.now())
            }
        }
        
        report_id = f"VK-REPORT-{os.urandom(4).hex().upper()}"
        report_filename = f"{self.reports_dir}/{report_id}.json"
        
        with open(report_filename, "w") as f:
            json.dump(report_data, f, indent=4)
        
        console.print(f"\n[bold green]RELATÓRIO CRIADO COM SUCESSO![/bold green]")
        console.print(f"[bold white]ID do Relatório: [bold red]{report_id}[/bold red][/bold white]")
        console.print(f"[bold white]Arquivo salvo em: [bold yellow]{report_filename}[/bold yellow][/bold white]\n")
        
        return report_filename
    
    def send_to_discord(self, report_file):
        try:
            with open(report_file, "r") as f:
                report_data = json.load(f)
            
            target = report_data["target"]
            
            embed = {
                "title": f"🚨 NOVO RELATÓRIO VALKIRIA - {target['name']}",
                "description": f"**Relatório enviado via sistema automatizado**\nID: `{report_file.split('/')[-1].split('.')[0]}`",
                "color": 16711680,  # Vermelho
                "fields": [
                    {"name": "🔍 Nome do Alvo", "value": target["name"], "inline": True},
                    {"name": "📍 Localização", "value": target["location"], "inline": True},
                    {"name": "🌐 Perfis Online", "value": target["online_profiles"] or "Não informado", "inline": False},
                    {"name": "🖥️ IPs Conhecidos", "value": target["ips"] or "Não informado", "inline": False},
                    {"name": "🔗 Evidências", "value": target["evidence"] or "Não informado", "inline": False},
                    {"name": "📝 Informações Adicionais", "value": target["info"] or "Nenhuma", "inline": False},
                    {"name": "📌 Sistema do Denunciante", "value": f"IP: {target['reporter_system']['local_ip}\nOS: {target['reporter_system']['system']}", "inline": False}
                ],
                "footer": {
                    "text": "Valkiria Network - Justiça nas Sombras"
                }
            }
            
            webhook = DiscordWebhook(url=self.webhook_url, rate_limit_retry=True)
            webhook.add_embed(embed)
            
            with Progress() as progress:
                task = progress.add_task("[red]Enviando para o Discord...", total=100)
                
                response = webhook.execute()
                for i in range(100):
                    sleep(0.01)
                    progress.update(task, advance=1)
            
            if response.status_code == 200:
                console.print("\n[bold green]RELATÓRIO ENVIADO COM SUCESSO PARA O DISCORD![/bold green]")
            else:
                console.print("\n[bold yellow]O relatório foi criado, mas houve um erro ao enviar para o Discord.[/bold yellow]")
                console.print(f"[bold white]Você pode enviar manualmente o arquivo: [bold yellow]{report_file}[/bold yellow][/bold white]")
        
        except Exception as e:
            console.print(f"\n[bold red]Erro ao enviar para o Discord: {e}[/bold red]")
    
    def run(self):
        console.print(self.generate_blood_banner())
        self.create_directories()
        self.create_web_interface()
        
        while True:
            self.show_menu()
            choice = console.input("[bold red]Valkiria> [/bold red]")
            
            if choice == "1":
                self.start_web_server()
            elif choice == "2":
                report_file = self.create_dox_report()
                send = console.input("[bold]Enviar relatório para o Discord agora? (s/n): [/bold]").lower()
                if send == 's':
                    self.send_to_discord(report_file)
            elif choice == "3":
                report_file = console.input("[bold]Caminho completo do relatório a enviar: [/bold]")
                if os.path.exists(report_file):
                    self.send_to_discord(report_file)
                else:
                    console.print("[bold red]Arquivo não encontrado![/bold red]")
            elif choice == "4":
                console.print(f"\n[bold white]Acesse nosso Telegram: [bold green]{self.telegram_link}[/bold green][/bold white]\n")
                webbrowser.open(self.telegram_link)
            elif choice == "5":
                console.print(f"\n[bold white]Junte-se ao nosso Discord: [bold green]{self.discord_link}[/bold green][/bold white]\n")
                webbrowser.open(self.discord_link)
            elif choice == "6":
                self.about_valkiria()
            elif choice == "0":
                console.print("\n[bold red]Saindo... A escuridão aguarda.[/bold red]\n")
                sys.exit(0)
            else:
                console.print("\n[bold red]Opção inválida. Tente novamente.[/bold red]\n")

if __name__ == "__main__":
    try:
        from datetime import datetime
        tool = ValkiriaTool()
        tool.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrompido. A caça continua.[/bold red]\n")
        sys.exit(0)
