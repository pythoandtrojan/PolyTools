#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import json
import re
from typing import List, Dict

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn
from rich.text import Text

console = Console()

class WiFiScanner:
    def __init__(self):
        self.interface = "wlan0"
        self.monitor_interface = None
        
    def verificar_root(self) -> bool:
        """Verifica se o usuário tem permissões root"""
        try:
            return os.geteuid() == 0
        except:
            return False
    
    def verificar_ferramentas(self) -> bool:
        """Verifica se as ferramentas necessárias estão instaladas"""
        try:
            subprocess.run(['iwconfig', '--version'], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         check=True)
            return True
        except:
            return False
    
    def detectar_interfaces_wifi(self) -> List[str]:
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
    
    def escanear_redes_wifi(self, interface: str) -> List[Dict]:
        """Escaneia redes WiFi próximas"""
        redes = []
        
        try:
            # Tentar colocar interface em modo monitor
            subprocess.run(['airmon-ng', 'check', 'kill'], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         check=False)
            
            subprocess.run(['airmon-ng', 'start', interface], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         check=False)
            
            self.monitor_interface = f"{interface}mon"
            
            # Escanear redes por 10 segundos
            console.print("[yellow]Escaneando redes WiFi... (10 segundos)[/yellow]")
            
            cmd = ['airodump-ng', '-w', '/tmp/wifi_scan', '--output-format', 'json', self.monitor_interface]
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(10)
            process.terminate()
            
            # Ler resultados do scan
            try:
                with open('/tmp/wifi_scan-01.json', 'r') as f:
                    data = json.load(f)
                    for ap in data.get('aps', []):
                        rede = {
                            'bssid': ap.get('bssid', 'N/A'),
                            'ssid': ap.get('essid', 'Hidden'),
                            'channel': ap.get('channel', 'N/A'),
                            'power': ap.get('power', 'N/A'),
                            'encryption': ap.get('encryption', 'N/A'),
                            'clients': len(ap.get('stations', []))
                        }
                        redes.append(rede)
            except:
                console.print("[red]Erro ao ler resultados do scan[/red]")
                
        except Exception as e:
            console.print(f"[red]Erro durante o scan: {str(e)}[/red]")
        
        finally:
            # Voltar para modo managed
            if self.monitor_interface:
                subprocess.run(['airmon-ng', 'stop', self.monitor_interface], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL, 
                             check=False)
        
        return redes
    
    def escanear_simples(self) -> List[Dict]:
        """Método simples de scan sem modo monitor"""
        redes = []
        try:
            console.print("[yellow]Escaneando redes WiFi...[/yellow]")
            
            # Usar iwlist para scan simples
            result = subprocess.run(['iwlist', 'wlan0', 'scan'], 
                                  capture_output=True, text=True, check=True)
            
            lines = result.stdout.split('\n')
            current_ap = {}
            
            for line in lines:
                line = line.strip()
                
                if 'Cell' in line and 'Address' in line:
                    if current_ap:
                        redes.append(current_ap)
                    current_ap = {'bssid': line.split('Address: ')[1]}
                
                elif 'ESSID:' in line:
                    ssid = line.split('ESSID:"')[1].split('"')[0]
                    current_ap['ssid'] = ssid if ssid else 'Hidden'
                
                elif 'Channel:' in line:
                    current_ap['channel'] = line.split('Channel:')[1].strip()
                
                elif 'Quality=' in line:
                    parts = line.split()
                    for part in parts:
                        if 'Quality=' in part:
                            current_ap['quality'] = part.split('=')[1]
                        elif 'level=' in part:
                            current_ap['power'] = part.split('=')[1]
                
                elif 'Encryption key:' in line:
                    current_ap['encryption'] = 'Enabled' if 'on' in line else 'Disabled'
            
            if current_ap:
                redes.append(current_ap)
                
        except Exception as e:
            console.print(f"[red]Erro no scan simples: {str(e)}[/red]")
        
        return redes
    
    def mostrar_resultados(self, redes: List[Dict]):
        """Mostra os resultados do scan em uma tabela"""
        if not redes:
            console.print("[red]Nenhuma rede WiFi encontrada![/red]")
            return
        
        console.print(Panel.fit(
            f"[green]✅ Found {len(redes)} WiFi networks[/green]",
            border_style="green"
        ))
        
        tabela = Table(title="Redes WiFi Disponíveis", show_header=True, header_style="bold magenta")
        tabela.add_column("#", style="cyan", width=4)
        tabela.add_column("SSID", style="green")
        tabela.add_column("BSSID", style="yellow")
        tabela.add_column("Canal", style="blue")
        tabela.add_column("Sinal", style="red")
        tabela.add_column("Proteção", style="magenta")
        
        for i, rede in enumerate(redes, 1):
            ssid = rede.get('ssid', 'Hidden')[:20] + '...' if len(rede.get('ssid', '')) > 20 else rede.get('ssid', 'Hidden')
            bssid = rede.get('bssid', 'N/A')[:8] + '...'
            channel = rede.get('channel', 'N/A')
            
            # Processar informação de sinal
            power = rede.get('power', 'N/A')
            if power != 'N/A' and '/' in power:
                power_value = int(power.split('/')[0])
                power_display = f"{power_value} dBm"
            else:
                power_display = power
            
            # Processar informação de criptografia
            encryption = rede.get('encryption', 'N/A')
            if 'WPA2' in encryption:
                encryption_icon = "🔒 WPA2"
            elif 'WPA' in encryption:
                encryption_icon = "🔐 WPA"
            elif 'WEP' in encryption:
                encryption_icon = "🔓 WEP"
            elif encryption == 'Enabled':
                encryption_icon = "❓ Unknown"
            elif encryption == 'Disabled':
                encryption_icon = "🚫 Open"
            else:
                encryption_icon = encryption
            
            tabela.add_row(
                str(i),
                ssid,
                bssid,
                channel,
                power_display,
                encryption_icon
            )
        
        console.print(tabela)
        
        console.print(Panel.fit(
            "[yellow]💡 Dica: Use 'iwlist wlan0 scan' para mais detalhes[/yellow]",
            border_style="yellow"
        ))
    
    def executar_scan(self):
        """Executa o scan de redes WiFi"""
        console.print(Panel.fit(
            "[bold]📡 Scanner de Redes WiFi[/bold]",
            border_style="cyan"
        ))
        
        # Verificar se estamos no Termux
        if not os.path.exists('/data/data/com.termux/files/home'):
            console.print("[yellow]⚠️  Este script é otimizado para Termux[/yellow]")
        
        # Verificar ferramentas
        if not self.verificar_ferramentas():
            console.print(Panel.fit(
                "[red]Ferramentas de wireless não encontradas![/red]\n"
                "Instale com: pkg install wireless-tools",
                border_style="red"
            ))
            return False
        
        # Detectar interfaces
        interfaces = self.detectar_interfaces_wifi()
        if not interfaces:
            console.print("[red]Nenhuma interface WiFi encontrada![/red]")
            console.print("Certifique-se de que:")
            console.print("1. Seu dispositivo tem WiFi")
            console.print("2. O WiFi está ativado")
            console.print("3. Você tem permissões adequadas")
            return False
        
        console.print(Panel.fit(
            f"[green]Interfaces WiFi detectadas: {', '.join(interfaces)}[/green]",
            title="Interfaces de Rede"
        ))
        
        # Tentar scan avançado primeiro
        redes = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task("Procurando redes WiFi...", total=None)
            
            try:
                redes = self.escanear_redes_wifi(interfaces[0])
            except:
                console.print("[yellow]Scan avançado falhou, tentando método simples...[/yellow]")
                redes = self.escanear_simples()
        
        # Mostrar resultados
        self.mostrar_resultados(redes)
        
        return True

def main():
    scanner = WiFiScanner()
    
    try:
        scanner.executar_scan()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrompido pelo usuário[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Erro: {str(e)}[/red]")

if __name__ == '__main__':
    main()
