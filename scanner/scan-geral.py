#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import threading
import subprocess
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

console = Console()

class WiFiAutoScanner:
    def __init__(self):
        self.network_info = {}
        self.discovered_hosts = []
        self.scan_results = {}
        self.scan_stats = {
            'total_hosts': 0,
            'responsive_hosts': 0,
            'open_ports': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Portas comuns para escaneamento
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
            443, 445, 993, 995, 1433, 1521, 1723, 1900, 
            2049, 2121, 3306, 3389, 3632, 4369, 5000, 
            5353, 5432, 5555, 5601, 5900, 6000, 6379, 
            6667, 8000, 8080, 8200, 8443, 8888, 9000, 
            9200, 27017, 47808
        ]
    
    def get_wifi_info(self):
        """Obtém informações da rede WiFi atual"""
        try:
            # Para Termux/Android
            try:
                result = subprocess.run(['termux-wifi-connectioninfo'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    wifi_info = json.loads(result.stdout)
                    self.network_info = {
                        'ssid': wifi_info.get('ssid', 'Desconhecido'),
                        'bssid': wifi_info.get('bssid', 'Desconhecido'),
                        'ip': wifi_info.get('ip', 'Desconhecido'),
                        'subnet_mask': '255.255.255.0'  # Padrão comum
                    }
                    return True
            except:
                pass
            
            # Para Linux tradicional
            try:
                # Obtém interface WiFi ativa
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'default' in line and 'wlan' in line:
                        parts = line.split()
                        interface = parts[4]
                        
                        # Obtém IP e mascara
                        result = subprocess.run(['ip', '-4', 'addr', 'show', interface], 
                                              capture_output=True, text=True)
                        ip_line = [l for l in result.stdout.split('\n') if 'inet ' in l]
                        if ip_line:
                            ip_info = ip_line[0].split()
                            ip = ip_info[1].split('/')[0]
                            subnet_mask = self.cidr_to_mask(int(ip_info[1].split('/')[1]))
                            
                            # Tenta obter SSID
                            ssid = "Desconhecido"
                            try:
                                result = subprocess.run(['iwgetid', '-r'], 
                                                      capture_output=True, text=True)
                                if result.returncode == 0:
                                    ssid = result.stdout.strip()
                            except:
                                pass
                            
                            self.network_info = {
                                'ssid': ssid,
                                'interface': interface,
                                'ip': ip,
                                'subnet_mask': subnet_mask
                            }
                            return True
            except:
                pass
            
            console.print("[yellow]⚠️  Não foi possível obter informações WiFi automaticamente[/yellow]")
            return False
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao obter informações WiFi: {e}[/red]")
            return False
    
    def cidr_to_mask(self, cidr):
        """Converte notação CIDR para mascara de sub-rede"""
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return socket.inet_ntoa(struct.pack('>I', mask))
    
    def discover_network_range(self):
        """Descobre o range da rede baseado no IP e mascara"""
        try:
            if not self.network_info.get('ip') or not self.network_info.get('subnet_mask'):
                console.print("[red]❌ Informações de rede insuficientes[/red]")
                return None
            
            ip = self.network_info['ip']
            mask = self.network_info['subnet_mask']
            
            # Calcula network address
            network_addr = self.calculate_network_address(ip, mask)
            if not network_addr:
                return None
            
            # Gera todos os IPs da rede
            network_ips = []
            for i in range(1, 255):  # Exclui network e broadcast addresses
                network_ips.append(f"{network_addr.rsplit('.', 1)[0]}.{i}")
            
            return network_ips
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao calcular range da rede: {e}[/red]")
            return None
    
    def calculate_network_address(self, ip, mask):
        """Calcula o endereço de rede"""
        try:
            ip_octets = list(map(int, ip.split('.')))
            mask_octets = list(map(int, mask.split('.')))
            
            network_octets = []
            for i in range(4):
                network_octets.append(str(ip_octets[i] & mask_octets[i]))
            
            return '.'.join(network_octets)
        except:
            return None
    
    def ping_sweep(self, ip_list, timeout=1):
        """Varredura ping para descobrir hosts ativos"""
        responsive_hosts = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.ping_host, ip, timeout): ip for ip in ip_list}
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                transient=True,
            ) as progress:
                task = progress.add_task("Descobrindo hosts ativos...", total=len(ip_list))
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            responsive_hosts.append(ip)
                            console.print(f"[green]✅ Host ativo: {ip}[/green]")
                    except:
                        pass
                    progress.update(task, advance=1)
        
        return responsive_hosts
    
    def ping_host(self, ip, timeout=1):
        """Verifica se um host está respondendo a ping"""
        try:
            # Usando ping com count=1 e timeout
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), ip],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except:
            return False
    
    def port_scan_host(self, host, ports, timeout=2):
        """Escaneia portas em um host específico"""
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.check_port, host, port, timeout): port for port in ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        open_ports[port] = result
                except:
                    pass
        
        return open_ports
    
    def check_port(self, host, port, timeout=2):
        """Verifica se uma porta está aberta"""
        result = {'port': port, 'status': 'closed', 'service': 'unknown', 'banner': ''}
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                connection_result = sock.connect_ex((host, port))
                
                if connection_result == 0:
                    result['status'] = 'open'
                    
                    # Tenta obter banner
                    try:
                        if port in [80, 443, 8000, 8080, 8443, 8888, 9000]:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        elif port == 21:
                            sock.send(b'USER anonymous\r\n')
                        elif port == 22:
                            sock.send(b'SSH-2.0-OpenSSH_7.4\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            result['banner'] = banner.strip()[:200]
                    except:
                        pass
                    
                    # Identifica serviço
                    result['service'] = self.identify_service(port, result['banner'])
        
        except:
            pass
        
        return result
    
    def identify_service(self, port, banner=""):
        """Identifica serviços baseado na porta e banner"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            5555: 'ADB', 9200: 'Elasticsearch', 27017: 'MongoDB'
        }
        
        service = service_map.get(port, 'unknown')
        
        # Refina com base no banner
        if banner:
            banner_lower = banner.lower()
            if 'apache' in banner_lower:
                service = 'Apache'
            elif 'nginx' in banner_lower:
                service = 'Nginx'
            elif 'iis' in banner_lower:
                service = 'IIS'
        
        return service
    
    def os_detection(self, host):
        """Tenta detectar o sistema operacional do host"""
        try:
            # Testa TTL
            result = subprocess.run(
                ['ping', '-c', '1', host],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if 'ttl=' in result.stdout.lower():
                ttl_line = [line for line in result.stdout.split('\n') if 'ttl=' in line.lower()]
                if ttl_line:
                    ttl = int(ttl_line[0].split('ttl=')[1].split()[0])
                    
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    elif ttl <= 255:
                        return "Solaris/AIX"
            
            return "Desconhecido"
        except:
            return "Desconhecido"
    
    def comprehensive_scan(self):
        """Escaneamento completo automático"""
        self.scan_stats['start_time'] = time.time()
        
        # Obtém informações da WiFi
        console.print(Panel.fit(
            "[bold]📡 OBTENDO INFORMAÇÕES DA REDE WiFi[/bold]",
            border_style="blue"
        ))
        
        if not self.get_wifi_info():
            console.print("[red]❌ Não foi possível obter informações da rede[/red]")
            return False
        
        console.print(Panel.fit(
            f"[bold]📋 INFORMAÇÕES DA REDE:[/bold]\n\n"
            f"📶 SSID: {self.network_info.get('ssid', 'Desconhecido')}\n"
            f"🌐 IP Local: {self.network_info.get('ip', 'Desconhecido')}\n"
            f"🔧 Interface: {self.network_info.get('interface', 'Desconhecida')}\n"
            f"🎯 Mascara: {self.network_info.get('subnet_mask', 'Desconhecida')}",
            border_style="green"
        ))
        
        # Descobre range da rede
        console.print("[bold]🔍 CALCULANDO RANGE DA REDE...[/bold]")
        network_ips = self.discover_network_range()
        if not network_ips:
            console.print("[red]❌ Não foi possível determinar o range da rede[/red]")
            return False
        
        console.print(f"[green]✅ Range da rede: {len(network_ips)} IPs para escanear[/green]")
        
        # Descobre hosts ativos
        console.print(Panel.fit(
            "[bold]🔎 PROCURANDO HOSTS ATIVOS[/bold]",
            border_style="blue"
        ))
        
        responsive_hosts = self.ping_sweep(network_ips)
        self.scan_stats['responsive_hosts'] = len(responsive_hosts)
        self.scan_stats['total_hosts'] = len(network_ips)
        
        if not responsive_hosts:
            console.print("[yellow]⚠️  Nenhum host ativo encontrado[/yellow]")
            return True
        
        console.print(f"[green]✅ {len(responsive_hosts)} hosts ativos encontrados[/green]")
        
        # Escaneia portas nos hosts ativos
        console.print(Panel.fit(
            "[bold]🚪 ESCANEANDO PORTAS NOS HOSTS[/bold]",
            border_style="blue"
        ))
        
        all_results = {}
        for host in responsive_hosts:
            console.print(f"[bold]🔍 Escaneando {host}...[/bold]")
            open_ports = self.port_scan_host(host, self.common_ports)
            
            if open_ports:
                host_info = {
                    'ports': open_ports,
                    'os': self.os_detection(host),
                    'hostname': self.resolve_hostname(host)
                }
                all_results[host] = host_info
                self.scan_stats['open_ports'] += len(open_ports)
                
                console.print(Panel.fit(
                    f"[green]✅ {host} - {len(open_ports)} portas abertas[/green]\n"
                    f"🖥️  OS: {host_info['os']}\n"
                    f"🏷️  Hostname: {host_info['hostname']}",
                    border_style="green"
                ))
        
        self.scan_results = all_results
        self.scan_stats['end_time'] = time.time()
        
        return True
    
    def resolve_hostname(self, ip):
        """Tenta resolver o hostname do IP"""
        try:
            hostname = socket.getfqdn(ip)
            return hostname if hostname != ip else "Não resolvido"
        except:
            return "Erro na resolução"
    
    def generate_report(self):
        """Gera relatório completo dos resultados"""
        if not self.scan_results:
            console.print("[yellow]⚠️  Nenhum resultado para reportar[/yellow]")
            return
        
        total_time = self.scan_stats['end_time'] - self.scan_stats['start_time']
        
        console.print(Panel.fit(
            f"[bold]📊 RELATÓRIO COMPLETO DO ESCANEAMENTO[/bold]\n\n"
            f"📶 Rede: {self.network_info.get('ssid', 'Desconhecida')}\n"
            f"⏰ Tempo total: {total_time:.2f} segundos\n"
            f"🌐 IPs verificados: {self.scan_stats['total_hosts']}\n"
            f"✅ Hosts ativos: {self.scan_stats['responsive_hosts']}\n"
            f"🚪 Portas abertas: {self.scan_stats['open_ports']}",
            title="[green]ESTATÍSTICAS GERAIS[/green]",
            border_style="green"
        ))
        
        # Detalhes por host
        for host, data in self.scan_results.items():
            console.print(Panel.fit(
                f"[bold]🎯 HOST: {host}[/bold]\n"
                f"🖥️  Sistema Operacional: {data['os']}\n"
                f"🏷️  Hostname: {data['hostname']}\n"
                f"🚪 Portas abertas: {len(data['ports'])}",
                border_style="blue"
            ))
            
            if data['ports']:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Porta", style="cyan")
                table.add_column("Serviço", style="green")
                table.add_column("Status", style="yellow")
                table.add_column("Banner", style="white")
                
                for port, info in data['ports'].items():
                    table.add_row(
                        str(port),
                        info['service'],
                        info['status'],
                        info['banner'][:50] + "..." if len(info['banner']) > 50 else info['banner']
                    )
                
                console.print(table)
            
            console.print("")  # Espaço entre hosts
        
        # Estatísticas de serviços
        service_stats = {}
        for host_data in self.scan_results.values():
            for port_info in host_data['ports'].values():
                service = port_info['service']
                service_stats[service] = service_stats.get(service, 0) + 1
        
        if service_stats:
            console.print(Panel.fit(
                "[bold]📈 ESTATÍSTICAS DE SERVIÇOS[/bold]\n\n" +
                "\n".join([f"• {service}: {count} ocorrências" 
                          for service, count in service_stats.items()]),
                border_style="cyan"
            ))
    
    def save_results(self, filename=None):
        """Salva os resultados em um arquivo"""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_scan_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("RELATÓRIO DE ESCANEAMENTO WiFi\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"Rede: {self.network_info.get('ssid', 'Desconhecida')}\n")
                f.write(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"IPs verificados: {self.scan_stats['total_hosts']}\n")
                f.write(f"Hosts ativos: {self.scan_stats['responsive_hosts']}\n")
                f.write(f"Portas abertas: {self.scan_stats['open_ports']}\n\n")
                
                for host, data in self.scan_results.items():
                    f.write(f"[HOST] {host}\n")
                    f.write(f"  OS: {data['os']}\n")
                    f.write(f"  Hostname: {data['hostname']}\n")
                    
                    if data['ports']:
                        f.write("  PORTAS ABERTAS:\n")
                        for port, info in data['ports'].items():
                            f.write(f"    {port} ({info['service']}) - {info['banner']}\n")
                    f.write("\n")
            
            console.print(f"[green]✅ Relatório salvo como: {filename}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao salvar relatório: {e}[/red]")
            return False

class WiFiScannerPanel:
    def __init__(self):
        self.scanner = WiFiAutoScanner()
        self.banner = """
[bold red]
    ╦ ╦╦╔╗╔╔═╗  ╔═╗ ┬ ┬┌─┐┌─┐┌─┐┬─┐  ╔═╗┌─┐┌─┐┌┬┐┌─┐┌─┐
    ║║║║║║║║ ║  ║═╬╗│ │├┤ ├─┤├┤ ├┬┘  ║╣ ┌─┘├─┤│││├┤ └─┐
    ╚╩╝╩╝╚╝╚═╝  ╚═╝╚└─┘└─┘┴ ┴└─┘┴└─  ╚═╝└─┘┴ ┴┴ ┴└─┘└─┘
[/bold red]
[bold white on red]        SCANNER AUTOMÁTICO DE REDE WiFi - ESCANEAMENTO COMPLETO[/bold white on red]
"""
    
    def show_menu(self):
        """Menu principal"""
        while True:
            console.clear()
            console.print(self.banner)
            
            table = Table(
                title="[bold cyan]🎭 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Escaneamento Automático Completo", "🚀")
            table.add_row("2", "Apenas Descobrir Hosts Ativos", "🔍")
            table.add_row("3", "Ver Informações da Rede WiFi", "📡")
            table.add_row("4", "Salvar Resultados", "💾")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False
            )
            
            if choice == "1":
                self.full_auto_scan()
            elif choice == "2":
                self.host_discovery_only()
            elif choice == "3":
                self.show_wifi_info()
            elif choice == "4":
                self.save_results()
            elif choice == "0":
                self.exit_program()
    
    def full_auto_scan(self):
        """Escaneamento automático completo"""
        console.print(Panel.fit(
            "[bold]🚀 ESCANEAMENTO AUTOMÁTICO COMPLETO[/bold]",
            border_style="blue"
        ))
        
        console.print("[yellow]⚠️  Este processo pode levar vários minutos...[/yellow]")
        
        if not Confirm.ask("[yellow]?[/yellow] Iniciar escaneamento completo?"):
            return
        
        try:
            success = self.scanner.comprehensive_scan()
            
            if success:
                console.print(Panel.fit(
                    "[green]✅ Escaneamento concluído com sucesso![/green]",
                    border_style="green"
                ))
                
                # Mostra relatório
                self.scanner.generate_report()
                
                # Pergunta se quer salvar
                if Confirm.ask("[yellow]?[/yellow] Deseja salvar os resultados?"):
                    filename = Prompt.ask(
                        "[yellow]?[/yellow] Nome do arquivo (Enter para padrão)"
                    )
                    if not filename:
                        self.scanner.save_results()
                    else:
                        self.scanner.save_results(filename)
            else:
                console.print("[red]❌ Escaneamento falhou[/red]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]⏹️ Escaneamento interrompido pelo usuário[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Erro durante o escaneamento: {e}[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def host_discovery_only(self):
        """Apenas descobre hosts ativos"""
        console.print(Panel.fit(
            "[bold]🔍 DESCOBERTA DE HOSTS ATIVOS[/bold]",
            border_style="blue"
        ))
        
        # Obtém informações da WiFi primeiro
        if not self.scanner.get_wifi_info():
            console.print("[red]❌ Não foi possível obter informações da rede[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        # Descobre range da rede
        network_ips = self.scanner.discover_network_range()
        if not network_ips:
            console.print("[red]❌ Não foi possível determinar o range da rede[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        timeout = IntPrompt.ask(
            "[yellow]?[/yellow] Timeout do ping (segundos)",
            default=1
        )
        
        console.print(f"[bold]🔎 Procurando hosts em {len(network_ips)} IPs...[/bold]")
        responsive_hosts = self.scanner.ping_sweep(network_ips, timeout)
        
        if responsive_hosts:
            console.print(Panel.fit(
                f"[green]✅ {len(responsive_hosts)} HOSTS ATIVOS ENCONTRADOS:[/green]\n\n" +
                "\n".join(responsive_hosts),
                border_style="green"
            ))
        else:
            console.print("[yellow]⚠️  Nenhum host ativo encontrado[/yellow]")
        
        input("\nPressione Enter para voltar...")
    
    def show_wifi_info(self):
        """Mostra informações da rede WiFi"""
        console.print(Panel.fit(
            "[bold]📡 INFORMAÇÕES DA REDE WiFi[/bold]",
            border_style="blue"
        ))
        
        if self.scanner.get_wifi_info():
            console.print(Panel.fit(
                f"[bold]📋 INFORMAÇÕES DA REDE:[/bold]\n\n"
                f"📶 SSID: {self.scanner.network_info.get('ssid', 'Desconhecido')}\n"
                f"🌐 IP Local: {self.scanner.network_info.get('ip', 'Desconhecido')}\n"
                f"🔧 Interface: {self.scanner.network_info.get('interface', 'Desconhecida')}\n"
                f"🎯 Mascara: {self.scanner.network_info.get('subnet_mask', 'Desconhecida')}\n"
                f"📡 BSSID: {self.scanner.network_info.get('bssid', 'Desconhecido')}",
                border_style="green"
            ))
        else:
            console.print("[red]❌ Não foi possível obter informações da rede[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def save_results(self):
        """Salva os resultados atuais"""
        if not self.scanner.scan_results:
            console.print("[yellow]⚠️  Nenhum resultado disponível para salvar[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        filename = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo (Enter para padrão)"
        )
        
        if self.scanner.save_results(filename):
            console.print("[green]✅ Resultados salvos com sucesso![/green]")
        else:
            console.print("[red]❌ Erro ao salvar resultados[/red]")
        
        input("\nPressione Enter para voltar...")
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: ESCANEAMENTO NÃO AUTORIZADO É CRIME! ⚠️[/blink bold red]\n\n"
            "Este tool é apenas para:\n"
            "• Testes em redes próprias\n"
            "• Auditorias de segurança autorizadas\n"
            "• Diagnóstico de problemas de rede",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        # Verifica se está no Termux
        try:
            subprocess.run(['termux-wifi-connectioninfo'], 
                         capture_output=True, check=True)
            console.print("[green]✅ Ambiente Termux detectado[/green]")
        except:
            console.print("[yellow]⚠️  Ambiente não-Termux, algumas funcionalidades podem ser limitadas[/yellow]")
        
        panel = WiFiScannerPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
