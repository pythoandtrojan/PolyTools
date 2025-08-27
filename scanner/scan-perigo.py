#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import threading
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

console = Console()

class DangerousPortScanner:
    def __init__(self):
        # Lista de portas perigosas com descrição e exploits
        self.dangerous_ports = {
            21: {"service": "FTP", "risk": "Alta", "description": "Serviço FTP - Senhas em texto claro"},
            22: {"service": "SSH", "risk": "Média", "description": "Servidor SSH - Bruteforce e vulnerabilidades"},
            23: {"service": "Telnet", "risk": "Alta", "description": "Telnet - Senhas em texto claro"},
            25: {"service": "SMTP", "risk": "Média", "description": "Servidor de email - Possível relay"},
            53: {"service": "DNS", "risk": "Média", "description": "Servidor DNS - Zone transfer attacks"},
            69: {"service": "TFTP", "risk": "Alta", "description": "TFTP - Acesso sem autenticação"},
            79: {"service": "Finger", "risk": "Média", "description": "Serviço Finger - Information disclosure"},
            80: {"service": "HTTP", "risk": "Variável", "description": "Servidor Web - Múltiplas vulnerabilidades"},
            110: {"service": "POP3", "risk": "Média", "description": "POP3 - Senhas em texto claro"},
            111: {"service": "RPC", "risk": "Alta", "description": "Portmapper - Information disclosure"},
            135: {"service": "RPC", "risk": "Alta", "description": "Microsoft RPC - Múltiplas vulnerabilidades"},
            139: {"service": "NetBIOS", "risk": "Alta", "description": "NetBIOS - Information disclosure"},
            143: {"service": "IMAP", "risk": "Média", "description": "IMAP - Senhas em texto claro"},
            161: {"service": "SNMP", "risk": "Alta", "description": "SNMP - Community strings padrão"},
            389: {"service": "LDAP", "risk": "Média", "description": "LDAP - Information disclosure"},
            443: {"service": "HTTPS", "risk": "Variável", "description": "HTTPS - Vulnerabilidades web"},
            445: {"service": "SMB", "risk": "Crítica", "description": "SMB - EternalBlue e outros exploits"},
            512: {"service": "rexec", "risk": "Alta", "description": "Remote execution - Comandos remotos"},
            513: {"service": "rlogin", "risk": "Alta", "description": "Remote login - Autenticação fraca"},
            514: {"service": "rsh", "risk": "Alta", "description": "Remote shell - Comandos remotos"},
            993: {"service": "IMAPS", "risk": "Média", "description": "IMAP SSL - Configurações inadequadas"},
            995: {"service": "POP3S", "risk": "Média", "description": "POP3 SSL - Configurações inadequadas"},
            1433: {"service": "MSSQL", "risk": "Alta", "description": "Microsoft SQL Server - Bruteforce"},
            1521: {"service": "Oracle", "risk": "Alta", "description": "Oracle DB - Contas padrão"},
            1723: {"service": "PPTP", "risk": "Alta", "description": "VPN PPTP - Vulnerabilidades conhecidas"},
            1900: {"service": "UPnP", "risk": "Alta", "description": "UPnP - SSDP amplification"},
            2049: {"service": "NFS", "risk": "Alta", "description": "Network File System - Exportações abertas"},
            2121: {"service": "FTP", "risk": "Alta", "description": "FTP alternativo - Mesmos riscos do FTP"},
            3306: {"service": "MySQL", "risk": "Alta", "description": "MySQL Server - Bruteforce"},
            3389: {"service": "RDP", "risk": "Alta", "description": "Remote Desktop - Bruteforce e vulnerabilidades"},
            3632: {"service": "Distcc", "risk": "Crítica", "description": "Distributed compiler - Remote code execution"},
            4369: {"service": "EPMD", "risk": "Alta", "description": "Erlang Port Mapper - Information disclosure"},
            5000: {"service": "UPnP", "risk": "Alta", "description": "UPnP - Configurações inadequadas"},
            5353: {"service": "mDNS", "risk": "Média", "description": "Multicast DNS - Information disclosure"},
            5432: {"service": "PostgreSQL", "risk": "Alta", "description": "PostgreSQL - Bruteforce"},
            5555: {"service": "ADB", "risk": "Crítica", "description": "Android Debug Bridge - Remote shell access"},
            5601: {"service": "Kibana", "risk": "Alta", "description": "Kibana - Vulnerabilidades conhecidas"},
            5900: {"service": "VNC", "risk": "Alta", "description": "VNC Server - Bruteforce e autenticação fraca"},
            6000: {"service": "X11", "risk": "Alta", "description": "X Window System - Remote access"},
            6379: {"service": "Redis", "risk": "Crítica", "description": "Redis - Acesso sem autenticação"},
            6667: {"service": "IRC", "risk": "Média", "description": "IRC Server - Possível botnet"},
            8000: {"service": "HTTP-Alt", "risk": "Variável", "description": "HTTP Alternativo - Aplicações web"},
            8080: {"service": "HTTP-Proxy", "risk": "Variável", "description": "HTTP Proxy - Configurações inadequadas"},
            8200: {"service": "HTTP-Alt2", "risk": "Variável", "description": "HTTP Alternativo 2 - Aplicações web"},
            8443: {"service": "HTTPS-Alt", "risk": "Variável", "description": "HTTPS Alternativo - Aplicações web"},
            8888: {"service": "HTTP-Alt3", "risk": "Variável", "description": "HTTP Alternativo 3 - Aplicações web"},
            9000: {"service": "HTTP-Alt4", "risk": "Variável", "description": "HTTP Alternativo 4 - Aplicações web"},
            9200: {"service": "Elasticsearch", "risk": "Crítica", "description": "Elasticsearch - Acesso sem autenticação"},
            27017: {"service": "MongoDB", "risk": "Crítica", "description": "MongoDB - Acesso sem autenticação"},
            47808: {"service": "BACnet", "risk": "Alta", "description": "BACnet - Dispositivos IoT vulneráveis"}
        }
        
        self.found_ports = []
        self.scan_stats = {
            'hosts_scanned': 0,
            'dangerous_ports_found': 0,
            'start_time': None,
            'end_time': None
        }
        
    def validate_ip(self, ip):
        """Valida um endereço IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def validate_network(self, network):
        """Valida uma rede no formato CIDR"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    def get_local_networks(self):
        """Obtém redes locais automaticamente"""
        networks = []
        try:
            # Obtém interfaces de rede
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'dev' in line and 'src' in line:
                    parts = line.split()
                    if len(parts) >= 7 and self.validate_network(parts[0]):
                        networks.append(parts[0])
            
            # Remove duplicatas
            networks = list(set(networks))
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao obter redes locais: {e}[/red]")
            
        return networks
    
    def host_discovery(self, network, timeout=1):
        """Descobre hosts ativos na rede"""
        hosts = []
        network_obj = ipaddress.ip_network(network, strict=False)
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {}
            
            for ip in network_obj.hosts():
                ip_str = str(ip)
                futures[executor.submit(self.ping_host, ip_str, timeout)] = ip_str
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        hosts.append(ip)
                        console.print(f"[green]✅ Host ativo: {ip}[/green]")
                except Exception:
                    pass
        
        return hosts
    
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
    
    def check_dangerous_port(self, host, port, timeout=2):
        """Verifica se uma porta perigosa está aberta"""
        result = {
            'host': host,
            'port': port,
            'status': 'closed',
            'service': self.dangerous_ports[port]["service"],
            'risk': self.dangerous_ports[port]["risk"],
            'description': self.dangerous_ports[port]["description"],
            'banner': ''
        }
        
        try:
            # Tentativa de conexão TCP
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
        
        except Exception:
            pass
        
        return result
    
    def scan_dangerous_ports(self, hosts, timeout=2):
        """Escaneia todas as portas perigosas nos hosts fornecidos"""
        self.scan_stats['start_time'] = time.time()
        results = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            
            for host in hosts:
                for port in self.dangerous_ports.keys():
                    futures.append(executor.submit(
                        self.check_dangerous_port, host, port, timeout
                    ))
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                transient=True,
            ) as progress:
                task = progress.add_task("Escaneando portas perigosas...", total=len(futures))
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result['status'] == 'open':
                            results.append(result)
                            self.show_dangerous_port_warning(result)
                        progress.update(task, advance=1)
                    except Exception:
                        progress.update(task, advance=1)
        
        self.scan_stats['end_time'] = time.time()
        self.scan_stats['hosts_scanned'] = len(hosts)
        self.scan_stats['dangerous_ports_found'] = len(results)
        self.found_ports = results
        
        return results
    
    def show_dangerous_port_warning(self, port_info):
        """Mostra alerta detalhado para porta perigosa encontrada"""
        risk_color = {
            "Crítica": "red",
            "Alta": "bright_red", 
            "Média": "yellow",
            "Variável": "cyan"
        }
        
        console.print(Panel.fit(
            f"[bold {risk_color[port_info['risk']]}]⚠️  PORTA PERIGOSA ENCONTRADA![/bold {risk_color[port_info['risk']]}]\n\n"
            f"🎯 [bold]Host:[/bold] {port_info['host']}\n"
            f"🚪 [bold]Porta:[/bold] {port_info['port']} ({port_info['service']})\n"
            f"🔴 [bold]Risco:[/bold] {port_info['risk']}\n"
            f"📝 [bold]Descrição:[/bold] {port_info['description']}\n"
            f"📋 [bold]Banner:[/bold] {port_info['banner'][:100]}{'...' if len(port_info['banner']) > 100 else ''}",
            title=f"[{risk_color[port_info['risk']]}]ALERTA DE SEGURANÇA[/{risk_color[port_info['risk']]}]",
            border_style=risk_color[port_info['risk']]
        ))
        
        # Mostra técnicas de exploração específicas
        self.show_exploitation_techniques(port_info)
    
    def show_exploitation_techniques(self, port_info):
        """Mostra técnicas de exploração específicas para a porta"""
        exploit_info = self.get_exploit_info(port_info['port'])
        
        if exploit_info:
            console.print(Panel.fit(
                f"[bold]🔓 TÉCNICAS DE EXPLORAÇÃO:[/bold]\n\n"
                f"{exploit_info}",
                title="[yellow]INFORMAÇÕES DE EXPLORAÇÃO[/yellow]",
                border_style="yellow"
            ))
    
    def get_exploit_info(self, port):
        """Retorna informações de exploração específicas para a porta"""
        exploits = {
            21: """1. Tentativa de login anonymous/anonymous
2. Bruteforce de credenciais: hydra -l user -P passlist.txt ftp://{host}
3. Verificar configurações de upload anônimo
4. Explorar vulnerabilidades específicas do servidor FTP""",
            
            22: """1. Bruteforce de SSH: hydra -l root -P passlist.txt ssh://{host}
2. Verificar chaves SSH públicas expostas
3. Testar usuários padrão (root, admin, etc.)
4. Explorar vulnerabilidades conhecidas do OpenSSH""",
            
            23: """1. Tentativa de login com credenciais padrão
2. Capturar tráfego para obter credenciais
3. Explorar vulnerabilidades do serviço Telnet""",
            
            445: """1. Verificar compartilhamentos SMB: smbclient -L {host}
2. Testar acesso anônimo: smbclient //{host}/public
3. Explorar EternalBlue (MS17-010) se não estiver patchado
4. Bruteforce de credenciais SMB""",
            
            5555: """1. Conectar via ADB: adb connect {host}:5555
2. Obter shell remoto: adb shell
3. Listar dispositivos: adb devices
4. Instalar APK malicioso: adb install malware.apk
5. Capturar screencast: adb shell screencap /sdcard/screen.png""",
            
            3389: """1. Bruteforce de RDP: hydra -l administrator -P passlist.txt rdp://{host}
2. Explorar vulnerabilidades BlueKeep (CVE-2019-0708)
3. Testar credenciais padrão de fabricante""",
            
            6379: """1. Conectar ao Redis: redis-cli -h {host}
2. Executar comandos: redis-cli FLUSHALL
3. Escrever arquivos: redis-cli config set dir /var/www/html
4. Ganhar shell reverso através do Redis""",
            
            27017: """1. Conectar sem autenticação: mongo {host}:27017
2. Listar databases: show dbs
3. Extrair dados sensíveis
4. Executar comandos JavaScript através do MongoDB""",
            
            9200: """1. Acessar Elasticsearch: curl http://{host}:9200/_search
2. Listar índices: curl http://{host}:9200/_cat/indices
3. Extrair dados sensíveis
4. Executar queries maliciosas"""
        }
        
        # Retorna informação genérica se não houver exploit específico
        default_exploit = """1. Verificar se o serviço está usando credenciais padrão
2. Realizar bruteforce de autenticação
3. Buscar por vulnerabilidades conhecidas específicas da versão
4. Verificar se há informações sensíveis expostas
5. Testar por vulnerabilidades de injection ou RCE"""
        
        return exploits.get(port, default_exploit)
    
    def generate_report(self):
        """Gera relatório dos resultados"""
        if not self.found_ports:
            console.print("[yellow]⚠️  Nenhuma porta perigosa encontrada[/yellow]")
            return
        
        total_time = self.scan_stats['end_time'] - self.scan_stats['start_time']
        
        console.print(Panel.fit(
            f"[bold]📊 RELATÓRIO DE PORTAS PERIGOSAS[/bold]\n\n"
            f"⏰ Tempo total: {total_time:.2f} segundos\n"
            f"🌐 Hosts escaneados: {self.scan_stats['hosts_scanned']}\n"
            f"🔴 Portas perigosas encontradas: {self.scan_stats['dangerous_ports_found']}",
            title="[green]ESTATÍSTICAS[/green]",
            border_style="green"
        ))
        
        # Tabela de portas encontradas
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Host", style="cyan")
        table.add_column("Porta", style="green")
        table.add_column("Serviço", style="yellow")
        table.add_column("Risco", style="red")
        table.add_column("Descrição", style="white")
        
        for port in self.found_ports:
            risk_color = {
                "Crítica": "red",
                "Alta": "bright_red", 
                "Média": "yellow",
                "Variável": "cyan"
            }
            
            table.add_row(
                port['host'],
                str(port['port']),
                port['service'],
                f"[{risk_color[port['risk']]}]{port['risk']}[/{risk_color[port['risk']]}]",
                port['description'][:50] + "..." if len(port['description']) > 50 else port['description']
            )
        
        console.print(table)

class DangerousPortScannerPanel:
    def __init__(self):
        self.scanner = DangerousPortScanner()
        self.banner = """
[bold red]
    ╔═╗┌─┐┌─┐┬ ┬  ╔═╗┌─┐┌─┐┌┬┐┌─┐┌─┐  ╔═╗┌─┐┌─┐┌┬┐┌─┐┌─┐
    ╠═╝├─┤│  ├─┤  ║ ╦│ │├─┘ ││├┤ └─┐  ║ ╦├┤ ├─┤│││├┤ └─┐
    ╩  ┴ ┴└─┘┴ ┴  ╚═╝└─┘┴  ─┴┘└─┘└─┘  ╚═╝└─┘┴ ┴┴ ┴└─┘└─┘
[/bold red]
[bold white on red]        SCANNER DE PORTAS PERIGOSAS COM EXPLORAÇÃO v2.0[/bold white on red]
"""
    
    def show_menu(self):
        """Menu principal"""
        while True:
            console.clear()
            console.print(self.banner)
            
            # Mostra estatísticas rápidas
            stats_panel = Panel.fit(
                f"[cyan]🔍 Portas monitoradas:[/cyan] {len(self.scanner.dangerous_ports)}\n"
                f"[cyan]🚨 Portas críticas:[/cyan] {len([p for p in self.scanner.dangerous_ports.values() if p['risk'] == 'Crítica'])}",
                title="[bold]ESTATÍSTICAS[/bold]",
                border_style="blue"
            )
            console.print(stats_panel)
            
            table = Table(
                title="[bold cyan]🎭 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            table.add_column("Status", style="yellow")
            
            table.add_row("1", "Escaneamento Completo em Rede", "🌐")
            table.add_row("2", "Escaneamento em Host Específico", "🎯")
            table.add_row("3", "Listar Todas as Portas Monitoradas", "📋")
            table.add_row("4", "Testar Porta Específica", "🔍")
            table.add_row("5", "Carregar Redes Automáticas", "📡")
            table.add_row("0", "Sair", "🚪")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if choice == "1":
                self.full_network_scan()
            elif choice == "2":
                self.single_host_scan()
            elif choice == "3":
                self.list_monitored_ports()
            elif choice == "4":
                self.test_specific_port()
            elif choice == "5":
                self.auto_network_scan()
            elif choice == "0":
                self.exit_program()
    
    def full_network_scan(self):
        """Escaneamento completo de rede"""
        console.print(Panel.fit(
            "[bold]🌐 ESCANEAMENTO COMPLETO DE REDE[/bold]",
            border_style="blue"
        ))
        
        networks = self.get_networks_input()
        if not networks:
            return
        
        timeout = IntPrompt.ask(
            "[yellow]?[/yellow] Timeout por porta (segundos)",
            default=2
        )
        
        # Descobrir hosts ativos primeiro
        all_hosts = []
        for network in networks:
            console.print(f"[bold]🔎 Procurando hosts ativos em {network}...[/bold]")
            hosts = self.scanner.host_discovery(network, 1)
            all_hosts.extend(hosts)
        
        if not all_hosts:
            console.print("[yellow]⚠️  Nenhum host ativo encontrado[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        console.print(f"[green]✅ {len(all_hosts)} hosts ativos encontrados[/green]")
        
        if not Confirm.ask("[yellow]?[/yellow] Iniciar escaneamento de portas perigosas?"):
            return
        
        # Escanear portas perigosas
        results = self.scanner.scan_dangerous_ports(all_hosts, timeout)
        
        # Gerar relatório
        self.scanner.generate_report()
        
        if results:
            console.print(Panel.fit(
                "[red]🚨 PORTAS PERIGOSAS ENCONTRADAS![/red]\n"
                "Revise os alertas acima e tome ações de mitigação.",
                border_style="red"
            ))
        
        input("\nPressione Enter para voltar...")
    
    def single_host_scan(self):
        """Escaneamento em host específico"""
        console.print(Panel.fit(
            "[bold]🎯 ESCANEAMENTO EM HOST ESPECÍFICO[/bold]",
            border_style="blue"
        ))
        
        host = Prompt.ask(
            "[yellow]?[/yellow] Digite o IP do host",
            default="192.168.1.1"
        )
        
        if not self.scanner.validate_ip(host):
            console.print("[red]❌ Endereço IP inválido[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        # Verificar se host está ativo
        console.print(f"[bold]🔎 Verificando se {host} está ativo...[/bold]")
        if not self.scanner.ping_host(host, 2):
            if not Confirm.ask("[yellow]?[/yellow] Host não responde a ping. Continuar mesmo assim?"):
                return
        
        timeout = IntPrompt.ask(
            "[yellow]?[/yellow] Timeout por porta (segundos)",
            default=2
        )
        
        console.print(f"[bold]🔍 Escaneando {host} por portas perigosas...[/bold]")
        results = self.scanner.scan_dangerous_ports([host], timeout)
        
        # Gerar relatório
        self.scanner.generate_report()
        
        input("\nPressione Enter para voltar...")
    
    def list_monitored_ports(self):
        """Lista todas as portas monitoradas"""
        console.print(Panel.fit(
            "[bold]📋 PORTAS MONITORADAS PELO SCANNER[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Porta", style="cyan")
        table.add_column("Serviço", style="green")
        table.add_column("Risco", style="red")
        table.add_column("Descrição", style="white")
        
        # Ordena por número de porta
        sorted_ports = sorted(self.scanner.dangerous_ports.items(), key=lambda x: x[0])
        
        for port, info in sorted_ports:
            risk_color = {
                "Crítica": "red",
                "Alta": "bright_red", 
                "Média": "yellow",
                "Variável": "cyan"
            }
            
            table.add_row(
                str(port),
                info['service'],
                f"[{risk_color[info['risk']]}]{info['risk']}[/{risk_color[info['risk']]}]",
                info['description']
            )
        
        console.print(table)
        input("\nPressione Enter para voltar...")
    
    def test_specific_port(self):
        """Testa uma porta específica"""
        console.print(Panel.fit(
            "[bold]🔍 TESTE DE PORTA ESPECÍFICA[/bold]",
            border_style="blue"
        ))
        
        host = Prompt.ask(
            "[yellow]?[/yellow] Digite o IP do host",
            default="192.168.1.1"
        )
        
        if not self.scanner.validate_ip(host):
            console.print("[red]❌ Endereço IP inválido[/red]")
            input("\nPressione Enter para voltar...")
            return
        
        port = IntPrompt.ask(
            "[yellow]?[/yellow] Digite a porta para testar",
            default=22
        )
        
        if port not in self.scanner.dangerous_ports:
            console.print("[yellow]⚠️  Esta porta não está na lista de perigosas[/yellow]")
            if not Confirm.ask("[yellow]?[/yellow] Testar mesmo assim?"):
                return
        
        timeout = IntPrompt.ask(
            "[yellow]?[/yellow] Timeout (segundos)",
            default=3
        )
        
        console.print(f"[bold]🔍 Testando porta {port} em {host}...[/bold]")
        result = self.scanner.check_dangerous_port(host, port, timeout)
        
        if result['status'] == 'open':
            self.scanner.show_dangerous_port_warning(result)
        else:
            console.print(Panel.fit(
                f"[green]✅ Porta {port} está fechada ou inacessível[/green]",
                border_style="green"
            ))
        
        input("\nPressione Enter para voltar...")
    
    def auto_network_scan(self):
        """Escaneamento automático de redes locais"""
        console.print(Panel.fit(
            "[bold]📡 DETECÇÃO AUTOMÁTICA DE REDES[/bold]",
            border_style="blue"
        ))
        
        console.print("[bold]🔍 Detectando redes locais...[/bold]")
        networks = self.scanner.get_local_networks()
        
        if not networks:
            console.print("[yellow]⚠️  Nenhuma rede local detectada[/yellow]")
            input("\nPressione Enter para voltar...")
            return
        
        console.print(Panel.fit(
            "[green]✅ Redes locais detectadas:[/green]\n" +
            "\n".join(networks),
            border_style="green"
        ))
        
        if Confirm.ask("[yellow]?[/yellow] Iniciar escaneamento nessas redes?"):
            timeout = IntPrompt.ask(
                "[yellow]?[/yellow] Timeout por porta (segundos)",
                default=2
            )
            
            # Descobrir hosts ativos
            all_hosts = []
            for network in networks:
                console.print(f"[bold]🔎 Procurando hosts em {network}...[/bold]")
                hosts = self.scanner.host_discovery(network, 1)
                all_hosts.extend(hosts)
            
            if not all_hosts:
                console.print("[yellow]⚠️  Nenhum host ativo encontrado[/yellow]")
                input("\nPressione Enter para voltar...")
                return
            
            console.print(f"[green]✅ {len(all_hosts)} hosts ativos encontrados[/green]")
            
            # Escanear portas perigosas
            results = self.scanner.scan_dangerous_ports(all_hosts, timeout)
            
            # Gerar relatório
            self.scanner.generate_report()
        
        input("\nPressione Enter para voltar...")
    
    def get_networks_input(self):
        """Obtém entrada de redes do usuário"""
        networks = []
        
        if Confirm.ask("[yellow]?[/yellow] Detectar redes automaticamente?"):
            auto_networks = self.scanner.get_local_networks()
            if auto_networks:
                networks.extend(auto_networks)
                console.print("[green]✅ Redes automáticas adicionadas[/green]")
        
        while True:
            network = Prompt.ask(
                "[yellow]?[/yellow] Adicionar rede (formato CIDR) ou Enter para continuar"
            )
            
            if not network:
                break
            
            if self.scanner.validate_network(network):
                networks.append(network)
                console.print(f"[green]✅ Rede adicionada: {network}[/green]")
            else:
                console.print("[red]❌ Formato de rede inválido. Use formato CIDR (ex: 192.168.1.0/24)[/red]")
        
        if not networks:
            console.print("[red]❌ Nenhuma rede especificada[/red]")
        
        return networks
    
    def exit_program(self):
        """Sai do programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ AVISO: ESCANEAMENTO NÃO AUTORIZADO É CRIME! ⚠️[/blink bold red]\n\n"
            "Este tool é apenas para testes de segurança autorizados.\n"
            "Use apenas em redes próprias ou com permissão explícita.",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        panel = DangerousPortScannerPanel()
        panel.show_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
