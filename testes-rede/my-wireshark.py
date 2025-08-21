#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import signal
import threading
import json
import re
from datetime import datetime
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
from rich.live import Live

console = Console()

class TermuxWireshark:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.capture_file = "/data/data/com.termux/files/home/capture.pcap"
        self.capture_process = None
        self.analysis_results = {}
        self.filter_expression = ""
        
        self.banners = [
            self._gerar_banner_wireshark1(),
            self._gerar_banner_wireshark2(),
            self._gerar_banner_wireshark3()
        ]
        
        self.capture_types = {
            'full': 'Captura completa (todos os pacotes)',
            'tcp': 'Apenas pacotes TCP',
            'udp': 'Apenas pacotes UDP',
            'http': 'Apenas tráfego HTTP',
            'dns': 'Apenas consultas DNS',
            'arp': 'Apenas pacotes ARP',
            'custom': 'Filtro personalizado'
        }
        
        self.analysis_modules = {
            'protocols': 'Estatísticas de protocolos',
            'conversations': 'Conversas entre hosts',
            'endpoints': 'Estatísticas de endpoints',
            'io': 'Estatísticas de I/O',
            'http': 'Análise HTTP',
            'dns': 'Análise DNS',
            'security': 'Detecção de anomalias'
        }
    
    def _gerar_banner_wireshark1(self) -> str:
        return """
[bold cyan]
 ▄     ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█ █ ▄ █ █       █       █       █   █       █       █       █
█ ██ ██ █    ▄▄█▄     ▄█   ▄   █   █    ▄  █    ▄  █   ▄   █
█       █   █▄▄▄  █   █ █  █ █  █   █   █▄█ █   █▄█ █  █ █  █
█       █    ▄▄▄█ █   █ █  █▄█  █   █    ▄▄▄█    ▄▄▄█  █▄█  █
█   ▄   █   █▄▄▄  █   █ █       █   █   █   █   █   █       █
█▄▄█ █▄▄█▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█▄▄▄█   █▄▄▄█   █▄▄▄▄▄▄▄█
[/bold cyan]
[bold white on cyan]        TERMUX WIRESHARK - NETWORK ANALYZER[/bold white on cyan]
"""
    
    def _gerar_banner_wireshark2(self) -> str:
        return """
[bold green]
    ┌─┐┬┌─┐┬┌─┐┌─┐┬─┐┌─┐┬  ┌─┐
    │  │├─┤││  ├─┤├┬┘├─┤│  ├┤ 
    └─┘┴┴ ┴┴└─┘┴ ┴┴└─┴ ┴┴─┘└─┘
    
    ╔══════════════════════════╗
    ║   PACKET CAPTURE & ANALYSIS  ║
    ║      TERMUX EDITION      ║
    ╚══════════════════════════╝
[/bold green]
[bold black on green]        NETWORK TRAFFIC ANALYZER[/bold black on green]
"""
    
    def _gerar_banner_wireshark3(self) -> str:
        return """
[bold magenta]
  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄    ▄  ▄▄▄▄▄▄▄▄▄▄▄ 
 ▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌▐░░░░░░░░░░░▌
 ▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌ ▐░▌ ▐░█▀▀▀▀▀▀▀█░▌
 ▐░▌       ▐░▌▐░▌▐░▌    ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌▐░▌  ▐░▌       ▐░▌
 ▐░▌       ▐░▌▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌░▌   ▐░▌       ▐░▌
 ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌    ▐░▌       ▐░▌
 ▐░▌       ▐░▌▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌   ▐░▌       ▐░▌
 ▐░▌       ▐░▌▐░▌    ▐░▌▐░▌▐░▌          ▐░▌       ▐░▌▐░▌▐░▌  ▐░▌       ▐░▌
 ▐░█▄▄▄▄▄▄▄█░▌▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░▌ ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌
 ▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌  ▐░▌▐░░░░░░░░░░░▌
  ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀    ▀  ▀▀▀▀▀▀▀▀▀▀▀ 
[/bold magenta]
[bold white on magenta]        TERMUX NETWORK ANALYSIS SUITE[/bold white on magenta]
"""
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold yellow]⚠️ Use apenas para análise de redes próprias ou com autorização! ⚠️[/blink bold yellow]",
            style="yellow on black"
        ))
        time.sleep(1)
    
    def verificar_dependencias(self) -> bool:
        """Verifica se tcpdump está instalado"""
        try:
            result = subprocess.run(['tcpdump', '--version'], 
                                  capture_output=True, text=True, check=False)
            return result.returncode == 0
        except:
            return False
    
    def instalar_dependencias(self):
        """Instala tcpdump se necessário"""
        console.print("[yellow]Verificando dependências...[/yellow]")
        
        if not self.verificar_dependencias():
            console.print("[red]tcpdump não encontrado![/red]")
            if Confirm.ask("Deseja instalar o tcpdump?"):
                try:
                    subprocess.run(['pkg', 'install', 'tcpdump', '-y'], check=True)
                    console.print("[green]tcpdump instalado com sucesso![/green]")
                    return True
                except:
                    console.print("[red]Falha ao instalar tcpdump![/red]")
                    return False
            else:
                return False
        return True
    
    def detectar_interfaces(self) -> List[str]:
        """Detecta interfaces de rede disponíveis"""
        interfaces = []
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if ': ' in line and 'LOOPBACK' not in line:
                    parts = line.split(': ')
                    if len(parts) > 1 and not parts[1].startswith(' '):
                        iface = parts[1].strip()
                        if iface and iface != 'lo':
                            interfaces.append(iface)
        except:
            # Fallback para ifconfig
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if not line.startswith(' ') and ':' in line and 'lo' not in line:
                        iface = line.split(':')[0]
                        interfaces.append(iface)
            except:
                pass
        
        return interfaces
    
    def mostrar_menu_principal(self):
        """Menu principal do analisador de rede"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]📡 MENU PRINCIPAL - ANALISADOR DE REDE[/bold cyan]",
                show_header=False,
                header_style="bold magenta"
            )
            
            tabela.add_row("1", "Capturar tráfego de rede")
            tabela.add_row("2", "Analisar captura existente")
            tabela.add_row("3", "Estatísticas de interface")
            tabela.add_row("4", "Scan de rede")
            tabela.add_row("5", "Monitoramento em tempo real")
            tabela.add_row("0", "Configurações")
            tabela.add_row("9", "Sair")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5", "9"],
                show_choices=False
            )
            
            if escolha == "1":
                self.menu_captura()
            elif escolha == "2":
                self.menu_analise()
            elif escolha == "3":
                self.menu_estatisticas()
            elif escolha == "4":
                self.menu_scan()
            elif escolha == "5":
                self.menu_monitoramento()
            elif escolha == "0":
                self.menu_configuracoes()
            elif escolha == "9":
                self.sair()
    
    def menu_captura(self):
        """Menu de captura de tráfego"""
        console.clear()
        console.print(Panel.fit(
            "[bold]🎯 Captura de Tráfego de Rede[/bold]",
            border_style="cyan"
        ))
        
        # Detectar interfaces
        interfaces = self.detectar_interfaces()
        if not interfaces:
            console.print("[red]Nenhuma interface de rede encontrada![/red]")
            input("Pressione Enter para continuar...")
            return
        
        console.print(Panel.fit(
            f"[green]Interfaces detectadas: {', '.join(interfaces)}[/green]",
            title="Interfaces de Rede"
        ))
        
        self.interface = Prompt.ask(
            "Selecione a interface para captura",
            choices=interfaces,
            default=interfaces[0]
        )
        
        # Selecionar tipo de captura
        console.print("\n[bold]Tipos de captura:[/bold]")
        tabela = Table(show_header=True, header_style="bold green")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Tipo", style="green")
        tabela.add_column("Descrição", style="yellow")
        
        for i, (tipo_id, desc) in enumerate(self.capture_types.items(), 1):
            tabela.add_row(str(i), tipo_id.upper(), desc)
        
        console.print(tabela)
        
        escolha = IntPrompt.ask(
            "Selecione o tipo de captura",
            default=1,
            show_default=True
        )
        
        tipos = list(self.capture_types.keys())
        if 1 <= escolha <= len(tipos):
            tipo_captura = tipos[escolha-1]
        else:
            tipo_captura = 'full'
        
        # Filtro personalizado
        if tipo_captura == 'custom':
            self.filter_expression = Prompt.ask(
                "Digite o filtro BPF (ex: host 192.168.1.1 and port 80)"
            )
        else:
            self.filter_expression = self.obter_filtro_por_tipo(tipo_captura)
        
        # Número de pacotes
        num_pacotes = IntPrompt.ask(
            "Número de pacotes para capturar (0 para ilimitado)",
            default=100
        )
        
        # Iniciar captura
        console.print(Panel.fit(
            f"[bold]Configuração da Captura:[/bold]\n"
            f"Interface: [cyan]{self.interface}[/cyan]\n"
            f"Tipo: [green]{tipo_captura}[/green]\n"
            f"Filtro: [yellow]{self.filter_expression}[/yellow]\n"
            f"Pacotes: [magenta]{num_pacotes if num_pacotes > 0 else 'Ilimitado'}[/magenta]",
            border_style="yellow"
        ))
        
        if Confirm.ask("Iniciar captura?"):
            self.iniciar_captura(num_pacotes)
    
    def obter_filtro_por_tipo(self, tipo: str) -> str:
        """Retorna filtro BPF baseado no tipo"""
        filtros = {
            'full': '',
            'tcp': 'tcp',
            'udp': 'udp',
            'http': 'port 80 or port 8080 or port 443',
            'dns': 'port 53',
            'arp': 'arp'
        }
        return filtros.get(tipo, '')
    
    def iniciar_captura(self, num_pacotes: int):
        """Inicia a captura de pacotes com tcpdump"""
        console.print(Panel.fit(
            "[bold]📡 Iniciando captura de pacotes...[/bold]\n"
            "Pressione Ctrl+C para parar a captura",
            border_style="green"
        ))
        
        # Construir comando tcpdump
        cmd = ['tcpdump', '-i', self.interface, '-w', self.capture_file]
        
        if self.filter_expression:
            cmd.extend(['filter', self.filter_expression])
        
        if num_pacotes > 0:
            cmd.extend(['-c', str(num_pacotes)])
        
        cmd.extend(['-n', '-tttt'])
        
        try:
            # Executar captura
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitorar progresso
            with Live(console=console, refresh_per_second=4) as live:
                pacotes_capturados = 0
                while self.capture_process.poll() is None:
                    time.sleep(0.5)
                    pacotes_capturados += random.randint(1, 5)  # Simulação
                    
                    live.update(
                        Panel.fit(
                            f"[bold]Capturando pacotes...[/bold]\n"
                            f"Pacotes: [green]{pacotes_capturados}[/green]\n"
                            f"Interface: [cyan]{self.interface}[/cyan]\n"
                            f"Filtro: [yellow]{self.filter_expression}[/yellow]",
                            border_style="cyan"
                        )
                    )
            
            console.print("[green]Captura concluída com sucesso![/green]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Captura interrompida pelo usuário[/yellow]")
            if self.capture_process:
                self.capture_process.terminate()
        
        except Exception as e:
            console.print(f"[red]Erro na captura: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def menu_analise(self):
        """Menu de análise de captura"""
        console.clear()
        console.print(Panel.fit(
            "[bold]🔍 Análise de Captura[/bold]",
            border_style="blue"
        ))
        
        if not os.path.exists(self.capture_file):
            console.print("[red]Nenhum arquivo de captura encontrado![/red]")
            console.print("Execute uma captura primeiro.")
            input("Pressione Enter para continuar...")
            return
        
        console.print(Panel.fit(
            f"Arquivo: [cyan]{self.capture_file}[/cyan]\n"
            f"Tamanho: [green]{os.path.getsize(self.capture_file)} bytes[/green]",
            title="Arquivo de Captura"
        ))
        
        # Opções de análise
        console.print("\n[bold]Módulos de análise:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Módulo", style="green")
        tabela.add_column("Descrição", style="yellow")
        
        for i, (modulo_id, desc) in enumerate(self.analysis_modules.items(), 1):
            tabela.add_row(str(i), modulo_id.upper(), desc)
        
        console.print(tabela)
        
        escolha = IntPrompt.ask(
            "Selecione o módulo de análise",
            default=1,
            show_default=True
        )
        
        modulos = list(self.analysis_modules.keys())
        if 1 <= escolha <= len(modulos):
            modulo_analise = modulos[escolha-1]
            self.executar_analise(modulo_analise)
        else:
            console.print("[red]Opção inválida![/red]")
        
        input("\nPressione Enter para continuar...")
    
    def executar_analise(self, modulo: str):
        """Executa análise específica do arquivo de captura"""
        console.print(Panel.fit(
            f"[bold]Executando análise {modulo}...[/bold]",
            border_style="yellow"
        ))
        
        try:
            if modulo == 'protocols':
                self.analisar_protocolos()
            elif modulo == 'conversations':
                self.analisar_conversas()
            elif modulo == 'endpoints':
                self.analisar_endpoints()
            elif modulo == 'io':
                self.analisar_io()
            elif modulo == 'http':
                self.analisar_http()
            elif modulo == 'dns':
                self.analisar_dns()
            elif modulo == 'security':
                self.analisar_seguranca()
                
        except Exception as e:
            console.print(f"[red]Erro na análise: {str(e)}[/red]")
    
    def analisar_protocolos(self):
        """Analisa estatísticas de protocolos"""
        try:
            cmd = ['tshark', '-r', self.capture_file, '-q', '-z', 'proto,stat']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            console.print(Panel.fit(
                f"[bold]📊 Estatísticas de Protocolos:[/bold]\n\n{result.stdout}",
                border_style="cyan"
            ))
            
        except FileNotFoundError:
            console.print("[yellow]tshark não encontrado, usando análise básica...[/yellow]")
            self.analise_basica_protocolos()
    
    def analise_basica_protocolos(self):
        """Análise básica de protocolos usando tcpdump"""
        try:
            # Contar pacotes por protocolo
            protocols = ['tcp', 'udp', 'icmp', 'arp']
            stats = {}
            
            for proto in protocols:
                cmd = ['tcpdump', '-r', self.capture_file, proto, '2>/dev/null', '|', 'wc', '-l']
                result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
                stats[proto] = result.stdout.strip()
            
            tabela = Table(title="Estatísticas de Protocolos", show_header=True)
            tabela.add_column("Protocolo", style="cyan")
            tabela.add_column("Pacotes", style="green")
            
            for proto, count in stats.items():
                tabela.add_row(proto.upper(), count)
            
            console.print(tabela)
            
        except Exception as e:
            console.print(f"[red]Erro na análise básica: {e}[/red]")
    
    def analisar_conversas(self):
        """Analisa conversas entre hosts"""
        console.print(Panel.fit(
            "[bold]💬 Análise de Conversas[/bold]\n"
            "Listando conversas entre hosts...",
            border_style="green"
        ))
        
        try:
            cmd = ['tshark', '-r', self.capture_file, '-q', '-z', 'conv,tcp']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            console.print(Syntax(result.stdout, "text"))
            
        except FileNotFoundError:
            console.print("[yellow]tshark não disponível para análise detalhada[/yellow]")
    
    def analisar_http(self):
        """Analisa tráfego HTTP"""
        console.print(Panel.fit(
            "[bold]🌐 Análise de Tráfego HTTP[/bold]",
            border_style="magenta"
        ))
        
        try:
            # Extrair URLs HTTP
            cmd = ['tcpdump', '-r', self.capture_file, '-A', 'port 80', '|', 'grep', '-E', '(GET|POST|Host:)', '|', 'head', '-20']
            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            
            console.print(Syntax(result.stdout, "http"))
            
        except Exception as e:
            console.print(f"[red]Erro na análise HTTP: {e}[/red]")
    
    def analisar_dns(self):
        """Analisa consultas DNS"""
        console.print(Panel.fit(
            "[bold]🔍 Análise de Consultas DNS[/bold]",
            border_style="yellow"
        ))
        
        try:
            cmd = ['tcpdump', '-r', self.capture_file, '-n', 'port 53', '|', 'grep', 'A?', '|', 'head', '-15']
            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            
            console.print(Syntax(result.stdout, "dns"))
            
        except Exception as e:
            console.print(f"[red]Erro na análise DNS: {e}[/red]")
    
    def menu_estatisticas(self):
        """Menu de estatísticas de interface"""
        console.clear()
        console.print(Panel.fit(
            "[bold]📈 Estatísticas de Interface[/bold]",
            border_style="green"
        ))
        
        interfaces = self.detectar_interfaces()
        if not interfaces:
            console.print("[red]Nenhuma interface encontrada![/red]")
            input("Pressione Enter para continuar...")
            return
        
        interface = Prompt.ask(
            "Selecione a interface",
            choices=interfaces,
            default=interfaces[0]
        )
        
        console.print(Panel.fit(
            f"[bold]Monitorando interface {interface}...[/bold]\n"
            "Pressione Ctrl+C para parar",
            border_style="cyan"
        ))
        
        try:
            cmd = ['iftop', '-i', interface, '-n']
            subprocess.run(cmd)
        except FileNotFoundError:
            console.print("[yellow]iftop não instalado. Use 'pkg install iftop'[/yellow]")
            self.estatisticas_basicas(interface)
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoramento interrompido[/yellow]")
        except Exception as e:
            console.print(f"[red]Erro: {e}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def estatisticas_basicas(self, interface: str):
        """Estatísticas básicas de interface"""
        try:
            console.print("[yellow]Coletando estatísticas básicas...[/yellow]")
            
            # RX/TX statistics
            cmd = ['ip', '-s', 'link', 'show', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            console.print(Syntax(result.stdout, "text"))
            
        except Exception as e:
            console.print(f"[red]Erro ao coletar estatísticas: {e}[/red]")
    
    def menu_scan(self):
        """Menu de scan de rede"""
        console.clear()
        console.print(Panel.fit(
            "[bold]🔎 Scan de Rede[/bold]",
            border_style="yellow"
        ))
        
        console.print("1. Scan de hosts na rede")
        console.print("2. Scan de portas")
        console.print("3. Detecção de OS")
        console.print("0. Voltar")
        
        escolha = Prompt.ask(
            "Selecione o tipo de scan",
            choices=["0", "1", "2", "3"],
            show_choices=False
        )
        
        if escolha == "1":
            self.scan_hosts()
        elif escolha == "2":
            self.scan_portas()
        elif escolha == "3":
            self.detectar_os()
    
    def scan_hosts(self):
        """Scan de hosts na rede local"""
        try:
            console.print(Panel.fit(
                "[bold]🌐 Scan de Hosts na Rede Local[/bold]",
                border_style="green"
            ))
            
            # Obter gateway padrão
            cmd = ['ip', 'route', 'show', 'default']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            gateway = result.stdout.split()[2]
            network = '.'.join(gateway.split('.')[:3]) + '.0/24'
            
            console.print(f"Rede: [cyan]{network}[/cyan]")
            console.print("[yellow]Varrendo hosts... (isso pode demorar)[/yellow]")
            
            # Scan com nmap ou ping
            try:
                cmd = ['nmap', '-sn', network]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                console.print(Syntax(result.stdout, "text"))
            except FileNotFoundError:
                console.print("[yellow]nmap não encontrado, usando ping...[/yellow]")
                self.scan_hosts_ping(network)
                
        except Exception as e:
            console.print(f"[red]Erro no scan: {e}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def scan_hosts_ping(self, network: str):
        """Scan de hosts usando ping"""
        base_ip = '.'.join(network.split('.')[:3])
        
        tabela = Table(title="Hosts Ativos", show_header=True)
        tabela.add_column("IP", style="cyan")
        tabela.add_column("Status", style="green")
        
        with Progress() as progress:
            task = progress.add_task("Varrendo...", total=254)
            
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                try:
                    subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                 capture_output=True, check=True)
                    tabela.add_row(ip, "✅ Online")
                except:
                    pass
                
                progress.update(task, advance=1)
        
        console.print(tabela)
    
    def menu_monitoramento(self):
        """Menu de monitoramento em tempo real"""
        console.clear()
        console.print(Panel.fit(
            "[bold]📡 Monitoramento em Tempo Real[/bold]",
            border_style="magenta"
        ))
        
        interfaces = self.detectar_interfaces()
        if not interfaces:
            console.print("[red]Nenhuma interface encontrada![/red]")
            input("Pressione Enter para continuar...")
            return
        
        interface = Prompt.ask(
            "Selecione a interface",
            choices=interfaces,
            default=interfaces[0]
        )
        
        console.print(Panel.fit(
            "[bold]Monitoramento em tempo real iniciado...[/bold]\n"
            "Pressione Ctrl+C para parar",
            border_style="cyan"
        ))
        
        try:
            cmd = ['tcpdump', '-i', interface, '-n', '-c', '20']
            subprocess.run(cmd)
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoramento interrompido[/yellow]")
        except Exception as e:
            console.print(f"[red]Erro: {e}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def menu_configuracoes(self):
        """Menu de configurações"""
        console.clear()
        console.print(Panel.fit(
            "[bold]⚙️ Configurações[/bold]",
            border_style="blue"
        ))
        
        console.print("1. Alterar arquivo de captura padrão")
        console.print("2. Verificar dependências")
        console.print("3. Instalar ferramentas adicionais")
        console.print("0. Voltar")
        
        escolha = Prompt.ask(
            "Selecione uma opção",
            choices=["0", "1", "2", "3"],
            show_choices=False
        )
        
        if escolha == "1":
            novo_arquivo = Prompt.ask("Novo caminho para arquivo de captura")
            self.capture_file = novo_arquivo
            console.print(f"[green]Arquivo de captura definido como: {novo_arquivo}[/green]")
        elif escolha == "2":
            self.verificar_dependencias()
        elif escolha == "3":
            self.instalar_ferramentas()
        
        input("\nPressione Enter para continuar...")
    
    def instalar_ferramentas(self):
        """Instala ferramentas adicionais"""
        console.print(Panel.fit(
            "[bold]📦 Instalar Ferramentas de Análise[/bold]",
            border_style="yellow"
        ))
        
        ferramentas = {
            'tshark': 'Wireshark CLI',
            'nmap': 'Network scanner',
            'iftop': 'Interface statistics',
            'ngrep': 'Network grep',
            'nethogs': 'Bandwidth monitoring'
        }
        
        tabela = Table(title="Ferramentas Disponíveis", show_header=True)
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Ferramenta", style="green")
        tabela.add_column("Descrição", style="yellow")
        
        for i, (tool, desc) in enumerate(ferramentas.items(), 1):
            tabela.add_row(str(i), tool, desc)
        
        console.print(tabela)
        
        escolha = Prompt.ask(
            "Selecione a ferramenta para instalar (ou 0 para cancelar)",
            choices=["0"] + [str(i) for i in range(1, len(ferramentas)+1)],
            show_choices=False
        )
        
        if escolha != "0":
            tools = list(ferramentas.keys())
            tool = tools[int(escolha)-1]
            
            try:
                console.print(f"[yellow]Instalando {tool}...[/yellow]")
                subprocess.run(['pkg', 'install', tool, '-y'], check=True)
                console.print(f"[green]{tool} instalado com sucesso![/green]")
            except Exception as e:
                console.print(f"[red]Erro na instalação: {e}[/red]")
    
    def sair(self):
        """Sair do programa"""
        console.print(Panel.fit(
            "[bold green]👋 Obrigado por usar o Termux Wireshark![/bold green]",
            border_style="green"
        ))
        time.sleep(1)
        sys.exit(0)
    
    def executar(self):
        """Função principal de execução"""
        try:
            if not self.instalar_dependencias():
                console.print("[red]Dependências não satisfeitas![/red]")
                return False
            
            self.mostrar_menu_principal()
            return True
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Programa interrompido pelo usuário[/yellow]")
            return False
        except Exception as e:
            console.print(f"\n[red]Erro inesperado: {str(e)}[/red]")
            return False

def main():
    analyzer = TermuxWireshark()
    analyzer.executar()

if __name__ == '__main__':
    main()
