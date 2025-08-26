#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import re
from typing import Dict, List, Optional, Tuple

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, BarColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.markdown import Markdown

console = Console()

class ScannerPortasNmap:
    def __init__(self):
        self.tecnicas_scanner = {
            'syn_stealth': {
                'nome': 'SYN Stealth Scan',
                'comando': '-sS',
                'descricao': 'Scan SYN furtivo (requer root para máximo potencial)',
                'nivel': 'avançado',
                'root': 'recomendado'
            },
            'connect': {
                'nome': 'Connect Scan',
                'comando': '-sT',
                'descricao': 'Scan de conexão TCP completa (sem root)',
                'nivel': 'básico',
                'root': 'não necessário'
            },
            'udp_scan': {
                'nome': 'UDP Scan',
                'comando': '-sU',
                'descricao': 'Scan de portas UDP (lento mas eficaz)',
                'nivel': 'intermediário',
                'root': 'recomendado'
            },
            'version_detection': {
                'nome': 'Version Detection',
                'comando': '-sV',
                'descricao': 'Detecção de versões de serviços',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'os_detection': {
                'nome': 'OS Detection',
                'comando': '-O',
                'descricao': 'Detecção de sistema operacional',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'ping_sweep': {
                'nome': 'Ping Sweep',
                'comando': '-sn',
                'descricao': 'Varredura de hosts ativos (ping)',
                'nivel': 'básico',
                'root': 'não necessário'
            },
            'quick_scan': {
                'nome': 'Quick Scan',
                'comando': '-T4 -F',
                'descricao': 'Scan rápido das portas mais comuns',
                'nivel': 'básico',
                'root': 'não necessário'
            },
            'comprehensive': {
                'nome': 'Comprehensive Scan',
                'comando': '-sS -sV -sC -O',
                'descricao': 'Scan completo (SYN + versões + scripts)',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'script_scan': {
                'nome': 'NSE Script Scan',
                'comando': '-sC',
                'descricao': 'Executa scripts padrão do Nmap',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'aggressive': {
                'nome': 'Aggressive Scan',
                'comando': '-A',
                'descricao': 'Modo agressivo (OS, versão, scripts, traceroute)',
                'nivel': 'avançado',
                'root': 'recomendado'
            },
            'no_ping': {
                'nome': 'No Ping Scan',
                'comando': '-Pn',
                'descricao': 'Scan sem verificação de host ativo',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'fragment': {
                'nome': 'Fragment Packets',
                'comando': '-f',
                'descricao': 'Fragmenta pacotes para evadir firewalls',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'decoy': {
                'nome': 'Decoy Scan',
                'comando': '-D RND:10',
                'descricao': 'Scan com endereços spoofados para anonimato',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'idle_scan': {
                'nome': 'Idle Scan',
                'comando': '-sI',
                'descricao': 'Scan zombie usando host intermediário',
                'nivel': 'expert',
                'root': 'necessário'
            },
            'null_scan': {
                'nome': 'NULL Scan',
                'comando': '-sN',
                'descricao': 'Scan com flags TCP NULL (evasivo)',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'fin_scan': {
                'nome': 'FIN Scan',
                'comando': '-sF',
                'descricao': 'Scan com flag FIN (evasivo)',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'xmas_scan': {
                'nome': 'Xmas Scan',
                'comando': '-sX',
                'descricao': 'Scan com flags FIN, PSH, URG (como árvore natal)',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'window_scan': {
                'nome': 'Window Scan',
                'comando': '-sW',
                'descricao': 'Scan analisando tamanho da janela TCP',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'maimon_scan': {
                'nome': 'Maimon Scan',
                'comando': '-sM',
                'descricao': 'Scan usando técnica de Uriel Maimon',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'ack_scan': {
                'nome': 'ACK Scan',
                'comando': '-sA',
                'descricao': 'Scan para mapeamento de firewalls',
                'nivel': 'avançado',
                'root': 'necessário'
            },
            'custom_ports': {
                'nome': 'Custom Port Range',
                'comando': '-p',
                'descricao': 'Scan em range específico de portas',
                'nivel': 'básico',
                'root': 'não necessário'
            },
            'top_ports': {
                'nome': 'Top Ports',
                'comando': '--top-ports',
                'descricao': 'Scan nas portas mais comuns',
                'nivel': 'básico',
                'root': 'não necessário'
            },
            'service_scan': {
                'nome': 'Service Scan All Ports',
                'comando': '-sV -p-',
                'descricao': 'Scan de versão em todas as portas (muito lento)',
                'nivel': 'avançado',
                'root': 'não necessário'
            },
            'timing_aggressive': {
                'nome': 'Aggressive Timing',
                'comando': '-T5',
                'descricao': 'Timing mais agressivo (mais rápido, mais detectável)',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'timing_stealth': {
                'nome': 'Stealth Timing',
                'comando': '-T2',
                'descricao': 'Timing furtivo (mais lento, menos detectável)',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'ipv6_scan': {
                'nome': 'IPv6 Scan',
                'comando': '-6',
                'descricao': 'Scan em endereços IPv6',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'script_vuln': {
                'nome': 'Vulnerability Scripts',
                'comando': '--script vuln',
                'descricao': 'Scripts de detecção de vulnerabilidades',
                'nivel': 'avançado',
                'root': 'não necessário'
            },
            'script_safe': {
                'nome': 'Safe Scripts',
                'comando': '--script safe',
                'descricao': 'Scripts considerados seguros',
                'nivel': 'intermediário',
                'root': 'não necessário'
            },
            'script_auth': {
                'nome': 'Authentication Scripts',
                'comando': '--script auth',
                'descricao': 'Scripts de bypass de autenticação',
                'nivel': 'avançado',
                'root': 'não necessário'
            },
            'output_normal': {
                'nome': 'Normal Output',
                'comando': '-oN',
                'descricao': 'Saída em formato normal',
                'nivel': 'básico',
                'root': 'não necessário'
            }
        }
        
        self.portas_comuns = {
            '21': 'FTP',
            '22': 'SSH',
            '23': 'Telnet',
            '25': 'SMTP',
            '53': 'DNS',
            '80': 'HTTP',
            '110': 'POP3',
            '135': 'MSRPC',
            '139': 'NetBIOS',
            '143': 'IMAP',
            '443': 'HTTPS',
            '445': 'SMB',
            '993': 'IMAPS',
            '995': 'POP3S',
            '1433': 'MSSQL',
            '3306': 'MySQL',
            '3389': 'RDP',
            '5432': 'PostgreSQL',
            '5900': 'VNC',
            '6379': 'Redis',
            '27017': 'MongoDB'
        }
        
        self._verificar_nmap()
    
    def _verificar_nmap(self):
        """Verifica se o Nmap está instalado"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise Exception("Nmap não encontrado")
            
            version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
            if version_match:
                console.print(f"[green]✓ Nmap encontrado - Versão {version_match.group(1)}[/green]")
            else:
                console.print("[yellow]⚠ Nmap encontrado mas versão não identificada[/yellow]")
                
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            console.print(Panel.fit(
                "[red]✗ Nmap não encontrado![/red]\n\n"
                "Para instalar no Termux:\n"
                "1. pkg update && pkg upgrade\n"
                "2. pkg install nmap\n\n"
                "Em outros sistemas Linux:\n"
                "1. sudo apt update\n"
                "2. sudo apt install nmap",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            
            if Confirm.ask("Deseja tentar instalar automaticamente?"):
                self._instalar_nmap()
            else:
                sys.exit(1)
    
    def _instalar_nmap(self):
        """Tenta instalar o Nmap automaticamente"""
        with Progress() as progress:
            task = progress.add_task("[cyan]Instalando Nmap...[/cyan]", total=100)
            
            try:
                if platform.system() == "Linux" and os.path.exists('/data/data/com.termux'):
                    # Termux
                    commands = [
                        ['pkg', 'update'],
                        ['pkg', 'install', '-y', 'nmap']
                    ]
                else:
                    # Outros Linux (requer root)
                    console.print("[yellow]⚠ Instalação automática requer root[/yellow]")
                    commands = [
                        ['sudo', 'apt', 'update'],
                        ['sudo', 'apt', 'install', '-y', 'nmap']
                    ]
                
                for cmd in commands:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    progress.update(task, advance=50)
                    if result.returncode != 0:
                        raise Exception(f"Falha ao executar: {' '.join(cmd)}")
                
                progress.update(task, completed=100)
                console.print("[green]✓ Nmap instalado com sucesso![/green]")
                time.sleep(2)
                
            except Exception as e:
                console.print(f"[red]✗ Falha na instalação: {str(e)}[/red]")
                sys.exit(1)
    
    def mostrar_banner(self):
        banner = """
[bold blue]
╔═╗┌─┐┌┬┐┌─┐┌┬┐┬ ┬  ╔═╗┌─┐┌┬┐┌─┐┬─┐
║ ╦├─┤ │ ├─┤ │ ├─┤  ╚═╗├┤  │ ├┤ ├┬┘
╚═╝┴ ┴ ┴ ┴ ┴ ┴ ┴ ┴  ╚═╝└─┘ ┴ └─┘┴└─
[/bold blue]
[bold white on blue]        SCANNER DE PORTAS NMAP - NO ROOT EDITION[/bold white on blue]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink yellow]⚠️ USE APENAS EM REDES PRÓPRIAS OU AUTORIZADAS! ⚠️[/blink yellow]",
            style="yellow on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔍 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Categoria", style="green")
            tabela.add_column("Requisito Root", style="red")
            
            categorias = {
                '1': "Scans Básicos (No Root)",
                '2': "Scans Avançados (Root Recomendado)",
                '3': "Scans Especializados",
                '4': "Scans de Scripts NSE"
            }
            
            for opcao, descricao in categorias.items():
                req_root = "❌ Não" if opcao == '1' else "⚠️ Parcial" if opcao in ['3', '4'] else "✅ Sim"
                tabela.add_row(opcao, descricao, req_root)
            
            tabela.add_row("5", "Scanner Rápido de Portas", "❌ Não")
            tabela.add_row("6", "Scanner Personalizado", "⚙️")
            tabela.add_row("0", "Sair", "🚪")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=['1', '2', '3', '4', '5', '6', '0'],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_scans_basicos()
            elif escolha == "2":
                self._mostrar_scans_avancados()
            elif escolha == "3":
                self._mostrar_scans_especializados()
            elif escolha == "4":
                self._mostrar_scans_scripts()
            elif escolha == "5":
                self._scanner_rapido_portas()
            elif escolha == "6":
                self._scanner_personalizado()
            elif escolha == "0":
                self._sair()
    
    def _mostrar_scans_basicos(self):
        scans = {k: v for k, v in self.tecnicas_scanner.items() 
                if v['nivel'] == 'básico' and v['root'] == 'não necessário'}
        self._mostrar_submenu(scans, "Scans Básicos (No Root)")
    
    def _mostrar_scans_avancados(self):
        scans = {k: v for k, v in self.tecnicas_scanner.items() 
                if v['nivel'] in ['avançado', 'expert']}
        self._mostrar_submenu(scans, "Scans Avançados")
    
    def _mostrar_scans_especializados(self):
        scans = {k: v for k, v in self.tecnicas_scanner.items() 
                if v['nome'] in ['UDP Scan', 'IPv6 Scan', 'Custom Port Range', 'Top Ports']}
        self._mostrar_submenu(scans, "Scans Especializados")
    
    def _mostrar_scans_scripts(self):
        scans = {k: v for k, v in self.tecnicas_scanner.items() 
                if 'script' in k}
        self._mostrar_submenu(scans, "Scans de Scripts NSE")
    
    def _mostrar_submenu(self, scans: Dict, titulo: str):
        while True:
            console.clear()
            console.print(Panel.fit(f"[bold]{titulo}[/bold]", border_style="blue"))
            
            tabela = Table(
                show_header=True,
                header_style="bold green"
            )
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Técnica", style="yellow")
            tabela.add_column("Descrição", style="white")
            tabela.add_column("Root", style="red")
            tabela.add_column("Nível", style="magenta")
            
            for i, (codigo, scan) in enumerate(scans.items(), 1):
                root_icon = "✅" if scan['root'] == 'necessário' else "⚠️" if scan['root'] == 'recomendado' else "❌"
                tabela.add_row(
                    str(i),
                    scan['nome'],
                    scan['descricao'],
                    f"{root_icon} {scan['root']}",
                    scan['nivel']
                )
            
            tabela.add_row("0", "Voltar", "Retornar ao menu", "↩️", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(scans)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            nome_scan = list(scans.keys())[int(escolha)-1]
            self._executar_scan(nome_scan)
    
    def _executar_scan(self, nome_scan: str):
        scan_data = self.tecnicas_scanner[nome_scan]
        
        if scan_data['root'] == 'necessário':
            console.print(Panel.fit(
                "[bold red]⚠️ ROOT NECESSÁRIO ⚠️[/bold red]\n"
                "Este scan requer privilégios de root para funcionar completamente.\n"
                "Algumas funcionalidades podem ser limitadas sem root.",
                border_style="red"
            ))
            
            if not Confirm.ask("Continuar mesmo sem root?", default=False):
                return
        
        console.print(Panel.fit(
            f"[bold]Configuração do Scan: {scan_data['nome']}[/bold]",
            border_style="yellow"
        ))
        
        alvo = Prompt.ask("[yellow]?[/yellow] Alvo (IP, hostname ou rede)", default="127.0.0.1")
        
        comando_base = f"nmap {scan_data['comando']}"
        
        # Configurações adicionais baseadas no tipo de scan
        if nome_scan == 'custom_ports':
            portas = Prompt.ask(
                "[yellow]?[/yellow] Portas (ex: 80,443,1000-2000)",
                default="1-1000"
            )
            comando_base += f" {portas}"
        
        elif nome_scan == 'top_ports':
            quantidade = IntPrompt.ask(
                "[yellow]?[/yellow] Número de portas top",
                default=100
            )
            comando_base += f" {quantidade}"
        
        comando_final = f"{comando_base} {alvo}"
        
        console.print(f"\n[bold]Comando:[/bold] [cyan]{comando_final}[/cyan]")
        
        if not Confirm.ask("Executar scan?"):
            return
        
        self._rodar_comando_nmap(comando_final, scan_data['nome'])
    
    def _scanner_rapido_portas(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]🔍 Scanner Rápido de Portas Comuns[/bold]",
            border_style="green"
        ))
        
        # Mostrar portas comuns
        tabela = Table(title="Portas Comuns", show_header=True, header_style="bold blue")
        tabela.add_column("Porta", style="cyan")
        tabela.add_column("Serviço", style="green")
        tabela.add_column("Descrição", style="white")
        
        for porta, servico in self.portas_comuns.items():
            desc = self._obter_descricao_porta(porta)
            tabela.add_row(porta, servico, desc)
        
        console.print(tabela)
        
        alvo = Prompt.ask("\n[yellow]?[/yellow] Alvo", default="127.0.0.1")
        portas = ",".join(self.portas_comuns.keys())
        
        comando = f"nmap -sT -p {portas} {alvo}"
        
        console.print(f"\n[bold]Comando:[/bold] [cyan]{comando}[/cyan]")
        
        if Confirm.ask("Executar scan rápido?"):
            self._rodar_comando_nmap(comando, "Scan Rápido Portas Comuns")
    
    def _scanner_personalizado(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]🎛️ Scanner Personalizado[/bold]",
            border_style="magenta"
        ))
        
        alvo = Prompt.ask("[yellow]?[/yellow] Alvo", default="127.0.0.1")
        
        # Opções personalizáveis
        tipo_scan = Prompt.ask(
            "[yellow]?[/yellow] Tipo de scan",
            choices=['connect', 'syn', 'udp', 'null', 'fin', 'xmas', 'ack'],
            default='connect'
        )
        
        portas = Prompt.ask(
            "[yellow]?[/yellow] Portas (ex: 80,443,1000-2000)",
            default="1-1000"
        )
        
        timing = IntPrompt.ask(
            "[yellow]?[/yellow] Timing (0-5, onde 5 é mais rápido)",
            default=3,
            choices=['0', '1', '2', '3', '4', '5']
        )
        
        deteccao_versao = Confirm.ask("[yellow]?[/yellow] Detecção de versão?")
        scripts_nse = Confirm.ask("[yellow]?[/yellow] Executar scripts NSE?")
        
        # Construir comando
        comando = "nmap"
        
        # Tipo de scan
        if tipo_scan == 'connect':
            comando += " -sT"
        elif tipo_scan == 'syn':
            comando += " -sS"
        elif tipo_scan == 'udp':
            comando += " -sU"
        elif tipo_scan == 'null':
            comando += " -sN"
        elif tipo_scan == 'fin':
            comando += " -sF"
        elif tipo_scan == 'xmas':
            comando += " -sX"
        elif tipo_scan == 'ack':
            comando += " -sA"
        
        # Portas
        comando += f" -p {portas}"
        
        # Timing
        comando += f" -T{timing}"
        
        # Detecção de versão
        if deteccao_versao:
            comando += " -sV"
        
        # Scripts NSE
        if scripts_nse:
            comando += " -sC"
        
        comando += f" {alvo}"
        
        console.print(f"\n[bold]Comando personalizado:[/bold] [cyan]{comando}[/cyan]")
        
        if Confirm.ask("Executar scan personalizado?"):
            self._rodar_comando_nmap(comando, "Scan Personalizado")
    
    def _rodar_comando_nmap(self, comando: str, nome_scan: str):
        console.print(f"\n[bold]Executando:[/bold] [blue]{nome_scan}[/blue]")
        console.print(f"[grey]Comando: {comando}[/grey]")
        
        try:
            # Executar com progresso
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("[cyan]Scanning...", total=100)
                
                # Executar nmap em background
                processo = subprocess.Popen(
                    comando.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Simular progresso (nmap não tem saída de progresso real)
                for i in range(10):
                    time.sleep(0.5)
                    progress.update(task, advance=10)
                    if processo.poll() is not None:
                        break
                
                # Esperar término
                stdout, stderr = processo.communicate()
                progress.update(task, completed=100)
            
            # Mostrar resultados
            console.print(Panel.fit(
                "[bold green]✓ Scan concluído![/bold green]",
                border_style="green"
            ))
            
            if stdout:
                console.print(Panel.fit(
                    stdout,
                    title="[bold]Resultados[/bold]",
                    border_style="blue"
                ))
            
            if stderr:
                console.print(Panel.fit(
                    f"[yellow]{stderr}[/yellow]",
                    title="[bold]Avisos/Erros[/bold]",
                    border_style="yellow"
                ))
            
            # Salvar resultados
            if stdout and Confirm.ask("Salvar resultados em arquivo?"):
                nome_arquivo = Prompt.ask(
                    "[yellow]?[/yellow] Nome do arquivo",
                    default=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                with open(nome_arquivo, 'w') as f:
                    f.write(f"Comando: {comando}\n")
                    f.write(f"Data: {datetime.now()}\n")
                    f.write("\nResultados:\n")
                    f.write(stdout)
                
                console.print(f"[green]✓ Resultados salvos em {nome_arquivo}[/green]")
        
        except KeyboardInterrupt:
            console.print("\n[red]✗ Scan cancelado pelo usuário[/red]")
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro durante o scan: {str(e)}[/red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _obter_descricao_porta(self, porta: str) -> str:
        descricoes = {
            '21': "File Transfer Protocol",
            '22': "Secure Shell",
            '23': "Telnet Protocol",
            '25': "Simple Mail Transfer Protocol",
            '53': "Domain Name System",
            '80': "Hypertext Transfer Protocol",
            '110': "Post Office Protocol v3",
            '135': "Microsoft RPC",
            '139': "NetBIOS Session Service",
            '143': "Internet Message Access Protocol",
            '443': "HTTP Secure",
            '445': "Microsoft SMB",
            '993': "IMAP over SSL",
            '995': "POP3 over SSL",
            '1433': "Microsoft SQL Server",
            '3306': "MySQL Database",
            '3389': "Remote Desktop Protocol",
            '5432': "PostgreSQL Database",
            '5900': "Virtual Network Computing",
            '6379': "Redis Database",
            '27017': "MongoDB Database"
        }
        return descricoes.get(porta, "Serviço desconhecido")
    
    def _sair(self):
        console.print(Panel.fit(
            "[blink yellow]⚠️ LEMBRE-SE: SCANNING NÃO AUTORIZADO É CRIME! ⚠️[/blink yellow]",
            border_style="yellow"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        scanner = ScannerPortasNmap()
        scanner.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
