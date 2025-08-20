#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import threading
import socket
import select
from typing import Dict, List, Optional, Tuple

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
from rich.style import Style

console = Console()

class NetcatTool:
    def __init__(self):
        self.banner = self._gerar_banner_netcat()
        self.config = {
            'mode': 'listen',
            'host': '0.0.0.0',
            'port': 4444,
            'protocol': 'tcp',
            'verbose': True,
            'keep_alive': False,
            'timeout': 30,
            'output_file': None,
            'execute_command': None,
            'hex_dump': False
        }
        
        self.modes = {
            'listen': 'Modo escuta (servidor)',
            'connect': 'Modo conexão (cliente)',
            'proxy': 'Modo proxy',
            'port_scan': 'Varredura de portas'
        }
        
        self.protocols = {
            'tcp': 'TCP - Conexão confiável',
            'udp': 'UDP - Conexão sem conexão'
        }
    
    def _gerar_banner_netcat(self) -> str:
        return """
[bold cyan]
╔═╗┬ ┬┌┬┐┌┬┐┌─┐┌─┐┌┬┐
╠═╝│ │ │  │ │ │└─┐ │ 
╩  └─┘ ┴  ┴ └─┘└─┘ ┴ 
[/bold cyan]
[bold blue]        FERRAMENTA NETCAT AVANÇADA - v2.0[/bold blue]
[bold yellow]        Swiss Army Knife de Redes[/bold yellow]
"""
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            console.print(self.banner)
            
            tabela = Table(
                title="[bold green]🔧 MENU NETCAT[/bold green]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=8)
            tabela.add_column("Função", style="green")
            tabela.add_column("Status", style="yellow")
            
            tabela.add_row("1", "Modo Escuta (Servidor)", "🔄 Aguardando conexões")
            tabela.add_row("2", "Modo Conexão (Cliente)", "📡 Conectar a servidor")
            tabela.add_row("3", "Varredura de Portas", "🔍 Scanner de portas")
            tabela.add_row("4", "Modo Proxy", "🔁 Relay de conexões")
            tabela.add_row("5", "Configurações", "⚙️ Personalizar opções")
            tabela.add_row("6", "Status da Config", "📋 Visualizar configuração")
            tabela.add_row("0", "Voltar", "↩️ Menu anterior")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=[str(i) for i in range(0, 7)],
                show_choices=False
            )
            
            if escolha == "1":
                self._modo_escuta()
            elif escolha == "2":
                self._modo_conexao()
            elif escolha == "3":
                self._varredura_portas()
            elif escolha == "4":
                self._modo_proxy()
            elif escolha == "5":
                self._menu_configuracao()
            elif escolha == "6":
                self._mostrar_configuracao()
            elif escolha == "0":
                return
    
    def _menu_configuracao(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES NETCAT[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", f"Host: {self.config['host']}")
            tabela.add_row("2", f"Porta: {self.config['port']}")
            tabela.add_row("3", f"Protocolo: {self.config['protocol'].upper()}")
            tabela.add_row("4", f"Verbose: {'✅' if self.config['verbose'] else '❌'}")
            tabela.add_row("5", f"Keep Alive: {'✅' if self.config['keep_alive'] else '❌'}")
            tabela.add_row("6", f"Timeout: {self.config['timeout']}s")
            tabela.add_row("7", f"Arquivo Saída: {self.config['output_file'] or 'Nenhum'}")
            tabela.add_row("8", f"Executar Comando: {self.config['execute_command'] or 'Nenhum'}")
            tabela.add_row("9", f"Hex Dump: {'✅' if self.config['hex_dump'] else '❌'}")
            tabela.add_row("0", "Voltar")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione para alterar",
                choices=[str(i) for i in range(0, 10)],
                show_choices=False
            )
            
            if escolha == "1":
                self.config['host'] = Prompt.ask(
                    "[yellow]?[/yellow] Digite o host",
                    default=self.config['host']
                )
            elif escolha == "2":
                self.config['port'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Digite a porta",
                    default=self.config['port']
                )
            elif escolha == "3":
                console.print("\n[bold]Protocolos disponíveis:[/bold]")
                for proto, desc in self.protocols.items():
                    console.print(f"  [cyan]{proto}[/cyan]: {desc}")
                
                self.config['protocol'] = Prompt.ask(
                    "[yellow]?[/yellow] Selecione o protocolo",
                    choices=list(self.protocols.keys()),
                    default=self.config['protocol']
                )
            elif escolha == "4":
                self.config['verbose'] = Confirm.ask(
                    "[yellow]?[/yellow] Modo verbose",
                    default=self.config['verbose']
                )
            elif escolha == "5":
                self.config['keep_alive'] = Confirm.ask(
                    "[yellow]?[/yellow] Manter conexão ativa",
                    default=self.config['keep_alive']
                )
            elif escolha == "6":
                self.config['timeout'] = IntPrompt.ask(
                    "[yellow]?[/yellow] Timeout (segundos)",
                    default=self.config['timeout']
                )
            elif escolha == "7":
                arquivo = Prompt.ask(
                    "[yellow]?[/yellow] Arquivo de saída (deixe vazio para nenhum)",
                    default=""
                )
                self.config['output_file'] = arquivo if arquivo else None
            elif escolha == "8":
                comando = Prompt.ask(
                    "[yellow]?[/yellow] Comando para executar na conexão",
                    default=""
                )
                self.config['execute_command'] = comando if comando else None
            elif escolha == "9":
                self.config['hex_dump'] = Confirm.ask(
                    "[yellow]?[/yellow] Mostrar hex dump",
                    default=self.config['hex_dump']
                )
            elif escolha == "0":
                return
    
    def _mostrar_configuracao(self):
        console.print(Panel.fit(
            f"""[bold]Configuração Atual:[/bold]
[cyan]Host:[/cyan] {self.config['host']}
[cyan]Porta:[/cyan] {self.config['port']}
[cyan]Protocolo:[/cyan] {self.config['protocol'].upper()}
[cyan]Verbose:[/cyan] {'✅' if self.config['verbose'] else '❌'}
[cyan]Keep Alive:[/cyan] {'✅' if self.config['keep_alive'] else '❌'}
[cyan]Timeout:[/cyan] {self.config['timeout']}s
[cyan]Arquivo Saída:[/cyan] {self.config['output_file'] or 'Nenhum'}
[cyan]Executar Comando:[/cyan] {self.config['execute_command'] or 'Nenhum'}
[cyan]Hex Dump:[/cyan] {'✅' if self.config['hex_dump'] else '❌'}""",
            title="[bold green]CONFIGURAÇÃO[/bold green]",
            border_style="green"
        ))
        input("\nPressione Enter para continuar...")
    
    def _modo_escuta(self):
        console.print(Panel.fit(
            "[bold red]🔊 MODO ESCUTA (SERVIDOR)[/bold red]",
            border_style="red"
        ))
        
        console.print(f"[yellow]Escutando em:[/yellow] {self.config['host']}:{self.config['port']}")
        console.print(f"[yellow]Protocolo:[/yellow] {self.config['protocol'].upper()}")
        
        if self.config['execute_command']:
            console.print(f"[yellow]Executando:[/yellow] {self.config['execute_command']}")
        
        try:
            if self.config['protocol'] == 'tcp':
                self._escuta_tcp()
            else:
                self._escuta_udp()
                
        except KeyboardInterrupt:
            console.print("\n[red]✗ Interrompido pelo usuário[/red]")
        except Exception as e:
            console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _escuta_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.config['host'], self.config['port']))
            s.listen(1)
            
            console.print(f"[green]✅ Escutando na porta {self.config['port']}...[/green]")
            console.print("[yellow]Pressione Ctrl+C para parar[/yellow]")
            
            conn, addr = s.accept()
            with conn:
                console.print(f"[green]🔗 Conexão estabelecida de {addr[0]}:{addr[1]}[/green]")
                
                # Executar comando se especificado
                if self.config['execute_command']:
                    output = subprocess.getoutput(self.config['execute_command'])
                    conn.sendall(output.encode())
                
                # Loop principal de comunicação
                while True:
                    try:
                        data = conn.recv(1024)
                        if not data:
                            break
                            
                        if self.config['hex_dump']:
                            hex_data = ' '.join(f'{b:02x}' for b in data)
                            console.print(f"[cyan]HEX:[/cyan] {hex_data}")
                        
                        texto = data.decode('utf-8', errors='ignore')
                        console.print(f"[blue]RECV:[/blue] {texto}")
                        
                        # Salvar em arquivo se especificado
                        if self.config['output_file']:
                            with open(self.config['output_file'], 'a') as f:
                                f.write(texto)
                        
                        # Echo response
                        if self.config['keep_alive']:
                            conn.sendall(data)
                            
                    except (ConnectionResetError, BrokenPipeError):
                        break
            
            console.print("[red]📴 Conexão fechada[/red]")
    
    def _escuta_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((self.config['host'], self.config['port']))
            
            console.print(f"[green]✅ Escutando UDP na porta {self.config['port']}...[/green]")
            console.print("[yellow]Pressione Ctrl+C para parar[/yellow]")
            
            while True:
                try:
                    data, addr = s.recvfrom(1024)
                    console.print(f"[green]📨 UDP de {addr[0]}:{addr[1]}[/green]")
                    
                    if self.config['hex_dump']:
                        hex_data = ' '.join(f'{b:02x}' for b in data)
                        console.print(f"[cyan]HEX:[/cyan] {hex_data}")
                    
                    texto = data.decode('utf-8', errors='ignore')
                    console.print(f"[blue]RECV:[/blue] {texto}")
                    
                    # Salvar em arquivo se especificado
                    if self.config['output_file']:
                        with open(self.config['output_file'], 'a') as f:
                            f.write(f"[{datetime.now()}] {addr}: {texto}\n")
                    
                    # Echo response
                    if self.config['keep_alive']:
                        s.sendto(data, addr)
                        
                except KeyboardInterrupt:
                    break
    
    def _modo_conexao(self):
        console.print(Panel.fit(
            "[bold green]📡 MODO CONEXÃO (CLIENTE)[/bold green]",
            border_style="green"
        ))
        
        host = Prompt.ask(
            "[yellow]?[/yellow] Digite o host para conectar",
            default=self.config['host']
        )
        porta = IntPrompt.ask(
            "[yellow]?[/yellow] Digite a porta",
            default=self.config['port']
        )
        
        try:
            if self.config['protocol'] == 'tcp':
                self._conectar_tcp(host, porta)
            else:
                self._conectar_udp(host, porta)
                
        except KeyboardInterrupt:
            console.print("\n[red]✗ Interrompido pelo usuário[/red]")
        except Exception as e:
            console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _conectar_tcp(self, host: str, porta: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.config['timeout'])
            s.connect((host, porta))
            
            console.print(f"[green]✅ Conectado a {host}:{porta}[/green]")
            console.print("[yellow]Digite 'quit' para sair[/yellow]")
            
            # Thread para receber dados
            def receiver():
                while True:
                    try:
                        data = s.recv(1024)
                        if not data:
                            break
                            
                        if self.config['hex_dump']:
                            hex_data = ' '.join(f'{b:02x}' for b in data)
                            console.print(f"\n[cyan]HEX:[/cyan] {hex_data}")
                        
                        texto = data.decode('utf-8', errors='ignore')
                        console.print(f"\n[green]RECV:[/green] {texto}")
                        
                    except (socket.timeout, ConnectionResetError):
                        break
            
            recv_thread = threading.Thread(target=receiver, daemon=True)
            recv_thread.start()
            
            # Loop principal para enviar dados
            while True:
                try:
                    mensagem = input("[blue]SEND: [/blue]")
                    
                    if mensagem.lower() == 'quit':
                        break
                    
                    s.sendall(mensagem.encode())
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    break
            
            console.print("[red]📴 Conexão fechada[/red]")
    
    def _conectar_udp(self, host: str, porta: int):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            console.print(f"[green]🔗 Socket UDP criado para {host}:{porta}[/green]")
            console.print("[yellow]Digite 'quit' para sair[/yellow]")
            
            while True:
                try:
                    mensagem = input("[blue]SEND: [/blue]")
                    
                    if mensagem.lower() == 'quit':
                        break
                    
                    s.sendto(mensagem.encode(), (host, porta))
                    
                    # Tentar receber resposta
                    try:
                        s.settimeout(2)
                        data, addr = s.recvfrom(1024)
                        
                        if self.config['hex_dump']:
                            hex_data = ' '.join(f'{b:02x}' for b in data)
                            console.print(f"\n[cyan]HEX:[/cyan] {hex_data}")
                        
                        texto = data.decode('utf-8', errors='ignore')
                        console.print(f"\n[green]RECV from {addr}:[/green] {texto}")
                        
                    except socket.timeout:
                        console.print("\n[yellow]⏰ Timeout aguardando resposta[/yellow]")
                    
                except KeyboardInterrupt:
                    break
    
    def _varredura_portas(self):
        console.print(Panel.fit(
            "[bold yellow]🔍 VARREDURA DE PORTAS[/bold yellow]",
            border_style="yellow"
        ))
        
        host = Prompt.ask(
            "[yellow]?[/yellow] Digite o host para scanear",
            default="127.0.0.1"
        )
        
        porta_inicio = IntPrompt.ask(
            "[yellow]?[/yellow] Porta inicial",
            default=1
        )
        porta_fim = IntPrompt.ask(
            "[yellow]?[/yellow] Porta final",
            default=1024
        )
        
        protocolo = Prompt.ask(
            "[yellow]?[/yellow] Protocolo (tcp/udp)",
            choices=['tcp', 'udp'],
            default='tcp'
        )
        
        timeout = IntPrompt.ask(
            "[yellow]?[/yellow] Timeout por porta (ms)",
            default=500
        ) / 1000  # Converter para segundos
        
        console.print(f"\n[cyan]Scanning {host}:{porta_inicio}-{porta_fim} ({protocolo.upper()})[/cyan]")
        
        portas_abertas = []
        
        with Progress() as progress:
            task = progress.add_task("[yellow]Scanning...[/yellow]", total=porta_fim - porta_inicio + 1)
            
            for porta in range(porta_inicio, porta_fim + 1):
                try:
                    if protocolo == 'tcp':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        resultado = sock.connect_ex((host, porta))
                        sock.close()
                        
                        if resultado == 0:
                            portas_abertas.append(porta)
                            console.print(f"[green]✅ Porta {porta} aberta (TCP)[/green]")
                    
                    else:  # UDP
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(timeout)
                        sock.sendto(b'', (host, porta))
                        
                        try:
                            data, addr = sock.recvfrom(1024)
                            portas_abertas.append(porta)
                            console.print(f"[green]✅ Porta {porta} respondeu (UDP)[/green]")
                        except socket.timeout:
                            pass
                        finally:
                            sock.close()
                    
                except Exception as e:
                    if self.config['verbose']:
                        console.print(f"[red]Erro na porta {porta}: {str(e)}[/red]")
                
                progress.update(task, advance=1)
        
        # Mostrar resultados
        console.print(Panel.fit(
            f"""[bold]RESULTADOS DO SCAN:[/bold]
[cyan]Host:[/cyan] {host}
[cyan]Portas escaneadas:[/cyan] {porta_inicio}-{porta_fim}
[cyan]Protocolo:[/cyan] {protocolo.upper()}
[cyan]Portas abertas:[/cyan] {', '.join(map(str, portas_abertas)) if portas_abertas else 'Nenhuma'}
[cyan]Total:[/cyan] {len(portas_abertas)} portas abertas""",
            title="[bold green]SCAN COMPLETO[/bold green]",
            border_style="green"
        ))
        
        input("\nPressione Enter para continuar...")
    
    def _modo_proxy(self):
        console.print(Panel.fit(
            "[bold magenta]🔁 MODO PROXY[/bold magenta]",
            border_style="magenta"
        ))
        
        console.print("[yellow]Este modo redireciona tráfego entre duas conexões[/yellow]")
        
        local_port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta local para escutar",
            default=8080
        )
        remote_host = Prompt.ask(
            "[yellow]?[/yellow] Host remoto para redirecionar",
            default="example.com"
        )
        remote_port = IntPrompt.ask(
            "[yellow]?[/yellow] Porta remota",
            default=80
        )
        
        console.print(f"[cyan]🔀 Redirecionando localhost:{local_port} -> {remote_host}:{remote_port}[/cyan]")
        
        try:
            self._iniciar_proxy(local_port, remote_host, remote_port)
        except KeyboardInterrupt:
            console.print("\n[red]✗ Proxy interrompido[/red]")
        except Exception as e:
            console.print(f"\n[red]✗ Erro no proxy: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _iniciar_proxy(self, local_port: int, remote_host: str, remote_port: int):
        def handle_client(client_sock):
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.connect((remote_host, remote_port))
                
                # Threads para forwarding bidirecional
                def forward(source, destination, name):
                    try:
                        while True:
                            data = source.recv(4096)
                            if not data:
                                break
                            if self.config['verbose']:
                                console.print(f"[blue]{name}:[/blue] {len(data)} bytes")
                            destination.sendall(data)
                    except:
                        pass
                
                # Iniciar threads de forwarding
                threads = [
                    threading.Thread(target=forward, args=(client_sock, remote_sock, "CLIENT→REMOTE")),
                    threading.Thread(target=forward, args=(remote_sock, client_sock, "REMOTE→CLIENT"))
                ]
                
                for t in threads:
                    t.daemon = True
                    t.start()
                
                for t in threads:
                    t.join()
                    
            except Exception as e:
                if self.config['verbose']:
                    console.print(f"[red]Erro no proxy: {str(e)}[/red]")
            finally:
                client_sock.close()
                remote_sock.close()
        
        # Servidor proxy
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind(('0.0.0.0', local_port))
        proxy_sock.listen(5)
        
        console.print(f"[green]✅ Proxy escutando na porta {local_port}[/green]")
        console.print("[yellow]Pressione Ctrl+C para parar[/yellow]")
        
        try:
            while True:
                client_sock, addr = proxy_sock.accept()
                console.print(f"[cyan]🔗 Nova conexão de {addr[0]}:{addr[1]}[/cyan]")
                
                client_thread = threading.Thread(target=handle_client, args=(client_sock,))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            pass
        finally:
            proxy_sock.close()

# Integração com o menu principal existente
def main():
    netcat_tool = NetcatTool()
    netcat_tool.mostrar_menu_principal()

if __name__ == '__main__':
    main()
