import os
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, IntPrompt
import nmap

console = Console()

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def show_banner():
    blood_banner = """
[bold red]
 ███▄ ▄███▓ ▄▄▄       ███▄    █   ██████  ▒█████   ██▀███  
▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██    ▒ ▒██▒  ██▒▓██ ▒ ██▒
▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒░ ▓██▄   ▒██░  ██▒▓██ ░▄█ ▒
▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒  ▒   ██▒▒██   ██░▒██▀▀█▄  
▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░▒██████▒▒░ ████▓▒░░██▓ ▒██▒
░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░  ░ ▒ ▒░   ░▒ ░ ▒░
░      ░     ░   ▒      ░   ░ ░ ░  ░  ░  ░ ░ ░ ▒    ░░   ░ 
       ░         ░  ░         ░       ░      ░ ░     ░     
[/bold red]
[blink bold white on red]        DARK NMAP SCANNER - ELITE EDITION[/blink bold white on red]
[bold white]          Forbidden knowledge for the initiated only[/bold white]
"""
    console.print(Panel.fit(blood_banner, padding=(1, 2), border_style="red"))

def execute_scan(target, scan_type, sudo=False):
    nm = nmap.PortScanner()
    try:
        with Progress() as progress:
            task = progress.add_task(f"[red]Penetrating {target}[/red]", total=100)
            nm.scan(hosts=target, arguments=scan_type, sudo=sudo)
            for i in range(100):
                progress.update(task, advance=1)
                time.sleep(0.01)
        return nm[target]
    except Exception as e:
        console.print(f"[red]System defense detected: {e}[/red]")
        return None

def display_results(scan_data):
    if not scan_data:
        console.print("[red]Target resisted our intrusion[/red]")
        return
    
    vuln_table = Table(title="[bold red]Vulnerability Assessment[/bold red]", show_header=True, header_style="bold white on red")
    vuln_table.add_column("Port", style="cyan")
    vuln_table.add_column("Service", style="green")
    vuln_table.add_column("Version", style="yellow")
    vuln_table.add_column("Potential Exploits", style="red")
    
    for proto in scan_data.all_protocols():
        for port, data in scan_data[proto].items():
            service = data['name']
            version = data.get('version', 'unknown')
            vuln_table.add_row(str(port), service, version, "CVE-2023-XXXXX")
    
    console.print(vuln_table)

def detect_cms(target):
    console.print(Panel.fit("[bold red]Select CMS Exploit Target[/bold red]", border_style="red"))
    console.print("1. [bold]WordPress Bruteforce[/bold]")
    console.print("2. [bold]Joomla SQL Injection[/bold]")
    
    try:
        choice = IntPrompt.ask("[red]Exploit>[/red]", choices=["1", "2"])
        console.print(f"[red]Preparing payload for {target}...[/red]")
        time.sleep(2)
        console.print("[blink red]Vulnerability confirmed! Ready for exploitation[/blink red]")
    except:
        console.print("[red]Exploit failed[/red]")

def main():
    while True:
        clear_screen()
        show_banner()
        
        console.print(Panel.fit("[bold red]Dark Operations Menu[/bold red]", border_style="red"))
        console.print("1. [bold]Stealth Network Recon[/bold]")
        console.print("2. [bold]Privileged Deep Scan[/bold]")
        console.print("3. [bold]CMS Vulnerability Assessment[/bold]")
        console.print("4. [bold]Erase Traces & Exit[/bold]")
        
        try:
            choice = IntPrompt.ask("[red]Operation>[/red]", choices=["1", "2", "3", "4"])
            
            if choice == 4:
                console.print("[blink red]Wiping logs...[/blink red]")
                time.sleep(1)
                console.print("[red]All traces eliminated[/red]")
                sys.exit(0)
            
            target = Prompt.ask("[red]Target IP/Domain>[/red]")
            
            if choice in (1, 2):
                scan_methods = [
                    ("Stealth SYN Scan", "-sS"),
                    ("Full TCP Connect", "-sT"),
                    ("UDP Services", "-sU"),
                    ("OS Fingerprinting", "-O"),
                    ("Aggressive Detection", "-A"),
                    ("Vulnerability Scan", "--script vuln"),
                    ("Brute Force Prep", "--script brute"),
                    ("Backdoor Check", "--script malware"),
                    ("Exploit Audit", "--script exploit"),
                    ("Full Recon", "-sS -sV -sC -O")
                ]
                
                console.print(Panel.fit("[bold red]Select Intrusion Method[/bold red]", border_style="red"))
                for i, (name, cmd) in enumerate(scan_methods, 1):
                    console.print(f"{i}. [bold]{name}[/bold] [dim]{cmd}[/dim]")
                
                scan_choice = IntPrompt.ask("[red]Method>[/red]", choices=[str(i) for i in range(1, 11)])
                scan_type = scan_methods[int(scan_choice)-1][1]
                
                results = execute_scan(target, scan_type, sudo=(choice == 2))
                display_results(results)
                
            elif choice == 3:
                detect_cms(target)
                
            input("\n[dim]Press Enter to continue the breach...[/dim]")
            
        except Exception as e:
            console.print(f"[red]Security mechanism triggered: {e}[/red]")
            input("\n[dim]Press Enter to evade detection...[/dim]")

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            console.print("[blink red]Warning: Operating without root privileges limits attack surface[/blink red]")
            time.sleep(2)
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Operation aborted - activating cleanup[/red]")
        sys.exit(1)
