#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import requests
import socket
import threading
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

class VPNManager:
    def __init__(self):
        self.vpn_config_dir = "vpn_configs"
        self.openvpn_installed = False
        self.wireguard_installed = False
        self.current_vpn = None
        self.check_dependencies()
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██╗   ██╗██████╗ ███╗   ██╗      ██████╗ ██████╗ ███╗   ██╗║
║  ██║   ██║██╔══██╗████╗  ██║     ██╔════╝██╔═══██╗████╗  ██║║
║  ██║   ██║██████╔╝██╔██╗ ██║     ██║     ██║   ██║██╔██╗ ██║║
║  ██║   ██║██╔═══╝ ██║╚██╗██║     ██║     ██║   ██║██║╚██╗██║║
║  ╚██████╔╝██║     ██║ ╚████║     ╚██████╗╚██████╔╝██║ ╚████║║
║   ╚═════╝ ╚═╝     ╚═╝  ╚═══╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝║
║                                                              ║
║                PROFESSIONAL VPN MANAGER v2.0                 ║
║                     Secure Your Connection                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def check_dependencies(self):
        """Verifica e instala dependências necessárias"""
        print(f"{Fore.YELLOW}[*] Verificando dependências...{Style.RESET_ALL}")
        
        # Verificar OpenVPN
        try:
            subprocess.run(["openvpn", "--version"], capture_output=True, check=True)
            self.openvpn_installed = True
            print(f"{Fore.GREEN}[✓] OpenVPN instalado{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[✗] OpenVPN não encontrado{Style.RESET_ALL}")
        
        # Verificar WireGuard
        try:
            subprocess.run(["wg", "--version"], capture_output=True, check=True)
            self.wireguard_installed = True
            print(f"{Fore.GREEN}[✓] WireGuard instalado{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[✗] WireGuard não encontrado{Style.RESET_ALL}")
        
        # Verificar curl
        try:
            subprocess.run(["curl", "--version"], capture_output=True, check=True)
            print(f"{Fore.GREEN}[✓] curl instalado{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[✗] curl não encontrado{Style.RESET_ALL}")
    
    def install_dependencies(self):
        """Instala as dependências necessárias"""
        print(f"{Fore.YELLOW}[*] Instalando dependências...{Style.RESET_ALL}")
        
        if os.name == 'posix':  # Linux/Unix
            if subprocess.run(["which", "apt-get"], capture_output=True).returncode == 0:
                # Debian/Ubuntu
                commands = [
                    "sudo apt-get update",
                    "sudo apt-get install -y openvpn wireguard curl resolvconf"
                ]
            elif subprocess.run(["which", "yum"], capture_output=True).returncode == 0:
                # CentOS/RHEL
                commands = [
                    "sudo yum install -y epel-release",
                    "sudo yum install -y openvpn wireguard-tools curl"
                ]
            else:
                print(f"{Fore.RED}[!] Gerenciador de pacotes não suportado{Style.RESET_ALL}")
                return False
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, check=True)
                    print(f"{Fore.GREEN}[+] Comando executado: {cmd}{Style.RESET_ALL}")
                except subprocess.CalledProcessError as e:
                    print(f"{Fore.RED}[!] Erro ao executar: {cmd}{Style.RESET_ALL}")
                    return False
        
        self.check_dependencies()
        return True
    
    def get_public_ip(self):
        """Obtém o IP público atual"""
        try:
            response = requests.get('https://api.ipify.org', timeout=10)
            return response.text
        except:
            return "Não disponível"
    
    def check_vpn_status(self):
        """Verifica se há uma conexão VPN ativa"""
        try:
            # Verifica interfaces de rede VPN
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            vpn_interfaces = ["tun", "wg", "ppp"]
            
            for interface in vpn_interfaces:
                if interface in result.stdout:
                    return True
            
            return False
        except:
            return False
    
    def download_vpn_configs(self):
        """Baixa configurações VPN gratuitas"""
        if not os.path.exists(self.vpn_config_dir):
            os.makedirs(self.vpn_config_dir)
            print(f"{Fore.GREEN}[+] Diretório de configurações criado{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] Baixando configurações VPN...{Style.RESET_ALL}")
        
        # Configurações OpenVPN gratuitas
        vpn_providers = [
            {
                "name": "VPNGate",
                "url": "http://www.vpngate.net/api/iphone/",
                "file": "vpngate.csv"
            },
            {
                "name": "FreeOpenVPN",
                "url": "https://freeopenvpn.org/pl/cc/pl-free.ovpn",
                "file": "freeopenvpn.ovpn"
            }
        ]
        
        for provider in vpn_providers:
            try:
                print(f"{Fore.CYAN}[*] Baixando {provider['name']}...{Style.RESET_ALL}")
                response = requests.get(provider['url'], timeout=30)
                
                if response.status_code == 200:
                    file_path = os.path.join(self.vpn_config_dir, provider['file'])
                    with open(file_path, 'w') as f:
                        f.write(response.text)
                    print(f"{Fore.GREEN}[+] {provider['name']} baixado com sucesso{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Erro ao baixar {provider['name']}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")
    
    def create_wireguard_config(self):
        """Cria configuração WireGuard de exemplo"""
        wg_dir = os.path.join(self.vpn_config_dir, "wireguard")
        if not os.path.exists(wg_dir):
            os.makedirs(wg_dir)
        
        # Configuração de exemplo
        config_content = """[Interface]
PrivateKey = YOUR_PRIVATE_KEY_HERE
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = server.example.com:51820
AllowedIPs = 0.0.0.0/0
"""
        
        config_path = os.path.join(wg_dir, "example.conf")
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        print(f"{Fore.GREEN}[+] Configuração WireGuard criada: {config_path}{Style.RESET_ALL}")
    
    def start_openvpn(self):
        """Inicia conexão OpenVPN"""
        if not self.openvpn_installed:
            print(f"{Fore.RED}[!] OpenVPN não está instalado{Style.RESET_ALL}")
            return False
        
        configs = [f for f in os.listdir(self.vpn_config_dir) if f.endswith('.ovpn')]
        
        if not configs:
            print(f"{Fore.RED}[!] Nenhuma configuração OpenVPN encontrada{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.CYAN}[*] Configurações disponíveis:{Style.RESET_ALL}")
        for i, config in enumerate(configs, 1):
            print(f"{i}. {config}")
        
        try:
            choice = int(input(f"\n{Fore.GREEN}Escolha uma configuração (1-{len(configs)}): {Style.RESET_ALL}")) - 1
            selected_config = configs[choice]
        except:
            print(f"{Fore.RED}[!] Escolha inválida{Style.RESET_ALL}")
            return False
        
        config_path = os.path.join(self.vpn_config_dir, selected_config)
        
        print(f"{Fore.YELLOW}[*] Iniciando OpenVPN com {selected_config}...{Style.RESET_ALL}")
        
        try:
            # Inicia OpenVPN em background
            process = subprocess.Popen(
                ["sudo", "openvpn", "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.current_vpn = {
                "type": "openvpn",
                "process": process,
                "config": selected_config
            }
            
            print(f"{Fore.GREEN}[+] OpenVPN iniciado. Verificando conexão...{Style.RESET_ALL}")
            
            # Aguarda a conexão ser estabelecida
            time.sleep(5)
            
            if self.check_vpn_status():
                print(f"{Fore.GREEN}[✓] VPN conectada com sucesso!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] Falha ao conectar VPN{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao iniciar OpenVPN: {e}{Style.RESET_ALL}")
            return False
    
    def start_wireguard(self):
        """Inicia conexão WireGuard"""
        if not self.wireguard_installed:
            print(f"{Fore.RED}[!] WireGuard não está instalado{Style.RESET_ALL}")
            return False
        
        wg_dir = os.path.join(self.vpn_config_dir, "wireguard")
        if not os.path.exists(wg_dir):
            os.makedirs(wg_dir)
        
        configs = [f for f in os.listdir(wg_dir) if f.endswith('.conf')]
        
        if not configs:
            print(f"{Fore.RED}[!] Nenhuma configuração WireGuard encontrada{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.CYAN}[*] Configurações disponíveis:{Style.RESET_ALL}")
        for i, config in enumerate(configs, 1):
            print(f"{i}. {config}")
        
        try:
            choice = int(input(f"\n{Fore.GREEN}Escolha uma configuração (1-{len(configs)}): {Style.RESET_ALL}")) - 1
            selected_config = configs[choice]
        except:
            print(f"{Fore.RED}[!] Escolha inválida{Style.RESET_ALL}")
            return False
        
        config_path = os.path.join(wg_dir, selected_config)
        interface_name = selected_config.replace('.conf', '')
        
        print(f"{Fore.YELLOW}[*] Iniciando WireGuard com {selected_config}...{Style.RESET_ALL}")
        
        try:
            # Para interface existente
            subprocess.run(["sudo", "wg-quick", "down", interface_name], 
                         capture_output=True)
            
            # Inicia nova interface
            result = subprocess.run(
                ["sudo", "wg-quick", "up", config_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.current_vpn = {
                    "type": "wireguard",
                    "interface": interface_name,
                    "config": selected_config
                }
                
                print(f"{Fore.GREEN}[+] WireGuard iniciado. Verificando conexão...{Style.RESET_ALL}")
                time.sleep(3)
                
                if self.check_vpn_status():
                    print(f"{Fore.GREEN}[✓] VPN WireGuard conectada com sucesso!{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}[!] Falha ao conectar VPN WireGuard{Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.RED}[!] Erro ao iniciar WireGuard: {result.stderr}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao iniciar WireGuard: {e}{Style.RESET_ALL}")
            return False
    
    def stop_vpn(self):
        """Para a conexão VPN atual"""
        if not self.current_vpn:
            print(f"{Fore.YELLOW}[!] Nenhuma VPN ativa{Style.RESET_ALL}")
            return True
        
        print(f"{Fore.YELLOW}[*] Parando VPN...{Style.RESET_ALL}")
        
        try:
            if self.current_vpn["type"] == "openvpn":
                if self.current_vpn["process"]:
                    self.current_vpn["process"].terminate()
                    self.current_vpn["process"].wait()
                    print(f"{Fore.GREEN}[+] OpenVPN parado{Style.RESET_ALL}")
            
            elif self.current_vpn["type"] == "wireguard":
                subprocess.run(["sudo", "wg-quick", "down", self.current_vpn["interface"]], 
                             capture_output=True)
                print(f"{Fore.GREEN}[+] WireGuard parado{Style.RESET_ALL}")
            
            self.current_vpn = None
            
            # Verifica se a VPN foi realmente desativada
            time.sleep(2)
            if not self.check_vpn_status():
                print(f"{Fore.GREEN}[✓] VPN desconectada com sucesso!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] A VPN pode não ter sido completamente desativada{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao parar VPN: {e}{Style.RESET_ALL}")
            return False
    
    def show_status(self):
        """Mostra status completo da VPN"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      STATUS DA VPN                          ║")
        print(f"╠══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        # IP Público
        ip = self.get_public_ip()
        print(f"{Fore.CYAN}║ {Fore.GREEN}IP Público: {Fore.WHITE}{ip:<45} {Fore.CYAN}║")
        
        # Status VPN
        vpn_active = self.check_vpn_status()
        status_text = f"{Fore.GREEN}ATIVA{Style.RESET_ALL}" if vpn_active else f"{Fore.RED}INATIVA{Style.RESET_ALL}"
        print(f"{Fore.CYAN}║ {Fore.GREEN}Status VPN: {status_text:<45} {Fore.CYAN}║")
        
        # VPN Atual
        if self.current_vpn:
            vpn_info = f"{self.current_vpn['type']} - {self.current_vpn['config']}"
            print(f"{Fore.CYAN}║ {Fore.GREEN}Conexão Atual: {Fore.WHITE}{vpn_info:<35} {Fore.CYAN}║")
        
        # Dependências
        deps = []
        if self.openvpn_installed: deps.append("OpenVPN")
        if self.wireguard_installed: deps.append("WireGuard")
        deps_text = ", ".join(deps) if deps else "Nenhuma"
        print(f"{Fore.CYAN}║ {Fore.GREEN}Dependências: {Fore.WHITE}{deps_text:<38} {Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    def speed_test(self):
        """Testa a velocidade da conexão"""
        print(f"{Fore.YELLOW}[*] Testando velocidade... Isso pode levar alguns segundos.{Style.RESET_ALL}")
        
        try:
            # Teste simples de velocidade usando speedtest-cli
            import speedtest
            
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            
            print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
            print(f"║                     TESTE DE VELOCIDADE                     ║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            print(f"║ {Fore.CYAN}Download: {Fore.WHITE}{download_speed:.2f} Mbps{Fore.GREEN}{' ':38}║")
            print(f"║ {Fore.CYAN}Upload: {Fore.WHITE}{upload_speed:.2f} Mbps{Fore.GREEN}{' ':40}║")
            print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
        except ImportError:
            print(f"{Fore.RED}[!] speedtest-cli não instalado. Instale com: pip3 install speedtest-cli{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro no teste de velocidade: {e}{Style.RESET_ALL}")
    
    def show_menu(self):
        """Exibe o menu principal"""
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                         MENU VPN                             ║
╠══════════════════════════════════════════════════════════════╣
║ {Fore.GREEN}1.{Fore.CYAN}  Instalar Dependências                          {Fore.CYAN}      ║
║ {Fore.GREEN}2.{Fore.CYAN}  Baixar Configurações VPN                       {Fore.CYAN}      ║
║ {Fore.GREEN}3.{Fore.CYAN}  Conectar OpenVPN                               {Fore.CYAN}      ║
║ {Fore.GREEN}4.{Fore.CYAN}  Conectar WireGuard                             {Fore.CYAN}      ║
║ {Fore.GREEN}5.{Fore.CYAN}  Desconectar VPN                                {Fore.CYAN}      ║
║ {Fore.GREEN}6.{Fore.CYAN}  Status da Conexão                              {Fore.CYAN}      ║
║ {Fore.GREEN}7.{Fore.CYAN}  Teste de Velocidade                            {Fore.CYAN}      ║
║ {Fore.GREEN}8.{Fore.CYAN}  Criar Configuração WireGuard                   {Fore.CYAN}      ║
║ {Fore.GREEN}9.{Fore.CYAN}  Sair                                           {Fore.CYAN}      ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(menu)
    
    def main(self):
        """Função principal"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_menu()
            
            choice = input(f"{Fore.GREEN}Escolha uma opção (1-9): {Style.RESET_ALL}")
            
            if choice == "1":
                self.install_dependencies()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "2":
                self.download_vpn_configs()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "3":
                self.start_openvpn()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "4":
                self.start_wireguard()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "5":
                self.stop_vpn()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "6":
                self.show_status()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "7":
                self.speed_test()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "8":
                self.create_wireguard_config()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "9":
                if self.current_vpn:
                    self.stop_vpn()
                print(f"{Fore.RED}\n[!] Saindo... Conexão segura!{Style.RESET_ALL}")
                break
            
            else:
                print(f"{Fore.RED}[!] Opção inválida! Tente novamente.{Style.RESET_ALL}")
                time.sleep(2)

if __name__ == "__main__":
    # Verificar se é root (necessário para VPN)
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script requer privilégios de root para funcionar corretamente.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Execute com: sudo python3 vpn_manager.py{Style.RESET_ALL}")
        sys.exit(1)
    
    # Verificar Python3
    try:
        subprocess.run(["python3", "--version"], capture_output=True, check=True)
    except:
        print(f"{Fore.RED}[!] Python3 não encontrado!{Style.RESET_ALL}")
        sys.exit(1)
    
    # Instalar colorama se necessário
    try:
        import colorama
        import requests
    except ImportError as e:
        print(f"{Fore.YELLOW}[!] Instalando dependências Python...{Style.RESET_ALL}")
        subprocess.run(["pip3", "install", "colorama", "requests"], check=True)
        import colorama
        import requests
    
    vpn = VPNManager()
    vpn.main()
