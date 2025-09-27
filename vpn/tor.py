#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import subprocess
import threading
from colorama import Fore, Style, init
import random

# Inicializar colorama
init(autoreset=True)

class TorManager:
    def __init__(self):
        self.tor_process = None
        self.tor_running = False
        self.current_ip = None
        self.original_ip = None
        self.check_tor_installation()
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""
{Fore.RED}
████████╗ ██████╗ ██████╗ 
╚══██╔══╝██╔═══██╗██╔══██╗
   ██║   ██║   ██║██████╔╝
   ██║   ██║   ██║██╔══██╗
   ██║   ╚██████╔╝██║  ██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    TOR MANAGER v3.0                          ║
║                 Anonymous Browsing Tool                      ║
║                 IP Change in Real-Time                       ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def check_tor_installation(self):
        """Verifica se o Tor está instalado"""
        print(f"{Fore.YELLOW}[*] Verificando instalação do Tor...{Style.RESET_ALL}")
        
        # Verifica se o Tor está instalado
        try:
            subprocess.run(["tor", "--version"], capture_output=True, check=True)
            print(f"{Fore.GREEN}[✓] Tor está instalado{Style.RESET_ALL}")
            return True
        except:
            print(f"{Fore.RED}[✗] Tor não está instalado{Style.RESET_ALL}")
            return False
    
    def install_tor(self):
        """Instala o Tor"""
        print(f"{Fore.YELLOW}[*] Instalando Tor...{Style.RESET_ALL}")
        
        if os.name == 'posix':  # Linux/Unix
            if subprocess.run(["which", "apt-get"], capture_output=True).returncode == 0:
                # Debian/Ubuntu
                commands = [
                    "sudo apt-get update",
                    "sudo apt-get install -y tor torsocks proxychains4"
                ]
            elif subprocess.run(["which", "yum"], capture_output=True).returncode == 0:
                # CentOS/RHEL
                commands = [
                    "sudo yum install -y epel-release",
                    "sudo yum install -y tor torsocks proxychains"
                ]
            elif subprocess.run(["which", "pacman"], capture_output=True).returncode == 0:
                # Arch Linux
                commands = [
                    "sudo pacman -Syu --noconfirm",
                    "sudo pacman -S --noconfirm tor torsocks"
                ]
            else:
                print(f"{Fore.RED}[!] Sistema não suportado{Style.RESET_ALL}")
                return False
            
            for cmd in commands:
                try:
                    print(f"{Fore.CYAN}[*] Executando: {cmd}{Style.RESET_ALL}")
                    subprocess.run(cmd, shell=True, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"{Fore.RED}[!] Erro na instalação: {e}{Style.RESET_ALL}")
                    return False
            
            print(f"{Fore.GREEN}[✓] Tor instalado com sucesso!{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Sistema operacional não suportado{Style.RESET_ALL}")
            return False
    
    def get_public_ip(self, use_tor=False):
        """Obtém o IP público atual"""
        try:
            if use_tor:
                # Usa proxychains para fazer requisição através do Tor
                cmd = ["proxychains", "curl", "-s", "https://api.ipify.org"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return result.stdout.strip()
            else:
                response = requests.get('https://api.ipify.org', timeout=10)
                return response.text
        except:
            return "Erro ao obter IP"
    
    def create_tor_config(self):
        """Cria configuração personalizada do Tor"""
        config_content = """SOCKSPort 9050
SOCKSPolicy accept 127.0.0.1
SOCKSPolicy reject *
Log notice file /var/log/tor/tor.log
DataDirectory /var/lib/tor
ExitNodes {us},{ca},{gb},{de},{fr}
StrictNodes 1
CircuitBuildTimeout 10
KeepalivePeriod 60
NewCircuitPeriod 15
MaxCircuitDirtiness 10
"""
        
        try:
            # Cria diretório de configuração se não existir
            os.makedirs("/etc/tor", exist_ok=True)
            
            with open("/etc/tor/torrc.custom", "w") as f:
                f.write(config_content)
            
            print(f"{Fore.GREEN}[+] Configuração do Tor criada: /etc/tor/torrc.custom{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao criar configuração: {e}{Style.RESET_ALL}")
            return False
    
    def start_tor(self):
        """Inicia o serviço Tor"""
        if self.tor_running:
            print(f"{Fore.YELLOW}[!] Tor já está em execução{Style.RESET_ALL}")
            return True
        
        print(f"{Fore.YELLOW}[*] Iniciando serviço Tor...{Style.RESET_ALL}")
        
        try:
            # Para o serviço Tor se estiver rodando
            subprocess.run(["sudo", "systemctl", "stop", "tor"], capture_output=True)
            
            # Inicia o Tor com configuração personalizada
            self.tor_process = subprocess.Popen(
                ["sudo", "tor", "-f", "/etc/tor/torrc.custom"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Aguarda o Tor inicializar
            print(f"{Fore.CYAN}[*] Aguardando inicialização do Tor...{Style.RESET_ALL}")
            time.sleep(10)
            
            # Verifica se o Tor está funcionando
            if self.check_tor_connection():
                self.tor_running = True
                self.original_ip = self.get_public_ip(use_tor=False)
                self.current_ip = self.get_public_ip(use_tor=True)
                
                print(f"{Fore.GREEN}[✓] Tor iniciado com sucesso!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] IP Original: {self.original_ip}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] IP Tor: {self.current_ip}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] Falha ao conectar através do Tor{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao iniciar Tor: {e}{Style.RESET_ALL}")
            return False
    
    def stop_tor(self):
        """Para o serviço Tor"""
        if not self.tor_running:
            print(f"{Fore.YELLOW}[!] Tor não está em execução{Style.RESET_ALL}")
            return True
        
        print(f"{Fore.YELLOW}[*] Parando serviço Tor...{Style.RESET_ALL}")
        
        try:
            if self.tor_process:
                self.tor_process.terminate()
                self.tor_process.wait()
            
            # Para o serviço systemd também
            subprocess.run(["sudo", "systemctl", "stop", "tor"], capture_output=True)
            
            self.tor_running = False
            self.current_ip = None
            
            print(f"{Fore.GREEN}[✓] Tor parado com sucesso!{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao parar Tor: {e}{Style.RESET_ALL}")
            return False
    
    def check_tor_connection(self):
        """Verifica se a conexão Tor está funcionando"""
        try:
            ip_without_tor = self.get_public_ip(use_tor=False)
            ip_with_tor = self.get_public_ip(use_tor=True)
            
            return ip_without_tor != ip_with_tor and ip_with_tor != "Erro ao obter IP"
        except:
            return False
    
    def change_tor_identity(self):
        """Força mudança de identidade do Tor (novo circuito)"""
        if not self.tor_running:
            print(f"{Fore.RED}[!] Tor não está em execução{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.YELLOW}[*] Mudando identidade Tor...{Style.RESET_ALL}")
        
        try:
            # Envia sinal para o Tor criar novo circuito
            subprocess.run(["sudo", "killall", "-HUP", "tor"], capture_output=True)
            time.sleep(3)
            
            old_ip = self.current_ip
            self.current_ip = self.get_public_ip(use_tor=True)
            
            print(f"{Fore.GREEN}[✓] Identidade alterada com sucesso!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] IP Anterior: {old_ip}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] IP Atual: {self.current_ip}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao mudar identidade: {e}{Style.RESET_ALL}")
            return False
    
    def real_time_ip_monitor(self):
        """Monitora mudanças de IP em tempo real"""
        if not self.tor_running:
            print(f"{Fore.RED}[!] Inicie o Tor primeiro{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Iniciando monitoramento em tempo real...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Pressione Ctrl+C para parar o monitoramento{Style.RESET_ALL}")
        
        try:
            last_ip = self.current_ip
            change_count = 0
            
            while True:
                current_ip = self.get_public_ip(use_tor=True)
                
                if current_ip != last_ip and current_ip != "Erro ao obter IP":
                    change_count += 1
                    print(f"\n{Fore.GREEN}[🎯] IP Alterado! Mudança #{change_count}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[🕐] {time.strftime('%H:%M:%S')}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[⬅] IP Anterior: {last_ip}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[➡] IP Atual: {current_ip}{Style.RESET_ALL}")
                    last_ip = current_ip
                
                print(f"{Fore.WHITE}[⏳] Monitorando... IP: {current_ip} | Mudanças: {change_count}", end="\r")
                time.sleep(5)  # Verifica a cada 5 segundos
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Monitoramento interrompido{Style.RESET_ALL}")
    
    def auto_ip_changer(self, interval=30):
        """Muda o IP automaticamente em intervalos regulares"""
        if not self.tor_running:
            print(f"{Fore.RED}[!] Inicie o Tor primeiro{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Iniciando mudança automática de IP...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Intervalo: {interval} segundos{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Pressione Ctrl+C para parar{Style.RESET_ALL}")
        
        try:
            change_count = 0
            while True:
                if self.change_tor_identity():
                    change_count += 1
                    print(f"{Fore.GREEN}[✓] Mudança #{change_count} concluída{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}[⏰] Próxima mudança em {interval} segundos...{Style.RESET_ALL}")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Mudança automática interrompida{Style.RESET_ALL}")
    
    def test_anonymity(self):
        """Testa o nível de anonimato"""
        if not self.tor_running:
            print(f"{Fore.RED}[!] Inicie o Tor primeiro{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Testando anonimato...{Style.RESET_ALL}")
        
        test_services = [
            {"name": "IP Check", "url": "https://api.ipify.org"},
            {"name": "DNS Leak", "url": "https://dnsleaktest.com"},
            {"name": "WebRTC Test", "url": "https://browserleaks.com/webrtc"},
        ]
        
        for service in test_services:
            try:
                print(f"{Fore.YELLOW}[*] Testando {service['name']}...{Style.RESET_ALL}")
                result = subprocess.run(
                    ["proxychains", "curl", "-s", service['url']],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    print(f"{Fore.GREEN}[✓] {service['name']}: OK{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[✗] {service['name']}: Falhou{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Erro no teste {service['name']}: {e}{Style.RESET_ALL}")
    
    def show_status(self):
        """Mostra status completo"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      STATUS DO TOR                          ║")
        print(f"╠══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        # Status do Tor
        tor_status = f"{Fore.GREEN}ATIVO{Style.RESET_ALL}" if self.tor_running else f"{Fore.RED}INATIVO{Style.RESET_ALL}"
        print(f"{Fore.CYAN}║ {Fore.GREEN}Tor: {tor_status:<50} {Fore.CYAN}║")
        
        # IPs
        if self.original_ip:
            print(f"{Fore.CYAN}║ {Fore.GREEN}IP Original: {Fore.WHITE}{self.original_ip:<38} {Fore.CYAN}║")
        if self.current_ip:
            print(f"{Fore.CYAN}║ {Fore.GREEN}IP Tor: {Fore.WHITE}{self.current_ip:<43} {Fore.CYAN}║")
        
        # Conexão
        connection_status = self.check_tor_connection()
        conn_text = f"{Fore.GREEN}FUNCIONANDO{Style.RESET_ALL}" if connection_status else f"{Fore.RED}COM PROBLEMAS{Style.RESET_ALL}"
        print(f"{Fore.CYAN}║ {Fore.GREEN}Conexão: {conn_text:<45} {Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    def show_menu(self):
        """Exibe o menu principal"""
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                         MENU TOR                             ║
╠══════════════════════════════════════════════════════════════╣
║ {Fore.GREEN}1.{Fore.CYAN}  Instalar Tor                                    {Fore.CYAN}    ║
║ {Fore.GREEN}2.{Fore.CYAN}  Criar Configuração                              {Fore.CYAN}    ║
║ {Fore.GREEN}3.{Fore.CYAN}  Iniciar Tor                                     {Fore.CYAN}    ║
║ {Fore.GREEN}4.{Fore.CYAN}  Parar Tor                                       {Fore.CYAN}    ║
║ {Fore.GREEN}5.{Fore.CYAN}  Mudar Identidade (IP)                           {Fore.CYAN}    ║
║ {Fore.GREEN}6.{Fore.CYAN}  Monitorar IP em Tempo Real                      {Fore.CYAN}    ║
║ {Fore.GREEN}7.{Fore.CYAN}  Mudança Automática de IP                        {Fore.CYAN}    ║
║ {Fore.GREEN}8.{Fore.CYAN}  Testar Anonimato                                {Fore.CYAN}    ║
║ {Fore.GREEN}9.{Fore.CYAN}  Status                                          {Fore.CYAN}    ║
║ {Fore.GREEN}0.{Fore.CYAN}  Sair                                            {Fore.CYAN}    ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(menu)
    
    def main(self):
        """Função principal"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_menu()
            
            choice = input(f"{Fore.GREEN}Escolha uma opção (0-9): {Style.RESET_ALL}")
            
            if choice == "1":
                self.install_tor()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "2":
                self.create_tor_config()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "3":
                self.start_tor()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "4":
                self.stop_tor()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "5":
                self.change_tor_identity()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "6":
                self.real_time_ip_monitor()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "7":
                interval = input(f"{Fore.GREEN}Intervalo em segundos (padrão: 30): {Style.RESET_ALL}")
                try:
                    interval = int(interval) if interval else 30
                    self.auto_ip_changer(interval)
                except ValueError:
                    print(f"{Fore.RED}[!] Intervalo inválido{Style.RESET_ALL}")
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "8":
                self.test_anonymity()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "9":
                self.show_status()
                input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            
            elif choice == "0":
                if self.tor_running:
                    self.stop_tor()
                print(f"{Fore.RED}\n[!] Saindo... Mantenha-se anônimo!{Style.RESET_ALL}")
                break
            
            else:
                print(f"{Fore.RED}[!] Opção inválida! Tente novamente.{Style.RESET_ALL}")
                time.sleep(2)

if __name__ == "__main__":
    # Verificar se é root
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Execute como root para funcionalidades completas!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Comando: sudo python3 tor_manager.py{Style.RESET_ALL}")
    
    # Verificar dependências Python
    try:
        import requests
        import colorama
    except ImportError:
        print(f"{Fore.YELLOW}[!] Instalando dependências...{Style.RESET_ALL}")
        subprocess.run(["pip3", "install", "requests", "colorama"], check=True)
        import requests
        import colorama
    
    tor_manager = TorManager()
    tor_manager.main()
