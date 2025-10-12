#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart TV Security Scanner - Ferramenta Real de Teste
"""

import os
import socket
import requests
import subprocess
import threading
import time
import json
from urllib.parse import urljoin
import netifaces

class SmartTVScanner:
    def __init__(self):
        self.target_ip = None
        self.results = {}
        self.common_ports = [80, 443, 8008, 8080, 7676, 8001, 8002]
        self.tv_models = {
            "samsung": ["T-NT", "T-KT", "T-JS"],
            "lg": ["webOS", "NetCast"],
            "sony": ["Android TV", "Google TV"],
            "philips": ["Android TV", "Saphi"]
        }

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def display_banner(self):
        banner = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║              🖥️  SMART TV SECURITY SCANNER 🛡️              ║
        ║                                                              ║
        ║         Scanner Real de Vulnerabilidades em TVs             ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        
        ⚠️  AVISO: Use apenas em redes próprias ou com autorização!
        """
        print(banner)

    def scan_network(self):
        """Escaneia a rede local por dispositivos Smart TV"""
        print("\n[🔍] Escaneando rede local por Smart TVs...")
        
        # Obtém o gateway e a rede
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network = '.'.join(default_gateway.split('.')[:3]) + '.0/24'
            
            print(f"[🌐] Rede detectada: {network}")
            
            # Usa nmap para scan rápido
            cmd = f"nmap -sn {network}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            tv_ips = []
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip = line.split()[-1]
                    if '(' in ip:
                        ip = ip.strip('()')
                    # Verifica se é uma TV conhecida
                    if self.check_tv_device(ip):
                        tv_ips.append(ip)
            
            return tv_ips
            
        except Exception as e:
            print(f"[❌] Erro no scan: {e}")
            return []

    def check_tv_device(self, ip):
        """Verifica se o IP pertence a uma Smart TV"""
        try:
            # Tenta conectar em portas comuns de TVs
            for port in [80, 8008, 8080]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
        except:
            pass
        return False

    def port_scan(self, ip):
        """Escaneia portas abertas no alvo"""
        print(f"\n[🔎] Escaneando portas em {ip}...")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[✅] Porta {port} aberta")
                sock.close()
            except:
                pass

        threads = []
        for port in self.common_ports:
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return open_ports

    def test_http_services(self, ip, ports):
        """Testa serviços HTTP/HTTPS"""
        print(f"\n[🌐] Testando serviços web...")
        vulnerabilities = []
        
        for port in ports:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{ip}:{port}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        print(f"[✅] {url} - Acessível")
                        
                        # Testa endpoints comuns
                        endpoints = [
                            "/", "/api", "/info", "/status",
                            "/udap/api", "/roap/api", "/apps/"
                        ]
                        
                        for endpoint in endpoints:
                            test_url = urljoin(url, endpoint)
                            try:
                                resp = requests.get(test_url, timeout=3, verify=False)
                                if resp.status_code == 200:
                                    print(f"[📱] Endpoint encontrado: {test_url}")
                                    vulnerabilities.append(f"Endpoint exposto: {test_url}")
                            except:
                                pass
                                
                except requests.RequestException:
                    pass
                    
        return vulnerabilities

    def test_upnp_vulnerabilities(self, ip):
        """Testa vulnerabilidades UPnP"""
        print(f"\n[🔓] Testando UPnP...")
        vulnerabilities = []
        
        try:
            # Scan UPnP com nmap
            cmd = f"nmap -p 1900 --script upnp-info {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "upnp-info" in result.stdout:
                vulnerabilities.append("UPnP ativo - possível exposição de serviços")
                print("[⚠️] UPnP ativo detectado")
                
        except Exception as e:
            print(f"[❌] Erro no teste UPnP: {e}")
            
        return vulnerabilities

    def test_dlna_services(self, ip):
        """Testa serviços DLNA"""
        print(f"\n[📡] Testando DLNA...")
        vulnerabilities = []
        
        try:
            cmd = f"nmap -p 8200,9000 --script dlna-capabilities {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "dlna" in result.stdout.lower():
                vulnerabilities.append("DLNA ativo - possível compartilhamento inseguro")
                print("[⚠️] DLNA ativo detectado")
                
        except Exception as e:
            print(f"[❌] Erro no teste DLNA: {e}")
            
        return vulnerabilities

    def test_default_credentials(self, ip, ports):
        """Testa credenciais padrão"""
        print(f"\n[🔑] Testando credenciais padrão...")
        credentials_found = []
        
        common_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("root", "root"),
            ("user", "user")
        ]
        
        for port in ports:
            for username, password in common_credentials:
                try:
                    url = f"http://{ip}:{port}"
                    response = requests.get(url, auth=(username, password), timeout=3)
                    if response.status_code == 200:
                        print(f"[🔓] Credenciais padrão encontradas: {username}:{password}")
                        credentials_found.append(f"{username}:{password} na porta {port}")
                except:
                    pass
                    
        return credentials_found

    def generate_report(self, ip, results):
        """Gera relatório completo"""
        print("\n" + "="*60)
        print("📊 RELATÓRIO DE VULNERABILIDADES")
        print("="*60)
        print(f"Alvo: {ip}")
        print(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*60)
        
        for category, findings in results.items():
            if findings:
                print(f"\n{category.upper()}:")
                for finding in findings:
                    print(f"  ⚠️  {finding}")
            else:
                print(f"\n{category.upper()}: ✅ Nenhuma vulnerabilidade encontrada")
        
        print("\n" + "="*60)
        print("🛡️  RECOMENDAÇÕES:")
        print("  • Alterar credenciais padrão")
        print("  • Desativar serviços não utilizados")
        print("  • Atualizar firmware regularmente")
        print("  • Usar firewall de rede")
        print("  • Isolar TV em VLAN separada")
        print("="*60)

    def scan_single_target(self, ip):
        """Escaneia um único alvo"""
        self.clear_screen()
        self.display_banner()
        
        print(f"[🎯] Iniciando scan no alvo: {ip}")
        
        results = {
            "portas_abertas": [],
            "servicos_web": [],
            "vulnerabilidades_upnp": [],
            "vulnerabilidades_dlna": [],
            "credenciais_padrao": []
        }
        
        # Scan de portas
        open_ports = self.port_scan(ip)
        results["portas_abertas"] = [f"Porta {port} aberta" for port in open_ports]
        
        # Testes diversos
        results["servicos_web"] = self.test_http_services(ip, open_ports)
        results["vulnerabilidades_upnp"] = self.test_upnp_vulnerabilities(ip)
        results["vulnerabilidades_dlna"] = self.test_dlna_services(ip)
        results["credenciais_padrao"] = self.test_default_credentials(ip, open_ports)
        
        # Gera relatório
        self.generate_report(ip, results)
        
        return results

    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print("\n🎮 MENU PRINCIPAL")
            print("═" * 50)
            print("1. 🔍 Scan Automático de Rede")
            print("2. 🎯 Scan de IP Específico")
            print("3. 📊 Ver Scan Anterior")
            print("4. 🚪 Sair")
            print("═" * 50)
            
            choice = input("\n🔹 Escolha uma opção (1-4): ").strip()
            
            if choice == '1':
                self.network_scan_menu()
            elif choice == '2':
                self.specific_scan_menu()
            elif choice == '3':
                self.show_previous_results()
            elif choice == '4':
                print("\n👋 Saindo...")
                break
            else:
                print("\n❌ Opção inválida!")
                time.sleep(2)

    def network_scan_menu(self):
        """Menu de scan de rede"""
        self.clear_screen()
        print("\n[🔍] Escaneando rede...")
        
        tv_ips = self.scan_network()
        
        if not tv_ips:
            print("[❌] Nenhuma Smart TV encontrada na rede.")
            input("\nPressione Enter para continuar...")
            return
        
        print(f"\n[✅] Smart TVs encontradas:")
        for i, ip in enumerate(tv_ips, 1):
            print(f"  {i}. {ip}")
        
        try:
            choice = input("\n🔹 Escolha uma TV para scan (número) ou 0 para voltar: ")
            if choice == '0':
                return
            index = int(choice) - 1
            if 0 <= index < len(tv_ips):
                self.scan_single_target(tv_ips[index])
                input("\nPressione Enter para continuar...")
        except (ValueError, IndexError):
            print("❌ Escolha inválida!")

    def specific_scan_menu(self):
        """Menu de scan específico"""
        self.clear_screen()
        ip = input("\n🔹 Digite o IP da Smart TV: ").strip()
        
        if ip:
            try:
                self.scan_single_target(ip)
            except Exception as e:
                print(f"❌ Erro durante o scan: {e}")
        else:
            print("❌ IP inválido!")
        
        input("\nPressione Enter para continuar...")

    def show_previous_results(self):
        """Mostra resultados anteriores"""
        self.clear_screen()
        if not self.results:
            print("\n❌ Nenhum scan realizado ainda.")
        else:
            for ip, results in self.results.items():
                self.generate_report(ip, results)
        
        input("\nPressione Enter para continuar...")

def main():
    """Função principal"""
    try:
        # Verifica se nmap está instalado
        result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
        if not result.stdout.strip():
            print("❌ Nmap não encontrado. Instale com: sudo apt-get install nmap")
            return
        
        scanner = SmartTVScanner()
        scanner.main_menu()
        
    except KeyboardInterrupt:
        print("\n\n👋 Programa interrompido pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro: {e}")

if __name__ == "__main__":
    main()
