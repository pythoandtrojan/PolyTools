#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart TV Port Scanner - Scanner Especializado em TVs
"""

import socket
import threading
import time
import os
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

class SmartTVPortScanner:
    def __init__(self):
        self.tv_ports = {
            # Samsung
            8001: "Samsung Tizen - Developer Mode",
            8002: "Samsung Tizen - Debug Port", 
            7676: "Samsung Smart View",
            9090: "Samsung - Remote Management",
            5600: "Samsung - Multi Screen Service",
            8080: "Samsung - HTTP Service",
            26101: "Samsung - App Framework",
            
            # LG WebOS
            3000: "LG webOS - Developer Mode",
            3001: "LG webOS - SSH Service",
            3002: "LG webOS - Developer SSH",
            9080: "LG webOS - Remote Management",
            9998: "LG webOS - Luna Service",
            9999: "LG webOS - Luna Service Bus",
            
            # Sony Android TV
            6466: "Sony - Google Cast",
            6467: "Sony - Google Cast Secure",
            8008: "Sony - Google Cast Alternate",
            8009: "Sony - Google Cast Secure Alternate",
            8443: "Sony - HTTPS Service",
            10000: "Sony - Media Server",
            
            # Philips
            1925: "Philips - JointSPACE API",
            8888: "Philips - Ambilight Control",
            8889: "Philips - Developer Mode",
            
            # Roku
            8060: "Roku - External Control Protocol (ECP)",
            8080: "Roku - Web Interface",
            8081: "Roku - Developer Application Server",
            8090: "Roku - Screen Mirroring",
            9090: "Roku - Developer Web Server",
            10020: "Roku - Media Player",
            
            # Amazon Fire TV
            7236: "Amazon Fire TV - ADB Debugging",
            5555: "Amazon Fire TV - ADB Connection",
            7007: "Amazon Fire TV - Media Server",
            8001: "Amazon Fire TV - Developer Options",
            
            # Apple TV
            3689: "Apple TV - Digital Audio Access Protocol (DAAP)",
            5353: "Apple TV - Bonjour/mDNS",
            7000: "Apple TV - AirPlay",
            7100: "Apple TV - AirPlay Control",
            62078: "Apple TV - Lockdown Service",
            
            # Android TV/Google TV
            5555: "Android TV - ADB Debugging",
            6466: "Android TV - Google Cast",
            6467: "Android TV - Google Cast Secure",
            8008: "Android TV - Google Cast Alternate",
            8009: "Android TV - Google Cast Secure Alternate",
            
            # Xiaomi Mi TV
            6095: "Xiaomi Mi TV - Remote Control",
            6096: "Xiaomi Mi TV - Screen Mirroring",
            8090: "Xiaomi Mi TV - Developer Mode",
            
            # Panasonic
            8080: "Panasonic Viera - Remote Control",
            50001: "Panasonic Viera - Command Control",
            50002: "Panasonic Viera - Render Control",
            
            # Sharp Aquos
            10002: "Sharp Aquos - Control Protocol",
            20060: "Sharp Aquos - Command Interface",
            
            # Toshiba
            8080: "Toshiba - Remote Control",
            9050: "Toshiba - Smart TV API",
            
            # Hisense
            8080: "Hisense - Remote Control",
            10025: "Hisense - VIDAA API",
            
            # Vizio
            7345: "Vizio - SmartCast API",
            9000: "Vizio - Development Port",
            10000: "Vizio - Media Server",
            
            # Protocolos Universais
            80: "HTTP Service - Universal",
            443: "HTTPS Service - Universal", 
            1900: "UPnP SSDP Discovery - Universal",
            5353: "mDNS/Bonjour - Universal",
            62078: "iOS Lockdown Proxy - Universal",
            22: "SSH Service - Universal",
            23: "Telnet Service - Universal"
        }
        
        self.tv_manufacturers = {
            "samsung": [8001, 8002, 7676, 9090, 5600, 8080, 26101],
            "lg": [3000, 3001, 3002, 9080, 9998, 9999],
            "sony": [6466, 6467, 8008, 8009, 8443, 10000],
            "philips": [1925, 8888, 8889],
            "roku": [8060, 8080, 8081, 8090, 9090, 10020],
            "amazon": [7236, 5555, 7007, 8001],
            "apple": [3689, 5353, 7000, 7100, 62078],
            "android": [5555, 6466, 6467, 8008, 8009],
            "xiaomi": [6095, 6096, 8090],
            "universal": [80, 443, 1900, 5353, 62078, 22, 23]
        }
        
        self.results = {}
        self.scan_progress = 0

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def display_banner(self):
        banner = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║              🖥️  SMART TV PORT SCANNER 🔍                  ║
        ║                                                              ║
        ║         Scanner Especializado em Smart TVs                  ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        
        📱 Suporta: Samsung, LG, Sony, Philips, Roku, Fire TV, Apple TV, Android TV
        """
        print(banner)

    def scan_port(self, target_ip, port, timeout=2):
        """Escaneia uma porta individual"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                service_info = self.tv_ports.get(port, "Unknown Service")
                banner = self.get_banner(target_ip, port)
                return (port, True, service_info, banner)
                
        except Exception as e:
            pass
            
        return (port, False, "", "")

    def get_banner(self, target_ip, port, timeout=2):
        """Tenta obter banner do serviço"""
        try:
            if port in [80, 443, 8080, 8443, 9080]:
                # Serviços HTTP
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{target_ip}:{port}"
                response = requests.get(url, timeout=timeout, verify=False)
                server_header = response.headers.get('Server', '')
                return f"HTTP Server: {server_header}"
                
            elif port == 22:
                # SSH
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target_ip, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return f"SSH: {banner}"
                
            elif port == 1900:
                # UPnP
                return "UPnP SSDP Service"
                
        except:
            pass
            
        return "No banner"

    def scan_tv_ports(self, target_ip, manufacturer="all", max_workers=50):
        """Escaneia portas específicas para Smart TV"""
        print(f"\n[🎯] Escaneando {target_ip} para portas de Smart TV...")
        
        if manufacturer == "all":
            ports_to_scan = list(self.tv_ports.keys())
        else:
            ports_to_scan = self.tv_manufacturers.get(manufacturer, list(self.tv_ports.keys()))
        
        open_ports = []
        total_ports = len(ports_to_scan)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in ports_to_scan
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                port, is_open, service_info, banner = future.result()
                completed += 1
                self.scan_progress = (completed / total_ports) * 100
                
                if is_open:
                    open_ports.append((port, service_info, banner))
                    print(f"[✅] Porta {port} aberta: {service_info}")
                
                print(f"📊 Progresso: {self.scan_progress:.1f}%", end='\r')
        
        return open_ports

    def detect_tv_manufacturer(self, target_ip):
        """Tenta detectar o fabricante da TV baseado nas portas abertas"""
        print(f"\n[🔍] Detectando fabricante da TV em {target_ip}...")
        
        # Escaneia portas chave de cada fabricante
        manufacturer_scores = {}
        
        for manufacturer, ports in self.tv_manufacturers.items():
            if manufacturer == "universal":
                continue
                
            score = 0
            for port in ports[:5]:  # Testa apenas as primeiras 5 portas
                if self.scan_port(target_ip, port, timeout=1)[1]:
                    score += 1
            
            if score > 0:
                manufacturer_scores[manufacturer] = score
        
        if manufacturer_scores:
            detected = max(manufacturer_scores.items(), key=lambda x: x[1])
            return detected[0], detected[1]
        
        return "unknown", 0

    def network_scan(self, network_range="192.168.1.0/24"):
        """Escaneia toda a rede por Smart TVs"""
        print(f"\n[🌐] Escaneando rede {network_range} por Smart TVs...")
        
        tv_devices = []
        network = ipaddress.ip_network(network_range, strict=False)
        
        def scan_host(ip):
            try:
                # Testa portas universais primeiro
                universal_ports = [80, 443, 1900, 8060]
                for port in universal_ports:
                    if self.scan_port(str(ip), port, timeout=1)[1]:
                        manufacturer, confidence = self.detect_tv_manufacturer(str(ip))
                        return (str(ip), manufacturer, confidence)
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_host, ip) for ip in network.hosts()]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, manufacturer, confidence = result
                    tv_devices.append((ip, manufacturer, confidence))
                    print(f"[✅] Smart TV encontrada: {ip} ({manufacturer} - confiança: {confidence})")
        
        return tv_devices

    def service_enumeration(self, target_ip, open_ports):
        """Enumera serviços detalhados nas portas abertas"""
        print(f"\n[📊] Enumerando serviços em {target_ip}...")
        
        services_info = {}
        
        for port, service, banner in open_ports:
            service_data = {
                'service_name': service,
                'banner': banner,
                'vulnerability_assessment': self.assess_vulnerability(port)
            }
            
            # Testa endpoints específicos se for serviço web
            if port in [80, 443, 8080, 8443, 9080]:
                service_data['web_endpoints'] = self.enumerate_web_endpoints(target_ip, port)
            
            services_info[port] = service_data
        
        return services_info

    def enumerate_web_endpoints(self, target_ip, port):
        """Enumera endpoints web comuns em Smart TVs"""
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{port}"
        
        common_endpoints = [
            "/", "/api", "/info", "/status", "/config",
            "/remote", "/control", "/apps", "/developer",
            "/udap/api", "/roap/api", "/query/device-info",
            "/dial.xml", "/ssdp/device-desc.xml"
        ]
        
        found_endpoints = []
        
        for endpoint in common_endpoints:
            try:
                url = base_url + endpoint
                response = requests.get(url, timeout=2, verify=False)
                if response.status_code == 200:
                    found_endpoints.append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', '')
                    })
                    print(f"[🌐] Endpoint encontrado: {endpoint}")
            except:
                pass
        
        return found_endpoints

    def assess_vulnerability(self, port):
        """Avalia vulnerabilidades baseado na porta"""
        risk_ports = {
            22: "ALTO - SSH exposto",
            23: "ALTO - Telnet exposto", 
            5555: "ALTO - ADB Debugging ativo",
            3000: "MÉDIO - Modo desenvolvedor",
            8001: "MÉDIO - Porta de desenvolvimento",
            9090: "MÉDIO - Gerenciamento remoto"
        }
        
        return risk_ports.get(port, "BAIXO - Serviço padrão")

    def generate_report(self, target_ip, open_ports, services_info, manufacturer):
        """Gera relatório completo do scan"""
        self.clear_screen()
        print("\n" + "="*70)
        print("📊 RELATÓRIO DE SCAN - SMART TV")
        print("="*70)
        print(f"Alvo: {target_ip}")
        print(f"Fabricante Detectado: {manufacturer.upper()}")
        print(f"Portas Abertas: {len(open_ports)}")
        print(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*70)
        
        print("\n🔓 PORTAS ABERTAS E SERVIÇOS:")
        for port, service, banner in open_ports:
            vuln_assessment = services_info[port]['vulnerability_assessment']
            print(f"  📍 Porta {port}: {service}")
            print(f"     🎌 Banner: {banner}")
            print(f"     ⚠️  Risco: {vuln_assessment}")
            
            if 'web_endpoints' in services_info[port]:
                endpoints = services_info[port]['web_endpoints']
                if endpoints:
                    print(f"     🌐 Endpoints Web:")
                    for endpoint in endpoints:
                        print(f"        - {endpoint['endpoint']} (HTTP {endpoint['status_code']})")
            print()
        
        print("\n🛡️ RECOMENDAÇÕES DE SEGURANÇA:")
        recommendations = self.generate_recommendations(open_ports)
        for rec in recommendations:
            print(f"  • {rec}")
        
        print("="*70)

    def generate_recommendations(self, open_ports):
        """Gera recomendações baseadas nas portas abertas"""
        recommendations = []
        high_risk_ports = [22, 23, 5555, 3000, 8001]
        
        for port, _, _ in open_ports:
            if port in high_risk_ports:
                if port == 22:
                    recommendations.append("DESATIVAR SSH - Exposição de terminal remoto")
                elif port == 23:
                    recommendations.append("DESATIVAR TELNET - Protocolo inseguro")
                elif port == 5555:
                    recommendations.append("DESATIVAR ADB - Debugging remoto ativo")
                elif port in [3000, 8001]:
                    recommendations.append("DESATIVAR MODO DESENVOLVEDOR - Em ambiente de produção")
        
        if not recommendations:
            recommendations = [
                "Manter firmware atualizado",
                "Usar firewall de rede",
                "Desativar serviços não utilizados",
                "Monitorar tráfego de rede"
            ]
        
        return recommendations

    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print("\n🎮 MENU PRINCIPAL")
            print("═" * 60)
            print("1. 🔍 Scan de IP Único")
            print("2. 🌐 Scan de Rede Completa")
            print("3. 🎯 Scan por Fabricante Específico")
            print("4. 📊 Gerar Relatório")
            print("5. 🚪 Sair")
            print("═" * 60)
            
            choice = input("\n🔹 Escolha uma opção (1-5): ").strip()
            
            if choice == '1':
                self.single_scan_menu()
            elif choice == '2':
                self.network_scan_menu()
            elif choice == '3':
                self.manufacturer_scan_menu()
            elif choice == '4':
                self.report_menu()
            elif choice == '5':
                print("\n👋 Saindo...")
                break
            else:
                print("\n❌ Opção inválida!")
                time.sleep(2)

    def single_scan_menu(self):
        """Menu de scan único"""
        self.clear_screen()
        target_ip = input("\n🔹 Digite o IP da Smart TV: ").strip()
        
        if target_ip:
            print(f"\n[🎯] Iniciando scan completo em {target_ip}...")
            
            # Detecta fabricante primeiro
            manufacturer, confidence = self.detect_tv_manufacturer(target_ip)
            print(f"[📱] Fabricante detectado: {manufacturer} (confiança: {confidence}/5)")
            
            # Scan completo
            open_ports = self.scan_tv_ports(target_ip, manufacturer)
            services_info = self.service_enumeration(target_ip, open_ports)
            
            # Gera relatório
            self.generate_report(target_ip, open_ports, services_info, manufacturer)
            
            # Salva resultados
            self.results[target_ip] = {
                'open_ports': open_ports,
                'services_info': services_info,
                'manufacturer': manufacturer
            }
        else:
            print("❌ IP inválido!")
        
        input("\n🔹 Pressione Enter para continuar...")

    def network_scan_menu(self):
        """Menu de scan de rede"""
        self.clear_screen()
        network = input("\n🔹 Digite a rede (ex: 192.168.1.0/24): ").strip() or "192.168.1.0/24"
        
        tv_devices = self.network_scan(network)
        
        if tv_devices:
            print(f"\n[✅] Scan concluído! {len(tv_devices)} Smart TV(s) encontrada(s).")
            for ip, manufacturer, confidence in tv_devices:
                print(f"  • {ip} - {manufacturer} (confiança: {confidence})")
        else:
            print("\n[❌] Nenhuma Smart TV encontrada na rede.")
        
        input("\n🔹 Pressione Enter para continuar...")

    def manufacturer_scan_menu(self):
        """Menu de scan por fabricante"""
        self.clear_screen()
        print("\n🏭 FABRICANTES DISPONÍVEIS:")
        for i, manufacturer in enumerate(self.tv_manufacturers.keys(), 1):
            print(f"  {i}. {manufacturer.upper()}")
        
        choice = input("\n🔹 Escolha o fabricante: ").strip()
        target_ip = input("🔹 IP da Smart TV: ").strip()
        
        if choice.isdigit() and target_ip:
            manufacturers = list(self.tv_manufacturers.keys())
            index = int(choice) - 1
            if 0 <= index < len(manufacturers):
                manufacturer = manufacturers[index]
                open_ports = self.scan_tv_ports(target_ip, manufacturer)
                services_info = self.service_enumeration(target_ip, open_ports)
                self.generate_report(target_ip, open_ports, services_info, manufacturer)
        
        input("\n🔹 Pressione Enter para continuar...")

    def report_menu(self):
        """Menu de relatórios"""
        self.clear_screen()
        if not self.results:
            print("\n❌ Nenhum scan realizado ainda.")
        else:
            for target_ip, data in self.results.items():
                self.generate_report(
                    target_ip, 
                    data['open_ports'], 
                    data['services_info'], 
                    data['manufacturer']
                )
        
        input("\n🔹 Pressione Enter para continuar...")

def main():
    """Função principal"""
    try:
        scanner = SmartTVPortScanner()
        scanner.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Programa interrompido pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro: {e}")

if __name__ == "__main__":
    main()
