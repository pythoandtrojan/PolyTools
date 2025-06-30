#!/usr/bin/env python

import os
import json
import requests
from datetime import datetime
from colorama import Fore, Style, init
import exifread
from PIL import Image, ExifTags
import subprocess


init(autoreset=True)
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
RESET = Style.RESET_ALL

class LiteGeoMetaTool:
    def __init__(self):
        self.results = {}
    
    def banner(self):
        os.system('clear')
        print(f"""{VERDE}
   █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█
   █ TERMUX LITE - Geoloc & Metadata █
   █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
   {RESET}Versão sem root e sem Termux:API
   {AMARELO}Recursos disponíveis:
   • Geolocalização por IP público
   • Análise de metadados de arquivos
   • WiFi básico (apenas info da rede conectada)
        {RESET}""")

    def get_network_info(self):
        """Obtém informações básicas da rede sem root"""
        try:
        
            ip = requests.get('https://api.ipify.org').text
            
            
            wifi_info = {}
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                interfaces = [line.split()[1].strip(':') 
                            for line in result.stdout.splitlines() 
                            if 'mtu' in line]
                wifi_info['interfaces'] = interfaces
            except:
                pass
            
            return {
                'ip_publico': ip,
                'rede': wifi_info
            }
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao obter info de rede: {e}{RESET}")
            return None

    def extract_metadata(self, file_path):
        """Extrai metadados de arquivos"""
        print(f"\n{CIANO}[+] Analisando: {file_path}{RESET}")
        
        metadata = {
            'arquivo': os.path.basename(file_path),
            'tamanho': os.path.getsize(file_path),
            'modificado': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        try:
            
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                with open(file_path, 'rb') as f:
                    tags = exifread.process_file(f)
                    for tag in tags:
                        if tag not in ('JPEGThumbnail', 'TIFFThumbnail'):
                            metadata[str(tag)] = str(tags[tag])
                
            
                gps = self._extract_gps_coords(file_path)
                if gps:
                    metadata['gps'] = gps
        except Exception as e:
            print(f"{AMARELO}[!] Erro nos metadados: {e}{RESET}")

        return metadata

    def _extract_gps_coords(self, image_path):
        """Tenta extrair coordenadas GPS de uma imagem"""
        try:
            img = Image.open(image_path)
            exif = {
                ExifTags.TAGS[k]: v
                for k, v in img._getexif().items()
                if k in ExifTags.TAGS
            }
            
            if 'GPSInfo' in exif:
                gps_info = {
                    ExifTags.GPSTAGS.get(k, k): v
                    for k, v in exif['GPSInfo'].items()
                }
                
                lat = self._convert_gps(gps_info.get('GPSLatitude'), gps_info.get('GPSLatitudeRef'))
                lon = self._convert_gps(gps_info.get('GPSLongitude'), gps_info.get('GPSLongitudeRef'))
                
                if lat and lon:
                    return {'latitude': lat, 'longitude': lon}
        except:
            return None

    def _convert_gps(self, coord, ref):
        """Converte coordenadas GPS para decimal"""
        try:
            decimal = coord[0] + (coord[1]/60) + (coord[2]/3600)
            if ref in ['S', 'W']:
                decimal = -decimal
            return round(decimal, 6)
        except:
            return None

    def show_menu(self):
        """Menu interativo simplificado"""
        self.banner()
        while True:
            print(f"\n{VERDE}Menu Principal{RESET}")
            print("1. Ver minha localização aproximada (IP)")
            print("2. Analisar metadados de arquivo")
            print("3. Ver informações da rede")
            print("4. Sair")
            
            opcao = input(f"{AMARELO}> {RESET}").strip()
            
            if opcao == "1":
                self._handle_ip_location()
            elif opcao == "2":
                self._handle_metadata()
            elif opcao == "3":
                self._handle_network_info()
            elif opcao == "4":
                break
            else:
                print(f"{VERMELHO}Opção inválida{RESET}")

    def _handle_ip_location(self):
        """Mostra localização pelo IP"""
        print(f"\n{VERDE}[+] Detectando localização aproximada...{RESET}")
        try:
            response = requests.get('http://ip-api.com/json/')
            data = response.json()
            
            if data['status'] == 'success':
                print(f"{AZUL}País: {data['country']}")
                print(f"Região: {data['regionName']}")
                print(f"Cidade: {data['city']}")
                print(f"Provedor: {data['isp']}")
                print(f"Coordenadas: {data['lat']}, {data['lon']}{RESET}")
            else:
                print(f"{VERMELHO}Não foi possível determinar a localização{RESET}")
        except Exception as e:
            print(f"{VERMELHO}Erro: {e}{RESET}")

    def _handle_metadata(self):
        """Lida com análise de metadados"""
        arquivo = input(f"{AMARELO}[?] Caminho do arquivo: {RESET}").strip()
        if os.path.exists(arquivo):
            meta = self.extract_metadata(arquivo)
            print(f"\n{VERDE}Metadados encontrados:{RESET}")
            for k, v in meta.items():
                print(f"{AZUL}{k}: {v}{RESET}")
        else:
            print(f"{VERMELHO}Arquivo não encontrado{RESET}")

    def _handle_network_info(self):
        """Mostra informações básicas de rede"""
        info = self.get_network_info()
        if info:
            print(f"\n{VERDE}Informações de rede:{RESET}")
            print(f"{AZUL}IP Público: {info['ip_publico']}")
            if 'rede' in info and 'interfaces' in info['rede']:
                print(f"Interfaces: {', '.join(info['rede']['interfaces'])}")
        else:
            print(f"{VERMELHO}Não foi possível obter informações{RESET}")

if __name__ == "__main__":
    
    try:
        import exifread
        from PIL import Image
    except ImportError:
        print(f"{AMARELO}[!] Instalando dependências...{RESET}")
        os.system("pip install exifread Pillow requests colorama --quiet")
    
    tool = LiteGeoMetaTool()
    tool.show_menu()
