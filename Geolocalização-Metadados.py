#!/usr/bin/env python3

import os
import sys
import json
import re
import subprocess
from datetime import datetime
from colorama import Fore, Style, init
import exifread
from PIL import Image, ExifTags


init(autoreset=True)
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
CIANO = Fore.CYAN
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

class TermuxWifiMetaTool:
    def __init__(self):
        self.results = {}

    def banner(self):
        """Exibe banner da ferramenta"""
        os.system('clear')
        print(f"""
{VERDE}{NEGRITO}
   ▄████  ██▓     ██▓ ███▄    █   ██████ 
  ██▒ ▀█▒▓██▒    ▓██▒ ██ ▀█   █ ▒██    ▒ 
 ▒██░▄▄▄░▒██░    ▒██▒▓██  ▀█ ██▒░ ▓██▄   
 ░▓█  ██▓▒██░    ░██░▓██▒  ▐▌██▒  ▒   ██▒
 ░▒▓███▀▒░██████▒░██░▒██░   ▓██░▒██████▒▒
  ░▒   ▒ ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
   ░   ░ ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░
 ░ ░   ░   ░ ░    ▒ ░   ░   ░ ░ ░  ░  ░  
       ░     ░  ░ ░           ░       ░  
{RESET}
{CIANO}{NEGRITO}   TERMUX WiFi & METADADOS TOOL
   Versão Simplificada para Termux
{RESET}
{AMARELO}   Recursos: Varredura WiFi e Análise de Metadados
   Otimizado para Android/Termux
{RESET}""")

    def scan_wifi_networks(self):
        """Varredura de redes WiFi no Termux"""
        print(f"\n{CIANO}[+] Varrendo redes WiFi próximas...{RESET}")
        
        try:
          
            result = subprocess.run(['termux-wifi-scaninfo'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=30)
            
            if result.returncode == 0:
                wifi_data = json.loads(result.stdout)
                print(f"{VERDE}[+] Encontradas {len(wifi_data)} redes WiFi{RESET}")
                return wifi_data
            else:
                print(f"{VERMELHO}[!] Erro ao escanear WiFi: {result.stderr}{RESET}")
                return []
                
        except Exception as e:
            print(f"{VERMELHO}[!] Falha na varredura WiFi: {e}{RESET}")
            return []

    def extract_metadata(self, file_path):
        """Extrai metadados de arquivos no Termux"""
        print(f"\n{CIANO}[+] Extraindo metadados de: {file_path}{RESET}")
        
        metadata = {
            "file": os.path.basename(file_path),
            "path": file_path,
            "size": os.path.getsize(file_path),
            "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
        
        try:
            
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                with open(file_path, 'rb') as f:
                    tags = exifread.process_file(f)
                    for tag in tags.keys():
                        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                            metadata[str(tag)] = str(tags[tag])
                
                
                gps_data = self.extract_gps(file_path)
                if gps_data:
                    metadata["gps"] = gps_data
                    print(f"{VERDE}[+] Coordenadas GPS encontradas{RESET}")
            
            print(f"{VERDE}[+] {len(metadata)} metadados extraídos{RESET}")
            return metadata
            
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao extrair metadados: {e}{RESET}")
            return None

    def extract_gps(self, image_path):
        """Extrai coordenadas GPS de imagens no Termux"""
        try:
            img = Image.open(image_path)
            exif_data = img._getexif()
            
            if not exif_data:
                return None
                
            gps_info = {}
            for tag, value in exif_data.items():
                decoded = ExifTags.TAGS.get(tag, tag)
                if decoded == "GPSInfo":
                    for t in value:
                        sub_decoded = ExifTags.GPSTAGS.get(t, t)
                        gps_info[sub_decoded] = value[t]
            
            if not gps_info:
                return None
                
            lat = self.convert_gps(gps_info.get("GPSLatitude"), gps_info.get("GPSLatitudeRef"))
            lon = self.convert_gps(gps_info.get("GPSLongitude"), gps_info.get("GPSLongitudeRef"))
            
            if lat and lon:
                return {
                    "latitude": lat,
                    "longitude": lon,
                    "altitude": gps_info.get("GPSAltitude"),
                    "timestamp": gps_info.get("GPSTimeStamp")
                }
        except Exception as e:
            print(f"{AMARELO}[!] Erro ao extrair GPS: {e}{RESET}")
            return None

    def convert_gps(self, coord, ref):
        """Converte coordenadas GPS EXIF para decimal"""
        try:
            if not coord or not ref:
                return None
                
            degrees = coord[0][0] / coord[0][1]
            minutes = coord[1][0] / coord[1][1]
            seconds = coord[2][0] / coord[2][1]
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            if ref in ['S', 'W']:
                decimal = -decimal
                
            return decimal
        except:
            return None

    def show_results(self):
        """Exibe resultados formatados"""
        print(f"\n{CIANO}{NEGRITO}=== RESULTADOS ==={RESET}")
        
        
        if "wifi" in self.results:
            print(f"\n{VERDE}{NEGRITO}● REDES WIFI DETECTADAS{RESET}")
            for i, network in enumerate(self.results["wifi"], 1):
                print(f"  {AZUL}↳ Rede {i}: {network.get('ssid', 'Oculto')}{RESET}")
                print(f"    {AMARELO}BSSID: {network.get('bssid', '?')}")
                print(f"    {AMARELO}Sinal: {network.get('rssi', '?')} dBm")
                print(f"    {AMARELO}Frequência: {network.get('frequency_mhz', '?')} MHz")
                print(f"    {AMARELO}Canal: {network.get('channel_width', '?')}")
        
        
        if "metadata" in self.results:
            print(f"\n{MAGENTA}{NEGRITO}● METADADOS DE ARQUIVO{RESET}")
            meta = self.results["metadata"]
            print(f"  {MAGENTA}↳ Arquivo: {meta.get('file')}{RESET}")
            print(f"  {MAGENTA}↳ Tamanho: {meta.get('size')} bytes{RESET}")
            print(f"  {MAGENTA}↳ Modificado: {meta.get('modified')}{RESET}")
            
            if "gps" in meta:
                gps = meta["gps"]
                print(f"  {VERDE}↳ Coordenadas GPS:{RESET}")
                print(f"    {AMARELO}Latitude: {gps.get('latitude')}")
                print(f"    {AMARELO}Longitude: {gps.get('longitude')}")
                if gps.get("altitude"):
                    print(f"    {AMARELO}Altitude: {gps.get('altitude')}")

    def save_report(self, filename=None):
        """Salva relatório completo"""
        if not self.results:
            print(f"{VERMELHO}[!] Nenhum resultado para salvar{RESET}")
            return
            
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"termux_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"{VERDE}[+] Relatório salvo como {filename}{RESET}")
        return filename

    def interactive_menu(self):
        """Menu interativo simplificado"""
        self.banner()
        
        while True:
            print(f"\n{CIANO}{NEGRITO}MENU PRINCIPAL{RESET}")
            print(f"  {VERDE}1{RESET} - Escanear redes WiFi")
            print(f"  {VERDE}2{RESET} - Extrair metadados de arquivo")
            print(f"  {VERDE}3{RESET} - Exibir resultados")
            print(f"  {VERDE}4{RESET} - Salvar relatório")
            print(f"  {VERDE}5{RESET} - Sair")
            
            choice = input(f"\n{AMARELO}[?] Selecione uma opção: {RESET}").strip()
            
            if choice == "1":
                wifi_data = self.scan_wifi_networks()
                if wifi_data:
                    self.results["wifi"] = wifi_data
            
            elif choice == "2":
                file_path = input(f"{AMARELO}[?] Caminho do arquivo: {RESET}").strip()
                if os.path.exists(file_path):
                    meta = self.extract_metadata(file_path)
                    if meta:
                        self.results["metadata"] = meta
                else:
                    print(f"{VERMELHO}[!] Arquivo não encontrado{RESET}")
            
            elif choice == "3":
                self.show_results()
            
            elif choice == "4":
                if self.results:
                    filename = input(f"{AMARELO}[?] Nome do arquivo (vazio para padrão): {RESET}").strip()
                    self.save_report(filename if filename else None)
                else:
                    print(f"{VERMELHO}[!] Nenhum resultado para salvar{RESET}")
            
            elif choice == "5":
                print(f"{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida{RESET}")

def main():
    
    try:
        subprocess.run(['termux-wifi-scaninfo'], 
                      capture_output=True, 
                      check=True)
    except:
        print(f"{VERMELHO}[!] Termux:API não instalado ou não configurado!")
        print(f"[!] Instale com: pkg install termux-api{RESET}")
        return
    
    tool = TermuxWifiMetaTool()
    tool.interactive_menu()

if __name__ == "__main__":
    # Verifica dependências básicas
    try:
        import exifread
        from PIL import Image
    except ImportError:
        print(f"{VERMELHO}[!] Instalando dependências...{RESET}")
        os.system("pkg install python -y && pip install exifread Pillow colorama")
    
    main()
