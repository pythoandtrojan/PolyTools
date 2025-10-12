import requests
import json
import time
from colorama import Fore, Style, init
import os
import urllib.parse

# Inicializar colorama
init(autoreset=True)

class ShipTracker:
    def __init__(self):
        self.ship_data = []
        
    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Exibe o banner"""
        banner = f"""
{Fore.BLUE}
 █████╗ ██████╗ ██╗      ███╗   ██╗ █████╗ ██╗   ██╗ █████╗ ██╗     
██╔══██╗██╔══██╗██║      ████╗  ██║██╔══██╗██║   ██║██╔══██╗██║     
███████║██████╔╝██║█████╗██╔██╗ ██║███████║██║   ██║███████║██║     
██╔══██║██╔═══╝ ██║╚════╝██║╚██╗██║██╔══██║╚██╗ ██╔╝██╔══██║██║     
██║  ██║██║     ██║      ██║ ╚████║██║  ██║ ╚████╔╝ ██║  ██║███████╗
╚═╝  ╚═╝╚═╝     ╚═╝      ╚═╝  ╚═══╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝
                                                                    
{Fore.CYAN}
                Rastreador de Navios - APIs Web
{Style.RESET_ALL}
        """
        print(banner)
    
    def wait_enter(self):
        """Aguarda Enter para continuar"""
        input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Style.RESET_ALL}")
    
    def display_url_instructions(self, url, service_name):
        """Exibe instruções para acessar a URL"""
        print(f"\n{Fore.GREEN}" + "═" * 70)
        print(f"📡 URL GERADA - {service_name}")
        print("═" * 70 + f"{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Copie e cole esta URL no seu navegador:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{url}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[!] Instruções:{Style.RESET_ALL}")
        print(f"1. {Fore.CYAN}Copie a URL acima{Style.RESET_ALL}")
        print(f"2. {Fore.CYAN}Abra seu navegador (Chrome, Firefox, etc.){Style.RESET_ALL}")
        print(f"3. {Fore.CYAN}Cole a URL na barra de endereços{Style.RESET_ALL}")
        print(f"4. {Fore.CYAN}Pressione Enter para acessar{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}✅ Você verá o mapa com a localização do navio!{Style.RESET_ALL}")
    
    def vessel_finder_by_mmsi(self, mmsi):
        """Gera URL para VesselFinder com MMSI"""
        url = f"https://www.vesselfinder.com/vessels?mmsi={mmsi}"
        
        print(f"\n{Fore.CYAN}[*] Buscando navio por MMSI: {mmsi}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] MMSI é um identificador único de 9 dígitos para navios{Style.RESET_ALL}")
        
        self.display_url_instructions(url, "VESSEL FINDER")
        
        print(f"\n{Fore.YELLOW}📋 Informações sobre MMSI:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• MMSI (Maritime Mobile Service Identity){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Número único de 9 dígitos para identificação de navios{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Usado para comunicação e rastreamento AIS{Style.RESET_ALL}")
    
    def vessel_finder_by_name(self, ship_name):
        """Gera URL para VesselFinder com nome do navio"""
        encoded_name = urllib.parse.quote(ship_name)
        url = f"https://www.vesselfinder.com/vessels?name={encoded_name}"
        
        print(f"\n{Fore.CYAN}[*] Buscando navio por nome: {ship_name}{Style.RESET_ALL}")
        
        self.display_url_instructions(url, "VESSEL FINDER")
        
        print(f"\n{Fore.YELLOW}💡 Dica: Se não encontrar, tente:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Nome completo do navio{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Nome exato como registrado{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• MMSI (mais preciso){Style.RESET_ALL}")
    
    def marine_traffic_by_coordinates(self, lat, lon, zoom=8):
        """Gera URL para MarineTraffic com coordenadas"""
        url = f"https://www.marinetraffic.com/en/ais/home/centerx:{lon}/centery:{lat}/zoom:{zoom}"
        
        print(f"\n{Fore.CYAN}[*] Buscando navios nas coordenadas:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📍 Latitude: {lat} | Longitude: {lon} | Zoom: {zoom}{Style.RESET_ALL}")
        
        self.display_url_instructions(url, "MARINE TRAFFIC")
        
        print(f"\n{Fore.YELLOW}🗺️  Informações sobre coordenadas:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Latitude: -90° a +90° (Negativo = Sul, Positivo = Norte){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Longitude: -180° a +180° (Negativo = Oeste, Positivo = Leste){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Zoom: 1-10 (1=visão global, 10=visão detalhada){Style.RESET_ALL}")
    
    def marine_traffic_by_port(self, port_name):
        """Gera URL para MarineTraffic com nome do porto"""
        encoded_port = urllib.parse.quote(port_name)
        url = f"https://www.marinetraffic.com/en/ais/index/search/all?keyword={encoded_port}"
        
        print(f"\n{Fore.CYAN}[*] Buscando porto: {port_name}{Style.RESET_ALL}")
        
        self.display_url_instructions(url, "MARINE TRAFFIC - PORTO")
        
        print(f"\n{Fore.YELLOW}⚓ Portos populares para teste:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Santos, Rotterdam, Singapore, Shanghai{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Hamburg, Antwerp, Los Angeles{Style.RESET_ALL}")
    
    def get_ship_examples(self):
        """Retorna exemplos de MMSI para teste"""
        examples = [
            {"mmsi": "244123456", "name": "Navio Exemplo 1", "type": "Cargo"},
            {"mmsi": "367123456", "name": "Navio Exemplo 2", "type": "Tanker"},
            {"mmsi": "636015874", "name": "Real Example", "type": "Container Ship"},
            {"mmsi": "257879000", "name": "Real Example", "type": "Passenger"}
        ]
        return examples
    
    def show_api_info(self):
        """Mostra informações sobre as APIs"""
        self.clear_screen()
        self.display_banner()
        
        print(f"{Fore.CYAN}" + "═" * 70)
        print("INFORMAÇÕES SOBRE AS APIS DE RASTREMENTO")
        print("═" + "═" * 69 + f"{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🚢 VESSEL FINDER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Site: https://www.vesselfinder.com{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Busca por: MMSI, Nome do Navio, IMO{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Dados: Posição, Rota, Velocidade, Destino{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}🌊 MARINE TRAFFIC{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Site: https://www.marinetraffic.com{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Busca por: Coordenadas, Porto, Nome{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Dados: Mapa em tempo real, Fotos, Detalhes{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}📡 SISTEMA AIS (Automatic Identification System){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Tecnologia usada para rastreamento{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Transmite: Posição, Velocidade, Curso{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Obrigatório para navios comerciais{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🎯 EXEMPLOS DE MMSI PARA TESTE:{Style.RESET_ALL}")
        examples = self.get_ship_examples()
        for example in examples:
            print(f"{Fore.CYAN}• MMSI: {example['mmsi']} - {example['name']} ({example['type']}){Style.RESET_ALL}")
        
        self.wait_enter()
    
    def menu_vessel_finder(self):
        """Menu do VesselFinder"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"{Fore.GREEN}" + "═" * 50)
            print("VESSEL FINDER - RASTREAMENTO POR NAVIO")
            print("═" * 50 + f"{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}[1] Buscar por MMSI (Recomendado)")
            print(f"[2] Buscar por Nome do Navio")
            print(f"[3] Voltar ao Menu Principal{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.clear_screen()
                self.display_banner()
                mmsi = input(f"{Fore.CYAN}[?] Digite o MMSI (9 dígitos): {Style.RESET_ALL}").strip()
                if mmsi and mmsi.isdigit() and len(mmsi) == 9:
                    self.vessel_finder_by_mmsi(mmsi)
                else:
                    print(f"{Fore.RED}[!] MMSI deve ter 9 dígitos numéricos!{Style.RESET_ALL}")
                self.wait_enter()
            elif choice == '2':
                self.clear_screen()
                self.display_banner()
                ship_name = input(f"{Fore.CYAN}[?] Digite o nome do navio: {Style.RESET_ALL}").strip()
                if ship_name:
                    self.vessel_finder_by_name(ship_name)
                else:
                    print(f"{Fore.RED}[!] Digite um nome válido!{Style.RESET_ALL}")
                self.wait_enter()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def menu_marine_traffic(self):
        """Menu do MarineTraffic"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"{Fore.BLUE}" + "═" * 50)
            print("MARINE TRAFFIC - MAPA E LOCALIZAÇÃO")
            print("═" * 50 + f"{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}[1] Buscar por Coordenadas")
            print(f"[2] Buscar por Porto")
            print(f"[3] Voltar ao Menu Principal{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.clear_screen()
                self.display_banner()
                try:
                    lat = input(f"{Fore.CYAN}[?] Latitude (ex: -23.5505): {Style.RESET_ALL}").strip()
                    lon = input(f"{Fore.CYAN}[?] Longitude (ex: -46.6333): {Style.RESET_ALL}").strip()
                    zoom = input(f"{Fore.CYAN}[?] Zoom (1-10, padrão=8): {Style.RESET_ALL}").strip()
                    
                    if not zoom:
                        zoom = 8
                    else:
                        zoom = int(zoom)
                    
                    if lat and lon:
                        self.marine_traffic_by_coordinates(float(lat), float(lon), zoom)
                    else:
                        print(f"{Fore.RED}[!] Coordenadas inválidas!{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}[!] Digite números válidos!{Style.RESET_ALL}")
                self.wait_enter()
            elif choice == '2':
                self.clear_screen()
                self.display_banner()
                port_name = input(f"{Fore.CYAN}[?] Digite o nome do porto: {Style.RESET_ALL}").strip()
                if port_name:
                    self.marine_traffic_by_port(port_name)
                else:
                    print(f"{Fore.RED}[!] Digite um nome de porto válido!{Style.RESET_ALL}")
                self.wait_enter()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def quick_search(self):
        """Busca rápida com exemplos"""
        self.clear_screen()
        self.display_banner()
        
        print(f"{Fore.GREEN}" + "═" * 50)
        print("BUSCA RÁPIDA - EXEMPLOS PRONTOS")
        print("═" * 50 + f"{Style.RESET_ALL}")
        
        examples = self.get_ship_examples()
        
        print(f"{Fore.YELLOW}🚢 Exemplos de MMSI para teste:{Style.RESET_ALL}")
        for i, example in enumerate(examples, 1):
            print(f"{Fore.CYAN}[{i}] MMSI: {example['mmsi']} - {example['name']}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[5] 🌊 Ver navios no Porto de Santos{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[6] 🗺️  Ver navios no Oceano Atlântico{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.CYAN}[?] Selecione um exemplo (1-6): {Style.RESET_ALL}")
        
        if choice == '1':
            self.vessel_finder_by_mmsi(examples[0]['mmsi'])
        elif choice == '2':
            self.vessel_finder_by_mmsi(examples[1]['mmsi'])
        elif choice == '3':
            self.vessel_finder_by_mmsi(examples[2]['mmsi'])
        elif choice == '4':
            self.vessel_finder_by_mmsi(examples[3]['mmsi'])
        elif choice == '5':
            self.marine_traffic_by_coordinates(-23.9608, -46.3332, 10)  # Porto de Santos
        elif choice == '6':
            self.marine_traffic_by_coordinates(0, -30, 4)  # Atlântico
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"{Fore.YELLOW}[1] 🚢 VesselFinder (Buscar Navio Específico)")
            print(f"[2] 🌊 MarineTraffic (Mapa e Localização)")
            print(f"[3] ⚡ Busca Rápida (Exemplos Prontos)")
            print(f"[4] 📡 Informações sobre as APIs")
            print(f"[5] 🚪 Sair{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.menu_vessel_finder()
            elif choice == '2':
                self.menu_marine_traffic()
            elif choice == '3':
                self.quick_search()
            elif choice == '4':
                self.show_api_info()
            elif choice == '5':
                print(f"{Fore.GREEN}[+] Obrigado por usar o Rastreador de Navios!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()

def main():
    """Função principal"""
    try:
        tracker = ShipTracker()
        tracker.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Programa interrompido pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
