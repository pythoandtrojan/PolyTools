import requests
import json
import time
from colorama import Fore, Style, init
import os

# Inicializar colorama
init(autoreset=True)

class VirusTotalAnalyzer:
    def __init__(self):
        self.api_key = None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = None
        
    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Exibe o banner"""
        banner = f"""
{Fore.GREEN}
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ████████╗ ██████╗ ████████╗ █████╗ ██╗     
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║     
██║   ██║██║██████╔╝██║   ██║███████╗█████╗██║   ██║   ██║   ██║   ███████║██║     
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║╚════╝██║   ██║   ██║   ██║   ██╔══██║██║     
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║      ██║   ╚██████╔╝   ██║   ██║  ██║███████╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝
                                                                                   
{Fore.CYAN}
              APK & URL Analyzer - VirusTotal API
{Style.RESET_ALL}
        """
        print(banner)
    
    def wait_enter(self):
        """Aguarda Enter para continuar"""
        input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Style.RESET_ALL}")
    
    def setup_api_key(self):
        """Configura a API key do VirusTotal"""
        self.clear_screen()
        self.display_banner()
        
        print(f"{Fore.CYAN}[*] Configuração da API Key do VirusTotal{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Você precisa de uma API key gratuita do VirusTotal{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Obtenha em: {Fore.WHITE}https://www.virustotal.com/gui/join-us{Style.RESET_ALL}")
        print()
        
        key = input(f"{Fore.CYAN}[?] Digite sua API Key (ou Enter para pular): {Style.RESET_ALL}").strip()
        
        if key:
            self.api_key = key
            self.headers = {"x-apikey": self.api_key}
            
            # Testa a API key
            if self.test_api_key():
                print(f"{Fore.GREEN}[+] API Key válida! Configuração concluída.{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] API Key inválida ou sem créditos.{Style.RESET_ALL}")
                self.api_key = None
                self.headers = None
                return False
        else:
            print(f"{Fore.YELLOW}[!] Modo sem API key ativado.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Use o site oficial para análises completas.{Style.RESET_ALL}")
            return True
    
    def test_api_key(self):
        """Testa se a API key é válida"""
        try:
            url = f"{self.base_url}/users/{self.api_key}"
            response = requests.get(url, headers=self.headers, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def recommend_website(self, target, target_type):
        """Recomenda o site oficial quando não há API key"""
        print(f"\n{Fore.YELLOW}" + "═" * 60)
        print(f"[!] API KEY NÃO CONFIGURADA")
        print("═" * 60)
        print(f"[!] Para análise completa, use o site oficial:{Style.RESET_ALL}")
        
        if target_type == "url":
            analysis_url = f"https://www.virustotal.com/gui/url/{self.calculate_hash(target)}"
            website_url = f"https://www.virustotal.com/gui/url-analysis"
        else:  # apk
            analysis_url = f"https://www.virustotal.com/gui/file/{self.calculate_hash(target)}"
            website_url = "https://www.virustotal.com/gui/file-analysis"
        
        print(f"{Fore.CYAN}[*] URL para análise direta:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{analysis_url}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Site oficial do VirusTotal:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{website_url}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Obter API key gratuita:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}https://www.virustotal.com/gui/join-us{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[*] Limitações da API gratuita:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}- 500 requisições/dia")
        print(f"- 4 requisições/minuto")
        print(f"- Acesso completo à API v3{Style.RESET_ALL}")
    
    def calculate_hash(self, target):
        """Calcula hash SHA256 para URLs (simplificado)"""
        import hashlib
        return hashlib.sha256(target.encode()).hexdigest()
    
    def analyze_url(self, url):
        """Analisa uma URL usando VirusTotal API"""
        if not self.api_key:
            self.recommend_website(url, "url")
            return
        
        try:
            print(f"{Fore.CYAN}[*] Analisando URL: {url}{Style.RESET_ALL}")
            
            # Primeiro, envia a URL para análise
            submit_url = f"{self.base_url}/urls"
            payload = {"url": url}
            
            response = requests.post(submit_url, headers=self.headers, data=payload, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                
                print(f"{Fore.GREEN}[+] URL submetida para análise. ID: {analysis_id}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Aguardando resultado...{Style.RESET_ALL}")
                
                # Aguarda um pouco e busca os resultados
                time.sleep(3)
                return self.get_analysis_results(analysis_id, "url")
            else:
                print(f"{Fore.RED}[!] Erro ao submeter URL: {response.status_code}{Style.RESET_ALL}")
                return None
                
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Erro de conexão: {e}{Style.RESET_ALL}")
            return None
    
    def analyze_apk_hash(self, file_hash):
        """Analisa um APK pelo hash usando VirusTotal API"""
        if not self.api_key:
            self.recommend_website(file_hash, "apk")
            return
        
        try:
            print(f"{Fore.CYAN}[*] Analisando APK (Hash: {file_hash}){Style.RESET_ALL}")
            
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                return self.parse_analysis_results(response.json(), "apk")
            elif response.status_code == 404:
                print(f"{Fore.YELLOW}[!] Arquivo não encontrado no VirusTotal.{Style.RESET_ALL}")
                return None
            else:
                print(f"{Fore.RED}[!] Erro na análise: {response.status_code}{Style.RESET_ALL}")
                return None
                
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Erro de conexão: {e}{Style.RESET_ALL}")
            return None
    
    def get_analysis_results(self, analysis_id, target_type):
        """Obtém resultados da análise"""
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                return self.parse_analysis_results(response.json(), target_type)
            else:
                print(f"{Fore.RED}[!] Erro ao obter resultados: {response.status_code}{Style.RESET_ALL}")
                return None
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Erro de conexão: {e}{Style.RESET_ALL}")
            return None
    
    def parse_analysis_results(self, data, target_type):
        """Parseia e exibe os resultados da análise"""
        if target_type == "url":
            stats = data['data']['attributes']['stats']
            results = data['data']['attributes']['results']
        else:  # apk
            stats = data['data']['attributes']['last_analysis_stats']
            results = data['data']['attributes']['last_analysis_results']
        
        # Exibe estatísticas
        print(f"\n{Fore.GREEN}" + "═" * 50)
        print("RESULTADOS DA ANÁLISE")
        print("═" * 50 + f"{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}Estatísticas:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}✅ Maliciosos: {stats.get('malicious', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}⚠️  Suspeitos: {stats.get('suspicious', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.RED}❌ Indetectado: {stats.get('undetected', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}🔵 Inofensivos: {stats.get('harmless', 0)}{Style.RESET_ALL}")
        
        # Exibe detalhes dos antivírus que detectaram como malicioso
        malicious_engines = []
        for engine, result in results.items():
            if result.get('category') == 'malicious' or result.get('result'):
                malicious_engines.append((engine, result.get('result', 'malicious')))
        
        if malicious_engines:
            print(f"\n{Fore.RED}🚨 Antivírus que detectaram como malicioso:{Style.RESET_ALL}")
            for engine, detection in malicious_engines[:10]:  # Mostra apenas os 10 primeiros
                print(f"  {Fore.RED}● {engine}: {detection}{Style.RESET_ALL}")
        
        # Link para análise completa
        if target_type == "url":
            analysis_url = f"https://www.virustotal.com/gui/url/{data['data']['id']}"
        else:
            analysis_url = f"https://www.virustotal.com/gui/file/{data['data']['id']}"
        
        print(f"\n{Fore.CYAN}🔗 Análise completa: {analysis_url}{Style.RESET_ALL}")
        
        return {
            'stats': stats,
            'malicious_engines': malicious_engines,
            'analysis_url': analysis_url
        }
    
    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            # Status da API key
            api_status = f"{Fore.GREEN}CONFIGURADA{Style.RESET_ALL}" if self.api_key else f"{Fore.RED}NÃO CONFIGURADA{Style.RESET_ALL}"
            print(f"{Fore.CYAN}[*] Status API Key: {api_status}{Style.RESET_ALL}")
            print()
            
            print(f"{Fore.YELLOW}[1] Configurar API Key")
            print(f"[2] Analisar URL")
            print(f"[3] Analisar APK por Hash")
            print(f"[4] Informações sobre API Key")
            print(f"[5] Sair{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.setup_api_key()
                self.wait_enter()
            elif choice == '2':
                self.menu_analyze_url()
            elif choice == '3':
                self.menu_analyze_apk()
            elif choice == '4':
                self.menu_api_info()
            elif choice == '5':
                print(f"{Fore.GREEN}[+] Saindo...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def menu_analyze_url(self):
        """Menu para analisar URL"""
        self.clear_screen()
        self.display_banner()
        
        url = input(f"{Fore.CYAN}[?] Digite a URL para análise: {Style.RESET_ALL}").strip()
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if url:
            result = self.analyze_url(url)
            if result:
                print(f"\n{Fore.GREEN}[+] Análise concluída!{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[!] Análise não pôde ser completada.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] URL inválida!{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def menu_analyze_apk(self):
        """Menu para analisar APK por hash"""
        self.clear_screen()
        self.display_banner()
        
        file_hash = input(f"{Fore.CYAN}[?] Digite o Hash SHA256 do APK: {Style.RESET_ALL}").strip()
        
        if len(file_hash) == 64:  # SHA256 tem 64 caracteres
            result = self.analyze_apk_hash(file_hash)
            if result:
                print(f"\n{Fore.GREEN}[+] Análise concluída!{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[!] APK não encontrado ou erro na análise.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Hash SHA256 inválido! Deve ter 64 caracteres.{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def menu_api_info(self):
        """Menu com informações sobre a API key"""
        self.clear_screen()
        self.display_banner()
        
        print(f"{Fore.CYAN}" + "═" * 60)
        print("INFORMAÇÕES SOBRE API KEY DO VIRUSTOTAL")
        print("═" * 60 + f"{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[!] Para usar a API, você precisa:{Style.RESET_ALL}")
        print(f"1. {Fore.CYAN}Acessar: {Fore.WHITE}https://www.virustotal.com/gui/join-us{Style.RESET_ALL}")
        print(f"2. {Fore.CYAN}Criar uma conta gratuita{Style.RESET_ALL}")
        print(f"3. {Fore.CYAN}Acessar seu perfil e gerar API Key{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Benefícios da API Key gratuita:{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}✓ 500 requisições por dia{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}✓ 4 requisições por minuto{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}✓ Acesso completo à API v3{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}✓ Análises em tempo real{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}[-] Limitações sem API Key:{Style.RESET_ALL}")
        print(f"   {Fore.RED}✗ Apenas links para site oficial{Style.RESET_ALL}")
        print(f"   {Fore.RED}✗ Sem acesso programático{Style.RESET_ALL}")
        print(f"   {Fore.RED}✗ Análises manuais necessárias{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Sua API Key atual: {Style.RESET_ALL}")
        if self.api_key:
            print(f"{Fore.GREEN}{self.api_key[:20]}...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Não configurada{Style.RESET_ALL}")
        
        self.wait_enter()

def main():
    """Função principal"""
    try:
        analyzer = VirusTotalAnalyzer()
        analyzer.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Programa interrompido pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro crítico: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
