import os
import requests
import json
import time
from datetime import datetime
import sys
import random
import webbrowser
from colorama import init, Fore, Back, Style


init(autoreset=True)


API_KEYS = {
    'binlist': None,
    'bincheck': None,
    'apilayer': None
}
RESULTS_DIR = "bin_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def show_banner():
    colors = [Fore.CYAN, Fore.MAGENTA, Fore.BLUE, Fore.YELLOW]
    color = random.choice(colors)
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""{color}
  ██████╗ ██╗███╗   ██╗    
  ██╔══██╗██║████╗  ██║    
  ██████╔╝██║██╔██╗ ██║    
  ██╔══██╗██║██║╚██╗██║   
  ██████╔╝██║██║ ╚████║    
  ╚═════╝ ╚═╝╚═╝  ╚═══╝    
  
{Fore.YELLOW}
  [+] BIN SCANNER ULTIMATE v4.0 [+]
  [+] Multi-API | Proxy Support | Bulk Check | JSON Export [+]
  [+] Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [+]
{Style.RESET_ALL}""")


def show_loading(msg="Processando"):
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    for i in range(10):
        for char in chars:
            sys.stdout.write(f"\r{Fore.BLUE}[*] {msg} {char} {i+1}/10{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
    print()


def check_connection():
    try:
        requests.get('https://google.com', timeout=5)
        return True
    except:
        return False


def setup_proxy():
    proxy = input(f"{Fore.YELLOW}[?] Usar proxy? (formato user:pass@ip:port ou Enter para pular): {Style.RESET_ALL}").strip()
    if not proxy:
        return None
    
    proxies = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}'
    }
    
    try:
        test = requests.get('https://api.ipify.org', proxies=proxies, timeout=10)
        print(f"{Fore.GREEN}[+] Proxy configurado com sucesso! IP: {test.text}{Style.RESET_ALL}")
        return proxies
    except Exception as e:
        print(f"{Fore.RED}[!] Proxy inválido ou não conectado: {e}{Style.RESET_ALL}")
        return None


def query_binlist(bin_number, proxies=None):
    try:
        url = f"https://lookup.binlist.net/{bin_number}"
        headers = {
            'Accept-Version': '3',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        
        show_loading("Consultando Binlist.net")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'api': 'Binlist.net',
                'data': {
                    'Bandeira': data.get('scheme', 'N/A'),
                    'Tipo': data.get('type', 'N/A'),
                    'Categoria': data.get('brand', 'N/A'),
                    'País': f"{data.get('country', {}).get('name', 'N/A')} {data.get('country', {}).get('emoji', '')}",
                    'Moeda': data.get('country', {}).get('currency', 'N/A'),
                    'Banco': data.get('bank', {}).get('name', 'N/A'),
                    'URL Banco': data.get('bank', {}).get('url', 'N/A'),
                    'Pré-pago': 'Sim' if data.get('prepaid', False) else 'Não'
                }
            }
        else:
            print(f"{Fore.RED}[!] Binlist.net: BIN não encontrado (Status: {response.status_code}){Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API Binlist.net: {e}{Style.RESET_ALL}")
        return None

def query_bincheck(bin_number, proxies=None):
    try:
        url = f"https://bin-checker.net/api/{bin_number}"
        params = {'api_key': 'free'}
        
        show_loading("Consultando BIN Checker")
        response = requests.get(url, params=params, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'api': 'BIN Checker',
                'data': {
                    'Bandeira': data.get('card_brand', 'N/A'),
                    'Tipo': data.get('card_type', 'N/A'),
                    'Nível': data.get('card_level', 'N/A'),
                    'País': f"{data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})",
                    'Banco': data.get('bank_name', 'N/A'),
                    'Telefone': data.get('bank_phone', 'N/A'),
                    'Site': data.get('bank_website', 'N/A'),
                    'Valido': data.get('valid', 'N/A')
                }
            }
        else:
            print(f"{Fore.RED}[!] BIN Checker: Limite atingido (Status: {response.status_code}){Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API BIN Checker: {e}{Style.RESET_ALL}")
        return None

def query_bindb(bin_number, proxies=None):
    try:
        url = f"https://bins.antipublic.cc/bins/{bin_number}"
        
        show_loading("Consultando BIN Database")
        response = requests.get(url, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'api': 'BIN Database',
                'data': {
                    'Bandeira': data.get('brand', 'N/A'),
                    'Tipo': data.get('type', 'N/A'),
                    'Sub-tipo': data.get('sub_type', 'N/A'),
                    'País': data.get('country', 'N/A'),
                    'Banco': data.get('bank', 'N/A'),
                    'Score': data.get('score', 'N/A'),
                    'Coordenadas': f"{data.get('country_info', {}).get('latitude', 'N/A')}, {data.get('country_info', {}).get('longitude', 'N/A')}"
                }
            }
        else:
            print(f"{Fore.RED}[!] BIN Database: BIN não encontrado (Status: {response.status_code}){Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API BIN Database: {e}{Style.RESET_ALL}")
        return None

def query_iin(bin_number, proxies=None):
    try:
        url = f"https://iinnetlookup.vercel.app/bin/{bin_number}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        
        show_loading("Consultando IIN Lookup")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'api': 'IIN Lookup',
                'data': {
                    'Bandeira': data.get('network', 'N/A'),
                    'Tipo': data.get('type', 'N/A'),
                    'Pré-pago': data.get('prepaid', 'N/A'),
                    'País': data.get('country', 'N/A'),
                    'Código ISO': data.get('country_code', 'N/A'),
                    'Banco': data.get('bank', 'N/A'),
                    'Telefone': data.get('phone', 'N/A')
                }
            }
        else:
            print(f"{Fore.RED}[!] IIN Lookup: BIN não encontrado (Status: {response.status_code}){Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API IIN Lookup: {e}{Style.RESET_ALL}")
        return None

def query_cardbinlist(bin_number, proxies=None):
    try:
        url = f"https://cardbinlist.com/api/{bin_number}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        
        show_loading("Consultando CardBinList")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('valid', False):
                return {
                    'api': 'CardBinList',
                    'data': {
                        'Bandeira': data.get('brand', 'N/A'),
                        'Tipo': data.get('type', 'N/A'),
                        'Categoria': data.get('category', 'N/A'),
                        'País': f"{data.get('country', {}).get('name', 'N/A')} {data.get('country', {}).get('emoji', '')}",
                        'Banco': data.get('bank', {}).get('name', 'N/A'),
                        'URL Banco': data.get('bank', {}).get('url', 'N/A'),
                        'Coordenadas': f"{data.get('country', {}).get('latitude', 'N/A')}, {data.get('country', {}).get('longitude', 'N/A')}"
                    }
                }
        print(f"{Fore.RED}[!] CardBinList: BIN não encontrado ou limite atingido{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API CardBinList: {e}{Style.RESET_ALL}")
        return None


def query_binlookup(bin_number, proxies=None):
    try:
        url = f"https://bin-ip-checker.p.rapidapi.com/?bin={bin_number}"
        headers = {
            'X-RapidAPI-Key': 'your-api-key-here',  
            'X-RapidAPI-Host': 'bin-ip-checker.p.rapidapi.com'
        }
        
        show_loading("Consultando BIN Lookup")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'api': 'BIN Lookup',
                'data': {
                    'Bandeira': data.get('cardBrand', 'N/A'),
                    'Tipo': data.get('cardType', 'N/A'),
                    'Nível': data.get('cardLevel', 'N/A'),
                    'País': data.get('countryName', 'N/A'),
                    'Banco': data.get('bankName', 'N/A'),
                    'Emissor': data.get('issuer', 'N/A'),
                    'Latitude': data.get('latitude', 'N/A'),
                    'Longitude': data.get('longitude', 'N/A')
                }
            }
        else:
            print(f"{Fore.RED}[!] BIN Lookup: Erro na API (Status: {response.status_code}){Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erro na API BIN Lookup: {e}{Style.RESET_ALL}")
        return None

def check_bin(bin_number, proxies=None):
    if not bin_number.isdigit() or len(bin_number) < 6:
        print(f"{Fore.RED}[!] BIN inválido. Deve conter apenas números (6-9 dígitos){Style.RESET_ALL}")
        return None
    
    bin_number = bin_number[:9]  
    print(f"\n{Fore.GREEN}[*] Verificando BIN: {bin_number}{Style.RESET_ALL}")
    
    
    apis = [
        query_binlist,
        query_bincheck,
        query_bindb,
        query_iin,
        query_cardbinlist,
        query_binlookup
    ]
    
    results = []
    for api in apis:
        result = api(bin_number, proxies)
        if result:
            results.append(result)
    
    if not results:
        print(f"{Fore.RED}[!] Nenhuma API retornou resultados para este BIN{Style.RESET_ALL}")
        return None
    
  
    print(f"\n{Fore.YELLOW}=== RESULTADOS CONSOLIDADOS ==={Style.RESET_ALL}")
    for result in results:
        print(f"\n{Fore.CYAN}>>> {result['api']}{Style.RESET_ALL}")
        for key, value in result['data'].items():
            print(f"{Fore.GREEN}{key}: {Fore.WHITE}{value}{Style.RESET_ALL}")
    
    return results


def bulk_check(proxies=None):
    try:
        file_path = input(f"\n{Fore.YELLOW}[?] Caminho do arquivo com BINs (um por linha): {Style.RESET_ALL}").strip()
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[!] Arquivo não encontrado!{Style.RESET_ALL}")
            return
        
        with open(file_path, 'r') as f:
            bins = [line.strip() for line in f if line.strip()]
        
        if not bins:
            print(f"{Fore.RED}[!] Nenhum BIN válido encontrado no arquivo!{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[*] Iniciando verificação de {len(bins)} BINs...{Style.RESET_ALL}")
        
        all_results = []
        for i, bin_num in enumerate(bins, 1):
            print(f"\n{Fore.YELLOW}[+] Verificando BIN {i}/{len(bins)}: {bin_num}{Style.RESET_ALL}")
            results = check_bin(bin_num, proxies)
            if results:
                all_results.extend(results)
            
            if i < len(bins):
                time.sleep(2)  
        
        
        if all_results:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{RESULTS_DIR}/bulk_results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(all_results, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Todos os resultados salvos em: {filename}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Verificação em massa concluída!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro durante verificação em massa: {e}{Style.RESET_ALL}")


def save_results(bin_number, results):
    try:
        if not results:
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{RESULTS_DIR}/{bin_number}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n{Fore.GREEN}[+] Resultados salvos em: {filename}{Style.RESET_ALL}")
        return filename
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao salvar resultados: {e}{Style.RESET_ALL}")
        return None


def show_menu():
    print(f"""
{Fore.YELLOW}[1] Verificar BIN individual
[2] Verificar múltiplos BINs (arquivo)
[3] Configurar proxy
[4] Sobre a ferramenta
[5] Sair{Style.RESET_ALL}""")

def about_screen():
    show_banner()
    print(f"""
{Fore.CYAN}[+] BIN Scanner Ultimate v4.0

{Fore.YELLOW}DESCRIÇÃO:{Fore.WHITE}
Ferramenta avançada para verificação de BINs (Bank Identification Numbers)
utilizando múltiplas APIs públicas com fallback automático para máxima precisão.

{Fore.YELLOW}RECURSOS:{Fore.WHITE}
- Suporte a 6 APIs diferentes
- Verificação individual e em massa
- Suporte a proxy
- Exportação para JSON
- Interface colorida e intuitiva

{Fore.YELLOW}APIS UTILIZADAS:{Fore.WHITE}
1. Binlist.net (oficial)
2. BIN Checker (com cache)
3. BIN Database (antipublic)
4. IIN Lookup
5. CardBinList (fallback)
6. BIN Lookup (nova API)

{Fore.YELLOW}DESENVOLVIDO POR:{Fore.WHITE}
erik/malwer

Pressione Enter para voltar...{Style.RESET_ALL}""")
    input()


def main():
    if not check_connection():
        print(f"{Fore.RED}[!] Sem conexão com a internet! Verifique sua rede.{Style.RESET_ALL}")
        return
    
    proxies = None
    show_banner()
    
    while True:
        show_menu()
        choice = input(f"\n{Fore.CYAN}[?] Escolha uma opção: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            show_banner()
            bin_input = input(f"\n{Fore.YELLOW}[?] Digite o BIN (6-9 dígitos): {Style.RESET_ALL}").strip()
            
            if bin_input.isdigit() and len(bin_input) >= 6:
                results = check_bin(bin_input, proxies)
                if results:
                    save = input(f"\n{Fore.YELLOW}[?] Salvar resultados? (S/N): {Style.RESET_ALL}").strip().lower()
                    if save == 's':
                        save_results(bin_input, results)
            else:
                print(f"{Fore.RED}[!] BIN inválido! Deve conter apenas números (6-9 dígitos){Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            show_banner()
        
        elif choice == '2':
            show_banner()
            bulk_check(proxies)
            input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            show_banner()
        
        elif choice == '3':
            show_banner()
            proxies = setup_proxy()
            input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")
            show_banner()
        
        elif choice == '4':
            about_screen()
            show_banner()
        
        elif choice == '5':
            print(f"\n{Fore.GREEN}[+] Obrigado por usar o BIN Scanner Ultimate!{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}[!] Opção inválida! Escolha entre 1-5.{Style.RESET_ALL}")
            time.sleep(1)
            show_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Programa interrompido pelo usuário.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro crítico: {e}{Style.RESET_ALL}")
