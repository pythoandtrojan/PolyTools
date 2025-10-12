import os
import time
import requests
from itertools import permutations, combinations
from colorama import Fore, Style, init
import sys

# Inicializar colorama
init(autoreset=True)

class SocialMediaOSINT:
    def __init__(self):
        self.combinations = []
        self.results = []
        self.wordlist = []
        
    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Exibe o banner colorido"""
        banner = f"""
{Fore.RED}
███████╗███████╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝████╗  ██║██╔════╝██╔══██╗
███████╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝
╚════██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗
███████║███████╗██║ ╚████║███████╗██║  ██║
╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Fore.CYAN}
         Social Media OSINT Tool
        Wordlist Combination Scanner
{Style.RESET_ALL}
        """
        print(banner)
    
    def wait_enter(self):
        """Aguarda Enter para continuar"""
        input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Style.RESET_ALL}")
        self.clear_screen()
        self.display_banner()
    
    def load_wordlist(self, filepath):
        """Carrega a wordlist do arquivo"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                self.wordlist = [line.strip() for line in file if line.strip()]
            return True
        except FileNotFoundError:
            print(f"{Fore.RED}[ERRO] Arquivo não encontrado: {filepath}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[ERRO] Erro ao carregar wordlist: {e}{Style.RESET_ALL}")
            return False
    
    def generate_combinations(self, max_combinations=3):
        """Gera combinações da wordlist"""
        print(f"{Fore.CYAN}[*] Gerando combinações...{Style.RESET_ALL}")
        
        self.combinations = []
        
        # Adiciona palavras individuais
        self.combinations.extend(self.wordlist)
        
        # Gera combinações de 2 palavras
        if len(self.wordlist) >= 2 and max_combinations >= 2:
            for combo in permutations(self.wordlist, 2):
                combination = ''.join(combo)
                if combination not in self.combinations:
                    self.combinations.append(combination)
        
        # Gera combinações de 3 palavras
        if len(self.wordlist) >= 3 and max_combinations >= 3:
            for combo in permutations(self.wordlist, 3):
                combination = ''.join(combo)
                if combination not in self.combinations:
                    self.combinations.append(combination)
        
        print(f"{Fore.GREEN}[+] {len(self.combinations)} combinações geradas{Style.RESET_ALL}")
    
    def save_combinations(self, filename="wordlist_combinada.txt"):
        """Salva as combinações em um arquivo"""
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                for combo in self.combinations:
                    file.write(combo + '\n')
            print(f"{Fore.GREEN}[+] Combinações salvas em: {filename}{Style.RESET_ALL}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}[ERRO] Erro ao salvar combinações: {e}{Style.RESET_ALL}")
            return None
    
    def check_github(self, username):
        """Verifica se usuário existe no GitHub"""
        try:
            url = f"https://api.github.com/users/{username}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                user_data = response.json()
                return {
                    'exists': True,
                    'url': f"https://github.com/{username}",
                    'name': user_data.get('name', 'N/A'),
                    'followers': user_data.get('followers', 0)
                }
            elif response.status_code == 404:
                return {'exists': False}
            else:
                return {'exists': False, 'error': f"Status code: {response.status_code}"}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def check_reddit(self, username):
        """Verifica se usuário existe no Reddit"""
        try:
            url = f"https://www.reddit.com/user/{username}/about.json"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                user_data = response.json()
                return {
                    'exists': True,
                    'url': f"https://reddit.com/user/{username}",
                    'karma': user_data.get('data', {}).get('total_karma', 0)
                }
            elif response.status_code == 404:
                return {'exists': False}
            else:
                return {'exists': False, 'error': f"Status code: {response.status_code}"}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def check_instagram(self, username):
        """Verifica se usuário existe no Instagram"""
        try:
            url = f"https://www.instagram.com/{username}/"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                return {
                    'exists': True,
                    'url': f"https://instagram.com/{username}"
                }
            elif response.status_code in [301, 302]:
                return {'exists': True, 'url': response.headers.get('Location', url)}
            else:
                return {'exists': False}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def check_twitter(self, username):
        """Verifica se usuário existe no Twitter/X"""
        try:
            url = f"https://twitter.com/{username}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Verificação básica - pode ter falsos positivos
                if "Esta conta no existe" not in response.text and "This account doesn't exist" not in response.text:
                    return {
                        'exists': True,
                        'url': f"https://twitter.com/{username}"
                    }
                else:
                    return {'exists': False}
            else:
                return {'exists': False}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def check_facebook(self, username):
        """Verifica se usuário existe no Facebook"""
        try:
            url = f"https://www.facebook.com/{username}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                return {
                    'exists': True,
                    'url': f"https://facebook.com/{username}"
                }
            else:
                return {'exists': False}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def check_youtube(self, username):
        """Verifica se usuário existe no YouTube"""
        try:
            url = f"https://www.youtube.com/@{username}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Verificação para ver se é uma página válida
                if "channel" in response.url or "user" in response.url:
                    return {
                        'exists': True,
                        'url': response.url
                    }
                else:
                    return {'exists': False}
            else:
                return {'exists': False}
                
        except requests.RequestException as e:
            return {'exists': False, 'error': str(e)}
    
    def scan_social_media(self, username):
        """Escaneia todas as redes sociais para um usuário"""
        results = {'username': username}
        
        print(f"{Fore.CYAN}[*] Verificando: {username}{Style.RESET_ALL}")
        
        # GitHub
        github_result = self.check_github(username)
        results['github'] = github_result
        
        # Reddit
        reddit_result = self.check_reddit(username)
        results['reddit'] = reddit_result
        
        # Instagram
        instagram_result = self.check_instagram(username)
        results['instagram'] = instagram_result
        
        # Twitter
        twitter_result = self.check_twitter(username)
        results['twitter'] = twitter_result
        
        # Facebook
        facebook_result = self.check_facebook(username)
        results['facebook'] = facebook_result
        
        # YouTube
        youtube_result = self.check_youtube(username)
        results['youtube'] = youtube_result
        
        return results
    
    def display_results(self, results):
        """Exibe os resultados de forma organizada"""
        print(f"\n{Fore.GREEN}═" * 60)
        print(f"RESULTADOS PARA: {results['username']}")
        print("═" * 60)
        
        platforms = {
            'GitHub': results.get('github', {}),
            'Reddit': results.get('reddit', {}),
            'Instagram': results.get('instagram', {}),
            'Twitter/X': results.get('twitter', {}),
            'Facebook': results.get('facebook', {}),
            'YouTube': results.get('youtube', {})
        }
        
        for platform, data in platforms.items():
            if data.get('exists'):
                status = f"{Fore.GREEN}✓ ENCONTRADO{Style.RESET_ALL}"
                url = data.get('url', 'N/A')
                print(f"{platform:12} {status} | URL: {url}")
            else:
                status = f"{Fore.RED}✗ NÃO ENCONTRADO{Style.RESET_ALL}"
                print(f"{platform:12} {status}")
        
        print(f"{Fore.GREEN}═" * 60)
    
    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"{Fore.YELLOW}[1] Carregar Wordlist")
            print(f"[2] Gerar Combinações")
            print(f"[3] Escanear Redes Sociais")
            print(f"[4] Salvar Resultados")
            print(f"[5] Sair{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.menu_load_wordlist()
            elif choice == '2':
                self.menu_generate_combinations()
            elif choice == '3':
                self.menu_scan_social_media()
            elif choice == '4':
                self.menu_save_results()
            elif choice == '5':
                print(f"{Fore.GREEN}[+] Saindo...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[ERRO] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def menu_load_wordlist(self):
        """Menu para carregar wordlist"""
        self.clear_screen()
        self.display_banner()
        
        filepath = input(f"{Fore.CYAN}[?] Caminho da wordlist: {Style.RESET_ALL}")
        
        if self.load_wordlist(filepath):
            print(f"{Fore.GREEN}[+] Wordlist carregada com {len(self.wordlist)} palavras{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Palavras: {', '.join(self.wordlist[:5])}{'...' if len(self.wordlist) > 5 else ''}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[ERRO] Falha ao carregar wordlist{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def menu_generate_combinations(self):
        """Menu para gerar combinações"""
        if not self.wordlist:
            print(f"{Fore.RED}[ERRO] Carregue uma wordlist primeiro!{Style.RESET_ALL}")
            self.wait_enter()
            return
        
        self.clear_screen()
        self.display_banner()
        
        try:
            max_comb = int(input(f"{Fore.CYAN}[?] Máximo de combinações (2-3): {Style.RESET_ALL}"))
            if max_comb not in [2, 3]:
                max_comb = 3
        except:
            max_comb = 3
        
        self.generate_combinations(max_comb)
        self.save_combinations()
        
        self.wait_enter()
    
    def menu_scan_social_media(self):
        """Menu para escanear redes sociais"""
        if not self.combinations:
            print(f"{Fore.RED}[ERRO] Gere as combinações primeiro!{Style.RESET_ALL}")
            self.wait_enter()
            return
        
        self.clear_screen()
        self.display_banner()
        
        print(f"{Fore.YELLOW}[!] Iniciando escaneamento em {len(self.combinations)} usuários...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Isso pode levar algum tempo...{Style.RESET_ALL}")
        
        self.results = []
        
        for i, username in enumerate(self.combinations, 1):
            print(f"\n{Fore.CYAN}[{i}/{len(self.combinations)}] Escaneando: {username}{Style.RESET_ALL}")
            
            result = self.scan_social_media(username)
            self.results.append(result)
            self.display_results(result)
            
            # Pequena pausa para não sobrecarregar as APIs
            time.sleep(1)
        
        print(f"{Fore.GREEN}[+] Escaneamento concluído!{Style.RESET_ALL}")
        self.wait_enter()
    
    def menu_save_results(self):
        """Menu para salvar resultados"""
        if not self.results:
            print(f"{Fore.RED}[ERRO] Execute o escaneamento primeiro!{Style.RESET_ALL}")
            self.wait_enter()
            return
        
        filename = input(f"{Fore.CYAN}[?] Nome do arquivo para salvar resultados: {Style.RESET_ALL}")
        if not filename:
            filename = "resultados_osint.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("RESULTADOS OSINT - REDES SOCIAIS\n")
                file.write("=" * 50 + "\n\n")
                
                for result in self.results:
                    file.write(f"Usuário: {result['username']}\n")
                    file.write("-" * 30 + "\n")
                    
                    for platform, data in result.items():
                        if platform != 'username' and data.get('exists'):
                            file.write(f"{platform}: {data.get('url', 'N/A')}\n")
                    
                    file.write("\n")
            
            print(f"{Fore.GREEN}[+] Resultados salvos em: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERRO] Erro ao salvar resultados: {e}{Style.RESET_ALL}")
        
        self.wait_enter()

def main():
    """Função principal"""
    try:
        tool = SocialMediaOSINT()
        tool.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Programa interrompido pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERRO CRÍTICO] {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
