import os
import requests
from colorama import init, Fore, Back, Style
import time
import json
import re
import whois  # Para verificação de domínios

# Inicializa colorama
init(autoreset=True)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    banner = f"""
███████░██░ ░██░███████░░   ██░     ░██░  ░██░██████░ ██   ██░███████░██████░
░░░██░░ ██░░░██░██  ░░      ██░░    ░██░  ░██░██   ██ ██  ██░ ██░░░░  ██   ██░
  ░██░  ███████░█████░░     ██░     ░██░  ░██░██████░ ████░   █████   ██████░░
  ░██░░ ██   ██░██   ░░     ██░░░░  ░██░░░░██░██  ██░ ██░░██░ ██░░░   ██   ██░░
  ░██░░ ██░░░██░███████░░   ███████ ░████████░██░░░██ ██░░ ██ ███████ ██   ██░
   ░░░  ░░░ ░░░ ░░░░░░░     ░░░░░░░  ░░░░░░░░ ░░   ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
   ░ ░  ░     ░ ░   ░ ░     ░░   ░░  ░░░  ░░░  ░   ░  ░    ░░ ░░    ░░      ░░
  ░  ░             ░   ░    ░   ░    ░  ░   ░  ░    ░       ░  ░   ░       ░     """
    print(banner)

def format_query(name):
    """Formata o nome para URLs (ex: 'João Silva' → 'joao_silva')"""
    formatted = name.lower().replace(" ", "_")
    return formatted

def check_site(site, query):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Verificação em duas etapas
        response = requests.get(site['url'].format(query=query), headers=headers, timeout=15)
        
        if response.status_code == 200:
            # Verificação adicional de conteúdo
            if site.get('validation_text'):
                if site['validation_text'].lower() in response.text.lower():
                    return True
                return False
            return True
        return False
    except Exception as e:
        return False

def check_whois(domain):
    """Verifica informações Whois de um domínio"""
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return None

def special_verification(query, platform):
    verificacoes = {
        "Instagram": f"{Fore.BLUE}Verificação especial: Perfil pode ser privado | Checar fotos",
        "Facebook": f"{Fore.BLUE}Verificação especial: Verificar amigos em comum",
        "Twitter": f"{Fore.BLUE}Verificação especial: Checar tweets recentes",
        "YouTube": f"{Fore.BLUE}Verificação especial: Analisar vídeos postados",
        "TikTok": f"{Fore.BLUE}Verificação especial: Verificar vídeos populares",
        "Whois": f"{Fore.BLUE}Verificação especial: Domínio registrado? Checar data de criação"
    }
    return verificacoes.get(platform, "")

def save_results(name, results):
    filename = f"results_{name.replace(' ', '_')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    print(f"\n{Fore.GREEN}[+] Resultados salvos em {filename}{Fore.RESET}")

def display_menu():
    print(f"\n{Fore.YELLOW}╔════════════════════════ MENU ═══════════════════════╗")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}1. Buscar por nome completo                   {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}2. Verificar domínio (Whois)                 {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}3. Sair                                      {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}╚══════════════════════════════════════════════════╝{Fore.RESET}")

def main():
    clear_terminal()
    display_banner()
    
    while True:
        display_menu()
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (1-3): {Fore.RESET}").strip()
        
        if choice == '1':
            name = input(f"\n{Fore.YELLOW}[?] Digite o nome completo para pesquisar: {Fore.RESET}").strip()
            query = format_query(name)
            
            print(f"\n{Fore.CYAN}[*] Iniciando busca avançada por {name}...{Fore.RESET}\n")
            time.sleep(1)
            
            # Lista de redes sociais (20 sites)
            sites = [
                {"name": "Instagram", "url": "https://www.instagram.com/{query}/", "validation_text": "instagram.com"},
                {"name": "Facebook", "url": "https://www.facebook.com/{query}/", "validation_text": "facebook.com"},
                {"name": "Twitter", "url": "https://twitter.com/{query}/", "validation_text": "twitter.com"},
                {"name": "YouTube", "url": "https://www.youtube.com/user/{query}/", "validation_text": "youtube.com"},
                {"name": "TikTok", "url": "https://www.tiktok.com/@{query}/", "validation_text": "tiktok.com"},
                {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{query}/", "validation_text": "linkedin.com"},
                {"name": "Pinterest", "url": "https://www.pinterest.com/{query}/", "validation_text": "pinterest.com"},
                {"name": "Reddit", "url": "https://www.reddit.com/user/{query}/", "validation_text": "reddit.com"},
                {"name": "Tumblr", "url": "https://{query}.tumblr.com/", "validation_text": "tumblr.com"},
                {"name": "Flickr", "url": "https://www.flickr.com/people/{query}/", "validation_text": "flickr.com"},
                {"name": "Vimeo", "url": "https://vimeo.com/{query}/", "validation_text": "vimeo.com"},
                {"name": "SoundCloud", "url": "https://soundcloud.com/{query}/", "validation_text": "soundcloud.com"},
                {"name": "Spotify", "url": "https://open.spotify.com/user/{query}/", "validation_text": "spotify.com"},
                {"name": "Twitch", "url": "https://www.twitch.tv/{query}/", "validation_text": "twitch.tv"},
                {"name": "GitHub", "url": "https://github.com/{query}/", "validation_text": "github.com"},
                {"name": "GitLab", "url": "https://gitlab.com/{query}/", "validation_text": "gitlab.com"},
                {"name": "Medium", "url": "https://medium.com/@{query}/", "validation_text": "medium.com"},
                {"name": "Quora", "url": "https://www.quora.com/profile/{query}/", "validation_text": "quora.com"},
                {"name": "Snapchat", "url": "https://www.snapchat.com/add/{query}/", "validation_text": "snapchat.com"},
                {"name": "Kwai", "url": "https://www.kwai.com/@{query}/", "validation_text": "kwai.com"}
            ]
            
            results = {"name": name, "accounts": []}
            found_accounts = 0
            
            for site in sites:
                print(f"{Fore.WHITE}[+] Verificando {site['name']}...", end=' ', flush=True)
                
                if check_site(site, query):
                    print(f"{Fore.GREEN}ENCONTRADO{Fore.RESET}")
                    special = special_verification(query, site['name'])
                    if special:
                        print(f"    {special}")
                    results["accounts"].append({
                        "platform": site['name'],
                        "url": site['url'].format(query=query),
                        "found": True
                    })
                    found_accounts += 1
                else:
                    print(f"{Fore.RED}Não encontrado{Fore.RESET}")
                    results["accounts"].append({
                        "platform": site['name'],
                        "url": site['url'].format(query=query),
                        "found": False
                    })
                
                time.sleep(0.7)  # Evitar bloqueio
            
            print(f"\n{Fore.CYAN}[*] Busca concluída! {found_accounts} contas encontradas.{Fore.RESET}")
            
            save = input(f"\n{Fore.YELLOW}[?] Deseja salvar os resultados? (s/n): {Fore.RESET}").lower()
            if save == 's':
                save_results(name, results)
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
            clear_terminal()
        
        elif choice == '2':
            domain = input(f"\n{Fore.YELLOW}[?] Digite o domínio para verificar (Whois): {Fore.RESET}").strip()
            print(f"\n{Fore.CYAN}[*] Verificando Whois de {domain}...{Fore.RESET}")
            
            domain_info = check_whois(domain)
            if domain_info:
                print(f"\n{Fore.GREEN}[+] Whois encontrado para {domain}:{Fore.RESET}")
                print(f"{Fore.YELLOW}Registrante: {domain_info.get('registrant_name', 'N/A')}")
                print(f"Data de criação: {domain_info.get('creation_date', 'N/A')}")
                print(f"Expira em: {domain_info.get('expiration_date', 'N/A')}{Fore.RESET}")
            else:
                print(f"{Fore.RED}[!] Domínio não encontrado ou erro na consulta.{Fore.RESET}")
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
            clear_terminal()
        
        elif choice == '3':
            print(f"\n{Fore.CYAN}[*] Saindo... Obrigado por usar Full Name Social Tracker!{Fore.RESET}")
            time.sleep(1)
            clear_terminal()
            break
        
        else:
            print(f"\n{Fore.RED}[!] Opção inválida. Por favor, escolha 1, 2 ou 3.{Fore.RESET}")
            time.sleep(1)
            clear_terminal()

if __name__ == "__main__":
    main()
