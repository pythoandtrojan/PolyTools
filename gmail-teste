import os
import requests
from colorama import init, Fore, Back, Style
import time
import json
import re
import threading
from queue import Queue
from bs4 import BeautifulSoup
import random

# Initialize colorama
init(autoreset=True)

# Global variables
CURRENT_EMAIL = ""
BANNER_VISIBLE = True

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    global BANNER_VISIBLE
    if BANNER_VISIBLE:
        banner = f"""
{Fore.CYAN}███████░██░ ░██░███████░░   ██░     ░██░  ░██░██████░ ██   ██░███████░██████░
{Fore.BLUE}░░░██░░ ██░░░██░██  ░░      ██░░    ░██░  ░██░██   ██ ██  ██░ ██░░░░  ██   ██░
{Fore.MAGENTA}  ░██░  ███████░█████░░     ██░     ░██░  ░██░██████░ ████░   █████   ██████░░
{Fore.YELLOW}  ░██░░ ██   ██░██   ░░     ██░░░░  ░██░░░░██░██  ██░ ██░░██░ ██░░░   ██   ██░░
{Fore.GREEN}  ░██░░ ██░░░██░███████░░   ███████ ░████████░██░░░██ ██░░ ██ ███████ ██   ██░
{Fore.RED}   ░░░  ░░░ ░░░ ░░░░░░░     ░░░░░░░  ░░░░░░░░ ░░   ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
{Fore.WHITE}   ░ ░  ░     ░ ░   ░ ░     ░░   ░░  ░░░  ░░░  ░   ░  ░    ░░ ░░    ░░      ░░
{Fore.CYAN}  ░  ░             ░   ░    ░   ░    ░  ░   ░  ░    ░       ░  ░   ░       ░     """
        print(banner)

def get_random_user_agent():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ]
    return random.choice(user_agents)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return re.match(pattern, email) is not None

def make_request(url, method='GET', headers=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            if headers is None:
                headers = {'User-Agent': get_random_user_agent()}
            
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=15,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return None
            time.sleep(2 ** attempt)  # Exponential backoff

# Platform-specific checkers
def check_instagram(username):
    try:
        url = f"https://www.instagram.com/{username}/?__a=1"
        response = make_request(url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                return bool(data.get('graphql', {}).get('user', {}).get('id'))
            except ValueError:
                # Fallback to HTML parsing if JSON fails
                soup = BeautifulSoup(response.text, 'html.parser')
                return bool(soup.find('meta', property='og:description'))
        
        return False
    except:
        return False

def check_twitter(username):
    try:
        # First check via API
        api_url = f"https://twitter.com/i/api/i/users/username_available.json?username={username}"
        response = make_request(api_url)
        
        if response and response.status_code == 200:
            data = response.json()
            if not data.get('valid', True):
                return True
        
        # Fallback to web check
        web_url = f"https://twitter.com/{username}"
        response = make_request(web_url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return not bool(soup.find('div', class_='errorpage'))
        
        return False
    except:
        return False

def check_facebook(username):
    try:
        url = f"https://www.facebook.com/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.find('title')
            if title and title.text.strip() != "Facebook":
                return True
        
        return False
    except:
        return False

def check_youtube(username):
    try:
        url = f"https://www.youtube.com/@{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_tiktok(username):
    try:
        url = f"https://www.tiktok.com/@{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('h1', class_='share-title'))
        
        return False
    except:
        return False

def check_github(username):
    try:
        url = f"https://api.github.com/users/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            data = response.json()
            return bool(data.get('login'))
        
        return False
    except:
        return False

def check_linkedin(username):
    try:
        url = f"https://www.linkedin.com/in/{username}"
        response = make_request(url, headers={'User-Agent': get_random_user_agent(), 'Accept-Language': 'en-US,en;q=0.9'})
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return not bool(soup.find('div', class_='error-container'))
        
        return False
    except:
        return False

def check_reddit(username):
    try:
        url = f"https://www.reddit.com/user/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return not bool(soup.find('div', class_='error-page'))
        
        return False
    except:
        return False

def check_pinterest(username):
    try:
        url = f"https://www.pinterest.com/{username}/"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_twitch(username):
    try:
        url = f"https://www.twitch.tv/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_spotify(username):
    try:
        url = f"https://open.spotify.com/user/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_soundcloud(username):
    try:
        url = f"https://soundcloud.com/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_vimeo(username):
    try:
        url = f"https://vimeo.com/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_medium(username):
    try:
        url = f"https://medium.com/@{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_gitlab(username):
    try:
        url = f"https://gitlab.com/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_snapchat(username):
    try:
        url = f"https://www.snapchat.com/add/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('title') and "Snapchat" in soup.find('title').text)
        
        return False
    except:
        return False

def check_flickr(username):
    try:
        url = f"https://www.flickr.com/people/{username}/"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_tumblr(username):
    try:
        url = f"https://{username}.tumblr.com/"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('meta', property='og:title'))
        
        return False
    except:
        return False

def check_quora(username):
    try:
        url = f"https://www.quora.com/profile/{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return not bool(soup.find('div', class_='error_page'))
        
        return False
    except:
        return False

def check_kwai(username):
    try:
        url = f"https://www.kwai.com/@{username}"
        response = make_request(url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('title') and username in soup.find('title').text)
        
        return False
    except:
        return False

def check_platform(site, email):
    username = email.split('@')[0]
    platform = site['name'].lower()
    
    print(f"{Fore.WHITE}[+] Testing URL: {site['url'].format(email=username)}")
    
    try:
        if platform == 'instagram':
            return check_instagram(username)
        elif platform == 'twitter':
            return check_twitter(username)
        elif platform == 'facebook':
            return check_facebook(username)
        elif platform == 'youtube':
            return check_youtube(username)
        elif platform == 'tiktok':
            return check_tiktok(username)
        elif platform == 'github':
            return check_github(username)
        elif platform == 'linkedin':
            return check_linkedin(username)
        elif platform == 'reddit':
            return check_reddit(username)
        elif platform == 'pinterest':
            return check_pinterest(username)
        elif platform == 'twitch':
            return check_twitch(username)
        elif platform == 'spotify':
            return check_spotify(username)
        elif platform == 'soundcloud':
            return check_soundcloud(username)
        elif platform == 'vimeo':
            return check_vimeo(username)
        elif platform == 'medium':
            return check_medium(username)
        elif platform == 'gitlab':
            return check_gitlab(username)
        elif platform == 'snapchat':
            return check_snapchat(username)
        elif platform == 'flickr':
            return check_flickr(username)
        elif platform == 'tumblr':
            return check_tumblr(username)
        elif platform == 'quora':
            return check_quora(username)
        elif platform == 'kwai':
            return check_kwai(username)
        else:
            # Default check for other platforms
            url = site['url'].format(email=username)
            response = make_request(url)
            
            if response and response.status_code == 200:
                if site.get('validation_text'):
                    return site['validation_text'].lower() in response.text.lower()
                return True
            return False
    except Exception as e:
        print(f"{Fore.RED}Error checking {site['name']}: {str(e)}{Fore.RESET}")
        return False

def worker(site_queue, results, email):
    while not site_queue.empty():
        site = site_queue.get()
        try:
            found = check_platform(site, email)
            results.append({
                'platform': site['name'],
                'url': site['url'].format(email=email.split('@')[0]),
                'found': found,
                'status': 'active' if found else 'not_found'
            })
        except Exception as e:
            print(f"{Fore.RED}Error in {site['name']}: {str(e)}")
        site_queue.task_done()

def check_multiple_sites(email, sites):
    site_queue = Queue()
    results = []
    
    for site in sites:
        site_queue.put(site)
    
    for _ in range(5):  # 5 threads simultaneously
        threading.Thread(target=worker, args=(site_queue, results, email)).start()
    
    site_queue.join()
    return results

def special_verification(email, platform):
    username = email.split('@')[0]
    verificacoes = {
        "Instagram": f"{Fore.BLUE}Verificação especial: Perfil pode ser privado | Checar fotos de perfil | https://www.instagram.com/{username}/",
        "Facebook": f"{Fore.BLUE}Verificação especial: Verificar amigos em comum | Analisar data de criação | https://www.facebook.com/{username}/",
        "Twitter": f"{Fore.BLUE}Verificação especial: Checar tweets recentes | Verificar seguidores | https://twitter.com/{username}/",
        "YouTube": f"{Fore.BLUE}Verificação especial: Analisar vídeos postados | Checar data de inscrição | https://www.youtube.com/@{username}/",
        "TikTok": f"{Fore.BLUE}Verificação especial: Verificar vídeos populares | Analisar bio | https://www.tiktok.com/@{username}/",
        "Kwai": f"{Fore.BLUE}Verificação especial: Checar vídeos postados | Verificar seguidores | https://www.kwai.com/@{username}/",
        "GitHub": f"{Fore.BLUE}Verificação especial: Verificar repositórios | Analisar atividade | https://github.com/{username}/",
        "LinkedIn": f"{Fore.BLUE}Verificação especial: Verificar conexões | Analisar experiência | https://www.linkedin.com/in/{username}/",
        "Reddit": f"{Fore.BLUE}Verificação especial: Analisar posts recentes | Verificar karma | https://www.reddit.com/user/{username}/",
        "Pinterest": f"{Fore.BLUE}Verificação especial: Verificar boards | Analisar pins | https://www.pinterest.com/{username}/",
        "Twitch": f"{Fore.BLUE}Verificação especial: Verificar streams recentes | Analisar seguidores | https://www.twitch.tv/{username}/"
    }
    return verificacoes.get(platform, "")

def save_results(email, results):
    if not os.path.exists('results'):
        os.makedirs('results')
    
    filename = f"results/results_{email.replace('@', '_at_')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n{Fore.GREEN}[+] Resultados salvos em {filename}{Fore.RESET}")

def display_menu():
    global BANNER_VISIBLE
    clear_terminal()
    display_banner()
    
    print(f"\n{Fore.YELLOW}╔════════════════════════ MENU ═══════════════════════╗")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}1. Buscar por email Gmail                     {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}2. Mostrar/Esconder banner                   {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}║ {Fore.CYAN}3. Sair                                      {Fore.YELLOW}║")
    print(f"{Fore.YELLOW}╚══════════════════════════════════════════════════╝{Fore.RESET}")

def main():
    global CURRENT_EMAIL, BANNER_VISIBLE
    
    sites = [
        {"name": "Instagram", "url": "https://www.instagram.com/{email}/", "validation_text": "instagram.com"},
        {"name": "Facebook", "url": "https://www.facebook.com/{email}/", "validation_text": "facebook.com"},
        {"name": "Twitter", "url": "https://twitter.com/{email}/", "validation_text": "twitter.com"},
        {"name": "YouTube", "url": "https://www.youtube.com/@{email}/", "validation_text": "youtube.com"},
        {"name": "TikTok", "url": "https://www.tiktok.com/@{email}/", "validation_text": "tiktok.com"},
        {"name": "Kwai", "url": "https://www.kwai.com/@{email}/", "validation_text": "kwai.com"},
        {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{email}/", "validation_text": "linkedin.com"},
        {"name": "Pinterest", "url": "https://www.pinterest.com/{email}/", "validation_text": "pinterest.com"},
        {"name": "Reddit", "url": "https://www.reddit.com/user/{email}/", "validation_text": "reddit.com"},
        {"name": "Tumblr", "url": "https://{email}.tumblr.com/", "validation_text": "tumblr.com"},
        {"name": "Flickr", "url": "https://www.flickr.com/people/{email}/", "validation_text": "flickr.com"},
        {"name": "Vimeo", "url": "https://vimeo.com/{email}/", "validation_text": "vimeo.com"},
        {"name": "SoundCloud", "url": "https://soundcloud.com/{email}/", "validation_text": "soundcloud.com"},
        {"name": "Spotify", "url": "https://open.spotify.com/user/{email}/", "validation_text": "spotify.com"},
        {"name": "Twitch", "url": "https://www.twitch.tv/{email}/", "validation_text": "twitch.tv"},
        {"name": "GitHub", "url": "https://github.com/{email}/", "validation_text": "github.com"},
        {"name": "GitLab", "url": "https://gitlab.com/{email}/", "validation_text": "gitlab.com"},
        {"name": "Medium", "url": "https://medium.com/@{email}/", "validation_text": "medium.com"},
        {"name": "Quora", "url": "https://www.quora.com/profile/{email}/", "validation_text": "quora.com"},
        {"name": "Snapchat", "url": "https://www.snapchat.com/add/{email}/", "validation_text": "snapchat.com"}
    ]
    
    while True:
        display_menu()
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (1-3): {Fore.RESET}").strip()
        
        if choice == '1':
            email = input(f"\n{Fore.YELLOW}[?] Digite o email do Gmail para pesquisar: {Fore.RESET}").strip().lower()
            
            if not validate_email(email):
                print(f"\n{Fore.RED}[!] Por favor, insira um email do Gmail válido (exemplo@gmail.com){Fore.RESET}")
                time.sleep(2)
                continue
            
            CURRENT_EMAIL = email
            print(f"\n{Fore.CYAN}[*] Iniciando busca avançada por {email}...{Fore.RESET}\n")
            time.sleep(1)
            
            start_time = time.time()
            results = check_multiple_sites(email, sites)
            elapsed_time = time.time() - start_time
            
            found_accounts = sum(1 for result in results if result['found'])
            
            print(f"\n{Fore.CYAN}╔════════════════════════ RESULTADOS ═══════════════════════╗")
            for result in results:
                platform = result['platform']
                status = f"{Fore.GREEN}ENCONTRADO" if result['found'] else f"{Fore.RED}NÃO ENCONTRADO"
                print(f"{Fore.CYAN}║ {Fore.WHITE}{platform.ljust(15)}: {status}{Fore.RESET}")
                
                if result['found']:
                    special = special_verification(email, platform)
                    if special:
                        print(f"{Fore.CYAN}║    {special}{Fore.RESET}")
            
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Contas encontradas: {Fore.YELLOW}{found_accounts}{Fore.WHITE}/{len(sites)}")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Tempo de execução: {Fore.YELLOW}{elapsed_time:.2f} segundos")
            print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════╝{Fore.RESET}")
            
            save = input(f"\n{Fore.YELLOW}[?] Deseja salvar os resultados? (s/n): {Fore.RESET}").lower()
            if save == 's':
                save_results(email, results)
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
        
        elif choice == '2':
            BANNER_VISIBLE = not BANNER_VISIBLE
            print(f"\n{Fore.GREEN}[+] Banner será {'mostrado' if BANNER_VISIBLE else 'escondido'} na próxima atualização.{Fore.RESET}")
            time.sleep(1)
        
        elif choice == '3':
            print(f"\n{Fore.CYAN}[*] Saindo... Obrigado por usar Gmail Social Tracker!{Fore.RESET}")
            time.sleep(1)
            clear_terminal()
            break
        
        else:
            print(f"\n{Fore.RED}[!] Opção inválida. Por favor, escolha 1, 2 ou 3.{Fore.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Programa interrompido pelo usuário.{Fore.RESET}")
        exit(0)
