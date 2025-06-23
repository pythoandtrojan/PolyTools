#!/usr/bin/env python3
import requests
import json
import re
import time
from datetime import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor


SOCIAL_APIS = {
    "GitHub": {
        "url": "https://api.github.com/users/{}",
        "type": "api"
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "type": "api"
    },
    "Steam": {
        "url": "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key=YOUR_STEAM_KEY&vanityurl={}",
        "type": "api"
    },
    "Facebook": {
        "url": "https://www.facebook.com/{}",
        "type": "scrape"
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "type": "scrape"
    },
    "Kwai": {
        "url": "https://www.kwai.com/@{}",
        "type": "scrape"
    }
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    print("""
\033[1;36m
 _   _ _____ ___  ___  ___ _____ _   _ ___  ___ _____ 
| | | |_   _/ _ \|  \/  |/  ___| | | |_  ||  ___|  _  |
| |_| | | |/ /_\ \ .  . |\ `--.| |_| | | || |__ | | | |
|  _  | | ||  _  | |\/| | `--. \  _  | | ||  __|| | | |
| | | | | || | | | |  | |/\__/ / | | | | || |___\ \_/ /
\_| |_/ \_/\_| |_\_|  |_/\____/\_| |_/\_/\____/ \___/ 
\033[0m
\033[1;33m
 SocialTraker - Rastreamento de Usuários em Redes Sociais - v2.0
\033[0m
\033[1;35m
 Inclui: GitHub, Reddit, Steam, Facebook, TikTok e Kwai
\033[0m
""")

def is_valid_username(username):
    """Valida o formato do nome de usuário"""
    return bool(re.match(r'^[a-zA-Z0-9_.-]{3,30}$', username))

def verificar_api(api, username):
    """Verifica usuário em APIs que não requerem autenticação"""
    try:
        url = SOCIAL_APIS[api]["url"].format(username)
        response = requests.get(url, headers=HEADERS, timeout=15)
        
        if api == "GitHub":
            if response.status_code == 200:
                data = response.json()
                events_url = f"https://api.github.com/users/{username}/events/public"
                events_response = requests.get(events_url, headers=HEADERS, timeout=15)
                events = events_response.json() if events_response.status_code == 200 else []
                
                return {
                    "exists": True,
                    "created_at": data.get("created_at", "Desconhecido"),
                    "followers": data.get("followers", 0),
                    "repositories": data.get("public_repos", 0),
                    "last_activity": events[0]["created_at"] if events else "Nenhuma atividade recente",
                    "profile_url": data.get("html_url", f"https://github.com/{username}")
                }
        
        elif api == "Reddit":
            if response.status_code == 200:
                data = response.json()
                posts_url = f"https://www.reddit.com/user/{username}/submitted.json"
                posts_response = requests.get(posts_url, headers=HEADERS, timeout=15)
                posts = posts_response.json().get("data", {}).get("children", []) if posts_response.status_code == 200 else []
                
                return {
                    "exists": True,
                    "created_at": datetime.fromtimestamp(data.get("data", {}).get("created_utc", 0)).strftime('%Y-%m-%d'),
                    "karma": data.get("data", {}).get("total_karma", 0),
                    "recent_posts": [post["data"]["title"] for post in posts[:3]],
                    "profile_url": f"https://reddit.com/user/{username}"
                }
        
        elif api == "Steam":
            data = response.json()
            if data.get("response", {}).get("success", 0) == 1:
                return {
                    "exists": True,
                    "profile_url": f"https://steamcommunity.com/id/{username}"
                }
        
        return {"exists": False}
    
    except Exception as e:
        return {"exists": False, "error": str(e)}

def verificar_scraping(api, username):
    """Verifica usuário através de scraping básico"""
    try:
        url = SOCIAL_APIS[api]["url"].format(username)
        response = requests.get(url, headers=HEADERS, timeout=15)
        
        if api == "Facebook":
            if response.status_code == 200:
          
                if re.search(r'content="profile"', response.text) or "fb://profile/" in response.text:
                    return {
                        "exists": True,
                        "profile_url": f"https://www.facebook.com/{username}"
                    }
        
        elif api == "TikTok":
            if response.status_code == 200:
                if f"@{username}" in response.text:
                    return {
                        "exists": True,
                        "profile_url": f"https://www.tiktok.com/@{username}"
                    }
        
        elif api == "Kwai":
            if response.status_code == 200:
                if f"@{username}" in response.text:
                    return {
                        "exists": True,
                        "profile_url": f"https://www.kwai.com/@{username}"
                    }
        
        return {"exists": False}
    
    except Exception as e:
        return {"exists": False, "error": str(e)}

def extrair_emails(texto):
    """Extrai emails de textos/bios"""
    return re.findall(r'[\w\.-]+@[\w\.-]+', texto)

def obter_historico(username):
    """Obtém histórico do usuário em todas as plataformas"""
    if not is_valid_username(username):
        return {"error": "Nome de usuário inválido"}
    
    resultados = {}
    
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}
        
        for api in SOCIAL_APIS:
            if SOCIAL_APIS[api]["type"] == "api":
                futures[executor.submit(verificar_api, api, username)] = api
            else:
                futures[executor.submit(verificar_scraping, api, username)] = api
        
        for future in futures:
            api = futures[future]
            try:
                resultados[api] = future.result()
            except Exception as e:
                resultados[api] = {"exists": False, "error": str(e)}
    
    return resultados

def gerar_relatorio(username, dados):
    """Gera relatório completo dos resultados"""
    limpar_tela()
    banner()
    
    print(f"\n\033[1;35mRELATÓRIO PARA: @{username}\033[0m")
    print("\033[1;34m═" * 60 + "\033[0m")
    
    for rede, info in dados.items():
        if rede == "error":
            print(f"\n\033[1;31m[!] {info}\033[0m")
            continue
            
        status = "\033[1;32mENCONTRADO\033[0m" if info.get("exists") else "\033[1;31mNÃO ENCONTRADO\033[0m"
        print(f"\n\033[1;36m{rede.upper()}:\033[0m {status}")
        
        if info.get("exists"):
            if "created_at" in info:
                print(f"📅 Criado em: {info['created_at']}")
            if "last_activity" in info:
                print(f"🔄 Última atividade: {info['last_activity']}")
            if "followers" in info:
                print(f"👥 Seguidores: {info['followers']}")
            if "repositories" in info:
                print(f"📂 Repositórios públicos: {info['repositories']}")
            if "karma" in info:
                print(f"⭐ Karma: {info['karma']}")
            if "recent_posts" in info:
                print(f"\n📝 Posts recentes:")
                for i, post in enumerate(info['recent_posts'][:3], 1):
                    print(f"  {i}. {post[:60]}...")
            
            print(f"\n🔗 Perfil: {info['profile_url']}")
        
        if "error" in info:
            print(f"\033[1;33m⚠ Aviso: {info['error']}\033[0m")
    
    print("\n\033[1;34m═" * 60 + "\033[0m")
    
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"social_report_{username}_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump({
            "username": username,
            "searched_at": timestamp,
            "results": dados
        }, f, indent=4, ensure_ascii=False)
    
    print(f"\n\033[1;32m[+] Relatório salvo como: {filename}\033[0m")

def main():
    limpar_tela()
    banner()
    
    while True:
        username = input("\n\033[1;32m[?] Digite o nome de usuário para pesquisar: \033[0m").strip()
        if is_valid_username(username):
            break
        print("\033[1;31m[!] Nome de usuário inválido. Use apenas letras, números e ._- (3-30 caracteres)\033[0m")
    
    print("\n\033[1;34m[+] Pesquisando em redes sociais...\033[0m")
    
    dados = obter_historico(username)
    gerar_relatorio(username, dados)
    
    input("\n\033[1;34mPressione Enter para sair...\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[+] Programa encerrado pelo usuário\033[0m")
        sys.exit(0)
