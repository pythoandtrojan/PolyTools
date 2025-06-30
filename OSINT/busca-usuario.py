#!/usr/bin/env python3
import os
import requests
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import re

PASTA_RESULTADOS = "ErikNet_Results"
os.makedirs(PASTA_RESULTADOS, exist_ok=True)


class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'


BANNER = colors.BLUE + r"""
███████░██░ ░██░███████░░   ██░     ░██░  ░██░██████░ ██   ██░███████░██████░
░░░██░░ ██░░░██░██  ░░      ██░░    ░██░  ░██░██   ██ ██  ██░ ██░░░░  ██   ██░
  ░██░  ███████░█████░░     ██░     ░██░  ░██░██████░ ████░   █████   ██████░░
  ░██░░ ██   ██░██   ░░     ██░░░░  ░██░░░░██░██  ██░ ██░░██░ ██░░░   ██   ██░░
  ░██░░ ██░░░██░███████░░   ███████ ░████████░██░░░██ ██░░ ██ ███████ ██   ██░
   ░░░  ░░░ ░░░ ░░░░░░░     ░░░░░░░  ░░░░░░░░ ░░   ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
   ░ ░  ░     ░ ░   ░ ░     ░░   ░░  ░░░  ░░░  ░   ░  ░    ░░ ░░    ░░      ░░
  ░  ░             ░   ░    ░   ░    ░  ░   ░  ░    ░       ░  ░   ░       ░ 
""" + colors.END
BANNER += colors.YELLOW + "  made in Brazil by Erik (16y) - Linux and Termux" + colors.END

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def validar_usuario(username):
    """Valida se o nome de usuário é válido"""
    if not username:
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False
    return True

def verificar_site(site, username):
    """Função para verificar um único site com verificações robustas"""
    config = sites[site]
    try:
        url = config["url"].format(username=username)
        resposta = requests.get(
            url,
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=10,
            allow_redirects=False
        )
        
        
        exists = False
        
        if resposta.status_code == 200:
            
            if site == "GitHub":
                exists = 'Não encontrado' not in resposta.text
            elif site == "Twitter":
                exists = 'data-screen-name=' in resposta.text
            elif site == "Instagram":
                exists = '"username":"' + username + '"' in resposta.text
            elif site == "Facebook":
                exists = 'content="https://www.facebook.com/' + username + '"' in resposta.text
            elif site == "YouTube":
                exists = '"channelId":"' in resposta.text
            elif site == "Reddit":
                exists = 'class="_3t5uN8xUmg0TOwRCOGQEcU"' in resposta.text
            elif site == "Pinterest":
                exists = '"profile_url":"/' + username + '"' in resposta.text
            elif site == "Tumblr":
                exists = '<title>' + username + ' | Tumblr</title>' in resposta.text
            elif site == "Flickr":
                exists = '"ownerNsid":"' in resposta.text
            elif site == "Vimeo":
                exists = '"name":"' + username + '"' in resposta.text
            else:
          
                exists = True
        
        dados = {
            'exists': exists,
            'url': url,
            'method': config["method"],
            'categoria': config["categoria"],
            'status_code': resposta.status_code
        }
        
        if exists:
            if site in ["Twitter", "GitHub", "Instagram", "Facebook", "YouTube", "Reddit"]:
                dados['nome_perfil'] = username
        
        return site, dados, None
        
    except requests.exceptions.RequestException as e:
        return site, None, f"Erro de conexão: {str(e)}"
    except Exception as e:
        return site, None, f"Erro inesperado: {str(e)}"

def mostrar_resultado_individual(site, dados, error):
    """Mostra o resultado de um único site"""
    if error:
        print(f"  {colors.RED}🔴 {site}: Erro ({error}){colors.END}")
    elif dados['exists']:
        print(f"  {colors.GREEN}🟢 {site}: Encontrado{colors.END}")
        print(f"     {colors.BLUE}🌐 URL: {dados['url']}{colors.END}")
        if 'nome_perfil' in dados:
            print(f"     {colors.BLUE}👤 Nome: {dados['nome_perfil']}{colors.END}")
    else:
        print(f"  {colors.YELLOW}⚪ {site}: Não encontrado{colors.END}")

def buscar_perfis(username):
    """Busca o usuário em todas as plataformas com threads"""
    if not validar_usuario(username):
        print(f"{colors.RED}Nome de usuário inválido! Use apenas letras, números, pontos, traços e underscores.{colors.END}")
        return None
    
    print(f"\n{colors.BOLD}Busca iniciada para: {username}{colors.END}")
    print(f"{colors.YELLOW}Verificando {len(sites)} plataformas...{colors.END}\n")
    
    resultados = {}
    total_sites = len(sites)
    sites_verificados = 0
    
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(verificar_site, site, username): site 
            for site in sites
        }
        
        for future in as_completed(futures):
            site = futures[future]
            sites_verificados += 1
            try:
                site, dados, error = future.result()
                if dados:
                    resultados[site] = dados
                mostrar_resultado_individual(site, dados, error)
                
            
                progresso = int((sites_verificados / total_sites) * 100)
                sys.stdout.write(f"\r{colors.BLUE}Progresso: {progresso}% ({sites_verificados}/{total_sites}){colors.END}")
                sys.stdout.flush()
                
            except Exception as e:
                print(f"\nErro ao processar {site}: {str(e)}")
    
    print(f"\n\n{colors.GREEN}Busca concluída!{colors.END}")
    return resultados

def resumo_resultados(resultados):
    """Mostra um resumo categorizado dos resultados"""
    if not resultados:
        return
    
    categorias = {}
    for site, dados in resultados.items():
        categoria = dados.get('categoria', 'Outros')
        if categoria not in categorias:
            categorias[categoria] = []
        categorias[categoria].append((site, dados))
    
    print(f"\n{colors.BOLD}═ RESUMO POR CATEGORIA ═{colors.END}")
    
    for categoria, sites in categorias.items():
        encontrados = [s[0] for s in sites if s[1]['exists']]
        nao_encontrados = [s[0] for s in sites if not s[1]['exists']]
        
        print(f"\n{colors.BOLD}▓ {categoria.upper()} ({len(sites)}){colors.END}")
        if encontrados:
            print(f"  {colors.GREEN}🟢 Encontrados ({len(encontrados)}):{colors.END}")
            print("   ", ", ".join(encontrados))
        if nao_encontrados:
            print(f"  {colors.YELLOW}⚪ Não encontrados ({len(nao_encontrados)}):{colors.END}")
            print("   ", ", ".join(nao_encontrados))

def salvar_resultados(username, resultados):
    """Salva os resultados em um arquivo JSON"""
    if not resultados:
        return
    
    nome_arquivo = f"eriknet_results_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    caminho_arquivo = os.path.join(PASTA_RESULTADOS, nome_arquivo)
    
    with open(caminho_arquivo, 'w', encoding='utf-8') as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)
    
    print(f"\n{colors.BLUE}Resultados salvos em: {caminho_arquivo}{colors.END}")

def menu_principal():
    limpar_tela()
    print(BANNER)
    print(f"\n[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}]")
    print(f"\n{colors.BOLD}1. Buscar por nome de usuário")
    print(f"2. Sair{colors.END}")
    
    try:
        return int(input("\nEscolha uma opção (1-2): "))
    except:
        return 0


sites = {
    
    "GitHub": {
        "url": "https://github.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Twitter": {
        "url": "https://twitter.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Facebook": {
        "url": "https://www.facebook.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Tumblr": {
        "url": "https://{username}.tumblr.com",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Vimeo": {
        "url": "https://vimeo.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "DeviantArt": {
        "url": "https://{username}.deviantart.com",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "500px": {
        "url": "https://500px.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "VK": {
        "url": "https://vk.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    "Goodreads": {
        "url": "https://www.goodreads.com/{username}",
        "method": "Web Scraping",
        "categoria": "redes sociais"
    },
    
    
    "YouTube": {
        "url": "https://www.youtube.com/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "DailyMotion": {
        "url": "https://www.dailymotion.com/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "Rumble": {
        "url": "https://rumble.com/user/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "Odysee": {
        "url": "https://odysee.com/@{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "PeerTube": {
        "url": "https://peertube.tv/accounts/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "Bitchute": {
        "url": "https://www.bitchute.com/channel/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "LiveLeak": {
        "url": "https://www.liveleak.com/c/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    "Metacafe": {
        "url": "https://www.metacafe.com/channels/{username}",
        "method": "Web Scraping",
        "categoria": "vídeo"
    },
    
    
    "Quora": {
        "url": "https://www.quora.com/profile/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Slashdot": {
        "url": "https://slashdot.org/~{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Discourse": {
        "url": "https://discourse.org/u/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Instructables": {
        "url": "https://www.instructables.com/member/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Hackaday": {
        "url": "https://hackaday.io/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "CodeProject": {
        "url": "https://www.codeproject.com/script/Membership/View.aspx?mid={username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "GeeksforGeeks": {
        "url": "https://auth.geeksforgeeks.org/user/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "LeetCode": {
        "url": "https://leetcode.com/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "CodePen": {
        "url": "https://codepen.io/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "Codecademy": {
        "url": "https://www.codecademy.com/profiles/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    "FreeCodeCamp": {
        "url": "https://www.freecodecamp.org/{username}",
        "method": "Web Scraping",
        "categoria": "fóruns"
    },
    
  
    "WordPress": {
        "url": "https://{username}.wordpress.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Blogger": {
        "url": "https://{username}.blogspot.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Tumblr": {
        "url": "https://{username}.tumblr.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "LiveJournal": {
        "url": "https://{username}.livejournal.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Weebly": {
        "url": "https://{username}.weebly.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Ghost": {
        "url": "https://{username}.ghost.io",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Substack": {
        "url": "https://{username}.substack.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Wix": {
        "url": "https://{username}.wixsite.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Squarespace": {
        "url": "https://{username}.squarespace.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    "Joomla": {
        "url": "https://{username}.joomla.com",
        "method": "Web Scraping",
        "categoria": "blogs"
    },
    
    # Programação e Desenvolvimento (15)
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "SourceForge": {
        "url": "https://sourceforge.net/u/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "npm": {
        "url": "https://www.npmjs.com/~{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "PyPI": {
        "url": "https://pypi.org/user/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "NuGet": {
        "url": "https://www.nuget.org/profiles/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Packagist": {
        "url": "https://packagist.org/users/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "RubyGems": {
        "url": "https://rubygems.org/profiles/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Crates.io": {
        "url": "https://crates.io/users/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Launchpad": {
        "url": "https://launchpad.net/~{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "CPAN": {
        "url": "https://metacpan.org/author/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Puppet Forge": {
        "url": "https://forge.puppet.com/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "Ansible Galaxy": {
        "url": "https://galaxy.ansible.com/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    "OpenHub": {
        "url": "https://www.openhub.net/accounts/{username}",
        "method": "Web Scraping",
        "categoria": "programação"
    },
    
    
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Adobe Portfolio": {
        "url": "https://{username}.myportfolio.com",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "ArtStation": {
        "url": "https://www.artstation.com/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "DeviantArt": {
        "url": "https://{username}.deviantart.com",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Pixiv": {
        "url": "https://www.pixiv.net/en/users/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Sketchfab": {
        "url": "https://sketchfab.com/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Canva": {
        "url": "https://www.canva.com/{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "Figma": {
        "url": "https://figma.com/@{username}",
        "method": "Web Scraping",
        "categoria": "design"
    },
    "InVision": {
        "url": "https://{username}.invisionapp.com",
        "method": "Web Scraping",
        "categoria": "design"
    },
    
    
    "AngelList": {
        "url": "https://angel.co/u/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Crunchbase": {
        "url": "https://www.crunchbase.com/person/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Upwork": {
        "url": "https://www.upwork.com/freelancers/~{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Fiverr": {
        "url": "https://www.fiverr.com/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Freelancer": {
        "url": "https://www.freelancer.com/u/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Toptal": {
        "url": "https://www.toptal.com/resume/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Guru": {
        "url": "https://www.guru.com/freelancers/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "PeoplePerHour": {
        "url": "https://www.peopleperhour.com/freelancer/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "99designs": {
        "url": "https://99designs.com/profiles/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    "Dribbble Hire": {
        "url": "https://dribbble.com/{username}",
        "method": "Web Scraping",
        "categoria": "negócios"
    },
    
    
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "About.me": {
        "url": "https://about.me/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "HubPages": {
        "url": "https://hubpages.com/@{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Wikipedia": {
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Wikia": {
        "url": "https://community.fandom.com/wiki/User:{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Slideshare": {
        "url": "https://www.slideshare.net/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "SpeakerDeck": {
        "url": "https://speakerdeck.com/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Issuu": {
        "url": "https://issuu.com/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Scribd": {
        "url": "https://www.scribd.com/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    },
    "Pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "method": "Web Scraping",
        "categoria": "outros"
    }
}

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == 1:
                username = input("\nDigite o nome de usuário: ").strip()
                resultados = buscar_perfis(username)
                
                if resultados:
                    resumo_resultados(resultados)
                    salvar_resultados(username, resultados)
                
            elif opcao == 2:
                print(f"\n{colors.GREEN}Saindo do ErikNet...{colors.END}")
                break
                
            else:
                print(f"\n{colors.RED}Opção inválida! Tente novamente.{colors.END}")
                time.sleep(1)
            
            input(f"\n{colors.BLUE}Pressione Enter para continuar...{colors.END}")
    
    except KeyboardInterrupt:
        print(f"\n\n{colors.RED}ErikNet interrompido pelo usuário!{colors.END}")
    except Exception as e:
        print(f"\n{colors.RED}ERRO CRÍTICO: {str(e)}{colors.END}")
    finally:
        print(f"\n{colors.BOLD}Obrigado por usar o ErikNet!{colors.END}\n")

if __name__ == "__main__":
    main()
