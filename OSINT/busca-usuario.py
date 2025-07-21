#!/usr/bin/env python3
import os
import requests
import time
from colorama import init, Fore, Back, Style

# Inicializar colorama
init(autoreset=True)

# Configurações
PASTA_RESULTADOS = "ErikNet_Results"
os.makedirs(PASTA_RESULTADOS, exist_ok=True)

# Banner ErikNet
BANNER = Fore.CYAN + r"""
███████░██░ ░██░███████░░   ██░     ░██░  ░██░██████░ ██   ██░███████░██████░
░░░██░░ ██░░░██░██  ░░      ██░░    ░██░  ░██░██   ██ ██  ██░ ██░░░░  ██   ██░
  ░██░  ███████░█████░░     ██░     ░██░  ░██░██████░ ████░   █████   ██████░░
  ░██░░ ██   ██░██   ░░     ██░░░░  ░██░░░░██░██  ██░ ██░░██░ ██░░░   ██   ██░░
  ░██░░ ██░░░██░███████░░   ███████ ░████████░██░░░██ ██░░ ██ ███████ ██   ██░
   ░░░  ░░░ ░░░ ░░░░░░░     ░░░░░░░  ░░░░░░░░ ░░   ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
   ░ ░  ░     ░ ░   ░ ░     ░░   ░░  ░░░  ░░░  ░   ░  ░    ░░ ░░    ░░      ░░
  ░  ░             ░   ░    ░   ░    ░  ░   ░  ░    ░       ░  ░   ░       ░ 
""" + Style.RESET_ALL + Fore.YELLOW + """
  made in Brazil Big The god and Erik 16y Linux and termux 
""" + Style.RESET_ALL

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def buscar_perfis(username):
    resultados = {}
    
    # Lista de redes sociais (20 brasileiras + internacionais relevantes)
    sites = {
        # Redes Brasileiras
        "Kwai": {
            "url": f"https://www.kwai.com/@{username}",
            "method": "Web Scraping"
        },
        "TikTok": {
            "url": f"https://www.tiktok.com/@{username}",
            "method": "Web Scraping"
        },
        "Skoob": {
            "url": f"https://www.skoob.com.br/usuario/{username}",
            "method": "Web Scraping"
        },
        "Vivver": {
            "url": f"https://www.vivver.com.br/{username}",
            "method": "Web Scraping"
        },
        "Recanto": {
            "url": f"https://www.recantodasletras.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "UOL": {
            "url": f"https://meu.uol.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Terra": {
            "url": f"https://perfil.terra.com.br/{username}",
            "method": "Web Scraping"
        },
        "iFood": {
            "url": f"https://www.ifood.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "OLX": {
            "url": f"https://www.olx.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Mercado Livre": {
            "url": f"https://www.mercadolivre.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Apontador": {
            "url": f"https://www.apontador.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Bonde": {
            "url": f"https://www.bonde.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "TodaOferta": {
            "url": f"https://www.todaoferta.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Trampos": {
            "url": f"https://www.trampos.co/{username}",
            "method": "Web Scraping"
        },
        "Vagas": {
            "url": f"https://www.vagas.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Catho": {
            "url": f"https://www.catho.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "99freelas": {
            "url": f"https://www.99freelas.com.br/perfil/{username}",
            "method": "Web Scraping"
        },
        "Workana": {
            "url": f"https://www.workana.com/freelancer/{username}",
            "method": "Web Scraping"
        },
        "Behance": {
            "url": f"https://www.behance.net/{username}",
            "method": "API"
        },
        "Dribbble": {
            "url": f"https://dribbble.com/{username}",
            "method": "Web Scraping"
        },
        
        # Redes Internacionais (mantidas por relevância)
        "Instagram": {
            "url": f"https://www.instagram.com/{username}",
            "method": "Web Scraping"
        },
        "Facebook": {
            "url": f"https://www.facebook.com/{username}",
            "method": "Web Scraping"
        },
        "Twitter": {
            "url": f"https://twitter.com/{username}",
            "method": "Web Scraping"
        },
        "GitHub": {
            "url": f"https://api.github.com/users/{username}",
            "method": "API"
        },
        "Reddit": {
            "url": f"https://www.reddit.com/user/{username}",
            "method": "API"
        },
        "YouTube": {
            "url": f"https://www.youtube.com/@{username}",
            "method": "Web Scraping"
        },
        "Twitch": {
            "url": f"https://www.twitch.tv/{username}",
            "method": "API"
        },
        "Pinterest": {
            "url": f"https://www.pinterest.com/{username}",
            "method": "Web Scraping"
        },
        "LinkedIn": {
            "url": f"https://www.linkedin.com/in/{username}",
            "method": "Web Scraping"
        },
        "Telegram": {
            "url": f"https://t.me/{username}",
            "method": "Web Scraping"
        }
    }

    for site, config in sites.items():
        try:
            time.sleep(0.5)  # Delay para evitar bloqueio
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            resposta = requests.head(config["url"], headers=headers, timeout=10, allow_redirects=True)
            
            dados = {
                'exists': resposta.status_code == 200,
                'url': resposta.url if resposta.status_code == 200 else config["url"],
                'method': config["method"]
            }
            
            resultados[site] = dados
            
        except Exception as e:
            resultados[site] = {
                'error': str(e),
                'exists': False,
                'url': config["url"],
                'method': config["method"]
            }
    
    return resultados

def mostrar_resultados_eriknet(dados):
    print("\n" + "═"*60)
    print(Fore.CYAN + " RESULTADOS ERIKNET ".center(60) + Style.RESET_ALL)
    print("═"*60)
    
    for plataforma, info in dados.items():
        print(f"\n▓ {Fore.YELLOW}{plataforma.upper()}{Style.RESET_ALL}")
        
        if 'error' in info:
            print(f"  {Fore.RED}🔴 ERRO: {info['error']}{Style.RESET_ALL}")
        else:
            if info.get('exists'):
                print(f"  {Fore.GREEN}🟢 ENCONTRADO{Style.RESET_ALL}")
                print(f"  {Fore.BLUE}🌐 URL: {info['url']}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}🔴 NÃO ENCONTRADO{Style.RESET_ALL}")
                
            print(f"  {Fore.MAGENTA}⚙️ MÉTODO: {info['method']}{Style.RESET_ALL}")
    
    print("\n" + "═"*60)
    print(f"{Fore.YELLOW}Total de redes verificadas: {len(dados)}{Style.RESET_ALL}")
    print("═"*60)

def menu_principal():
    limpar_tela()
    print(BANNER)
    print(f"\n{Fore.GREEN}[{time.strftime('%d/%m/%Y %H:%M:%S')}]{Style.RESET_ALL}")
    print("\n1. Buscar por nome de usuário")
    print("2. Sair")
    
    try:
        return int(input(f"\n{Fore.YELLOW}Escolha uma opção (1-2): {Style.RESET_ALL}"))
    except:
        return 0

def executar_busca():
    while True:
        opcao = menu_principal()
        
        if opcao == 1:
            username = input(f"\n{Fore.YELLOW}Digite o nome de usuário: {Style.RESET_ALL}").strip()
            if username:
                print(f"\n{Fore.YELLOW}⏳ Buscando por '{username}' em 30 redes sociais...{Style.RESET_ALL}")
                resultados = buscar_perfis(username)
                mostrar_resultados_eriknet(resultados)
            else:
                print(f"{Fore.RED}❌ Por favor, insira um nome de usuário válido!{Style.RESET_ALL}")
                
        elif opcao == 2:
            print(f"\n{Fore.GREEN}Saindo do ErikNet...{Style.RESET_ALL}")
            break
            
        else:
            print(f"\n{Fore.RED}❌ Opção inválida! Tente novamente.{Style.RESET_ALL}")
            time.sleep(1)
            
        input(f"\n{Fore.YELLOW}Pressione Enter para continuar...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        executar_busca()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}ErikNet interrompido pelo usuário!{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}ERRO CRÍTICO: {str(e)}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.GREEN}Obrigado por usar o ErikNet! Segurança sempre.{Style.RESET_ALL}\n")
