#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import re
import time
import subprocess
import logging
import random
import hashlib # Para Gravatar
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from tqdm import tqdm # Para barra de progresso

# Inicializa colorama para cores no terminal
init(autoreset=True)

# Configura o sistema de logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)]) # Envia logs para stdout

# Configurações globais
class Config:
    PASTA_RESULTADOS = "ErikNet_Resultados"
    TEMPO_LIMITE_REQUISICAO = 15 # Tempo limite em segundos para requisições HTTP
    # Lista de User-Agents comuns para rotação
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/103.0.1264.71",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Android 12; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
        "Mozilla/5.0 (Linux; Android 10; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36 ErikNet/5.0",
    ]
    MAX_TRABALHADORES = 20 # Número máximo de threads para buscas paralelas (ajuste conforme seu hardware/conexão)
    
    # Configurações de Proxy - defina estas como variáveis de ambiente!
    # Exemplo (no terminal):
    # export HTTP_PROXY="http://user:password@host:port"
    # export HTTPS_PROXY="https://user:password@host:port"
    # export SOCKS_PROXY="socks5://127.0.0.1:9050" (para TOR, por exemplo)
    
    PROXIES: Optional[Dict[str, str]] = {}
    if os.getenv('HTTP_PROXY'):
        PROXIES['http'] = os.getenv('HTTP_PROXY')
    if os.getenv('HTTPS_PROXY'):
        PROXIES['https'] = os.getenv('HTTPS_PROXY')
    # Se SOCKS_PROXY estiver definido, ele sobrescreve http/https para direcionar todo o tráfego
    if os.getenv('SOCKS_PROXY'):
        PROXIES['http'] = os.getenv('SOCKS_PROXY')
        PROXIES['https'] = os.getenv('SOCKS_PROXY')
    
    # Cria a pasta de resultados se não existir
    os.makedirs(PASTA_RESULTADOS, exist_ok=True)

# Banner ErikNet
BANNER = r"""
███████░██░ ░██░███████░░    ██░     ░██░ ░ ██░ ██████░ ██    ██░███████░██████░
░░░██░░ ██░░░██░██  ░░       ██░░    ░██░ ░ ██░ ██  ░██ ██  ██░  ██░░░░  ██  ░██░
  ░██░  ███████░█████░░      ██░     ░██░ ░ █░  ███████░████░    █████   ██████░░
  ░██░░ ██  ░██░██  ░░       ██░░░░  ░██░░░░██░ ██  ██░ ██░░██░  ██░░░   ██  ░██░░
  ░██░░ ██░░░██░███████░░    ███████ ░████████░ ██░░░██ ██░░ ██  ███████ ██  ░██░
    ░░░ ░░░ ░░░ ░░░░░░░      ░░░░░░░  ░░░░░░░░ ░░  ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
    ░ ░ ░     ░ ░  ░ ░      ░░  ░░  ░░░  ░░░  ░  ░  ░  ░░ ░░  ░    ░░    ░░
  ░ ░           ░  ░    ░  ░    ░  ░ ░    ░  ░    ░     ░  ░    ░  ░
  Feito no Brasil por Big The God e Erik (16 anos, Linux e Termux)  
"""

def limpar_tela():
    """Limpa a tela do terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')

def obter_user_agent_aleatorio() -> str:
    """Retorna uma string de User-Agent aleatória da lista predefinida."""
    return random.choice(Config.USER_AGENTS)

def executar_holehe(email: str) -> Dict[str, Any]:
    """
    Executa a ferramenta Holehe para verificar a existência de um e-mail
    em diversas plataformas (requer holehe instalado).
    Retorna um dicionário padronizado com os resultados.
    """
    logging.info(f"{Fore.BLUE}\nExecutando Holehe para verificação de e-mail: {email}...{Style.RESET_ALL}")
    dados_resultado = {'saida_bruta': None, 'erro': None}
    try:
        processo = subprocess.run(['holehe', email], capture_output=True, text=True, timeout=120)
        dados_resultado['saida_bruta'] = processo.stdout
        
        if processo.returncode == 0:
            logging.info(f"{Fore.GREEN}\nResultados do Holehe:\n{Style.RESET_ALL}{processo.stdout}")
            
            nome_arquivo = f"holehe_resultados_{email.replace('@', '_').replace('.', '_')}.txt"
            caminho_arquivo = os.path.join(Config.PASTA_RESULTADOS, nome_arquivo)
            
            with open(caminho_arquivo, 'w', encoding='utf-8') as f:
                f.write(processo.stdout)
            
            logging.info(f"{Fore.GREEN}Resultados do Holehe salvos em: {caminho_arquivo}{Style.RESET_ALL}")
            return {'existe': True, 'metodo': 'Ferramenta Externa (Holehe)', 'url': 'N/A', 'dados': dados_resultado}
        else:
            dados_resultado['erro'] = processo.stderr
            logging.error(f"{Fore.RED}\nErro ao executar Holehe:\n{Style.RESET_ALL}{processo.stderr}")
            return {'existe': False, 'metodo': 'Ferramenta Externa (Holehe)', 'url': 'N/A', 'dados': dados_resultado, 'erro': dados_resultado['erro']}
    except FileNotFoundError:
        msg_erro = "Holehe não está instalado. Por favor, instale com: 'pip install holehe'"
        logging.error(f"{Fore.RED}\n{msg_erro}{Style.RESET_ALL}")
        dados_resultado['erro'] = msg_erro
        return {'existe': False, 'metodo': 'Ferramenta Externa (Holehe)', 'url': 'N/A', 'dados': dados_resultado, 'erro': dados_resultado['erro']}
    except Timeout:
        msg_erro = f"Holehe atingiu o tempo limite para {email}."
        logging.error(f"{Fore.RED}\nErro: {msg_erro}{Style.RESET_ALL}")
        dados_resultado['erro'] = msg_erro
        return {'existe': False, 'metodo': 'Ferramenta Externa (Holehe)', 'url': 'N/A', 'dados': dados_resultado, 'erro': dados_resultado['erro']}
    except Exception as e:
        msg_erro = f"Erro inesperado ao executar Holehe: {str(e)}"
        logging.error(f"{Fore.RED}\n{msg_erro}{Style.RESET_ALL}")
        dados_resultado['erro'] = msg_erro
        return {'existe': False, 'metodo': 'Ferramenta Externa (Holehe)', 'url': 'N/A', 'dados': dados_resultado, 'erro': dados_resultado['erro']}

def verificar_gmail_heuristica(email: str) -> Dict[str, Any]:
    """
    Tenta verificar a existência de uma conta Gmail através de heurísticas.
    AVISO: Esta é uma verificação NÃO OFICIAL e instável.
    Pode resultar em falsos positivos/negativos, estar sujeita a mudanças pelo Google, ou levar a bloqueios.
    """
    logging.info(f"{Fore.BLUE}Verificando Gmail (heurística não oficial) para {email}...{Style.RESET_ALL}")
    sessao = requests.Session()
    headers = {
        "User-Agent": obter_user_agent_aleatorio(),
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    
    # Garante que os proxies sejam usados se configurados
    sessao.proxies = Config.PROXIES if Config.PROXIES else {}

    try:
        # Tentativa 1: Verificação de cookie GX no endpoint gxlu
        resposta1 = sessao.head(
            "https://mail.google.com/mail/gxlu",
            params={"email": email},
            timeout=Config.TEMPO_LIMITE_REQUISICAO,
            headers=headers
        )
        
        # Tentativa 2: Set-cookie na resposta GET de gxlu
        resposta2 = sessao.get(
            f"https://mail.google.com/mail/gxlu?email={email}",
            headers=headers,
            timeout=Config.TEMPO_LIMITE_REQUISICAO
        )
        
        # Tentativa 3: Disponibilidade de nome de utilizador no signup (endpoint JSON)
        # Nota: Este endpoint é mais propenso a ser bloqueado ou mudar.
        status_signup_disponibilidade = 'N/A'
        try:
            # Para este endpoint específico, o Google pode esperar apenas a parte do nome de utilizador
            parte_nome_usuario = email.split('@')[0]
            headers_signup = {
                "Content-Type": "application/json", 
                "User-Agent": obter_user_agent_aleatorio(),
                "Referer": "https://accounts.google.com/signup" # Adiciona Referer para realismo
            }
            resposta3 = sessao.post(
                "https://accounts.google.com/_/signup/usernameavailability",
                headers=headers_signup,
                json={"input_01": {"input": parte_nome_usuario, "first_name": "", "last_name": ""}},
                params={"hl": "pt-BR"},
                timeout=Config.TEMPO_LIMITE_REQUISICAO
            )
            # Se 'valid' for False, significa que o nome de usuário JÁ ESTÁ em uso (ou seja, existe)
            status_signup_disponibilidade = resposta3.json().get("input_01", {}).get("valid") is False if resposta3.status_code == 200 else 'N/A'
        except (RequestException, Timeout, json.JSONDecodeError) as e:
            logging.debug(f"Falha na tentativa 3 de verificação Gmail para {email}: {e}")
            status_signup_disponibilidade = 'Erro'

        existe = any([
            bool(resposta1.cookies.get("GX")),
            "set-cookie" in resposta2.headers,
            status_signup_disponibilidade is True
        ])

        return {'existe': existe, 'metodo': 'Heurística Gmail', 'url': f"mailto:{email}", 'detalhes': {
            'cookie_gx_detectado': bool(resposta1.cookies.get("GX")),
            'header_set_cookie_detectado': "set-cookie" in resposta2.headers,
            'username_indisponivel_signup': status_signup_disponibilidade
        }}
    except Timeout:
        logging.warning(f"{Fore.YELLOW}Tempo limite na verificação do Gmail para {email}.{Style.RESET_ALL}")
        return {'existe': False, 'metodo': 'Heurística Gmail', 'url': f"mailto:{email}", 'erro': 'Tempo limite da requisição'}
    except RequestException as e:
        logging.warning(f"{Fore.YELLOW}Erro de requisição na verificação do Gmail para {email}: {str(e)}{Style.RESET_ALL}")
        return {'existe': False, 'metodo': 'Heurística Gmail', 'url': f"mailto:{email}", 'erro': f'Erro de requisição: {e}'}
    except Exception as e:
        logging.error(f"{Fore.RED}Erro inesperado na verificação do Gmail para {email}: {str(e)}{Style.RESET_ALL}")
        return {'existe': False, 'metodo': 'Heurística Gmail', 'url': f"mailto:{email}", 'erro': f'Erro inesperado: {e}'}


def buscar_perfis(username: str) -> Dict[str, Any]:
    """
    Busca perfis de utilizador em uma vasta lista de redes sociais e plataformas
    verificando URLs de perfil comuns.
    """
    resultados: Dict[str, Any] = {}
    
    # Dicionário de sites a serem verificados.
    # 'url': URL do perfil, com '{username}' como placeholder.
    # 'metodo': Método de verificação ('Web Scraping', 'API Pública', 'Checagem de Status').
    # 'texto_nao_encontrado': (Opcional) Lista de textos em minúsculas que indicam que o perfil NÃO existe,
    #                   mesmo se o status HTTP for 200 (útil para perfis "não encontrados" com 200 OK).
    # 'campo_json_nome': (Opcional) Caminho para o campo com o nome real em uma resposta JSON (e.g., 'data.name').
    # 'nota': (Opcional) Nota sobre a dificuldade ou limitações da verificação.
    
    # Para o Gravatar, verificamos se o username de entrada é um e-mail válido,
    # pois o Gravatar usa hashes de e-mails.
    is_username_email = re.match(r"[^@]+@[^@]+\.[^@]+", username)
    gravatar_url = f"https://gravatar.com/{hashlib.md5(username.lower().encode('utf-8')).hexdigest()}?d=404" if is_username_email else "N/A"

    sites = {
        # --- Redes Sociais Populares ---
        "Facebook": {"url": "https://www.facebook.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["página não encontrada", "content_owner_id", "não está disponível", "page not found", "error 404"]},
        "Instagram": {"url": "https://www.instagram.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["esta página não está disponível", "page not found", "não foi possível encontrar esta página"]},
        "Twitter/X": {"url": "https://twitter.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["esta conta não existe", "essa conta não existe", "account suspended"]},
        "TikTok": {"url": "https://www.tiktok.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["couldn't find this account", "this account is private"]},
        "Kwai": {"url": "https://www.kwai.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["não existe", "not exist"]},
        "LinkedIn": {"url": "https://www.linkedin.com/in/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["this page doesn't exist", "página não existe"]},
        "Reddit": {"url": "https://www.reddit.com/user/{username}/about.json", "metodo": "API Pública", "campo_json_nome": "data.name", "texto_nao_encontrado": ['{"message": "not found", "error": 404}', "page not found"]},
        "Pinterest": {"url": "https://www.pinterest.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["não podemos encontrar esta página", "page not found"]},
        "Snapchat (Story)": {"url": "https://story.snapchat.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "Mastodon (Exemplo .social)": {"url": "https://mastodon.social/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found", "the page you were looking for doesn't exist"]},
        "Tumblr": {"url": "https://{username}.tumblr.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["whatever you were looking for doesn't exist", "there's nothing here", "404 not found"]},
        "Flickr": {"url": "https://www.flickr.com/people/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found", "page not found"]},
        "Imgur": {"url": "https://imgur.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found", "page not found"]},
        "DeviantArt": {"url": "https://www.deviantart.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "error 404"]},
        "Weibo (Não direto por URL)": {"url": "N/A", "metodo": "API não pública direta", "nota": "Altamente restrito para buscas externas. Requer acesso à API oficial."},
        "VK (Não direto por URL)": {"url": "N/A", "metodo": "API não pública direta", "nota": "Altamente restrito para buscas externas. Requer acesso à API oficial."},
        "Telegram (Canal/Usuário Público)": {"url": "https://t.me/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["channel not found", "user not found"]},
        "WhatsApp (wa.me)": {"url": "N/A", "metodo": "Verificação via Link", "nota": "Requer número de telefone, não nome de usuário. Verificação instável e não oficial."},
        "OnlyFans": {"url": "https://onlyfans.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "oops! we can’t find this page", "404"]},
        
        # --- Plataformas de Vídeo ---
        "YouTube (Canal)": {"url": "https://www.youtube.com/@{username}/about", "metodo": "Web Scraping", "texto_nao_encontrado": ["este canal não existe", "this channel does not exist"]},
        "Twitch": {"url": "https://www.twitch.tv/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["não existe", "page not found"]},
        "Vimeo": {"url": "https://vimeo.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["página não encontrada", "page not found"]},
        "Dailymotion": {"url": "https://www.dailymotion.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Bilibili": {"url": "https://space.bilibili.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["404"]},
        
        # --- Plataformas de Música/Áudio ---
        "SoundCloud": {"url": "https://soundcloud.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["this soundcloud is not available", "page not found"]},
        "Spotify (Usuário)": {"url": "https://open.spotify.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Bandcamp": {"url": "https://{username}.bandcamp.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["no results found", "page not found"]},
        "Last.fm": {"url": "https://www.last.fm/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Mixcloud": {"url": "https://www.mixcloud.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "ReverbNation": {"url": "https://www.reverbnation.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        
        # --- Plataformas de Desenvolvimento/Tecnologia ---
        "GitHub": {"url": "https://api.github.com/users/{username}", "metodo": "API Pública", "campo_json_nome": "name", "texto_nao_encontrado": ['{"message": "not found"', "page not found"]},
        "GitLab": {"url": "https://gitlab.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "não encontrado"]},
        "Bitbucket": {"url": "https://bitbucket.org/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "CodePen": {"url": "https://codepen.io/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Repl.it": {"url": "https://replit.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["404: not found"]},
        "HackerRank": {"url": "https://www.hackerrank.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "LeetCode": {"url": "https://leetcode.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "StackOverflow": {"url": "https://stackoverflow.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "SourceForge": {"url": "https://sourceforge.net/u/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["no user found"]},
        "Dev.to": {"url": "https://dev.to/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Hashnode": {"url": "https://hashnode.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Codeforces": {"url": "https://codeforces.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "AtCoder": {"url": "https://atcoder.jp/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "Keybase": {"url": "https://keybase.io/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Codecademy": {"url": "https://www.codecademy.com/profiles/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "FreeCodeCamp": {"url": "https://www.freecodecamp.org/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "not found"], "nota": "URL pode exigir formato de ID específico."},
        "Hackster.io": {"url": "https://www.hackster.io/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Visual Studio Marketplace (Extensões)": {"url": "https://marketplace.visualstudio.com/items?itemName={username}", "metodo": "Web Scraping (para extensões)", "texto_nao_encontrado": ["page not found"], "nota": "Primário para extensões, não usuários."},
        
        # --- Arte e Design ---
        "Dribbble": {"url": "https://dribbble.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Behance": {"url": "https://www.behance.net/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "ArtStation": {"url": "https://www.artstation.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "500px": {"url": "https://500px.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Unsplash": {"url": "https://unsplash.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Pixabay": {"url": "https://pixabay.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Giphy": {"url": "https://giphy.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},

        # --- Blogs e Conteúdo ---
        "Medium": {"url": "https://medium.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Blogger": {"url": "https://{username}.blogspot.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["não existe", "not exist"]},
        "WordPress.com": {"url": "https://{username}.wordpress.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["doesn't exist"]},
        "Substack": {"url": "https://{username}.substack.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["this page doesn't exist"]},
        "Quora": {"url": "https://www.quora.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "LiveJournal": {"url": "https://{username}.livejournal.com", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "Goodreads": {"url": "https://www.goodreads.com/user/show/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Wattpad": {"url": "https://www.wattpad.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "Issuu": {"url": "https://issuu.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Scribd": {"url": "https://www.scribd.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},

        # --- Fóruns e Comunidades ---
        "Fandom (Wikia)": {"url": "https://community.fandom.com/wiki/User:{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["não existe", "page not found"]},
        "Indie Hackers": {"url": "https://www.indiehackers.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Product Hunt": {"url": "https://www.producthunt.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "StackExchange": {"url": "https://stackexchange.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "Brave Community": {"url": "https://community.brave.com/u/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page doesn’t exist or is private.", "not found"]},
        "Lastpass Community": {"url": "https://community.lastpass.com/t5/user/viewprofilepage/user-id/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "Productivity Hunters": {"url": "https://productivity.stackexchange.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        
        # --- Plataformas de Jogos ---
        "Steam (Perfil Personalizado)": {"url": "https://steamcommunity.com/id/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["no profile could be retrieved", "page not found"]},
        "Steam (ID Numérico)": {"url": "https://steamcommunity.com/profiles/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["no profile could be retrieved", "page not found"], "nota": "Requer um SteamID64 numérico."},
        "Itch.io": {"url": "https://{username}.itch.io", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Chess.com": {"url": "https://www.chess.com/member/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["player not found"]},
        "Lichess": {"url": "https://lichess.org/@/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Xbox Live (Busca Gamertag)": {"url": "N/A", "metodo": "API não pública", "nota": "Requer API oficial ou simulação complexa para Gamertag."},
        "PlayStation Network (Busca ID)": {"url": "N/A", "metodo": "API não pública", "nota": "Requer API oficial ou simulação complexa para PSN ID."},
        "Nintendo Network (Busca ID)": {"url": "N/A", "metodo": "API não pública", "nota": "Requer API oficial ou simulação complexa para Nintendo ID."},
        "Epic Games": {"url": "https://www.epicgames.com/account/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]}, # Improvável que funcione via URL simples
        "Kick.com": {"url": "https://kick.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        
        # --- Livros ---
        "Skoob (BR)": {"url": "https://www.skoob.com.br/usuario/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["usuário não encontrado"]},

        # --- Viagens/Localização ---
        "Foursquare": {"url": "https://foursquare.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "TripAdvisor": {"url": "https://www.tripadvisor.com/Profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Airbnb (Não direto por URL)": {"url": "N/A", "metodo": "API não pública", "nota": "Perfis de usuários não são publicamente acessíveis via URL direta."},
        "Zillow": {"url": "https://www.zillow.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Yelp": {"url": "https://www.yelp.com/user_details?userid={username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Houzz": {"url": "https://www.houzz.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Geocaching": {"url": "https://www.geocaching.com/profile/?guid={username}", "metodo": "Web Scraping (Requer ID, não nome de usuário)", "nota": "Esta URL espera um GUID, não um nome de usuário simples."},

        # --- Crowdfunding/Apoio ---
        "Kickstarter": {"url": "https://www.kickstarter.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Patreon": {"url": "https://www.patreon.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Ko-fi": {"url": "https://ko-fi.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},

        # --- Educação/Aprendizado ---
        "Duolingo": {"url": "https://www.duolingo.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        
        # --- Negócios/Profissional ---
        "Crunchbase": {"url": "https://www.crunchbase.com/person/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "cannot find person"]},
        "AngelList": {"url": "https://angel.co/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Xing": {"url": "https://www.xing.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        
        # --- Várias Outras Plataformas ---
        "About.me": {"url": "https://about.me/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Linktree": {"url": "https://linktr.ee/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "CalmlyWriter": {"url": "https://calmlywriter.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "GitBook": {"url": "https://app.gitbook.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "OpenSea": {"url": "https://opensea.io/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Etsy": {"url": "https://www.etsy.com/shop/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "eBay": {"url": "https://www.ebay.com/usr/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["member not found", "page not found"]},
        "Google Sites": {"url": "https://sites.google.com/view/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "Canva": {"url": "https://www.canva.com/p/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Gravatar": {"url": gravatar_url, "metodo": "Checagem de Status (via hash de email)", "texto_nao_encontrado": ["page not found"], "nota": "Só funciona se o nome de usuário for um endereço de e-mail válido."},
        "MyFitnessPal": {"url": "https://www.myfitnesspal.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["profile not found"]},
        "Runkeeper": {"url": "https://runkeeper.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Strava": {"url": "https://www.strava.com/athletes/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Untappd": {"url": "https://untappd.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "Vivino": {"url": "https://www.vivino.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Zhihu": {"url": "https://www.zhihu.com/people/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "404"]},
        "ResearchGate": {"url": "https://www.researchgate.net/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["profile not found"]},
        "academia.edu": {"url": "https://{username}.academia.edu/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Smule": {"url": "https://www.smule.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Taringa!": {"url": "https://www.taringa.net/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "TradingView": {"url": "https://www.tradingview.com/u/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Truecaller": {"url": "https://www.truecaller.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Poshmark": {"url": "https://poshmark.com/closet/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Depop": {"url": "https://www.depop.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Discogs": {"url": "https://www.discogs.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Etsy (Loja)": {"url": "https://www.etsy.com/shop/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "FanFiction.net": {"url": "https://www.fanfiction.net/u/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["story not found"], "nota": "URLs de perfil de usuário são geralmente por ID, não nome de usuário."},
        "Fandom (Usuário Geral)": {"url": "https://www.fandom.com/f/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "GameJolt": {"url": "https://gamejolt.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Genius": {"url": "https://genius.com/artists/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Principalmente para artistas/bandas, não todos os usuários."},
        "IFTTT": {"url": "https://ifttt.com/p/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Indiegogo": {"url": "https://www.indiegogo.com/individuals/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Kaggle": {"url": "https://www.kaggle.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Libera.Chat (IRC Nick)": {"url": "N/A", "metodo": "IRC/Comunidade (Sem URL direta)", "nota": "Rede IRC, sem perfis de usuário públicos via web."},
        "ManyVids": {"url": "https://www.manyvids.com/Profile/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Medium (Tag)": {"url": "https://medium.com/tag/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para tags, não usuários."},
        "NPM (Autor do Pacote)": {"url": "https://www.npmjs.com/~{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["not found"]},
        "OpenCollective": {"url": "https://opencollective.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "PeerTube (Exemplo .fr)": {"url": "https://framatube.org/accounts/username", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Descentralizado, depende da instância."},
        "Pexels (Foto)": {"url": "https://www.pexels.com/photo/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para fotos, não usuários."},
        "Picsart": {"url": "https://picsart.com/u/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Pikabu": {"url": "https://pikabu.ru/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Post.news": {"url": "https://www.post.news/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Quizlet": {"url": "https://quizlet.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Revolut (Comunidade)": {"url": "https://community.revolut.com/u/{username}/summary", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Sketchfab (Download)": {"url": "https://sketchfab.com/models/{username}/download", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para modelos, não usuários."},
        "Slant": {"url": "https://www.slant.co/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Smash.gg (Usuário)": {"url": "https://smash.gg/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Splice": {"url": "https://splice.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "StackBlitz": {"url": "https://stackblitz.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Taringa! (Comunidade)": {"url": "https://www.taringa.net/comunidades/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para comunidades, não usuários."},
        "TensorFlow (Comunidade)": {"url": "https://community.tensorflow.org/u/{username}/summary", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "TheSpruce": {"url": "https://www.thespruce.com/search?q={username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["no results found"], "nota": "Busca, não perfil."},
        "Trello (Perfil Público)": {"url": "https://trello.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Apenas se o perfil público estiver ativado."},
        "Udemy": {"url": "https://www.udemy.com/user/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para instrutores, não todos os usuários."},
        "Unsplash (Foto)": {"url": "https://unsplash.com/photos/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para fotos, não usuários."},
        "Upwork": {"url": "https://www.upwork.com/freelancers/~{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para freelancers, requer prefixo ~."},
        "Vero (Criador)": {"url": "https://vero.co/app/creator/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Webflow": {"url": "https://webflow.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Write.as": {"url": "https://write.as/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Youpic": {"url": "https://youpic.com/photographer/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Zuiker.com": {"url": "https://zuiker.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        # Mais plataformas específicas/de nicho
        "Keybase (Git)": {"url": "https://keybase.io/{username}/git", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para repositórios Git do Keybase."},
        "MySpace (Arquivado)": {"url": "https://myspace.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Maioria arquivada, perfis públicos limitados."},
        "SlideShare (Usuário)": {"url": "https://www.slideshare.net/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Speaker Deck": {"url": "https://speakerdeck.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Telegram (Chat em Grupo - Nome de Usuário)": {"url": "https://t.me/joinchat/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para links de chat em grupo, não perfis de usuário."},
        "Fiverr (Comprador)": {"url": "https://www.fiverr.com/buyers/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Improvável que funcione sem ID específico."},
        "Imgur (Álbum)": {"url": "https://imgur.com/a/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para álbuns, não usuários."},
        "LiveJournal (Comunidade)": {"url": "https://{username}.livejournal.com/community/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para comunidades, não usuários."},
        "Patreon (Post)": {"url": "https://www.patreon.com/posts/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para posts, não usuários."},
        "Redbubble (Coleção)": {"url": "https://www.redbubble.com/people/{username}/collections", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para coleções, não usuários."},
        "Steam (Grupos)": {"url": "https://steamcommunity.com/groups/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para grupos, não usuários."},
        "Twitch (VOD)": {"url": "https://www.twitch.tv/{username}/videos", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para VODs, não verificação de perfil de usuário geral."},
        "YouTube (Legado do Usuário)": {"url": "https://www.youtube.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["this channel does not exist"], "nota": "URLs de usuário legadas, a maioria migrou para @username."},
        "Bluesky (Perfil)": {"url": "https://bsky.app/profile/{username}.bsky.social", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "not found"], "nota": "Assume domínio bsky.social padrão."},
        "Carrd.co": {"url": "https://{username}.carrd.co/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Dribbble (Jogador)": {"url": "https://dribbble.com/players/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Etsy (Padrão)": {"url": "https://www.etsy.com/pattern/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "FanDuel": {"url": "https://www.fanduel.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Flipboard": {"url": "https://flipboard.com/@{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Goodreads (Grupo)": {"url": "https://www.goodreads.com/group/show/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Hey.com (World)": {"url": "https://world.hey.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Kaggle (Conjunto de Dados)": {"url": "https://www.kaggle.com/datasets/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para conjuntos de dados, não usuários."},
        "Plex.tv": {"url": "https://app.plex.tv/desktop/#!/settings/account/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Requer sessão autenticada."},
        "Redbubble (Coleção)": {"url": "https://www.redbubble.com/people/{username}/collections", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para coleções, não usuários."},
        "Resumake.ai": {"url": "https://resumake.ai/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para currículos gerados, não perfis gerais."},
        "Roblox": {"url": "https://www.roblox.com/users/{username}/profile", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Requer ID de usuário numérico."},
        "Snapchat (Perfis Públicos)": {"url": "https://www.snapchat.com/add/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Steamgifts": {"url": "https://www.steamgifts.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Strava (Atividade)": {"url": "https://www.strava.com/athletes/{username}/activity", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para atividades, não perfil principal."},
        "Toptal": {"url": "https://www.toptal.com/remote/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para freelancers Toptal."},
        "Transfermarkt": {"url": "https://www.transfermarkt.com/profil/spieler/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para jogadores de futebol, não usuários gerais."},
        "WeHeartIt": {"url": "https://weheartit.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Wikipedia (Página de Discussão do Usuário)": {"url": "https://pt.wikipedia.org/wiki/Usuário_Discussão:{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["não existe", "page not found"]},
        "Zomato": {"url": "https://www.zomato.com/users/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "App Store (Desenvolvedor)": {"url": "N/A", "metodo": "Web Scraping (Requer ID)", "texto_nao_encontrado": ["not found"], "nota": "Requer ID de Desenvolvedor, não nome de usuário."},
        "Google Play Store (Desenvolvedor)": {"url": "N/A", "metodo": "Web Scraping (Requer ID)", "texto_nao_encontrado": ["not found"], "nota": "Requer ID de Desenvolvedor, não nome de usuário."},
        "Microsoft Store (Desenvolvedor)": {"url": "N/A", "metodo": "Web Scraping (Requer ID)", "texto_nao_encontrado": ["not found"], "nota": "Requer ID de Desenvolvedor, não nome de usuário."},
        "Crunchyroll": {"url": "https://www.crunchyroll.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["user not found"]},
        "MyAnimeList": {"url": "https://myanimelist.net/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Smogon": {"url": "https://www.smogon.com/forums/members/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "URL exata pode requerer ID numérico após o username."},
        "TV Time": {"url": "https://www.tvtime.com/user/{username}/profile", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Goodreads (Livro)": {"url": "https://www.goodreads.com/book/show/{username}", "metodo": "Web Scraping (se username for ID do livro)", "texto_nao_encontrado": ["page not found"], "nota": "Para livros, não usuários, a menos que o nome de usuário seja um ID de livro."},
        "TheMovieDatabase (TMDB)": {"url": "https://www.themoviedb.org/person/{username}", "metodo": "Web Scraping (se username for ID da pessoa)", "texto_nao_encontrado": ["page not found"], "nota": "Para pessoas/filmes, não usuários gerais, a menos que o nome de usuário seja um ID de pessoa."},
        "Letterboxd (Usuário)": {"url": "https://letterboxd.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Vsco": {"url": "https://vsco.co/{username}/gallery", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Ello": {"url": "https://ello.co/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Diaspora* (Exemplo .com)": {"url": "https://diasp.org/u/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Gab": {"url": "https://gab.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found", "account not found"]},
        "Parler": {"url": "https://parler.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]}, # Site tem sido instável
        "Minds": {"url": "https://www.minds.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "MeWe": {"url": "https://mewe.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Ok.ru": {"url": "https://ok.ru/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "LiveLeak (Arquivos)": {"url": "N/A", "metodo": "Arquivos", "nota": "LiveLeak está offline. Pesquisar em arquivos se necessário."},
        "Bitchute": {"url": "https://www.bitchute.com/channel/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["channel not found"]},
        "DLive": {"url": "https://dlive.tv/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "BrandMe": {"url": "https://brand.me/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Classmates.com": {"url": "N/A", "metodo": "Web Scraping (Requer Login)", "texto_nao_encontrado": ["page not found"], "nota": "Requer login para a maioria do conteúdo."},
        "Codeigniter": {"url": "N/A", "metodo": "Web Scraping", "texto_nao_encontrado": ["invalid user id"], "nota": "Requer ID de usuário numérico."},
        "Coroflot": {"url": "https://www.coroflot.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Craigslist (Usuário)": {"url": "N/A", "metodo": "Web Scraping", "texto_nao_encontrado": ["no results"], "nota": "Requer localização (ex: sfbay). Não é um perfil de usuário direto."},
        "Dating.com": {"url": "N/A", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Requer ID direto, provavelmente bloqueado."},
        "DeviantArt (Grupos)": {"url": "https://www.deviantart.com/users/profile/groups/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para grupos, não perfis de usuário individuais diretamente."},
        "Disqus": {"url": "https://disqus.com/by/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Doomworld": {"url": "https://www.doomworld.com/profile/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Dribbble (Time)": {"url": "https://dribbble.com/teams/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para times, não usuários individuais."},
        "Etsy (Time)": {"url": "https://www.etsy.com/teams/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para times, não usuários individuais."},
        "FanGraphs": {"url": "https://www.fangraphs.com/players/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para jogadores de beisebol, não usuários gerais."},
        "Foodspotting": {"url": "https://www.foodspotting.com/places/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para locais, não usuários."},
        "GameFAQs": {"url": "https://gamefaqs.gamespot.com/community/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Habbo (Usuário)": {"url": "https://www.habbo.com/profile/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Instructables": {"url": "https://www.instructables.com/member/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "LibriVox": {"url": "https://librivox.org/author/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para autores, não usuários gerais."},
        "NationStates": {"url": "https://www.nationstates.net/nation={username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "OpenHub": {"url": "https://www.openhub.net/accounts/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Player.me": {"url": "https://player.me/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "ProtonMail (Blog)": {"url": "https://proton.me/blog/author/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para autores de blog."},
        "Reverb (Usuário)": {"url": "https://reverb.com/shop/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Roblox (Perfil - Busca por Nome de Usuário)": {"url": "N/A", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Busca de nome de usuário direta não confiável."},
        "RuneScape": {"url": "https://apps.runescape.com/runemetrics/profile/profile?user={username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["no profile found"]},
        "Sketchfab": {"url": "https://sketchfab.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Spreaker": {"url": "https://www.spreaker.com/user/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "Talenthouse": {"url": "https://www.talenthouse.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "TheFork": {"url": "https://www.thefork.com/restaurant/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"], "nota": "Para restaurantes, não usuários."},
        "Wikimapia": {"url": "http://wikimapia.org/user/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
        "YouNow": {"url": "https://www.younow.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["page not found"]},
    }

    sessao = requests.Session()
    # Garante que os proxies sejam usados para a sessão
    if Config.PROXIES:
        sessao.proxies = Config.PROXIES

    lista_futuros = []
    for nome_site, config_site in sites.items():
        if config_site["url"] == "N/A":
            resultados[nome_site] = {'existe': False, 'url': config_site['url'], 'metodo': config_site['metodo'], 'nota': config_site.get('nota', 'Não verificável via URL direta.')}
        else:
            lista_futuros.append(executor.submit(_verificar_perfil_unico, sessao, username, nome_site, config_site))
    
    # Usa tqdm para uma barra de progresso
    for futuro in tqdm(as_completed(lista_futuros), total=len(lista_futuros), desc=f"{Fore.GREEN}Verificando perfis para {username}{Style.RESET_ALL}", unit="site"):
        nome_site_debug = ""
        try:
            resultado = futuro.result()
            nome_site_debug = resultado.get('nome_site_debug') # Obtém o nome do site para usar como chave
            if 'nome_site_debug' in resultado:
                del resultado['nome_site_debug'] # Remove o campo de depuração
            resultados[nome_site_debug if nome_site_debug else "Desconhecido"] = resultado
        except Exception as e:
            logging.error(f"{Fore.RED}Erro inesperado ao coletar resultado do futuro para {nome_site_debug}: {e}{Style.RESET_ALL}")
            if nome_site_debug:
                resultados[nome_site_debug] = {'erro': str(e), 'existe': False, 'url': sites.get(nome_site_debug, {}).get('url', 'N/A')}
            else:
                 resultados["Erro Desconhecido"] = {'erro': str(e), 'existe': False, 'url': 'N/A'}
    
    return resultados

def _verificar_perfil_unico(sessao: requests.Session, username: str, nome_site: str, config: Dict) -> Dict[str, Any]:
    """Função auxiliar para verificar um único perfil de forma segura."""
    time.sleep(0.1) # Pequena pausa para evitar rate limiting (ajuste se necessário)
    
    # Adiciona o nome do site para depuração em caso de erro no future.result()
    template_resultado = {
        'existe': False,
        'url': config["url"].format(username=username),
        'metodo': config["metodo"],
        'nome_perfil_encontrado': username, # Valor padrão, será atualizado se encontrado
        'status_http': 'N/A',
        'erro': None,
        'nome_site_debug': nome_site # Para depuração no as_completed
    }

    url = template_resultado['url']
    
    # Prepara cabeçalhos personalizados para cada requisição
    headers = {
        'User-Agent': obter_user_agent_aleatorio(),
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': url # Referer pode ser auto-referencial ou um site popular genérico
    }
    # Adiciona referers específicos se necessário para certos sites
    if nome_site == "Instagram":
        headers['Referer'] = "https://www.instagram.com/"
    elif nome_site == "Twitter/X":
        headers['Referer'] = "https://twitter.com/"

    logging.debug(f"Verificando {nome_site}: {url}")
    try:
        resposta = sessao.get( # Usa o objeto de sessão
            url,
            headers=headers,
            timeout=Config.TEMPO_LIMITE_REQUISICAO,
            allow_redirects=True # Seguir redirecionamentos é importante para perfis
        )
        
        template_resultado['status_http'] = resposta.status_code
        
        existe = False

        # Verifica se o status code é 200 OK e não contém texto de "não encontrado"
        if resposta.status_code == 200:
            if config.get("texto_nao_encontrado"):
                conteudo_minusculo = resposta.text.lower()
                e_nao_encontrado_por_texto = False
                for texto in config["texto_nao_encontrado"]:
                    if texto.lower() in conteudo_minusculo:
                        e_nao_encontrado_por_texto = True
                        break
                if not e_nao_encontrado_por_texto:
                    existe = True
            else: # Se não há texto_nao_encontrado, 200 OK implica existência
                existe = True
        elif resposta.status_code == 404: # 404 é um bom indicador de não existência
            existe = False
        # Para outros códigos (e.g., 403 Forbidden, 500 Internal Server Error),
        # assumimos não existência para a finalidade da busca, mas logamos o erro.
        else:
            logging.warning(f"{Fore.YELLOW}Resposta inesperada para {nome_site} ({url}): Status {resposta.status_code}{Style.RESET_ALL}")
            template_resultado['erro'] = f"Status HTTP inesperado: {resposta.status_code}"
            existe = False

        template_resultado['existe'] = existe

        # Tenta extrair nome do perfil para APIs JSON ou web scraping simples (se existe for True)
        if existe and resposta.status_code == 200:
            if config.get("campo_json_nome"):
                try:
                    dados_json = resposta.json()
                    campos = config["campo_json_nome"].split('.')
                    valor = dados_json
                    for campo in campos:
                        if isinstance(valor, dict):
                            valor = valor.get(campo)
                        else: # Se o caminho não é um dicionário, o campo não existe
                            valor = None
                            break
                    if valor and not isinstance(valor, dict) and not isinstance(valor, list):
                        template_resultado['nome_perfil_encontrado'] = valor
                except json.JSONDecodeError:
                    logging.debug(f"Não foi possível decodificar JSON para {nome_site}. Ignorando extração de nome via JSON.")
                except Exception as e:
                    logging.debug(f"Erro ao extrair JSON para {nome_site}: {e}")
            
            # Adicional para sites onde o nome de utilizador é diretamente visível e significa existência
            elif nome_site in ["Twitter/X", "Telegram (Canal/Usuário Público)"] and existe:
                template_resultado['nome_perfil_encontrado'] = username # Assume o nome de usuário da busca

        return template_resultado
    except Timeout:
        logging.warning(f"{Fore.YELLOW}Tempo limite ao verificar {nome_site} ({url}).{Style.RESET_ALL}")
        template_resultado['erro'] = 'Tempo limite da requisição'
        template_resultado['existe'] = False
        return template_resultado
    except (RequestException, ConnectionError) as e:
        logging.warning(f"{Fore.YELLOW}Erro de requisição ao verificar {nome_site} ({url}): {str(e)}{Style.RESET_ALL}")
        template_resultado['erro'] = f'Erro de conexão/requisição: {e}'
        template_resultado['existe'] = False
        return template_resultado
    except Exception as e:
        logging.error(f"{Fore.RED}Erro inesperado ao verificar {nome_site} ({url}): {str(e)}{Style.RESET_ALL}")
        template_resultado['erro'] = f'Erro inesperado: {e}'
        template_resultado['existe'] = False
        return template_resultado

def exibir_resultados_eriknet(dados: Dict[str, Any], titulo: str) -> None:
    """Apresenta os resultados da busca de forma formatada."""
    limpar_tela() # Limpa a tela antes de mostrar os resultados
    print(BANNER) # Reexibe o banner
    print(f"\n{Fore.CYAN}═"*80 + Style.RESET_ALL)
    print(f"{Fore.CYAN} {titulo.upper()} RESULTADOS ".center(80) + Style.RESET_ALL)
    print(f"{Fore.CYAN}═"*80 + Style.RESET_ALL)
    
    contador_encontrados = 0
    total_verificados = 0
    
    # Garante uma ordem consistente (alfabética por plataforma)
    for plataforma in sorted(dados.keys()):
        info = dados[plataforma]
        
        # Lida com erros gerais da thread
        if 'erro' in info and info['erro'] is not None:
            print(f"\n{Fore.RED}▓ {plataforma.upper()}{Style.RESET_ALL}")
            print(f"  🔴 ERRO: {info['erro']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            if info.get('status_http') != 'N/A':
                 print(f"  STATUS HTTP: {info['status_http']}")
        # Lida com plataformas que possuem notas (ex: requer ID numérico)
        elif 'nota' in info:
            total_verificados += 1
            print(f"\n{Fore.YELLOW}▓ {plataforma.upper()}{Style.RESET_ALL}")
            print(f"  🟡 NOTA: {info['nota']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            print(f"  ⚙️ MÉTODO: {info.get('metodo', 'N/A')}")
        # Tratamento especial para Holehe
        elif plataforma == "Holehe Status":
            total_verificados += 1
            cor_status = Fore.GREEN if info.get('existe') else Fore.RED
            texto_status = "SUCESSO" if info.get('existe') else "FALHA"
            print(f"\n{cor_status}▓ HOLEHE (VERIFICAÇÃO DE E-MAIL){Style.RESET_ALL}")
            print(f"  {cor_status}STATUS: {texto_status}{Style.RESET_ALL}")
            if info.get('dados') and info['dados'].get('saida_bruta'):
                # Exibe o início da saída bruta, limitando para não poluir
                print(f"  SAÍDA BRUTA (parcial): {info['dados']['saida_bruta'][:200]}...") 
            elif info.get('erro'):
                print(f"  ERRO: {info['erro']}")
        # Lida com verificações de perfil regulares
        else:
            total_verificados += 1
            cor_status = Fore.RED
            texto_status = "NÃO ENCONTRADO"
            
            if info.get('existe'):
                contador_encontrados += 1
                cor_status = Fore.GREEN
                texto_status = "ENCONTRADO"
            
            print(f"\n{cor_status}▓ {plataforma.upper()}{Style.RESET_ALL}")
            print(f"  {cor_status}STATUS: {texto_status}{Style.RESET_ALL}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            
            # Exibe nome_perfil_encontrado se for diferente do username de busca
            # Ou se o username_encontrado for explicitamente definido e diferente do username da URL
            username_url_part = info.get('url', '').split('/')[-1].replace('@', '').lower() # Última parte da URL
            if info.get('url') and len(info.get('url').split('/')) > 2 and info.get('url').split('/')[-2]: # Penúltima parte
                 username_url_part = info.get('url').split('/')[-2].replace('@', '').lower()

            if info.get('nome_perfil_encontrado') and str(info['nome_perfil_encontrado']).lower() != username.lower():
                print(f"  📛 NOME/USUÁRIO ENCONTRADO: {info['nome_perfil_encontrado']}")
            elif info.get('nome_perfil_encontrado'): # Se for o mesmo username da busca, apenas confirma
                print(f"  📛 USUÁRIO: {info['nome_perfil_encontrado']}")
            
            print(f"  ⚙️ MÉTODO: {info.get('metodo', 'N/A')}")
            if info.get('status_http') != 'N/A':
                 print(f"  STATUS HTTP: {info['status_http']}")

            # Detalhes específicos para a heurística do Gmail
            if plataforma == "Gmail (Verificação Heurística)" and info.get('detalhes'):
                print(f"  DETALHES (Heurística):")
                print(f"    - Cookie GX detectado: {info['detalhes'].get('cookie_gx_detectado')}")
                print(f"    - Header Set-Cookie detectado: {info['detalhes'].get('header_set_cookie_detectado')}")
                print(f"    - Username indisponível no signup: {info['detalhes'].get('username_indisponivel_signup')}")

    print(f"\n{Fore.CYAN}═"*80 + Style.RESET_ALL)
    print(f"{Fore.CYAN} RESUMO: {contador_encontrados} de {total_verificados} plataformas com perfil encontrado ".center(80) + Style.RESET_ALL)
    print(f"{Fore.CYAN}═"*80 + Style.RESET_ALL)

def exportar_para_json(dados: Dict[str, Any], prefixo_arquivo: str) -> None:
    """Exporta os resultados de uma busca para um arquivo JSON."""
    timestamp = int(time.time())
    nome_arquivo = f"eriknet_resultados_{prefixo_arquivo}_{timestamp}.json"
    caminho_arquivo = os.path.join(Config.PASTA_RESULTADOS, nome_arquivo)
    
    try:
        with open(caminho_arquivo, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=4, ensure_ascii=False)
        logging.info(f"{Fore.GREEN}✅ Resultados exportados para: {caminho_arquivo}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"{Fore.RED}❌ Erro ao exportar resultados para JSON: {str(e)}{Style.RESET_ALL}")

def menu_principal() -> int:
    """Exibe o menu principal e obtém a escolha do utilizador."""
    limpar_tela()
    print(BANNER)
    print(f"\n[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}]")
    print(f"\n{Fore.LIGHTCYAN_EX}MENU PRINCIPAL:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Buscar por nome de usuário ({len(sites)} plataformas){Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. Buscar por e-mail (com Holehe e Verificação Gmail){Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. Exportar últimos resultados para JSON{Style.RESET_ALL}")
    print(f"{Fore.CYAN}4. Sair{Style.RESET_ALL}")
    
    try:
        escolha = input(f"\n{Fore.CYAN}Escolha uma opção (1-4): {Style.RESET_ALL}").strip()
        return int(escolha)
    except ValueError:
        return 0 # Opção inválida

def executar_eriknet():
    """Loop principal de execução do ErikNet."""
    ultimos_resultados: Optional[Dict[str, Any]] = None
    ultimo_prefixo_arquivo: Optional[str] = None
    
    # Define o executor de threads uma vez para o loop
    with ThreadPoolExecutor(max_workers=Config.MAX_TRABALHADORES) as executor:
        while True:
            opcao = menu_principal()
            
            if opcao == 1:
                username = input(f"\n{Fore.YELLOW}Digite o nome de usuário (min. 2 caracteres, sem espaços): {Style.RESET_ALL}").strip()
                # Validação robusta de nome de usuário
                if not username or len(username) < 2 or re.search(r'\s', username) or not re.match(r"^[a-zA-Z0-9_-]+$", username):
                    logging.warning(f"{Fore.YELLOW}Nome de usuário inválido! Não pode ser vazio, deve ter no mínimo 2 caracteres, sem espaços e apenas letras, números, '-' ou '_'.{Style.RESET_ALL}")
                    time.sleep(2)
                    continue
                
                logging.info(f"\n{Fore.BLUE}🔍 Buscando em mais de 100 plataformas para: {username}...{Style.RESET_ALL}")
                ultimos_resultados = buscar_perfis(username) # Passa o executor para a função
                ultimo_prefixo_arquivo = f"usuario_{username}"
                exibir_resultados_eriknet(ultimos_resultados, f"Busca por Usuário: {username}")
                
            elif opcao == 2:
                email = input(f"\n{Fore.YELLOW}Digite o e-mail: {Style.RESET_ALL}").strip().lower()
                # Validação robusta de e-mail
                if not email or not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                    logging.warning(f"{Fore.YELLOW}Formato de e-mail inválido ou vazio!{Style.RESET_ALL}")
                    time.sleep(2)
                    continue

                nome_usuario_do_email = email.split('@')[0]
                
                logging.info(f"\n{Fore.BLUE}🔍 Iniciando busca por e-mail: {email}...{Style.RESET_ALL}")

                resultados_combinados = {}

                # Executa Holehe
                resultado_holehe_dict = executar_holehe(email)
                resultados_combinados["Holehe Status"] = resultado_holehe_dict
                
                # Verificação adicional do Gmail
                resultado_verificacao_gmail = verificar_gmail_heuristica(email)
                resultados_combinados["Gmail (Verificação Heurística)"] = resultado_verificacao_gmail
                
                # Busca por perfis sociais usando nome de usuário derivado do e-mail
                logging.info(f"\n{Fore.BLUE}🔍 Buscando perfis sociais para o usuário derivado do e-mail: {nome_usuario_do_email}...{Style.RESET_ALL}")
                resultados_perfis_sociais = buscar_perfis(nome_usuario_do_email) # Passa o executor
                resultados_combinados.update(resultados_perfis_sociais) # Adiciona os resultados da busca por perfil
                
                ultimos_resultados = resultados_combinados
                ultimo_prefixo_arquivo = f"email_{email.replace('@', '_').replace('.', '_')}"
                exibir_resultados_eriknet(ultimos_resultados, f"Busca por E-mail: {email}")
                
            elif opcao == 3: # Exportar resultados
                if ultimos_resultados and ultimo_prefixo_arquivo:
                    exportar_para_json(ultimos_resultados, ultimo_prefixo_arquivo)
                else:
                    logging.warning(f"{Fore.YELLOW}❌ Nenhum resultado disponível para exportar. Realize uma busca primeiro.{Style.RESET_ALL}")
                
            elif opcao == 4: # Sair
                logging.info(f"{Fore.GREEN}\nSaindo do ErikNet...{Style.RESET_ALL}")
                break
                
            else:
                logging.warning(f"{Fore.YELLOW}Opção inválida! Por favor, tente novamente.{Style.RESET_ALL}")
                time.sleep(1)
                
            if opcao != 4: # Não pedir Enter se estiver saindo
                input(f"\n{Fore.CYAN}Pressione Enter para continuar...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        executar_eriknet()
    except KeyboardInterrupt:
        logging.info(f"{Fore.YELLOW}\n\nErikNet interrompido pelo usuário!{Style.RESET_ALL}")
    except Exception as e:
        logging.critical(f"{Fore.RED}\nERRO CRÍTICO INESPERADO: {str(e)}{Style.RESET_ALL}", exc_info=True)
    finally:
        logging.info(f"{Fore.GREEN}\nObrigado por usar o ErikNet! Segurança sempre.\n{Style.RESET_ALL}")

