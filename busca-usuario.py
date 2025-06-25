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
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from tqdm import tqdm

# Inicializa colorama para cores no terminal
init(autoreset=True)

# Configura o sistema de logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])

# Configurações globais
class Config:
    PASTA_RESULTADOS = "ErikNet_Resultados"
    TEMPO_LIMITE_REQUISICAO = 15
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
    MAX_TRABALHADORES = 20
    
    PROXIES: Optional[Dict[str, str]] = {}
    if os.getenv('HTTP_PROXY'):
        PROXIES['http'] = os.getenv('HTTP_PROXY')
    if os.getenv('HTTPS_PROXY'):
        PROXIES['https'] = os.getenv('HTTPS_PROXY')
    if os.getenv('SOCKS_PROXY'):
        PROXIES['http'] = os.getenv('SOCKS_PROXY')
        PROXIES['https'] = os.getenv('SOCKS_PROXY')
    
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

# Definir o dicionário de sites globalmente
SITES = {
    "Facebook": {"url": "https://www.facebook.com/{username}", "metodo": "Web Scraping", "texto_nao_encontrado": ["página não encontrada", "content_owner_id", "não está disponível", "page not found", "error 404"]},
    "Instagram": {"url": "https://www.instagram.com/{username}/", "metodo": "Web Scraping", "texto_nao_encontrado": ["esta página não está disponível", "page not found", "não foi possível encontrar esta página"]},
    "WhatsApp": {"url":"https://api.whatsapp.com/send?phone={phone}","metodo":"API/URL","texto_nao_encontrado":["invalid phone number","error"]} },
    "YouTube": {"url":"https://www.youtube.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["This channel does not exist","404"]} },
    "TikTok": {"url":"https://www.tiktok.com/@{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found","Couldn't find this account"]} },
    "Twitter": {"url":"https://x.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["User not found","suspended account"]} },
    "LinkedIn": {"url":"https://www.linkedin.com/in/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found","Profile unavailable"]} },
    "Pinterest": {"url":"https://www.pinterest.com/{username}/","metodo":"Web Scraping","texto_nao_encontrado":["Page not found","We couldn't find that account"]} },
    "Reddit": {"url":"https://www.reddit.com/user/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Sorry, nobody on Reddit goes by that name."]} },
    "Snapchat": {"url":"https://www.snapchat.com/add/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Could not find user"]} },
    "Telegram": {"url":"https://t.me/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Username not found"]} },
    "WeChat": {"url":"https://weixin.qq.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["not available"]} },
    "Tumblr": {"url":"https://{username}.tumblr.com","metodo":"Web Scraping","texto_nao_encontrado":["404 Not Found"]} },
    "Discord": {"url":"https://discord.com/users/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Unknown User"]} },
    "Mastodon": {"url":"https://mastodon.social/@{username}","metodo":"Web Scraping","texto_nao_encontrado":["Not found"]} },
    "Clubhouse": {"url":"https://www.clubhouse.com/@{username}","metodo":"Web Scraping","texto_nao_encontrado":["Profile Not Found"]} },
    "Threads": {"url":"https://www.threads.net/@{username}","metodo":"Web Scraping","texto_nao_encontrado":["Couldn't find this account"]} },
    "Weibo": {"url":"https://weibo.com/u/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["访问被拒绝","未找到页面"]} },
    "VK": {"url":"https://vk.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found"]} },
    "Baidu Tieba": {"url":"https://tieba.baidu.com/home/main?un={username}","metodo":"Web Scraping","texto_nao_encontrado":["贴子不存在"]} },
    "Quora": {"url":"https://www.quora.com/profile/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Discord Server": {"url":"https://discord.gg/{invite}","metodo":"Web Scraping","texto_nao_encontrado":["Invite Invalid"]} },
    "Twitch": {"url":"https://www.twitch.tv/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Sorry. Unless you’ve got a time machine, that content is unavailable."]} },
    "Skype": {"url":"https://join.skype.com/invite/{code}","metodo":"Web Scraping","texto_nao_encontrado":["Something's gone wrong"]} },
    "Medium": {"url":"https://medium.com/@{username}","metodo":"Web Scraping","texto_nao_encontrado":["404 Not Found"]} },
    "XiaoHongShu": {"url":"https://www.xiaohongshu.com/user/profile/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["未找到用户"]} },
    "Douyin": {"url":"https://www.douyin.com/user/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["未找到内容"]} },
    "Kuaishou": {"url":"https://www.kuaishou.com/u/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["该用户不存在"]} },
    "Line": {"url":"https://line.me/R/ti/p/~{username}","metodo":"Web Scraping","texto_nao_encontrado":["User not found"]} },
    "Viber": {"url":"https://vb.me/{username}","metodo":"Web Scraping","texto_nao_encontrado":["User not found"]} },
    "Telegram Channel": {"url":"https://t.me/{channel}","metodo":"Web Scraping","texto_nao_encontrado":["Channel not found"]} },
    "Periscope": {"url":"https://www.pscp.tv/{username}","metodo":"Web Scraping","texto_nao_encontrado":["This account has ended"]} },
    "SoundCloud": {"url":"https://soundcloud.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["We can’t find that account"]} },
    "Bandcamp": {"url":"https://{username}.bandcamp.com","metodo":"Web Scraping","texto_nao_encontrado":["404 Not Found"]} },
    "DeviantArt": {"url":"https://www.deviantart.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Oops! That page can't be found."]} },
    "Flickr": {"url":"https://www.flickr.com/people/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["not found"]} },
    "Mixcloud": {"url":"https://www.mixcloud.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["No such user"]} },
    "Pinterest Business": {"url":"https://business.pinterest.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found"]} },
    "Yelp": {"url":"https://www.yelp.com/user_details?userid={userid}","metodo":"Web Scraping","texto_nao_encontrado":["Not Available"]} },
    "Tripadvisor": {"url":"https://www.tripadvisor.com/members/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Profile Not Found"]} },
    "Goodreads": {"url":"https://www.goodreads.com/user/show/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Slack": {"url":"https://{workspace}.slack.com/team/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["User Not Found"]} },
    "GitHub": {"url":"https://github.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Not Found"]} },
    "Dribbble": {"url":"https://dribbble.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Behance": {"url":"https://www.behance.net/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found"]} },
    "StackOverflow": {"url":"https://stackoverflow.com/users/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "StackExchange": {"url":"https://{site}.stackexchange.com/users/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Amazon": {"url":"https://www.amazon.com/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found","User doesn’t exist"]} },
    "eBay": {"url":"https://www.ebay.com/usr/{username}","metodo":"Web Scraping","texto_nao_encontrado":["User ID Not Found"]} },
    "Walmart": {"url":"https://www.walmart.com/cp/{username}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "AliExpress": {"url":"https://www.aliexpress.com/store/{storeid}","metodo":"Web Scraping","texto_nao_encontrado":["This store does not exist"]} },
    "Etsy": {"url":"https://www.etsy.com/shop/{shopname}","metodo":"Web Scraping","texto_nao_encontrado":["Shop Not Found"]} },
    "BestBuy": {"url":"https://www.bestbuy.com/site/{username}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Target": {"url":"https://www.target.com/shop/{seller}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Newegg": {"url":"https://www.newegg.com/user/{username}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Costco": {"url":"https://www.costco.com/{username}.html","metodo":"Web Scraping","texto_nao_encontrado":["not found"]} },
    "Wayfair": {"url":"https://www.wayfair.com/shops/{shopid}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Shopee": {"url":"https://shopee.com.br/user/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "MercadoLibre": {"url":"https://perfil.mercadolivre.com.br/{nickname}","metodo":"Web Scraping","texto_nao_encontrado":["Usuário inexistente"]} },
    "Temu": {"url":"https://www.temu.com/shop/{shopid}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Ubuy": {"url":"https://www.ubuy.com/store/{storeid}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Zalando": {"url":"https://www.zalando.com/shop/{shop}","metodo":"Web Scraping","texto_nao_encontrado":["Page not found"]} },
    "ASOS": {"url":"https://www.asos.com/{username}","metodo":"Web Scraping","texto_nao_encontrado":["404"]} },
    "Rakuten": {"url":"https://www.rakuten.com/shop/{shopname}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} },
    "Flipkart": {"url":"https://www.flipkart.com/user/profile/{userid}","metodo":"Web Scraping","texto_nao_encontrado":["Page Not Found"]} }
}

def limpar_tela():
    """Limpa a tela do terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')

def obter_user_agent_aleatorio() -> str:
    """Retorna uma string de User-Agent aleatória da lista predefinida."""
    return random.choice(Config.USER_AGENTS)

def executar_holehe(email: str) -> Dict[str, Any]:
    """Executa a ferramenta Holehe para verificar a existência de um e-mail."""
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
    except TimeoutError:
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
    """Tenta verificar a existência de uma conta Gmail através de heurísticas."""
    logging.info(f"{Fore.BLUE}Verificando Gmail (heurística não oficial) para {email}...{Style.RESET_ALL}")
    sessao = requests.Session()
    headers = {
        "User-Agent": obter_user_agent_aleatorio(),
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    
    sessao.proxies = Config.PROXIES if Config.PROXIES else {}

    try:
        resposta1 = sessao.head(
            "https://mail.google.com/mail/gxlu",
            params={"email": email},
            timeout=Config.TEMPO_LIMITE_REQUISICAO,
            headers=headers
        )
        
        resposta2 = sessao.get(
            f"https://mail.google.com/mail/gxlu?email={email}",
            headers=headers,
            timeout=Config.TEMPO_LIMITE_REQUISICAO
        )
        
        status_signup_disponibilidade = 'N/A'
        try:
            parte_nome_usuario = email.split('@')[0]
            headers_signup = {
                "Content-Type": "application/json", 
                "User-Agent": obter_user_agent_aleatorio(),
                "Referer": "https://accounts.google.com/signup"
            }
            resposta3 = sessao.post(
                "https://accounts.google.com/_/signup/usernameavailability",
                headers=headers_signup,
                json={"input_01": {"input": parte_nome_usuario, "first_name": "", "last_name": ""}},
                params={"hl": "pt-BR"},
                timeout=Config.TEMPO_LIMITE_REQUISICAO
            )
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

def buscar_perfis(username: str, executor: ThreadPoolExecutor) -> Dict[str, Any]:
    """Busca perfis de utilizador em uma vasta lista de redes sociais e plataformas."""
    resultados: Dict[str, Any] = {}
    
    is_username_email = re.match(r"[^@]+@[^@]+\.[^@]+", username)
    gravatar_url = f"https://gravatar.com/{hashlib.md5(username.lower().encode('utf-8')).hexdigest()}?d=404" if is_username_email else "N/A"

    # Usar o dicionário global SITES
    sites = SITES.copy()
    sites["Gravatar"] = {"url": gravatar_url, "metodo": "Checagem de Status (via hash de email)", 
                        "texto_nao_encontrado": ["page not found"], 
                        "nota": "Só funciona se o nome de usuário for um endereço de e-mail válido."}

    sessao = requests.Session()
    if Config.PROXIES:
        sessao.proxies = Config.PROXIES

    lista_futuros = []
    for nome_site, config_site in sites.items():
        if config_site["url"] == "N/A":
            resultados[nome_site] = {'existe': False, 'url': config_site['url'], 
                                   'metodo': config_site['metodo'], 
                                   'nota': config_site.get('nota', 'Não verificável via URL direta.')}
        else:
            lista_futuros.append(executor.submit(_verificar_perfil_unico, sessao, username, nome_site, config_site))
    
    for futuro in tqdm(as_completed(lista_futuros), total=len(lista_futuros), 
                      desc=f"{Fore.GREEN}Verificando perfis para {username}{Style.RESET_ALL}", unit="site"):
        try:
            resultado = futuro.result()
            nome_site = resultado.get('nome_site_debug', 'Desconhecido')
            if 'nome_site_debug' in resultado:
                del resultado['nome_site_debug']
            resultados[nome_site] = resultado
        except Exception as e:
            logging.error(f"{Fore.RED}Erro inesperado ao coletar resultado do futuro: {e}{Style.RESET_ALL}")
            resultados["Erro Desconhecido"] = {'erro': str(e), 'existe': False, 'url': 'N/A'}
    
    return resultados

def _verificar_perfil_unico(sessao: requests.Session, username: str, nome_site: str, config: Dict) -> Dict[str, Any]:
    """Função auxiliar para verificar um único perfil de forma segura."""
    time.sleep(0.1)
    
    template_resultado = {
        'existe': False,
        'url': config["url"].format(username=username),
        'metodo': config["metodo"],
        'nome_perfil_encontrado': username,
        'status_http': 'N/A',
        'erro': None,
        'nome_site_debug': nome_site
    }

    url = template_resultado['url']
    
    headers = {
        'User-Agent': obter_user_agent_aleatorio(),
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': url
    }

    try:
        resposta = sessao.get(
            url,
            headers=headers,
            timeout=Config.TEMPO_LIMITE_REQUISICAO,
            allow_redirects=True
        )
        
        template_resultado['status_http'] = resposta.status_code
        existe = False

        if resposta.status_code == 200:
            if config.get("texto_nao_encontrado"):
                conteudo_minusculo = resposta.text.lower()
                e_nao_encontrado_por_texto = any(texto.lower() in conteudo_minusculo 
                                               for texto in config["texto_nao_encontrado"])
                if not e_nao_encontrado_por_texto:
                    existe = True
            else:
                existe = True
        elif resposta.status_code == 404:
            existe = False
        else:
            logging.warning(f"{Fore.YELLOW}Resposta inesperada para {nome_site} ({url}): Status {resposta.status_code}{Style.RESET_ALL}")
            template_resultado['erro'] = f"Status HTTP inesperado: {resposta.status_code}"
            existe = False

        template_resultado['existe'] = existe

        if existe and resposta.status_code == 200:
            if config.get("campo_json_nome"):
                try:
                    dados_json = resposta.json()
                    campos = config["campo_json_nome"].split('.')
                    valor = dados_json
                    for campo in campos:
                        if isinstance(valor, dict):
                            valor = valor.get(campo)
                        else:
                            valor = None
                            break
                    if valor and not isinstance(valor, (dict, list)):
                        template_resultado['nome_perfil_encontrado'] = valor
                except (json.JSONDecodeError, AttributeError) as e:
                    logging.debug(f"Não foi possível decodificar JSON para {nome_site}: {e}")
            
            elif nome_site in ["Twitter/X", "Telegram (Canal/Usuário Público)"] and existe:
                template_resultado['nome_perfil_encontrado'] = username

        return template_resultado
    except Timeout:
        logging.warning(f"{Fore.YELLOW}Tempo limite ao verificar {nome_site} ({url}).{Style.RESET_ALL}")
        template_resultado['erro'] = 'Tempo limite da requisição'
        return template_resultado
    except (RequestException, ConnectionError) as e:
        logging.warning(f"{Fore.YELLOW}Erro de requisição ao verificar {nome_site} ({url}): {str(e)}{Style.RESET_ALL}")
        template_resultado['erro'] = f'Erro de conexão/requisição: {e}'
        return template_resultado
    except Exception as e:
        logging.error(f"{Fore.RED}Erro inesperado ao verificar {nome_site} ({url}): {str(e)}{Style.RESET_ALL}")
        template_resultado['erro'] = f'Erro inesperado: {e}'
        return template_resultado

def exibir_resultados_eriknet(dados: Dict[str, Any], titulo: str) -> None:
    """Apresenta os resultados da busca de forma formatada."""
    limpar_tela()
    print(BANNER)
    print(f"\n{Fore.CYAN}═"*80 + Style.RESET_ALL)
    print(f"{Fore.CYAN} {titulo.upper()} RESULTADOS ".center(80) + Style.RESET_ALL)
    print(f"{Fore.CYAN}═"*80 + Style.RESET_ALL)
    
    contador_encontrados = 0
    total_verificados = 0
    
    for plataforma in sorted(dados.keys()):
        info = dados[plataforma]
        
        if 'erro' in info and info['erro'] is not None:
            print(f"\n{Fore.RED}▓ {plataforma.upper()}{Style.RESET_ALL}")
            print(f"  🔴 ERRO: {info['erro']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            if info.get('status_http') != 'N/A':
                 print(f"  STATUS HTTP: {info['status_http']}")
        elif 'nota' in info:
            total_verificados += 1
            print(f"\n{Fore.YELLOW}▓ {plataforma.upper()}{Style.RESET_ALL}")
            print(f"  🟡 NOTA: {info['nota']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            print(f"  ⚙️ MÉTODO: {info.get('metodo', 'N/A')}")
        elif plataforma == "Holehe Status":
            total_verificados += 1
            cor_status = Fore.GREEN if info.get('existe') else Fore.RED
            texto_status = "SUCESSO" if info.get('existe') else "FALHA"
            print(f"\n{cor_status}▓ HOLEHE (VERIFICAÇÃO DE E-MAIL){Style.RESET_ALL}")
            print(f"  {cor_status}STATUS: {texto_status}{Style.RESET_ALL}")
            if info.get('dados') and info['dados'].get('saida_bruta'):
                print(f"  SAÍDA BRUTA (parcial): {info['dados']['saida_bruta'][:200]}...") 
            elif info.get('erro'):
                print(f"  ERRO: {info['erro']}")
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
            
            username_url_part = info.get('url', '').split('/')[-1].replace('@', '').lower()
            if info.get('url') and len(info.get('url').split('/')) > 2 and info.get('url').split('/')[-2]:
                 username_url_part = info.get('url').split('/')[-2].replace('@', '').lower()

            if info.get('nome_perfil_encontrado') and str(info['nome_perfil_encontrado']).lower() != username_url_part:
                print(f"  📛 NOME/USUÁRIO ENCONTRADO: {info['nome_perfil_encontrado']}")
            elif info.get('nome_perfil_encontrado'):
                print(f"  📛 USUÁRIO: {info['nome_perfil_encontrado']}")
            
            print(f"  ⚙️ MÉTODO: {info.get('metodo', 'N/A')}")
            if info.get('status_http') != 'N/A':
                 print(f"  STATUS HTTP: {info['status_http']}")

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
    print(f"{Fore.CYAN}1. Buscar por nome de usuário ({len(SITES)} plataformas){Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. Buscar por e-mail (com Holehe e Verificação Gmail){Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. Exportar últimos resultados para JSON{Style.RESET_ALL}")
    print(f"{Fore.CYAN}4. Sair{Style.RESET_ALL}")
    
    try:
        escolha = input(f"\n{Fore.CYAN}Escolha uma opção (1-4): {Style.RESET_ALL}").strip()
        return int(escolha)
    except ValueError:
        return 0

def executar_eriknet():
    """Loop principal de execução do ErikNet."""
    ultimos_resultados: Optional[Dict[str, Any]] = None
    ultimo_prefixo_arquivo: Optional[str] = None
    
    with ThreadPoolExecutor(max_workers=Config.MAX_TRABALHADORES) as executor:
        while True:
            opcao = menu_principal()
            
            if opcao == 1:
                username = input(f"\n{Fore.YELLOW}Digite o nome de usuário (min. 2 caracteres, sem espaços): {Style.RESET_ALL}").strip()
                if not username or len(username) < 2 or re.search(r'\s', username) or not re.match(r"^[a-zA-Z0-9_-]+$", username):
                    logging.warning(f"{Fore.YELLOW}Nome de usuário inválido!{Style.RESET_ALL}")
                    time.sleep(2)
                    continue
                
                logging.info(f"\n{Fore.BLUE}🔍 Buscando em mais de 100 plataformas para: {username}...{Style.RESET_ALL}")
                ultimos_resultados = buscar_perfis(username, executor)
                ultimo_prefixo_arquivo = f"usuario_{username}"
                exibir_resultados_eriknet(ultimos_resultados, f"Busca por Usuário: {username}")
                
            elif opcao == 2:
                email = input(f"\n{Fore.YELLOW}Digite o e-mail: {Style.RESET_ALL}").strip().lower()
                if not email or not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                    logging.warning(f"{Fore.YELLOW}Formato de e-mail inválido ou vazio!{Style.RESET_ALL}")
                    time.sleep(2)
                    continue

                nome_usuario_do_email = email.split('@')[0]
                
                logging.info(f"\n{Fore.BLUE}🔍 Iniciando busca por e-mail: {email}...{Style.RESET_ALL}")

                resultados_combinados = {}
                resultado_holehe_dict = executar_holehe(email)
                resultados_combinados["Holehe Status"] = resultado_holehe_dict
                
                resultado_verificacao_gmail = verificar_gmail_heuristica(email)
                resultados_combinados["Gmail (Verificação Heurística)"] = resultado_verificacao_gmail
                
                logging.info(f"\n{Fore.BLUE}🔍 Buscando perfis sociais para o usuário derivado do e-mail: {nome_usuario_do_email}...{Style.RESET_ALL}")
                resultados_perfis_sociais = buscar_perfis(nome_usuario_do_email, executor)
                resultados_combinados.update(resultados_perfis_sociais)
                
                ultimos_resultados = resultados_combinados
                ultimo_prefixo_arquivo = f"email_{email.replace('@', '_').replace('.', '_')}"
                exibir_resultados_eriknet(ultimos_resultados, f"Busca por E-mail: {email}")
                
            elif opcao == 3:
                if ultimos_resultados and ultimo_prefixo_arquivo:
                    exportar_para_json(ultimos_resultados, ultimo_prefixo_arquivo)
                else:
                    logging.warning(f"{Fore.YELLOW}❌ Nenhum resultado disponível para exportar.{Style.RESET_ALL}")
                
            elif opcao == 4:
                logging.info(f"{Fore.GREEN}\nSaindo do ErikNet...{Style.RESET_ALL}")
                break
                
            else:
                logging.warning(f"{Fore.YELLOW}Opção inválida! Por favor, tente novamente.{Style.RESET_ALL}")
                time.sleep(1)
                
            if opcao != 4:
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
