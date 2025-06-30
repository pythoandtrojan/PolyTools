#!/usr/bin/env python3

import os
import sys
import json
import re
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from diskcache import Cache
from functools import lru_cache, wraps 
import hashlib
from bs4 import BeautifulSoup


init(autoreset=True)


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)]) 


def rate_limit(calls_per_second: int):
    min_interval = 1.0 / calls_per_second
    last_call_time = {} 

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            func_name = func.__name__
            now = time.monotonic()
            elapsed = now - last_call_time.get(func_name, 0)

            if elapsed < min_interval:
                wait_time = min_interval - elapsed
                logging.debug(f"[{func_name}] Waiting for {wait_time:.2f} seconds due to rate limit.")
                time.sleep(wait_time)

            last_call_time[func_name] = time.monotonic()
            return func(*args, **kwargs)
        return wrapper
    return decorator

class Config:
    """Configurações otimizadas para Termux e investigações avançadas"""
    TIMEOUT = 15
    MAX_WORKERS = 3 if "com.termux" in os.getcwd() else 5
    CACHE_TTL = 3600  
    USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36'
    CACHE_DIR = "/data/data/com.termux/files/usr/tmp/gmail_cache" if "com.termux" in os.getcwd() else "/tmp/gmail_cache"
    
   
    APIS = {
        'google_password_checkup': 'https://passwords.google.com/checkup/api/hasPasswordLeak',
        'breachdirectory': 'https://breachdirectory.p.rapidapi.com/',
        'snusbase': 'https://api.snusbase.com/v2/search',
        'telegram_check': 'https://my.telegram.org/auth/send_password', 
        'leakcheck': 'https://leakcheck.io/api',
        'hunter_io_verifier': 'https://api.hunter.io/v2/email-verifier',
        'hunter_io_domain_search': 'https://api.hunter.io/v2/domain-search',
        'emailrep': 'https://emailrep.io/',
        'dehashed': 'https://api.dehashed.com/v1/search',
        'leaklookup': 'https://api.leaklookup.com/v2/search'
    }


    API_KEYS: Dict[str, str] = {
        'LEAKCHECK_API_KEY': os.getenv('LEAKCHECK_API_KEY', 'YOUR_LEAKCHECK_API_KEY'),
        'HUNTER_API_KEY': os.getenv('HUNTER_API_KEY', 'YOUR_HUNTER_API_KEY'),
        'DEHASHED_API_KEY': os.getenv('DEHASHED_API_KEY', 'YOUR_DEHASHED_API_KEY'),
        'LEAKLOOKUP_API_KEY': os.getenv('LEAKLOOKUP_API_KEY', 'YOUR_LEAKLOOKUP_API_KEY'),
       
    }

class TermuxUtils:
    """Utilitários específicos para Termux"""
    
    @staticmethod
    def check_dependencies():
        """Verifica e instala dependências faltantes"""
        logging.info(f"{Fore.YELLOW}[*] Verificando e instalando dependências...{Style.RESET_ALL}")
        
        required_packages = [
            "requests",
            "colorama",
            "bs4", 
            "diskcache",
           
        ]
        
        missing_packages = []
        for pkg in required_packages:
            try:
                __import__(pkg.replace('-', '_'))
            except ImportError:
                missing_packages.append(pkg)
        
        if missing_packages:
            logging.warning(f"{Fore.YELLOW}[!] As seguintes dependências estão faltando: {', '.join(missing_packages)}{Style.RESET_ALL}")
            install_cmd = "pip install " + " ".join(missing_packages)
            if "com.termux" in os.getcwd():
                install_cmd = "pkg install python -y && " + install_cmd
            
            logging.info(f"{Fore.YELLOW}[!] Tentando instalar dependências...{Style.RESET_ALL}")
            os.system(install_cmd)
            logging.info(f"{Fore.GREEN}[✓] Instalação de dependências concluída (verifique os logs acima para erros).{Style.RESET_ALL}")
        else:
            logging.info(f"{Fore.GREEN}[✓] Todas as dependências necessárias estão instaladas.{Style.RESET_ALL}")

class CacheManager:
    """Gerenciamento de cache em disco para Termux"""
    
    def __init__(self):
        os.makedirs(Config.CACHE_DIR, exist_ok=True)
        self.cache = Cache(Config.CACHE_DIR)
    
    def get(self, key: str) -> Any:
        return self.cache.get(key)
    
    def set(self, key: str, value: Any, ttl: int = Config.CACHE_TTL):
        self.cache.set(key, value, expire=ttl)

class GmailInvestigator:
    """Investigador avançado para contas Gmail, com padronização de respostas."""
    
    def __init__(self):
        self.cache = CacheManager()

    def _is_api_configured(self, api_name: str) -> bool:
        """Verifica se a chave de API para um serviço está configurada."""
        key_name = f'{api_name.upper()}_API_KEY'
        api_key = Config.API_KEYS.get(key_name)
        if api_key and api_key != f'YOUR_{api_name.upper()}_API_KEY':
            return True
        logging.warning(f"{Fore.YELLOW}[{api_name.capitalize()}] Chave de API '{key_name}' não configurada ou padrão. Pule esta verificação.{Style.RESET_ALL}")
        return False

    @lru_cache(maxsize=128)
    @rate_limit(calls_per_second=0.5) 
    def check_google_leaks(self, email: str) -> Dict:
        """Verifica vazamentos de senha usando Google Password Checkup."""
        cache_key = f"leak_google_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Google Leak Check] Retornando do cache para {email}.")
            return cached

        try:
            payload = {'username': email, 'isAccount': True}
            headers = {'User-Agent': Config.USER_AGENT}
            
            response = requests.post(
                Config.APIS['google_password_checkup'],
                json=payload,
                headers=headers,
                timeout=Config.TIMEOUT
            )
            
            if response.status_code == 200:
                has_leak = response.json().get('hasLeak', False)
                result = {
                    'found': has_leak,
                    'data': {'hasLeak': has_leak, 'source': 'Google Password Checkup'},
                    'error': None
                }
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[Google Leak Check] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[Google Leak Check] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Google Leak Check Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Google Leak Check Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Google Leak Check Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    def check_breaches(self, email: str) -> Dict:
        """Verifica múltiplas bases de dados de vazamentos e serviços."""
        sources = {
            'breachdirectory': self._check_breachdirectory,
            'snusbase': self._check_snusbase,
            'telegram': self._check_telegram_account, 
            'leakcheck': self._check_leakcheck,
            'hunter_io': self._check_hunter_io,
            'emailrep': self._check_emailrep,
            'gravatar': self._check_gravatar,
            'dehashed': self._check_dehashed, 
            'leaklookup': self._check_leaklookup 
          
        }

        results = {}
        with ThreadPoolExecutor(max_workers=min(Config.MAX_WORKERS, len(sources))) as executor:
            futures = {executor.submit(func, email): name for name, func in sources.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    logging.error(f"{Fore.RED}[{name.capitalize()} Error] Erro ao executar: {e}{Style.RESET_ALL}")
                    results[name] = {'found': False, 'data': {}, 'error': str(e)}
        return results

    @rate_limit(calls_per_second=1) 
    def _check_breachdirectory(self, email: str) -> Dict:
        """Verifica vazamentos usando BreachDirectory."""
       
        
        cache_key = f"breachdir_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[BreachDirectory] Retornando do cache para {email}.")
            return cached

        try:
            headers = {
                'X-RapidAPI-Key': 'free', 
                'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com',
                'User-Agent': Config.USER_AGENT
            }
            response = requests.get(
                f"{Config.APIS['breachdirectory']}?query={email}",
                headers=headers,
                timeout=Config.TIMEOUT
            )

            if response.status_code == 200:
                data = response.json().get('result', [])
                result = {'found': bool(data), 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[BreachDirectory] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[BreachDirectory] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[BreachDirectory Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[BreachDirectory Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[BreachDirectory Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.5) 
    def _check_snusbase(self, email: str) -> Dict:
        """Verifica vazamentos usando Snusbase."""
        cache_key = f"snusbase_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Snusbase] Retornando do cache para {email}.")
            return cached

        try:
            response = requests.post(
                Config.APIS['snusbase'],
                auth=('public', ''), 
                json={'type': 'email', 'term': email},
                timeout=Config.TIMEOUT,
                headers={'User-Agent': Config.USER_AGENT}
            )
            if response.status_code == 200:
                data = response.json().get('results', [])
                result = {'found': bool(data), 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[Snusbase] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[Snusbase] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Snusbase Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Snusbase Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Snusbase Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.2)
    def _check_telegram_account(self, email: str) -> Dict:
        """
        Verifica a possível associação de um email a uma conta Telegram.
        AVISO: Esta é uma verificação NÃO OFICIAL e instável.
        Pode resultar em falsos positivos/negativos e ser bloqueada pelo Telegram a qualquer momento.
        Se a precisão for crítica, considere desabilitar ou remover.
        """
        logging.warning(f"{Fore.YELLOW}[Telegram Check] Esta é uma verificação NÃO OFICIAL e instável. Use com extrema cautela.{Style.RESET_ALL}")
        cache_key = f"telegram_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Telegram Check] Retornando do cache para {email}.")
            return cached

        try:
            
            response = requests.post(
                Config.APIS['telegram_check'],
                data={'phone': email},
                timeout=Config.TIMEOUT,
                headers={'User-Agent': Config.USER_AGENT}
            )
            
          
            is_associated = "phone_num_unconfirmed" in response.text or "auth_code_sent" in response.text
            
            result = {'found': is_associated, 'data': {'response_text': response.text}, 'error': None}
            self.cache.set(cache_key, result)
            return result
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Telegram Check Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Telegram Check Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Telegram Check Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.5) 
    def _check_leakcheck(self, email: str) -> Dict:
        """Verifica vazamentos usando LeakCheck.io."""
        if not self._is_api_configured('leakcheck'):
            return {'found': False, 'data': {}, 'error': 'API key not configured'}

        cache_key = f"leakcheck_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[LeakCheck] Retornando do cache para {email}.")
            return cached

        try:
            headers = {'User-Agent': Config.USER_AGENT}
            params = {'key': Config.API_KEYS['LEAKCHECK_API_KEY'], 'check': email, 'type': 'email'}
            response = requests.get(
                Config.APIS['leakcheck'],
                headers=headers,
                params=params,
                timeout=Config.TIMEOUT
            )

            if response.status_code == 200:
                data = response.json().get('data', [])
                result = {'found': bool(data), 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[LeakCheck] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[LeakCheck] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[LeakCheck Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[LeakCheck Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[LeakCheck Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=1) # Limite para Hunter.io
    def _check_hunter_io(self, email: str) -> Dict:
        """Verifica email profissional e reputação usando Hunter.io."""
        if not self._is_api_configured('hunter'):
            return {'found': False, 'data': {}, 'error': 'API key not configured'}

        cache_key = f"hunterio_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Hunter.io] Retornando do cache para {email}.")
            return cached

        try:
            params = {'email': email, 'api_key': Config.API_KEYS['HUNTER_API_KEY']}
            response = requests.get(
                Config.APIS['hunter_io_verifier'],
                params=params,
                timeout=Config.TIMEOUT,
                headers={'User-Agent': Config.USER_AGENT}
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                found = data.get('result') == 'deliverable'
                result = {'found': found, 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[Hunter.io] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[Hunter.io] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Hunter.io Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Hunter.io Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Hunter.io Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.5) 
    def _check_emailrep(self, email: str) -> Dict:
        """Verifica reputação do email usando EmailRep.io."""
        cache_key = f"emailrep_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[EmailRep.io] Retornando do cache para {email}.")
            return cached

        try:
            
            headers = {'User-Agent': Config.USER_AGENT}
            response = requests.get(
                f"{Config.APIS['emailrep']}{email}",
                headers=headers,
                timeout=Config.TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                found = data.get('reputation') in ['bad', 'suspicious'] or data.get('details', {}).get('malicious_activity', False)
                result = {'found': found, 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[EmailRep.io] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[EmailRep.io] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[EmailRep.io Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[EmailRep.io Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[EmailRep.io Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=1) 
    def _check_gravatar(self, email: str) -> Dict:
        """Verifica se o email tem um perfil Gravatar."""
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        
        cache_key = f"gravatar_{email_hash}"
        cached = self.cache.get(cache_key)
        if cached: 
            logging.info(f"[Gravatar] Retornando do cache para {email}.")
            return cached

        try:
            response = requests.get(gravatar_url, timeout=Config.TIMEOUT, headers={'User-Agent': Config.USER_AGENT})
            has_gravatar = response.status_code == 200
            
            result = {'found': has_gravatar, 'data': {'gravatar_url': gravatar_url if has_gravatar else None}, 'error': None}
            self.cache.set(cache_key, result)
            return result
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Gravatar Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Gravatar Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Gravatar Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.2) 
    def _check_dehashed(self, email: str) -> Dict:
        """Verifica vazamentos usando Dehashed.com (requer API Key)."""
        if not self._is_api_configured('dehashed'):
            return {'found': False, 'data': {}, 'error': 'API key not configured'}

        cache_key = f"dehashed_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Dehashed] Retornando do cache para {email}.")
            return cached

        try:
         
            headers = {'User-Agent': Config.USER_AGENT}
            auth = (os.getenv('DEHASHED_EMAIL', 'YOUR_DEHASHED_EMAIL'), Config.API_KEYS['DEHASHED_API_KEY'])
            params = {'query': email}

            response = requests.get(
                Config.APIS['dehashed'],
                headers=headers,
                params=params,
                auth=auth,
                timeout=Config.TIMEOUT
            )

            if response.status_code == 200:
                data = response.json().get('entries', [])
                found = bool(data)
                result = {'found': found, 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 401:
                logging.error(f"{Fore.RED}[Dehashed] Autenticação falhou. Verifique sua chave de API e email. {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Authentication failed'}
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[Dehashed] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[Dehashed] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Dehashed Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Dehashed Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Dehashed Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

    @rate_limit(calls_per_second=0.2) 
    def _check_leaklookup(self, email: str) -> Dict:
        """Verifica vazamentos usando Leak-Lookup.com (requer API Key)."""
        if not self._is_api_configured('leaklookup'):
            return {'found': False, 'data': {}, 'error': 'API key not configured'}

        cache_key = f"leaklookup_{hashlib.md5(email.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            logging.info(f"[Leak-Lookup] Retornando do cache para {email}.")
            return cached

        try:
            headers = {'User-Agent': Config.USER_AGENT}
            params = {'key': Config.API_KEYS['LEAKLOOKUP_API_KEY'], 'type': 'email', 'query': email}

            response = requests.get(
                Config.APIS['leaklookup'],
                headers=headers,
                params=params,
                timeout=Config.TIMEOUT
            )

            if response.status_code == 200:
                data = response.json().get('result', {}).get('leaks', [])
                found = bool(data)
                result = {'found': found, 'data': data, 'error': None}
                self.cache.set(cache_key, result)
                return result
            elif response.status_code == 401:
                logging.error(f"{Fore.RED}[Leak-Lookup] Autenticação falhou. Verifique sua chave de API. {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Authentication failed'}
            elif response.status_code == 429:
                logging.warning(f"{Fore.YELLOW}[Leak-Lookup] Limite de requisições excedido para {email}.{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': 'Rate limit exceeded'}
            else:
                logging.error(f"{Fore.RED}[Leak-Lookup] Erro {response.status_code} para {email}: {response.text}{Style.RESET_ALL}")
                return {'found': False, 'data': {}, 'error': f'HTTP Error {response.status_code}'}
        except requests.exceptions.Timeout:
            logging.error(f"{Fore.RED}[Leak-Lookup Error] Tempo limite excedido para {email}.{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logging.error(f"{Fore.RED}[Leak-Lookup Error] Erro de requisição para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Request error: {e}'}
        except Exception as e:
            logging.error(f"{Fore.RED}[Leak-Lookup Error] Erro inesperado para {email}: {e}{Style.RESET_ALL}")
            return {'found': False, 'data': {}, 'error': f'Unexpected error: {e}'}

 
    def _check_socialblade(self, email: str) -> Dict:
        """(Implementação futura) Verifica contas em plataformas de streaming via Social Blade."""
        logging.info(f"{Fore.YELLOW}[SocialBlade] Implementação futura. Requer pesquisa e entendimento da API.{Style.RESET_ALL}")
        return {'found': False, 'data': {}, 'error': 'Not implemented'}

    def _check_ipqualityscore(self, email: str) -> Dict:
        """(Implementação futura) Analisa reputação do email e risco de fraude."""
        logging.info(f"{Fore.YELLOW}[IPQualityScore] Implementação futura. Requer chave de API e entendimento da API.{Style.RESET_ALL}")
        return {'found': False, 'data': {}, 'error': 'Not implemented'}

    def _check_twitter(self, email: str) -> Dict:
        """(Implementação futura) Verifica associação com conta do Twitter (requer API Twitter dev)."""
        logging.info(f"{Fore.YELLOW}[Twitter API] Implementação futura. Requer conta de desenvolvedor Twitter.{Style.RESET_ALL}")
        return {'found': False, 'data': {}, 'error': 'Not implemented'}

    def find_related_accounts(self, email: str) -> List[str]:
        """Gera variações comuns do username e domínios comuns para pesquisa manual."""
        username = email.split('@')[0]

        variations = [
            f"{username}{i}@gmail.com" for i in range(1, 3)
        ] + [
            f"{username}.{i}@gmail.com" for i in range(1, 3)
        ]
       
        common_domains = [
            f"{username}@outlook.com",
            f"{username}@hotmail.com",
            f"{username}@yahoo.com"
        ]
        return list(set(variations + common_domains)) 

class ForensicAnalyzer:
    """Análise forense avançada (funções mais complexas ou experimentais)."""
    
    @staticmethod
    def estimate_account_age(email: str) -> Optional[int]:
        """
        Estimativa da idade da conta baseada em pesquisa web (experimental e não confiável).
        Requer a biblioteca 'google' (pip install google), que é uma wrapper não oficial.
        Pode ser bloqueada pelo Google e retornar resultados imprecisos.
        Recomendado manter comentado ou usar apenas para fins de experimentação.
        """
        logging.warning(f"{Fore.YELLOW}[ForensicAnalyzer] Estimativa de idade da conta é experimental e pode ser imprecisa/bloqueada.{Style.RESET_ALL}")
        try:
            from googlesearch import search
            
            query = f'site:gmail.com "{email}"'
            results = list(search(query, num=3, stop=3, pause=2))
            
            if not results:
                logging.info(f"Não foram encontrados resultados para estimar a idade da conta {email}.")
                return None
                
            earliest_year = datetime.now().year
            for url in results:
                try:
                    response = requests.get(url, timeout=Config.TIMEOUT, headers={'User-Agent': Config.USER_AGENT})
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text = soup.get_text().lower()
                    for year in range(2004, datetime.now().year + 1): 
                        if str(year) in text:
                            earliest_year = min(earliest_year, year)
                except Exception as e:
                    logging.debug(f"Erro ao processar URL {url} para estimativa de idade: {e}")
                    continue
                    
            return earliest_year if earliest_year != datetime.now().year else None
        except ImportError:
            logging.error(f"{Fore.RED}[ForensicAnalyzer Error] A biblioteca 'google' não está instalada. Execute 'pip install google'.{Style.RESET_ALL}")
            return None
        except Exception as e:
            logging.error(f"{Fore.RED}[ForensicAnalyzer Error] Erro na estimativa de idade da conta: {e}{Style.RESET_ALL}")
            return None

class RiskAssessor:
    """Avaliação avançada de riscos com pesos dinâmicos."""
    
    @staticmethod
    def calculate_risk(leaks: Dict, breaches: Dict) -> Dict:
        """Calcula score de risco com pesos dinâmicos baseados nos resultados das APIs."""
        score = 0
        details = []
        
      
        if leaks.get('found') and leaks['data'].get('hasLeak'):
            score += 40
            details.append("Senha vazada (Google Password Checkup)")
        elif leaks.get('error'):
            details.append(f"Erro na verificação de vazamento do Google: {leaks['error']}")

        breach_sources = ['breachdirectory', 'snusbase', 'leakcheck', 'dehashed', 'leaklookup']
        total_breach_entries = 0
        for source_name in breach_sources:
            source_data = breaches.get(source_name)
            if source_data and source_data.get('found') and isinstance(source_data.get('data'), list):
                num_entries = len(source_data['data'])
                total_breach_entries += num_entries
                if num_entries > 0:
                    details.append(f"Encontrado em {num_entries} entradas de vazamento de {source_name.capitalize()}")
            elif source_data and source_data.get('error'):
                details.append(f"Erro na verificação de {source_name.capitalize()}: {source_data['error']}")
            elif source_data and not source_data.get('found') and source_data.get('error'):
                 details.append(f"Verificação de {source_name.capitalize()} não configurada/falhou: {source_data['error']}")

        if total_breach_entries > 0:
            score += min(total_breach_entries * 2, 30) 
            
      
        hunter_data = breaches.get('hunter_io')
        if hunter_data and hunter_data.get('found'):
            if hunter_data['data'].get('disposable'):
                score += 10
                details.append("Email identificado como descartável/temporário (Hunter.io)")

            if hunter_data['data'].get('score') is not None and hunter_data['data']['score'] < 50:
                 score += 10
                 details.append(f"Baixa qualidade/reputação do email (Hunter.io score: {hunter_data['data']['score']})")
        elif hunter_data and hunter_data.get('error'):
            details.append(f"Erro na verificação Hunter.io: {hunter_data['error']}")

       
        emailrep_data = breaches.get('emailrep')
        if emailrep_data and emailrep_data.get('found'):
            rep_data = emailrep_data['data']
            reputation = rep_data.get('reputation')
            if reputation == 'bad':
                score += 30
                details.append("Reputação de email ruim (EmailRep.io)")
            elif reputation == 'suspicious':
                score += 15
                details.append("Reputação de email suspeita (EmailRep.io)")
            
            if rep_data.get('malicious_activity'):
                score += 20
                details.append("Atividade maliciosa associada (EmailRep.io)")
            if rep_data.get('abuse_reported'):
                score += 10
                details.append("Abuso reportado (EmailRep.io)")
            if rep_data.get('blacklisted'):
                score += 25
                details.append("Email em blacklist (EmailRep.io)")
        elif emailrep_data and emailrep_data.get('error'):
            details.append(f"Erro na verificação EmailRep.io: {emailrep_data['error']}")

        
        telegram_data = breaches.get('telegram')
        if telegram_data and telegram_data.get('found'):
            score += 5 
            details.append("Possível conta no Telegram associada (verificação não oficial)")
        elif telegram_data and telegram_data.get('error'):
            details.append(f"Erro na verificação Telegram: {telegram_data['error']}")


        gravatar_data = breaches.get('gravatar')
        if gravatar_data and gravatar_data.get('found'):
            score += 2 
            details.append("Perfil Gravatar encontrado (indica uso público do email)")
        elif gravatar_data and gravatar_data.get('error'):
            details.append(f"Erro na verificação Gravatar: {gravatar_data['error']}")

        
        score = min(score, 100)
        
  
        level = "Baixo"
        if score >= 70: level = "Crítico"
        elif score >= 50: level = "Alto"
        elif score >= 30: level = "Médio"
        
        return {
            'score': score,
            'level': level,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }

class ReportGenerator:
    """Geração de relatórios para Termux e desktop."""
    
    @staticmethod
    def generate_report(email: str, investigator: GmailInvestigator) -> Dict:
        """Gera relatório completo, coletando dados de várias fontes."""
        logging.info(f"{Fore.BLUE}[*] Verificando vazamentos do Google...{Style.RESET_ALL}")
        leaks = investigator.check_google_leaks(email)        
        logging.info(f"{Fore.BLUE}[*] Verificando em múltiplas bases de dados de vazamentos e APIs...{Style.RESET_ALL}")
        breaches = investigator.check_breaches(email)       
        logging.info(f"{Fore.BLUE}[*] Buscando contas relacionadas...{Style.RESET_ALL}")
        related = investigator.find_related_accounts(email)  
        logging.info(f"{Fore.BLUE}[*] Calculando avaliação de risco...{Style.RESET_ALL}")
        risk = RiskAssessor.calculate_risk(leaks, breaches)
        
        report_data = {
            'metadata': {
                'email': email,
                'generated_at': datetime.now().isoformat(),
                'tool': 'Gmail Forensic Investigator'
            },
            'leaks': leaks,
            'breaches': breaches,
            'related_accounts': related,
            'risk_assessment': risk,
        }
        
            
        return report_data
    
    @staticmethod
    def print_termux_report(report: Dict):
        """Versão simplificada e colorida do relatório para Termux."""
        print(f"\n{Fore.CYAN}=== RELATÓRIO FORENSE GMAIL ==={Style.RESET_ALL}")
        print(f"Email: {report['metadata']['email']}")
        print(f"Gerado em: {report['metadata']['generated_at']}")
        
        print(f"\n{Fore.MAGENTA}--- AVALIAÇÃO DE RISCO ---{Style.RESET_ALL}")
        risk_level = report['risk_assessment']['level']
        risk_score = report['risk_assessment']['score']
        
        color_map = {
            "Crítico": Fore.RED,
            "Alto": Fore.LIGHTRED_EX,
            "Médio": Fore.YELLOW,
            "Baixo": Fore.GREEN
        }
        level_color = color_map.get(risk_level, Fore.WHITE)
        
        print(f"Nível de Risco: {level_color}{risk_level}{Style.RESET_ALL} ({risk_score}/100)")
        
        if report['risk_assessment']['details']:
            print(f"\n{Fore.RED}● FATORES DE RISCO DETECTADOS:{Style.RESET_ALL}")
            for detail in report['risk_assessment']['details']:
                print(f" - {detail}")
        else:
            print(f"{Fore.GREEN}● Nenhum fator de risco significativo detectado.{Style.RESET_ALL}")

        print(f"\n{Fore.MAGENTA}--- RESULTADOS DETALHADOS ---{Style.RESET_ALL}")
        
        
        google_leak = report['leaks']
        if google_leak.get('found'):
            print(f"\n{Fore.RED}● SENHA VAZADA (Google):{Style.RESET_ALL} Sim. Verifique em https://passwords.google.com")
        elif google_leak.get('error'):
            print(f"{Fore.RED}● SENHA VAZADA (Google):{Style.RESET_ALL} Erro na verificação: {google_leak['error']}")
        else:
            print(f"{Fore.GREEN}● Senha não encontrada em vazamentos do Google.{Style.RESET_ALL}")

        
        print(f"\n{Fore.BLUE}● VAZAMENTOS GERAIS:{Style.RESET_ALL}")
        breach_sources = ['breachdirectory', 'snusbase', 'leakcheck', 'dehashed', 'leaklookup']
        found_any_breach = False
        for source_name in breach_sources:
            source_data = report['breaches'].get(source_name)
            if source_data and source_data.get('found'):
                num_entries = len(source_data.get('data', []))
                print(f"  {Fore.YELLOW}De {source_name.replace('_', ' ').title()}: {num_entries} entradas encontradas.{Style.RESET_ALL}")
                found_any_breach = True
            elif source_data and source_data.get('error'):
                print(f"  {Fore.RED}De {source_name.replace('_', ' ').title()}: Erro - {source_data['error']}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}De {source_name.replace('_', ' ').title()}: N/A (Não encontrado ou chave/configuração pendente).{Style.RESET_ALL}")

        if not found_any_breach and all(not report['breaches'].get(s, {}).get('found') and not report['breaches'].get(s, {}).get('error') for s in breach_sources):
             print(f"  {Fore.GREEN}Nenhum vazamento encontrado nas bases gerais verificadas.{Style.RESET_ALL}")


    
        print(f"\n{Fore.BLUE}● VERIFICAÇÃO DE CONTAS/SERVIÇOS:{Style.RESET_ALL}")
        
        telegram_data = report['breaches'].get('telegram')
        if telegram_data and telegram_data.get('found'):
            print(f"  {Fore.YELLOW}Conta no Telegram:{Style.RESET_ALL} Provavelmente associada (verificação não oficial).")
        elif telegram_data and telegram_data.get('error'):
            print(f"  {Fore.RED}Conta no Telegram:{Style.RESET_ALL} Erro na verificação: {telegram_data['error']}")
        else:
            print(f"  {Fore.GREEN}Conta no Telegram:{Style.RESET_ALL} Não encontrada ou não verificável.")

        hunter_data = report['breaches'].get('hunter_io', {})
        if hunter_data.get('found'):
            print(f"  {Fore.YELLOW}Hunter.io (Verificação Profissional):{Style.RESET_ALL}")
            print(f"    Status: {hunter_data['data'].get('result', 'N/A')}")
            print(f"    Descartável: {hunter_data['data'].get('disposable', 'N/A')}")
            print(f"    Score de Qualidade: {hunter_data['data'].get('score', 'N/A')}")
        elif hunter_data.get('error'):
            print(f"  {Fore.RED}Hunter.io:{Style.RESET_ALL} Erro na verificação: {hunter_data['error']}")
        else:
            print(f"  {Fore.GREEN}Hunter.io:{Style.RESET_ALL} N/A (Chave não configurada ou não verificado).")

        emailrep_data = report['breaches'].get('emailrep', {})
        if emailrep_data.get('found') or emailrep_data.get('data'): # Exibir dados mesmo se 'found' for False mas dados existirem
            print(f"  {Fore.YELLOW}EmailRep.io (Reputação):{Style.RESET_ALL}")
            data_to_show = emailrep_data['data']
            print(f"    Reputação: {data_to_show.get('reputation', 'N/A')}")
            print(f"    Atividade Maliciosa: {data_to_show.get('malicious_activity', 'N/A')}")
            print(f"    Reporte de Abuso: {data_to_show.get('abuse_reported', 'N/A')}")
            print(f"    Blacklisted: {data_to_show.get('blacklisted', 'N/A')}")
        elif emailrep_data.get('error'):
            print(f"  {Fore.RED}EmailRep.io:{Style.RESET_ALL} Erro na verificação: {emailrep_data['error']}")
        else:
            print(f"  {Fore.GREEN}EmailRep.io:{Style.RESET_ALL} N/A (Não verificado).")

        gravatar_data = report['breaches'].get('gravatar')
        if gravatar_data and gravatar_data.get('found'):
            print(f"  {Fore.YELLOW}Perfil Gravatar:{Style.RESET_ALL} Encontrado.")
        elif gravatar_data and gravatar_data.get('error'):
            print(f"  {Fore.RED}Perfil Gravatar:{Style.RESET_ALL} Erro na verificação: {gravatar_data['error']}")
        else:
            print(f"  {Fore.GREEN}Perfil Gravatar:{Style.RESET_ALL} Não encontrado.")

        if report['related_accounts']:
            print(f"\n{Fore.BLUE}● POSSÍVEIS CONTAS RELACIONADAS (variações comuns):{Style.RESET_ALL}")
            for acc in report['related_accounts']:
                print(f" - {acc}")
        
        if 'account_age_estimate' in report and report['account_age_estimate']:
            print(f"\n{Fore.BLUE}● IDADE ESTIMADA DA CONTA:{Style.RESET_ALL} Desde {report['account_age_estimate']}")

    @staticmethod
    def save_json_report(report: Dict, filename: str):
        """Salva relatório completo em JSON."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logging.info(f"{Fore.GREEN}[✓] Relatório salvo como {filename}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}[!] Erro ao salvar relatório JSON: {e}{Style.RESET_ALL}")

def main():
    try:
        
        if "com.termux" in os.getcwd():
            TermuxUtils.check_dependencies()
            logging.info(f"{Fore.YELLOW}[*] Modo Termux ativado{Style.RESET_ALL}")
        
        
        if len(sys.argv) > 1:
            email = sys.argv[1].lower()
        else:
            email = input(f"{Fore.YELLOW}[?] Email Gmail: {Style.RESET_ALL}").strip().lower()
        
      
        if not re.match(r'^[a-z0-9._%+-]+@gmail\.com$', email):
            raise ValueError("Formato de email inválido. Use somente contas Gmail.")
        
      
        logging.info(f"\n{Fore.BLUE}[*] Analisando {email}...{Style.RESET_ALL}")
        investigator = GmailInvestigator()
        report = ReportGenerator.generate_report(email, investigator)
        
        
        if "com.termux" in os.getcwd():
            ReportGenerator.print_termux_report(report)
        else:
          
            from pprint import pprint
            print(f"\n{Fore.CYAN}=== RELATÓRIO COMPLETO (DESKTOP) ==={Style.RESET_ALL}")
            pprint(report)
        
        
        filename = f"gmail_forensic_{email.split('@')[0]}_{int(time.time())}.json"
        ReportGenerator.save_json_report(report, filename)
        
    except ValueError as ve:
        logging.error(f"{Fore.RED}[!] Erro de validação: {str(ve)}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"{Fore.RED}[!] Ocorreu um erro inesperado: {str(e)}{Style.RESET_ALL}", exc_info=True) # exc_info para traceback
        sys.exit(1)

if __name__ == "__main__":
    main() oque vc acha desse codigo seja extremamente chato e sinsero e pra termux
