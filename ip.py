#!/usr/bin/env python3
import requests
import sys
import json
import re
import socket
import time
from datetime import datetime

VERDE = "\033[92m"
AMARELO = "\033[93m"
VERMELHO = "\033[91m"
AZUL = "\033[94m"
MAGENTA = "\033[95m"
CIANO = "\033[96m"
RESET = "\033[0m"
NEGRITO = "\033[1m"

def mostrar_banner():
    banner = f"""
    {AZUL}#######################################
    #      {NEGRITO}FERRAMENTA DE CONSULTA IP{RESET}{AZUL}      #
    #   {VERDE}Desenvolvido por Erik Visivel{RESET}{AZUL}     #
    #######################################{RESET}
    """
    print(banner)

def validar_ip(ip):
    padrao = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(padrao, ip) is not None

def resolver_dominio(dominio):
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

def consultar_ip(ip, usar_proxy=False):
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    
    proxies = None
    if usar_proxy:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
    
    try:
        inicio = time.time()
        response = requests.get(url, proxies=proxies, timeout=10)
        tempo_resposta = time.time() - inicio
        
        dados = response.json()
        dados['tempo_resposta'] = round(tempo_resposta * 1000, 2)  
        
        if dados.get('status') == 'fail':
            print(f"{VERMELHO}Erro: {dados.get('message')}{RESET}")
            return None
        
        return dados
    except Exception as e:
        print(f"{VERMELHO}Erro ao consultar o IP: {e}{RESET}")
        return None

def get_bandeira(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return chr(127397 + ord(country_code[0])) + chr(127397 + ord(country_code[1]))
    except:
        return ""

def formatar_dados(dados):
    if not dados:
        return f"{VERMELHO}Nenhum dado disponível.{RESET}"
    
    # Detecções com cores
    mobile = f"{VERMELHO}Sim{RESET}" if dados.get('mobile') else f"{VERDE}Não{RESET}"
    proxy = f"{VERMELHO}Sim{RESET}" if dados.get('proxy') else f"{VERDE}Não{RESET}"
    hosting = f"{VERMELHO}Sim{RESET}" if dados.get('hosting') else f"{VERDE}Não{RESET}"
    
    bandeira = get_bandeira(dados.get('countryCode'))
    
    formato = f"""
    {AZUL}[+]{RESET} {NEGRITO}Informações do IP{RESET}: {CIANO}{dados.get('query', 'N/A')}{RESET}
    {AZUL}[+]{RESET} Data/Hora da consulta: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
    {AZUL}[+]{RESET} Tempo de resposta: {dados.get('tempo_resposta', 'N/A')} ms
    
    {AMARELO}[ Localização ]{RESET}
    Continente: {dados.get('continent', 'N/A')} ({dados.get('continentCode', 'N/A')})
    País: {bandeira} {dados.get('country', 'N/A')} ({dados.get('countryCode', 'N/A')})
    Região: {dados.get('regionName', 'N/A')} ({dados.get('region', 'N/A')})
    Cidade: {dados.get('city', 'N/A')}
    Distrito: {dados.get('district', 'N/A')}
    CEP: {dados.get('zip', 'N/A')}
    Coordenadas: Latitude {dados.get('lat', 'N/A')}, Longitude {dados.get('lon', 'N/A')}
    Fuso Horário: {dados.get('timezone', 'N/A')}
    Offset UTC: {dados.get('offset', 'N/A')} segundos
    Moeda: {dados.get('currency', 'N/A')}
    
    {AMARELO}[ Rede ]{RESET}
    ISP: {dados.get('isp', 'N/A')}
    Organização: {dados.get('org', 'N/A')}
    AS Number/Name: {dados.get('as', 'N/A')} / {dados.get('asname', 'N/A')}
    DNS Reverso: {dados.get('reverse', 'N/A')}
    
    {AMARELO}[ Detecções ]{RESET}
    Móvel: {mobile}
    Proxy: {proxy}
    Hosting: {hosting}
    """
    return formato

def salvar_resultado(dados, formato='txt'):
    if not dados:
        return False
    
    ip = dados.get('query', 'resultado')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"ip_result_{ip}_{timestamp}.{formato}"
    
    try:
        with open(nome_arquivo, 'w') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2)
            else:
                f.write(formatar_dados(dados))
        print(f"{VERDE}[+] Resultado salvo em: {nome_arquivo}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[-] Erro ao salvar resultado: {e}{RESET}")
        return False

def modo_interativo():
    while True:
        print(f"\n{CIANO}Modo Interativo (digite 'sair' para encerrar){RESET}")
        entrada = input("Digite IP ou domínio: ").strip()
        
        if entrada.lower() in ['sair', 'exit', 'quit']:
            break
            
        if not entrada:
            continue
            
        ip = entrada
        if not validar_ip(entrada):
            ip = resolver_dominio(entrada)
            if not ip:
                print(f"{VERMELHO}[-] Domínio inválido ou não resolvido{RESET}")
                continue
            print(f"{AZUL}[+] Domínio resolvido para IP: {ip}{RESET}")
        
        dados = consultar_ip(ip)
        if dados:
            print(formatar_dados(dados))
            
            salvar = input("Salvar resultado? (s/n/txt/json): ").lower()
            if salvar.startswith('s') or salvar.startswith('t'):
                salvar_resultado(dados, 'txt')
            elif salvar.startswith('j'):
                salvar_resultado(dados, 'json')

def main():
    mostrar_banner()
    
    if len(sys.argv) < 2:
        modo_interativo()
        sys.exit(0)
    
    ips = []
    usar_proxy = False
    salvar_json = False
    salvar_txt = False
    
    for arg in sys.argv[1:]:
        if arg in ['-p', '--proxy']:
            usar_proxy = True
        elif arg in ['-j', '--json']:
            salvar_json = True
        elif arg in ['-t', '--txt']:
            salvar_txt = True
        elif arg in ['-h', '--help']:
            print(f"""
{Uso:}
  {sys.argv[0]} [OPÇÕES] <IP1 IP2...|domínio>
  
{Opções:}
  -p, --proxy    Usar proxy Tor (requer Tor em execução)
  -j, --json     Salvar resultado em JSON
  -t, --txt      Salvar resultado em TXT
  -h, --help     Mostrar esta ajuda
  (sem argumentos) Modo interativo
            """)
            sys.exit(0)
        elif validar_ip(arg) or not validar_ip(arg) and '.' in arg:
            # Pode ser IP ou domínio
            if not validar_ip(arg):
                ip = resolver_dominio(arg)
                if ip:
                    print(f"{AZUL}[+] Domínio '{arg}' resolvido para IP: {ip}{RESET}")
                    ips.append(ip)
                else:
                    print(f"{VERMELHO}[-] Domínio inválido ou não resolvido: {arg}{RESET}")
            else:
                ips.append(arg)
    
    if not ips:
        print(f"{VERMELHO}Nenhum IP válido fornecido.{RESET}")
        sys.exit(1)
    
    for ip in ips:
        print(f"\n{CIANO}Consultando informações para: {ip}{RESET}")
        
        dados = consultar_ip(ip, usar_proxy)
        if dados:
            print(formatar_dados(dados))
            
            if salvar_txt:
                salvar_resultado(dados, 'txt')
            if salvar_json:
                salvar_resultado(dados, 'json')

if __name__ == "__main__":
    main()
