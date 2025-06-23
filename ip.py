#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime

def mostrar_banner():
    banner = """
    #######################################
    #      FERRAMENTA DE CONSULTA IP      #
    #   Desenvolvido por erik visivel     #
    #######################################
    """
    print(banner)

def consultar_ip(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    
    try:
        response = requests.get(url)
        dados = response.json()
        
        if dados.get('status') == 'fail':
            print(f"Erro: {dados.get('message')}")
            return None
        
        return dados
    except Exception as e:
        print(f"Erro ao consultar o IP: {e}")
        return None

def formatar_dados(dados):
    if not dados:
        return "Nenhum dado disponível."
    
    formato = f"""
    [+] Informações do IP: {dados.get('query', 'N/A')}
    [+] Data/Hora da consulta: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
    
    [ Localização ]
    Continente: {dados.get('continent', 'N/A')} ({dados.get('continentCode', 'N/A')})
    País: {dados.get('country', 'N/A')} ({dados.get('countryCode', 'N/A')})
    Região: {dados.get('regionName', 'N/A')} ({dados.get('region', 'N/A')})
    Cidade: {dados.get('city', 'N/A')}
    Distrito: {dados.get('district', 'N/A')}
    CEP: {dados.get('zip', 'N/A')}
    Coordenadas: Latitude {dados.get('lat', 'N/A')}, Longitude {dados.get('lon', 'N/A')}
    Fuso Horário: {dados.get('timezone', 'N/A')}
    Offset UTC: {dados.get('offset', 'N/A')} segundos
    Moeda: {dados.get('currency', 'N/A')}
    
    [ Rede ]
    ISP: {dados.get('isp', 'N/A')}
    Organização: {dados.get('org', 'N/A')}
    AS Number/Name: {dados.get('as', 'N/A')} / {dados.get('asname', 'N/A')}
    DNS Reverso: {dados.get('reverse', 'N/A')}
    
    [ Detecções ]
    Móvel: {'Sim' if dados.get('mobile') else 'Não'}
    Proxy: {'Sim' if dados.get('proxy') else 'Não'}
    Hosting: {'Sim' if dados.get('hosting') else 'Não'}
    """
    return formato

def main():
    mostrar_banner()
    
    if len(sys.argv) < 2:
        print("Uso: python ip.py <endereço_ip>")
        print("Exemplo: python ip.py 8.8.8.8")
        sys.exit(1)
    
    ip = sys.argv[1]
    print(f"\nConsultando informações para o IP: {ip}\n")
    
    dados = consultar_ip(ip)
    if dados:
        print(formatar_dados(dados))

if __name__ == "__main__":
    main()
