#!/usr/bin/env python3
import requests
import re
import os
import json
import concurrent.futures
from datetime import datetime
from urllib.parse import quote
import time
import hashlib
import socket
import threading

# Cores para terminal
class Cores:
    VERDE = '\033[92m'
    VERMELHO = '\033[91m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    MAGENTA = '\033[95m'
    CIANO = '\033[96m'
    BRANCO = '\033[97m'
    NEGRITO = '\033[1m'
    RESET = '\033[0m'

# Configurações
os.makedirs('cache_ip', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# APIs de consulta IP
APIS = {
    'IPInfo': {
        'url': "https://ipinfo.io/{ip}/json",
        'fields': {
            'ip': 'ip',
            'hostname': 'hostname',
            'cidade': 'city',
            'regiao': 'region',
            'pais': 'country',
            'localizacao': 'loc',
            'organizacao': 'org',
            'timezone': 'timezone',
            'servico': 'IPInfo'
        }
    },
    'IPAPI': {
        'url': "http://ip-api.com/json/{ip}",
        'fields': {
            'ip': 'query',
            'pais': 'country',
            'codigo_pais': 'countryCode',
            'regiao': 'regionName',
            'cidade': 'city',
            'cep': 'zip',
            'latitude': 'lat',
            'longitude': 'lon',
            'timezone': 'timezone',
            'isp': 'isp',
            'organizacao': 'org',
            'asn': 'as',
            'status': 'status',
            'servico': 'IPAPI'
        }
    },
    'IPWhoIs': {
        'url': "https://ipwho.is/{ip}",
        'fields': {
            'ip': 'ip',
            'tipo': 'type',
            'continente': 'continent',
            'pais': 'country',
            'regiao': 'region',
            'cidade': 'city',
            'latitude': 'latitude',
            'longitude': 'longitude',
            'asn_numero': 'asn.asn',
            'asn_nome': 'asn.name',
            'asn_dominio': 'asn.domain',
            'asn_rota': 'asn.route',
            'asn_tipo': 'asn.type',
            'timezone_id': 'timezone.id',
            'timezone_atual': 'timezone.current_time',
            'sucesso': 'success',
            'servico': 'IPWhoIs'
        }
    }
}

# Portas comuns para scan
PORTAS_COMUNS = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
██╗██████╗ ██╗   ██╗██╗  ██╗        ██╗    ██╗██████╗ ██╗   ██╗ ██████╗ 
██║██╔══██╗██║   ██║██║  ██║       ██╔╝    ██║██╔══██╗██║   ██║██╔════╝ 
██║██████╔╝██║   ██║███████║      ██╔╝     ██║██████╔╝██║   ██║███████╗ 
██║██╔═══╝ ╚██╗ ██╔╝╚════██║     ██╔╝      ██║██╔═══╝ ╚██╗ ██╔╝██╔═══██╗
██║██║      ╚████╔╝      ██║    ██╔╝       ██║██║      ╚████╔╝ ╚██████╔╝
╚═╝╚═╝       ╚═══╝       ╚═╝    ╚═╝        ╚═╝╚═╝       ╚═══╝   ╚═════╝ 
                                                                        
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   CONSULTOR DE IP AVANÇADO
   Geolocalização + Port Scan
{Cores.RESET}
{Cores.AMARELO}   Múltiplas APIs + Google Maps + Scan Portas
   Cache Inteligente
{Cores.RESET}""")

def validar_ip(ip):
    """Valida formato do endereço IP"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_ip/{nome}.json"
        if dados is not None:  # Modo escrita
            with open(caminho, 'w', encoding='utf-8') as f:
                json.dump({'data': dados, 'timestamp': time.time()}, f)
            return dados
        else:  # Modo leitura
            if os.path.exists(caminho):
                with open(caminho, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                    if time.time() - cache['timestamp'] < TEMPO_CACHE:
                        return cache['data']
        return None
    except (IOError, json.JSONDecodeError):
        return None

def consultar_ipinfo(ip):
    """Consulta específica para IPInfo API"""
    cache_id = f"ipinfo_{ip}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and 'ip' in dados:
                resultado = {
                    'ip': dados.get('ip', ''),
                    'hostname': dados.get('hostname', ''),
                    'cidade': dados.get('city', ''),
                    'regiao': dados.get('region', ''),
                    'pais': dados.get('country', ''),
                    'localizacao': dados.get('loc', ''),
                    'organizacao': dados.get('org', ''),
                    'timezone': dados.get('timezone', ''),
                    'servico': 'IPInfo'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    return None

def consultar_ipapi(ip):
    """Consulta específica para IP-API"""
    cache_id = f"ipapi_{ip}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"http://ip-api.com/json/{ip}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and dados.get('status') == 'success':
                resultado = {
                    'ip': dados.get('query', ''),
                    'pais': dados.get('country', ''),
                    'codigo_pais': dados.get('countryCode', ''),
                    'regiao': dados.get('regionName', ''),
                    'cidade': dados.get('city', ''),
                    'cep': dados.get('zip', ''),
                    'latitude': dados.get('lat', ''),
                    'longitude': dados.get('lon', ''),
                    'timezone': dados.get('timezone', ''),
                    'isp': dados.get('isp', ''),
                    'organizacao': dados.get('org', ''),
                    'asn': dados.get('as', ''),
                    'status': dados.get('status', ''),
                    'servico': 'IPAPI'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    return None

def consultar_ipwhois(ip):
    """Consulta específica para IPWhoIs"""
    cache_id = f"ipwhois_{ip}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://ipwho.is/{ip}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and dados.get('success'):
                resultado = {
                    'ip': dados.get('ip', ''),
                    'tipo': dados.get('type', ''),
                    'continente': dados.get('continent', ''),
                    'pais': dados.get('country', ''),
                    'regiao': dados.get('region', ''),
                    'cidade': dados.get('city', ''),
                    'latitude': dados.get('latitude', ''),
                    'longitude': dados.get('longitude', ''),
                    'asn_numero': dados.get('asn', {}).get('asn', ''),
                    'asn_nome': dados.get('asn', {}).get('name', ''),
                    'asn_dominio': dados.get('asn', {}).get('domain', ''),
                    'asn_rota': dados.get('asn', {}).get('route', ''),
                    'asn_tipo': dados.get('asn', {}).get('type', ''),
                    'timezone_id': dados.get('timezone', {}).get('id', ''),
                    'timezone_atual': dados.get('timezone', {}).get('current_time', ''),
                    'sucesso': dados.get('success', ''),
                    'servico': 'IPWhoIs'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    return None

def consultar_apis_paralelo(ip):
    """Consulta todas as APIs em paralelo"""
    if not validar_ip(ip):
        return {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(consultar_ipinfo, ip): 'IPInfo',
            executor.submit(consultar_ipapi, ip): 'IPAPI',
            executor.submit(consultar_ipwhois, ip): 'IPWhoIs'
        }
        
        resultados = {}
        for future in concurrent.futures.as_completed(futures):
            nome_api = futures[future]
            try:
                resultado = future.result()
                if resultado:
                    resultados[nome_api] = resultado
            except Exception:
                pass
    
    return resultados

def testar_porta(ip, porta, timeout=2):
    """Testa se uma porta está aberta"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))
            return resultado == 0
    except:
        return False

def scan_portas(ip, portas):
    """Faz scan de portas de forma paralela"""
    print(f"{Cores.AMARELO}[*] Scaneando {len(portas)} portas em {ip}...{Cores.RESET}")
    
    portas_abertas = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(testar_porta, ip, porta): porta for porta in portas}
        
        for future in concurrent.futures.as_completed(futures):
            porta = futures[future]
            try:
                if future.result():
                    portas_abertas.append(porta)
                    print(f"{Cores.VERDE}[+] Porta {porta} aberta{Cores.RESET}")
            except:
                pass
    
    return sorted(portas_abertas)

def obter_servico_porta(porta):
    """Retorna o serviço comum associado à porta"""
    servicos = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3306: "MySQL", 5432: "PostgreSQL",
        27017: "MongoDB", 6379: "Redis", 11211: "Memcached"
    }
    return servicos.get(porta, "Desconhecido")

def gerar_link_google_maps(lat, lng):
    """Gera link para Google Maps com as coordenadas"""
    if lat and lng:
        return f"https://www.google.com/maps?q={lat},{lng}&z=15"
    return None

def exibir_resultado_individual(api_nome, dados):
    """Exibe resultados individuais de cada API"""
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== {api_nome} ==={Cores.RESET}")
    
    if not dados:
        print(f"{Cores.VERMELHO}  Nenhum dado retornado{Cores.RESET}")
        return
    
    if 'ip' in dados:
        print(f"{Cores.AZUL}  IP:{Cores.RESET} {dados['ip']}")
    
    if api_nome == 'IPInfo':
        if 'hostname' in dados and dados['hostname']:
            print(f"{Cores.AZUL}  Hostname:{Cores.RESET} {dados['hostname']}")
        if 'cidade' in dados and dados['cidade'] and 'regiao' in dados and dados['regiao']:
            print(f"{Cores.AZUL}  Localização:{Cores.RESET} {dados['cidade']}, {dados['regiao']}")
        if 'pais' in dados and dados['pais']:
            print(f"{Cores.AZUL}  País:{Cores.RESET} {dados['pais']}")
        if 'organizacao' in dados and dados['organizacao']:
            print(f"{Cores.AZUL}  Organização:{Cores.RESET} {dados['organizacao']}")
        if 'localizacao' in dados and dados['localizacao']:
            lat, lng = dados['localizacao'].split(',')
            maps_link = gerar_link_google_maps(lat, lng)
            print(f"{Cores.AZUL}  Coordenadas:{Cores.RESET} {dados['localizacao']}")
            if maps_link:
                print(f"{Cores.AZUL}  Google Maps:{Cores.RESET} {Cores.CIANO}{maps_link}{Cores.RESET}")
    
    elif api_nome == 'IPAPI':
        if 'cidade' in dados and dados['cidade'] and 'regiao' in dados and dados['regiao']:
            print(f"{Cores.AZUL}  Localização:{Cores.RESET} {dados['cidade']}, {dados['regiao']}")
        if 'pais' in dados and dados['pais']:
            print(f"{Cores.AZUL}  País:{Cores.RESET} {dados['pais']}")
        if 'isp' in dados and dados['isp']:
            print(f"{Cores.AZUL}  ISP:{Cores.RESET} {dados['isp']}")
        if 'asn' in dados and dados['asn']:
            print(f"{Cores.AZUL}  ASN:{Cores.RESET} {dados['asn']}")
        if 'latitude' in dados and 'longitude' in dados:
            maps_link = gerar_link_google_maps(dados['latitude'], dados['longitude'])
            print(f"{Cores.AZUL}  Coordenadas:{Cores.RESET} {dados['latitude']}, {dados['longitude']}")
            if maps_link:
                print(f"{Cores.AZUL}  Google Maps:{Cores.RESET} {Cores.CIANO}{maps_link}{Cores.RESET}")
    
    elif api_nome == 'IPWhoIs':
        if 'continente' in dados and dados['continente']:
            print(f"{Cores.AZUL}  Continente:{Cores.RESET} {dados['continente']}")
        if 'cidade' in dados and dados['cidade'] and 'regiao' in dados and dados['regiao']:
            print(f"{Cores.AZUL}  Localização:{Cores.RESET} {dados['cidade']}, {dados['regiao']}")
        if 'pais' in dados and dados['pais']:
            print(f"{Cores.AZUL}  País:{Cores.RESET} {dados['pais']}")
        if 'asn_nome' in dados and dados['asn_nome']:
            print(f"{Cores.AZUL}  ASN:{Cores.RESET} {dados['asn_nome']} ({dados.get('asn_numero', '')})")
        if 'latitude' in dados and 'longitude' in dados:
            maps_link = gerar_link_google_maps(dados['latitude'], dados['longitude'])
            print(f"{Cores.AZUL}  Coordenadas:{Cores.RESET} {dados['latitude']}, {dados['longitude']}")
            if maps_link:
                print(f"{Cores.AZUL}  Google Maps:{Cores.RESET} {Cores.CIANO}{maps_link}{Cores.RESET}")

def exibir_resultados_combinados(resultados, ip):
    """Exibe resumo combinado dos dados"""
    if not resultados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para este IP{Cores.RESET}")
        return
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== DADOS COMBINADOS (RESUMO) ==={Cores.RESET}")
    print(f"{Cores.AZUL}Endereço IP:{Cores.RESET} {ip}")
    
    # Combinar localização
    localizacao = None
    coordenadas = None
    
    for api in ['IPInfo', 'IPAPI', 'IPWhoIs']:
        if api in resultados:
            dados = resultados[api]
            if not localizacao and 'cidade' in dados and dados['cidade']:
                cidade = dados['cidade']
                regiao = dados.get('regiao', '')
                pais = dados.get('pais', dados.get('codigo_pais', ''))
                localizacao = f"{cidade}, {regiao}, {pais}"
            
            if not coordenadas:
                if 'localizacao' in dados and dados['localizacao']:
                    coordenadas = dados['localizacao']
                elif 'latitude' in dados and 'longitude' in dados:
                    coordenadas = f"{dados['latitude']}, {dados['longitude']}"
            break
    
    if localizacao:
        print(f"{Cores.AZUL}Localização:{Cores.RESET} {localizacao}")
    
    # Combinar organização/ISP
    organizacao = None
    for api in ['IPInfo', 'IPAPI', 'IPWhoIs']:
        if api in resultados:
            dados = resultados[api]
            if not organizacao:
                organizacao = dados.get('organizacao') or dados.get('isp') or dados.get('asn_nome')
            if organizacao:
                break
    
    if organizacao:
        print(f"{Cores.AZUL}Organização:{Cores.RESET} {organizacao}")
    
    # Link do Google Maps
    if coordenadas:
        # Extrair lat e lng das coordenadas
        if ',' in coordenadas:
            partes = coordenadas.split(',')
            if len(partes) == 2:
                lat = partes[0].strip()
                lng = partes[1].strip()
                maps_link = gerar_link_google_maps(lat, lng)
                if maps_link:
                    print(f"\n{Cores.CIANO}{Cores.NEGRITO}🗺️  LOCALIZAÇÃO NO GOOGLE MAPS:{Cores.RESET}")
                    print(f"{Cores.VERDE}{Cores.NEGRITO}{maps_link}{Cores.RESET}")
    
    print(f"{Cores.AZUL}APIs com resposta:{Cores.RESET} {len(resultados)}/3")

def exibir_portas_abertas(portas_abertas):
    """Exibe as portas abertas encontradas"""
    if not portas_abertas:
        print(f"{Cores.VERMELHO}[!] Nenhuma porta aberta encontrada{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== PORTAS ABERTAS ENCONTRADAS ==={Cores.RESET}")
    for porta in portas_abertas:
        servico = obter_servico_porta(porta)
        print(f"{Cores.VERDE}✓ Porta {porta:5} - {servico}{Cores.RESET}")

def combinar_dados(resultados):
    """Combina dados de todas as APIs para exportação"""
    if not resultados:
        return None
    
    combinado = {
        'ip': '',
        'localizacao': {},
        'rede': {},
        'apis_responderam': list(resultados.keys()),
        'total_apis': len(resultados)
    }
    
    # Combinar dados de todas as APIs
    for api, dados in resultados.items():
        if not combinado['ip'] and 'ip' in dados:
            combinado['ip'] = dados['ip']
        
        # Localização
        if 'cidade' in dados and dados['cidade'] and not combinado['localizacao'].get('cidade'):
            combinado['localizacao']['cidade'] = dados['cidade']
        if 'regiao' in dados and dados['regiao'] and not combinado['localizacao'].get('regiao'):
            combinado['localizacao']['regiao'] = dados['regiao']
        if 'pais' in dados and dados['pais'] and not combinado['localizacao'].get('pais'):
            combinado['localizacao']['pais'] = dados['pais']
        if 'latitude' in dados and 'longitude' in dados and not combinado['localizacao'].get('coordenadas'):
            combinado['localizacao']['coordenadas'] = f"{dados['latitude']},{dados['longitude']}"
        
        # Rede
        if 'organizacao' in dados and dados['organizacao'] and not combinado['rede'].get('organizacao'):
            combinado['rede']['organizacao'] = dados['organizacao']
        if 'isp' in dados and dados['isp'] and not combinado['rede'].get('isp'):
            combinado['rede']['isp'] = dados['isp']
        if 'asn' in dados and dados['asn'] and not combinado['rede'].get('asn'):
            combinado['rede']['asn'] = dados['asn']
    
    return combinado

def salvar_resultado(dados, portas_abertas, ip, formato='txt'):
    if not dados:
        return False
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_ip', exist_ok=True)
        nome_arquivo = f"resultados_ip/ip_{ip}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                resultado_completo = {
                    'dados': dados,
                    'portas_abertas': portas_abertas,
                    'timestamp': timestamp
                }
                json.dump(resultado_completo, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== CONSULTA IP {ip} ===\n\n")
                f.write(f"IP: {dados.get('ip', 'N/A')}\n")
                
                if dados.get('localizacao'):
                    loc = dados['localizacao']
                    if loc.get('cidade') and loc.get('regiao'):
                        f.write(f"Localização: {loc['cidade']}, {loc['regiao']}, {loc.get('pais', '')}\n")
                    if loc.get('coordenadas'):
                        f.write(f"Coordenadas: {loc['coordenadas']}\n")
                        maps_link = gerar_link_google_maps(*loc['coordenadas'].split(','))
                        if maps_link:
                            f.write(f"Google Maps: {maps_link}\n")
                
                if dados.get('rede'):
                    rede = dados['rede']
                    if rede.get('organizacao'):
                        f.write(f"Organização: {rede['organizacao']}\n")
                    if rede.get('isp'):
                        f.write(f"ISP: {rede['isp']}\n")
                    if rede.get('asn'):
                        f.write(f"ASN: {rede['asn']}\n")
                
                f.write(f"\nAPIs: {', '.join(dados.get('apis_responderam', []))}\n")
                f.write(f"Total APIs: {dados.get('total_apis', 0)}/3\n")
                
                if portas_abertas:
                    f.write(f"\n=== PORTAS ABERTAS ({len(portas_abertas)}) ===\n")
                    for porta in portas_abertas:
                        servico = obter_servico_porta(porta)
                        f.write(f"Porta {porta}: {servico}\n")
                
                f.write(f"\nDATA: {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar IP")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR DE IP AVANÇADO{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Consulta em 3 APIs públicas simultaneamente
- Geolocalização precisa com coordenadas
- Links diretos para Google Maps
- Scan de portas abertas
- Identificação de serviços
- Cache inteligente para performance

{Cores.AMARELO}APIs utilizadas:{Cores.RESET}
- IPInfo.io - Dados completos + localização
- IP-API.com - Informações de rede + ISP
- IPWho.is - Dados técnicos + ASN

{Cores.AMARELO}Portas verificadas:{Cores.RESET}
- 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP)
- 53 (DNS), 80 (HTTP), 110 (POP3), 443 (HTTPS)
- 993 (IMAPS), 995 (POP3S), 8080, 8443

{Cores.AMARELO}Informações obtidas:{Cores.RESET}
- Localização geográfica (cidade, região, país)
- Coordenadas GPS (latitude, longitude)
- ISP e organização responsável
- Número ASN e informações de rede
- Hostname reverso
- Portas abertas e serviços

{Cores.VERDE}Pressione Enter para voltar...{Cores.RESET}""")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                try:
                    ip = input(f"\n{Cores.CIANO}Digite o endereço IP: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not validar_ip(ip):
                    print(f"{Cores.VERMELHO}[!] IP inválido. Use formato IPv4.{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"\n{Cores.AMARELO}[*] Consultando IP {ip} em 3 APIs...{Cores.RESET}")
                
                # Consultar APIs em paralelo
                resultados = consultar_apis_paralelo(ip)
                dados_combinados = combinar_dados(resultados)
                
                banner()
                print(f"{Cores.VERDE}{Cores.NEGRITO}RESULTADOS PARA IP {ip}{Cores.RESET}")
                
                # Exibir resultados individuais de cada API
                for api_nome in ['IPInfo', 'IPAPI', 'IPWhoIs']:
                    exibir_resultado_individual(api_nome, resultados.get(api_nome))
                
                # Exibir dados combinados
                exibir_resultados_combinados(resultados, ip)
                
                # Scan de portas
                try:
                    scan = input(f"\n{Cores.CIANO}Deseja escanear portas? (S/N): {Cores.RESET}").strip().lower()
                    if scan in ['s', 'sim', 'y', 'yes']:
                        portas_abertas = scan_portas(ip, PORTAS_COMUNS)
                        exibir_portas_abertas(portas_abertas)
                    else:
                        portas_abertas = []
                except (EOFError, KeyboardInterrupt):
                    portas_abertas = []
                
                # Opção de exportação
                if dados_combinados:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(dados_combinados, portas_abertas, ip, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(dados_combinados, portas_abertas, ip, 'txt')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '2':
                sobre()
            
            elif opcao == '3':
                print(f"\n{Cores.VERDE}[+] Saindo...{Cores.RESET}")
                break
            
            else:
                print(f"{Cores.VERMELHO}[!] Opção inválida!{Cores.RESET}")
                try:
                    input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
    
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Programa interrompido{Cores.RESET}")
    except Exception as e:
        print(f"\n{Cores.VERMELHO}[!] Erro fatal: {str(e)}{Cores.RESET}")
    finally:
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor de IP Avançado!{Cores.RESET}")

if __name__ == "__main__":
    main()
