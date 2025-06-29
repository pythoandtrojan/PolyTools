#!/usr/bin/env python3

import requests
import sys
import json
import re
import socket
import time
from datetime import datetime
import os
import nmap  
import vulners 

class Cores:
    VERDE = "\033[92m"
    AMARELO = "\033[93m"
    VERMELHO = "\033[91m"
    AZUL = "\033[94m"
    MAGENTA = "\033[95m"
    CIANO = "\033[96m"
    RESET = "\033[0m"
    NEGRITO = "\033[1m"
    FUNDO_PRETO = "\033[40m"
    FUNDO_VERMELHO = "\033[41m"

def mostrar_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    banner = f"""
{Cores.AZUL}╔══════════════════════════════════════════╗
║          {Cores.NEGRITO}IP SCANNER COMPLETO{Cores.RESET}{Cores.AZUL}            ║
║                                              ║
║ {Cores.VERDE}• Consulta IP + Portas + Vulnerabilidades •{Cores.RESET}{Cores.AZUL} ║
╚══════════════════════════════════════════╝{Cores.RESET}
"""
    print(banner)

def mostrar_menu():
    print(f"""
{Cores.CIANO}╔════════════════ MENU ════════════════╗
║                                       ║
║  1. Consultar IP/ipv4/ipv6            ║
║  2. Modo interativo                   ║
║  3. Scanner Completo (IP+Portas+Vuln) ║
║  4. Sair                              ║
║                                       ║
╚════════════════════════════════════════╝{Cores.RESET}
""")

def limpar_tela():
    input("\nPressione Enter para continuar...")
    os.system('clear' if os.name == 'posix' else 'cls')

def validar_ip(ip):
    # IPv4
    padrao_ipv4 = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    # IPv6 (simplificado)
    padrao_ipv6 = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::|^([0-9a-fA-F]{1,4}:){0,6}:([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    
    return re.match(padrao_ipv4, ip) is not None or re.match(padrao_ipv6, ip) is not None

def resolver_dominio(dominio):
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror as e:
        print(f"{Cores.VERMELHO}[-] Erro ao resolver domínio: {e}{Cores.RESET}")
        return None
    except Exception as e:
        print(f"{Cores.VERMELHO}[-] Erro inesperado: {e}{Cores.RESET}")
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
        response = requests.get(url, proxies=proxies, timeout=15)
        tempo_resposta = time.time() - inicio
        
        if response.status_code != 200:
            raise Exception(f"Código HTTP {response.status_code}")
        
        dados = response.json()
        dados['tempo_resposta'] = round(tempo_resposta * 1000, 2)
        
        if dados.get('status') == 'fail':
            raise Exception(dados.get('message', 'Erro desconhecido na API'))
        
        return dados
    
    except requests.exceptions.Timeout:
        print(f"{Cores.VERMELHO}[-] Tempo de consulta excedido{Cores.RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{Cores.VERMELHO}[-] Erro na requisição: {e}{Cores.RESET}")
        return None
    except json.JSONDecodeError:
        print(f"{Cores.VERMELHO}[-] Resposta inválida da API{Cores.RESET}")
        return None
    except Exception as e:
        print(f"{Cores.VERMELHO}[-] Erro ao consultar o IP: {e}{Cores.RESET}")
        return None

def scan_portas(ip, portas="21-443", arguments="-sV"):
    """Realiza varredura de portas usando Nmap"""
    try:
        print(f"\n{Cores.AZUL}[+] Iniciando varredura de portas em {ip}...{Cores.RESET}")
        
        nm = nmap.PortScanner()
        inicio_scan = time.time()
        
        nm.scan(ip, portas, arguments=arguments)
        
        tempo_scan = time.time() - inicio_scan
        resultados = []
        
        if ip in nm.all_hosts():
            host = nm[ip]
            
            for proto in host.all_protocols():
                portas_abertas = host[proto].keys()
                
                for port in sorted(portas_abertas):
                    porta_info = {
                        'porta': port,
                        'protocolo': proto,
                        'estado': host[proto][port]['state'],
                        'servico': host[proto][port]['name'],
                        'versao': host[proto][port].get('version', 'desconhecida'),
                        'produto': host[proto][port].get('product', 'desconhecido')
                    }
                    resultados.append(porta_info)
        
        return {
            'tempo_scan': round(tempo_scan, 2),
            'portas_abertas': resultados
        }
    
    except nmap.PortScannerError as e:
        print(f"{Cores.VERMELHO}[-] Erro no Nmap: {e}{Cores.RESET}")
        return None
    except Exception as e:
        print(f"{Cores.VERMELHO}[-] Erro durante o scan: {e}{Cores.RESET}")
        return None

def verificar_vulnerabilidades(servico, versao):
    """Verifica vulnerabilidades conhecidas usando Vulners API"""
    try:
        if not servico or not versao:
            return None
            
        vulners_api = vulners.VulnersApi()
        resultados = vulners_api.softwareVulnerabilities(servico, versao)
        
        vulnerabilidades = []
        
        if resultados.get('cvelist'):
            for cve in resultados['cvelist']:
                vulnerabilidades.append({
                    'id': cve.get('id'),
                    'tipo': cve.get('type'),
                    'titulo': cve.get('title'),
                    'severidade': cve.get('cvss', {}).get('score', 0),
                    'descricao': cve.get('description'),
                    'referencia': cve.get('href')
                })
        
        return sorted(vulnerabilidades, key=lambda x: x['severidade'], reverse=True)[:5]  # Retorna as 5 mais críticas
    
    except Exception as e:
        print(f"{Cores.VERMELHO}[-] Erro ao verificar vulnerabilidades: {e}{Cores.RESET}")
        return None

def get_bandeira(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return chr(127397 + ord(country_code[0])) + chr(127397 + ord(country_code[1]))
    except:
        return ""

def detectar_dispositivo(isp):
    if not isp:
        return "Desconhecido"
    
    isp_lower = isp.lower()
    
    # Detecção de provedores móveis
    mobile_keywords = ['mobile', 'celular', 'wireless', '3g', '4g', '5g', 'lte']
    if any(keyword in isp_lower for keyword in mobile_keywords):
        return "Dispositivo Móvel"
    
    # Detecção de marcas específicas
    marcas = {
        'apple': 'Apple',
        'samsung': 'Samsung',
        'xiaomi': 'Xiaomi',
        'huawei': 'Huawei',
        'motorola': 'Motorola',
        'google': 'Google',
        'oneplus': 'OnePlus'
    }
    
    for marca, nome in marcas.items():
        if marca in isp_lower:
            return f"Possível {nome}"
    
    return "Desconhecido"

def formatar_dados(dados, scan_resultados=None):
    if not dados:
        return f"{Cores.VERMELHO}Nenhum dado disponível.{Cores.RESET}"
    
    
    mobile = f"{Cores.VERMELHO}Sim{Cores.RESET}" if dados.get('mobile') else f"{Cores.VERDE}Não{Cores.RESET}"
    proxy = f"{Cores.VERMELHO}Sim{Cores.RESET}" if dados.get('proxy') else f"{Cores.VERDE}Não{Cores.RESET}"
    hosting = f"{Cores.VERMELHO}Sim{Cores.RESET}" if dados.get('hosting') else f"{Cores.VERDE}Não{Cores.RESET}"
    
    bandeira = get_bandeira(dados.get('countryCode'))
    dispositivo = detectar_dispositivo(dados.get('isp'))
    
    formato = f"""
    {Cores.AZUL}┌───────────────────────────────┐{Cores.RESET}
    {Cores.AZUL}│{Cores.NEGRITO}  INFORMAÇÕES DO IP          {Cores.RESET}{Cores.AZUL}│{Cores.RESET}
    {Cores.AZUL}└───────────────────────────────┘{Cores.RESET}
    {Cores.CIANO}• IP:{Cores.RESET} {dados.get('query', 'N/A')}
    {Cores.CIANO}• Data/Hora:{Cores.RESET} {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
    {Cores.CIANO}• Tempo resposta:{Cores.RESET} {dados.get('tempo_resposta', 'N/A')} ms
    
    {Cores.AMARELO}┌───────────────────────────────┐{Cores.RESET}
    {Cores.AMARELO}│{Cores.NEGRITO}  LOCALIZAÇÃO               {Cores.RESET}{Cores.AMARELO}│{Cores.RESET}
    {Cores.AMARELO}└───────────────────────────────┘{Cores.RESET}
    {Cores.CIANO}• Continente:{Cores.RESET} {dados.get('continent', 'N/A')} ({dados.get('continentCode', 'N/A')})
    {Cores.CIANO}• País:{Cores.RESET} {bandeira} {dados.get('country', 'N/A')} ({dados.get('countryCode', 'N/A')})
    {Cores.CIANO}• Região:{Cores.RESET} {dados.get('regionName', 'N/A')} ({dados.get('region', 'N/A')})
    {Cores.CIANO}• Cidade:{Cores.RESET} {dados.get('city', 'N/A')}
    {Cores.CIANO}• Distrito:{Cores.RESET} {dados.get('district', 'N/A')}
    {Cores.CIANO}• CEP:{Cores.RESET} {dados.get('zip', 'N/A')}
    {Cores.CIANO}• Coordenadas:{Cores.RESET} Lat {dados.get('lat', 'N/A')}, Lon {dados.get('lon', 'N/A')}
    {Cores.CIANO}• Fuso Horário:{Cores.RESET} {dados.get('timezone', 'N/A')}
    {Cores.CIANO}• Moeda:{Cores.RESET} {dados.get('currency', 'N/A')}
    
    {Cores.AMARELO}┌───────────────────────────────┐{Cores.RESET}
    {Cores.AMARELO}│{Cores.NEGRITO}  REDE & DISPOSITIVO        {Cores.RESET}{Cores.AMARELO}│{Cores.RESET}
    {Cores.AMARELO}└───────────────────────────────┘{Cores.RESET}
    {Cores.CIANO}• ISP:{Cores.RESET} {dados.get('isp', 'N/A')}
    {Cores.CIANO}• Organização:{Cores.RESET} {dados.get('org', 'N/A')}
    {Cores.CIANO}• AS Number/Name:{Cores.RESET} {dados.get('as', 'N/A')} / {dados.get('asname', 'N/A')}
    {Cores.CIANO}• DNS Reverso:{Cores.RESET} {dados.get('reverse', 'N/A')}
    {Cores.CIANO}• Tipo Dispositivo:{Cores.RESET} {dispositivo}
    
    {Cores.AMARELO}┌───────────────────────────────┐{Cores.RESET}
    {Cores.AMARELO}│{Cores.NEGRITO}  DETECÇÕES DE SEGURANÇA    {Cores.RESET}{Cores.AMARELO}│{Cores.RESET}
    {Cores.AMARELO}└───────────────────────────────┘{Cores.RESET}
    {Cores.CIANO}• Móvel:{Cores.RESET} {mobile}
    {Cores.CIANO}• Proxy/VPN:{Cores.RESET} {proxy}
    {Cores.CIANO}• Hosting/Data Center:{Cores.RESET} {hosting}
    """
    

    if scan_resultados and scan_resultados.get('portas_abertas'):
        formato += f"""
    {Cores.VERMELHO}┌───────────────────────────────┐{Cores.RESET}
    {Cores.VERMELHO}│{Cores.NEGRITO}  PORTAS ABERTAS           {Cores.RESET}{Cores.VERMELHO}│{Cores.RESET}
    {Cores.VERMELHO}└───────────────────────────────┘{Cores.RESET}
    {Cores.CIANO}• Tempo de scan:{Cores.RESET} {scan_resultados.get('tempo_scan', 'N/A')} segundos
    {Cores.CIANO}• Portas encontradas:{Cores.RESET} {len(scan_resultados['portas_abertas']}
    """
        
        for porta in scan_resultados['portas_abertas']:
            formato += f"""
    {Cores.CIANO}┌ Porta:{Cores.RESET} {porta['porta']}/{porta['protocolo']} - {porta['estado']}
    {Cores.CIANO}├ Serviço:{Cores.RESET} {porta['servico']}
    {Cores.CIANO}├ Versão:{Cores.RESET} {porta['versao']}
    {Cores.CIANO}└ Produto:{Cores.RESET} {porta['produto']}
    """
            
        
            if porta['servico'] != 'unknown' and porta['versao'] != 'desconhecida':
                vulns = verificar_vulnerabilidades(porta['servico'], porta['versao'])
                if vulns:
                    formato += f"    {Cores.VERMELHO}  ! Vulnerabilidades conhecidas !{Cores.RESET}\n"
                    for vuln in vulns:
                        severidade = ""
                        if vuln['severidade'] >= 7.5:
                            severidade = f"{Cores.VERMELHO}CRÍTICA{Cores.RESET}"
                        elif vuln['severidade'] >= 5.0:
                            severidade = f"{Cores.AMARELO}ALTA{Cores.RESET}"
                        else:
                            severidade = f"{Cores.VERDE}MODERADA{Cores.RESET}"
                            
                        formato += f"""
    {Cores.CIANO}  ├─ {vuln['id']} ({severidade})
    {Cores.CIANO}  ├─ {vuln['titulo']}
    {Cores.CIANO}  └─ {vuln['referencia']}
    """
    
    return formato

def salvar_resultado(dados, scan_resultados=None, formato='txt'):
    if not dados:
        return False
    
    ip = dados.get('query', 'resultado')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"ip_scan_{ip}_{timestamp}.{formato}"
    
    try:
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato == 'json':
                resultado_completo = {
                    'informacoes_ip': dados,
                    'scan_portas': scan_resultados
                }
                json.dump(resultado_completo, f, indent=2, ensure_ascii=False)
            else:
                f.write(formatar_dados(dados, scan_resultados).replace(Cores.RESET, '').replace(Cores.NEGRITO, ''))
        print(f"{Cores.VERDE}[+] Resultado salvo em: {nome_arquivo}{Cores.RESET}")
        return True
    except PermissionError:
        print(f"{Cores.VERMELHO}[-] Permissão negada para salvar o arquivo{Cores.RESET}")
        return False
    except Exception as e:
        print(f"{Cores.VERMELHO}[-] Erro ao salvar resultado: {e}{Cores.RESET}")
        return False

def scanner_completo():
    entrada = input("Digite o IP ou domínio para scan completo: ").strip()
    if not entrada:
        print(f"{Cores.VERMELHO}[-] Nenhum valor informado{Cores.RESET}")
        return
    
    ip = entrada
    if not validar_ip(entrada):
        print(f"{Cores.AZUL}[+] Tentando resolver domínio...{Cores.RESET}")
        ip = resolver_dominio(entrada)
        if not ip:
            print(f"{Cores.VERMELHO}[-] Domínio inválido ou não resolvido{Cores.RESET}")
            return
        print(f"{Cores.AZUL}[+] Domínio resolvido para IP: {ip}{Cores.RESET}")
    
    print(f"\n{Cores.AZUL}[+] Iniciando consulta de informações...{Cores.RESET}")
    dados = consultar_ip(ip)
    
    if not dados:
        return
    
    print(f"\n{Cores.AZUL}[+] Iniciando varredura de portas...{Cores.RESET}")
    scan_resultados = scan_portas(ip, portas="1-1000", arguments="-sV -T4")
    
    if dados or scan_resultados:
        print(formatar_dados(dados, scan_resultados))
        
        while True:
            salvar = input("\nDeseja salvar o resultado? (s/n/txt/json): ").lower().strip()
            if salvar in ['s', 'sim', 't', 'txt']:
                salvar_resultado(dados, scan_resultados, 'txt')
                break
            elif salvar in ['j', 'json']:
                salvar_resultado(dados, scan_resultados, 'json')
                break
            elif salvar in ['n', 'não', 'nao']:
                break
            else:
                print(f"{Cores.VERMELHO}Opção inválida. Use s/n/txt/json{Cores.RESET}")

def consulta_unica():
    entrada = input("Digite o IP ou domínio: ").strip()
    if not entrada:
        print(f"{Cores.VERMELHO}[-] Nenhum valor informado{Cores.RESET}")
        return
    
    ip = entrada
    if not validar_ip(entrada):
        print(f"{Cores.AZUL}[+] Tentando resolver domínio...{Cores.RESET}")
        ip = resolver_dominio(entrada)
        if not ip:
            print(f"{Cores.VERMELHO}[-] Domínio inválido ou não resolvido{Cores.RESET}")
            return
        print(f"{Cores.AZUL}[+] Domínio resolvido para IP: {ip}{Cores.RESET}")
    
    print(f"{Cores.AZUL}[+] Consultando informações...{Cores.RESET}")
    dados = consultar_ip(ip)
    
    if dados:
        print(formatar_dados(dados))
        
        while True:
            salvar = input("Deseja salvar o resultado? (s/n/txt/json): ").lower().strip()
            if salvar in ['s', 'sim', 't', 'txt']:
                salvar_resultado(dados, None, 'txt')
                break
            elif salvar in ['j', 'json']:
                salvar_resultado(dados, None, 'json')
                break
            elif salvar in ['n', 'não', 'nao']:
                break
            else:
                print(f"{Cores.VERMELHO}Opção inválida. Use s/n/txt/json{Cores.RESET}")

def modo_interativo():
    while True:
        try:
            print(f"\n{Cores.CIANO}Modo Interativo (digite 'sair' para encerrar){Cores.RESET}")
            entrada = input("Digite IP ou domínio (ou 'scan' para modo completo): ").strip()
            
            if entrada.lower() in ['sair', 'exit', 'quit']:
                break
                
            if not entrada:
                continue
                
            if entrada.lower() == 'scan':
                scanner_completo()
                limpar_tela()
                continue
                
            ip = entrada
            if not validar_ip(entrada):
                print(f"{Cores.AZUL}[+] Tentando resolver domínio...{Cores.RESET}")
                ip = resolver_dominio(entrada)
                if not ip:
                    print(f"{Cores.VERMELHO}[-] Domínio inválido ou não resolvido{Cores.RESET}")
                    continue
                print(f"{Cores.AZUL}[+] Domínio resolvido para IP: {ip}{Cores.RESET}")
            
            print(f"{Cores.AZUL}[+] Consultando informações...{Cores.RESET}")
            dados = consultar_ip(ip)
            
            if dados:
                print(formatar_dados(dados))
                
                while True:
                    salvar = input("Salvar resultado? (s/n/txt/json): ").lower().strip()
                    if salvar in ['s', 'sim', 't', 'txt']:
                        salvar_resultado(dados, None, 'txt')
                        break
                    elif salvar in ['j', 'json']:
                        salvar_resultado(dados, None, 'json')
                        break
                    elif salvar in ['n', 'não', 'nao']:
                        break
                    else:
                        print(f"{Cores.VERMELHO}Opção inválida. Use s/n/txt/json{Cores.RESET}")
            
            limpar_tela()
            
        except KeyboardInterrupt:
            print(f"\n{Cores.VERMELHO}Operação interrompida pelo usuário{Cores.RESET}")
            break
        except Exception as e:
            print(f"{Cores.VERMELHO}[-] Erro inesperado: {e}{Cores.RESET}")
            continue

def main():
    mostrar_banner()
    
    if len(sys.argv) > 1:
        
        ips = []
        usar_proxy = False
        salvar_json = False
        salvar_txt = False
        scan_completo = False
        
        try:
            for arg in sys.argv[1:]:
                if arg in ['-p', '--proxy']:
                    usar_proxy = True
                elif arg in ['-j', '--json']:
                    salvar_json = True
                elif arg in ['-t', '--txt']:
                    salvar_txt = True
                elif arg in ['-s', '--scan']:
                    scan_completo = True
                elif arg in ['-h', '--help']:
                    print(f"""
Uso:
  {sys.argv[0]} [OPÇÕES] <IP1 IP2...|domínio>
  
Opções:
  -p, --proxy    Usar proxy Tor (requer Tor em execução)
  -j, --json     Salvar resultado em JSON
  -t, --txt      Salvar resultado em TXT
  -s, --scan     Executar scan completo (IP + Portas + Vulnerabilidades)
  -h, --help     Mostrar esta ajuda
                    """)
                    sys.exit(0)
                elif validar_ip(arg) or '.' in arg or ':' in arg:
                    if not validar_ip(arg):
                        ip = resolver_dominio(arg)
                        if ip:
                            print(f"{Cores.AZUL}[+] Domínio '{arg}' resolvido para IP: {ip}{Cores.RESET}")
                            ips.append(ip)
                        else:
                            print(f"{Cores.VERMELHO}[-] Domínio inválido ou não resolvido: {arg}{Cores.RESET}")
                    else:
                        ips.append(arg)
            
            if not ips:
                print(f"{Cores.VERMELHO}Nenhum IP válido fornecido.{Cores.RESET}")
                sys.exit(1)
            
            for ip in ips:
                if scan_completo:
                    print(f"\n{Cores.CIANO}Executando scan completo em: {ip}{Cores.RESET}")
                    
                    dados = consultar_ip(ip, usar_proxy)
                    scan_resultados = scan_portas(ip, portas="1-1000", arguments="-sV -T4")
                    
                    print(formatar_dados(dados, scan_resultados))
                    
                    if salvar_txt:
                        salvar_resultado(dados, scan_resultados, 'txt')
                    if salvar_json:
                        salvar_resultado(dados, scan_resultados, 'json')
                else:
                    print(f"\n{Cores.CIANO}Consultando informações para: {ip}{Cores.RESET}")
                    
                    dados = consultar_ip(ip, usar_proxy)
                    if dados:
                        print(formatar_dados(dados))
                        
                        if salvar_txt:
                            salvar_resultado(dados, None, 'txt')
                        if salvar_json:
                            salvar_resultado(dados, None, 'json')
            
            limpar_tela()
        
        except KeyboardInterrupt:
            print(f"\n{Cores.VERMELHO}Operação interrompida pelo usuário{Cores.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Cores.VERMELHO}[-] Erro inesperado: {e}{Cores.RESET}")
            sys.exit(1)
    else:

        while True:
            mostrar_banner()
            mostrar_menu()
            opcao = input("Selecione uma opção: ")
            
            if opcao == '1':
                mostrar_banner()
                consulta_unica()
                limpar_tela()
            elif opcao == '2':
                mostrar_banner()
                modo_interativo()
            elif opcao == '3':
                mostrar_banner()
                scanner_completo()
                limpar_tela()
            elif opcao == '4':
                print(f"\n{Cores.VERDE}Encerrando o programa...{Cores.RESET}")
                break
            else:
                print(f"\n{Cores.VERMELHO}Opção inválida!{Cores.RESET}")
                time.sleep(1)

if __name__ == "__main__":
    
    try:
        nmap.PortScanner()
    except:
        print(f"{Cores.VERMELHO}[-] Nmap não encontrado. Por favor, instale o Nmap para usar todas as funcionalidades.{Cores.RESET}")
    
    try:
        vulners.VulnersApi()
    except:
        print(f"{Cores.AMARELO}[!] Vulners API não configurada. Algumas verificações de vulnerabilidade podem não funcionar.{Cores.RESET}")
    
    main()
