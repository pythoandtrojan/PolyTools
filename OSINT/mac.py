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
os.makedirs('cache_mac', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# APIs de consulta MAC
APIS = {
    'MacLookup': {
        'url': "https://api.maclookup.app/v2/macs/{mac}",
        'fields': {
            'empresa': 'company',
            'endereco': 'address',
            'pais': 'country',
            'prefixo_mac': 'macPrefix',
            'inicio_bloco': 'blockStart',
            'fim_bloco': 'blockEnd',
            'tamanho_bloco': 'blockSize',
            'tipo_bloco': 'blockType',
            'atualizado': 'updated',
            'aleatorio': 'isRand',
            'privado': 'isPrivate',
            'sucesso': 'success',
            'encontrado': 'found',
            'servico': 'MacLookup'
        }
    },
    'MacVendors': {
        'url': "https://api.macvendors.com/{mac}",
        'fields': {
            'empresa': 'raw',  # Esta API retorna apenas o nome direto
            'servico': 'MacVendors'
        }
    },
    'MacAddressIO': {
        'url': "https://api.macaddress.io/v1?apiKey=at_Xe1qYb4Ht5t6h6G2h8Cw5aNvOGSI&output=json&search={mac}",
        'fields': {
            'empresa': 'vendorDetails.companyName',
            'endereco': 'vendorDetails.companyAddress',
            'pais': 'vendorDetails.countryCode',
            'prefixo_mac': 'macAddressDetails.searchTerm',
            'tipo_bloco': 'macAddressDetails.transmissionType',
            'administrativo': 'macAddressDetails.adminType',
            'servico': 'MacAddressIO'
        }
    }
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ███╗   ███╗ █████╗  ██████╗
   ████╗ ████║██╔══██╗██╔════╝
   ██╔████╔██║███████║██║     
   ██║╚██╔╝██║██╔══██║██║     
   ██║ ╚═╝ ██║██║  ██║╚██████╗
   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   CONSULTOR DE ENDEREÇO MAC
   Identificação de Fabricantes
{Cores.RESET}
{Cores.AMARELO}   Múltiplas APIs + Dados Combinados
   Cache Inteligente
{Cores.RESET}""")

def validar_mac(mac):
    """Valida formato do endereço MAC"""
    if not mac or not isinstance(mac, str):
        return False
    
    # Remove separadores e verifica se tem 12 caracteres hexadecimais
    mac_limpo = re.sub(r'[^0-9A-Fa-f]', '', mac)
    return len(mac_limpo) == 12

def formatar_mac(mac):
    """Formata o MAC para exibição padrão"""
    if not mac:
        return ""
    
    mac_limpo = re.sub(r'[^0-9A-Fa-f]', '', mac)
    if len(mac_limpo) == 12:
        return ':'.join(mac_limpo[i:i+2] for i in range(0, 12, 2)).upper()
    return mac.upper()

def normalizar_mac(mac):
    """Normaliza o MAC para uso nas APIs (sem separadores)"""
    if not mac:
        return ""
    
    mac_limpo = re.sub(r'[^0-9A-Fa-f]', '', mac)
    return mac_limpo.upper() if len(mac_limpo) == 12 else mac.upper()

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_mac/{nome}.json"
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

def consultar_maclookup(mac):
    """Consulta específica para MacLookup API"""
    cache_id = f"maclookup_{mac}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and dados.get('success') and dados.get('found'):
                resultado = {
                    'empresa': dados.get('company', ''),
                    'endereco': dados.get('address', ''),
                    'pais': dados.get('country', ''),
                    'prefixo_mac': dados.get('macPrefix', ''),
                    'inicio_bloco': dados.get('blockStart', ''),
                    'fim_bloco': dados.get('blockEnd', ''),
                    'tamanho_bloco': dados.get('blockSize', ''),
                    'tipo_bloco': dados.get('blockType', ''),
                    'atualizado': dados.get('updated', ''),
                    'aleatorio': dados.get('isRand', False),
                    'privado': dados.get('isPrivate', False),
                    'servico': 'MacLookup'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    return None

def consultar_macvendors(mac):
    """Consulta específica para MacVendors API"""
    cache_id = f"macvendors_{mac}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.macvendors.com/{mac}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            empresa = response.text.strip()
            if empresa and not empresa.startswith('Not Found'):
                resultado = {
                    'empresa': empresa,
                    'servico': 'MacVendors'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, ValueError):
        pass
    return None

def consultar_macaddressio(mac):
    """Consulta específica para MacAddress.io API"""
    cache_id = f"macaddressio_{mac}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        # API key pública (pode ter limitações)
        url = f"https://api.macaddress.io/v1?apiKey=at_Xe1qYb4Ht5t6h6G2h8Cw5aNvOGSI&output=json&search={mac}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and 'vendorDetails' in dados:
                vendor = dados['vendorDetails']
                resultado = {
                    'empresa': vendor.get('companyName', ''),
                    'endereco': vendor.get('companyAddress', ''),
                    'pais': vendor.get('countryCode', ''),
                    'prefixo_mac': dados.get('macAddressDetails', {}).get('searchTerm', ''),
                    'tipo_bloco': dados.get('macAddressDetails', {}).get('transmissionType', ''),
                    'administrativo': dados.get('macAddressDetails', {}).get('adminType', ''),
                    'servico': 'MacAddressIO'
                }
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    return None

def consultar_apis_paralelo(mac):
    """Consulta todas as APIs em paralelo"""
    if not validar_mac(mac):
        return {}
    
    mac_normalizado = normalizar_mac(mac)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(consultar_maclookup, mac_normalizado): 'MacLookup',
            executor.submit(consultar_macvendors, mac_normalizado): 'MacVendors',
            executor.submit(consultar_macaddressio, mac_normalizado): 'MacAddressIO'
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

def exibir_resultado_individual(api_nome, dados):
    """Exibe resultados individuais de cada API"""
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== {api_nome} ==={Cores.RESET}")
    
    if not dados:
        print(f"{Cores.VERMELHO}  Nenhum dado retornado{Cores.RESET}")
        return
    
    if 'empresa' in dados and dados['empresa']:
        print(f"{Cores.AZUL}  Fabricante:{Cores.RESET} {Cores.VERDE}{dados['empresa']}{Cores.RESET}")
    
    if api_nome == 'MacLookup':
        if 'endereco' in dados and dados['endereco']:
            print(f"{Cores.AZUL}  Endereço:{Cores.RESET} {dados['endereco']}")
        if 'pais' in dados and dados['pais']:
            print(f"{Cores.AZUL}  País:{Cores.RESET} {dados['pais']}")
        if 'prefixo_mac' in dados and dados['prefixo_mac']:
            print(f"{Cores.AZUL}  Prefixo MAC:{Cores.RESET} {dados['prefixo_mac']}")
        if 'tipo_bloco' in dados and dados['tipo_bloco']:
            print(f"{Cores.AZUL}  Tipo Bloco:{Cores.RESET} {dados['tipo_bloco']}")
        if 'atualizado' in dados and dados['atualizado']:
            print(f"{Cores.AZUL}  Atualizado:{Cores.RESET} {dados['atualizado']}")
        if 'privado' in dados:
            status = "Sim" if dados['privado'] else "Não"
            print(f"{Cores.AZUL}  Endereço Privado:{Cores.RESET} {status}")
    
    elif api_nome == 'MacAddressIO':
        if 'endereco' in dados and dados['endereco']:
            print(f"{Cores.AZUL}  Endereço:{Cores.RESET} {dados['endereco']}")
        if 'pais' in dados and dados['pais']:
            print(f"{Cores.AZUL}  País:{Cores.RESET} {dados['pais']}")
        if 'tipo_bloco' in dados and dados['tipo_bloco']:
            print(f"{Cores.AZUL}  Tipo Transmissão:{Cores.RESET} {dados['tipo_bloco']}")

def exibir_resultados_combinados(resultados, mac_formatado):
    """Exibe resumo combinado dos dados"""
    if not resultados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para este MAC{Cores.RESET}")
        return
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== DADOS COMBINADOS (RESUMO) ==={Cores.RESET}")
    print(f"{Cores.AZUL}Endereço MAC:{Cores.RESET} {mac_formatado}")
    
    # Combinar fabricantes (priorizar MacLookup > MacAddressIO > MacVendors)
    fabricante = None
    for api in ['MacLookup', 'MacAddressIO', 'MacVendors']:
        if api in resultados and 'empresa' in resultados[api] and resultados[api]['empresa']:
            fabricante = resultados[api]['empresa']
            break
    
    if fabricante:
        print(f"{Cores.AZUL}Fabricante:{Cores.RESET} {Cores.VERDE}{fabricante}{Cores.RESET}")
    
    # Informações adicionais
    infos_adicionais = []
    for api in ['MacLookup', 'MacAddressIO']:
        if api in resultados:
            dados = resultados[api]
            if 'pais' in dados and dados['pais']:
                infos_adicionais.append(f"País: {dados['pais']}")
            if 'tipo_bloco' in dados and dados['tipo_bloco']:
                infos_adicionais.append(f"Tipo: {dados['tipo_bloco']}")
            break
    
    if infos_adicionais:
        print(f"{Cores.AZUL}Informações:{Cores.RESET} {', '.join(infos_adicionais)}")
    
    print(f"{Cores.AZUL}APIs com resposta:{Cores.RESET} {len(resultados)}/3")

def combinar_dados(resultados):
    """Combina dados de todas as APIs para exportação"""
    if not resultados:
        return None
    
    combinado = {
        'mac': '',
        'fabricante': '',
        'detalhes': {},
        'apis_responderam': list(resultados.keys()),
        'total_apis': len(resultados)
    }
    
    # Priorizar fabricante do MacLookup
    for api in ['MacLookup', 'MacAddressIO', 'MacVendors']:
        if api in resultados and 'empresa' in resultados[api] and resultados[api]['empresa']:
            combinado['fabricante'] = resultados[api]['empresa']
            combinado['detalhes'] = resultados[api].copy()
            break
    
    return combinado

def salvar_resultado(dados, mac, formato='txt'):
    if not dados:
        return False
    
    try:
        mac_limpo = normalizar_mac(mac)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_mac', exist_ok=True)
        nome_arquivo = f"resultados_mac/mac_{mac_limpo}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== CONSULTA ENDEREÇO MAC ===\n\n")
                f.write(f"MAC:          {formatar_mac(mac)}\n")
                f.write(f"Fabricante:   {dados.get('fabricante', 'Não identificado')}\n")
                f.write(f"APIs:         {', '.join(dados.get('apis_responderam', []))}\n")
                f.write(f"Total APIs:   {dados.get('total_apis', 0)}/3\n")
                
                if dados.get('detalhes'):
                    f.write(f"\n=== DETALHES ===\n")
                    for chave, valor in dados['detalhes'].items():
                        if chave not in ['servico'] and valor:
                            f.write(f"{chave.upper():<15}: {valor}\n")
                
                f.write(f"\nDATA:         {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar MAC Address")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR DE MAC ADDRESS{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Consulta em 3 APIs públicas simultaneamente
- Identificação de fabricantes de dispositivos
- Dados técnicos sobre alocação de blocos MAC
- Cache inteligente para melhor performance

{Cores.AMARELO}APIs utilizadas:{Cores.RESET}
- MacLookup.app - Dados completos + endereço + país
- MacVendors.com - Identificação rápida do fabricante  
- MacAddress.io - Dados técnicos adicionais

{Cores.AMARELO}Formatos MAC aceitos:{Cores.RESET}
- 44:38:39:ff:ef:57 (com dois pontos)
- 443839FFEF57 (sem separadores)
- 44-38-39-ff-ef-57 (com hífens)
- 4438.39ff.ef57 (com pontos)

{Cores.AMARELO}Informações obtidas:{Cores.RESET}
- Nome do fabricante/empresa
- Endereço da empresa
- País de registro
- Tipo de bloco MAC (MA-L, MA-M, MA-S)
- Data de atualização dos dados
- Status de endereço privado/aleatório

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
                    mac = input(f"\n{Cores.CIANO}Digite o endereço MAC: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not validar_mac(mac):
                    print(f"{Cores.VERMELHO}[!] MAC inválido. Deve conter 12 caracteres hexadecimais.{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                mac_formatado = formatar_mac(mac)
                print(f"\n{Cores.AMARELO}[*] Consultando MAC {mac_formatado} em 3 APIs...{Cores.RESET}")
                
                # Consultar APIs em paralelo
                resultados = consultar_apis_paralelo(mac)
                dados_combinados = combinar_dados(resultados)
                
                banner()
                print(f"{Cores.VERDE}{Cores.NEGRITO}RESULTADOS PARA MAC {mac_formatado}{Cores.RESET}")
                
                # Exibir resultados individuais de cada API
                for api_nome in ['MacLookup', 'MacVendors', 'MacAddressIO']:
                    exibir_resultado_individual(api_nome, resultados.get(api_nome))
                
                # Exibir dados combinados
                exibir_resultados_combinados(resultados, mac_formatado)
                
                # Opção de exportação
                if dados_combinados:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(dados_combinados, mac, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(dados_combinados, mac, 'txt')
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
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor de MAC Address!{Cores.RESET}")

if __name__ == "__main__":
    main()
