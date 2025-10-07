#!/usr/bin/env python3
import requests
import re
import os
import json
import concurrent.futures
from datetime import datetime
from urllib.parse import quote
import sqlite3
import math
import time
import hashlib
from collections import defaultdict

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
os.makedirs('cache_cep', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# APIs públicas atualizadas
APIS = {
    'ViaCEP': {
        'url': "https://viacep.com.br/ws/{cep}/json/",
        'fields': {
            'cep': 'cep',
            'logradouro': 'logradouro',
            'complemento': 'complemento',
            'bairro': 'bairro',
            'cidade': 'localidade',
            'uf': 'uf',
            'estado': 'estado',
            'regiao': 'regiao',
            'ibge': 'ibge',
            'ddd': 'ddd',
            'siafi': 'siafi',
            'servico': 'ViaCEP'
        }
    },
    'AwesomeAPI': {
        'url': "https://cep.awesomeapi.com.br/json/{cep}",
        'fields': {
            'cep': 'cep',
            'logradouro': 'address',
            'tipo_logradouro': 'address_type',
            'nome_logradouro': 'address_name',
            'bairro': 'district',
            'cidade': 'city',
            'uf': 'state',
            'ibge': 'city_ibge',
            'lat': 'lat',
            'lng': 'lng',
            'ddd': 'ddd',
            'servico': 'AwesomeAPI'
        }
    },
    'BrasilAPI': {
        'url': "https://brasilapi.com.br/api/cep/v2/{cep}",
        'fields': {
            'cep': 'cep',
            'logradouro': 'street',
            'bairro': 'neighborhood',
            'cidade': 'city',
            'uf': 'state',
            'ibge': 'city_ibge',
            'servico': 'BrasilAPI'
        }
    },
    'OpenCEP': {
        'url': "https://opencep.com/v1/{cep}",
        'fields': {
            'cep': 'cep',
            'logradouro': 'address',
            'bairro': 'district',
            'cidade': 'city',
            'uf': 'state',
            'ibge': 'ibge',
            'ddd': 'ddd',
            'servico': 'OpenCEP'
        }
    }
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ██████╗ ██████╗ ██████╗ 
   ██╔═══██╗██╔══██╗██╔══██╗
   ██║   ██║██████╔╝██████╔╝
   ██║   ██║██╔═══╝ ██╔═══╝ 
   ╚██████╔╝██║     ██║     
    ╚═════╝ ╚═╝     ╚═╝     
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   CONSULTOR DE CEP AVANÇADO
   Versão Turbo com Múltiplas APIs
{Cores.RESET}
{Cores.AMARELO}   Dados completos + Localização Google Maps
   Informações IBGE detalhadas
{Cores.RESET}""")

def validar_cep(cep):
    if not cep or not isinstance(cep, str):
        return False
    cep = re.sub(r'[^0-9]', '', cep)
    return len(cep) == 8

def formatar_cep(cep):
    if not cep:
        return ""
    cep = re.sub(r'[^0-9]', '', cep)
    return f"{cep[:5]}-{cep[5:]}" if len(cep) == 8 else cep

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_cep/{nome}.json"
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

def consultar_api(nome_api, config, cep):
    if not cep or not validar_cep(cep):
        return None
        
    cache_id = f"{nome_api}_{cep}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = config['url'].format(cep=cep)
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and not (isinstance(dados, dict) and dados.get('erro')):
                resultado = {}
                for campo_local, campo_api in config['fields'].items():
                    if campo_api in dados and dados[campo_api] not in [None, ""]:
                        resultado[campo_local] = dados[campo_api]
                
                # Processamento especial para ViaCEP
                if nome_api == 'ViaCEP' and 'uf' in resultado:
                    resultado['estado'] = obter_nome_estado(resultado['uf'])
                    resultado['regiao'] = obter_regiao_por_uf(resultado['uf'])
                
                resultado['servico'] = nome_api
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
        pass
    return None

def obter_nome_estado(uf):
    estados = {
        'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
        'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
        'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
        'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
        'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
        'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
        'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
    }
    return estados.get(uf.upper(), '')

def obter_regiao_por_uf(uf):
    regioes = {
        'Norte': ['AC', 'AP', 'AM', 'PA', 'RO', 'RR', 'TO'],
        'Nordeste': ['AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE'],
        'Centro-Oeste': ['DF', 'GO', 'MT', 'MS'],
        'Sudeste': ['ES', 'MG', 'RJ', 'SP'],
        'Sul': ['PR', 'RS', 'SC']
    }
    for regiao, ufs in regioes.items():
        if uf.upper() in ufs:
            return regiao
    return ''

def consultar_ibge(codigo_ibge):
    """Consulta dados detalhados do IBGE para o município"""
    if not codigo_ibge:
        return None
    
    cache_id = f"ibge_{codigo_ibge}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://servicodados.ibge.gov.br/api/v1/localidades/municipios/{codigo_ibge}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            dados = response.json()
            if dados:
                # Estruturar dados do IBGE
                info_ibge = {
                    'id': dados.get('id'),
                    'municipio': dados.get('nome'),
                    'microrregiao': dados.get('microrregiao', {}).get('nome'),
                    'mesorregiao': dados.get('microrregiao', {}).get('mesorregiao', {}).get('nome'),
                    'regiao_imediata': dados.get('regiao-imediata', {}).get('nome'),
                    'regiao_intermediaria': dados.get('regiao-imediata', {}).get('regiao-intermediaria', {}).get('nome'),
                    'regiao_uf': dados.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {}).get('nome'),
                    'regiao_sigla': dados.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {}).get('sigla'),
                    'regiao_nome': dados.get('microrregiao', {}).get('mesorregiao', {}).get('UF', {}).get('regiao', {}).get('nome')
                }
                cache_arquivo(cache_id, info_ibge)
                return info_ibge
    except requests.RequestException:
        pass
    return None

def consultar_apis_paralelo(cep):
    if not validar_cep(cep):
        return {}
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(consultar_api, nome, config, cep): nome
            for nome, config in APIS.items()
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

def gerar_link_google_maps(lat, lng, endereco=None):
    """Gera link para Google Maps"""
    if lat and lng:
        return f"https://www.google.com/maps?q={lat},{lng}"
    elif endereco:
        endereco_encoded = quote(endereco)
        return f"https://www.google.com/maps/search/?api=1&query={endereco_encoded}"
    return None

def exibir_resultado_individual(api_nome, dados):
    """Exibe resultados individuais de cada API"""
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== {api_nome} ==={Cores.RESET}")
    
    if not dados:
        print(f"{Cores.VERMELHO}  Nenhum dado retornado{Cores.RESET}")
        return
    
    # Dados básicos
    if 'cep' in dados:
        print(f"{Cores.AZUL}  CEP:{Cores.RESET} {dados['cep']}")
    if 'logradouro' in dados:
        print(f"{Cores.AZUL}  Logradouro:{Cores.RESET} {dados['logradouro']}")
    if 'bairro' in dados:
        print(f"{Cores.AZUL}  Bairro:{Cores.RESET} {dados['bairro']}")
    if 'cidade' in dados and 'uf' in dados:
        print(f"{Cores.AZUL}  Cidade/UF:{Cores.RESET} {dados['cidade']}/{dados['uf']}")
    
    # Dados específicos por API
    if api_nome == 'ViaCEP':
        if 'complemento' in dados and dados['complemento']:
            print(f"{Cores.AZUL}  Complemento:{Cores.RESET} {dados['complemento']}")
        if 'ddd' in dados:
            print(f"{Cores.AZUL}  DDD:{Cores.RESET} {dados['ddd']}")
        if 'ibge' in dados:
            print(f"{Cores.AZUL}  Código IBGE:{Cores.RESET} {dados['ibge']}")
        if 'regiao' in dados:
            print(f"{Cores.AZUL}  Região:{Cores.RESET} {dados['regiao']}")
    
    elif api_nome == 'AwesomeAPI':
        if 'tipo_logradouro' in dados:
            print(f"{Cores.AZUL}  Tipo:{Cores.RESET} {dados['tipo_logradouro']}")
        if 'lat' in dados and 'lng' in dados:
            print(f"{Cores.AZUL}  Coordenadas:{Cores.RESET} {dados['lat']}, {dados['lng']}")
            maps_link = gerar_link_google_maps(dados['lat'], dados['lng'])
            if maps_link:
                print(f"{Cores.AZUL}  Google Maps:{Cores.RESET} {maps_link}")
    
    elif api_nome == 'BrasilAPI':
        if 'ibge' in dados:
            print(f"{Cores.AZUL}  Código IBGE:{Cores.RESET} {dados['ibge']}")
    
    elif api_nome == 'OpenCEP':
        if 'ddd' in dados:
            print(f"{Cores.AZUL}  DDD:{Cores.RESET} {dados['ddd']}")

def exibir_resultados_combinados(dados_combinados, resultados_apis):
    """Exibe dados combinados e resumo"""
    if not dados_combinados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para este CEP{Cores.RESET}")
        return
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== DADOS COMBINADOS (RESUMO) ==={Cores.RESET}")
    print(f"{Cores.AZUL}CEP:{Cores.RESET} {dados_combinados.get('cep', 'N/A')}")
    print(f"{Cores.AZUL}Endereço:{Cores.RESET} {dados_combinados.get('logradouro', 'N/A')}")
    if dados_combinados.get('complemento'):
        print(f"{Cores.AZUL}Complemento:{Cores.RESET} {dados_combinados['complemento']}")
    print(f"{Cores.AZUL}Bairro:{Cores.RESET} {dados_combinados.get('bairro', 'N/A')}")
    print(f"{Cores.AZUL}Cidade:{Cores.RESET} {dados_combinados.get('cidade', 'N/A')}")
    print(f"{Cores.AZUL}UF:{Cores.RESET} {dados_combinados.get('uf', 'N/A')}")
    
    if dados_combinados.get('ddd'):
        print(f"{Cores.AZUL}DDD:{Cores.RESET} {dados_combinados['ddd']}")
    
    # Link do Google Maps
    if dados_combinados.get('lat') and dados_combinados.get('lng'):
        maps_link = gerar_link_google_maps(
            dados_combinados['lat'], 
            dados_combinados['lng'],
            f"{dados_combinados.get('logradouro', '')}, {dados_combinados.get('cidade', '')}"
        )
        print(f"{Cores.AZUL}Localização:{Cores.RESET} {maps_link}")
    else:
        # Gerar link com endereço mesmo sem coordenadas
        endereco = f"{dados_combinados.get('logradouro', '')} {dados_combinados.get('bairro', '')} {dados_combinados.get('cidade', '')} {dados_combinados.get('uf', '')}"
        maps_link = gerar_link_google_maps(None, None, endereco.strip())
        if maps_link:
            print(f"{Cores.AZUL}Localização:{Cores.RESET} {maps_link}")

def exibir_dados_ibge(dados_ibge):
    """Exibe dados detalhados do IBGE"""
    if not dados_ibge:
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES IBGE DETALHADAS ==={Cores.RESET}")
    print(f"{Cores.AZUL}Município:{Cores.RESET} {dados_ibge.get('municipio', 'N/A')}")
    print(f"{Cores.AZUL}Código IBGE:{Cores.RESET} {dados_ibge.get('id', 'N/A')}")
    
    if dados_ibge.get('microrregiao'):
        print(f"{Cores.AZUL}Microrregião:{Cores.RESET} {dados_ibge['microrregiao']}")
    if dados_ibge.get('mesorregiao'):
        print(f"{Cores.AZUL}Mesorregião:{Cores.RESET} {dados_ibge['mesorregiao']}")
    if dados_ibge.get('regiao_imediata'):
        print(f"{Cores.AZUL}Região Imediata:{Cores.RESET} {dados_ibge['regiao_imediata']}")
    if dados_ibge.get('regiao_intermediaria'):
        print(f"{Cores.AZUL}Região Intermediária:{Cores.RESET} {dados_ibge['regiao_intermediaria']}")
    if dados_ibge.get('regiao_nome'):
        print(f"{Cores.AZUL}Região:{Cores.RESET} {dados_ibge['regiao_nome']}")

def combinar_dados(resultados):
    """Combina dados de todas as APIs"""
    if not resultados:
        return None
    
    campos_prioritarios = {
        'cep': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'logradouro': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'complemento': ['ViaCEP'],
        'bairro': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'cidade': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'uf': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'ibge': ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP'],
        'ddd': ['ViaCEP', 'AwesomeAPI', 'OpenCEP'],
        'lat': ['AwesomeAPI'],
        'lng': ['AwesomeAPI'],
        'estado': ['ViaCEP'],
        'regiao': ['ViaCEP']
    }
    
    final = {}
    for campo, fontes in campos_prioritarios.items():
        for fonte in fontes:
            if fonte in resultados and campo in resultados[fonte] and resultados[fonte][campo]:
                final[campo] = resultados[fonte][campo]
                break
    
    if final:
        final['fontes_consultadas'] = list(resultados.keys())
        final['total_apis'] = len(resultados)
    return final if final else None

def salvar_resultado(dados, formato='txt'):
    if not dados:
        return False
    
    try:
        cep_limpo = re.sub(r'[^0-9]', '', dados.get('cep', 'sem_cep'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados', exist_ok=True)
        nome_arquivo = f"resultados/cep_{cep_limpo}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DO CEP {dados.get('cep', 'N/A')} ===\n\n")
                f.write(f"LOGRADOURO: {dados.get('logradouro', 'N/A')}\n")
                if dados.get('complemento'):
                    f.write(f"COMPLEMENTO: {dados['complemento']}\n")
                f.write(f"BAIRRO:     {dados.get('bairro', 'N/A')}\n")
                f.write(f"CIDADE:     {dados.get('cidade', 'N/A')}\n")
                f.write(f"UF:         {dados.get('uf', 'N/A')}\n")
                
                if 'ddd' in dados:
                    f.write(f"DDD:        {dados['ddd']}\n")
                
                if 'lat' in dados and 'lng' in dados:
                    f.write(f"LATITUDE:   {dados['lat']}\n")
                    f.write(f"LONGITUDE:  {dados['lng']}\n")
                    maps_link = gerar_link_google_maps(dados['lat'], dados['lng'])
                    if maps_link:
                        f.write(f"MAPS:       {maps_link}\n")
                
                f.write(f"\nFONTES:     {', '.join(dados.get('fontes_consultadas', []))}\n")
                f.write(f"TOTAL APIS: {dados.get('total_apis', 0)}\n")
                f.write(f"DATA:       {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar CEP")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR DE CEP AVANÇADO{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Consulta em 4 APIs públicas simultaneamente
- Dados individuais de cada API
- Dados combinados inteligentes
- Informações detalhadas do IBGE
- Links diretos para Google Maps
- Cache inteligente para performance

{Cores.AMARELO}APIs utilizadas:{Cores.RESET}
- ViaCEP (Correios) - Dados completos + DDD + IBGE
- AwesomeAPI - Coordenadas GPS + Google Maps
- BrasilAPI - Dados oficiais do governo
- OpenCEP - Dados alternativos

{Cores.AMARELO}Funcionalidades:{Cores.RESET}
- Visualização individual por API
- Dados combinados otimizados
- Links de localização no mapa
- Informações demográficas do IBGE
- Exportação em JSON/TXT

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
                    cep = input(f"\n{Cores.CIANO}Digite o CEP (com ou sem hífen): {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not validar_cep(cep):
                    print(f"{Cores.VERMELHO}[!] CEP inválido. Deve conter 8 dígitos.{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                cep_formatado = formatar_cep(cep)
                print(f"\n{Cores.AMARELO}[*] Consultando CEP {cep_formatado} em 4 APIs...{Cores.RESET}")
                
                # Consultar APIs em paralelo
                resultados = consultar_apis_paralelo(cep)
                dados_combinados = combinar_dados(resultados)
                
                banner()
                print(f"{Cores.VERDE}{Cores.NEGRITO}RESULTADOS PARA CEP {cep_formatado}{Cores.RESET}")
                
                # Exibir resultados individuais de cada API
                for api_nome in ['ViaCEP', 'AwesomeAPI', 'BrasilAPI', 'OpenCEP']:
                    exibir_resultado_individual(api_nome, resultados.get(api_nome))
                
                # Exibir dados combinados
                exibir_resultados_combinados(dados_combinados, resultados)
                
                # Consultar e exibir dados do IBGE se disponível
                if dados_combinados and 'ibge' in dados_combinados:
                    dados_ibge = consultar_ibge(dados_combinados['ibge'])
                    exibir_dados_ibge(dados_ibge)
                
                # Opção de exportação
                if dados_combinados:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(dados_combinados, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(dados_combinados, 'txt')
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
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor de CEP Avançado!{Cores.RESET}")

if __name__ == "__main__":
    main()
