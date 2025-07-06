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

# APIs públicas sem necessidade de chave
APIS = {
    'BrasilAPI': {
        'url': "https://brasilapi.com.br/api/cep/v1/{cep}",
        'fields': {
            'cep': 'cep',
            'estado': 'state',
            'cidade': 'city',
            'bairro': 'neighborhood', 
            'logradouro': 'street',
            'servico': 'BrasilAPI'
        }
    },
    'ViaCEP': {
        'url': "https://viacep.com.br/ws/{cep}/json/",
        'fields': {
            'cep': 'cep',
            'estado': 'uf',
            'cidade': 'localidade',
            'bairro': 'bairro',
            'logradouro': 'logradouro',
            'complemento': 'complemento',
            'servico': 'ViaCEP'
        }
    },
    'OpenCEP': {
        'url': "https://opencep.com/v1/{cep}",
        'fields': {
            'cep': 'cep',
            'estado': 'state',
            'cidade': 'city',
            'bairro': 'district',
            'logradouro': 'address',
            'servico': 'OpenCEP'
        }
    },
    'WideCEP': {
        'url': "https://cep.awesomeapi.com.br/json/{cep}",
        'fields': {
            'cep': 'cep',
            'estado': 'state',
            'cidade': 'city',
            'bairro': 'district',
            'logradouro': 'address',
            'lat': 'lat',
            'lng': 'lng',
            'ddd': 'ddd',
            'servico': 'WideCEP'
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
   Versão Termux - Sem Chaves API
{Cores.RESET}
{Cores.AMARELO}   Integração com múltiplas fontes públicas
   Dados completos e combinados
{Cores.RESET}""")

def validar_cep(cep):
    cep = re.sub(r'[^0-9]', '', cep)
    return len(cep) == 8

def formatar_cep(cep):
    cep = re.sub(r'[^0-9]', '', cep)
    return f"{cep[:5]}-{cep[5:]}" if len(cep) == 8 else cep

def calcular_distancia(lat1, lon1, lat2, lon2):
    raio_terra = 6371  # km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2) * math.sin(dlat/2) + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2) * math.sin(dlon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return raio_terra * c

def gerar_hash(texto):
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    caminho = f"cache_cep/{nome}.json"
    if dados is not None:  # Modo escrita
        with open(caminho, 'w') as f:
            json.dump({'data': dados, 'timestamp': time.time()}, f)
        return dados
    else:  # Modo leitura
        if os.path.exists(caminho):
            with open(caminho) as f:
                cache = json.load(f)
                if time.time() - cache['timestamp'] < TEMPO_CACHE:
                    return cache['data']
        return None

def consultar_api(nome_api, config, cep):
    cache_id = f"{nome_api}_{cep}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = config['url'].format(cep=cep)
        headers = {'User-Agent': 'Mozilla/5.0 (Termux; Linux arm64)'}
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if 'erro' not in dados and dados:
                resultado = {}
                for campo_local, campo_api in config['fields'].items():
                    if campo_api in dados:
                        resultado[campo_local] = dados[campo_api]
                resultado['servico'] = nome_api
                cache_arquivo(cache_id, resultado)
                return resultado
    except Exception:
        pass
    return None

def consultar_apis_paralelo(cep):
    with concurrent.futures.ThreadPoolExecutor() as executor:
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

def combinar_dados(resultados):
    if not resultados:
        return None
        
    campos_prioritarios = {
        'cep': ['WideCEP', 'BrasilAPI', 'ViaCEP', 'OpenCEP'],
        'logradouro': ['ViaCEP', 'BrasilAPI', 'OpenCEP', 'WideCEP'],
        'bairro': ['ViaCEP', 'BrasilAPI', 'OpenCEP', 'WideCEP'],
        'cidade': ['BrasilAPI', 'ViaCEP', 'OpenCEP', 'WideCEP'],
        'estado': ['BrasilAPI', 'ViaCEP', 'OpenCEP', 'WideCEP'],
        'complemento': ['ViaCEP'],
        'lat': ['WideCEP'],
        'lng': ['WideCEP'],
        'ddd': ['WideCEP']
    }
    
    combinado = defaultdict(list)
    for api, dados in resultados.items():
        for campo, valor in dados.items():
            combinado[campo].append((api, valor))
    
    final = {}
    for campo, fontes in campos_prioritarios.items():
        for fonte in fontes:
            if fonte in resultados and campo in resultados[fonte]:
                final[campo] = resultados[fonte][campo]
                break
    
    final['fontes'] = ', '.join(resultados.keys())
    return final

def obter_dados_ibge(codigo_ibge):
    try:
        response = requests.get(f"https://servicodados.ibge.gov.br/api/v1/localidades/municipios/{codigo_ibge}", timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def obter_dados_geograficos(lat, lng):
    try:
        response = requests.get(f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lng}&format=json", timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def exibir_resultados(dados):
    if not dados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para este CEP{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== DADOS PRINCIPAIS ==={Cores.RESET}")
    print(f"{Cores.AZUL}CEP:{Cores.RESET} {dados.get('cep', 'N/A')}")
    print(f"{Cores.AZUL}Logradouro:{Cores.RESET} {dados.get('logradouro', 'N/A')}")
    if 'complemento' in dados and dados['complemento']:
        print(f"{Cores.AZUL}Complemento:{Cores.RESET} {dados['complemento']}")
    print(f"{Cores.AZUL}Bairro:{Cores.RESET} {dados.get('bairro', 'N/A')}")
    print(f"{Cores.AZUL}Cidade/UF:{Cores.RESET} {dados.get('cidade', 'N/A')}/{dados.get('estado', 'N/A')}")
    
    if 'ddd' in dados:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES ADICIONAIS ==={Cores.RESET}")
        print(f"{Cores.AZUL}DDD:{Cores.RESET} {dados['ddd']}")
    
    if 'lat' in dados and 'lng' in dados:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== COORDENADAS GEOGRÁFICAS ==={Cores.RESET}")
        print(f"{Cores.AZUL}Latitude:{Cores.RESET} {dados['lat']}")
        print(f"{Cores.AZUL}Longitude:{Cores.RESET} {dados['lng']}")
        
        dados_geo = obter_dados_geograficos(dados['lat'], dados['lng'])
        if dados_geo:
            if 'display_name' in dados_geo:
                print(f"\n{Cores.AZUL}Localização:{Cores.RESET} {dados_geo['display_name']}")
    
    print(f"\n{Cores.AZUL}Fontes consultadas:{Cores.RESET} {dados.get('fontes', 'N/A')}")

def salvar_resultado(dados, formato='txt'):
    if not dados:
        return False
    
    cep_limpo = re.sub(r'[^0-9]', '', dados.get('cep', 'sem_cep'))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"resultados/cep_{cep_limpo}_{timestamp}.{formato}"
    os.makedirs('resultados', exist_ok=True)
    
    try:
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DO CEP {dados.get('cep', 'N/A')} ===\n\n")
                f.write(f"LOGRADOURO: {dados.get('logradouro', 'N/A')}\n")
                if 'complemento' in dados:
                    f.write(f"COMPLEMENTO: {dados['complemento']}\n")
                f.write(f"BAIRRO:     {dados.get('bairro', 'N/A')}\n")
                f.write(f"CIDADE/UF:  {dados.get('cidade', 'N/A')}/{dados.get('estado', 'N/A')}\n")
                
                if 'ddd' in dados:
                    f.write(f"\n=== INFORMAÇÕES ADICIONAIS ===\n")
                    f.write(f"DDD:        {dados['ddd']}\n")
                
                if 'lat' in dados and 'lng' in dados:
                    f.write(f"\n=== COORDENADAS ===\n")
                    f.write(f"LATITUDE:   {dados['lat']}\n")
                    f.write(f"LONGITUDE:  {dados['lng']}\n")
                
                f.write(f"\nFONTES:     {dados.get('fontes', 'N/A')}\n")
                f.write(f"DATA:       {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar CEP")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}")

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR DE CEP{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Consulta em múltiplas APIs públicas simultaneamente
- Combinação inteligente dos melhores resultados
- Cache de consultas para melhor performance
- Funcionamento offline após primeira consulta
- Sem necessidade de chaves API

{Cores.AMARELO}APIs utilizadas:{Cores.RESET}
- BrasilAPI (Governo Brasileiro)
- ViaCEP (Correios)
- OpenCEP (Open Source)
- WideCEP (Dados complementares)

{Cores.AMARELO}Dados obtidos:{Cores.RESET}
- Endereço completo
- Coordenadas geográficas (quando disponível)
- Código DDD
- Informações demográficas básicas

{Cores.VERDE}Pressione Enter para voltar...{Cores.RESET}""")
    input()

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                cep = input(f"\n{Cores.CIANO}Digite o CEP (com ou sem hífen): {Cores.RESET}").strip()
                
                if not validar_cep(cep):
                    print(f"{Cores.VERMELHO}[!] CEP inválido. Deve conter 8 dígitos.{Cores.RESET}")
                    input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    continue
                
                cep_formatado = formatar_cep(cep)
                print(f"\n{Cores.AMARELO}[*] Consultando CEP {cep_formatado}...{Cores.RESET}")
                
                resultados = consultar_apis_paralelo(cep)
                dados_combinados = combinar_dados(resultados)
                
                banner()
                exibir_resultados(dados_combinados)
                
                if dados_combinados:
                    exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                    if exportar.startswith('j'):
                        salvar_resultado(dados_combinados, 'json')
                    elif exportar.startswith('t'):
                        salvar_resultado(dados_combinados, 'txt')
                
                input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
            
            elif opcao == '2':
                sobre()
            
            elif opcao == '3':
                print(f"\n{Cores.VERDE}[+] Saindo...{Cores.RESET}")
                break
            
            else:
                print(f"{Cores.VERMELHO}[!] Opção inválida!{Cores.RESET}")
                input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Programa interrompido{Cores.RESET}")
    except Exception as e:
        print(f"\n{Cores.VERMELHO}[!] Erro fatal: {str(e)}{Cores.RESET}")
    finally:
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor de CEP!{Cores.RESET}")

if __name__ == "__main__":
    main()
