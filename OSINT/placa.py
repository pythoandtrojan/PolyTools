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
os.makedirs('cache_placa', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# APIs públicas para consulta de placas (pode variar conforme disponibilidade)
APIS = {
    'SinespCidadao': {
        'url': "https://www.sinespcidadao.com.br/api/consultas/placa/{placa}",
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; Mobile)',
            'Accept': 'application/json'
        },
        'fields': {
            'placa': 'placa',
            'marca': 'marca',
            'modelo': 'modelo',
            'cor': 'cor',
            'ano': 'ano',
            'situacao': 'situacao',
            'cidade': 'municipio',
            'uf': 'uf',
            'servico': 'SinespCidadao'
        }
    },
    'PlacaFipe': {
        'url': "https://placafipe.com.br/api/v1/consultas/placa/{placa}",
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; Mobile)'
        },
        'fields': {
            'placa': 'placa',
            'marca': 'marca',
            'modelo': 'modelo',
            'ano': 'ano',
            'cor': 'cor',
            'cidade': 'cidade',
            'uf': 'uf',
            'valor_fipe': 'valor',
            'servico': 'PlacaFipe'
        }
    }
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ██████╗ ██╗      █████╗  ██████╗ █████╗ 
   ██╔══██╗██║     ██╔══██╗██╔════╝██╔══██╗
   ██████╔╝██║     ███████║██║     ███████║
   ██╔═══╝ ██║     ██╔══██║██║     ██╔══██║
   ██║     ███████╗██║  ██║╚██████╗██║  ██║
   ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ 
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   CONSULTOR DE PLACA DE VEÍCULOS
   Versão Termux - Consulta Pública
{Cores.RESET}
{Cores.AMARELO}   Integração com múltiplas fontes
   Dados básicos de veículos
{Cores.RESET}""")

def validar_placa(placa):
    if not placa or not isinstance(placa, str):
        return False
    
    # Verifica formato Mercosul (AAA1A11) ou antigo (AAA1111)
    placa = placa.upper().strip()
    padrao_antigo = re.compile(r'^[A-Z]{3}\d{4}$')
    padrao_mercosul = re.compile(r'^[A-Z]{3}\d[A-Z]\d{2}$')
    
    return bool(padrao_antigo.match(placa)) or bool(padrao_mercosul.match(placa))

def formatar_placa(placa):
    if not placa:
        return ""
    placa = placa.upper().strip()
    return placa[:3] + '-' + placa[3:] if len(placa) == 7 else placa

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_placa/{nome}.json"
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

def consultar_api(nome_api, config, placa):
    if not placa or not validar_placa(placa):
        return None
        
    cache_id = f"{nome_api}_{placa}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = config['url'].format(placa=placa)
        headers = config.get('headers', {'User-Agent': 'Mozilla/5.0 (Termux; Linux arm64)'})
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and not isinstance(dados, list) and 'erro' not in dados:
                resultado = {}
                for campo_local, campo_api in config['fields'].items():
                    if campo_api in dados and dados[campo_api]:
                        resultado[campo_local] = dados[campo_api]
                resultado['servico'] = nome_api
                cache_arquivo(cache_id, resultado)
                return resultado
    except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
        pass
    return None

def consultar_apis_paralelo(placa):
    if not validar_placa(placa):
        return {}
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(consultar_api, nome, config, placa): nome
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
    if not resultados or not isinstance(resultados, dict):
        return None
        
    campos_prioritarios = {
        'placa': ['SinespCidadao', 'PlacaFipe'],
        'marca': ['SinespCidadao', 'PlacaFipe'],
        'modelo': ['SinespCidadao', 'PlacaFipe'],
        'ano': ['SinespCidadao', 'PlacaFipe'],
        'cor': ['SinespCidadao', 'PlacaFipe'],
        'cidade': ['SinespCidadao', 'PlacaFipe'],
        'uf': ['SinespCidadao', 'PlacaFipe'],
        'situacao': ['SinespCidadao'],
        'valor_fipe': ['PlacaFipe']
    }
    
    final = {}
    for campo, fontes in campos_prioritarios.items():
        for fonte in fontes:
            if fonte in resultados and campo in resultados[fonte] and resultados[fonte][campo]:
                final[campo] = resultados[fonte][campo]
                break
    
    if final:
        final['fontes'] = ', '.join(resultados.keys())
    return final if final else None

def exibir_resultados(dados):
    if not dados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para esta placa{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== DADOS DO VEÍCULO ==={Cores.RESET}")
    print(f"{Cores.AZUL}Placa:{Cores.RESET} {formatar_placa(dados.get('placa', 'N/A'))}")
    print(f"{Cores.AZUL}Marca/Modelo:{Cores.RESET} {dados.get('marca', 'N/A')} / {dados.get('modelo', 'N/A')}")
    print(f"{Cores.AZUL}Ano:{Cores.RESET} {dados.get('ano', 'N/A')}")
    print(f"{Cores.AZUL}Cor:{Cores.RESET} {dados.get('cor', 'N/A')}")
    
    if 'situacao' in dados:
        print(f"{Cores.AZUL}Situação:{Cores.RESET} {dados['situacao']}")
    
    print(f"{Cores.AZUL}Localização:{Cores.RESET} {dados.get('cidade', 'N/A')}/{dados.get('uf', 'N/A')}")
    
    if 'valor_fipe' in dados:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES FINANCEIRAS ==={Cores.RESET}")
        print(f"{Cores.AZUL}Valor FIPE:{Cores.RESET} {dados['valor_fipe']}")
    
    print(f"\n{Cores.AZUL}Fontes consultadas:{Cores.RESET} {dados.get('fontes', 'N/A')}")

def salvar_resultado(dados, formato='txt'):
    if not dados:
        return False
    
    try:
        placa_limpa = re.sub(r'[^A-Z0-9]', '', dados.get('placa', 'sem_placa')).upper()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_placa', exist_ok=True)
        nome_arquivo = f"resultados_placa/placa_{placa_limpa}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DA PLACA {formatar_placa(dados.get('placa', 'N/A'))} ===\n\n")
                f.write(f"MARCA/MODELO: {dados.get('marca', 'N/A')} / {dados.get('modelo', 'N/A')}\n")
                f.write(f"ANO:         {dados.get('ano', 'N/A')}\n")
                f.write(f"COR:         {dados.get('cor', 'N/A')}\n")
                
                if 'situacao' in dados:
                    f.write(f"SITUAÇÃO:    {dados['situacao']}\n")
                
                f.write(f"LOCALIZAÇÃO: {dados.get('cidade', 'N/A')}/{dados.get('uf', 'N/A')}\n")
                
                if 'valor_fipe' in dados:
                    f.write(f"\n=== INFORMAÇÕES FINANCEIRAS ===\n")
                    f.write(f"VALOR FIPE:  {dados['valor_fipe']}\n")
                
                f.write(f"\nFONTES:     {dados.get('fontes', 'N/A')}\n")
                f.write(f"DATA:       {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar Placa")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR DE PLACA{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Consulta em múltiplas fontes públicas
- Suporte a placas no formato antigo e Mercosul
- Cache de consultas para melhor performance
- Funcionamento offline após primeira consulta

{Cores.AMARELO}Dados obtidos:{Cores.RESET}
- Marca e modelo do veículo
- Ano de fabricação
- Cor
- Situação do veículo
- Localização (cidade/UF)
- Valor FIPE (quando disponível)

{Cores.VERMELHO}Aviso importante:{Cores.RESET}
Este script utiliza apenas APIs públicas disponíveis e
não realiza consultas em bancos de dados oficiais como
o DENATRAN. Algumas informações podem estar incompletas.

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
                    placa = input(f"\n{Cores.CIANO}Digite a placa (com ou sem hífen): {Cores.RESET}").strip().upper()
                    placa = re.sub(r'[^A-Z0-9]', '', placa)  # Remove caracteres especiais
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not validar_placa(placa):
                    print(f"{Cores.VERMELHO}[!] Placa inválida. Formato esperado: AAA1234 ou AAA1A23{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                placa_formatada = formatar_placa(placa)
                print(f"\n{Cores.AMARELO}[*] Consultando placa {placa_formatada}...{Cores.RESET}")
                
                resultados = consultar_apis_paralelo(placa)
                dados_combinados = combinar_dados(resultados)
                
                banner()
                exibir_resultados(dados_combinados)
                
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
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor de Placa!{Cores.RESET}")

if __name__ == "__main__":
    main()
