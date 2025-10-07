#!/usr/bin/env python3
import requests
import os
import json
import csv
from datetime import datetime
import time
import hashlib
import sys
import re

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
os.makedirs('cache_imei', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# URL da base de dados IMEI
IMEI_DB_URL = "https://raw.githubusercontent.com/VTSTech/IMEIDB/master/imeidb.csv"

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
██╗███╗   ███╗███████╗██╗
██║████╗ ████║██╔════╝██║
██║██╔████╔██║█████╗  ██║
██║██║╚██╔╝██║██╔══╝  ██║
██║██║ ╚═╝ ██║███████╗██║
╚═╝╚═╝     ╚═╝╚══════╝╚═╝
                         
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   CONSULTOR IMEI
   Identificação de Dispositivos
{Cores.RESET}
{Cores.AMARELO}   Base de dados completa + Validação
   Fabricante + Modelo + País
{Cores.RESET}""")

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_imei/{nome}.json"
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

def baixar_base_imei():
    """Baixa e atualiza a base de dados IMEI"""
    cache_id = "base_imei_completa"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    print(f"{Cores.AMARELO}[*] Baixando base de dados IMEI...{Cores.RESET}")
    
    try:
        response = requests.get(IMEI_DB_URL, timeout=30)
        if response.status_code == 200:
            # Processar CSV
            dados_csv = response.text.splitlines()
            leitor = csv.reader(dados_csv)
            
            base_imei = {}
            next(leitor)  # Pular cabeçalho se existir
            
            for linha in leitor:
                if len(linha) >= 5:
                    imei_prefix = linha[0].strip()
                    fabricante = linha[1].strip()
                    modelo = linha[2].strip()
                    pais = linha[3].strip()
                    tipo = linha[4].strip() if len(linha) > 4 else "Dispositivo Móvel"
                    
                    base_imei[imei_prefix] = {
                        'fabricante': fabricante,
                        'modelo': modelo,
                        'pais': pais,
                        'tipo': tipo
                    }
            
            print(f"{Cores.VERDE}[+] Base de dados carregada: {len(base_imei)} dispositivos{Cores.RESET}")
            cache_arquivo(cache_id, base_imei)
            return base_imei
        else:
            print(f"{Cores.VERMELHO}[!] Erro ao baixar base: HTTP {response.status_code}{Cores.RESET}")
            return {}
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao baixar base: {str(e)}{Cores.RESET}")
        return {}

def validar_imei(imei):
    """Valida o número IMEI usando o algoritmo Luhn"""
    if not imei or not imei.isdigit():
        return False
    
    if len(imei) != 15:
        return False
    
    # Algoritmo de Luhn para IMEI
    total = 0
    for i, digito in enumerate(imei):
        num = int(digito)
        if i % 2 == 1:  # Dígitos pares (índice ímpar)
            num = num * 2
            if num > 9:
                num = num - 9
        total += num
    
    return total % 10 == 0

def calcular_digito_verificador(imei_14):
    """Calcula o dígito verificador para os 14 primeiros dígitos"""
    if len(imei_14) != 14 or not imei_14.isdigit():
        return None
    
    total = 0
    for i, digito in enumerate(imei_14):
        num = int(digito)
        if i % 2 == 0:  # Posições ímpares (índice par)
            num = num * 2
            if num > 9:
                num = num - 9
        total += num
    
    digito_verificador = (10 - (total % 10)) % 10
    return digito_verificador

def consultar_imei_tac(imei):
    """Consulta informações TAC (Type Allocation Code) - primeiros 8 dígitos"""
    tac = imei[:8]
    base_imei = baixar_base_imei()
    
    # Buscar correspondência exata
    if tac in base_imei:
        return base_imei[tac]
    
    # Buscar correspondência parcial (6 primeiros dígitos)
    tac_6 = imei[:6]
    for prefix, info in base_imei.items():
        if prefix.startswith(tac_6):
            return info
    
    return None

def consultar_imei_api_externa(imei):
    """Tenta consultar APIs externas para mais informações"""
    cache_id = f"api_imei_{imei}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    apis = [
        {
            'nome': 'IMEI API',
            'url': f"https://imei.apis.com/check/{imei}",
            'campos': {
                'modelo': 'model',
                'fabricante': 'manufacturer',
                'status': 'status'
            }
        }
    ]
    
    for api in apis:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            response = requests.get(api['url'], headers=headers, timeout=10)
            
            if response.status_code == 200:
                dados = response.json()
                resultado = {
                    'fabricante': dados.get(api['campos']['fabricante'], ''),
                    'modelo': dados.get(api['campos']['modelo'], ''),
                    'status': dados.get(api['campos']['status'], ''),
                    'fonte': api['nome']
                }
                cache_arquivo(cache_id, resultado)
                return resultado
        except:
            continue
    
    return None

def obter_info_fabricante(fabricante):
    """Obtém informações adicionais sobre o fabricante"""
    fabricantes_info = {
        'Samsung': {'pais': 'Coreia do Sul', 'fundacao': 1938, 'site': 'samsung.com'},
        'Apple': {'pais': 'EUA', 'fundacao': 1976, 'site': 'apple.com'},
        'Huawei': {'pais': 'China', 'fundacao': 1987, 'site': 'huawei.com'},
        'Xiaomi': {'pais': 'China', 'fundacao': 2010, 'site': 'mi.com'},
        'Nokia': {'pais': 'Finlândia', 'fundacao': 1865, 'site': 'nokia.com'},
        'Motorola': {'pais': 'EUA', 'fundacao': 1928, 'site': 'motorola.com'},
        'LG': {'pais': 'Coreia do Sul', 'fundacao': 1958, 'site': 'lg.com'},
        'Sony': {'pais': 'Japão', 'fundacao': 1946, 'site': 'sony.com'},
        'Google': {'pais': 'EUA', 'fundacao': 1998, 'site': 'google.com'},
        'OnePlus': {'pais': 'China', 'fundacao': 2013, 'site': 'oneplus.com'},
        'Oppo': {'pais': 'China', 'fundacao': 2004, 'site': 'oppo.com'},
        'Vivo': {'pais': 'China', 'fundacao': 2009, 'site': 'vivo.com'},
        'Realme': {'pais': 'China', 'fundacao': 2018, 'site': 'realme.com'},
        'ZTE': {'pais': 'China', 'fundacao': 1985, 'site': 'zte.com.cn'},
        'Alcatel': {'pais': 'França', 'fundacao': 1898, 'site': 'alcatel.com'},
        'TCL': {'pais': 'China', 'fundacao': 1981, 'site': 'tcl.com'},
        'Lenovo': {'pais': 'China', 'fundacao': 1984, 'site': 'lenovo.com'},
        'HTC': {'pais': 'Taiwan', 'fundacao': 1997, 'site': 'htc.com'},
        'Asus': {'pais': 'Taiwan', 'fundacao': 1989, 'site': 'asus.com'},
        'BlackBerry': {'pais': 'Canadá', 'fundacao': 1984, 'site': 'blackberry.com'}
    }
    
    return fabricantes_info.get(fabricante, {})

def analisar_estrutura_imei(imei):
    """Analisa a estrutura do IMEI"""
    # TAC (Type Allocation Code) - 8 primeiros dígitos
    tac = imei[:8]
    
    # SNR (Serial Number) - 6 dígitos do meio
    snr = imei[8:14]
    
    # Dígito verificador - último dígito
    dv = imei[14]
    
    return {
        'tac': tac,
        'snr': snr,
        'digito_verificador': dv,
        'tac_formatado': f"{tac[:2]} {tac[2:4]} {tac[4:6]} {tac[6:8]}",
        'snr_formatado': f"{snr[:2]} {snr[2:4]} {snr[4:6]}"
    }

def consultar_todos_dados_imei(imei):
    """Consulta todas as informações disponíveis do IMEI"""
    print(f"{Cores.AMARELO}[*] Analisando IMEI {imei}...{Cores.RESET}")
    
    # Validação básica
    if not validar_imei(imei):
        return {'erro': 'IMEI inválido - Não passou na validação Luhn'}
    
    # Informações da base de dados TAC
    info_tac = consultar_imei_tac(imei)
    
    # Informações de APIs externas
    info_api = consultar_imei_api_externa(imei)
    
    # Análise estrutural
    estrutura = analisar_estrutura_imei(imei)
    
    # Combinar resultados
    resultado = {
        'imei': imei,
        'valido': True,
        'estrutura': estrutura,
        'tac_info': info_tac,
        'api_info': info_api,
        'consultado_em': datetime.now().isoformat()
    }
    
    return resultado

def exibir_resultados_imei(resultado):
    """Exibe os resultados da consulta IMEI"""
    if 'erro' in resultado:
        print(f"{Cores.VERMELHO}[!] {resultado['erro']}{Cores.RESET}")
        return False
    
    imei = resultado['imei']
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== RESULTADOS IMEI {imei} ==={Cores.RESET}")
    
    # Status de validação
    print(f"{Cores.AZUL}Status:{Cores.RESET} {Cores.VERDE}✓ VÁLIDO (Algoritmo Luhn){Cores.RESET}")
    
    # Estrutura do IMEI
    estrutura = resultado['estrutura']
    print(f"\n{Cores.AZUL}Estrutura do IMEI:{Cores.RESET}")
    print(f"  {Cores.CIANO}TAC (Type Allocation Code):{Cores.RESET} {estrutura['tac']}")
    print(f"  {Cores.CIANO}SNR (Serial Number):{Cores.RESET} {estrutura['snr']}")
    print(f"  {Cores.CIANO}Dígito Verificador:{Cores.RESET} {estrutura['digito_verificador']}")
    print(f"  {Cores.CIANO}Formato:{Cores.RESET} {estrutura['tac_formatado']} - {estrutura['snr_formatado']} - {estrutura['digito_verificador']}")
    
    # Informações do dispositivo
    info_tac = resultado.get('tac_info')
    if info_tac:
        print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== INFORMAÇÕES DO DISPOSITIVO ==={Cores.RESET}")
        print(f"  {Cores.CIANO}Fabricante:{Cores.RESET} {Cores.VERDE}{info_tac['fabricante']}{Cores.RESET}")
        print(f"  {Cores.CIANO}Modelo:{Cores.RESET} {info_tac['modelo']}")
        print(f"  {Cores.CIANO}País de Origem:{Cores.RESET} {info_tac['pais']}")
        print(f"  {Cores.CIANO}Tipo:{Cores.RESET} {info_tac['tipo']}")
        
        # Informações adicionais do fabricante
        info_fabricante = obter_info_fabricante(info_tac['fabricante'])
        if info_fabricante:
            print(f"\n  {Cores.CIANO}Informações do Fabricante:{Cores.RESET}")
            print(f"    {Cores.AZUL}País:{Cores.RESET} {info_fabricante['pais']}")
            print(f"    {Cores.AZUL}Fundado:{Cores.RESET} {info_fabricante['fundacao']}")
            print(f"    {Cores.AZUL}Site:{Cores.RESET} {info_fabricante['site']}")
    else:
        print(f"\n{Cores.AMARELO}[!] Dispositivo não encontrado na base de dados TAC{Cores.RESET}")
    
    # Informações de API externa
    info_api = resultado.get('api_info')
    if info_api:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES ADICIONAIS ==={Cores.RESET}")
        print(f"  {Cores.CIANO}Fonte:{Cores.RESET} {info_api['fonte']}")
        if info_api.get('status'):
            print(f"  {Cores.CIANO}Status:{Cores.RESET} {info_api['status']}")
    
    # Informações técnicas
    print(f"\n{Cores.AZUL}Informações Técnicas:{Cores.RESET}")
    print(f"  {Cores.CIANO}Comprimento:{Cores.RESET} 15 dígitos")
    print(f"  {Cores.CIANO}Formato:{Cores.RESET} TAC (8) + SNR (6) + DV (1)")
    print(f"  {Cores.CIANO}Validação:{Cores.RESET} Algoritmo Luhn")
    
    return True

def gerar_relatorio_imei(imei, resultado):
    """Gera um relatório completo do IMEI"""
    if 'erro' in resultado:
        return None
    
    relatorio = {
        'imei': imei,
        'valido': resultado['valido'],
        'data_consulta': resultado['consultado_em'],
        'estrutura': resultado['estrutura'],
        'dispositivo': resultado.get('tac_info'),
        'informacoes_adicionais': resultado.get('api_info')
    }
    
    if relatorio['dispositivo']:
        fabricante = relatorio['dispositivo']['fabricante']
        info_fabricante = obter_info_fabricante(fabricante)
        relatorio['fabricante_info'] = info_fabricante
    
    return relatorio

def salvar_resultado(resultado, imei, formato='txt'):
    """Salva os resultados em arquivo"""
    if 'erro' in resultado:
        return False
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_imei', exist_ok=True)
        nome_arquivo = f"resultados_imei/imei_{imei}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                relatorio = gerar_relatorio_imei(imei, resultado)
                json.dump(relatorio, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== RELATÓRIO IMEI {imei} ===\n\n")
                
                f.write("STATUS: VÁLIDO ✓\n\n")
                
                f.write("ESTRUTURA DO IMEI:\n")
                estrutura = resultado['estrutura']
                f.write(f"TAC (Type Allocation Code): {estrutura['tac']}\n")
                f.write(f"SNR (Serial Number): {estrutura['snr']}\n")
                f.write(f"Dígito Verificador: {estrutura['digito_verificador']}\n")
                f.write(f"Formato: {estrutura['tac_formatado']} - {estrutura['snr_formatado']} - {estrutura['digito_verificador']}\n\n")
                
                info_tac = resultado.get('tac_info')
                if info_tac:
                    f.write("INFORMAÇÕES DO DISPOSITIVO:\n")
                    f.write(f"Fabricante: {info_tac['fabricante']}\n")
                    f.write(f"Modelo: {info_tac['modelo']}\n")
                    f.write(f"País de Origem: {info_tac['pais']}\n")
                    f.write(f"Tipo: {info_tac['tipo']}\n\n")
                    
                    info_fabricante = obter_info_fabricante(info_tac['fabricante'])
                    if info_fabricante:
                        f.write("INFORMAÇÕES DO FABRICANTE:\n")
                        f.write(f"País: {info_fabricante['pais']}\n")
                        f.write(f"Fundado: {info_fabricante['fundacao']}\n")
                        f.write(f"Site: {info_fabricante['site']}\n\n")
                
                f.write("INFORMAÇÕES TÉCNICAS:\n")
                f.write("Comprimento: 15 dígitos\n")
                f.write("Formato: TAC (8) + SNR (6) + DV (1)\n")
                f.write("Validação: Algoritmo Luhn\n\n")
                
                f.write(f"Data da consulta: {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def testar_imei_exemplo():
    """Testa com IMEIs de exemplo"""
    imeis_exemplo = [
        "352982103456789",  # Samsung
        "357223064567890",  # Apple
        "358240055678901",  # Huawei
        "868988046789012",  # Xiaomi
        "351885107890123",  # Nokia
    ]
    
    print(f"{Cores.AMARELO}[*] IMEIs de exemplo para teste:{Cores.RESET}")
    for i, imei in enumerate(imeis_exemplo, 1):
        print(f"  {Cores.CIANO}{i}. {imei}{Cores.RESET}")

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar IMEI")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Validar IMEI")
    print(f"{Cores.VERDE}[3]{Cores.RESET} IMEIs de Exemplo")
    print(f"{Cores.VERDE}[4]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[5]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '5'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR IMEI{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Validação completa usando algoritmo Luhn
- Base de dados com milhares de dispositivos
- Identificação de fabricante e modelo
- Informações do país de origem
- Análise estrutural do IMEI
- Cache inteligente para performance

{Cores.AMARELO}O que é IMEI?{Cores.RESET}
IMEI (International Mobile Equipment Identity) é um número único
de 15 dígitos que identifica cada dispositivo móvel.

{Cores.AMARELO}Estrutura do IMEI:{Cores.RESET}
- TAC (8 dígitos): Type Allocation Code - Identifica modelo/fabricante
- SNR (6 dígitos): Serial Number - Número de série único
- DV (1 dígito): Dígito Verificador - Validação Luhn

{Cores.AMARELO}Validação Luhn:{Cores.RESET}
Algoritmo matemático que verifica a validade do número através
do dígito verificador.

{Cores.VERDE}Pressione Enter para voltar...{Cores.RESET}""")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    try:
        # Baixar base de dados na inicialização
        print(f"{Cores.AMARELO}[*] Inicializando consultor IMEI...{Cores.RESET}")
        base_carregada = baixar_base_imei()
        
        if not base_carregada:
            print(f"{Cores.VERMELHO}[!] Base de dados não pôde ser carregada{Cores.RESET}")
            print(f"{Cores.AMARELO}[*] Funcionalidade limitada - apenas validação{Cores.RESET}")
        
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                try:
                    imei = input(f"\n{Cores.CIANO}Digite o IMEI (15 dígitos): {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                # Remover espaços e caracteres especiais
                imei = re.sub(r'[^0-9]', '', imei)
                
                if not imei:
                    print(f"{Cores.VERMELHO}[!] IMEI não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                if len(imei) != 15:
                    print(f"{Cores.VERMELHO}[!] IMEI deve ter exatamente 15 dígitos{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                # Consultar IMEI
                resultado = consultar_todos_dados_imei(imei)
                
                banner()
                sucesso = exibir_resultados_imei(resultado)
                
                # Opção de exportação
                if sucesso:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(resultado, imei, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(resultado, imei, 'txt')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '2':
                banner()
                try:
                    imei = input(f"\n{Cores.CIANO}Digite o IMEI para validação: {Cores.RESET}").strip()
                    imei = re.sub(r'[^0-9]', '', imei)
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not imei:
                    print(f"{Cores.VERMELHO}[!] IMEI não pode estar vazio{Cores.RESET}")
                elif len(imei) != 15:
                    print(f"{Cores.VERMELHO}[!] IMEI deve ter 15 dígitos{Cores.RESET}")
                else:
                    if validar_imei(imei):
                        print(f"{Cores.VERDE}[+] IMEI VÁLIDO ✓{Cores.RESET}")
                        
                        # Mostrar dígito verificador calculado
                        digito_calculado = calcular_digito_verificador(imei[:14])
                        print(f"{Cores.AZUL}Dígito verificador calculado: {digito_calculado}{Cores.RESET}")
                        print(f"{Cores.AZUL}Dígito verificador real: {imei[14]}{Cores.RESET}")
                    else:
                        print(f"{Cores.VERMELHO}[!] IMEI INVÁLIDO ✗{Cores.RESET}")
                        
                        # Sugerir correção
                        digito_correto = calcular_digito_verificador(imei[:14])
                        if digito_correto is not None:
                            imei_corrigido = imei[:14] + str(digito_correto)
                            print(f"{Cores.AMARELO}[*] IMEI correto seria: {imei_corrigido}{Cores.RESET}")
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '3':
                banner()
                testar_imei_exemplo()
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '4':
                sobre()
            
            elif opcao == '5':
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
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor IMEI!{Cores.RESET}")

if __name__ == "__main__":
    # Verificar dependências
    try:
        import requests
    except ImportError:
        print(f"{Cores.VERMELHO}[!] Biblioteca 'requests' não encontrada.{Cores.RESET}")
        print(f"{Cores.AMARELO}[*] Instale com: pip install requests{Cores.RESET}")
        sys.exit(1)
    
    main()
