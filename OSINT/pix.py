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
os.makedirs('cache_pix', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# APIs públicas para consulta de dados relacionados (simuladas)
APIS = {
    'BancoCentral': {
        'url': "https://api.bcb.gov.br/pix/v1/participants/{chave}",
        'fields': {
            'banco': 'nomeInstituicao',
            'ispb': 'ispb',
            'servico': 'Banco Central'
        },
        'fake': True
    },
    'RegistroBR': {
        'url': "https://registro.br/v2/ajax/pix/{chave}",
        'fields': {
            'tipo': 'tipo',
            'registrado_em': 'created',
            'servico': 'Registro.br'
        },
        'fake': True
    },
    'WhatsApp': {
        'url': "https://web.whatsapp.com/send?phone={chave}",
        'fields': {
            'existe': 'status',
            'servico': 'WhatsApp'
        },
        'fake': False
    }
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.MAGENTA}{Cores.NEGRITO}
   ██████╗ ██╗██╗  ██╗
   ██╔══██╗██║╚██╗██╔╝
   ██████╔╝██║ ╚███╔╝ 
   ██╔═══╝ ██║ ██╔██╗ 
   ██║     ██║██╔╝ ██╗
   ╚═╝     ╚═╝╚═╝  ╚═╝
{Cores.RESET}
{Cores.CIANO}{Cores.NEGRITO}   CONSULTOR PIX AVANÇADO
   Versão Termux - Sem Chaves API
{Cores.RESET}
{Cores.AMARELO}   Verificação de chaves PIX públicas
   Dados simulados para estudo
{Cores.RESET}""")

def validar_chave(chave):
    """Valida os formatos de chave PIX mais comuns"""
    if not chave:
        return False
    
    # CPF (11 dígitos)
    if re.match(r'^\d{11}$', chave):
        return True
    
    # CNPJ (14 dígitos)
    if re.match(r'^\d{14}$', chave):
        return True
    
    # Telefone (DDD + número)
    if re.match(r'^(\+55)?\d{10,11}$', chave.replace(" ", "")):
        return True
    
    # Email (formato básico)
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', chave):
        return True
    
    # Chave aleatória (UUID)
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', chave.lower()):
        return True
    
    return False

def formatar_chave(chave):
    """Formata a chave para exibição"""
    if not chave:
        return ""
    
    # Telefone
    if re.match(r'^(\+55)?\d{10,11}$', chave.replace(" ", "")):
        num = re.sub(r'[^0-9]', '', chave)
        return f"+{num[:2]} {num[2:7]}-{num[7:]}" if len(num) == 12 else f"{num[:2]} {num[2:6]}-{num[6:]}"
    
    return chave

def gerar_hash(texto):
   
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
   
    try:
        caminho = f"cache_pix/{nome}.json"
        if dados is not None:  # Modo escrita
            with open(caminho, 'w', encoding='utf-8') as f:
                json.dump({'data': dados, 'timestamp': time.time()}, f)
            return dados
        else: 
            if os.path.exists(caminho):
                with open(caminho, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                    if time.time() - cache['timestamp'] < TEMPO_CACHE:
                        return cache['data']
        return None
    except (IOError, json.JSONDecodeError):
        return None

def consultar_api(nome_api, config, chave):
    """Consulta uma API específica"""
    if not chave or not validar_chave(chave):
        return None
        
    cache_id = f"{nome_api}_{gerar_hash(chave)}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        if config.get('fake', False):
            # Resposta simulada
            resultado = {
                'chave': chave,
                'servico': nome_api,
                'status': 'simulado'
            }
            
            # Dados fictícios baseados no tipo de chave
            if re.match(r'^\d{11}$', chave):  # CPF
                resultado.update({
                    'tipo': 'CPF',
                    'banco': 'Banco Simulado S.A.',
                    'titular': 'Fulano da Silva'
                })
            elif re.match(r'^\d{14}$', chave):  # CNPJ
                resultado.update({
                    'tipo': 'CNPJ',
                    'banco': 'Banco Empresarial LTDA',
                    'razao_social': 'Empresa Simulada ME'
                })
            elif '@' in chave:  # Email
                resultado.update({
                    'tipo': 'Email',
                    'banco': 'Banco Digital',
                    'titular': chave.split('@')[0]
                })
            else:  # Telefone ou aleatória
                resultado.update({
                    'tipo': 'Telefone' if re.match(r'^(\+55)?\d{10,11}$', chave.replace(" ", "")) else 'Aleatória',
                    'banco': 'Banco Popular',
                    'titular': 'Cliente Genérico'
                })
            
            cache_arquivo(cache_id, resultado)
            return resultado
        
        # Consulta real (apenas WhatsApp neste exemplo)
        if nome_api == 'WhatsApp':
            url = config['url'].format(chave=chave)
            headers = {'User-Agent': 'Mozilla/5.0 (Termux; Linux arm64)'}
            response = requests.head(url, headers=headers, timeout=15)
            
            resultado = {
                'chave': chave,
                'servico': 'WhatsApp',
                'existe': response.status_code == 200,
                'status': 'sucesso' if response.status_code == 200 else 'não encontrado'
            }
            
            cache_arquivo(cache_id, resultado)
            return resultado
            
    except requests.RequestException as e:
        return {
            'chave': chave,
            'servico': nome_api,
            'status': 'erro',
            'erro': str(e)
        }
    
    return None

def consultar_apis_paralelo(chave):
   
    if not validar_chave(chave):
        return {}
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(consultar_api, nome, config, chave): nome
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
        'tipo': ['RegistroBR', 'BancoCentral'],
        'banco': ['BancoCentral', 'RegistroBR'],
        'titular': ['BancoCentral', 'RegistroBR'],
        'existe': ['WhatsApp']
    }
    
    final = {
        'chave': next(iter(resultados.values()))['chave'] if resultados else None,
        'status': 'simulado' if any(r.get('status') == 'simulado' for r in resultados.values()) else 'real'
    }
    
    for campo, fontes in campos_prioritarios.items():
        for fonte in fontes:
            if fonte in resultados and campo in resultados[fonte] and resultados[fonte][campo]:
                final[campo] = resultados[fonte][campo]
                break
    
    if final:
        final['fontes'] = ', '.join(resultados.keys())
    return final if final else None

def exibir_resultados(dados):
    """Exibe os resultados formatados"""
    if not dados:
        print(f"{Cores.VERMELHO}[!] Nenhum dado encontrado para esta chave{Cores.RESET}")
        return
    
    chave_formatada = formatar_chave(dados.get('chave', ''))
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== DADOS DA CHAVE PIX ==={Cores.RESET}")
    print(f"{Cores.AZUL}Chave:{Cores.RESET} {chave_formatada}")
    print(f"{Cores.AZUL}Tipo:{Cores.RESET} {dados.get('tipo', 'N/A')}")
    
    if 'banco' in dados:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES BANCÁRIAS ==={Cores.RESET}")
        print(f"{Cores.AZUL}Banco:{Cores.RESET} {dados['banco']}")
    
    if 'titular' in dados:
        print(f"{Cores.AZUL}Titular:{Cores.RESET} {dados['titular']}")
    
    if 'existe' in dados:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== STATUS ==={Cores.RESET}")
        status = "Sim" if dados['existe'] else "Não"
        cor = Cores.VERDE if dados['existe'] else Cores.VERMELHO
        print(f"{Cores.AZUL}Registrado:{Cores.RESET} {cor}{status}{Cores.RESET}")
    
    print(f"\n{Cores.AZUL}Fontes consultadas:{Cores.RESET} {dados.get('fontes', 'N/A')}")
    print(f"{Cores.AZUL}Tipo de dados:{Cores.RESET} {dados.get('status', 'N/A')}")

def salvar_resultado(dados, formato='txt'):
    """Salva os resultados em arquivo"""
    if not dados:
        return False
    
    try:
        chave_hash = gerar_hash(dados.get('chave', 'sem_chave'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_pix', exist_ok=True)
        nome_arquivo = f"resultados_pix/pix_{chave_hash}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DA CHAVE PIX ===\n\n")
                f.write(f"CHAVE:    {formatar_chave(dados.get('chave', 'N/A'))}\n")
                f.write(f"TIPO:     {dados.get('tipo', 'N/A')}\n")
                
                if 'banco' in dados:
                    f.write(f"\n=== INFORMAÇÕES BANCÁRIAS ===\n")
                    f.write(f"BANCO:    {dados['banco']}\n")
                    if 'titular' in dados:
                        f.write(f"TITULAR:  {dados['titular']}\n")
                
                if 'existe' in dados:
                    f.write(f"\n=== STATUS ===\n")
                    f.write(f"REGISTRADO: {'Sim' if dados['existe'] else 'Não'}\n")
                
                f.write(f"\nFONTES:   {dados.get('fontes', 'N/A')}\n")
                f.write(f"TIPO DE DADOS: {dados.get('status', 'N/A')}\n")
                f.write(f"DATA:     {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Consultar chave PIX")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O CONSULTOR PIX{Cores.RESET}

{Cores.AMARELO}Aviso importante:{Cores.RESET}
Este é um projeto educacional que utiliza dados simulados.
Não é possível obter dados reais de chaves PIX sem autorização.

{Cores.AMARELO}Formatos suportados:{Cores.RESET}
- CPF (11 dígitos)
- CNPJ (14 dígitos)
- Telefone (com DDD)
- Email
- Chave aleatória (UUID)

{Cores.AMARELO}Funcionalidades:{Cores.RESET}
- Simulação de consulta bancária
- Verificação de número no WhatsApp
- Cache de consultas
- Exportação de resultados

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
                    chave = input(f"\n{Cores.CIANO}Digite a chave PIX (CPF, CNPJ, telefone, email ou aleatória): {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not validar_chave(chave):
                    print(f"{Cores.VERMELHO}[!] Chave inválida. Formatos aceitos: CPF, CNPJ, telefone, email ou UUID{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"\n{Cores.AMARELO}[*] Consultando chave PIX...{Cores.RESET}")
                
                resultados = consultar_apis_paralelo(chave)
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
        print(f"{Cores.CIANO}\nObrigado por usar o Consultor PIX!{Cores.RESET}")

if __name__ == "__main__":
    main()
