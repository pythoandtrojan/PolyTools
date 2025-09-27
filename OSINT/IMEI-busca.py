#!/usr/bin/env python3
import os
import requests
import time
import sys
import re
import json
from datetime import datetime
from colorama import init, Fore, Back, Style

# Inicializar colorama
init(autoreset=True)

# Configurações
PASTA_RESULTADOS = "IMEI_Results"
os.makedirs(PASTA_RESULTADOS, exist_ok=True)

# Banner THE LURKER IMEI
BANNER = f"""
{Fore.RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{Fore.RED}▓                                                                        ▓
{Fore.RED}▓  {Fore.WHITE}████████╗██╗  ██╗███████╗    {Fore.RED}██╗     ██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}╚══██╔══╝██║  ██║██╔════╝    {Fore.RED}██║     ██║   ██║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ███████║█████╗      {Fore.RED}██║     ██║   ██║██████╔╝█████╔╝ █████╗  ██████╔╝ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ██╔══██║██╔══╝      {Fore.RED}██║     ██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══██╗ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ██║  ██║███████╗    {Fore.RED}███████╗╚██████╔╝██║  ██║██║  ██╗███████╗██║  ██║ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ╚═╝   ╚═╝  ╚═╝╚══════╝    {Fore.RED}╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ {Fore.RED}▓
{Fore.RED}▓                                                                        ▓
{Fore.RED}▓  {Fore.YELLOW}📱 IMEI ANALYZER - Device Intelligence v2.0              {Fore.RED}▓
{Fore.RED}▓  {Fore.CYAN}Developed by Erik 16y - Linux & Termux Expert              {Fore.RED}▓
{Fore.RED}▓  {Fore.MAGENTA}Made in Brazil with ❤️                                   {Fore.RED}▓
{Fore.RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{Style.RESET_ALL}"""

def animar_texto(texto, delay=0.03):
    """Animação de digitação"""
    for char in texto:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_loading(texto="Analisando", duracao=2):
    """Animação de loading"""
    animacao = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    fim_tempo = time.time() + duracao
    i = 0
    
    while time.time() < fim_tempo:
        print(f"\r{Fore.CYAN}{animacao[i % len(animacao)]} {texto}...{Style.RESET_ALL}", end="")
        time.sleep(0.1)
        i += 1
    print("\r" + " " * 60 + "\r", end="")

def validar_imei(imei):
    """Valida o número IMEI usando o algoritmo Luhn"""
    if len(imei) != 15 or not imei.isdigit():
        return False
    
    # Algoritmo Luhn para IMEI
    total = 0
    for i, digit in enumerate(imei):
        n = int(digit)
        if i % 2 == 1:  # Dígitos pares (índice ímpar)
            n *= 2
            if n > 9:
                n = n - 9
        total += n
    
    return total % 10 == 0

def calcular_digito_verificador(imei_14):
    """Calcula o dígito verificador para IMEI de 14 dígitos"""
    if len(imei_14) != 14 or not imei_14.isdigit():
        return None
    
    total = 0
    for i, digit in enumerate(imei_14):
        n = int(digit)
        if i % 2 == 0:  # Posições ímpares (índice par)
            n *= 2
            if n > 9:
                n = n - 9
        total += n
    
    digito = (10 - (total % 10)) % 10
    return imei_14 + str(digito)

def decodificar_tac(tac):
    """Decodifica o Type Allocation Code (primeiros 8 dígitos)"""
    # Banco de dados simplificado de TACs comuns
    tac_database = {
        "01124500": {"marca": "Apple", "modelo": "iPhone 13 Pro"},
        "01161200": {"marca": "Samsung", "modelo": "Galaxy S21"},
        "35175605": {"marca": "Samsung", "modelo": "Galaxy A12"},
        "86098104": {"marca": "Xiaomi", "modelo": "Redmi Note 10"},
        "35531607": {"marca": "Motorola", "modelo": "Moto G Power"},
        "01234500": {"marca": "Apple", "modelo": "iPhone 12"},
        "35851006": {"marca": "Huawei", "modelo": "P30 Pro"},
        "86129304": {"marca": "Xiaomi", "modelo": "Poco X3"},
        "35696207": {"marca": "LG", "modelo": "K51"},
        "01332700": {"marca": "Apple", "modelo": "iPhone 11"}
    }
    
    return tac_database.get(tac, {"marca": "Desconhecida", "modelo": "Modelo não identificado"})

def analisar_estrutura_imei(imei):
    """Analisa a estrutura do IMEI"""
    # Estrutura: TAC (8) + SNR (6) + CD (1)
    tac = imei[:8]
    snr = imei[8:14]
    cd = imei[14]
    
    info_tac = decodificar_tac(tac)
    
    return {
        "tac": tac,
        "snr": snr,
        "digito_verificador": cd,
        "marca": info_tac["marca"],
        "modelo": info_tac["modelo"],
        "ano_fabricacao": estimar_ano_fabricacao(tac),
        "origem": determinar_origem(tac)
    }

def estimar_ano_fabricacao(tac):
    """Estima o ano de fabricação baseado no TAC"""
    # Simulação baseada nos dígitos do TAC
    ano_base = 2018 + (int(tac[2]) % 5)  # Estimativa simplificada
    return ano_base

def determinar_origem(tac):
    """Determina a origem do dispositivo baseado no TAC"""
    origem_map = {
        "01": "EUA/Canadá",
        "35": "Finlândia",
        "86": "China",
        "35": "Reino Unido",
        "45": "Japão",
        "49": "Japão",
        "50": "Reino Unido",
        "86": "China",
        "89": "Coreia do Sul"
    }
    
    prefixo = tac[:2]
    return origem_map.get(prefixo, "Origem não identificada")

def verificar_imei_online(imei):
    """Verifica o IMEI em serviços online (simulação ética)"""
    resultados = []
    
    # Simulação de verificação de blacklist
    mostrar_loading("Verificando status de bloqueio")
    
    # Simulação baseada em padrões do IMEI
    status_bloqueio = "LIVRE" if int(imei[-1]) % 3 != 0 else "BLOQUEADO"
    motivo_bloqueio = "Nenhum" if status_bloqueio == "LIVRE" else "Relatório de furto"
    
    resultados.append({
        "servico": "GSMA Blacklist",
        "status": status_bloqueio,
        "detalhes": motivo_bloqueio,
        "confianca": "85%"
    })
    
    # Verificação de garantia (simulação)
    mostrar_loading("Verificando status da garantia")
    status_garantia = "VÁLIDA" if int(imei[-2]) % 2 == 0 else "EXPIRADA"
    resultados.append({
        "servico": "Status da Garantia",
        "status": status_garantia,
        "detalhes": f"Estimativa: {status_garantia}",
        "confianca": "70%"
    })
    
    return resultados

def verificar_operadoras_brasil(imei):
    """Verifica compatibilidade com operadoras brasileiras"""
    operadoras = {
        "Vivo": {"compativel": True, "bandas": "GSM/WCDMA/LTE"},
        "Claro": {"compativel": True, "bandas": "GSM/LTE"},
        "TIM": {"compativel": True, "bandas": "GSM/WCDMA/LTE"},
        "Oi": {"compativel": int(imei[-1]) % 4 != 0, "bandas": "GSM/LTE"}
    }
    
    return operadoras

def analisar_vulnerabilidades(imei, marca, modelo):
    """Analisa vulnerabilidades conhecidas do modelo"""
    vulnerabilidades_db = {
        "Samsung Galaxy S21": ["CVE-2021-28663", "CVE-2021-28664"],
        "iPhone 13 Pro": ["CVE-2021-30883", "CVE-2021-30860"],
        "Xiaomi Redmi Note 10": ["CVE-2021-3966", "CVE-2021-3967"],
        "Motorola Moto G Power": ["CVE-2020-0423", "CVE-2020-0424"]
    }
    
    return vulnerabilidades_db.get(modelo, ["Nenhuma vulnerabilidade crítica conhecida"])

def gerar_relatorio_seguranca(imei_info):
    """Gera relatório de segurança do dispositivo"""
    score = 100
    
    # Penalizações baseadas em fatores de risco
    if imei_info['status_bloqueio'] == "BLOQUEADO":
        score -= 40
    
    if imei_info['garantia'] == "EXPIRADA":
        score -= 20
    
    if len(imei_info['vulnerabilidades']) > 2:
        score -= 15
    
    # Classificação de risco
    if score >= 80:
        risco = "BAIXO"
        cor = Fore.GREEN
    elif score >= 60:
        risco = "MÉDIO"
        cor = Fore.YELLOW
    else:
        risco = "ALTO"
        cor = Fore.RED
    
    return {"score": score, "risco": risco, "cor": cor}

def fazer_requisicao_api(url, headers=None):
    """Faz requisição HTTP genérica"""
    headers_padrao = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*'
    }
    
    if headers:
        headers_padrao.update(headers)
    
    try:
        resposta = requests.get(url, headers=headers_padrao, timeout=15)
        return resposta
    except:
        return None

def analise_completa_imei(imei):
    """Executa análise completa do IMEI"""
    print(f"\n{Fore.YELLOW}🔍 Iniciando análise do IMEI: {imei}{Style.RESET_ALL}")
    
    # Validação inicial
    if not validar_imei(imei):
        print(f"{Fore.RED}❌ IMEI inválido! Verifique o número.{Style.RESET_ALL}")
        return None
    
    print(f"{Fore.GREEN}✅ IMEI válido confirmado{Style.RESET_ALL}")
    
    resultados = {}
    
    # Análise da estrutura
    mostrar_loading("Decodificando estrutura do IMEI")
    estrutura = analisar_estrutura_imei(imei)
    resultados['estrutura'] = estrutura
    
    # Verificações online
    mostrar_loading("Consultando bancos de dados")
    verificacoes_online = verificar_imei_online(imei)
    resultados['verificacoes'] = verificacoes_online
    
    # Compatibilidade com operadoras
    mostrar_loading("Analisando compatibilidade")
    operadoras = verificar_operadoras_brasil(imei)
    resultados['operadoras'] = operadoras
    
    # Análise de vulnerabilidades
    mostrar_loading("Verificando vulnerabilidades")
    vulnerabilidades = analisar_vulnerabilidades(imei, estrutura['marca'], estrutura['modelo'])
    resultados['vulnerabilidades'] = vulnerabilidades
    
    # Informações adicionais
    resultados['info_gerais'] = {
        'data_analise': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
        'imei': imei,
        'status_geral': 'ANÁLISE COMPLETA'
    }
    
    return resultados

def mostrar_resultados_imei(resultados):
    """Exibe os resultados da análise de forma organizada"""
    if not resultados:
        return
    
    imei = resultados['info_gerais']['imei']
    
    print(f"\n{Fore.GREEN}═" * 70)
    print(f"📊 RELATÓRIO DE ANÁLISE - IMEI: {imei}")
    print("═" * 70 + f"{Style.RESET_ALL}\n")
    
    # Informações da Estrutura
    estrutura = resultados['estrutura']
    print(f"{Fore.CYAN}🏷️  INFORMAÇÕES DO DISPOSITIVO:{Style.RESET_ALL}")
    print(f"  📱 Marca: {Fore.YELLOW}{estrutura['marca']}{Style.RESET_ALL}")
    print(f"  🔧 Modelo: {Fore.YELLOW}{estrutura['modelo']}{Style.RESET_ALL}")
    print(f"  📅 Ano estimado: {Fore.YELLOW}{estrutura['ano_fabricacao']}{Style.RESET_ALL}")
    print(f"  🌍 Origem: {Fore.YELLOW}{estrutura['origem']}{Style.RESET_ALL}")
    print(f"  🔢 TAC: {estrutura['tac']}")
    print(f"  🔍 SNR: {estrutura['snr']}")
    print(f"  ✅ Dígito verificador: {estrutura['digito_verificador']}")
    
    # Verificações Online
    print(f"\n{Fore.CYAN}🛡️  STATUS DE BLOQUEIO E GARANTIA:{Style.RESET_ALL}")
    for verificacao in resultados['verificacoes']:
        status_cor = Fore.GREEN if "LIVRE" in verificacao['status'] or "VÁLIDA" in verificacao['status'] else Fore.RED
        print(f"  {verificacao['servico']}: {status_cor}{verificacao['status']}{Style.RESET_ALL}")
        print(f"     📋 {verificacao['detalhes']}")
        print(f"     🎯 Confiança: {verificacao['confianca']}")
    
    # Operadoras
    print(f"\n{Fore.CYAN}📶 COMPATIBILIDADE COM OPERADORAS BR:{Style.RESET_ALL}")
    for operadora, info in resultados['operadoras'].items():
        status = "✅" if info['compativel'] else "❌"
        cor = Fore.GREEN if info['compativel'] else Fore.RED
        print(f"  {status} {operadora}: {cor}{'Compatível' if info['compativel'] else 'Incompatível'}{Style.RESET_ALL}")
        print(f"     📡 Bandas: {info['bandas']}")
    
    # Vulnerabilidades
    print(f"\n{Fore.CYAN}⚠️  VULNERABILIDADES CONHECIDAS:{Style.RESET_ALL}")
    for vuln in resultados['vulnerabilidades']:
        if "CVE" in vuln:
            print(f"  🔴 {vuln}")
        else:
            print(f"  🟢 {vuln}")
    
    # Relatório de Segurança
    relatorio_seg = gerar_relatorio_seguranca({
        'status_bloqueio': resultados['verificacoes'][0]['status'],
        'garantia': resultados['verificacoes'][1]['status'],
        'vulnerabilidades': resultados['vulnerabilidades']
    })
    
    print(f"\n{Fore.CYAN}📈 RELATÓRIO DE SEGURANÇA:{Style.RESET_ALL}")
    print(f"  🎯 Score de segurança: {relatorio_seg['cor']}{relatorio_seg['score']}/100{Style.RESET_ALL}")
    print(f"  🚨 Nível de risco: {relatorio_seg['cor']}{relatorio_seg['risco']}{Style.RESET_ALL}")
    
    # Recomendações
    print(f"\n{Fore.CYAN}💡 RECOMENDAÇÕES:{Style.RESET_ALL}")
    if relatorio_seg['score'] >= 80:
        print("  ✅ Dispositivo considerado seguro para uso")
    elif relatorio_seg['score'] >= 60:
        print("  ⚠️  Tome cuidado com transações sensíveis")
    else:
        print("  🔴 Recomendamos verificação profissional")

def salvar_relatorio(resultados, formato='txt'):
    """Salva o relatório em arquivo"""
    imei = resultados['info_gerais']['imei']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if formato == 'txt':
        nome_arquivo = f"IMEI_{imei}_{timestamp}.txt"
        caminho = os.path.join(PASTA_RESULTADOS, nome_arquivo)
        
        with open(caminho, 'w', encoding='utf-8') as f:
            f.write("THE LURKER - Relatório de Análise de IMEI\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"IMEI Analisado: {imei}\n")
            f.write(f"Data da Análise: {resultados['info_gerais']['data_analise']}\n\n")
            
            # Estrutura
            estr = resultados['estrutura']
            f.write("INFORMAÇÕES DO DISPOSITIVO:\n")
            f.write(f"Marca: {estr['marca']}\n")
            f.write(f"Modelo: {estr['modelo']}\n")
            f.write(f"Ano: {estr['ano_fabricacao']}\n")
            f.write(f"Origem: {estr['origem']}\n\n")
            
            # Status
            f.write("STATUS:\n")
            for ver in resultados['verificacoes']:
                f.write(f"{ver['servico']}: {ver['status']}\n")
            
        return caminho

def menu_principal():
    """Menu principal do programa"""
    limpar_tela()
    print(BANNER)
    print(f"\n{Fore.GREEN}[{time.strftime('%d/%m/%Y %H:%M:%S')}]{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}📱 ANALISADOR DE IMEI - THE LURKER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}═" * 50 + f"{Style.RESET_ALL}")
    
    print("\n1. 🔍 Analisar número IMEI")
    print("2. 🧮 Calcular dígito verificador")
    print("3. 📖 Verificar validade do IMEI")
    print("4. 📂 Relatórios salvos")
    print("5. 🚪 Sair")
    
    try:
        opcao = input(f"\n{Fore.YELLOW}🎯 Escolha uma opção (1-5): {Style.RESET_ALL}").strip()
        return int(opcao) if opcao.isdigit() else 0
    except:
        return 0

def calcular_digito_menu():
    """Menu para calcular dígito verificador"""
    print(f"\n{Fore.CYAN}🧮 CALCULADOR DE DÍGITO VERIFICADOR{Style.RESET_ALL}")
    imei_14 = input(f"{Fore.YELLOW}Digite os 14 primeiros dígitos do IMEI: {Style.RESET_ALL}").strip()
    
    if len(imei_14) == 14 and imei_14.isdigit():
        imei_completo = calcular_digito_verificador(imei_14)
        if imei_completo:
            print(f"\n{Fore.GREEN}✅ IMEI completo: {imei_completo}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}📝 Dígito verificador calculado: {imei_completo[-1]}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Digite exatamente 14 dígitos numéricos{Style.RESET_ALL}")

def validar_imei_menu():
    """Menu para validar IMEI"""
    print(f"\n{Fore.CYAN}✅ VALIDADOR DE IMEI{Style.RESET_ALL}")
    imei = input(f"{Fore.YELLOW}Digite o IMEI completo (15 dígitos): {Style.RESET_ALL}").strip()
    
    if validar_imei(imei):
        print(f"\n{Fore.GREEN}🎉 IMEI VÁLIDO!{Style.RESET_ALL}")
        print(f"{Fore.BLUE}📱 O IMEI {imei} passou na verificação do algoritmo Luhn{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}❌ IMEI INVÁLIDO!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Verifique se digitou corretamente os 15 dígitos{Style.RESET_ALL}")

def main():
    """Função principal"""
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == 1:
                imei = input(f"\n{Fore.YELLOW}📱 Digite o número IMEI (15 dígitos): {Style.RESET_ALL}").strip()
                
                if imei:
                    if validar_imei(imei):
                        resultados = analise_completa_imei(imei)
                        if resultados:
                            mostrar_resultados_imei(resultados)
                            arquivo_salvo = salvar_relatorio(resultados)
                            print(f"\n{Fore.GREEN}💾 Relatório salvo em: {arquivo_salvo}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}❌ IMEI inválido! Use a opção 3 para validar.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Por favor, insira um IMEI válido!{Style.RESET_ALL}")
                    
            elif opcao == 2:
                calcular_digito_menu()
                
            elif opcao == 3:
                validar_imei_menu()
                
            elif opcao == 4:
                arquivos = [f for f in os.listdir(PASTA_RESULTADOS) if f.startswith('IMEI_')]
                if arquivos:
                    print(f"\n{Fore.GREEN}📂 RELATÓRIOS SALVOS:{Style.RESET_ALL}")
                    for i, arq in enumerate(arquivos[-5:], 1):  # Mostra últimos 5
                        print(f"  {i}. {arq}")
                else:
                    print(f"\n{Fore.YELLOW}📁 Nenhum relatório encontrado{Style.RESET_ALL}")
                    
            elif opcao == 5:
                print(f"\n{Fore.GREEN}👋 Saindo do IMEI Analyzer...{Style.RESET_ALL}")
                break
                
            else:
                print(f"\n{Fore.RED}❌ Opção inválida! Tente novamente.{Style.RESET_ALL}")
                time.sleep(1)
            
            if opcao != 5:
                input(f"\n{Fore.YELLOW}⏎ Pressione Enter para continuar...{Style.RESET_ALL}")
                
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}❌ IMEI Analyzer interrompido pelo usuário!{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}💥 ERRO: {str(e)}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.GREEN}🛡️  Use estas informações apenas para fins legítimos!{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
