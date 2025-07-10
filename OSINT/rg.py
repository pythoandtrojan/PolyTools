#!/usr/bin/env python3
import requests
import json
import os
import sys
from datetime import datetime
from time import sleep
import platform
from pyfiglet import Figlet
from colorama import Fore, Back, Style, init

# Inicializa colorama
init(autoreset=True)

# Configurações
API_URL = "https://777apisss.vercel.app/consulta/rg/"
API_KEY = "firminoh7778"
OUTPUT_DIR = "consultas_rg"
LOG_FILE = "consultas.log"

# Cores personalizadas
class Cores:
    TITULO = Fore.CYAN + Style.BRIGHT
    DADO = Fore.WHITE + Style.BRIGHT
    VALOR = Fore.YELLOW
    ERRO = Fore.RED + Style.BRIGHT
    SUCESSO = Fore.GREEN + Style.BRIGHT
    DESTAQUE = Fore.MAGENTA + Style.BRIGHT
    BANNER = Fore.BLUE + Style.BRIGHT

# Verificar e instalar dependências necessárias
def verificar_dependencias():
    try:
        import pyfiglet
        import colorama
    except ImportError:
        print(f"{Cores.ERRO}Dependências não encontradas. Instalando...")
        try:
            import pip
            pip.main(['install', 'pyfiglet', 'colorama'])
            print(f"{Cores.SUCESSO}Dependências instaladas com sucesso!")
            sleep(2)
        except:
            print(f"{Cores.ERRO}Erro ao instalar dependências. Instale manualmente:")
            print("pip install pyfiglet colorama")
            sys.exit(1)

# Criar diretórios necessários
def criar_diretorios():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

# Banner profissional
def mostrar_banner():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
    
    f = Figlet(font='slant')
    print(f"{Cores.BANNER}{f.renderText('Valkyria RG')}")
    print(f"{Cores.DESTAQUE}{'='*60}")
    print(f"{Cores.DESTAQUE} SISTEMA DE CONSULTA DE DOCUMENTOS - RG")
    print(f"{Cores.DESTAQUE} Versão 2.1 | Segurança da Informação")
    print(f"{Cores.DESTAQUE}{'='*60}\n")

# Consulta à API
def consultar_rg(rg):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) ValkyriaRG/2.1',
        'Accept': 'application/json'
    }
    
    params = {
        'query': rg,
        'apikey': API_KEY
    }
    
    try:
        resposta = requests.get(
            API_URL,
            params=params,
            headers=headers,
            timeout=15
        )
        
        resposta.raise_for_status()
        return resposta.json()
    
    except requests.exceptions.RequestException as e:
        print(f"{Cores.ERRO}Erro na consulta: {str(e)}")
        return None

# Exibir resultados formatados
def exibir_resultados(data):
    if not data or data.get('status') != 1:
        print(f"\n{Cores.ERRO}Nenhum dado encontrado para este RG")
        return
    
    registro = data['dados'][0]
    
    print(f"\n{Cores.TITULO}{' DADOS ENCONTRADOS ':=^60}")
    
    # Seção de dados pessoais
    print(f"\n{Cores.DADO}➤ DADOS PESSOAIS")
    print(f"{Cores.DADO}┌{'─'*58}┐")
    print(f"{Cores.DADO}│ {Cores.DADO}Nome: {Cores.VALOR}{registro.get('NOME', 'Não informado'):<49}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Mãe: {Cores.VALOR}{registro.get('NOME_MAE', 'Não informado'):<50}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Pai: {Cores.VALOR}{registro.get('NOME_PAI', 'Não informado'):<50}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Nascimento: {Cores.VALOR}{registro.get('NASC', 'Não informado'):<44}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Sexo: {Cores.VALOR}{registro.get('SEXO', 'Não informado'):<50}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Estado Civil: {Cores.VALOR}{registro.get('ESTCIV', 'Não informado'):<43}│")
    print(f"{Cores.DADO}└{'─'*58}┘")
    
    # Seção de documentos
    print(f"\n{Cores.DADO}➤ DOCUMENTOS")
    print(f"{Cores.DADO}┌{'─'*58}┐")
    print(f"{Cores.DADO}│ {Cores.DADO}RG: {Cores.VALOR}{registro.get('RG', 'Não informado'):<51}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Órgão Emissor: {Cores.VALOR}{registro.get('ORGAO_EMISSOR', 'Não informado'):<40}│")
    print(f"{Cores.DADO}│ {Cores.DADO}UF Emissão: {Cores.VALOR}{registro.get('UF_EMISSAO', 'Não informado'):<44}│")
    print(f"{Cores.DADO}│ {Cores.DADO}CPF: {Cores.VALOR}{registro.get('CPF', 'Não informado'):<51}│")
    print(f"{Cores.DADO}└{'─'*58}┘")
    
    # Seção de informações adicionais
    print(f"\n{Cores.DADO}➤ INFORMAÇÕES ADICIONAIS")
    print(f"{Cores.DADO}┌{'─'*58}┐")
    print(f"{Cores.DADO}│ {Cores.DADO}CBO: {Cores.VALOR}{registro.get('CBO', 'Não informado'):<51}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Mosaic: {Cores.VALOR}{registro.get('CD_MOSAIC', 'N/A'):<47}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Situação Cadastral: {Cores.VALOR}{registro.get('CD_SIT_CAD', 'Não informado'):<36}│")
    print(f"{Cores.DADO}│ {Cores.DADO}Última Atualização: {Cores.VALOR}{registro.get('DT_INFORMACAO', 'Não informado'):<36}│")
    print(f"{Cores.DADO}└{'─'*58}┘")
    
    print(f"\n{Cores.DADO}Consulta realizada em: {Cores.VALOR}{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"{Cores.DADO}Fonte: {Cores.VALOR}{data.get('criador', 'Sistema Valkyria')}\n")

# Salvar resultados em arquivo
def salvar_consulta(data, rg):
    if not data:
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"RG_{rg}_{timestamp}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Registrar no log
        with open(LOG_FILE, 'a', encoding='utf-8') as log:
            log.write(f"{timestamp};{rg};{filepath}\n")
        
        return True
    except Exception as e:
        print(f"{Cores.ERRO}Erro ao salvar arquivo: {str(e)}")
        return False

# Menu principal
def menu_principal():
    while True:
        mostrar_banner()
        print(f"{Cores.DADO}1. Consultar RG")
        print(f"{Cores.DADO}2. Sair\n")
        
        opcao = input(f"{Cores.DADO}Selecione uma opção: {Cores.VALOR}").strip()
        
        if opcao == "1":
            consultar_documento()
        elif opcao == "2":
            print(f"\n{Cores.SUCESSO}Sistema encerrado. Até logo!")
            sys.exit(0)
        else:
            print(f"\n{Cores.ERRO}Opção inválida! Tente novamente.")
            sleep(1)

# Fluxo de consulta
def consultar_documento():
    mostrar_banner()
    print(f"{Cores.DADO}Digite o número do RG (somente números)")
    print(f"{Cores.DADO}Ou pressione ENTER para voltar\n")
    
    rg = input(f"{Cores.DADO}RG: {Cores.VALOR}").strip()
    
    if not rg:
        return
    
    if not rg.isdigit():
        print(f"\n{Cores.ERRO}O RG deve conter apenas números!")
        sleep(2)
        return
    
    print(f"\n{Cores.DADO}Consultando... Por favor aguarde.\n")
    
    dados = consultar_rg(rg)
    exibir_resultados(dados)
    
    if dados and dados.get('status') == 1:
        if salvar_consulta(dados, rg):
            print(f"{Cores.SUCESSO}Consulta salva com sucesso no diretório '{OUTPUT_DIR}'")
    
    input(f"\n{Cores.DADO}Pressione ENTER para continuar...")

# Ponto de entrada
if __name__ == "__main__":
    try:
        verificar_dependencias()
        criar_diretorios()
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{Cores.ERRO}Operação cancelada pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Cores.ERRO}Erro crítico: {str(e)}")
        sys.exit(1)
