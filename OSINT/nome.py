#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
import os
import json
import re
from datetime import datetime
from colorama import Fore, Style, init

# Configurações iniciais
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

# Configurações da API
API_URL = "https://api.encrypt.wtf/new/api.php"
TOKEN = "ifindy"
BASE = "nome_completo2"

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ███╗   ██╗ ██████╗ ███╗   ███╗███████╗
   ████╗  ██║██╔═══██╗████╗ ████║██╔════╝
   ██╔██╗ ██║██║   ██║██╔████╔██║█████╗  
   ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  
   ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗
   ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
{RESET}
{CIANO}{NEGRITO}   CONSULTA POR NOME - TURBO+
{RESET}""")

def nome_valido(nome):
    """Valida se o nome contém apenas letras e espaços"""
    return re.fullmatch(r"[A-Za-zÀ-ÿ\s]{4,}", nome)

def agrupar_por_pessoa(dados):
    """Agrupa os dados por pessoa (sufixo numérico)"""
    pessoas = {}
    
    for chave, valor in dados.items():
        match = re.match(r"(.*?)(\d+)$", chave)
        if match:
            campo, idx = match.groups()
            if idx not in pessoas:
                pessoas[idx] = {}
            pessoas[idx][campo] = valor
        else:
            if "geral" not in pessoas:
                pessoas["geral"] = {}
            pessoas["geral"][chave] = valor
    
    return pessoas

def mostrar_loading():
    """Animação de loading"""
    print(f"{AMARELO}Consultando... ⏳{RESET}", end='\r')

def consultar_api(nome):
    """Faz a consulta à API com tratamento de erros"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    mostrar_loading()
    inicio = datetime.now()
    
    try:
        resposta = requests.get(url, headers=headers, timeout=20, verify=False)
        tempo_resposta = (datetime.now() - inicio).total_seconds()
        
        print(f"{AZUL}[*] Tempo de resposta: {tempo_resposta:.2f}s{RESET}")
        print(f"{AZUL}[*] Status HTTP: {resposta.status_code}{RESET}")

        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                print(f"{VERDE}[+] Dados recebidos!{RESET}")
                log_consulta(nome, "SUCESSO")
                return dados
            except ValueError:
                erro = "Resposta não é JSON válido"
                print(f"{VERMELHO}[!] {erro}{RESET}")
                log_consulta(nome, f"ERRO - {erro}")
                return None
        else:
            erro = f"Erro HTTP {resposta.status_code}"
            print(f"{VERMELHO}[!] {erro}{RESET}")
            log_consulta(nome, f"ERRO - {erro}")
            return None
            
    except requests.exceptions.Timeout:
        erro = "Timeout (20s)"
        print(f"{VERMELHO}[!] {erro}{RESET}")
        log_consulta(nome, f"ERRO - {erro}")
        return None
    except Exception as e:
        erro = f"Erro inesperado: {str(e)}"
        print(f"{VERMELHO}[!] {erro}{RESET}")
        log_consulta(nome, f"ERRO - {erro}")
        return None

def mostrar_resultados(dados):
    """Exibe os resultados organizados por pessoa"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado{RESET}")
        return

    agrupados = agrupar_por_pessoa(dados)
    total_pessoas = len(agrupados) - (1 if "geral" in agrupados else 0)
    
    print(f"\n{VERDE}{NEGRITO}=== RESULTADOS ENCONTRADOS ==={RESET}")
    print(f"{AMARELO}Total de pessoas encontradas: {total_pessoas}{RESET}")
    
    for idx, info in agrupados.items():
        if idx == "geral":
            continue
            
        print(f"\n{CIANO}{NEGRITO}--- Pessoa {idx} ---{RESET}")
        
        for categoria in ['nome', 'cpf', 'rg', 'data_nascimento', 'mae', 'pai', 
                         'endereco', 'cidade', 'estado', 'telefone', 'celular']:
            if categoria in info:
                print(f"{AZUL}  {categoria.replace('_', ' ').title():<15}:{RESET} {info[categoria]}")
        
        # Mostra campos não padrão
        outros_campos = [k for k in info.keys() if k not in ['nome', 'cpf', 'rg', 'data_nascimento', 
                                                           'mae', 'pai', 'endereco', 'cidade', 
                                                           'estado', 'telefone', 'celular']]
        if outros_campos:
            print(f"\n{AMARELO}  Outras informações:{RESET}")
            for campo in outros_campos:
                print(f"{AZUL}  {campo.replace('_', ' ').title():<15}:{RESET} {info[campo]}")

def salvar_em_arquivo(dados, nome_busca):
    """Salva os resultados em arquivo JSON"""
    if not dados:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"resultado_{nome_busca[:20].replace(' ', '_')}_{timestamp}.json"
    
    try:
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=4, ensure_ascii=False)
        
        print(f"{VERDE}[+] Resultado salvo em: {nome_arquivo}{RESET}")
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar arquivo: {e}{RESET}")

def log_consulta(nome, status):
    """Registra a consulta em arquivo de log"""
    with open("consultas.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] - {nome[:30]} | Status: {status}\n")

def consultar_lista_nomes(caminho):
    """Consulta uma lista de nomes de um arquivo"""
    if not os.path.isfile(caminho):
        print(f"{VERMELHO}[!] Arquivo não encontrado: {caminho}{RESET}")
        return

    with open(caminho, "r", encoding="utf-8") as f:
        nomes = [linha.strip() for linha in f if linha.strip()]
    
    if not nomes:
        print(f"{VERMELHO}[!] Nenhum nome válido no arquivo{RESET}")
        return
    
    print(f"\n{VERDE}[+] Iniciando consulta de {len(nomes)} nomes{RESET}")
    
    for i, nome in enumerate(nomes, 1):
        print(f"\n{CIANO}{NEGRITO}>>> Consultando {i}/{len(nomes)}: {nome}{RESET}")
        dados = consultar_api(nome)
        mostrar_resultados(dados)
        salvar_em_arquivo(dados, nome)
    
    print(f"\n{VERDE}{NEGRITO}[+] Todas as consultas foram concluídas{RESET}")

def main():
    """Função principal"""
    try:
        while True:
            banner()
            print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
            print(f"{VERDE}[1]{RESET} Consultar por Nome")
            print(f"{VERDE}[2]{RESET} Consultar lista de nomes (arquivo .txt)")
            print(f"{VERDE}[3]{RESET} Visualizar log de consultas")
            print(f"{VERDE}[4]{RESET} Sair")
            
            opcao = input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()
            
            if opcao == '1':
                banner()
                nome = input(f"\n{CIANO}Digite o nome completo: {RESET}").strip()
                
                if not nome_valido(nome):
                    print(f"{VERMELHO}[!] Nome inválido. Use apenas letras e espaços (mínimo 4 caracteres){RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                dados = consultar_api(nome)
                mostrar_resultados(dados)
                salvar_em_arquivo(dados, nome)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                banner()
                caminho = input(f"\n{CIANO}Digite o caminho do arquivo .txt com os nomes: {RESET}").strip()
                consultar_lista_nomes(caminho)
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':
                banner()
                if os.path.exists("consultas.log"):
                    with open("consultas.log", "r", encoding="utf-8") as f:
                        print(f"\n{VERDE}{NEGRITO}=== LOG DE CONSULTAS ==={RESET}")
                        print(f.read())
                else:
                    print(f"{VERMELHO}[!] Nenhum log encontrado{RESET}")
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':
                print(f"\n{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
