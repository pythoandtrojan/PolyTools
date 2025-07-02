#!/usr/bin/env python3

import requests
import urllib.parse
import urllib3
import os
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
{CIANO}{NEGRITO}   CONSULTA DE PESSOAS - DADOS ORGANIZADOS
{RESET}""")

def consultar_api(nome):
    """Faz a consulta à API"""
    query = urllib.parse.quote(nome)
    url = f"{API_URL}?token={TOKEN}&base={BASE}&query={query}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }

    try:
        resposta = requests.get(url, headers=headers, timeout=15, verify=False)
        
        if resposta.status_code == 200:
            try:
                dados = resposta.json()
                if isinstance(dados, list):
                    return dados
                elif isinstance(dados, dict):
                    return [dados]
                return []
            except ValueError:
                print(f"{VERMELHO}[!] Resposta não é JSON válido{RESET}")
                return None
        else:
            print(f"{VERMELHO}[!] Erro HTTP {resposta.status_code}{RESET}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{VERMELHO}[!] Tempo de consulta excedido{RESET}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{VERMELHO}[!] Erro na requisição: {e}{RESET}")
        return None

def filtrar_dados(pessoas):
    """Menu de filtros para os resultados"""
    while True:
        print(f"\n{VERDE}{NEGRITO}=== FILTROS DISPONÍVEIS ==={RESET}")
        print(f"{AZUL}[1]{RESET} Filtrar por CPF")
        print(f"{AZUL}[2]{RESET} Filtrar por Cidade")
        print(f"{AZUL}[3]{RESET} Filtrar por Idade")
        print(f"{AZUL}[4]{RESET} Limpar filtros")
        print(f"{AZUL}[5]{RESET} Voltar")
        
        opcao = input(f"\n{CIANO}Escolha um filtro: {RESET}").strip()
        
        if opcao == '1':
            cpf = input(f"{CIANO}Digite o CPF: {RESET}").strip()
            pessoas = [p for p in pessoas if 'cpf' in p and str(p['cpf']) == cpf]
            print(f"{VERDE}[+] Filtrado por CPF: {len(pessoas)} resultado(s){RESET}")
            
        elif opcao == '2':
            cidade = input(f"{CIANO}Digite a cidade: {RESET}").strip().lower()
            pessoas = [p for p in pessoas if 'cidade' in p and cidade in p['cidade'].lower()]
            print(f"{VERDE}[+] Filtrado por cidade: {len(pessoas)} resultado(s){RESET}")
            
        elif opcao == '3':
            try:
                idade_min = int(input(f"{CIANO}Idade mínima: {RESET}").strip())
                idade_max = int(input(f"{CIANO}Idade máxima: {RESET}").strip())
                pessoas = [p for p in pessoas if 'data_nascimento' in p and 
                          idade_min <= calcular_idade(p['data_nascimento']) <= idade_max]
                print(f"{VERDE}[+] Filtrado por idade ({idade_min}-{idade_max}): {len(pessoas)} resultado(s){RESET}")
            except:
                print(f"{VERMELHO}[!] Idades inválidas{RESET}")
                
        elif opcao == '4':
            return None  # Sinaliza para recarregar
            
        elif opcao == '5':
            return pessoas
            
        else:
            print(f"{VERMELHO}[!] Opção inválida{RESET}")
            
        if not pessoas:
            print(f"{VERMELHO}[!] Nenhum resultado com esses filtros{RESET}")
            return []

def calcular_idade(data_nasc):
    """Calcula idade a partir da data de nascimento"""
    from datetime import datetime
    try:
        nasc = datetime.strptime(data_nasc, '%Y-%m-%d')
        hoje = datetime.now()
        return (hoje - nasc).days // 365
    except:
        return 0

def mostrar_detalhes_pessoa(pessoa):
    """Mostra TODOS os dados de uma pessoa de forma super organizada"""
    print(f"\n{CIANO}{NEGRITO}=== DADOS COMPLETOS ==={RESET}")
    
    # Organiza em grupos lógicos
    grupos = {
        'Identificação': ['nome', 'nome_completo', 'cpf', 'rg', 'data_nascimento', 'idade', 'sexo'],
        'Filiação': ['mae', 'pai', 'conjuge'],
        'Contatos': ['telefone', 'celular', 'email'],
        'Endereço': ['endereco', 'logradouro', 'numero', 'complemento', 'bairro', 'cidade', 'estado', 'cep'],
        'Documentos': ['titulo_eleitor', 'pis', 'ctps', 'cnh'],
        'Financeiro': ['renda', 'profissao', 'empresa'],
        'Outros': []
    }
    
    for grupo, campos in grupos.items():
        print(f"\n{VERDE}{NEGRITO}» {grupo.upper()}{RESET}")
        encontrou = False
        
        for campo in campos:
            if campo in pessoa and pessoa[campo]:
                print(f"{AZUL}  {campo.replace('_', ' ').title():<20}:{RESET} {pessoa[campo]}")
                encontrou = True
                
        # Mostra campos não categorizados
        if grupo == 'Outros':
            for chave, valor in pessoa.items():
                if not any(chave in g for g in grupos.values()) and valor:
                    print(f"{AZUL}  {chave.replace('_', ' ').title():<20}:{RESET} {valor}")
                    encontrou = True
                    
        if not encontrou:
            print(f"{AMARELO}  Nenhum dado disponível{RESET}")

def menu_principal():
    """Exibe o menu principal"""
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} Consultar por Nome")
    print(f"{VERDE}[2]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}").strip()

def main():
    """Função principal"""
    dados_originais = None
    
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                nome = input(f"\n{CIANO}Digite o nome completo: {RESET}").strip()
                
                if not nome or len(nome.split()) < 2:
                    print(f"{VERMELHO}[!] Digite um nome completo válido{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                dados_originais = consultar_api(nome)
                
                if not dados_originais:
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                pessoas = dados_originais.copy()
                
                while True:
                    resultado_filtro = filtrar_dados(pessoas)
                    
                    if resultado_filtro is None:  # Limpar filtros
                        pessoas = dados_originais.copy()
                        continue
                    elif not resultado_filtro:  # Voltar ao menu
                        break
                        
                    pessoas = resultado_filtro
                    
                    print(f"\n{VERDE}{NEGRITO}=== RESULTADOS ==={RESET}")
                    print(f"{AMARELO}Total encontrado: {len(pessoas)}{RESET}")
                    
                    for i, pessoa in enumerate(pessoas, 1):
                        print(f"\n{CIANO}{NEGRITO}--- Pessoa {i}/{len(pessoas)} ---{RESET}")
                        mostrar_detalhes_pessoa(pessoa)
                        
                        if i % 3 == 0:  # Mostra 3 por vez
                            op = input(f"\n{CIANO}Continuar? (S/N): {RESET}").strip().lower()
                            if op != 's':
                                break
            
            elif opcao == '2':
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
