#!/usr/bin/env python3
import requests
import json
import re
import os
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL


API_URL = "https://www.receitaws.com.br/v1/cnpj/"
LIMITE_CONSULTAS = 3  

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ____ _  _ ____ _  _ ____ ____ 
   |___ |  | |___ |\ | |___ |__/ 
   |___ |__| |___ | \| |___ |  \ 
{RESET}
{CIANO}{NEGRITO}   CONSULTA CNPJ - RECEITA FEDERAL
   Versão 2.0 - Terminal Avançado
{RESET}
{AMARELO}   API: receitaws.com.br
   Limite: {LIMITE_CONSULTAS} consultas/minuto
{RESET}""")

def validar_cnpj(cnpj):
    cnpj = re.sub(r'[^0-9]', '', cnpj)
    if len(cnpj) != 14:
        return False
    
    
    def calcula_digito(d):
        return 11 - d % 11 if d % 11 > 1 else 0

    temp = [int(c) for c in cnpj[:12]]
    soma = sum((5 - i) * num for i, num in enumerate(temp[:4]))
    soma += sum((9 - i) * num for i, num in enumerate(temp[4:12]))
    dig1 = calcula_digito(soma)
    
    temp.append(dig1)
    soma = sum((6 - i) * num for i, num in enumerate(temp[:5]))
    soma += sum((9 - i) * num for i, num in enumerate(temp[5:13]))
    dig2 = calcula_digito(soma)
    
    return cnpj[-2:] == f"{dig1}{dig2}"

def formatar_cnpj(cnpj):
    cnpj = re.sub(r'[^0-9]', '', cnpj)
    return f"{cnpj[:2]}.{cnpj[2:5]}.{cnpj[5:8]}/{cnpj[8:12]}-{cnpj[12:14]}"

def consultar_api(cnpj):
    try:
        response = requests.get(f"{API_URL}{cnpj}", timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"{VERMELHO}[!] Limite de consultas excedido. Aguarde 1 minuto{RESET}")
        else:
            print(f"{VERMELHO}[!] Erro na API: HTTP {response.status_code}{RESET}")
        
        return None
    except Exception as e:
        print(f"{VERMELHO}[!] Erro de conexão: {e}{RESET}")
        return None

def mostrar_resultados(dados):
    if not dados or 'status' not in dados:
        print(f"{VERMELHO}[!] CNPJ não encontrado ou dados inválidos{RESET}")
        return

    print(f"\n{CIANO}{NEGRITO}=== DADOS EMPRESARIAIS ==={RESET}")
    print(f"{AZUL}CNPJ:{RESET} {formatar_cnpj(dados.get('cnpj', ''))}")
    print(f"{AZUL}Razão Social:{RESET} {dados.get('nome', 'N/A')}")
    print(f"{AZUL}Nome Fantasia:{RESET} {dados.get('fantasia', 'N/A')}")
    print(f"{AZUL}Situação:{RESET} {VERDE if dados.get('situacao') == 'ATIVA' else VERMELHO}{dados.get('situacao', 'N/A')}{RESET}")
    print(f"{AZUL}Data Abertura:{RESET} {dados.get('abertura', 'N/A')}")
    print(f"{AZUL}Porte:{RESET} {dados.get('porte', 'N/A')}")
    print(f"{AZUL}Natureza Jurídica:{RESET} {dados.get('natureza_juridica', 'N/A')}")
    print(f"{AZUL}Capital Social:{RESET} R$ {float(dados.get('capital_social', 0)):,.2f}")

    print(f"\n{CIANO}{NEGRITO}=== ATIVIDADES ==={RESET}")
    print(f"{AZUL}Atividade Principal:{RESET}")
    for ativ in dados.get('atividade_principal', []):
        print(f"  {ativ.get('code', '')} - {ativ.get('text', '')}")

    print(f"\n{AZUL}Atividades Secundárias:{RESET}")
    for ativ in dados.get('atividades_secundarias', []):
        print(f"  {ativ.get('code', '')} - {ativ.get('text', '')}")

    print(f"\n{CIANO}{NEGRITO}=== ENDEREÇO ==={RESET}")
    print(f"{AZUL}Logradouro:{RESET} {dados.get('logradouro', 'N/A')}")
    print(f"{AZUL}Número:{RESET} {dados.get('numero', 'N/A')}")
    print(f"{AZUL}Complemento:{RESET} {dados.get('complemento', 'N/A')}")
    print(f"{AZUL}Bairro:{RESET} {dados.get('bairro', 'N/A')}")
    print(f"{AZUL}Município:{RESET} {dados.get('municipio', 'N/A')}/{dados.get('uf', 'N/A')}")
    print(f"{AZUL}CEP:{RESET} {dados.get('cep', 'N/A')}")

    print(f"\n{CIANO}{NEGRITO}=== CONTATOS ==={RESET}")
    print(f"{AZUL}Telefone:{RESET} {dados.get('telefone', 'N/A')}")
    print(f"{AZUL}Email:{RESET} {dados.get('email', 'N/A')}")

    if 'qsa' in dados and dados['qsa']:
        print(f"\n{CIANO}{NEGRITO}=== QUADRO SOCIETÁRIO ==={RESET}")
        for i, socio in enumerate(dados['qsa'], 1):
            print(f"{AZUL}{i}. {socio.get('qual', 'Sócio')}:{RESET} {socio.get('nome', 'N/A')}")

def salvar_resultado(dados, formato='json'):
    if not dados:
        return False

    cnpj = re.sub(r'[^0-9]', '', dados.get('cnpj', 'sem_cnpj'))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cnpj_{cnpj}_{timestamp}.{formato}"

    try:
        with open(filename, 'w') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS CNPJ {formatar_cnpj(cnpj)} ===\n\n")
                f.write(f"RAZÃO SOCIAL: {dados.get('nome', 'N/A')}\n")
                f.write(f"NOME FANTASIA: {dados.get('fantasia', 'N/A')}\n")
                f.write(f"SITUAÇÃO: {dados.get('situacao', 'N/A')}\n\n")
                f.write("=== ENDEREÇO ===\n")
                f.write(f"{dados.get('logradouro', 'N/A')}, {dados.get('numero', 'N/A')}\n")
                f.write(f"COMPLEMENTO: {dados.get('complemento', 'N/A')}\n")
                f.write(f"BAIRRO: {dados.get('bairro', 'N/A')}\n")
                f.write(f"CEP: {dados.get('cep', 'N/A')} - {dados.get('municipio', 'N/A')}/{dados.get('uf', 'N/A')}\n")

        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} Consultar CNPJ")
    print(f"{VERDE}[2]{RESET} Sobre")
    print(f"{VERDE}[3]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE ESTA FERRAMENTA{RESET}

{AMARELO}Desenvolvido para:{RESET}
- Consultas rápidas de CNPJ no Terminal
- Dados diretos da Receita Federal
- Uso em verificações comerciais legítimas

{AMARELO}Fonte dos dados:{RESET}
API ReceitaWS (receitaws.com.br)

{AMARELO}Limitações:{RESET}
- Limite de 3 consultas/minuto
- Dados podem ter até 1 dia de atraso
- Uso exclusivo para fins legais

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                cnpj = input(f"\n{CIANO}Digite o CNPJ (somente números): {RESET}").strip()
                
                if not validar_cnpj(cnpj):
                    print(f"{VERMELHO}[!] CNPJ inválido. Deve conter 14 dígitos{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                print(f"\n{AMARELO}[*] Consultando CNPJ {formatar_cnpj(cnpj)}...{RESET}")
                dados = consultar_api(cnpj)
                
                if dados:
                    mostrar_resultados(dados)
                    
                    exportar = input(f"\n{CIANO}Exportar resultado? (JSON/TXT/Não): {RESET}").lower()
                    if exportar.startswith('j'):
                        salvar_resultado(dados, 'json')
                    elif exportar.startswith('t'):
                        salvar_resultado(dados, 'txt')
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                sobre()
            
            elif opcao == '3':
                print(f"\n{VERDE}[+] Saindo...{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida!{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
