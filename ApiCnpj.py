
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

# Configurações da API
API_URL = "https://www.cpfhub.io/api/v1/"
API_KEY = ""  
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ____ ____ _____ _  _ _  _ 
   |___ |__| |___ |  | |\ | 
   |___ |  | |___ |__| | \| 
{RESET}
{CIANO}{NEGRITO}   CONSULTA CPF - CPFHUB.IO
   Versão 2.0 - Terminal Avançado
{RESET}
{AMARELO}   API: cpfhub.io
   Limite: 3 consultas/minuto (gratuito)
{RESET}""")

def validar_cpf(cpf):
    cpf = re.sub(r'[^0-9]', '', cpf)
    if len(cpf) != 11:
        return False
    
    
    def calcula_digito(d):
        return (11 - d % 11) if (11 - d % 11) <= 9 else 0

    temp = [int(c) for c in cpf[:9]]
    soma = sum((10 - i) * num for i, num in enumerate(temp))
    dig1 = calcula_digito(soma)
    
    temp.append(dig1)
    soma = sum((11 - i) * num for i, num in enumerate(temp))
    dig2 = calcula_digito(soma)
    
    return cpf[-2:] == f"{dig1}{dig2}"

def formatar_cpf(cpf):
    cpf = re.sub(r'[^0-9]', '', cpf)
    return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"

def consultar_api(cpf):
    if not API_KEY:
        print(f"{VERMELHO}[!] Chave API não configurada. Obtenha em cpfhub.io{RESET}")
        return None

    try:
        response = requests.get(
            f"{API_URL}consultar?cpf={cpf}",
            headers=HEADERS,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            print(f"{VERMELHO}[!] Erro de autenticação. Verifique sua chave API{RESET}")
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
        print(f"{VERMELHO}[!] CPF não encontrado ou dados inválidos{RESET}")
        return

    print(f"\n{CIANO}{NEGRITO}=== DADOS PESSOAIS ==={RESET}")
    print(f"{AZUL}CPF:{RESET} {formatar_cpf(dados.get('cpf', ''))}")
    print(f"{AZUL}Nome:{RESET} {dados.get('nome', 'N/A')}")
    print(f"{AZUL}Data Nascimento:{RESET} {dados.get('data_nascimento', 'N/A')}")
    print(f"{AZUL}Sexo:{RESET} {dados.get('sexo', 'N/A')}")
    print(f"{AZUL}Situação Cadastral:{RESET} {VERDE if dados.get('situacao_cadastral') == 'Regular' else VERMELHO}{dados.get('situacao_cadastral', 'N/A')}{RESET}")
    print(f"{AZUL}Data Inscrição:{RESET} {dados.get('data_inscricao', 'N/A')}")

    print(f"\n{CIANO}{NEGRITO}=== INFORMAÇÕES ELEITORAIS ==={RESET}")
    print(f"{AZUL}Título Eleitor:{RESET} {dados.get('titulo_eleitor', 'N/A')}")
    print(f"{AZUL}Zona Eleitoral:{RESET} {dados.get('zona_eleitoral', 'N/A')}")
    print(f"{AZUL}Seção Eleitoral:{RESET} {dados.get('secao_eleitoral', 'N/A')}")

    print(f"\n{CIANO}{NEGRITO}=== ENDEREÇO ==={RESET}")
    print(f"{AZUL}Logradouro:{RESET} {dados.get('logradouro', 'N/A')}")
    print(f"{AZUL}Número:{RESET} {dados.get('numero', 'N/A')}")
    print(f"{AZUL}Complemento:{RESET} {dados.get('complemento', 'N/A')}")
    print(f"{AZUL}Bairro:{RESET} {dados.get('bairro', 'N/A')}")
    print(f"{AZUL}Cidade:{RESET} {dados.get('cidade', 'N/A')}/{dados.get('uf', 'N/A')}")
    print(f"{AZUL}CEP:{RESET} {dados.get('cep', 'N/A')}")

    print(f"\n{CIANO}{NEGRITO}=== INFORMAÇÕES ADICIONAIS ==={RESET}")
    print(f"{AZUL}Mãe:{RESET} {dados.get('mae', 'N/A')}")
    print(f"{AZUL}Pai:{RESET} {dados.get('pai', 'N/A')}")
    print(f"{AZUL}NIS/PIS:{RESET} {dados.get('nis', 'N/A')}")
    print(f"{AZUL}Última Atualização:{RESET} {dados.get('ultima_atualizacao', 'N/A')}")

def salvar_resultado(dados, formato='json'):
    if not dados:
        return False

    cpf = re.sub(r'[^0-9]', '', dados.get('cpf', 'sem_cpf'))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cpf_{cpf}_{timestamp}.{formato}"

    try:
        with open(filename, 'w') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS CPF {formatar_cpf(cpf)} ===\n\n")
                f.write(f"NOME: {dados.get('nome', 'N/A')}\n")
                f.write(f"NASCIMENTO: {dados.get('data_nascimento', 'N/A')}\n")
                f.write(f"SITUAÇÃO: {dados.get('situacao_cadastral', 'N/A')}\n\n")
                f.write("=== ENDEREÇO ===\n")
                f.write(f"{dados.get('logradouro', 'N/A')}, {dados.get('numero', 'N/A')}\n")
                f.write(f"COMPLEMENTO: {dados.get('complemento', 'N/A')}\n")
                f.write(f"BAIRRO: {dados.get('bairro', 'N/A')}\n")
                f.write(f"CEP: {dados.get('cep', 'N/A')} - {dados.get('cidade', 'N/A')}/{dados.get('uf', 'N/A')}\n")

        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} Consultar CPF")
    print(f"{VERDE}[2]{RESET} Configurar API Key")
    print(f"{VERDE}[3]{RESET} Sobre")
    print(f"{VERDE}[4]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def configurar_api():
    banner()
    global API_KEY, HEADERS
    print(f"\n{CIANO}{NEGRITO}CONFIGURAR CHAVE API{RESET}")
    print(f"{AMARELO}Obtenha sua chave em: https://www.cpfhub.io{RESET}")
    nova_key = input(f"\n{CIANO}Digite sua chave API: {RESET}").strip()
    
    if nova_key:
        API_KEY = nova_key
        HEADERS["Authorization"] = f"Bearer {API_KEY}"
        print(f"{VERDE}[+] Chave API configurada com sucesso{RESET}")
    else:
        print(f"{VERMELHO}[!] Chave inválida{RESET}")
    
    input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE ESTA FERRAMENTA{RESET}

{AMARELO}Desenvolvido para:{RESET}
- Consultas rápidas de CPF no Terminal
- Obter informações da API CPFHub.io
- Uso em verificações legítimas

{AMARELO}Fonte dos dados:{RESET}
API oficial do CPFHub (https://www.cpfhub.io)

{AMARELO}Limitações:{RESET}
- Requer chave API válida
- Limite de 3 consultas/minuto (plano gratuito)
- Uso exclusivo para fins legais

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                cpf = input(f"\n{CIANO}Digite o CPF (somente números): {RESET}").strip()
                
                if not validar_cpf(cpf):
                    print(f"{VERMELHO}[!] CPF inválido. Verifique os dígitos{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                print(f"\n{AMARELO}[*] Consultando CPF {formatar_cpf(cpf)}...{RESET}")
                dados = consultar_api(cpf)
                
                if dados:
                    mostrar_resultados(dados)
                    
                    exportar = input(f"\n{CIANO}Exportar resultado? (JSON/TXT/Não): {RESET}").lower()
                    if exportar.startswith('j'):
                        salvar_resultado(dados, 'json')
                    elif exportar.startswith('t'):
                        salvar_resultado(dados, 'txt')
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':
                configurar_api()
            
            elif opcao == '3':
                sobre()
            
            elif opcao == '4':
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
