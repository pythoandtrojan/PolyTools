#!/usr/bin/env python3

import requests
import re
import os
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

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

# APIs
API_BRASILAPI = "https://brasilapi.com.br/api/cep/v1/"
API_VIACEP = "https://viacep.com.br/ws/{cep}/json/"

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ____ ____ ____  
   | __|  __|  __| 
   |__||____|____| 
{RESET}
{CIANO}{NEGRITO}   CONSULTA CEP - MULTI API
   Versão 3.0 - Terminal Avançado
{RESET}
{AMARELO}   APIs: brasilapi.com.br e viacep.com.br
   Dados combinados para máxima precisão
{RESET}""")

def validar_cep(cep):
    """Valida o formato do CEP"""
    padrao = r'^\d{5}-?\d{3}$'
    return re.match(padrao, cep) is not None

def formatar_cep(cep):
    """Formata o CEP para o padrão 00000-000"""
    cep = re.sub(r'[^0-9]', '', cep)
    return f"{cep[:5]}-{cep[5:]}" if len(cep) == 8 else cep

def consultar_brasilapi(cep):
    """Consulta a BrasilAPI para obter dados do CEP"""
    try:
        response = requests.get(f"{API_BRASILAPI}{cep}", timeout=10)
        
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

def consultar_viacep(cep):
    """Consulta a ViaCEP para obter dados do CEP"""
    try:
        cep_limpo = re.sub(r'[^0-9]', '', cep)
        response = requests.get(API_VIACEP.format(cep=cep_limpo), timeout=10)
        
        if response.status_code == 200:
            dados = response.json()
            return None if 'erro' in dados else dados
        return None
    except Exception:
        return None

def combinar_dados(dados1, dados2):
    """Combina dados de ambas as APIs, priorizando informações não nulas"""
    if not dados1 and not dados2:
        return None
        
    combined = {}
    sources = []
    
    if dados1:
        combined.update(dados1)
        sources.append(dados1.get('service', 'BrasilAPI'))
    
    if dados2:
        # Mapear campos diferentes entre as APIs
        field_map = {
            'logradouro': 'street',
            'localidade': 'city',
            'uf': 'state',
            'bairro': 'neighborhood',
            'complemento': 'complement'
        }
        
        for via_field, brasil_field in field_map.items():
            if via_field in dados2 and dados2[via_field] and (brasil_field not in combined or not combined[brasil_field]):
                combined[brasil_field] = dados2[via_field]
        
        sources.append('ViaCEP')
    
    combined['service'] = ' + '.join(sources)
    return combined

def mostrar_resultados(dados):
    """Exibe os resultados formatados e coloridos"""
    if not dados:
        print(f"{VERMELHO}[!] Nenhum dado encontrado para este CEP{RESET}")
        return

    print(f"\n{CIANO}{NEGRITO}=== DADOS COMBINADOS DO CEP ==={RESET}")
    print(f"{AZUL}CEP:{RESET} {dados.get('cep', 'N/A')}")
    print(f"{AZUL}Logradouro:{RESET} {dados.get('street', 'N/A')}")
    print(f"{AZUL}Complemento:{RESET} {dados.get('complement', 'N/A')}")
    print(f"{AZUL}Bairro:{RESET} {dados.get('neighborhood', 'N/A')}")
    print(f"{AZUL}Cidade:{RESET} {dados.get('city', 'N/A')}")
    print(f"{AZUL}Estado:{RESET} {dados.get('state', 'N/A')}")
    print(f"{AZUL}IBGE:{RESET} {dados.get('ibge', 'N/A')}")
    print(f"{AZUL}DDD:{RESET} {dados.get('ddd', 'N/A')}")
    print(f"{AZUL}GIA:{RESET} {dados.get('gia', 'N/A')}")
    print(f"{AZUL}SIAFI:{RESET} {dados.get('siafi', 'N/A')}")
    print(f"{AZUL}Fonte:{RESET} {dados.get('service', 'N/A')}")

def salvar_resultado(dados, formato='json'):
    """Salva os resultados em arquivo"""
    if not dados:
        return False

    cep = re.sub(r'[^0-9]', '', dados.get('cep', 'sem_cep'))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cep_{cep}_{timestamp}.{formato}"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if formato == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== DADOS DO CEP {dados.get('cep', 'N/A')} ===\n\n")
                f.write(f"LOGRADOURO: {dados.get('street', 'N/A')}\n")
                f.write(f"COMPLEMENTO: {dados.get('complement', 'N/A')}\n")
                f.write(f"BAIRRO:     {dados.get('neighborhood', 'N/A')}\n")
                f.write(f"CIDADE:     {dados.get('city', 'N/A')}\n")
                f.write(f"ESTADO:     {dados.get('state', 'N/A')}\n")
                f.write(f"IBGE:       {dados.get('ibge', 'N/A')}\n")
                f.write(f"DDD:        {dados.get('ddd', 'N/A')}\n")
                f.write(f"GIA:        {dados.get('gia', 'N/A')}\n")
                f.write(f"SIAFI:      {dados.get('siafi', 'N/A')}\n")
                f.write(f"FONTE:      {dados.get('service', 'N/A')}\n")

        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    """Exibe o menu principal"""
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} Consultar CEP")
    print(f"{VERDE}[2]{RESET} Sobre")
    print(f"{VERDE}[3]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def sobre():
    """Exibe informações sobre o programa"""
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE ESTA FERRAMENTA{RESET}

{AMARELO}Desenvolvido para:{RESET}
- Consultas completas de CEP no Terminal
- Combinação de dados de múltiplas fontes
- Dados precisos dos Correios e IBGE

{AMARELO}Fontes dos dados:{RESET}
- BrasilAPI (brasilapi.com.br)
- ViaCEP (viacep.com.br)

{AMARELO}Vantagens:{RESET}
- Maior taxa de acerto (consulta múltiplas APIs)
- Mais campos de informação (IBGE, DDD, etc.)
- Dados oficiais e atualizados
- Interface otimizada para Termux

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    """Função principal do programa"""
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                cep = input(f"\n{CIANO}Digite o CEP (com ou sem hífen): {RESET}").strip()
                
                if not validar_cep(cep):
                    print(f"{VERMELHO}[!] CEP inválido. Formato esperado: 00000-000 ou 00000000{RESET}")
                    input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
                    continue
                
                cep_formatado = formatar_cep(cep)
                print(f"\n{AMARELO}[*] Consultando CEP {cep_formatado}...{RESET}")
                
                # Consulta paralela às APIs
                print(f"{AZUL}[*] Consultando BrasilAPI...{RESET}")
                dados_brasilapi = consultar_brasilapi(cep)
                
                print(f"{AZUL}[*] Consultando ViaCEP...{RESET}")
                dados_viacep = consultar_viacep(cep)
                
                dados_combinados = combinar_dados(dados_brasilapi, dados_viacep)
                mostrar_resultados(dados_combinados)
                
                if dados_combinados:
                    exportar = input(f"\n{CIANO}Exportar resultado? (JSON/TXT/Não): {RESET}").lower()
                    if exportar.startswith('j'):
                        salvar_resultado(dados_combinados, 'json')
                    elif exportar.startswith('t'):
                        salvar_resultado(dados_combinados, 'txt')
                
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
