#!/usr/bin/env python3

import os
import sys
import json
import requests
from colorama import Fore, Style, init
from datetime import datetime

# Configuração de cores
init(autoreset=True)
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
CIANO = Fore.CYAN
RESET = Style.RESET_ALL

class CPFValidator:
    def __init__(self):
        self.apis = {
            "ReceitaWS": {
                "url": "https://receitaws.com.br/v1/cpf/{}",
                "fields": ["nome", "nascimento", "situacao"],
                "rate_limit": 3  # Consultas por minuto
            },
            "ConsultaCPF": {
                "url": "https://api.consultacpf.com.br/{}",
                "key": None,  # Necessário cadastro
                "fields": ["status", "nome", "emitido_em"]
            },
            "CPFValidator": {
                "url": "https://cpfvalidator.com/api/{}",
                "fields": ["valid", "formatted"]
            }
        }
        self.cache_file = "cpf_cache.json"
        self.cache = self.load_cache()

    def load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}

    def save_cache(self):
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=4)

    def banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{VERDE}
   ██████╗ ██████╗ ███████╗
  ██╔════╝ ██╔══██╗██╔════╝
  ██║      ██████╔╝█████╗  
  ██║      ██╔═══╝ ██╔══╝  
  ╚██████╔╝██║     ██║     
   ╚═════╝ ╚═╝     ╚═╝     
{RESET}{CIANO}  Consulta Ética de CPF - Top APIs{RESET}
{AMARELO}  ATENÇÃO: Use apenas para consultas legítimas{RESET}""")

    def validate_cpf(self, cpf):
        """Valida formatação do CPF"""
        cpf = ''.join(filter(str.isdigit, cpf))
        if len(cpf) != 11:
            return False
        return cpf

    def consultar_api(self, api_name, cpf):
        """Consulta uma API específica"""
        api = self.apis[api_name]
        url = api["url"].format(cpf)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
        
        if api_name in self.cache.get(cpf, {}):
            return self.cache[cpf][api_name]
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Filtra apenas os campos relevantes
                filtered = {k: data.get(k) for k in api["fields"]}
                
                # Atualiza cache
                if cpf not in self.cache:
                    self.cache[cpf] = {}
                self.cache[cpf][api_name] = filtered
                self.save_cache()
                
                return filtered
            else:
                print(f"{VERMELHO}[!] {api_name}: Erro {response.status_code}{RESET}")
                return None
        except Exception as e:
            print(f"{VERMELHO}[!] {api_name}: {str(e)}{RESET}")
            return None

    def mostrar_resultados(self, cpf, resultados):
        """Exibe os resultados formatados"""
        print(f"\n{VERDE}═ Resultados para CPF: {cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}{RESET}")
        
        for api_name, dados in resultados.items():
            print(f"\n{AZUL}▌ {api_name}{RESET}")
            if dados:
                for campo, valor in dados.items():
                    print(f"  {AMARELO}→ {campo}: {valor}{RESET}")
            else:
                print(f"  {VERMELHO}× Sem dados disponíveis{RESET}")

    def menu_principal(self):
        """Interface de linha de comando"""
        self.banner()
        
        while True:
            print(f"\n{CIANO}Menu:{RESET}")
            print("1. Consultar CPF")
            print("2. Sair")
            
            opcao = input(f"{AMARELO}> {RESET}").strip()
            
            if opcao == "1":
                cpf = input(f"{AMARELO}Digite o CPF (somente números): {RESET}").strip()
                cpf_validado = self.validate_cpf(cpf)
                
                if not cpf_validado:
                    print(f"{VERMELHO}CPF inválido!{RESET}")
                    continue
                
                resultados = {}
                for api_name in self.apis:
                    print(f"{VERDE}[+] Consultando {api_name}...{RESET}")
                    resultados[api_name] = self.consultar_api(api_name, cpf_validado)
                
                self.mostrar_resultados(cpf_validado, resultados)
                
            elif opcao == "2":
                print(f"{VERDE}Saindo...{RESET}")
                break
            else:
                print(f"{VERMELHO}Opção inválida!{RESET}")

if __name__ == "__main__":
    # Verifica dependências
    try:
        import requests
    except ImportError:
        print(f"{VERMELHO}Instalando dependências...{RESET}")
        os.system("pip install requests colorama")
    
    tool = CPFValidator()
    tool.menu_principal()
