#!/usr/bin/env python3
import random
import re
import os
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

class GeradorAleatorio:
    @staticmethod
    def gerar_cpf(formatado=True):
        """Gera CPF válido aleatório"""
        def calcular_digito(dados, pesos):
            soma = sum(int(dados[i]) * pesos[i] for i in range(len(pesos)))
            resto = soma % 11
            return 0 if resto < 2 else 11 - resto
        
        # Gera 9 números aleatórios
        numeros = [random.randint(0, 9) for _ in range(9)]
        
        # Primeiro dígito verificador
        pesos1 = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito1 = calcular_digito(''.join(map(str, numeros)), pesos1)
        numeros.append(digito1)
        
        # Segundo dígito verificador
        pesos2 = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito2 = calcular_digito(''.join(map(str, numeros)), pesos2)
        numeros.append(digito2)
        
        cpf = ''.join(map(str, numeros))
        
        if formatado:
            return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
        return cpf

    @staticmethod
    def gerar_telefone(formatado=True):
        """Gera número de telefone brasileiro aleatório"""
        ddd = str(random.randint(11, 99))
        
        # Decide se é celular (9) ou fixo (2-5)
        if random.choice([True, False]):
            # Celular
            numero = f"9{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
        else:
            # Fixo
            numero = f"{random.randint(2, 5)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
        
        if formatado:
            if len(numero) == 9:  # Celular
                return f"({ddd}) {numero[:5]}-{numero[5:]}"
            else:  # Fixo
                return f"({ddd}) {numero[:4]}-{numero[4:]}"
        return ddd + numero

    @staticmethod
    def gerar_placa_mercosul():
        """Gera placa no padrão Mercosul aleatória"""
        letras = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        numeros = '0123456789'
        
        # Formato: LLL NL NL
        placa = (
            random.choice(letras) + 
            random.choice(letras) + 
            random.choice(letras) +
            random.choice(numeros) +
            random.choice(letras) +
            random.choice(numeros) +
            random.choice(letras)
        )
        return placa

    @staticmethod
    def gerar_cartao_credito():
        """Gera número de cartão de crédito aleatório (apenas formato)"""
        bandeiras = {
            'Visa': '4',
            'Mastercard': '5',
            'American Express': '3',
            'Elo': '6'
        }
        
        bandeira = random.choice(list(bandeiras.keys()))
        prefixo = bandeiras[bandeira]
        
        # Gera os demais dígitos
        if bandeira == 'American Express':
            tamanho = 15
            resto = ''.join([str(random.randint(0, 9)) for _ in range(13)])
            numero = prefixo + resto
        else:
            tamanho = 16
            resto = ''.join([str(random.randint(0, 9)) for _ in range(14)])
            numero = prefixo + resto
        
        # Formata em grupos de 4
        grupos = [numero[i:i+4] for i in range(0, len(numero), 4)]
        return f"{bandeira}: {' '.join(grupos)}"

    @staticmethod
    def gerar_ip():
        """Gera endereço IP aleatório"""
        def gerar_octeto():
            return str(random.randint(0, 255))
        
        # Gera IPs mais comuns (não gera IPs reservados)
        primeiro_octeto = random.choice([10, 172, 192, *list(range(1, 255))])
        
        if primeiro_octeto == 10:
            # IP privado classe A
            ip = f"10.{gerar_octeto()}.{gerar_octeto()}.{gerar_octeto()}"
        elif primeiro_octeto == 172:
            # IP privado classe B
            ip = f"172.{random.randint(16, 31)}.{gerar_octeto()}.{gerar_octeto()}"
        elif primeiro_octeto == 192:
            # IP privado classe C
            ip = f"192.168.{gerar_octeto()}.{gerar_octeto()}"
        else:
            # IP público
            ip = f"{primeiro_octeto}.{gerar_octeto()}.{gerar_octeto()}.{gerar_octeto()}"
        
        return ip

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ██████╗ ███████╗██████╗  █████╗ ██████╗ 
   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗
   ██████╔╝█████╗  ██████╔╝███████║██████╔╝
   ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██╔══██╗
   ██║  ██║███████╗██║  ██║██║  ██║██║  ██║
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{RESET}
{CIANO}{NEGRITO}   GERADOR ALEATÓRIO v2.0
   Terminal de Dados Fictícios
{RESET}
{AMARELO}   Tipos: CPF, Telefone, Placa, Cartão, IP
   Uso para testes e desenvolvimento
{RESET}""")

def mostrar_resultado(tipo: str, dados: list):
    """Exibe resultados gerados"""
    print(f"\n{CIANO}{NEGRITO}=== {tipo.upper()} GERADO(S) ==={RESET}")
    for i, item in enumerate(dados, 1):
        print(f"{AZUL}{i:2d}.{RESET} {VERDE}{item}{RESET}")

def salvar_resultados(tipo: str, dados: list):
    """Salva resultados em arquivo"""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{tipo}_{timestamp}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{tipo.upper()} Gerados em {datetime.now()}\n")
            f.write("=" * 50 + "\n")
            for i, item in enumerate(dados, 1):
                f.write(f"{i:2d}. {item}\n")
        print(f"{VERDE}[+] Resultados salvos em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL - GERADOR{RESET}")
    print(f"{VERDE}[1]{RESET} Gerar CPF")
    print(f"{VERDE}[2]{RESET} Gerar Telefone")
    print(f"{VERDE}[3]{RESET} Gerar Placa Mercosul")
    print(f"{VERDE}[4]{RESET} Gerar Cartão de Crédito")
    print(f"{VERDE}[5]{RESET} Gerar IP")
    print(f"{VERDE}[6]{RESET} Gerar Todos")
    print(f"{VERDE}[7]{RESET} Sobre")
    print(f"{VERDE}[8]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def gerar_todos():
    """Gera um exemplo de cada tipo"""
    banner()
    print(f"\n{CIANO}{NEGRITO}=== TODOS OS TIPOS ==={RESET}")
    
    gerador = GeradorAleatorio()
    
    resultados = {
        'CPF': [gerador.gerar_cpf()],
        'Telefone': [gerador.gerar_telefone()],
        'Placa Mercosul': [gerador.gerar_placa_mercosul()],
        'Cartão de Crédito': [gerador.gerar_cartao_credito()],
        'IP': [gerador.gerar_ip()]
    }
    
    for tipo, dados in resultados.items():
        mostrar_resultado(tipo, dados)
    
    salvar = input(f"\n{CIANO}Salvar todos os resultados? (S/N): {RESET}").lower()
    if salvar in ['s', 'sim']:
        for tipo, dados in resultados.items():
            salvar_resultados(tipo, dados)

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE O GERADOR ALEATÓRIO{RESET}

{AMARELO}Funcionalidades:{RESET}
• Geração de CPFs válidos (com dígitos verificadores)
• Geração de telefones brasileiros (celular/fixo)
• Geração de placas Mercosul
• Geração de números de cartão (apenas formato)
• Geração de endereços IP

{AMARELO}Características:{RESET}
✓ Dados fictícios para testes
✓ Formatos válidos e realistas
✓ Geração em lote
✓ Exportação para arquivo

{AMARELO}Exemplos:{RESET}
CPF: 123.456.789-09
Telefone: (11) 99999-9999
Placa: ABC1D23
Cartão: Visa 1234 5678 9012 3456
IP: 192.168.1.1

{AMARELO}Aviso:{RESET}
Use apenas para testes e desenvolvimento!

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        gerador = GeradorAleatorio()
        
        while True:
            opcao = menu_principal()
            
            if opcao in ['1', '2', '3', '4', '5']:
                banner()
                quantidade = input(f"\n{CIANO}Quantos deseja gerar? (padrão: 1): {RESET}").strip()
                quantidade = int(quantidade) if quantidade.isdigit() and int(quantidade) > 0 else 1
                
                resultados = []
                
                if opcao == '1':  # CPF
                    for _ in range(quantidade):
                        resultados.append(gerador.gerar_cpf())
                    mostrar_resultado('CPF', resultados)
                    
                elif opcao == '2':  # Telefone
                    for _ in range(quantidade):
                        resultados.append(gerador.gerar_telefone())
                    mostrar_resultado('Telefone', resultados)
                    
                elif opcao == '3':  # Placa
                    for _ in range(quantidade):
                        resultados.append(gerador.gerar_placa_mercosul())
                    mostrar_resultado('Placa Mercosul', resultados)
                    
                elif opcao == '4':  # Cartão
                    for _ in range(quantidade):
                        resultados.append(gerador.gerar_cartao_credito())
                    mostrar_resultado('Cartão de Crédito', resultados)
                    
                elif opcao == '5':  # IP
                    for _ in range(quantidade):
                        resultados.append(gerador.gerar_ip())
                    mostrar_resultado('Endereço IP', resultados)
                
                if quantidade > 0:
                    salvar = input(f"\n{CIANO}Salvar resultados? (S/N): {RESET}").lower()
                    if salvar in ['s', 'sim']:
                        tipo = {
                            '1': 'CPF', '2': 'Telefone', '3': 'Placa', 
                            '4': 'Cartao', '5': 'IP'
                        }[opcao]
                        salvar_resultados(tipo, resultados)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '6':  # Gerar Todos
                gerar_todos()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '7':  # Sobre
                sobre()
            
            elif opcao == '8':  # Sair
                print(f"\n{VERDE}[+] Saindo... Até logo!{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida!{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
