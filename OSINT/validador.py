#!/usr/bin/env python3
import re
import os
import json
from datetime import datetime
from colorama import Fore, Style, init
from typing import Dict, Optional

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

class Validador:
    @staticmethod
    def validar_cpf(cpf: str) -> bool:
        """Valida CPF brasileiro"""
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) != 11 or cpf == cpf[0] * 11:
            return False
        
        def calcular_digito(dados: str, pesos: list) -> int:
            soma = sum(int(dados[i]) * pesos[i] for i in range(len(pesos)))
            resto = soma % 11
            return 0 if resto < 2 else 11 - resto
        
        # Primeiro dígito verificador
        pesos1 = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito1 = calcular_digito(cpf[:9], pesos1)
        
        # Segundo dígito verificador
        pesos2 = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito2 = calcular_digito(cpf[:10], pesos2)
        
        return cpf[-2:] == f"{digito1}{digito2}"
    
    @staticmethod
    def validar_telefone(telefone: str) -> Dict[str, bool]:
        """Valida telefone brasileiro"""
        telefone = re.sub(r'[^0-9]', '', telefone)
        
        resultados = {
            'valido': False,
            'tipo': 'Inválido',
            'com_ddd': False
        }
        
        # Celular (11 dígitos com 9 na quinta posição)
        if len(telefone) == 11 and telefone[2] == '9':
            resultados.update({
                'valido': True,
                'tipo': 'Celular',
                'com_ddd': True
            })
        # Telefone fixo (10 dígitos)
        elif len(telefone) == 10 and telefone[2] in ['2', '3', '4', '5']:
            resultados.update({
                'valido': True,
                'tipo': 'Fixo',
                'com_ddd': True
            })
        # Número sem DDD (8 dígitos)
        elif len(telefone) == 8:
            if telefone[0] == '9':
                resultados.update({
                    'valido': True,
                    'tipo': 'Celular',
                    'com_ddd': False
                })
            else:
                resultados.update({
                    'valido': True,
                    'tipo': 'Fixo',
                    'com_ddd': False
                })
        
        return resultados
    
    @staticmethod
    def validar_ip(ip: str) -> Dict[str, bool]:
        """Valida endereço IP"""
        resultados = {
            'valido': False,
            'tipo': 'Inválido',
            'publico': False,
            'privado': False
        }
        
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not re.match(ipv4_pattern, ip):
            return resultados
        
        partes = ip.split('.')
        
        try:
            # Verifica se cada parte está entre 0-255
            for parte in partes:
                if not 0 <= int(parte) <= 255:
                    return resultados
            
            resultados['valido'] = True
            
            # Verifica IPs privados
            if (partes[0] == '10' or
                (partes[0] == '172' and 16 <= int(partes[1]) <= 31) or
                (partes[0] == '192' and partes[1] == '168')):
                resultados['tipo'] = 'Privado'
                resultados['privado'] = True
            # Verifica IPs reservados/multicast
            elif (partes[0] == '127' or  # localhost
                  partes[0] == '169' and partes[1] == '254' or  # link-local
                  partes[0] == '224' and partes[1] == '0' and partes[2] == '0'):  # multicast
                resultados['tipo'] = 'Reservado'
            else:
                resultados['tipo'] = 'Público'
                resultados['publico'] = True
                
        except ValueError:
            pass
        
        return resultados
    
    @staticmethod
    def validar_email(email: str) -> bool:
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validar_cep(cep: str) -> bool:
        """Valida CEP brasileiro"""
        cep = re.sub(r'[^0-9]', '', cep)
        return len(cep) == 8 and cep.isdigit()

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
   ███████╗██╗   ██╗ █████╗ ██╗     ██████╗  █████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██║     ██╔══██╗██╔══██╗██╔══██╗
   ███████╗██║   ██║███████║██║     ██║  ██║███████║██║  ██║
   ╚════██║██║   ██║██╔══██║██║     ██║  ██║██╔══██║██║  ██║
   ███████║╚██████╔╝██║  ██║███████╗██████╔╝██║  ██║██████╔╝
   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═════╝ 
{RESET}
{CIANO}{NEGRITO}   VALIDADOR MULTI-FORMATOS v2.0
   Terminal Avançado de Validação
{RESET}
{AMARELO}   Formatos suportados: CPF, Telefone, IP, Email, CEP
   Validação local - Sem consulta a APIs externas
{RESET}""")

def formatar_cpf(cpf: str) -> str:
    """Formata CPF para exibição"""
    cpf = re.sub(r'[^0-9]', '', cpf)
    return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:11]}" if len(cpf) == 11 else cpf

def formatar_telefone(telefone: str) -> str:
    """Formata telefone para exibição"""
    telefone = re.sub(r'[^0-9]', '', telefone)
    
    if len(telefone) == 11:  # Com DDD e 9
        return f"({telefone[:2]}) {telefone[2:7]}-{telefone[7:]}"
    elif len(telefone) == 10:  # Com DDD sem 9
        return f"({telefone[:2]}) {telefone[2:6]}-{telefone[6:]}"
    elif len(telefone) == 8:  # Sem DDD
        return f"{telefone[:4]}-{telefone[4:]}"
    else:
        return telefone

def formatar_cep(cep: str) -> str:
    """Formata CEP para exibição"""
    cep = re.sub(r'[^0-9]', '', cep)
    return f"{cep[:5]}-{cep[5:8]}" if len(cep) == 8 else cep

def mostrar_resultado_cpf(cpf: str, valido: bool):
    """Exibe resultado da validação de CPF"""
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO CPF ==={RESET}")
    print(f"{AZUL}CPF:{RESET} {formatar_cpf(cpf)}")
    
    if valido:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ VÁLIDO{RESET}")
        print(f"{AZUL}Formato:{RESET} {VERDE}Correto{RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ INVÁLIDO{RESET}")
        print(f"{AZUL}Problema:{RESET} {VERMELHO}Incorreto ou dígitos verificadores errados{RESET}")

def mostrar_resultado_telefone(telefone: str, resultado: Dict):
    """Exibe resultado da validação de telefone"""
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO TELEFONE ==={RESET}")
    print(f"{AZUL}Telefone:{RESET} {formatar_telefone(telefone)}")
    
    if resultado['valido']:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ VÁLIDO{RESET}")
        print(f"{AZUL}Tipo:{RESET} {VERDE}{resultado['tipo']}{RESET}")
        print(f"{AZUL}DDD:{RESET} {VERDE if resultado['com_ddd'] else AMARELO}{'Sim' if resultado['com_ddd'] else 'Não'}{RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ INVÁLIDO{RESET}")
        print(f"{AZUL}Problema:{RESET} {VERMELHO}Formato brasileiro incorreto{RESET}")

def mostrar_resultado_ip(ip: str, resultado: Dict):
    """Exibe resultado da validação de IP"""
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO ENDEREÇO IP ==={RESET}")
    print(f"{AZUL}IP:{RESET} {ip}")
    
    if resultado['valido']:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ VÁLIDO{RESET}")
        print(f"{AZUL}Tipo:{RESET} {VERDE}{resultado['tipo']}{RESET}")
        
        if resultado['publico']:
            print(f"{AZUL}Acesso:{RESET} {AMARELO}Público (Internet){RESET}")
        elif resultado['privado']:
            print(f"{AZUL}Acesso:{RESET} {CIANO}Privado (Rede Local){RESET}")
        else:
            print(f"{AZUL}Acesso:{RESET} {MAGENTA}Reservado/Uso Especial{RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ INVÁLIDO{RESET}")
        print(f"{AZUL}Problema:{RESET} {VERMELHO}Formato IPv4 incorreto{RESET}")

def mostrar_resultado_email(email: str, valido: bool):
    """Exibe resultado da validação de email"""
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO EMAIL ==={RESET}")
    print(f"{AZUL}Email:{RESET} {email}")
    
    if valido:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ VÁLIDO{RESET}")
        print(f"{AZUL}Formato:{RESET} {VERDE}Correto{RESET}")
        dominio = email.split('@')[1] if '@' in email else ''
        print(f"{AZUL}Domínio:{RESET} {CIANO}{dominio}{RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ INVÁLIDO{RESET}")
        print(f"{AZUL}Problema:{RESET} {VERMELHO}Formato de email incorreto{RESET}")

def mostrar_resultado_cep(cep: str, valido: bool):
    """Exibe resultado da validação de CEP"""
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO CEP ==={RESET}")
    print(f"{AZUL}CEP:{RESET} {formatar_cep(cep)}")
    
    if valido:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ VÁLIDO{RESET}")
        print(f"{AZUL}Formato:{RESET} {VERDE}Correto (8 dígitos){RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ INVÁLIDO{RESET}")
        print(f"{AZUL}Problema:{RESET} {VERMELHO}Formato brasileiro incorreto{RESET}")

def salvar_resultado(tipo: str, entrada: str, valido: bool, dados_extras: Dict = None):
    """Salva resultado em arquivo JSON"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"validacao_{tipo}_{timestamp}.json"
    
    resultado = {
        'tipo': tipo,
        'entrada': entrada,
        'valido': valido,
        'data_validacao': datetime.now().isoformat(),
        'dados_extras': dados_extras or {}
    }
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)
        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL - VALIDADOR{RESET}")
    print(f"{VERDE}[1]{RESET} Validar CPF")
    print(f"{VERDE}[2]{RESET} Validar Telefone")
    print(f"{VERDE}[3]{RESET} Validar Endereço IP")
    print(f"{VERDE}[4]{RESET} Validar Email")
    print(f"{VERDE}[5]{RESET} Validar CEP")
    print(f"{VERDE}[6]{RESET} Validar Todos")
    print(f"{VERDE}[7]{RESET} Sobre")
    print(f"{VERDE}[8]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def validar_todos():
    """Valida todos os formatos em sequência"""
    banner()
    print(f"\n{CIANO}{NEGRITO}=== VALIDAÇÃO COMPLETA ==={RESET}")
    
    validador = Validador()
    
    # CPF
    cpf = input(f"\n{AMARELO}Digite o CPF: {RESET}").strip()
    resultado_cpf = validador.validar_cpf(cpf)
    mostrar_resultado_cpf(cpf, resultado_cpf)
    
    # Telefone
    telefone = input(f"\n{AMARELO}Digite o Telefone: {RESET}").strip()
    resultado_telefone = validador.validar_telefone(telefone)
    mostrar_resultado_telefone(telefone, resultado_telefone)
    
    # IP
    ip = input(f"\n{AMARELO}Digite o Endereço IP: {RESET}").strip()
    resultado_ip = validador.validar_ip(ip)
    mostrar_resultado_ip(ip, resultado_ip)
    
    # Email
    email = input(f"\n{AMARELO}Digite o Email: {RESET}").strip()
    resultado_email = validador.validar_email(email)
    mostrar_resultado_email(email, resultado_email)
    
    # CEP
    cep = input(f"\n{AMARELO}Digite o CEP: {RESET}").strip()
    resultado_cep = validador.validar_cep(cep)
    mostrar_resultado_cep(cep, resultado_cep)
    
    # Salvar resultados consolidados
    salvar = input(f"\n{CIANO}Salvar resultados completos? (S/N): {RESET}").lower()
    if salvar in ['s', 'sim']:
        dados_completos = {
            'cpf': {'entrada': cpf, 'valido': resultado_cpf},
            'telefone': {'entrada': telefone, 'valido': resultado_telefone['valido'], 'detalhes': resultado_telefone},
            'ip': {'entrada': ip, 'valido': resultado_ip['valido'], 'detalhes': resultado_ip},
            'email': {'entrada': email, 'valido': resultado_email},
            'cep': {'entrada': cep, 'valido': resultado_cep}
        }
        salvar_resultado('COMPLETO', 'Multiplas entradas', True, dados_completos)

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE O VALIDADOR MULTI-FORMATOS{RESET}

{AMARELO}Funcionalidades:{RESET}
• Validação de CPF brasileiro (dígitos verificadores)
• Validação de telefone (formatos brasileiros)
• Validação de endereço IP (IPv4)
• Validação de email (formato padrão)
• Validação de CEP brasileiro

{AMARELO}Características:{RESET}
✓ Validação 100% local
✓ Não consulta APIs externas
✓ Preserva sua privacidade
✓ Resultados instantâneos
✓ Exportação em JSON

{AMARELO}Formatos aceitos:{RESET}
CPF: 123.456.789-09 ou 12345678909
Telefone: (11) 99999-9999 ou 11999999999
IP: 192.168.1.1
Email: usuario@dominio.com
CEP: 12345-678 ou 12345678

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        validador = Validador()
        
        while True:
            opcao = menu_principal()
            
            if opcao == '1':  # CPF
                banner()
                cpf = input(f"\n{CIANO}Digite o CPF: {RESET}").strip()
                resultado = validador.validar_cpf(cpf)
                mostrar_resultado_cpf(cpf, resultado)
                
                salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    salvar_resultado('CPF', cpf, resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':  # Telefone
                banner()
                telefone = input(f"\n{CIANO}Digite o Telefone: {RESET}").strip()
                resultado = validador.validar_telefone(telefone)
                mostrar_resultado_telefone(telefone, resultado)
                
                salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    salvar_resultado('TELEFONE', telefone, resultado['valido'], resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':  # IP
                banner()
                ip = input(f"\n{CIANO}Digite o Endereço IP: {RESET}").strip()
                resultado = validador.validar_ip(ip)
                mostrar_resultado_ip(ip, resultado)
                
                salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    salvar_resultado('IP', ip, resultado['valido'], resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':  # Email
                banner()
                email = input(f"\n{CIANO}Digite o Email: {RESET}").strip()
                resultado = validador.validar_email(email)
                mostrar_resultado_email(email, resultado)
                
                salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    salvar_resultado('EMAIL', email, resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '5':  # CEP
                banner()
                cep = input(f"\n{CIANO}Digite o CEP: {RESET}").strip()
                resultado = validador.validar_cep(cep)
                mostrar_resultado_cep(cep, resultado)
                
                salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    salvar_resultado('CEP', cep, resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '6':  # Validar Todos
                validar_todos()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '7':  # Sobre
                sobre()
            
            elif opcao == '8':  # Sair
                print(f"\n{VERDE}[+] Saindo... Obrigado por usar o Validador!{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida!{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
