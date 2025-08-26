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
     ██╗ ██████╗ ██╗  ██╗███╗   ██╗    ████████╗██╗  ██╗███████╗
     ██║██╔═══██╗██║  ██║████╗  ██║    ╚══██╔══╝██║  ██║██╔════╝
     ██║██║   ██║███████║██╔██╗ ██║       ██║   ███████║█████╗  
██   ██║██║   ██║██╔══██║██║╚██╗██║       ██║   ██╔══██║██╔══╝  
╚█████╔╝╚██████╔╝██║  ██║██║ ╚████║       ██║   ██║  ██║███████╗
 ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝╚══════╝
                         ██████╗ ██╗██████╗ ██████╗ ███████╗██████╗ 
                         ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
                         ██████╔╝██║██████╔╝██████╔╝█████╗  ██████╔╝
                         ██╔═══╝ ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
                         ██║     ██║██║     ██║     ███████╗██║  ██║
                         ╚═╝     ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
                  [ JOHN THE RIPPER MENU - 30 TECHNIQUES ]
    """ + Style.RESET_ALL)

# ======= Técnicas de Ataque John the Ripper =======
tecnicas = {
    1: ("Dictionary Attack", "john --wordlist=WORDLIST HASH_FILE"),
    2: ("Incremental Mode", "john --incremental HASH_FILE"),
    3: ("Single Crack Mode", "john --single HASH_FILE"),
    4: ("External Mode", "john --external:MODE HASH_FILE"),
    5: ("Rule-Based Attack", "john --rules HASH_FILE"),
    6: ("Mask Attack", "john --mask=MASK HASH_FILE"),
    7: ("Wordlist + Rules", "john --wordlist=WORDLIST --rules HASH_FILE"),
    8: ("LM Hash Attack", "john --format=lm HASH_FILE"),
    9: ("NTLM Hash Attack", "john --format=nt HASH_FILE"),
    10: ("MD5 Hash Attack", "john --format=raw-md5 HASH_FILE"),
    11: ("SHA1 Hash Attack", "john --format=raw-sha1 HASH_FILE"),
    12: ("SHA256 Hash Attack", "john --format=raw-sha256 HASH_FILE"),
    13: ("SHA512 Hash Attack", "john --format=raw-sha512 HASH_FILE"),
    14: ("Unix crypt() Attack", "john --format=crypt HASH_FILE"),
    15: ("PDF Attack", "john --format=pdf HASH_FILE"),
    16: ("ZIP Attack", "john --format=zip HASH_FILE"),
    17: ("RAR Attack", "john --format=rar HASH_FILE"),
    18: ("7Z Attack", "john --format=7z HASH_FILE"),
    19: ("Word Document Attack", "john --format=office HASH_FILE"),
    20: ("Excel Attack", "john --format=office HASH_FILE"),
    21: ("PowerPoint Attack", "john --format=office HASH_FILE"),
    22: ("WPA/WPA2 Attack", "john --format=wpapsk HASH_FILE"),
    23: ("PKCS#12 Attack", "john --format=pfx HASH_FILE"),
    24: ("Kerberos Attack", "john --format=krb5pa-sha1 HASH_FILE"),
    25: ("Bitcoin Wallet", "john --format=bitcoin HASH_FILE"),
    26: ("MySQL Hash", "john --format=mysql HASH_FILE"),
    27: ("PostgreSQL Hash", "john --format=postgres HASH_FILE"),
    28: ("Oracle Hash", "john --format=oracle HASH_FILE"),
    29: ("SSH Key Attack", "john --format=ssh HASH_FILE"),
    30: ("Custom Format", "john --format=FORMAT HASH_FILE"),
}

# ======= Verificar se o John the Ripper está instalado =======
def verificar_john():
    try:
        result = subprocess.run(["john", "--help"], capture_output=True, text=True, timeout=10)
        if "John the Ripper" in result.stdout or "John the Ripper" in result.stderr:
            print(Fore.GREEN + "[+] John the Ripper encontrado!")
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(Fore.RED + "[X] John the Ripper não encontrado.")
        
        # Tentar instalar automaticamente
        print(Fore.YELLOW + "[~] Tentando instalar o John the Ripper...")
        try:
            if os.name == 'posix':  # Linux/Unix
                subprocess.run(["sudo", "apt", "install", "john", "-y"], 
                             capture_output=True, timeout=120)
                print(Fore.GREEN + "[+] John the Ripper instalado com sucesso!")
                return True
            else:  # Windows
                print(Fore.RED + "[X] Instalação automática não suportada no Windows.")
                print(Fore.YELLOW + "[!] Baixe manualmente: https://www.openwall.com/john/")
                return False
        except:
            print(Fore.RED + "[X] Falha ao instalar John the Ripper automaticamente.")
            print(Fore.YELLOW + "[!] Instale manualmente: sudo apt install john")
            return False

# ======= Obter entrada do usuário =======
def obter_entrada(prompt, default=""):
    if default:
        entrada = input(Fore.YELLOW + f"{prompt} [{default}]: ").strip()
        return entrada if entrada else default
    else:
        return input(Fore.YELLOW + f"{prompt}: ").strip()

# ======= Construir comando John =======
def construir_comando(base_cmd):
    comando = base_cmd
    
    # Substituir HASH_FILE
    if "HASH_FILE" in comando:
        hash_file = obter_entrada("Digite o caminho do arquivo de hash", "hashes.txt")
        comando = comando.replace("HASH_FILE", hash_file)
    
    # Substituir WORDLIST
    if "WORDLIST" in comando:
        wordlist = obter_entrada("Digite o caminho da wordlist", "passwords.txt")
        comando = comando.replace("WORDLIST", wordlist)
    
    # Substituir MASK
    if "MASK=" in comando:
        mask = obter_entrada("Digite a máscara", "?a?a?a?a?a?a")
        comando = comando.replace("?a?a?a?a?a?a", mask)
    
    # Substituir FORMAT
    if "FORMAT" in comando and "--format=" in comando:
        formato = obter_entrada("Digite o formato", "raw-md5")
        comando = comando.replace("FORMAT", formato)
    
    # Substituir MODE em external mode
    if "MODE" in comando:
        mode = obter_entrada("Digite o modo externo", "Wordlist")
        comando = comando.replace("MODE", mode)
    
    return comando

# ======= Executar comando John =======
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

# ======= Mostrar técnicas em 3 colunas =======
def mostrar_tecnicas():
    print(Fore.CYAN + "\n[~] Técnicas de Ataque Disponíveis:")
    print(Fore.CYAN + "-" * 90)
    
    # Organizar em 3 colunas
    items = list(tecnicas.items())
    for i in range(0, len(items), 3):
        linha = ""
        for j in range(3):
            if i + j < len(items):
                num, (nome, _) = items[i + j]
                linha += f"{Fore.YELLOW}[{num:02d}] {nome:<25}"
        print(linha)

# ======= Mostrar hashes recuperados =======
def mostrar_hashes_recuperados():
    try:
        if os.path.exists("~/.john/john.pot"):
            print(Fore.GREEN + "\n[+] Hashes recuperados:")
            with open("~/.john/john.pot", "r") as f:
                for linha in f:
                    print(Fore.CYAN + linha.strip())
        else:
            print(Fore.YELLOW + "[!] Nenhum hash recuperado ainda.")
    except:
        print(Fore.YELLOW + "[!] Não foi possível verificar hashes recuperados.")

# ======= Gerar arquivos de exemplo =======
def gerar_arquivos_exemplo():
    print(Fore.CYAN + "\n[~] Gerando arquivos de exemplo...")
    
    # Arquivo de hashes de exemplo
    hashes_exemplo = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # password (MD5)
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # password (SHA256)
        "$6$rounds=656000$WgUQeJ/ydugXtQhL$cL/aqLlnsLb.y4pV.8gS6lD7L6Q8Lz6L1L6L1L6L1L6L1L6L1L6L1L6L1L6",  # password (Unix crypt)
        "d0763edaa9d9bd2a9516280e9044d885",  # monkey (MD5)
    ]
    
    with open("hashes.txt", "w") as f:
        for hash_val in hashes_exemplo:
            f.write(f"{hash_val}\n")
    print(Fore.GREEN + "[+] Arquivo 'hashes.txt' criado com hashes de exemplo")
    
    # Wordlist de exemplo
    senhas_comuns = [
        "password", "123456", "12345678", "qwerty", "abc123", 
        "monkey", "letmein", "dragon", "baseball", "iloveyou",
        "trustno1", "sunshine", "master", "hello", "freedom"
    ]
    
    with open("passwords.txt", "w") as f:
        for senha in senhas_comuns:
            f.write(f"{senha}\n")
    print(Fore.GREEN + "[+] Arquivo 'passwords.txt' criado com senhas comuns")
    
    input(Fore.GREEN + "\nPressione Enter para continuar...")

# ======= Menu =======
def menu():
    while True:
        banner()
        mostrar_tecnicas()
        mostrar_hashes_recuperados()
        
        print(Fore.CYAN + "\n" + "="*90)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[01-30] Selecionar técnica de ataque")
        print(Fore.CYAN + "[S]     Mostrar senhas recuperadas")
        print(Fore.CYAN + "[G]     Gerar arquivos de exemplo")
        print(Fore.CYAN + "[C]     Comando personalizado do John")
        print(Fore.CYAN + "[0]     Sair")
        print(Fore.CYAN + "="*90)

        try:
            escolha = input(Fore.YELLOW + "\nEscolha uma opção: ").strip().upper()
            
            if escolha == '0':
                print(Fore.GREEN + "Saindo...")
                sys.exit()
            elif escolha == 'C':
                comando_personalizado = input(Fore.YELLOW + "Digite o comando John personalizado: ").strip()
                executar_comando(comando_personalizado)
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            elif escolha == 'S':
                mostrar_hashes_recuperados()
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            elif escolha == 'G':
                gerar_arquivos_exemplo()
            else:
                try:
                    escolha_num = int(escolha)
                    if escolha_num in tecnicas:
                        nome, comando_base = tecnicas[escolha_num]
                        comando_final = construir_comando(comando_base)
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
    print(Fore.RED + Style.BRIGHT + "\n" + "="*90)
    print("AVISO LEGAL:")
    print("Este software é apenas para fins educacionais e de teste de segurança.")
    print("Só utilize em sistemas e arquivos que você possui permissão explícita para testar.")
    print("O cracking de senhas sem autorização é ILEGAL.")
    print("O uso indevido desta ferramenta é de sua exclusiva responsabilidade.")
    print("Respeite as leis locais e não utilize para atividades ilegais.")
    print("="*90)
    
    resposta = input(Fore.YELLOW + "\nVocê concorda com os termos? (S/N): ").strip().upper()
    if resposta != 'S':
        print(Fore.RED + "Você precisa concordar com os termos para usar este software.")
        sys.exit(1)

# ======= MAIN =======
if __name__ == "__main__":
    mostrar_aviso()
    if verificar_john():
        menu()
    else:
        print(Fore.RED + "[X] John the Ripper não está instalado. Abortando.")
        sys.exit(1)
