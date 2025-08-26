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
   ███████╗██████╗  █████╗ ███╗   ███╗
   ██╔════╝██╔══██╗██╔══██╗████╗ ████║
   ███████╗██████╔╝███████║██╔████╔██║
   ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║
   ███████║██║     ██║  ██║██║ ╚═╝ ██║
   ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝
             [ SPAM TOOLS - TOP 30 ]
    """ + Style.RESET_ALL)

# ======= Ferramentas de Spam (Top 30) =======
ferramentas = {
    1: ("SpamBot", "https://github.com/topics/spam-bot", "python3 spambot.py"),
    2: ("Spammer-Grab", "https://github.com/termuxprofessor/spammer-grab", "bash spammer-grab.sh"),
    3: ("SpamSMS", "https://github.com/4L13199/LITESPAM", "bash LITESPAM.sh"),
    4: ("SpamCall", "https://github.com/4L13199/LITECALL", "python3 litecall.py"),
    5: ("SpamWa", "https://github.com/4L13199/LITESPAM", "bash litespam.sh"),
    6: ("SpamMail", "https://github.com/4L13199/LITESPAM", "python3 spam-mail.py"),
    7: ("SpamX", "https://github.com/keralahacker/spamx", "python3 spamx.py"),
    8: ("SpamTools", "https://github.com/BlackHoleSecurity/spamtools", "python3 spamtools.py"),
    9: ("Spammer-Email", "https://github.com/4L13199/spammer-email", "python3 spammer-email.py"),
    10: ("SpamSMS-Indonesia", "https://github.com/4L13199/spamsms-indonesia", "python3 spamsms.py"),
    11: ("SpamCall-Indonesia", "https://github.com/4L13199/spamcall-indonesia", "python3 spamcall.py"),
    12: ("SpamWa-Indonesia", "https://github.com/4L13199/spamwa-indonesia", "python3 spamwa.py"),
    13: ("SpamMail-Indonesia", "https://github.com/4L13199/spammail-indonesia", "python3 spammail.py"),
    14: ("SpamSMS-Brazil", "https://github.com/4L13199/spamsms-brazil", "python3 spamsms.py"),
    15: ("SpamCall-Brazil", "https://github.com/4L13199/spamcall-brazil", "python3 spamcall.py"),
    16: ("SpamWa-Brazil", "https://github.com/4L13199/spamwa-brazil", "python3 spamwa.py"),
    17: ("SpamMail-Brazil", "https://github.com/4L13199/spammail-brazil", "python3 spammail.py"),
    18: ("SpamSMS-USA", "https://github.com/4L13199/spamsms-usa", "python3 spamsms.py"),
    19: ("SpamCall-USA", "https://github.com/4L13199/spamcall-usa", "python3 spamcall.py"),
    20: ("SpamWa-USA", "https://github.com/4L13199/spamwa-usa", "python3 spamwa.py"),
    21: ("SpamMail-USA", "https://github.com/4L13199/spammail-usa", "python3 spammail.py"),
    22: ("SpamSMS-India", "https://github.com/4L13199/spamsms-india", "python3 spamsms.py"),
    23: ("SpamCall-India", "https://github.com/4L13199/spamcall-india", "python3 spamcall.py"),
    24: ("SpamWa-India", "https://github.com/4L13199/spamwa-india", "python3 spamwa.py"),
    25: ("SpamMail-India", "https://github.com/4L13199/spammail-india", "python3 spammail.py"),
    26: ("SpamSMS-Russia", "https://github.com/4L13199/spamsms-russia", "python3 spamsms.py"),
    27: ("SpamCall-Russia", "https://github.com/4L13199/spamcall-russia", "python3 spamcall.py"),
    28: ("SpamWa-Russia", "https://github.com/4L13199/spamwa-russia", "python3 spamwa.py"),
    29: ("SpamMail-Russia", "https://github.com/4L13199/spammail-russia", "python3 spammail.py"),
    30: ("SpamSMS-China", "https://github.com/4L13199/spamsms-china", "python3 spamsms.py"),
}

# ======= Pasta padrão =======
pasta_tools = "SpamTools"

def checar_pasta():
    if not os.path.exists(pasta_tools):
        os.makedirs(pasta_tools)
        print(Fore.GREEN + f"[+] Pasta '{pasta_tools}' criada com sucesso!")

# ======= Verificar se a ferramenta já existe =======
def verificar_ferramenta(nome):
    destino = os.path.join(pasta_tools, nome)
    return os.path.exists(destino)

# ======= Clonar ferramenta =======
def clonar(nome, url):
    destino = os.path.join(pasta_tools, nome)
    if verificar_ferramenta(nome):
        print(Fore.YELLOW + f"[!] {nome} já foi baixada anteriormente.")
        return True
    else:
        try:
            print(Fore.GREEN + f"[+] Clonando {nome} ...")
            result = subprocess.run(["git", "clone", url, destino], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(Fore.GREEN + f"[+] {nome} clonada com sucesso!")
                return True
            else:
                print(Fore.RED + f"[X] Erro ao clonar {nome}: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[X] Timeout ao clonar {nome}. O processo demorou muito.")
            return False
        except Exception as e:
            print(Fore.RED + f"[X] Erro ao clonar {nome}: {e}")
            return False

# ======= Instalar dependências =======
def instalar_dependencias(nome):
    destino = os.path.join(pasta_tools, nome)
    requisitos_path = os.path.join(destino, "requirements.txt")
    
    if os.path.exists(requisitos_path):
        print(Fore.CYAN + f"[~] Instalando dependências para {nome}...")
        try:
            result = subprocess.run(["pip3", "install", "-r", requisitos_path], 
                                  capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                print(Fore.GREEN + f"[+] Dependências de {nome} instaladas com sucesso!")
            else:
                print(Fore.YELLOW + f"[!] Alguns erros ao instalar dependências: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[X] Timeout ao instalar dependências para {nome}.")
        except Exception as e:
            print(Fore.YELLOW + f"[!] Erro ao instalar dependências: {e}")

# ======= Executar ferramenta =======
def executar(nome, comando):
    caminho = os.path.join(pasta_tools, nome)
    if not os.path.exists(caminho):
        print(Fore.RED + f"[X] {nome} não foi encontrada. Baixe primeiro.")
        return
    
    # Primeiro instala as dependências
    instalar_dependencias(nome)
    
    print(Fore.CYAN + f"[>] Executando {nome}...")
    time.sleep(2)
    
    try:
        # Navega para o diretório e executa o comando
        os.chdir(caminho)
        
        # Verifica se o comando específico existe, caso contrário tenta encontrar um executável
        if not os.path.exists(comando.split()[0]):
            # Tenta encontrar um script executável
            scripts = [f for f in os.listdir('.') if os.path.isfile(f) and os.access(f, os.X_OK)]
            if scripts:
                comando = f"./{scripts[0]}"
        
        # Executa o comando
        os.system(comando)
    except Exception as e:
        print(Fore.RED + f"[X] Erro ao executar {nome}: {e}")
    finally:
        # Volta para o diretório original
        os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ======= Mostrar status das ferramentas =======
def mostrar_status():
    print(Fore.CYAN + "\n[~] Status das Ferramentas:")
    print(Fore.CYAN + "-" * 50)
    for i, (nome, _, _) in ferramentas.items():
        status = Fore.GREEN + "INSTALADA" if verificar_ferramenta(nome) else Fore.RED + "NÃO INSTALADA"
        print(f"{Fore.YELLOW}[{i}] {nome}: {status}")

# ======= Menu =======
def menu():
    while True:
        banner()
        mostrar_status()
        
        print(Fore.CYAN + "\n" + "="*50)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[1-30] Baixar/Executar ferramenta específica")
        print(Fore.CYAN + "[A]    Baixar todas as ferramentas")
        print(Fore.CYAN + "[S]    Mostrar status de todas as ferramentas")
        print(Fore.CYAN + "[0]    Sair")
        print(Fore.CYAN + "="*50)

        try:
            escolha = input(Fore.YELLOW + "\nEscolha uma opção: ").strip().upper()
            
            if escolha == '0':
                print(Fore.GREEN + "Saindo...")
                sys.exit()
            elif escolha == 'A':
                print(Fore.CYAN + "[~] Baixando todas as ferramentas...")
                for i, (nome, url, _) in ferramentas.items():
                    print(Fore.CYAN + f"[{i}] Baixando {nome}...")
                    clonar(nome, url)
                    time.sleep(1)
                input(Fore.GREEN + "\n[+] Todas as ferramentas foram baixadas. Pressione Enter para continuar...")
            elif escolha == 'S':
                # Já mostramos o status no banner, só precisamos esperar
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            else:
                try:
                    escolha_num = int(escolha)
                    if escolha_num in ferramentas:
                        nome, url, comando = ferramentas[escolha_num]
                        if clonar(nome, url):
                            executar(nome, comando)
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

# ======= Verificar dependências do sistema =======
def verificar_dependencias():
    dependencias = ['git', 'python3', 'pip3']
    print(Fore.CYAN + "[~] Verificando dependências...")
    
    for dep in dependencias:
        try:
            subprocess.run([dep, '--version'], capture_output=True, check=True)
            print(Fore.GREEN + f"[+] {dep} encontrado.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(Fore.RED + f"[X] {dep} não encontrado. Por favor, instale-o.")
            if dep == 'git':
                print(Fore.YELLOW + "[!] No Debian/Ubuntu: sudo apt install git")
            time.sleep(2)
            return False
    
    return True

# ======= Aviso Legal =======
def mostrar_aviso():
    print(Fore.RED + Style.BRIGHT + "\n" + "="*70)
    print("AVISO LEGAL:")
    print("Este software é apenas para fins educacionais e de teste.")
    print("O uso indevido desta ferramenta é de sua responsabilidade.")
    print("Respeite as leis locais e não utilize para atividades ilegais.")
    print("="*70)
    
    resposta = input(Fore.YELLOW + "\nVocê concorda com os termos? (S/N): ").strip().upper()
    if resposta != 'S':
        print(Fore.RED + "Você precisa concordar com os termos para usar este software.")
        sys.exit(1)

# ======= MAIN =======
if __name__ == "__main__":
    mostrar_aviso()
    if verificar_dependencias():
        checar_pasta()
        menu()
    else:
        print(Fore.RED + "[X] Dependências necessárias não encontradas. Abortando.")
        sys.exit(1)
