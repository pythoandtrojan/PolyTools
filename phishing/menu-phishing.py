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
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
             [ PHISHING MENU - TOP 30 ]
    """ + Style.RESET_ALL)

# ======= Ferramentas (Top 30 Phishing GitHub) =======
ferramentas = {
    1: ("Zphisher", "https://github.com/htr-tech/zphisher.git", "bash zphisher.sh"),
    2: ("SocialFish", "https://github.com/An0nUD4Y/SocialFish.git", "python3 SocialFish.py"),
    3: ("HiddenEye", "https://github.com/DarkSecDevelopers/HiddenEye.git", "python3 HiddenEye.py"),
    4: ("BlackPhish", "https://github.com/iinc0gnit0/BlackPhish.git", "bash blackphish.sh"),
    5: ("AdvPhishing", "https://github.com/Ignitetch/AdvPhishing.git", "bash AdvPhishing.sh"),
    6: ("ShellPhish", "https://github.com/thelinuxchoice/shellphish.git", "bash shellphish.sh"),
    7: ("PhishX", "https://github.com/WeebSec/PhishX.git", "bash PhishX.sh"),
    8: ("CamPhish", "https://github.com/techchipnet/CamPhish.git", "bash camphish.sh"),
    9: ("SayCheese", "https://github.com/hangetzzu/saycheese.git", "bash saycheese.sh"),
    10: ("QRJacking", "https://github.com/cryptedwolf/qrjacking.git", "python3 qrjacking.py"),
    11: ("WifiPhisher", "https://github.com/wifiphisher/wifiphisher.git", "python3 wifiphisher.py"),
    12: ("Evilginx2", "https://github.com/kgretzky/evilginx2.git", "bash install.sh"),
    13: ("KingPhisher", "https://github.com/securestate/king-phisher.git", "python3 KingPhisher.py"),
    14: ("Storm-Breaker", "https://github.com/ultrasecurity/Storm-Breaker.git", "bash Storm-Breaker.sh"),
    15: ("PyPhisher", "https://github.com/KasRoudra/PyPhisher.git", "python3 pyphisher.py"),
    16: ("Cupp", "https://github.com/Mebus/cupp.git", "python3 cupp.py"),
    17: ("Seeker", "https://github.com/thewhiteh4t/seeker.git", "python3 seeker.py"),
    18: ("EvilURL", "https://github.com/UndeadSec/EvilURL.git", "python3 evilurl.py"),
    19: ("KatPhish", "https://github.com/tsug0d/KatPhish.git", "bash KatPhish.sh"),
    20: ("FakeMail", "https://github.com/suxsem/FakeMail.git", "python3 fakemail.py"),
    21: ("Gophish", "https://github.com/gophish/gophish.git", "./gophish"),
    22: ("Modlishka", "https://github.com/drk1wi/Modlishka.git", "./dist/proxy"),
    23: ("CredSniper", "https://github.com/ustayready/CredSniper.git", "python3 credsniper.py"),
    24: ("PhishLulz", "https://github.com/PHISHLULZ/PHISHLULZ.git", "bash PHISHLULZ.sh"),
    25: ("Lucid", "https://github.com/Lucid-Revenge/Lucid.git", "python3 lucid.py"),
    26: ("Nexphisher", "https://github.com/htr-tech/nexphisher.git", "bash nexphisher.sh"),
    27: ("Artemis", "https://github.com/sweetsoftware/Artemis.git", "python3 artemis.py"),
    28: ("BlackEye", "https://github.com/An0nUD4Y/BlackEye.git", "bash blackeye.sh"),
    29: ("iSmish", "https://github.com/4L13199/ismish.git", "python2 iSmish.py"),
    30: ("PhishBait", "https://github.com/pan0pt1c0n/PhishBait.git", "python3 phishbait.py"),
}

# ======= Pasta padrão =======
pasta_tools = "Ferramentas"

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
            escolha = input(f"\n{Fore.YELLOW}investiga{Fore.BLUE}@{Fore.GREEN}phishing {Fore.RED}> {Fore.BLUE}> ").strip().upper()
            
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

# ======= MAIN =======
if __name__ == "__main__":
    if verificar_dependencias():
        checar_pasta()
        menu()
    else:
        print(Fore.RED + "[X] Dependências necessárias não encontradas. Abortando.")
        sys.exit(1)
