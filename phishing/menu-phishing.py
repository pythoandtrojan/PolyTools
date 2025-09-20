#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import json
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
             [ PHISHING MENU - TOP 40 ]
    """ + Style.RESET_ALL)

# ======= Ferramentas (Top 40 Phishing GitHub) =======
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
    12: ("Evilginx2", "https://github.com/kgretzky/evilginx2.git", "make install"),
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
    31: ("MaskPhish", "https://github.com/jaykali/maskphish.git", "bash maskphish.sh"),
    32: ("PhishTales", "https://github.com/An0nUD4Y/PhishTales.git", "python3 phishtales.py"),
    33: ("GhostPhisher", "https://github.com/savio-code/ghost-phisher.git", "python3 ghost.py"),
    34: ("Lockphish", "https://github.com/jaykali/lockphish.git", "bash lockphish.sh"),
    35: ("AnglerPhish", "https://github.com/An0nUD4Y/AnglerPhish.git", "python3 anglerphish.py"),
    36: ("Weeman", "https://github.com/evait-security/weeman.git", "python2 weeman.py"),
    37: ("SiteBroker", "https://github.com/Anon-Exploiter/SiteBroker.git", "python3 sitebroker.py"),
    38: ("URLCrazy", "https://github.com/urbanadventurer/urlcrazy.git", "./urlcrazy"),
    39: ("PhishEye", "https://github.com/An0nUD4Y/PhishEye.git", "python3 phisheye.py"),
    40: ("PhishXpert", "https://github.com/An0nUD4Y/PhishXpert.git", "bash phishxpert.sh"),
}

# ======= Pasta padrão =======
pasta_tools = "Ferramentas"
status_file = os.path.join(pasta_tools, "status.json")

# ======= Carregar status das ferramentas =======
def carregar_status():
    if os.path.exists(status_file):
        try:
            with open(status_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

# ======= Salvar status das ferramentas =======
def salvar_status(status):
    if not os.path.exists(pasta_tools):
        os.makedirs(pasta_tools)
    with open(status_file, 'w') as f:
        json.dump(status, f)

# ======= Verificar se a ferramenta já existe =======
def verificar_ferramenta(nome):
    destino = os.path.join(pasta_tools, nome)
    status_data = carregar_status()
    
    # Verifica se existe fisicamente e no arquivo de status
    if os.path.exists(destino) and nome in status_data and status_data[nome].get("instalada", False):
        return True
    return False

# ======= Clonar ferramenta =======
def clonar(nome, url):
    destino = os.path.join(pasta_tools, nome)
    status_data = carregar_status()
    
    if verificar_ferramenta(nome):
        print(Fore.YELLOW + f"[!] {nome} já foi baixada anteriormente.")
        return True
    else:
        try:
            print(Fore.GREEN + f"[+] Clonando {nome} ...")
            result = subprocess.run(["git", "clone", url, destino], 
                                  capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                print(Fore.GREEN + f"[+] {nome} clonada com sucesso!")
                # Atualizar status
                status_data[nome] = {"instalada": True, "url": url, "data_instalacao": time.strftime("%Y-%m-%d %H:%M:%S")}
                salvar_status(status_data)
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
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(Fore.GREEN + f"[+] Dependências de {nome} instaladas com sucesso!")
            else:
                print(Fore.YELLOW + f"[!] Alguns erros ao instalar dependências: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[X] Timeout ao instalar dependências para {nome}.")
        except Exception as e:
            print(Fore.YELLOW + f"[!] Erro ao instalar dependências: {e}")
    
    # Verificar se há script de instalação
    scripts_instalacao = ["install.sh", "setup.py", "install.py", "setup.sh"]
    for script in scripts_instalacao:
        script_path = os.path.join(destino, script)
        if os.path.exists(script_path):
            print(Fore.CYAN + f"[~] Executando script de instalação {script} para {nome}...")
            try:
                if script.endswith('.sh'):
                    subprocess.run(["bash", script], cwd=destino, timeout=300)
                elif script.endswith('.py'):
                    subprocess.run(["python3", script], cwd=destino, timeout=300)
                print(Fore.GREEN + f"[+] Script de instalação executado com sucesso!")
            except Exception as e:
                print(Fore.YELLOW + f"[!] Erro ao executar script de instalação: {e}")

# ======= Executar ferramenta =======
def executar(nome, comando):
    caminho = os.path.join(pasta_tools, nome)
    status_data = carregar_status()
    
    if not verificar_ferramenta(nome):
        print(Fore.RED + f"[X] {nome} não foi encontrada. Baixe primeiro.")
        return
    
    # Primeiro instala as dependências
    instalar_dependencias(nome)
    
    print(Fore.CYAN + f"[>] Executando {nome}...")
    time.sleep(2)
    
    try:
        # Navega para o diretório
        os.chdir(caminho)
        
        # Verifica se o comando específico existe
        comando_partes = comando.split()
        arquivo_principal = comando_partes[0]
        
        if not os.path.exists(arquivo_principal):
            # Tenta encontrar um script executável
            scripts = [f for f in os.listdir('.') if os.path.isfile(f) and 
                     (f.endswith('.sh') or f.endswith('.py') or os.access(f, os.X_OK))]
            
            if scripts:
                # Prioriza scripts com nomes conhecidos
                for script_preferido in [nome.lower(), "main", "start", "run"]:
                    for script in scripts:
                        if script_preferido in script.lower():
                            arquivo_principal = script
                            break
                    if arquivo_principal != comando_partes[0]:
                        break
                
                if arquivo_principal.endswith('.sh'):
                    comando = f"bash {arquivo_principal}"
                elif arquivo_principal.endswith('.py'):
                    comando = f"python3 {arquivo_principal}"
                else:
                    comando = f"./{arquivo_principal}"
        
        print(Fore.MAGENTA + f"[+] Executando: {comando}")
        
        # Executa o comando
        os.system(comando)
        
        # Atualiza último uso no status
        status_data[nome]["ultimo_uso"] = time.strftime("%Y-%m-%d %H:%M:%S")
        salvar_status(status_data)
        
    except Exception as e:
        print(Fore.RED + f"[X] Erro ao executar {nome}: {e}")
    finally:
        # Volta para o diretório original
        os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ======= Mostrar status das ferramentas =======
def mostrar_status():
    status_data = carregar_status()
    print(Fore.CYAN + "\n[~] Status das Ferramentas:")
    print(Fore.CYAN + "-" * 70)
    
    for i, (nome, url, _) in ferramentas.items():
        if verificar_ferramenta(nome):
            status = Fore.GREEN + "INSTALADA"
            if nome in status_data and "data_instalacao" in status_data[nome]:
                data = status_data[nome]["data_instalacao"]
                status += Fore.WHITE + f" ({data})"
        else:
            status = Fore.RED + "NÃO INSTALADA"
        
        print(f"{Fore.YELLOW}[{i:2d}] {nome:<20}: {status}")

# ======= Reparar instalação =======
def reparar_instalacao():
    print(Fore.CYAN + "[~] Verificando e reparando instalações...")
    status_data = carregar_status()
    
    for nome, url, _ in ferramentas.values():
        destino = os.path.join(pasta_tools, nome)
        
        if os.path.exists(destino) and (nome not in status_data or not status_data[nome].get("instalada", False)):
            print(Fore.YELLOW + f"[!] Reparando status de {nome}...")
            if nome not in status_data:
                status_data[nome] = {}
            status_data[nome]["instalada"] = True
            status_data[nome]["url"] = url
            status_data[nome]["data_reparo"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    salvar_status(status_data)
    print(Fore.GREEN + "[+] Verificação de instalações concluída!")

# ======= Limpar ferramenta =======
def limpar_ferramenta(nome):
    destino = os.path.join(pasta_tools, nome)
    status_data = carregar_status()
    
    if os.path.exists(destino):
        try:
            import shutil
            shutil.rmtree(destino)
            print(Fore.GREEN + f"[+] {nome} removida com sucesso!")
        except Exception as e:
            print(Fore.RED + f"[X] Erro ao remover {nome}: {e}")
            return False
    
    # Atualizar status
    if nome in status_data:
        status_data[nome]["instalada"] = False
        salvar_status(status_data)
    
    return True

# ======= Menu =======
def menu():
    reparar_instalacao()  # Reparar status ao iniciar
    
    while True:
        banner()
        mostrar_status()
        
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[1-40] Baixar/Executar ferramenta específica")
        print(Fore.CYAN + "[A]    Baixar todas as ferramentas")
        print(Fore.CYAN + "[L]    Limpar ferramenta específica")
        print(Fore.CYAN + "[R]    Reparar instalações")
        print(Fore.CYAN + "[S]    Mostrar status detalhado")
        print(Fore.CYAN + "[0]    Sair")
        print(Fore.CYAN + "="*70)

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
                input(Fore.GREEN + "\n[+] Todas as ferramentas foram processadas. Pressione Enter para continuar...")
            elif escolha == 'L':
                try:
                    num = int(input(Fore.YELLOW + "Número da ferramenta para limpar: "))
                    if num in ferramentas:
                        nome, _, _ = ferramentas[num]
                        if limpar_ferramenta(nome):
                            print(Fore.GREEN + f"[+] {nome} limpa com sucesso!")
                        else:
                            print(Fore.RED + f"[X] Falha ao limpar {nome}")
                    else:
                        print(Fore.RED + "Número inválido.")
                except ValueError:
                    print(Fore.RED + "Entrada inválida.")
                time.sleep(2)
            elif escolha == 'R':
                reparar_instalacao()
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            elif escolha == 'S':
                # Mostrar status detalhado
                status_data = carregar_status()
                print(Fore.CYAN + "\n[~] Status Detalhado:")
                for nome, info in status_data.items():
                    print(f"{Fore.YELLOW}{nome}:")
                    for key, value in info.items():
                        print(f"  {Fore.CYAN}{key}: {Fore.WHITE}{value}")
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
    dependencias = ['git', 'python3', 'pip3', 'wget']
    print(Fore.CYAN + "[~] Verificando dependências...")
    
    for dep in dependencias:
        try:
            if dep == 'pip3':
                subprocess.run([dep, '--version'], capture_output=True, check=True)
            else:
                subprocess.run([dep, '--version'], capture_output=True, check=True)
            print(Fore.GREEN + f"[+] {dep} encontrado.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(Fore.RED + f"[X] {dep} não encontrado. Por favor, instale-o.")
            if dep == 'git':
                print(Fore.YELLOW + "[!] No Debian/Ubuntu: sudo apt install git")
            elif dep in ['python3', 'pip3']:
                print(Fore.YELLOW + "[!] No Debian/Ubuntu: sudo apt install python3 python3-pip")
            elif dep == 'wget':
                print(Fore.YELLOW + "[!] No Debian/Ubuntu: sudo apt install wget")
            time.sleep(2)
            return False
    
    return True

# ======= MAIN =======
if __name__ == "__main__":
    if verificar_dependencias():
        if not os.path.exists(pasta_tools):
            os.makedirs(pasta_tools)
        menu()
    else:
        print(Fore.RED + "[X] Dependências necessárias não encontradas. Abortando.")
        sys.exit(1)
