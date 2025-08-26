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
     ███████╗██╗  ██╗███████╗██████╗ ██╗     ██╗ ██████╗██╗  ██╗
     ██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██║██╔════╝██║ ██╔╝
     ███████╗███████║█████╗  ██████╔╝██║     ██║██║     █████╔╝ 
     ╚════██║██╔══██║██╔══╝  ██╔══██╗██║     ██║██║     ██╔═██╗ 
     ███████║██║  ██║███████╗██║  ██║███████╗██║╚██████╗██║  ██╗
     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝
                [ SHERLOCK USERNAME SEARCH MENU ]
    """ + Style.RESET_ALL)

# ======= Plataformas do Sherlock =======
plataformas = {
    1: ("Todas as Plataformas", ""),
    2: ("Facebook", "facebook"),
    3: ("Instagram", "instagram"),
    4: ("Twitter", "twitter"),
    5: ("LinkedIn", "linkedin"),
    6: ("GitHub", "github"),
    7: ("Reddit", "reddit"),
    8: ("Pinterest", "pinterest"),
    9: ("Tumblr", "tumblr"),
    10: ("YouTube", "youtube"),
    11: ("Twitch", "twitch"),
    12: ("TikTok", "tiktok"),
    13: ("Snapchat", "snapchat"),
    14: ("Telegram", "telegram"),
    15: ("VK", "vk"),
    16: ("Weibo", "weibo"),
    17: ("QQ", "qq"),
    18: ("Baidu", "baidu"),
    19: ("Spotify", "spotify"),
    20: ("SoundCloud", "soundcloud"),
    21: ("DeviantArt", "deviantart"),
    22: ("Flickr", "flickr"),
    23: ("Medium", "medium"),
    24: ("Vimeo", "vimeo"),
    25: ("Dribbble", "dribbble"),
    26: ("Behance", "behance"),
    27: ("GitLab", "gitlab"),
    28: ("Keybase", "keybase"),
    29: ("Roblox", "roblox"),
    30: ("Xbox", "xbox"),
}

# ======= Verificar se o Sherlock está instalado =======
def verificar_sherlock():
    try:
        # Primeiro tenta com o comando sherlock normal
        result = subprocess.run(["sherlock", "--version"], capture_output=True, text=True, timeout=10)
        if "sherlock" in result.stdout.lower() or "sherlock" in result.stderr.lower():
            print(Fore.GREEN + "[+] Sherlock encontrado (comando: sherlock)!")
            return "sherlock"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        # Se não encontrar, tenta com python -m sherlock
        result = subprocess.run(["python", "-m", "sherlock", "--version"], capture_output=True, text=True, timeout=10)
        if "sherlock" in result.stdout.lower() or "sherlock" in result.stderr.lower():
            print(Fore.GREEN + "[+] Sherlock encontrado (comando: python -m sherlock)!")
            return "python -m sherlock"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        # Tenta com python3 -m sherlock
        result = subprocess.run(["python3", "-m", "sherlock", "--version"], capture_output=True, text=True, timeout=10)
        if "sherlock" in result.stdout.lower() or "sherlock" in result.stderr.lower():
            print(Fore.GREEN + "[+] Sherlock encontrado (comando: python3 -m sherlock)!")
            return "python3 -m sherlock"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    print(Fore.RED + "[X] Sherlock não encontrado.")
    
    # Tentar instalar automaticamente via pip
    print(Fore.YELLOW + "[~] Tentando instalar o Sherlock via pip...")
    try:
        subprocess.run(["pip", "install", "sherlock-project"], 
                     capture_output=True, timeout=300)
        
        # Verificar se a instalação foi bem-sucedida
        try:
            result = subprocess.run(["python3", "-m", "sherlock", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if "sherlock" in result.stdout.lower() or "sherlock" in result.stderr.lower():
                print(Fore.GREEN + "[+] Sherlock instalado com sucesso via pip!")
                return "python3 -m sherlock"
        except:
            pass
            
    except Exception as e:
        print(Fore.RED + f"[X] Falha ao instalar Sherlock: {e}")
    
    print(Fore.YELLOW + "[!] Instale manualmente: pip install sherlock-project")
    return None

# ======= Obter entrada do usuário =======
def obter_entrada(prompt, default=""):
    if default:
        entrada = input(Fore.YELLOW + f"{prompt} [{default}]: ").strip()
        return entrada if entrada else default
    else:
        return input(Fore.YELLOW + f"{prompt}: ").strip()

# ======= Construir comando Sherlock =======
def construir_comando(comando_sherlock, plataforma, username):
    comando = f"{comando_sherlock} {username}"
    
    # Adicionar plataforma específica se não for "Todas as Plataformas"
    if plataforma and plataforma != "Todas as Plataformas":
        comando += f" --site {plataforma}"
    
    # Adicionar opções adicionais
    print(Fore.CYAN + "\n[~] Opções adicionais:")
    print(Fore.CYAN + "[1] Busca rápida (apenas resultados positivos)")
    print(Fore.CYAN + "[2] Busca completa (todos os resultados)")
    print(Fore.CYAN + "[3] Salvar resultados em arquivo")
    
    opcao = obter_entrada("Escolha uma opção", "1")
    
    if opcao == "1":
        comando += " --print-found"
    elif opcao == "3":
        arquivo = obter_entrada("Nome do arquivo para salvar", f"{username}_results.txt")
        comando += f" --output {arquivo}"
        comando += " --print-found"
    
    # Adicionar timeout personalizado
    timeout = obter_entrada("Timeout (segundos)", "60")
    comando += f" --timeout {timeout}"
    
    return comando

# ======= Executar comando Sherlock =======
def executar_comando(comando):
    print(Fore.CYAN + f"[>] Executando: {comando}")
    print(Fore.YELLOW + "[!] Esta operação pode demorar vários minutos...")
    
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
                linha = output.decode().strip()
                if "found" in linha.lower() or "positive" in linha.lower():
                    print(Fore.GREEN + linha)
                elif "error" in linha.lower() or "failed" in linha.lower():
                    print(Fore.RED + linha)
                else:
                    print(Fore.CYAN + linha)
        
        # Verificar se houve erro
        stderr = processo.stderr.read()
        if stderr:
            print(Fore.RED + f"Erro: {stderr.decode()}")
            
    except KeyboardInterrupt:
        print(Fore.RED + "\n[X] Busca interrompida pelo usuário.")
    except Exception as e:
        print(Fore.RED + f"[X] Erro ao executar comando: {e}")

# ======= Mostrar plataformas em 3 colunas =======
def mostrar_plataformas():
    print(Fore.CYAN + "\n[~] Plataformas Disponíveis:")
    print(Fore.CYAN + "-" * 90)
    
    # Organizar em 3 colunas
    items = list(plataformas.items())
    for i in range(0, len(items), 3):
        linha = ""
        for j in range(3):
            if i + j < len(items):
                num, (nome, _) = items[i + j]
                linha += f"{Fore.YELLOW}[{num:02d}] {nome:<25}"
        print(linha)

# ======= Verificar resultados anteriores =======
def verificar_resultados_anteriores():
    resultados = []
    for arquivo in os.listdir("."):
        if arquivo.endswith("_results.txt"):
            resultados.append(arquivo)
    
    if resultados:
        print(Fore.GREEN + "\n[+] Resultados anteriores encontrados:")
        for i, arquivo in enumerate(resultados, 1):
            print(Fore.CYAN + f"[{i}] {arquivo}")
        
        escolha = input(Fore.YELLOW + "\nDeseja visualizar algum resultado? (Número ou Enter para pular): ").strip()
        if escolha.isdigit():
            index = int(escolha) - 1
            if 0 <= index < len(resultados):
                try:
                    with open(resultados[index], 'r') as f:
                        print(Fore.GREEN + f"\nConteúdo de {resultados[index]}:")
                        print(Fore.CYAN + "-" * 50)
                        print(f.read())
                except Exception as e:
                    print(Fore.RED + f"Erro ao ler arquivo: {e}")
    else:
        print(Fore.YELLOW + "[!] Nenhum resultado anterior encontrado.")

# ======= Menu =======
def menu(comando_sherlock):
    while True:
        banner()
        mostrar_plataformas()
        verificar_resultados_anteriores()
        
        print(Fore.CYAN + "\n" + "="*90)
        print(Fore.MAGENTA + "OPÇÕES:")
        print(Fore.CYAN + "[01-30] Selecionar plataforma para busca")
        print(Fore.CYAN + "[U]     Verificar usuário em todas as plataformas")
        print(Fore.CYAN + "[C]     Comando personalizado do Sherlock")
        print(Fore.CYAN + "[0]     Sair")
        print(Fore.CYAN + "="*90)

        try:
            escolha = input(Fore.YELLOW + "\nEscolha uma opção: ").strip().upper()
            
            if escolha == '0':
                print(Fore.GREEN + "Saindo...")
                sys.exit()
            elif escolha == 'C':
                comando_personalizado = input(Fore.YELLOW + "Digite o comando Sherlock personalizado: ").strip()
                executar_comando(comando_personalizado)
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            elif escolha == 'U':
                username = obter_entrada("Digite o nome de usuário para buscar")
                comando_final = construir_comando(comando_sherlock, "", username)
                executar_comando(comando_final)
                input(Fore.GREEN + "\nPressione Enter para continuar...")
            else:
                try:
                    escolha_num = int(escolha)
                    if escolha_num in plataformas:
                        nome_plataforma, codigo_plataforma = plataformas[escolha_num]
                        username = obter_entrada("Digite o nome de usuário para buscar")
                        comando_final = construir_comando(comando_sherlock, codigo_plataforma, username)
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
    print("Só utilize para verificar seus próprios usuários ou com autorização explícita.")
    print("A verificação de usuários sem autorização pode violar termos de serviço.")
    print("O uso indevido desta ferramenta é de sua exclusiva responsabilidade.")
    print("Respeite as leis locais e a privacidade dos outros.")
    print("="*90)
    
    resposta = input(Fore.YELLOW + "\nVocê concorda com os termos? (S/N): ").strip().upper()
    if resposta != 'S':
        print(Fore.RED + "Você precisa concordar com os termos para usar este software.")
        sys.exit(1)

# ======= MAIN =======
if __name__ == "__main__":
    mostrar_aviso()
    comando_sherlock = verificar_sherlock()
    if comando_sherlock:
        menu(comando_sherlock)
    else:
        print(Fore.RED + "[X] Sherlock não está instalado. Abortando.")
        sys.exit(1)
