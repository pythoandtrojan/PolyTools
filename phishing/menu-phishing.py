#!/usr/bin/env python3
import os
import sys
import subprocess
import time
from datetime import datetime

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def criar_diretorio():
    if not os.path.exists('PhishingTools'):
        os.makedirs('PhishingTools')
        print(f"{colors.GREEN}[+] Diretório 'PhishingTools' criado com sucesso!{colors.END}")
    os.chdir('PhishingTools')

def verificar_ferramenta(nome):
    """Verifica se uma ferramenta está instalada"""
    if nome in ['serveo', 'localtunnel']:
        try:
            if nome == 'serveo':
                subprocess.run(['ssh', '-V'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            elif nome == 'localtunnel':
                subprocess.run(['lt', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except:
            return False
    else:
        return os.path.exists(nome)

def instalar_ferramenta(nome, url):
    """Tenta instalar uma ferramenta específica"""
    print(f"\n{colors.YELLOW}[*] Verificando {nome}...{colors.END}")
    
    if verificar_ferramenta(nome):
        print(f"{colors.GREEN}[+] {nome} já está instalado.{colors.END}")
        return True
    
    resposta = input(f"{colors.YELLOW}[?] {nome} não encontrado. Deseja instalar? (s/n): {colors.END}").strip().lower()
    
    if resposta != 's':
        print(f"{colors.YELLOW}[-] Instalação de {nome} cancelada.{colors.END}")
        return False
    
    print(f"{colors.YELLOW}[*] Baixando {nome}...{colors.END}")
    try:
        if 'git' in url:
            subprocess.run(['git', 'clone', url], check=True)
            print(f"{colors.GREEN}[+] {nome} instalado com sucesso via Git!{colors.END}")
            return True
        elif 'npm' in url:
            subprocess.run(url.split(), check=True)
            print(f"{colors.GREEN}[+] {nome} instalado com sucesso via npm!{colors.END}")
            return True
        else:
            arquivo = url.split('/')[-1]
            subprocess.run(['wget', url, '-O', arquivo], check=True)
            
            if arquivo.endswith('.zip'):
                subprocess.run(['unzip', arquivo], check=True)
                os.remove(arquivo)
            elif arquivo.endswith(('.tar.gz', '.gz')):
                subprocess.run(['tar', 'xvf', arquivo], check=True)
                os.remove(arquivo)
            
            # Verifica se o arquivo baixado precisa de permissões de execução
            if nome in ['ngrok', 'cloudflared', 'chisel', 'rathole', 'inlets']:
                if os.path.exists(nome):
                    os.chmod(nome, 0o755)
                else:
                    # Algumas ferramentas são extraídas em subdiretórios
                    for root, dirs, files in os.walk('.'):
                        if nome in files:
                            os.chmod(os.path.join(root, nome), 0o755)
            
            print(f"{colors.GREEN}[+] {nome} instalado com sucesso!{colors.END}")
            return True
    except subprocess.CalledProcessError as e:
        print(f"{colors.RED}[-] Erro ao instalar {nome}: Comando falhou com código {e.returncode}{colors.END}")
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao instalar {nome}: {str(e)}{colors.END}")
    
    return False

def menu_principal():
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{colors.BLUE}
  ____  _     _     _       _     _____ _     _     _____ _____ ____  
 |  _ \| |__ (_)___| |__   (_)___|  ___| |__ (_)___|  ___| ____/ ___| 
 | |_) | '_ \| / __| '_ \  | / __| |_  | '_ \| / __| |_  |  _| \___ \ 
 |  __/| | | | \__ \ | | | | \__ \  _| | | | | \__ \  _| | |___ ___) |
 |_|   |_| |_|_|___/_| |_| |_|___/_|   |_| |_|_|___/_|   |_____|____/ 
                                                                       
{colors.PURPLE}╔══════════════════════════════════════════════════════════╗
║{colors.CYAN}           MENU PRINCIPAL - FERRAMENTAS DE PHISHING         {colors.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {colors.WHITE}1. {colors.GREEN}Phishing Tools                                {colors.PURPLE}║
║ {colors.WHITE}2. {colors.GREEN}Túneis (Ngrok, Serveo, LocalTunnel, etc)      {colors.PURPLE}║
║ {colors.WHITE}3. {colors.RED}Sair                                            {colors.PURPLE}║
╚══════════════════════════════════════════════════════════╝{colors.END}""")

        escolha = input(f"\n{colors.YELLOW}[?] Selecione uma opção: {colors.END}")
        
        if escolha == '1':
            menu_phishing()
        elif escolha == '2':
            menu_tuneis()
        elif escolha == '3':
            print(f"\n{colors.RED}[!] Saindo...{colors.END}")
            sys.exit()
        else:
            print(f"\n{colors.RED}[-] Opção inválida! Tente novamente.{colors.END}")
            time.sleep(1)

def menu_phishing():
    ferramentas_phishing = {
        '1': ('SocialFish', 'https://github.com/UndeadSec/SocialFish.git'),
        '2': ('HiddenEye', 'https://github.com/DarkSecDevelopers/HiddenEye.git'),
        '3': ('Zphisher', 'https://github.com/htr-tech/zphisher.git'),
        '4': ('BlackPhish', 'https://github.com/iinc0gnit0/BlackPhish.git'),
        '5': ('PyPhisher', 'https://github.com/KasRoudra/PyPhisher.git'),
        '6': ('ShellPhish', 'https://github.com/thelinuxchoice/shellphish.git'),
        '7': ('nexphisher', 'https://github.com/htr-tech/nexphisher.git'),
        '8': ('AnonPhisher', 'https://github.com/ExpertAnonymous/AnonPhisher.git'),
        '9': ('Phishious', 'https://github.com/Viralmaniar/Phishious.git'),
        '10': ('ArtPhish', 'https://github.com/rajkumardusad/ArtPhish.git'),
        '11': ('PhishFleet', 'https://github.com/PhishFleet/PhishFleet.git'),
        '12': ('PhishMon', 'https://github.com/JasonJerry/PhishMon.git'),
        '13': ('Voltar', None)
    }

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{colors.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{colors.CYAN}               FERRAMENTAS DE PHISHING               {colors.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {colors.WHITE}1. {colors.GREEN}SocialFish                                {colors.PURPLE}║
║ {colors.WHITE}2. {colors.GREEN}HiddenEye                                 {colors.PURPLE}║
║ {colors.WHITE}3. {colors.GREEN}Zphisher                                  {colors.PURPLE}║
║ {colors.WHITE}4. {colors.GREEN}BlackPhish                                {colors.PURPLE}║
║ {colors.WHITE}5. {colors.GREEN}PyPhisher                                 {colors.PURPLE}║
║ {colors.WHITE}6. {colors.GREEN}ShellPhish                                {colors.PURPLE}║
║ {colors.WHITE}7. {colors.GREEN}nexphisher                                {colors.PURPLE}║
║ {colors.WHITE}8. {colors.GREEN}AnonPhisher                               {colors.PURPLE}║
║ {colors.WHITE}9. {colors.GREEN}Phishious                                 {colors.PURPLE}║
║ {colors.WHITE}10.{colors.GREEN}ArtPhish                                  {colors.PURPLE}║
║ {colors.WHITE}11.{colors.GREEN}PhishFleet                                {colors.PURPLE}║
║ {colors.WHITE}12.{colors.GREEN}PhishMon                                  {colors.PURPLE}║
║ {colors.WHITE}13.{colors.RED}Voltar ao Menu Principal                   {colors.PURPLE}║
╚══════════════════════════════════════════════════════════╝{colors.END}""")

        escolha = input(f"\n{colors.YELLOW}[?] Selecione uma ferramenta (1-13): {colors.END}")
        
        if escolha == '13':
            return
        elif escolha in ferramentas_phishing:
            nome, url = ferramentas_phishing[escolha]
            if nome == 'Voltar':
                return
            if instalar_ferramenta(nome, url):
                executar_ferramenta(nome)
        else:
            print(f"\n{colors.RED}[-] Opção inválida! Tente novamente.{colors.END}")
            time.sleep(1)

def menu_tuneis():
    ferramentas_tunel = {
        '1': ('ngrok', 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip'),
        '2': ('serveo', 'https://serveo.net/'),
        '3': ('localtunnel', 'npm install -g localtunnel'),
        '4': ('cloudflared', 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'),
        '5': ('bore', 'https://github.com/ekzhang/bore.git'),
        '6': ('chisel', 'https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz'),
        '7': ('rathole', 'https://github.com/rapiz1/rathole/releases/download/v0.4.4/rathole-x86_64-unknown-linux-musl.tar.gz'),
        '8': ('inlets', 'https://github.com/inlets/inlets-pro/releases/download/0.9.3/inlets-pro'),
        '9': ('Voltar', None)
    }

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{colors.PURPLE}
╔══════════════════════════════════════════════════════════╗
║{colors.CYAN}                  FERRAMENTAS DE TÚNEL                 {colors.PURPLE}║
╠══════════════════════════════════════════════════════════╣
║ {colors.WHITE}1. {colors.GREEN}Ngrok                                      {colors.PURPLE}║
║ {colors.WHITE}2. {colors.GREEN}Serveo.net                                 {colors.PURPLE}║
║ {colors.WHITE}3. {colors.GREEN}LocalTunnel                                {colors.PURPLE}║
║ {colors.WHITE}4. {colors.GREEN}Cloudflared                                {colors.PURPLE}║
║ {colors.WHITE}5. {colors.GREEN}Bore                                       {colors.PURPLE}║
║ {colors.WHITE}6. {colors.GREEN}Chisel                                     {colors.PURPLE}║
║ {colors.WHITE}7. {colors.GREEN}Rathole                                    {colors.PURPLE}║
║ {colors.WHITE}8. {colors.GREEN}Inlets                                     {colors.PURPLE}║
║ {colors.WHITE}9. {colors.RED}Voltar ao Menu Principal                   {colors.PURPLE}║
╚══════════════════════════════════════════════════════════╝{colors.END}""")

        escolha = input(f"\n{colors.YELLOW}[?] Selecione um túnel (1-9): {colors.END}")
        
        if escolha == '9':
            return
        elif escolha in ferramentas_tunel:
            nome, url = ferramentas_tunel[escolha]
            if nome == 'Voltar':
                return
            if instalar_ferramenta(nome, url):
                executar_tunel(nome)
        else:
            print(f"\n{colors.RED}[-] Opção inválida! Tente novamente.{colors.END}")
            time.sleep(1)

def executar_ferramenta(nome):
    try:
        print(f"\n{colors.YELLOW}[*] Iniciando {nome}...{colors.END}")
        
        # Verifica se a ferramenta existe
        if not verificar_ferramenta(nome):
            print(f"{colors.RED}[-] {nome} não está instalado.{colors.END}")
            time.sleep(2)
            return
        
        # Verifica se é um diretório (ferramentas baixadas via git)
        if os.path.isdir(nome):
            os.chdir(nome)
        
        # Executa a ferramenta específica
        if nome == 'SocialFish':
            subprocess.run(['python3', 'SocialFish.py'], check=True)
        elif nome == 'HiddenEye':
            subprocess.run(['python3', 'HiddenEye.py'], check=True)
        elif nome == 'Zphisher':
            subprocess.run(['bash', 'zphisher.sh'], check=True)
        elif nome == 'BlackPhish':
            subprocess.run(['python3', 'blackphish.py'], check=True)
        elif nome == 'PyPhisher':
            subprocess.run(['python3', 'pyphisher.py'], check=True)
        elif nome == 'ShellPhish':
            subprocess.run(['bash', 'shellphish.sh'], check=True)
        elif nome == 'nexphisher':
            subprocess.run(['bash', 'nexphisher.sh'], check=True)
        elif nome == 'AnonPhisher':
            subprocess.run(['python3', 'AnonPhisher.py'], check=True)
        elif nome == 'Phishious':
            subprocess.run(['python3', 'phishious.py'], check=True)
        elif nome == 'ArtPhish':
            subprocess.run(['python3', 'artphish.py'], check=True)
        elif nome == 'PhishFleet':
            subprocess.run(['python3', 'phishfleet.py'], check=True)
        elif nome == 'PhishMon':
            subprocess.run(['python3', 'phishmon.py'], check=True)
        
        # Volta ao diretório anterior se necessário
        if os.path.isdir(nome):
            os.chdir('..')
            
    except subprocess.CalledProcessError as e:
        print(f"{colors.RED}[-] Erro ao executar {nome}: Comando falhou com código {e.returncode}{colors.END}")
    except FileNotFoundError:
        print(f"{colors.RED}[-] Arquivo principal não encontrado em {nome}. Verifique a instalação.{colors.END}")
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao executar {nome}: {str(e)}{colors.END}")
    finally:
        input(f"\n{colors.YELLOW}[!] Pressione Enter para continuar...{colors.END}")

def executar_tunel(nome):
    try:
        print(f"\n{colors.YELLOW}[*] Preparando {nome}...{colors.END}")
        
        if not verificar_ferramenta(nome):
            print(f"{colors.RED}[-] {nome} não está instalado.{colors.END}")
            time.sleep(2)
            return
        
        porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
        
        if nome == 'ngrok':
            if not os.path.exists('./ngrok'):
                print(f"{colors.RED}[-] ngrok não encontrado no diretório atual.{colors.END}")
                return
            subprocess.run(['./ngrok', 'http', porta])
        elif nome == 'serveo':
            subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', '-R', '80:localhost:' + porta, 'serveo.net'])
        elif nome == 'localtunnel':
            subprocess.run(['lt', '--port', porta])
        elif nome == 'cloudflared':
            if not os.path.exists('./cloudflared'):
                print(f"{colors.RED}[-] cloudflared não encontrado no diretório atual.{colors.END}")
                return
            subprocess.run(['./cloudflared', 'tunnel', '--url', 'http://localhost:' + porta])
        elif nome == 'bore':
            if not os.path.exists('bore'):
                print(f"{colors.RED}[-] Diretório bore não encontrado.{colors.END}")
                return
            os.chdir('bore')
            subprocess.run(['cargo', 'run', '--', '--port', porta])
            os.chdir('..')
        elif nome == 'chisel':
            if not os.path.exists('./chisel'):
                print(f"{colors.RED}[-] chisel não encontrado no diretório atual.{colors.END}")
                return
            modo = input(f"{colors.YELLOW}[?] Modo (server/client): {colors.END}")
            if modo == 'server':
                subprocess.run(['./chisel', 'server', '--port', '8080'])
            else:
                server = input(f"{colors.YELLOW}[?] Endereço do servidor (ex: 1.2.3.4:8080): {colors.END}")
                subprocess.run(['./chisel', 'client', server, porta + ':localhost:' + porta])
        elif nome == 'rathole':
            if not os.path.exists('./rathole'):
                print(f"{colors.RED}[-] rathole não encontrado no diretório atual.{colors.END}")
                return
            config = input(f"{colors.YELLOW}[?] Caminho para o arquivo de configuração: {colors.END}")
            subprocess.run(['./rathole', config])
        elif nome == 'inlets':
            if not os.path.exists('./inlets'):
                print(f"{colors.RED}[-] inlets não encontrado no diretório atual.{colors.END}")
                return
            token = input(f"{colors.YELLOW}[?] Token de autenticação: {colors.END}")
            subprocess.run(['./inlets', 'server', '--token', token])
            
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Tunelamento interrompido pelo usuário.{colors.END}")
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao executar {nome}: {str(e)}{colors.END}")
    finally:
        input(f"\n{colors.YELLOW}[!] Pressione Enter para continuar...{colors.END}")

def main():
    try:
        criar_diretorio()
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{colors.RED}[!] Programa interrompido pelo usuário.{colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{colors.RED}[!] Erro crítico: {str(e)}{colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    main()
