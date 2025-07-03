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

def instalar_ferramentas():
    ferramentas = {
        'SocialFish': 'https://github.com/UndeadSec/SocialFish.git',
        'HiddenEye': 'https://github.com/DarkSecDevelopers/HiddenEye.git',
        'Zphisher': 'https://github.com/htr-tech/zphisher.git',
        'BlackPhish': 'https://github.com/iinc0gnit0/BlackPhish.git',
        'PhisherMan': 'https://github.com/FDX100/Phisher-Man.git',
        'PyPhisher': 'https://github.com/KasRoudra/PyPhisher.git',
        'ShellPhish': 'https://github.com/thelinuxchoice/shellphish.git',
        'AnonPhisher': 'https://github.com/ExpertAnonymous/AnonPhisher.git',
        'nexphisher': 'https://github.com/htr-tech/nexphisher.git',
        'phishcatch': 'https://github.com/Stephin-Franklin/PhishCatch.git',
        'phishbuster': 'https://github.com/ShantanuKumar/PhishBuster.git',
        'phishx': 'https://github.com/TechnicalMujeeb/PhishX.git',
        'phishious': 'https://github.com/Viralmaniar/Phishious.git',
        'artphish': 'https://github.com/rajkumardusad/ArtPhish.git',
        'phishytics': 'https://github.com/surya-dev-singh/Phishytics.git',
        'phishmon': 'https://github.com/JasonJerry/PhishMon.git',
        'phishi': 'https://github.com/An0nUD4Y/Phishi.git',
        'phishlulz': 'https://github.com/cyberkallan/PhishLulz.git',
        'phishfleet': 'https://github.com/PhishFleet/PhishFleet.git',
        'phishytics': 'https://github.com/surya-dev-singh/Phishytics.git',
        'ngrok': 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip',
        'serveo': 'https://serveo.net/',
        'localtunnel': 'npm install -g localtunnel',
        'cloudflared': 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64',
        'bore': 'https://github.com/ekzhang/bore.git',
        'chisel': 'https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz',
        'rathole': 'https://github.com/rapiz1/rathole/releases/download/v0.4.4/rathole-x86_64-unknown-linux-musl.tar.gz',
        'inlets': 'https://github.com/inlets/inlets-pro/releases/download/0.9.3/inlets-pro'
    }

    for nome, url in ferramentas.items():
        if not os.path.exists(nome):
            print(f"{colors.YELLOW}[*] Baixando {nome}...{colors.END}")
            try:
                if 'git' in url:
                    subprocess.run(['git', 'clone', url], check=True)
                elif 'npm' in url:
                    subprocess.run(url.split(), check=True)
                else:
                    subprocess.run(['wget', url, '-O', f'{nome}.zip'], check=True)
                    subprocess.run(['unzip', f'{nome}.zip'], check=True)
                    os.remove(f'{nome}.zip')
                print(f"{colors.GREEN}[+] {nome} instalado com sucesso!{colors.END}")
            except Exception as e:
                print(f"{colors.RED}[-] Erro ao instalar {nome}: {str(e)}{colors.END}")

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
        
        if escolha == '1':
            executar_ferramenta('SocialFish')
        elif escolha == '2':
            executar_ferramenta('HiddenEye')
        elif escolha == '3':
            executar_ferramenta('Zphisher')
        elif escolha == '4':
            executar_ferramenta('BlackPhish')
        elif escolha == '5':
            executar_ferramenta('PyPhisher')
        elif escolha == '6':
            executar_ferramenta('ShellPhish')
        elif escolha == '7':
            executar_ferramenta('nexphisher')
        elif escolha == '8':
            executar_ferramenta('AnonPhisher')
        elif escolha == '9':
            executar_ferramenta('Phishious')
        elif escolha == '10':
            executar_ferramenta('ArtPhish')
        elif escolha == '11':
            executar_ferramenta('PhishFleet')
        elif escolha == '12':
            executar_ferramenta('PhishMon')
        elif escolha == '13':
            return
        else:
            print(f"\n{colors.RED}[-] Opção inválida! Tente novamente.{colors.END}")
            time.sleep(1)

def menu_tuneis():
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
        
        if escolha == '1':
            executar_tunel('ngrok')
        elif escolha == '2':
            executar_tunel('serveo')
        elif escolha == '3':
            executar_tunel('localtunnel')
        elif escolha == '4':
            executar_tunel('cloudflared')
        elif escolha == '5':
            executar_tunel('bore')
        elif escolha == '6':
            executar_tunel('chisel')
        elif escolha == '7':
            executar_tunel('rathole')
        elif escolha == '8':
            executar_tunel('inlets')
        elif escolha == '9':
            return
        else:
            print(f"\n{colors.RED}[-] Opção inválida! Tente novamente.{colors.END}")
            time.sleep(1)

def executar_ferramenta(nome):
    try:
        print(f"\n{colors.YELLOW}[*] Iniciando {nome}...{colors.END}")
        
        if nome == 'SocialFish':
            os.chdir('SocialFish')
            subprocess.run(['python3', 'SocialFish.py'], check=True)
        elif nome == 'HiddenEye':
            os.chdir('HiddenEye')
            subprocess.run(['python3', 'HiddenEye.py'], check=True)
        elif nome == 'Zphisher':
            os.chdir('zphisher')
            subprocess.run(['bash', 'zphisher.sh'], check=True)
        elif nome == 'BlackPhish':
            os.chdir('BlackPhish')
            subprocess.run(['python3', 'blackphish.py'], check=True)
        elif nome == 'PyPhisher':
            os.chdir('PyPhisher')
            subprocess.run(['python3', 'pyphisher.py'], check=True)
        elif nome == 'ShellPhish':
            os.chdir('shellphish')
            subprocess.run(['bash', 'shellphish.sh'], check=True)
        elif nome == 'nexphisher':
            os.chdir('nexphisher')
            subprocess.run(['bash', 'nexphisher.sh'], check=True)
        elif nome == 'AnonPhisher':
            os.chdir('AnonPhisher')
            subprocess.run(['python3', 'AnonPhisher.py'], check=True)
        elif nome == 'Phishious':
            os.chdir('Phishious')
            subprocess.run(['python3', 'phishious.py'], check=True)
        elif nome == 'ArtPhish':
            os.chdir('ArtPhish')
            subprocess.run(['python3', 'artphish.py'], check=True)
        elif nome == 'PhishFleet':
            os.chdir('PhishFleet')
            subprocess.run(['python3', 'phishfleet.py'], check=True)
        elif nome == 'PhishMon':
            os.chdir('PhishMon')
            subprocess.run(['python3', 'phishmon.py'], check=True)
            
        os.chdir('..')
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao executar {nome}: {str(e)}{colors.END}")
        time.sleep(2)

def executar_tunel(nome):
    try:
        print(f"\n{colors.YELLOW}[*] Iniciando {nome}...{colors.END}")
        
        if nome == 'ngrok':
            if not os.path.exists('ngrok'):
                print(f"{colors.RED}[-] Ngrok não encontrado. Baixe primeiro.{colors.END}")
                time.sleep(2)
                return
            porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
            subprocess.run(['./ngrok', 'http', porta], check=True)
            
        elif nome == 'serveo':
            porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
            subprocess.run(['ssh', '-R', '80:localhost:' + porta, 'serveo.net'], check=True)
            
        elif nome == 'localtunnel':
            porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
            subprocess.run(['lt', '--port', porta], check=True)
            
        elif nome == 'cloudflared':
            if not os.path.exists('cloudflared'):
                print(f"{colors.RED}[-] Cloudflared não encontrado. Baixe primeiro.{colors.END}")
                time.sleep(2)
                return
            porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
            subprocess.run(['./cloudflared', 'tunnel', '--url', 'http://localhost:' + porta], check=True)
            
        elif nome == 'bore':
            os.chdir('bore')
            porta = input(f"{colors.YELLOW}[?] Digite a porta para o túnel (ex: 8080): {colors.END}")
            subprocess.run(['cargo', 'run', '--', '--port', porta], check=True)
            os.chdir('..')
            
        elif nome == 'chisel':
            if not os.path.exists('chisel'):
                print(f"{colors.RED}[-] Chisel não encontrado. Baixe primeiro.{colors.END}")
                time.sleep(2)
                return
            modo = input(f"{colors.YELLOW}[?] Modo (server/client): {colors.END}")
            if modo == 'server':
                subprocess.run(['./chisel', 'server', '--port', '8080'], check=True)
            else:
                server = input(f"{colors.YELLOW}[?] Endereço do servidor (ex: 1.2.3.4:8080): {colors.END}")
                porta = input(f"{colors.YELLOW}[?] Porta local para encaminhar (ex: 8080): {colors.END}")
                subprocess.run(['./chisel', 'client', server, porta + ':localhost:' + porta], check=True)
                
        elif nome == 'rathole':
            if not os.path.exists('rathole'):
                print(f"{colors.RED}[-] Rathole não encontrado. Baixe primeiro.{colors.END}")
                time.sleep(2)
                return
            config = input(f"{colors.YELLOW}[?] Caminho para o arquivo de configuração: {colors.END}")
            subprocess.run(['./rathole', config], check=True)
            
        elif nome == 'inlets':
            if not os.path.exists('inlets'):
                print(f"{colors.RED}[-] Inlets não encontrado. Baixe primeiro.{colors.END}")
                time.sleep(2)
                return
            token = input(f"{colors.YELLOW}[?] Token de autenticação: {colors.END}")
            subprocess.run(['./inlets', 'server', '--token', token], check=True)
            
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao executar {nome}: {str(e)}{colors.END}")
        time.sleep(2)
def main():
    criar_diretorio()
    instalar_ferramentas()
    menu_principal()

if __name__ == '__main__':
    main()
