#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import time
import shutil
import requests
from datetime import datetime

class cores:
    VERMELHO = '\033[91m'
    VERDE = '\033[92m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    ROXO = '\033[95m'
    CIANO = '\033[96m'
    BRANCO = '\033[97m'
    FIM = '\033[0m'
    NEGRITO = '\033[1m'
    SUBLINHADO = '\033[4m'

# Configurações globais
PASTA_TOOLS = "FerramentasPhishing"
ARQUIVO_LOG = "registro.log"
TERMUX = True if 'com.termux' in os.environ.get('PREFIX', '') else False

def registrar_log(mensagem):
    """Registra mensagens no arquivo de log"""
    data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ARQUIVO_LOG, "a", encoding='utf-8') as f:
        f.write(f"[{data_hora}] {mensagem}\n")

def verificar_dependencias():
    """Verifica e instala dependências básicas"""
    dependencias = {
        'python3': 'pkg install python -y',
        'pip': 'pkg install python-pip -y',
        'git': 'pkg install git -y',
        'wget': 'pkg install wget -y',
        'unzip': 'pkg install unzip -y',
        'php': 'pkg install php -y',
        'ssh': 'pkg install openssh -y',
        'npm': 'pkg install nodejs -y',
        'cargo': 'pkg install rust -y'
    }
    
    print(f"\n{cores.AMARELO}[*] Verificando dependências do sistema...{cores.FIM}")
    
    for dep, cmd in dependencias.items():
        try:
            subprocess.run(['which', dep], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{cores.VERDE}[✓] {dep} já instalado{cores.FIM}")
        except:
            print(f"{cores.AMARELO}[!] Instalando {dep}...{cores.FIM}")
            try:
                subprocess.run(cmd.split(), check=True)
                print(f"{cores.VERDE}[✓] {dep} instalado com sucesso{cores.FIM}")
            except subprocess.CalledProcessError:
                print(f"{cores.VERMELHO}[✗] Falha ao instalar {dep}{cores.FIM}")
                return False
    return True

def criar_diretorio():
    """Cria o diretório principal"""
    if not os.path.exists(PASTA_TOOLS):
        os.makedirs(PASTA_TOOLS)
        print(f"{cores.VERDE}[+] Diretório '{PASTA_TOOLS}' criado com sucesso!{cores.FIM}")
    os.chdir(PASTA_TOOLS)
    return os.path.abspath(PASTA_TOOLS)

def verificar_ferramenta(nome):
    """Verifica se uma ferramenta está instalada corretamente"""
    # Ferramentas executáveis diretas
    if nome in ['ngrok', 'cloudflared', 'chisel', 'rathole', 'inlets']:
        return os.path.exists(nome) and os.access(nome, os.X_OK)
    
    # Ferramentas em repositórios Git
    if os.path.isdir(nome):
        # Verifica arquivos essenciais para cada ferramenta
        if nome == 'SocialFish':
            return os.path.exists(os.path.join(nome, 'SocialFish.py'))
        elif nome == 'HiddenEye':
            return os.path.exists(os.path.join(nome, 'HiddenEye.py'))
        elif nome == 'Zphisher':
            return os.path.exists(os.path.join(nome, 'zphisher.sh'))
        elif nome == 'BlackPhish':
            return os.path.exists(os.path.join(nome, 'blackphish.py'))
        elif nome == 'PyPhisher':
            return os.path.exists(os.path.join(nome, 'pyphisher.py'))
        return True
    
    # Ferramentas instaladas via npm/pip
    if nome == 'serveo':
        try:
            subprocess.run(['ssh', '-V'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except:
            return False
    elif nome == 'localtunnel':
        try:
            subprocess.run(['lt', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except:
            return False
    
    return False

def instalar_dependencias(nome):
    """Instala dependências específicas para cada ferramenta"""
    print(f"{cores.AMARELO}[*] Verificando dependências para {nome}...{cores.FIM}")
    
    try:
        if os.path.isdir(nome):
            # Instala dependências Python
            req_file = os.path.join(nome, 'requirements.txt')
            if os.path.exists(req_file):
                print(f"{cores.AMARELO}[*] Instalando dependências Python...{cores.FIM}")
                subprocess.run(['pip3', 'install', '-r', req_file], check=True)
            
            # Dependências específicas
            if nome == 'HiddenEye':
                print(f"{cores.AMARELO}[*] Instalando dependências extras para HiddenEye...{cores.FIM}")
                subprocess.run(['pkg', 'install', 'php', 'openssh', '-y'], check=True)
            
            elif nome == 'SocialFish':
                print(f"{cores.AMARELO}[*] Instalando dependências extras para SocialFish...{cores.FIM}")
                subprocess.run(['pip3', 'install', 'requests', 'bs4'], check=True)
            
            elif nome == 'Zphisher':
                print(f"{cores.AMARELO}[*] Instalando dependências para Zphisher...{cores.FIM}")
                subprocess.run(['pkg', 'install', 'php', 'wget', 'git', 'unzip', '-y'], check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"{cores.VERMELHO}[-] Erro ao instalar dependências para {nome}: {e}{cores.FIM}")
        return False

def instalar_ferramenta(nome, url):
    """Instala uma ferramenta específica"""
    print(f"\n{cores.AMARELO}[*] Verificando {nome}...{cores.FIM}")
    
    if verificar_ferramenta(nome):
        print(f"{cores.VERDE}[+] {nome} já está instalado.{cores.FIM}")
        return True
    
    resposta = input(f"{cores.AMARELO}[?] {nome} não encontrado. Deseja instalar? (s/n): {cores.FIM}").strip().lower()
    
    if resposta != 's':
        print(f"{cores.AMARELO}[-] Instalação de {nome} cancelada.{cores.FIM}")
        return False
    
    print(f"{cores.AMARELO}[*] Baixando {nome}...{cores.FIM}")
    try:
        if 'git' in url:
            subprocess.run(['git', 'clone', url], check=True)
            print(f"{cores.VERDE}[+] {nome} instalado via Git!{cores.FIM}")
            instalar_dependencias(nome)
            return True
        elif 'npm' in url:
            subprocess.run(url.split(), check=True)
            print(f"{cores.VERDE}[+] {nome} instalado via npm!{cores.FIM}")
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
            
            # Configura permissões
            if nome in ['ngrok', 'cloudflared', 'chisel', 'rathole', 'inlets']:
                for root, dirs, files in os.walk('.'):
                    if nome in files:
                        os.chmod(os.path.join(root, nome), 0o755)
            
            print(f"{cores.VERDE}[+] {nome} instalado com sucesso!{cores.FIM}")
            return True
    except subprocess.CalledProcessError as e:
        print(f"{cores.VERMELHO}[-] Erro ao instalar {nome}: {e}{cores.FIM}")
    except Exception as e:
        print(f"{cores.VERMELHO}[-] Erro ao instalar {nome}: {str(e)}{cores.FIM}")
    
    return False

def executar_ferramenta(nome):
    """Executa uma ferramenta de phishing"""
    try:
        print(f"\n{cores.AMARELO}[*] Iniciando {nome}...{cores.FIM}")
        
        if not verificar_ferramenta(nome):
            print(f"{cores.VERMELHO}[-] {nome} não está instalado corretamente.{cores.FIM}")
            time.sleep(2)
            return
        
        if os.path.isdir(nome):
            os.chdir(nome)
        
        # Comandos específicos para cada ferramenta
        comandos = {
            'SocialFish': ['python3', 'SocialFish.py'],
            'HiddenEye': ['python3', 'HiddenEye.py'],
            'Zphisher': ['bash', 'zphisher.sh'],
            'BlackPhish': ['python3', 'blackphish.py'],
            'PyPhisher': ['python3', 'pyphisher.py'],
            'ShellPhish': ['bash', 'shellphish.sh'],
            'nexphisher': ['bash', 'nexphisher.sh'],
            'AnonPhisher': ['python3', 'AnonPhisher.py'],
            'Phishious': ['python3', 'phishious.py'],
            'ArtPhish': ['python3', 'artphish.py'],
            'PhishFleet': ['python3', 'phishfleet.py'],
            'PhishMon': ['python3', 'phishmon.py'],
            'Evilginx2': ['sudo', 'evilginx'],
            'Gophish': ['./gophish'],
            'KingPhisher': ['king-phisher'],
            'Modlishka': ['./modlishka']
        }
        
        if nome in comandos:
            subprocess.run(comandos[nome], check=True)
        else:
            print(f"{cores.VERMELHO}[-] Comando para {nome} não configurado.{cores.FIM}")
        
        if os.path.isdir(nome):
            os.chdir('..')
            
    except subprocess.CalledProcessError as e:
        print(f"{cores.VERMELHO}[-] Erro ao executar {nome}: {e}{cores.FIM}")
    except Exception as e:
        print(f"{cores.VERMELHO}[-] Erro ao executar {nome}: {str(e)}{cores.FIM}")
    finally:
        input(f"\n{cores.AMARELO}[!] Pressione Enter para continuar...{cores.FIM}")

def executar_tunel(nome):
    """Executa um túnel reverso"""
    try:
        print(f"\n{cores.AMARELO}[*] Preparando {nome}...{cores.FIM}")
        
        if not verificar_ferramenta(nome):
            print(f"{cores.VERMELHO}[-] {nome} não está instalado.{cores.FIM}")
            time.sleep(2)
            return
        
        porta = input(f"{cores.AMARELO}[?] Digite a porta para o túnel (ex: 8080): {cores.FIM}")
        
        # Comandos específicos para cada túnel
        if nome == 'ngrok':
            if not os.path.exists('./ngrok'):
                print(f"{cores.VERMELHO}[-] ngrok não encontrado.{cores.FIM}")
                return
            subprocess.run(['./ngrok', 'http', porta])
        elif nome == 'serveo':
            subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', '-R', '80:localhost:' + porta, 'serveo.net'])
        elif nome == 'localtunnel':
            subprocess.run(['lt', '--port', porta])
        elif nome == 'cloudflared':
            if not os.path.exists('./cloudflared'):
                print(f"{cores.VERMELHO}[-] cloudflared não encontrado.{cores.FIM}")
                return
            subprocess.run(['./cloudflared', 'tunnel', '--url', 'http://localhost:' + porta])
        elif nome == 'bore':
            if not os.path.exists('bore'):
                print(f"{cores.VERMELHO}[-] Diretório bore não encontrado.{cores.FIM}")
                return
            os.chdir('bore')
            subprocess.run(['cargo', 'run', '--', '--port', porta])
            os.chdir('..')
        elif nome == 'chisel':
            if not os.path.exists('./chisel'):
                print(f"{cores.VERMELHO}[-] chisel não encontrado.{cores.FIM}")
                return
            modo = input(f"{cores.AMARELO}[?] Modo (server/client): {cores.FIM}")
            if modo == 'server':
                subprocess.run(['./chisel', 'server', '--port', '8080'])
            else:
                server = input(f"{cores.AMARELO}[?] Endereço do servidor (ex: 1.2.3.4:8080): {cores.FIM}")
                subprocess.run(['./chisel', 'client', server, porta + ':localhost:' + porta])
        elif nome == 'rathole':
            if not os.path.exists('./rathole'):
                print(f"{cores.VERMELHO}[-] rathole não encontrado.{cores.FIM}")
                return
            config = input(f"{cores.AMARELO}[?] Caminho para o arquivo de configuração: {cores.FIM}")
            subprocess.run(['./rathole', config])
        elif nome == 'inlets':
            if not os.path.exists('./inlets'):
                print(f"{cores.VERMELHO}[-] inlets não encontrado.{cores.FIM}")
                return
            token = input(f"{cores.AMARELO}[?] Token de autenticação: {cores.FIM}")
            subprocess.run(['./inlets', 'server', '--token', token])
            
    except KeyboardInterrupt:
        print(f"\n{cores.AMARELO}[!] Túnel interrompido pelo usuário.{cores.FIM}")
    except Exception as e:
        print(f"{cores.VERMELHO}[-] Erro ao executar {nome}: {str(e)}{cores.FIM}")
    finally:
        input(f"\n{cores.AMARELO}[!] Pressione Enter para continuar...{cores.FIM}")

def menu_principal():
    """Exibe o menu principal"""
    while True:
        os.system('clear')
        print(f"""{cores.AZUL}
  ____  _     _     _       _     _____ _     _     _____ _____ ____  
 |  _ \| |__ (_)___| |__   (_)___|  ___| |__ (_)___|  ___| ____/ ___| 
 | |_) | '_ \| / __| '_ \  | / __| |_  | '_ \| / __| |_  |  _| \___ \ 
 |  __/| | | | \__ \ | | | | \__ \  _| | | | | \__ \  _| | |___ ___) |
 |_|   |_| |_|_|___/_| |_| |_|___/_|   |_| |_|_|___/_|   |_____|____/ 
                                                                       
{cores.ROXO}╔══════════════════════════════════════════════════════════╗
║{cores.CIANO}           MENU PRINCIPAL - FERRAMENTAS DE PHISHING         {cores.ROXO}║
╠══════════════════════════════════════════════════════════╣
║ {cores.BRANCO}1. {cores.VERDE}Ferramentas de Phishing                          {cores.ROXO}║
║ {cores.BRANCO}2. {cores.VERDE}Túneis (Ngrok, Serveo, LocalTunnel, etc)         {cores.ROXO}║
║ {cores.BRANCO}3. {cores.VERMELHO}Sair                                            {cores.ROXO}║
╚══════════════════════════════════════════════════════════╝{cores.FIM}""")

        escolha = input(f"\n{cores.AMARELO}[?] Selecione uma opção: {cores.FIM}")
        
        if escolha == '1':
            menu_phishing()
        elif escolha == '2':
            menu_tuneis()
        elif escolha == '3':
            print(f"\n{cores.VERMELHO}[!] Saindo...{cores.FIM}")
            sys.exit()
        else:
            print(f"\n{cores.VERMELHO}[-] Opção inválida! Tente novamente.{cores.FIM}")
            time.sleep(1)

def menu_phishing():
    """Exibe o menu de ferramentas de phishing"""
    ferramentas = {
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
        '13': ('Evilginx2', 'https://github.com/kgretzky/evilginx2.git'),
        '14': ('Gophish', 'https://github.com/gophish/gophish.git'),
        '15': ('KingPhisher', 'https://github.com/securestate/king-phisher.git'),
        '16': ('Modlishka', 'https://github.com/drk1wi/Modlishka.git'),
        '17': ('Voltar', None)
    }

    while True:
        os.system('clear')
        print(f"""{cores.ROXO}
╔══════════════════════════════════════════════════════════╗
║{cores.CIANO}               FERRAMENTAS DE PHISHING               {cores.ROXO}║
╠══════════════════════════════════════════════════════════╣
║ {cores.BRANCO}1. {cores.VERDE}SocialFish                                {cores.ROXO}║
║ {cores.BRANCO}2. {cores.VERDE}HiddenEye                                 {cores.ROXO}║
║ {cores.BRANCO}3. {cores.VERDE}Zphisher                                  {cores.ROXO}║
║ {cores.BRANCO}4. {cores.VERDE}BlackPhish                                {cores.ROXO}║
║ {cores.BRANCO}5. {cores.VERDE}PyPhisher                                 {cores.ROXO}║
║ {cores.BRANCO}6. {cores.VERDE}ShellPhish                                {cores.ROXO}║
║ {cores.BRANCO}7. {cores.VERDE}nexphisher                                {cores.ROXO}║
║ {cores.BRANCO}8. {cores.VERDE}AnonPhisher                               {cores.ROXO}║
║ {cores.BRANCO}9. {cores.VERDE}Phishious                                 {cores.ROXO}║
║ {cores.BRANCO}10.{cores.VERDE}ArtPhish                                  {cores.ROXO}║
║ {cores.BRANCO}11.{cores.VERDE}PhishFleet                                {cores.ROXO}║
║ {cores.BRANCO}12.{cores.VERDE}PhishMon                                  {cores.ROXO}║
║ {cores.BRANCO}13.{cores.VERDE}Evilginx2                                 {cores.ROXO}║
║ {cores.BRANCO}14.{cores.VERDE}Gophish                                   {cores.ROXO}║
║ {cores.BRANCO}15.{cores.VERDE}KingPhisher                               {cores.ROXO}║
║ {cores.BRANCO}16.{cores.VERDE}Modlishka                                 {cores.ROXO}║
║ {cores.BRANCO}17.{cores.VERMELHO}Voltar ao Menu Principal               {cores.ROXO}║
╚══════════════════════════════════════════════════════════╝{cores.FIM}""")

        escolha = input(f"\n{cores.AMARELO}[?] Selecione uma ferramenta (1-17): {cores.FIM}")
        
        if escolha == '17':
            return
        elif escolha in ferramentas:
            nome, url = ferramentas[escolha]
            if nome == 'Voltar':
                return
            if instalar_ferramenta(nome, url):
                executar_ferramenta(nome)
        else:
            print(f"\n{cores.VERMELHO}[-] Opção inválida! Tente novamente.{cores.FIM}")
            time.sleep(1)

def menu_tuneis():
    """Exibe o menu de túneis reversos"""
    tuneis = {
        '1': ('ngrok', 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm64.zip' if TERMUX else 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip'),
        '2': ('serveo', 'https://serveo.net/'),
        '3': ('localtunnel', 'npm install -g localtunnel'),
        '4': ('cloudflared', 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64' if TERMUX else 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'),
        '5': ('bore', 'https://github.com/ekzhang/bore.git'),
        '6': ('chisel', 'https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_arm64.gz' if TERMUX else 'https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz'),
        '7': ('rathole', 'https://github.com/rapiz1/rathole/releases/download/v0.4.4/rathole-aarch64-unknown-linux-musl.tar.gz' if TERMUX else 'https://github.com/rapiz1/rathole/releases/download/v0.4.4/rathole-x86_64-unknown-linux-musl.tar.gz'),
        '8': ('inlets', 'https://github.com/inlets/inlets-pro/releases/download/0.9.3/inlets-pro-arm64' if TERMUX else 'https://github.com/inlets/inlets-pro/releases/download/0.9.3/inlets-pro'),
        '9': ('Voltar', None)
    }

    while True:
        os.system('clear')
        print(f"""{cores.ROXO}
╔══════════════════════════════════════════════════════════╗
║{cores.CIANO}                  FERRAMENTAS DE TÚNEL                 {cores.ROXO}║
╠══════════════════════════════════════════════════════════╣
║ {cores.BRANCO}1. {cores.VERDE}Ngrok                                      {cores.ROXO}║
║ {cores.BRANCO}2. {cores.VERDE}Serveo.net                                 {cores.ROXO}║
║ {cores.BRANCO}3. {cores.VERDE}LocalTunnel                                {cores.ROXO}║
║ {cores.BRANCO}4. {cores.VERDE}Cloudflared                                {cores.ROXO}║
║ {cores.BRANCO}5. {cores.VERDE}Bore                                       {cores.ROXO}║
║ {cores.BRANCO}6. {cores.VERDE}Chisel                                     {cores.ROXO}║
║ {cores.BRANCO}7. {cores.VERDE}Rathole                                    {cores.ROXO}║
║ {cores.BRANCO}8. {cores.VERDE}Inlets                                     {cores.ROXO}║
║ {cores.BRANCO}9. {cores.VERMELHO}Voltar ao Menu Principal               {cores.ROXO}║
╚══════════════════════════════════════════════════════════╝{cores.FIM}""")

        escolha = input(f"\n{cores.AMARELO}[?] Selecione um túnel (1-9): {cores.FIM}")
        
        if escolha == '9':
            return
        elif escolha in tuneis:
            nome, url = tuneis[escolha]
            if nome == 'Voltar':
                return
            if instalar_ferramenta(nome, url):
                executar_tunel(nome)
        else:
            print(f"\n{cores.VERMELHO}[-] Opção inválida! Tente novamente.{cores.FIM}")
            time.sleep(1)

def main():
    """Função principal"""
    try:
        print(f"{cores.AZUL}{cores.NEGRITO}\n[+] Iniciando Phishing Tools Manager para Termux{cores.FIM}")
        
        if not verificar_dependencias():
            print(f"{cores.VERMELHO}[-] Falha ao instalar dependências necessárias.{cores.FIM}")
            sys.exit(1)
            
        criar_diretorio()
        menu_principal()
        
    except KeyboardInterrupt:
        print(f"\n{cores.VERMELHO}[!] Programa interrompido pelo usuário.{cores.FIM}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{cores.VERMELHO}[!] Erro crítico: {str(e)}{cores.FIM}")
        registrar_log(f"Erro crítico: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
