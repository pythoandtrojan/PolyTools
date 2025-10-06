#!/usr/bin/env python3
"""
PAINEL TERMUX API DASHBOARD
Script bonitão para visualizar todas as funções do Termux API
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
import threading

class TermuxDashboard:
    def __init__(self):
        self.running = True
        self.setup_colors()
        
    def setup_colors(self):
        """Configura cores para terminal"""
        self.COLORS = {
            'RED': '\033[91m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'BLUE': '\033[94m',
            'PURPLE': '\033[95m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'BOLD': '\033[1m',
            'UNDERLINE': '\033[4m',
            'END': '\033[0m'
        }
    
    def color_text(self, text, color):
        """Aplica cor ao texto"""
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['END']}"
    
    def run_command(self, cmd):
        """Executa comando e retorna resultado"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else f"Erro: {result.stderr}"
        except Exception as e:
            return f"Erro: {str(e)}"
    
    def get_battery_info(self):
        """Obtém informações da bateria"""
        try:
            result = self.run_command("termux-battery-status")
            if result and not result.startswith("Erro"):
                battery_data = json.loads(result)
                percentage = battery_data.get('percentage', 'N/A')
                status = battery_data.get('status', 'N/A')
                health = battery_data.get('health', 'N/A')
                temperature = battery_data.get('temperature', 'N/A')
                
                # Emoji baseado na carga
                if percentage >= 80: emoji = "🔋"
                elif percentage >= 40: emoji = "🔋"
                else: emoji = "🪫"
                
                return {
                    'percentage': percentage,
                    'status': status,
                    'health': health,
                    'temperature': temperature,
                    'emoji': emoji
                }
        except:
            pass
        return None
    
    def get_location_info(self):
        """Obtém informações de localização"""
        try:
            result = self.run_command("termux-location")
            if result and not result.startswith("Erro"):
                loc_data = json.loads(result)
                latitude = loc_data.get('latitude', 'N/A')
                longitude = loc_data.get('longitude', 'N/A')
                accuracy = loc_data.get('accuracy', 'N/A')
                
                return {
                    'latitude': latitude,
                    'longitude': longitude,
                    'accuracy': accuracy,
                    'emoji': "📍"
                }
        except:
            pass
        return None
    
    def get_sensor_data(self):
        """Obtém dados dos sensores"""
        sensors = []
        for sensor in ['accelerometer', 'gyroscope', 'light', 'proximity']:
            try:
                result = self.run_command(f"termux-sensor -s {sensor} -n 1")
                if result and not result.startswith("Erro"):
                    sensors.append({
                        'name': sensor,
                        'emoji': self.get_sensor_emoji(sensor),
                        'data': result[:50] + "..." if len(result) > 50 else result
                    })
            except:
                pass
        return sensors
    
    def get_sensor_emoji(self, sensor_name):
        """Retorna emoji para cada sensor"""
        emoji_map = {
            'accelerometer': '📱',
            'gyroscope': '🔄',
            'light': '💡',
            'proximity': '👆',
            'magnetic': '🧭',
            'pressure': '📊'
        }
        return emoji_map.get(sensor_name, '📡')
    
    def get_device_info(self):
        """Obtém informações do dispositivo"""
        try:
            result = self.run_command("termux-telephony-deviceinfo")
            if result and not result.startswith("Erro"):
                device_data = json.loads(result)
                return {
                    'device_id': device_data.get('device_id', 'N/A'),
                    'software_version': device_data.get('software_version', 'N/A'),
                    'phone_count': device_data.get('phone_count', 'N/A'),
                    'emoji': '📱'
                }
        except:
            pass
        return None
    
    def get_storage_info(self):
        """Obtém informações de armazenamento"""
        try:
            result = self.run_command("termux-storage-info")
            if result and not result.startswith("Erro"):
                storage_data = json.loads(result)
                external_available = storage_data.get('external_available', 'N/A')
                external_total = storage_data.get('external_total', 'N/A')
                
                if external_total != 'N/A' and external_available != 'N/A':
                    used = (external_total - external_available) / (1024**3)  # GB
                    total = external_total / (1024**3)
                    percent_used = (used / total) * 100
                else:
                    used = total = percent_used = 'N/A'
                
                return {
                    'used_gb': f"{used:.1f}" if used != 'N/A' else 'N/A',
                    'total_gb': f"{total:.1f}" if total != 'N/A' else 'N/A',
                    'percent_used': f"{percent_used:.1f}" if percent_used != 'N/A' else 'N/A',
                    'emoji': '💾'
                }
        except:
            pass
        return None
    
    def create_box(self, title, content, color='CYAN', width=35):
        """Cria uma caixa bonita com conteúdo"""
        border = "╔" + "═" * (width - 2) + "╗"
        bottom_border = "╚" + "═" * (width - 2) + "╝"
        
        lines = [border]
        lines.append(f"║ {self.color_text(title.center(width-4), color)} ║")
        lines.append("╟" + "─" * (width - 2) + "╢")
        
        for line in content:
            if len(line) > width - 4:
                line = line[:width-7] + "..."
            lines.append(f"║ {line.ljust(width-4)} ║")
        
        lines.append(bottom_border)
        return "\n".join(lines)
    
    def show_quick_actions(self):
        """Mostra ações rápidas disponíveis"""
        actions = [
            "1. 📸 Tirar Foto",
            "2. 🎤 Gravar Áudio (10s)",
            "3. 🔊 Falar Texto",
            "4. 📍 Compartilhar Localização",
            "5. 🔔 Testar Notificação",
            "6. 📱 Vibrar",
            "Q. Sair"
        ]
        
        box = self.create_box("🚀 AÇÕES RÁPIDAS", actions, 'PURPLE', 35)
        print(box)
    
    def execute_quick_action(self, choice):
        """Executa ação rápbaseada na escolha"""
        actions = {
            '1': lambda: self.run_command("termux-camera-photo -c 0 foto_$(date +%s).jpg"),
            '2': lambda: self.run_command("termux-microphone-record -l 10 audio_$(date +%s).aac"),
            '3': lambda: self.run_command('termux-tts-speak "Teste do painel Termux"'),
            '4': lambda: self.run_command("termux-location > localizacao_$(date +%s).json"),
            '5': lambda: self.run_command('termux-notification --title "Painel Termux" --content "Funcionando!"'),
            '6': lambda: self.run_command("termux-vibrate -d 500")
        }
        
        if choice in actions:
            result = actions[choice]()
            print(self.color_text(f"Ação executada: {result}", "GREEN"))
            time.sleep(1)
    
    def clear_screen(self):
        """Limpa a tela"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def display_header(self):
        """Mostra cabeçalho bonito"""
        header = f"""
{self.color_text('╔══════════════════════════════════════╗', 'CYAN')}
{self.color_text('║           🚀 TERMUX API DASHBOARD    ║', 'CYAN')}
{self.color_text('║            📱 Painel de Controle     ║', 'CYAN')}
{self.color_text('╚══════════════════════════════════════╝', 'CYAN')}
{self.color_text(f'📅 {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 'YELLOW')}
"""
        print(header)
    
    def display_dashboard(self):
        """Exibe o painel principal"""
        self.clear_screen()
        self.display_header()
        
        # Informações em tempo real
        boxes = []
        
        # Bateria
        battery = self.get_battery_info()
        if battery:
            bat_content = [
                f"{battery['emoji']} Carga: {battery['percentage']}%",
                f"📊 Status: {battery['status']}",
                f"❤️ Saúde: {battery['health']}",
                f"🌡️ Temp: {battery['temperature']}°C"
            ]
            boxes.append(self.create_box("🔋 BATERIA", bat_content, 'GREEN'))
        
        # Localização
        location = self.get_location_info()
        if location:
            loc_content = [
                f"📍 Lat: {location['latitude']:.4f}",
                f"📍 Lon: {location['longitude']:.4f}",
                f"🎯 Precisão: {location['accuracy']}m"
            ]
            boxes.append(self.create_box("🌍 LOCALIZAÇÃO", loc_content, 'BLUE'))
        
        # Dispositivo
        device = self.get_device_info()
        if device:
            dev_content = [
                f"📱 ID: {device['device_id'][:15]}...",
                f"⚙️ SW: {device['software_version']}",
                f"📞 Chips: {device['phone_count']}"
            ]
            boxes.append(self.create_box("📟 DISPOSITIVO", dev_content, 'YELLOW'))
        
        # Armazenamento
        storage = self.get_storage_info()
        if storage:
            stor_content = [
                f"💾 Usado: {storage['used_gb']}GB",
                f"💾 Total: {storage['total_gb']}GB",
                f"📊 Uso: {storage['percent_used']}%"
            ]
            boxes.append(self.create_box("💾 ARMAZENAMENTO", stor_content, 'PURPLE'))
        
        # Sensores
        sensors = self.get_sensor_data()
        if sensors:
            sensor_content = []
            for sensor in sensors[:3]:  # Mostra apenas 3 sensores
                sensor_content.append(f"{sensor['emoji']} {sensor['name']}: {sensor['data'][:20]}...")
            boxes.append(self.create_box("📡 SENSORES", sensor_content, 'RED'))
        
        # Exibe caixas em grid 2x2
        for i in range(0, len(boxes), 2):
            row_boxes = boxes[i:i+2]
            row_lines = []
            
            # Divide cada caixa em linhas
            box_lines = [box.split('\n') for box in row_boxes]
            max_lines = max(len(lines) for lines in box_lines)
            
            # Preenche com linhas vazias se necessário
            for lines in box_lines:
                while len(lines) < max_lines:
                    lines.append(" " * 35)
            
            # Combina as caixas lado a lado
            for j in range(max_lines):
                line = "  ".join(box_lines[k][j] for k in range(len(row_boxes)))
                row_lines.append(line)
            
            print("\n".join(row_lines))
            print()
        
        # Ações rápidas
        self.show_quick_actions()
    
    def run(self):
        """Loop principal do dashboard"""
        try:
            while self.running:
                self.display_dashboard()
                
                print(self.color_text("\n🎯 Selecione uma ação (1-6) ou Q para sair: ", "BOLD"))
                choice = input().strip().lower()
                
                if choice == 'q':
                    self.running = False
                    print(self.color_text("\n👋 Saindo do Painel Termux...", "YELLOW"))
                elif choice in ['1', '2', '3', '4', '5', '6']:
                    self.execute_quick_action(choice)
                else:
                    print(self.color_text("❌ Opção inválida! Pressione Enter para continuar...", "RED"))
                    input()
        
        except KeyboardInterrupt:
            print(self.color_text("\n\n👋 Painel finalizado pelo usuário!", "YELLOW"))
        except Exception as e:
            print(self.color_text(f"\n❌ Erro: {str(e)}", "RED"))

def main():
    """Função principal"""
    print("🔍 Verificando Termux API...")
    
    # Verifica se Termux API está instalado
    try:
        result = subprocess.run(["termux-battery-status"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print("❌ Termux API não está instalado ou configurado!")
            print("💡 Instale com: pkg install termux-api")
            print("💡 E instale o app Termux:API do Google Play")
            return
    except:
        print("❌ Termux API não está disponível!")
        return
    
    print("✅ Termux API detectado! Iniciando painel...")
    time.sleep(2)
    
    # Inicia o dashboard
    dashboard = TermuxDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()
