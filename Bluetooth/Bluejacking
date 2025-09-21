import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from bluetooth import *

class BluejackingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Bluejacking Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variáveis
        self.devices = []
        self.selected_device = None
        self.is_scanning = False
        
        # Configurar estilo
        self.setup_style()
        
        # Criar interface
        self.setup_ui()
        
    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configurar cores
        self.root.configure(bg='#2c3e50')
        style.configure('Title.TLabel', background='#2c3e50', foreground='white', font=('Arial', 16, 'bold'))
        style.configure('Subtitle.TLabel', background='#2c3e50', foreground='#ecf0f1', font=('Arial', 10))
        style.configure('Action.TButton', font=('Arial', 10, 'bold'), background='#3498db', foreground='white')
        style.configure('Listbox.TFrame', background='#34495e')
        style.configure('Device.TLabel', background='#34495e', foreground='white')
        
    def setup_ui(self):
        # Banner superior
        banner_frame = ttk.Frame(self.root, style='Title.TFrame')
        banner_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(banner_frame, text="Bluejacking Tool", style='Title.TLabel')
        title_label.pack(pady=5)
        
        subtitle_label = ttk.Label(banner_frame, 
                                  text="Ferramenta para envio de mensagens via Bluetooth (Bluejacking)", 
                                  style='Subtitle.TLabel')
        subtitle_label.pack(pady=5)
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Painel esquerdo - Lista de dispositivos
        left_panel = ttk.Frame(main_frame, style='Listbox.TFrame')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        ttk.Label(left_panel, text="Dispositivos Bluetooth Detectados", style='Device.TLabel').pack(pady=5)
        
        # Lista de dispositivos
        self.device_listbox = tk.Listbox(left_panel, bg='#2c3e50', fg='white', selectbackground='#3498db')
        self.device_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.device_listbox.bind('<<ListboxSelect>>', self.on_device_select)
        
        # Botões de ação
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Escanear Dispositivos", 
                  command=self.start_scanning, style='Action.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(button_frame, text="Parar Escaneamento", 
                  command=self.stop_scanning, style='Action.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Painel direito - Detalhes e envio de mensagem
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Informações do dispositivo
        info_frame = ttk.LabelFrame(right_panel, text="Informações do Dispositivo")
        info_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.device_info = scrolledtext.ScrolledText(info_frame, height=8, bg='#ecf0f1')
        self.device_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.device_info.config(state=tk.DISABLED)
        
        # Área de mensagem
        msg_frame = ttk.LabelFrame(right_panel, text="Enviar Mensagem")
        msg_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(msg_frame, text="Mensagem:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.message_text = scrolledtext.ScrolledText(msg_frame, height=6, bg='#ecf0f1')
        self.message_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Banner de advertência
        warning_frame = ttk.Frame(msg_frame)
        warning_frame.pack(fill=tk.X, padx=5, pady=5)
        
        warning_label = ttk.Label(warning_frame, 
                                 text="AVISO: Bluejacking é apenas para fins educacionais. \nNão use esta ferramenta para atividades maliciosas.",
                                 foreground='red', font=('Arial', 8, 'bold'), justify=tk.CENTER)
        warning_label.pack()
        
        ttk.Button(msg_frame, text="Enviar Mensagem", 
                  command=self.send_message, style='Action.TButton').pack(pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Pronto para escanear dispositivos")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def on_device_select(self, event):
        selection = self.device_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_device = self.devices[index]
            self.show_device_info()
            
    def show_device_info(self):
        self.device_info.config(state=tk.NORMAL)
        self.device_info.delete(1.0, tk.END)
        
        if self.selected_device:
            info = f"Endereço: {self.selected_device[0]}\n"
            info += f"Nome: {self.selected_device[1]}\n"
            
            # Tentar obter mais informações do dispositivo
            try:
                services = find_service(address=self.selected_device[0])
                info += f"\nServiços encontrados: {len(services)}\n"
                
                for i, service in enumerate(services[:3]):  # Mostrar apenas os primeiros 3 serviços
                    info += f"  Serviço {i+1}: {service['name']} ({service['protocol']})\n"
                
                if len(services) > 3:
                    info += f"  ... e mais {len(services) - 3} serviços\n"
                    
            except Exception as e:
                info += f"\nErro ao buscar serviços: {str(e)}\n"
                
            self.device_info.insert(tk.END, info)
        
        self.device_info.config(state=tk.DISABLED)
            
    def start_scanning(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.status_var.set("Escaneando dispositivos Bluetooth...")
            self.device_listbox.delete(0, tk.END)
            self.devices = []
            
            # Executar escaneamento em thread separada
            scan_thread = threading.Thread(target=self.scan_devices)
            scan_thread.daemon = True
            scan_thread.start()
            
    def stop_scanning(self):
        self.is_scanning = False
        self.status_var.set("Escaneamento interrompido")
        
    def scan_devices(self):
        try:
            while self.is_scanning:
                self.status_var.set("Procurando dispositivos Bluetooth...")
                
                # Descobrir dispositivos próximos
                nearby_devices = discover_devices(lookup_names=True, duration=8, flush_cache=True)
                
                # Atualizar lista de dispositivos
                for addr, name in nearby_devices:
                    if (addr, name) not in self.devices:
                        self.devices.append((addr, name))
                        self.root.after(0, self.update_device_list, addr, name)
                
                self.status_var.set(f"Encontrados {len(nearby_devices)} dispositivos. Escaneando...")
                time.sleep(2)
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Erro durante o escaneamento: {str(e)}"))
            self.is_scanning = False
            self.status_var.set("Erro durante o escaneamento")
            
    def update_device_list(self, addr, name):
        self.device_listbox.insert(tk.END, f"{name} ({addr})")
        
    def send_message(self):
        if not self.selected_device:
            messagebox.showwarning("Aviso", "Selecione um dispositivo primeiro!")
            return
            
        message = self.message_text.get(1.0, tk.END).strip()
        if not message:
            messagebox.showwarning("Aviso", "Digite uma mensagem para enviar!")
            return
            
        # Tentar enviar a mensagem
        try:
            # Bluejacking geralmente usa o serviço OBEX Object Push
            port = 0  # O bluejacking tradicional usa o canal 0 do RFCOMM
            
            # Criar socket Bluetooth
            sock = BluetoothSocket(RFCOMM)
            sock.connect((self.selected_device[0], port))
            
            # Enviar mensagem (formato vCard para bluejacking)
            vcard_message = f"BEGIN:VCARD\nVERSION:2.1\nN:;{message};;;\nEND:VCARD"
            sock.send(vcard_message)
            sock.close()
            
            messagebox.showinfo("Sucesso", f"Mensagem enviada para {self.selected_device[1]}!")
            self.status_var.set(f"Mensagem enviada para {self.selected_device[1]}")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao enviar mensagem: {str(e)}")
            self.status_var.set("Erro ao enviar mensagem")

if __name__ == "__main__":
    root = tk.Tk()
    app = BluejackingTool(root)
    root.mainloop()
