#!/usr/bin/env python3
import os
import sys
import socket
import subprocess
import threading
import time
from time import sleep
import readline
import curses
from curses import wrapper
import random

# Sistema de Cores Avançado
class colors:
    # Cores básicas
    PINK = '\033[38;5;206m'
    CYAN = '\033[38;5;45m'
    DARK = '\033[38;5;238m'
    PURPLE = '\033[38;5;129m'
    GREEN = '\033[38;5;118m'
    RED = '\033[38;5;196m'
    ORANGE = '\033[38;5;208m'
    BLUE = '\033[38;5;33m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    # Elementos especiais
    CRANIO = f"{DARK}☠{END}"
    HEART = f"{PINK}♥{END}"
    FIRE = f"{RED}🔥{END}"
    EYE = f"{RED}♥{END}"
    MOUTH = f"{PURPLE}⨀{END}"
    
    # Gradientes
    @staticmethod
    def gradient(text, start_color, end_color):
        result = ""
        steps = len(text)
        for i, char in enumerate(text):
            r = start_color[0] + (end_color[0]-start_color[0])*i//steps
            g = start_color[1] + (end_color[1]-start_color[1])*i//steps
            b = start_color[2] + (end_color[2]-start_color[2])*i//steps
            result += f"\033[38;2;{r};{g};{b}m{char}"
        return result + colors.END

# Sistema de Animação Avançado
class Animator:
    @staticmethod
    def animate_banner(stdscr):
        curses.curs_set(0)
        stdscr.clear()
        
        # Configurações de cor
        curses.start_color()
        curses.init_pair(1, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
        
        banner = [
            "        .o oOOOOOOOo                                            OOOo",
            "        Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO",
            "        OboO...........OOo. .oOOOOOo.    OOOo.oOOOOOo..........OO",
            "        OOP.oOOOOOOOOOOO POOOOOOOOOOOo.    OOOOOOOOOOP,OOOOOOOOOOOB",
            "        OOOOO     OOOOOoOOOOOOOOOOO .adOOOOOOOOOoOOO     OOOOOo",
            "        .OOOO            OOOOOOOOOOOOOOOOOOOOOOO            OO",
            "        OOOOO                  OOOOOOOOOOOOOO                 oOO",
            "       oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.",
            "      oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO",
            "     OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO    OOOOOOOOOOOOOO.OOOOOOOOOOOOOO",
            "     OOOO       YOoOOOOMOIONODOO    .    OOROAOPOEOOOoOY     OOO",
            "        Y           OOOOOOOOOOOOOO. .oOOo. :OOOOOOOOOOO?         :",
            "        :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .",
            "        .            oOOP%OOOOOOOOoOOOOOOO?oOOOOO?OOOOOOo",
            "                      %o  OOOO%OOOO%%OOOOO%OOOOOO%OOO",
            "                          $  OOOOO OY  OOOOO  o             .",
            "        .                  .     OP          : o     ."
        ]
        
        # Posições dos olhos e boca (linha, coluna)
        eyes_pos = [(3, 20), (3, 25)]
        mouth_pos = [(4, 23)]
        
        # Animação
        for frame in range(30):
            stdscr.clear()
            
            # Desenha o banner
            for i, line in enumerate(banner):
                stdscr.addstr(i, 0, line, curses.color_pair(1))
            
            # Anima os olhos
            eye_char = random.choice(["⨀", "⩌", "◉", "⬤"]) if frame % 3 == 0 else "⨀"
            for y, x in eyes_pos:
                stdscr.addstr(y, x, eye_char, curses.color_pair(2)|curses.A_BOLD)
            
            # Anima a boca
            mouth_chars = ["⩗", "⩖", "⩊", "⩈"]
            mouth_char = mouth_chars[frame % len(mouth_chars)]
            for y, x in mouth_pos:
                stdscr.addstr(y, x, mouth_char, curses.color_pair(3)|curses.A_BOLD)
            
            # Efeito de brilho aleatório
            if frame % 5 == 0:
                for _ in range(3):
                    y, x = random.randint(0, len(banner)-1), random.randint(0, len(banner[0])-1)
                    stdscr.addstr(y, x, banner[y][x], curses.A_BLINK)
            
            stdscr.refresh()
            time.sleep(0.1)
        
        # Transição para o modo texto
        for i in range(10, 0, -1):
            stdscr.addstr(len(banner)+1, 0, f"Iniciando em {i}...", curses.color_pair(3))
            stdscr.refresh()
            time.sleep(0.5)
            stdscr.addstr(len(banner)+1, 0, " " * 20)

    @staticmethod
    def loading(stdscr, seconds=3):
        curses.curs_set(0)
        frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        start_time = time.time()
        
        while time.time() - start_time < seconds:
            for frame in frames:
                stdscr.addstr(0, 0, f"{frame} Processando...", curses.color_pair(2))
                stdscr.refresh()
                time.sleep(0.1)
        
        curses.curs_set(1)

# Sistema de Interface
class UI:
    themes = {
        'dark': {
            'text': '\033[38;5;250m',
            'prompt': '\033[38;5;129m',
            'banner': '\033[38;5;206m',
            'border': '\033[38;5;238m',
            'highlight': '\033[38;5;196m'
        },
        'kawaii': {
            'text': '\033[38;5;255m',
            'prompt': '\033[38;5;219m',
            'banner': '\033[38;5;213m',
            'border': '\033[38;5;219m',
            'highlight': '\033[38;5;207m'
        },
        'matrix': {
            'text': '\033[38;5;118m',
            'prompt': '\033[38;5;82m',
            'banner': '\033[38;5;46m',
            'border': '\033[38;5;22m',
            'highlight': '\033[38;5;154m'
        }
    }
    
    current_theme = 'dark'
    
    @classmethod
    def set_theme(cls, theme_name):
        if theme_name in cls.themes:
            cls.current_theme = theme_name
    
    @classmethod
    def color(cls, element):
        return cls.themes[cls.current_theme].get(element, '\033[0m')
    
    @staticmethod
    def clear():
        os.system('clear' if os.name != 'nt' else 'cls')
    
    @classmethod
    def dynamic_border(cls, text, length=60):
        border_char = '✧' if cls.current_theme == 'kawaii' else '═'
        border = border_char * (length // 2)
        return f"{cls.color('border')}{border} {cls.color('highlight')}{text} {cls.color('border')}{border}{colors.END}"

# Banner Interativo
def print_banner():
    UI.clear()
    
    if UI.current_theme == 'kawaii':
        banner = f"""
        {UI.color('banner')} (◕‿◕✿) {colors.PINK}Kawaii NetCat v4.0 {UI.color('highlight')}(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧
        {UI.color('text')}✧ Modo: {UI.color('highlight')}Fofinho Ultra Mega Power
        {UI.color('text')}✧ Comandos especiais: help, clear, theme
        {UI.dynamic_border(f"Conecte-se com amor {colors.HEART}")}
        """
    elif UI.current_theme == 'matrix':
        banner = f"""
        {UI.color('banner')} ╔═╗╔╦╗╔═╗╔╦╗  {colors.GREEN}Matrix Mode {UI.color('highlight')}v4.0
        {UI.color('text')} ╚═╗ ║ ╠═╣ ║   {UI.color('text')}Sistema de conexão segura
        {UI.color('highlight')} ╚═╝ ╩ ╩ ╩ ╩   {UI.color('text')}Nível de acesso: ROOT
        {UI.dynamic_border("Siga o coelho branco")}
        """
    else:  # Dark theme
        banner = f"""
        {UI.color('banner')}             .-~-.
            /  {colors.CRANIO}  \\
           |  .-.  |
            \\|  |/ 
             '--'
        {UI.dynamic_border(f"Dark NetCat {colors.CRANIO} v4.0")}
        {UI.color('text')}✧ Modo: {UI.color('highlight')}Sombras Ativadas
        {UI.color('text')}✧ Comandos especiais: help, clear, theme
        {UI.color('text')}✧ Pressione CTRL+D para limpar a tela
        {UI.dynamic_border("Entre se ousar")}
        """
    
    print(banner)

# Sistema de Comandos Especiais
class SpecialCommands:
    @staticmethod
    def handle(cmd, nc_instance):
        if cmd == "clear":
            UI.clear()
            print_banner()
            return True
        elif cmd.startswith("theme "):
            theme = cmd.split()[1]
            UI.set_theme(theme.lower())
            print(f"\n{UI.color('highlight')}✧ Tema alterado para {theme}{colors.END}\n")
            print_banner()
            return True
        elif cmd == "kawaii":
            UI.set_theme('kawaii')
            print(f"\n{colors.PINK}✧･ﾟ: * Modo Kawaii Ativado *:･ﾟ✧")
            print(f"{colors.HEART} {colors.CRANIO} {colors.HEART} Comandos fofos habilitados {colors.HEART} {colors.CRANIO} {colors.HEART}\n{colors.END}")
            print_banner()
            return True
        elif cmd == "malware":
            nc_instance.malware_mode = not nc_instance.malware_mode
            status = "ATIVADO" if nc_instance.malware_mode else "DESATIVADO"
            color = colors.RED if nc_instance.malware_mode else colors.GREEN
            print(f"\n{color}✧ Modo Malware {status} {colors.CRANIO}\n{colors.END}")
            return True
        elif cmd == "help":
            help_text = f"""
{UI.dynamic_border("Sistema de Ajuda")}
{UI.color('text')}Comandos disponíveis:
{UI.color('highlight')}help        {UI.color('text')}- Mostra esta mensagem
{UI.color('highlight')}clear       {UI.color('text')}- Limpa a tela
{UI.color('highlight')}theme <name>{UI.color('text')}- Muda o tema (dark, kawaii, matrix)
{UI.color('highlight')}kawaii      {UI.color('text')}- Ativa modo kawaii
{UI.color('highlight')}malware     {UI.color('text')}- Alterna modo malware
{UI.color('highlight')}exit        {UI.color('text')}- Sai do programa
{UI.dynamic_border("")}
            """
            print(help_text)
            return True
        return False

class KawaiiNetcat:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None
        self.malware_mode = False
        self.history = []
        self.setup_readline()

    def setup_readline(self):
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.completer)
        readline.set_history_length(100)

    def completer(self, text, state):
        options = [i for i in ['help', 'clear', 'kawaii', 'malware', 'exit', 'theme dark', 'theme kawaii', 'theme matrix'] if i.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def connect(self):
        try:
            wrapper(Animator.animate_banner)
            
            print(f"{UI.color('text')}Iniciando conexão com {self.ip}:{self.port}...")
            wrapper(lambda stdscr: Animator.loading(stdscr, 2))
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ip, self.port))
            
            print(f"\n{colors.GREEN}✧ Conexão estabelecida com {self.ip}:{self.port} {colors.HEART}{colors.END}\n")
            return True
        except Exception as e:
            print(f"\n{colors.RED}✧ Falha na conexão: {str(e)} {colors.CRANIO}{colors.END}")
            return False

    def send(self, data):
        try:
            self.sock.send(data.encode() + b'\n')
            return True
        except:
            return False

    def receive(self):
        try:
            data = self.sock.recv(4096).decode().strip()
            if not data:
                return None
            return data
        except:
            return None

    def execute(self, cmd):
        if SpecialCommands.handle(cmd, self):
            return ""

        if self.malware_mode:
            result = self.execute_malware(cmd)
            if result:
                return result

        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
            return result.decode()
        except subprocess.TimeoutExpired:
            return f"{colors.ORANGE}✧ Comando excedeu o tempo limite{colors.END}"
        except Exception as e:
            return f"{colors.RED}✧ Erro: {str(e)}{colors.END}"

    def execute_malware(self, cmd):
        malware_cmds = {
            "scan": f"{colors.PURPLE}✧ Varredura de rede iniciada...{colors.END}",
            "exploit": f"{colors.RED}✧ Explorando vulnerabilidades {colors.FIRE}{colors.END}",
            "steal": f"{colors.DARK}✧ Coletando dados sensíveis... {colors.CRANIO}{colors.END}",
            "selfdestruct": f"""{colors.RED}
            ╔══════════════════════════════════════╗
            ║  AUTODESTRUIÇÃO ATIVADA              ║
            ║  Tempo restante: 10 segundos         ║
            ╚══════════════════════════════════════╝
            {colors.END}"""
        }
        return malware_cmds.get(cmd.lower())

    def interactive_loop(self):
        while True:
            try:
                cmd = input(f"{UI.color('prompt')}kd-shell{UI.color('text')}@{UI.color('highlight')}{self.ip}{UI.color('text')}:{UI.color('prompt')}{self.port}{colors.END}$ ")
                
                if cmd.lower() == "exit":
                    print(f"{colors.PINK}✧ Saindo... Até logo! {colors.HEART}{colors.END}")
                    break
                
                if not self.send(cmd):
                    print(f"{colors.RED}✧ Erro ao enviar comando{colors.END}")
                    break
                
                wrapper(lambda stdscr: Animator.loading(stdscr, 1))
                response = self.receive()
                if response is None:
                    print(f"{colors.RED}✧ Conexão perdida{colors.END}")
                    break
                
                print(f"\n{response}\n")
                self.history.append(cmd)

            except KeyboardInterrupt:
                print(f"\n{colors.ORANGE}✧ Use 'exit' para sair corretamente{colors.END}")
            except EOFError:
                UI.clear()
                print_banner()

    def run(self):
        print_banner()
        if not self.connect():
            return
        
        try:
            self.interactive_loop()
        finally:
            if self.sock:
                self.sock.close()

def main():
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <IP> <PORTA>")
        return

    try:
        nc = KawaiiNetcat(sys.argv[1], int(sys.argv[2]))
        nc.run()
    except Exception as e:
        print(f"{colors.RED}✧ Erro fatal: {str(e)}{colors.END}")

if __name__ == "__main__":
    main()
