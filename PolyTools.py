#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import time
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
import webbrowser

console = Console()

# Configuração do usuário
USER_FILE = ".user"
def get_username():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            return f.read().strip()
    return "guest"

def set_username():
    username = console.input("[bold green]Defina seu nome de usuário: [/bold green]")
    with open(USER_FILE, 'w') as f:
        f.write(username)
    return username

class Banners:
    @staticmethod
    def main_menu():
        return """[bold red]
         ⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀       ⣀⣠⣤⣤⣶⠶⠶⠶⠶⠶⠶⠶⢖⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀       ⢀⣠⡴⠞⠛⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀       ⣀⣴⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀       ⠀⢀⣠⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠈⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀       ⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀       ⠀⣠⡞⠁⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀   ⠈⠹⣦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀       ⠀⢀⣼⠋⠀⠀⠀⢀⣤⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⣦⣀⠀⠀   ⠀⠈⢿⣄⠀⠀⠀⠀⠀
⠀⠀⠀       ⢀⡾⠁⠀⣠⡾⢁⣾⡿⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣆⠹⣦⠀⠀⢻⣆⠀⠀⠀⠀
⠀       ⠀⢀⡾⠁⢀⢰⣿⠃⠾⢋⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⠀⢹⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡌⠻⠆⢿⣧⢀⠀⢻⣆⠀⠀⠀
⠀       ⠀⣾⠁⢠⡆⢸⡟⣠⣶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣦⡸⣿⠀⣆⠀⢿⡄⠀⠀
⠀       ⢸⡇⠀⣽⡇⢸⣿⠟⢡⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣉⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⠙⢿⣿⠀⣿⡀⠘⣿⠀⠀
       ⡀⣿⠁⠀⣿⡇⠘⣡⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⣦⡙⠀⣿⡇⠀⢻⡇⠀
       ⢸⡟⠀⡄⢻⣧⣾⡿⢋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣴⣿⠉⡄⢸⣿⠀
       ⢾⡇⢰⣧⠸⣿⡏⢠⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠀⠓⢶⠶⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣆⠙⣿⡟⢰⡧⠀⣿⠀
       ⣸⡇⠰⣿⡆⠹⣠⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⣿⡏⠀⠠⢺⠢⠀⠀⣿⣷⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⠸⠁⣾⡇⠀⣿⠀
       ⣿⡇⠀⢻⣷⠀⣿⡿⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡅⠀⠀⢸⡄⠀⠀⣿⣿⣿⣿⣿⣿⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡆⣰⣿⠁⠀⣿⠀
       ⢸⣧⠀⡈⢿⣷⣿⠃⣰⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣇⠀⢀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣸⡀⢿⣧⣿⠃⡀⢸⣿⠀
       ⠀⣿⡀⢷⣄⠹⣿⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⣿⣿⠀⣼⣿⣿⣿⣿⣿⣿⣿⡯⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⢸⡟⢁⣴⠇⣼⡇⠀
       ⠀⢸⡇⠘⣿⣷⡈⢰⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⣿⣿⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢰⣿⡧⠈⣴⣿⠏⢠⣿⠀⠀
  ⠀     ⠀⢿⡄⠘⢿⣿⣦⣿⣯⠘⣆⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⡎⢸⣿⣣⣾⡿⠏⠀⣾⠇⠀⠀
⠀       ⠀⠈⢷⡀⢦⣌⠛⠿⣿⡀⢿⣆⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢀⣿⡁⣼⡿⠟⣉⣴⠂⣼⠏⠀⠀⠀
⠀⠀  ⠀     ⠈⢷⡈⠻⣿⣶⣤⡁⠸⣿⣆⠡⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢀⣾⡟⠀⣡⣴⣾⡿⠁⣴⠏⠀⠀⠀⠀
⠀⠀  ⠀     ⠀⠈⢿⣄⠈⢙⠿⢿⣷⣼⣿⣦⠹⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⢡⣾⣿⣶⣿⠿⢛⠉⢀⣾⠏⠀⠀⠀⠀⠀
⠀⠀  ⠀⠀     ⠀⠀⠹⣧⡀⠳⣦⣌⣉⣙⠛⠃⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠐⠛⠋⣉⣉⣤⡶⠁⣰⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀       ⠀⠀⠈⠻⣦⡀⠙⠛⠿⠿⠿⠿⠿⠟⠛⠛⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠙⠟⠛⠿⠿⠿⠿⠟⠛⣠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀  ⠀     ⠀⠀⠈⠛⢶⣄⠙⠶⣦⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⣤⡶⠖⣁⣴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀       ⠀⠀⠀⠙⠻⣶⣄⡉⠉⠉⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠉⠉⠉⠉⣡⣴⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀       ⠀⠀⠀⠀⠉⠛⠷⢦⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣠⣴⠶⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀       ⠀⠉⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠋⠉⠁⠀
            
     v 9.7.0 data: 7/11/2025                  ass:  | made: Brasil⠀⠀⠀⠀
                             desde: 10/7/2025⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀               
        [/bold red]"""

    @staticmethod
    def osint():
        return """
    [bold blue]
                       ╔══════════════════════╗
                       ║     [ USUÁRIO ]      ║
                       ╚══════════════════════╝
                                 │
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
 [ USERNAME ]              [ E-MAIL ]                  [ TELEFONE ]
       │                         │                         │
       ▼                         ▼                         ▼
 [ REDES SOCIAIS ]      [ GRAVATAR / BREACH ]        [ WHATSAPP / SMS ]
       │                         │                         │
 ┌─────┴─────┐           ┌───────┴────────┐         ┌──────┴──────┐
 ▼           ▼           ▼                ▼         ▼             ▼
[ NOME ]   [ CPF ]   [ CNPJ ]       [ BIN (CARTÃO) ]   [ LOCALIZAÇÃO ]
       │                         │                         │
       ▼                         ▼                         ▼
 [ RG ]                   [ ENDEREÇO / CEP ]          [ IP / ASN ]
       │                         │                         │
       ▼                         ▼                         ▼
 [ IMAGEM ]              [ FOTO DO PERFIL ]         [ LINKEDIN / PRO ]
       │                         │                         │
       └──────────────┬──────────┴───────────┬────────────┘
                      ▼                      ▼
                [ RELATÓRIO OSINT ]     [ WEBHOOK / JSON ]

        """

    @staticmethod
    def malware():
        return """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣤⣤⣤⣤⣶⣶⣶⣶⣶⣶⣤⣤⣤⣤⣤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣤⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⣀⣀⡄⠀⠀⡀⠀⠀
⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣾⠁⠀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀
⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁
⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀
⠀⣾⣿⣿⣿⣿⡿⠋⠹⣿⣿⣿⣿⣿⡇⠀⠀⠙⣿⣿⡿⠛⠛⠛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀
⢀⣿⣿⣿⡿⠃⠀⠀⢰⣿⣿⣿⣿⣿⠁⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠈⠛⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀
⢸⣿⣿⡏⠀⠀⠀⠀⠀⠛⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠉⠀⠀⠀⠀⠈⠙⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀
⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⡿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢼⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⡿⢿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠸⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠉⠁⠀⠘⢿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⠿⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                       
        """

    @staticmethod
    def scanner():
        return """
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣶⣶⣶⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⢠⣿⣿⣿⣿⣿⣿⣿⣿⠿⠃⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⡀⠻⠿⣿⠿⣿⣿⣿⠏⣰⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣶⡆⠀⠀⠀⠀⠉⠀⠻⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠙⠛⣉⣭⣙⢻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⣉⠛⣛⣉⠁⠀⠀⢀⣤⣴⣦⣤⣀⣶⡆⣾⣿⣿⣿⣯⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡏⠀⠀⣰⠟⠉⠉⠙⢿⣿⣿⣇⢻⣿⣿⣿⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⡟⠀⠀⠀⠁⠀⠀⠀⠀⢸⣿⣿⣿⣦⡙⠿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⢋⣩⣭⣉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⡖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⢠⣴⡾⣿⣿⡛⢋⠉⣠⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠟⣉⣤⣶⣤⣤⣤⡀⠀⠀⣴⣿⠟⠁⣩⣿⣿⣿⣿⣿⣻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⢇⣾⣿⣿⣿⣿⣿⣿⣿⡆⠺⠿⠋⢀⣾⣿⡿⢫⣾⣿⠟⢮⣝⠿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⣳⣾⣷⣷⡄⠀⠈⢿⢸⣿⣿⣿⡿⣫⣶⣿⣿⣿⣷⣄⢻⡿⢋⣴⣿⣿⠟⣠⣴⡿⠷⣟⣯⣤⣶⡶⣶⣄⡀⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⡿⠃⠈⠛⢿⣦⣀⣈⡈⢿⣿⡟⣼⣿⣿⣿⣿⣿⠿⣛⣃⣀⣘⠿⠟⢣⣾⣿⡿⠃⣴⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣾⣼⡿⠋⠉⠀⠀⠀⠀⠀⠘⠿⣸⠧⡄⠻⠁⣿⣿⣿⣿⢏⣴⣿⣿⣿⣿⣿⣷⣄⢻⡟⠋⠀⣼⣿⣿⣿⠋⠉⠵⠿⣿⣿⣿⣿⢋⣷⣿⣦⡀⠀⠀⠀
⠀⠀⠀⠀⠀⣼⣿⠋⠀⢠⣶⣶⣶⣾⣿⣿⣿⣿⣷⡄⣶⣶⣆⣻⣿⣿⢯⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠁⣀⣠⣴⣮⢻⠇⠀⣷⡄⠀⠀⠹⣿⣷⣿⣿⣿⣿⣷⣤⡀⠀
⠀⠀⠀⠀⠀⣿⡇⠀⢰⣯⣽⠉⠉⢩⣍⣉⣉⣩⣭⣥⣭⣍⣻⣥⣭⣭⣜⠿⣿⣿⣿⣿⣿⣿⣿⠿⢛⡸⢿⣿⣿⡿⠀⠀⠀⢹⣷⣀⣀⠀⠀⠁⢿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⢀⣼⠿⠃⠀⢸⣿⡇⠀⢸⣿⠻⠟⠿⠿⠿⠿⢿⣿⣿⠋⠛⣻⣭⣴⣶⣄⠉⠛⠿⠟⢫⣾⣿⣿⣿⣆⣀⡈⠀⠀⠀⠀⠀⠉⠛⠉⠀⠀⠀⢘⣿⣿⣿⣿⣿⣿⣿⣿
⣠⡴⠟⠛⠁⠀⠀⢸⣿⡧⠀⣾⣿⡀⠀⢠⣼⡻⣿⣿⣿⣿⣿⣿⠎⣿⠿⠟⠃⣀⣴⣿⣿⠈⣙⡻⠿⠃⢾⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⠟
⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⢿⣿⡇⠀⣼⣿⡇⠉⠙⠛⠋⠉⠀⠀⠀⠀⠀⣾⡛⠻⣿⡇⠀⣿⣧⠀⠀⠘⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠿⠿⠃⠀⢠⣤⣴⡆
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⢸⣿⡇⠀⣿⣿⡇⠀⠀⠀⣠⠾⠛⢿⣿⣷⣿⣿⣿⣧⠹⠃⠀⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠇⠀⠀⠀⠀⣼⣿⣿⠃
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⠇⢸⣶⡅⢐⡿⠏⠀⠀⠀⢀⣴⣿⣷⡌⠿⠿⠿⠿⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡏⠀⠀⠀⠀⢀⣤⣿⣿⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠜⠋⠀⠀⠀⢻⣧⠘⣿⣦⠀⠀⢠⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⢀⣼⣿⠟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡏⠀⠘⢿⣧⠀⢸⣿⣿⣿⣿⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠛⠋⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠟⠀⠀⠀⢰⣿⠆⢸⣿⣿⣿⣿⢿⣿⣧⣤⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⢸⣿⣿⡿⣱⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣠⣤⣤⣤⣤⣶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠈⣿⣿⢧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⠇⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⣉⠉⠻⠋⠁⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⠿⠋⢰⣿⣿⣧⣦⡀⣀⣴⣶⣤⣴⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠙⠛⠿⠿⠿⠿⠿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def brute_force():
        return """
      ⠀⠀⠀⠀⠀⠀⢀⣤⢤⣤⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⡟⢻⡟⠛⠲⢧⢩⡙⣷⣤⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⢠⢴⡟⡿⢩⠇⠛⢯⣿⠛⣟⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣤⣶⡿⠛⣁⣴⣿⣿⢶⡆⢸⢱⠃⡿⢿⠀⠀⠀⠀⠀⢸⣿⣿⠟⠋⠛⣿⣿⣿⠀⠀⠀⠀⠀⢸⠸⡀⢇⢸⠀⣶⢾⣿⡷⣄⡙⠿⣷⡦⣄⡀⠀⠀⠀⠀
⠀⠀⣠⣶⣿⡿⠟⠉⢠⡞⢁⣽⠟⠁⠘⠿⣿⣾⣦⣧⠟⠀⠀⠀⠀⠀⣼⢻⣿⣛⣻⣟⣿⣿⣿⡄⠀⠀⠀⠀⠸⢶⣧⣾⣾⠿⠟⠀⠙⣿⣆⠹⣦⠈⠙⢿⣮⣗⢦⠀⠀
⠀⣸⣿⠏⠈⠀⠀⢀⡾⣥⣿⡏⠀⠀⠀⠀⠀⠈⠛⠋⠀⠀⠀⠀⠀⠀⣿⣄⠉⣹⠏⢟⠉⢁⣼⡇⠀⠀⠀⠀⠀⠘⠙⠋⠀⠀⠀⠀⠀⠘⣿⣧⡻⣆⠀⠀⠀⠉⢷⣷⠀
⠀⣿⡏⠀⠀⠀⢠⡮⢾⣿⣿⣴⡖⢦⡀⠀⢀⣀⣀⣀⠀⠀⠀⠀⠀⠀⣾⠸⠿⡭⣿⣧⡽⢻⢸⡆⠀⠀⠀⠀⠀⣀⣀⣄⣀⠀⠀⣠⠖⣶⣼⣿⣿⠾⣆⠀⠀⠀⢸⣿⡇
⢸⢿⣿⣄⡒⠶⣿⣴⣿⠛⠛⠒⠢⢍⣻⣶⠏⠒⠀⢈⣛⣷⣄⠀⠀⢀⣿⣷⡐⠀⣒⡒⠀⣴⣿⣇⠀⠀⢀⣴⣟⣋⠀⠐⠊⣷⡾⣋⡥⠖⠚⠛⢿⣷⣾⣷⠶⣠⣼⡿⢳
⠘⢿⣶⣯⣍⣥⣤⡴⣿⣦⡀⠀⠀⠀⠙⣿⣷⣶⠒⠀⠐⠛⠛⠶⣾⣿⡇⣿⢿⣿⣿⣿⣿⣿⢇⣯⣿⡶⠟⠛⠛⠃⠀⠐⣶⣶⣿⡟⠁⠀⠀⠀⣠⣾⡷⣤⣤⣭⣭⢷⣿⠟
⠀⠀⠙⢷⣤⣤⣗⡲⢿⣾⣍⠀⠀⠀⠀⣸⣿⣿⣯⣓⡒⠢⠀⠀⠀⢉⡛⠻⢿⣻⣿⣿⣿⠿⠛⠃⠀⠀⠀⠤⠒⣒⣮⣿⣿⣿⡀⠀⠀⠀⢈⣿⣾⠷⣒⣠⣤⣴⠟⠁⠀
⠀⠀⠀⠀⠹⣿⡉⠉⠛⠛⢿⣿⣷⣿⣿⣟⠟⢻⣾⣦⡉⠁⠀⠀⠀⠀⠈⠙⣶⣿⣿⣿⣷⠞⠉⠀⠀⠀⠀⠀⠉⣡⣿⣿⠛⢛⣿⣿⣿⣿⣿⠟⠉⠋⢉⣹⡟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢻⣦⡀⠀⢈⣩⣿⣿⣿⣿⠿⡟⢿⣻⣿⣷⣦⣀⠀⠀⠀⠉⢻⣿⣿⣿⣿⠊⠁⠀⠀⢀⣤⣶⣾⣿⣿⠛⡻⢿⣿⣿⣿⣯⣉⠀⠀⣠⣿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⠿⠿⠿⠿⡿⠁⣰⠇⠀⢿⣿⣻⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣟⣿⣿⠁⠀⣧⡀⠹⡿⠿⠿⠿⠿⠟⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⣰⣿⡀⠀⣸⣟⢿⣿⣿⣿⣿⠿⠿⠿⢿⣿⣽⠿⠿⠿⢿⣿⣿⣿⣿⢛⣿⠀⢰⣿⣷⣠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣷⣰⡏⣩⡟⠉⢿⡟⠁⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠙⣿⠉⠙⣯⠉⣧⣸⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⡟⠛⣿⠀⣠⣿⣿⠿⠟⠛⠻⣿⣿⣿⠿⠛⠛⠿⣷⣿⣧⡀⢸⡟⠻⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣧⣾⣇⠀⢿⡟⠁⠀⠀⠀⠀⢸⣿⣯⠀⠀⠀⠀⠀⠙⣿⠃⢸⣿⣴⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣼⡟⢦⡘⣷⣄⣠⣤⣴⣶⣿⣷⣿⣶⣶⣤⣤⣄⣴⣟⣠⢞⣷⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⡄⠻⣿⡿⠛⠁⠀⠈⢻⣿⡿⠋⠀⠈⠙⠻⣿⡿⠃⣞⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣷⢤⣹⡇⠀⠀⠀⠀⢸⣿⣷⠀⠀⠀⠀⠀⣿⡀⢼⣽⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⣇⠹⣷⣄⣀⣀⣠⣾⣿⣿⣦⣀⣀⣀⣴⡿⢁⡿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣷⡈⠀⢿⡟⠉⠉⠉⠉⢿⠋⠉⠉⠉⠙⣿⠃⠊⣰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢯⣧⠀⣸⣇⠀⠀⠀⠀⠸⠀⠀⠀⠀⢀⣿⠀⢴⣯⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣦⡀⠀⠀⢠⠀⠀⠀⣠⣾⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠓⠚⠛⠛⠛⠛⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def sql_inject():
        return """
        ⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠛⠛⠶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠉⠓⠶⢤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢳⣿⠻⢶⢶⣤⣤⣀⣠⣾⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠶⣦⡉⢩⣿⣿⣿⠈⢨⠈⡟⢿⡶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠻⣷⣿⠋⠓⢸⣼⣻⣦⢤⣌⣏⠛⡻⡶⢤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠿⣵⣦⣩⣼⡛⠧⣞⣸⣿⣿⣷⠒⡶⢮⣯⡟⢲⢦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠿⣷⣦⣯⣝⠹⡇⡀⡇⣸⢁⣿⣴⣷⣶⡉⠛⠳⣶⣤⣀⣴⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠾⣷⣇⣉⠹⣏⠼⢹⣿⣰⢧⣸⢿⣻⠀⣿⣷⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⢿⣧⣨⣥⠴⡇⡬⠇⠀⣾⣿⣿⡛⠷⢦⣤⣀⡀⠀⠀⠀⠀⢀⣀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠳⢶⣷⣤⣼⣯⣿⣍⠛⠿⣶⣮⣍⡉⠛⢶⣤⣴⣿⣿⡆⠀⢠
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣯⡿⠉⠉⠛⠲⢶⣮⣙⠛⠷⢶⣭⣿⣿⣿⠁⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠷⣾⢿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⡾⠋⠀⠀⠀⠀
        """
        
    @staticmethod
    def span():
        return """
     ⠀⠀⠀⢀⣠⣤⣤⣶⣶⣶⣶⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀
⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀
⠀⢀⣾⣿⣿⣿⣿⡿⠟⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀
⠀⣾⣿⣿⣿⣿⡟⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀
⢠⣿⣿⣿⣿⣿⣧⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠘⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠈⠻⢿⣿⠟⠉⠛⠿⣿⣿⣿⣿⣿⣿⠃
⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⡿⠀
⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣴⣾⣿⣿⣿⣿⡿⠁⠀
⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀
⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀
⠠⠛⠛⠛⠉⠁⠀⠈⠙⠛⠛⠿⠿⠿⠿⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def phishing():
        return """
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣶⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡿⠿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢉⣡⣤⣶⣶⣶⣶⣶⣶⣶⣶⣤⠀⠀⢸⣇⠀⠀
⠀⠙⣿⣷⣦⡀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠉⣿⠟⠁⠀⠀⢸⡟⠀⠀
⠀⠀⢸⣿⡿⠋⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠖⠁⠀⠀⣷⡄⢸⡇⠀⠀
⠀⠀⠀⣿⠁⢴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⢿⣀⣸⡇⠀⠀
⠀⠀⠀⣿⣷⣤⣈⠛⠻⢿⣿⡿⢁⣼⣿⣿⡿⠛⣿⣿⣿⣦⣄⡀⠈⠉⠉⠉⠁⠀⠀
⠀⠀⢀⣿⡿⠟⠁⠀⠀⠀⠀⠀⠛⠉⠉⠠⠤⠾⠿⠿⠿⠿⠟⠛⠋⠁⠀⠀⠀⠀
⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def xss():
        return """
        01011000 01010011 01010011 00100000 01000001 01010100 01010100 01000001 01000011 01001011 01010011
        01001001 01001110 01001010 01000101 01000011 01010100 01001001 01001110 01000111 00100000 01001101 01000001 01001100 01001001 01000011 01001001 01001111 01010101 01010011 00100000 01010011 01000011 01010010 01001001 01010000 01010100 01010011
        01000011 01010010 01001111 01010011 01010011 00100000 01010011 01001001 01010100 01000101 00100000 01010011 01000011 01010010 01001001 01010000 01010100 01001001 01001110 01000111
        """
        
    @staticmethod
    def git_exposto():
        return """
          ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣀⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⣿⣿⣶⠾⠛⠋⠉⠹⣧⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡿⠉⠉⠉⠛⠻⢶⡶⠾⠟⠛⠛⣿⣿⣳⣿⣷⣿⣿⣦⣀⠀⢀⣀⣻⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣟⣷⣿⣿⣿⣿⣻⢿⣿⣿⣿⢿⣿⣦⠀⠀⠀⠀
⠀⠀⠀⠀⢹⣇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣾⣽⡿⣿⣾⡽⣯⣿⣿⣿⣻⣾⡿⠀⠀⠀⠀
⠀⠀⠀⠀⢈⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⣿⣿⣟⣯⣷⣿⡅⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠛⠉⠈⣷⠀⠀⠀⠀
⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠴⣿⠶⠶⠖⠂
⠀⣀⣀⣠⣿⣤⣄⠀⠀⠀⢠⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣷⠀⠀⠀⠀⣀⣾⣁⠀⠀⠀
⠀⠉⠁⣰⠟⠛⢦⡀⠀⠀⠻⠿⠃⠀⠀⠀⠀⣠⠤⣄⠀⠀⠀⠀⠈⠋⠀⠀⠀⠀⢩⡿⠉⠉⠉⠀
⢀⣤⢶⣿⡀⠀⠘⣧⣀⣀⠀⠀⠀⠀⠀⠀⠀⠳⠤⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⣳⡿⢧⣄⡀⠀⠀
⢸⡁⠀⠀⠑⠀⠀⠉⠉⠉⠛⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡾⠛⠁⠀⠀⠉⠀⠀
⠀⠛⢶⣤⡀⠀⢠⡶⠶⠂⠀⠈⣷⣤⣤⣤⣤⣀⣀⣤⣤⣤⣤⣴⣶⣿⡿⣍⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢹⡇⠀⠻⣄⣀⡼⠂⢀⣿⣿⣻⣿⣍⣉⣉⣉⣿⣟⡿⣿⣿⡟⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠻⣦⣀⠈⠁⣀⣴⡿⣿⣳⣟⡾⣽⣻⣟⣯⢷⣯⣟⣿⠏⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠉⠛⠛⠋⠉⠀⠙⣟⠺⢽⣷⣻⣾⣽⣻⠾⢻⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⢄⣀⡼⠧⣀⡠⠔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def zero_day():
        return """
   ⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⣠⡀⠀⠀⢀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣤⣤⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⡿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⣠⠀⣶⣤⣄⣉⣉⣉⣉⣉⣠⣤⣶⠀⣄⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣶⣾⣿⣿⣿⣿⣦⣄⣉⣙⣛⣛⣛⣛⣋⣉⣠⣴⣿⣿⣿⣿⣷⣶⠀⠀⠀
⠀⠀⠀⠀⠈⠉⠉⠛⠛⠛⠻⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠛⠛⠉⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⣆⠀⠀⠀⢠⡄⠀⠀⠀⣰⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣠⣶⣾⣿⡆⠸⣿⣶⣶⣾⣿⣿⣷⣶⣶⣿⠇⢰⣿⣷⣶⣄⡀⠀⠀⠀
⠀⠀⠺⠿⣿⣿⣿⣿⣿⣄⠙⢿⣿⣿⣿⣿⣿⣿⡿⠋⣠⣿⣿⣿⣿⣿⠿⠗⠀⠀
⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣷⡄⠈⠙⠛⠛⠋⠁⢠⣾⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣤⣬⣿⣿⣿⣇⠐⣿⣿⣿⣿⠂⣸⣿⣿⣿⣥⣤⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠘⠻⠿⠿⢿⣿⣿⣿⣧⠈⠿⠿⠁⣼⣿⣿⣿⡿⠿⠿⠟⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⠀⣶⣦⠀⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def dos():
        return """
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠦⠤⡒⠋⠀⠳⠤⠴⡾⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠂⢔⡨⣕⠀⠀⠀⠀⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠺⢥⡀⠀⢈⡂⢁⡆⠀⠀⣹⣄⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⠞⢛⡟⠓⠲⢤⣄⡀⠀⠀⠀⢀⣸⡆⠀⠛⠉⠁⣰⠋⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠶⠶⢦⣴⢿⠿⣏⣠⡯⠤⣶⣖⣈⣉⣉⡿⠒⢚⠟⢹⠷⣲⠟⠓⠲⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣶⡀⠾⣍⣘⡾⢿⣄⠀⠀⠀⠀⠉⠛⠷⠴⠾⠥⠴⠟⠛⠁⠀⠀⠀⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⠶⠶⢶⣾⣿⠟⡈⠙⠢⢄⡀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣴⠞⠛⠉⠀⢠⣤⣤⡞⣿⣿⡴⠁⠀⠀⢰⣻⠀⠀⢘⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣤⡾⠋⠀⠀⠀⠀⠀⠈⠛⣿⡻⣝⠀⠀⠀⠀⠀⡿⠃⠀⢠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⡾⠋⠀⢠⣤⠀⠀⠀⠀⠀⠀⠈⠛⠿⠳⢦⣄⡀⠀⠀⢀⣠⠟⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣼⠏⢀⣴⣿⡯⠀⠀⠀⠀⠀⠀⠒⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠁⠀⠀⠹⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⡏⠰⣮⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⢐⣿⡮⣿⡷⠄⠀⠀⠉⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⡏⢸⣿⣿⣿⡇⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣇⢨⣿⣿⣿⣿⢤⣒⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡄⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⢻⣿⣿⣿⣿⣦⣭⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣶⣶⣾⣿⣿⡇⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⡆⢻⣿⣿⣿⣟⢿⡻⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡿⣿⡇⠁⠀⠀⠀⢠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢿⣄⠙⣿⣿⣿⣷⣯⠉⠛⠷⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⢻⣦⡈⢿⣿⣿⣿⣿⣯⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠀⠀⣠⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⣦⡉⠛⠿⢿⣿⣿⣿⣷⣤⣤⣤⣤⣤⣦⣶⡾⠟⢉⣠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠛⠷⣦⣀⡉⠉⠉⠉⠛⠿⠛⠛⠛⢃⣁⣤⡶⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠳⠶⠶⠶⠶⠾⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def ddos():
        return """
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⡖⠿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣞⡻⠉⢀⠀⠈⠳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡏⠀⡂⣸⣦⠀⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢻⠉⠻⠐⣭⡀⠀⠙⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⢡⠤⠜⠂⠀⠀⠈⠘⠀⠀⠀⠱⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠞⠁⠙⢦⣀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠉⠳⣄⠀⠀⠹⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣼⣶⣶⢒⣒⡒⢤⡤⠀⠀⢦⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣶⣿⣿⣿⣾⣧⣤⣬⣤⣀⣙⣿⣤⣤⡆⠂⠂⡀⠀⠀⠀⠀⣀⠀⠠⠐⠂⠈⡋⣟⣿⣇⣠⡀⡼⣇⣀⡀⠰⣷⣶⣶⣶⠒⠒⠒⠒⠒⠒⠒⠒⠢⠤⢄⡀
⠀⠀⠀⠀⠉⠉⢛⣿⢿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠂⠂⠀⠉⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣿⣷⣶⣶⣶⣶⣶⣶⣾⣿⠿⠛⠁
⠀⠀⠀⠀⠀⠀⠈⠛⢻⣿⣿⣿⣿⡏⢁⣀⣀⣠⣤⣤⡤⠀⢀⠀⠀⢀⡀⣀⣠⣤⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⢿⠟⠛⠋⠉⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⡿⠿⠛⠛⠉⠀⠀⠒⢾⠤⠤⠤⠀⠚⠛⠉⢩⠙⠛⠛⠟⠿⣿⡿⢿⡿⣿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣿⣿⠟⢻⠁⠀⠀⢀⣀⣀⣀⣀⠤⠀⠀⠀⠀⠀⢀⣤⡤⠼⣴⣤⣤⣤⣤⣿⡿⠿⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠠⢶⣶⣶⣶⣿⣦⣤⣠⣿⣿⣶⣾⣿⣶⣿⣿⠿⠿⠛⠁⠀⠀⠀⠀⠤⠤⠶⠿⢿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠿⠿⠿⠙⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⠟⢿⣿⣿⣿⣿⡿⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⡇⠀⣿⣿⣿⣿⠟⠀⢸⠋⠀⠀⠀⠀⠠⣤⣀⣄⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡟⠀⢠⣿⣿⡟⠁⠀⠀⡸⠁⠀⠠⠀⠀⠁⠀⢉⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⠀⠀⣼⡟⠁⠀⠀⠀⢠⡇⢀⢄⡞⠀⠀⡳⣴⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠙⠚⠋⠀⠀⠀⠀⢀⣾⠇⠡⠈⠀⠀⢀⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠿⡆⠀⠀⢀⣴⠏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣷⣶⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        
    @staticmethod
    def dox():
        return """
     ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
     ⠀⢹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀
     ⠀⢸⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⣠⣿⡇⠀
     ⠀⠸⣿⣿⣷⣦⣀⡴⢶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⣴⣾⣿⣿⠇⠀
     ⠀⠀⢻⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣿⣿⣿⣿⣿⡟⠀⠀
⠀     ⠀⣠⣻⡿⠿⢿⣫⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⣿⣻⣥⠀⠀
     ⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡿⣟⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀
     ⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⡹⡜⠋⡾⣼⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀
     ⠀⠀⣿⣻⣾⣭⣝⣛⣛⣛⣛⣃⣿⣾⣇⣛⣛⣛⣛⣯⣭⣷⣿⣿⡇⠀
⠀     ⠰⢿⣿⣎⠙⠛⢻⣿⡿⠿⠟⣿⣿⡟⠿⠿⣿⡛⠛⠋⢹⣿⡿⢳⠀
     ⠀⠘⣦⡙⢿⣦⣀⠀⠀⠀⢀⣼⣿⣿⣿⣳⣄⠀⠀⠀⢀⣠⡿⢛⣡⡏⠀
⠀     ⠀⠹⣟⢿⣾⣿⣿⣿⣿⣿⣧⣿⣿⣧⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀
⠀     ⠀⢰⣿⣣⣿⣭⢿⣿⣱⣶⣿⣿⣿⣿⣷⣶⢹⣿⣭⣻⣶⣿⣿⠀⠀
⠀     ⠀⠈⣿⢿⣿⣿⠏⣿⣾⣛⠿⣿⣿⣿⠟⣻⣾⡏⢿⣿⣯⡿⡏⠀⠀
⠀     ⠀⠤⠾⣟⣿⡁⠘⢨⣟⢻⡿⠾⠿⠾⢿⡛⣯⠘⠀⣸⣽⡛⠲⠄⠀
⠀⠀     ⠀⠀⠘⣿⣧⠀⠸⠃⠈⠙⠛⠛⠉⠈⠁⠹⠀⠀⣿⡟⠀⠀⠀⠀
⠀⠀⠀⠀     ⠀⢻⣿⣶⣀⣠⠀⠀⠀⠀⠀⠀⢠⡄⡄⣦⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀     ⠘⣿⣷⣻⣿⢷⢶⢶⢶⢆⣗⡿⣇⣷⣿⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀     ⠈⠻⣿⣿⣛⣭⣭⣭⣭⣭⣻⣿⡿⠛⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀     ⠀⠀⠈⠻⠿⠟⠛⠛⠛⠻⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀
        """

    @staticmethod
    def teste_rede():
        return """
        ████████╗███████╗███████╗████████╗███████╗
        ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝
           ██║   █████╗  ███████╗   ██║   ███████╗
           ██║   ██╔══╝  ╚════██║   ██║   ╚════██║
           ██║   ███████╗███████║   ██║   ███████║
           ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝
        """

    @staticmethod
    def linux():
        return """
        ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
        ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
        ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
        ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ 
        ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
        ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
        """

    @staticmethod
    def vpn():
        return """
        ██╗   ██╗██████╗ ███╗   ██╗
        ██║   ██║██╔══██╗████╗  ██║
        ██║   ██║██████╔╝██╔██╗ ██║
        ██║   ██║██╔═══╝ ██║╚██╗██║
        ╚██████╔╝██║     ██║ ╚████║
         ╚═════╝ ╚═╝     ╚═╝  ╚═══╝
        """

    @staticmethod
    def wifi():
        return """
        ██╗    ██╗██╗███████╗██╗
        ██║    ██║██║██╔════╝██║
        ██║ █╗ ██║██║█████╗  ██║
        ██║███╗██║██║██╔══╝  ██║
        ╚███╔███╔╝██║██║     ██║
         ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝
        """

    @staticmethod
    def bluetooth():
        return """
⠀⣿⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⡏⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠉⠲⣄⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠐⡰⠋⢙⣿⣦⡀⠀⠀⠀⠀⠀
⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣙⣦⣮⣤⡀⣸⣿⣿⣿⣆⠀⠀⠀⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⣿⢟⣫⠟⠋⠀⠀⠀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⣷⣿⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢹⣿⣿⣧⣿⣿⣆⡹⣖⡐⠠⠤⠠⠤
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣤⣿⣿⣿⡟⠹⣿⣿⣿⣿⣷⡀⠄⢀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣧⣴⣿⣿⣿⣿⠏⢧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢳⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣼⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠛⠻⠿⣿⣿⣿⡿⠿⠿⠿⠿⠿⢿⣿⣿⠏⠀⠀
        """

    @staticmethod
    def extras():
        return """
       ███████╗██╗  ██╗████████╗██████╗  █████╗ ███████╗
       ██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝
       █████╗   ╚███╔╝    ██║   ██████╔╝███████║███████╗
       ██╔══╝   ██╔██╗    ██║   ██╔══██╗██╔══██║╚════██║
       ███████╗██╔╝ ██╗   ██║   ██║  ██║██║  ██║███████║
       ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                 
        """

class HackerMenu:
    def __init__(self):
        self.username = get_username()
        self.tools = {
            "OSINT": {
                "BuscaDeSites.py": "Busca informações em sites",
                "metadados.py": "Extrai metadados de arquivos",
                "Leaked-Databases.py": "Consulta bancos de dados vazados",
                "busca-usuario.py": "Busca por usuários em redes sociais",
                "gmail-social.py": "busca por gmail em redes sociais",
                "nome-social.py": "busca por nome real em redes sociais",
                "cep.py": "Consulta informações por CEP",
                "cnpj.py": "Consulta dados de CNPJ",
                "cpf.py": "Consulta dados de CPF",
                "insta-dados.py": "Coleta dados do Instagram",
                "investigaçãoDeG-mail.py": "Investiga contas de Gmail",
                "ip.py": "Rastreamento de IP",
                "nome.py": "Busca por nomes",
                "pais.py": "Consulta informações de países",
                "rastreador-bitcoin.py": "Rastreia transações Bitcoin",
                "rg.py": "Consulta dados de RG",
                "telefone.py": "Busca por números de telefone",
                "bin.py": "Consulta informações de BIN (cartões)",
                "placa.py": "Consulta informações de placas de veículos",
                "sherlock.py": "Busca por nomes de usuário em redes sociais",
                "pix.py": "Consulta informações de chaves PIX",
                "gmail-api.py": "api que consulta dados vazados de um tau gmail",
                "holehe.py": "procura redes sociais vinculado a um gmail",
                "FOTO.py": "procura meta dados de foto",
                "whois.py": "busca com whois",
                "apis-web.py": "apis em pagina web",
                "numero-usuario.py": "busca redes vinculada a um numero",
                "IMEI-busca.py": "busca de imei",
                "parentes.py": "busca de parentes de uma vitima",
                "extra.py": "ferramentas extras de osint",
                "mac.py": "consulta de mac",
                "verificador-link.py": "verifica se link e seguro",
                "camera.py": "olhar cameras",
                "github.py": "envestigar usuario do github",
                "mapa-osint.py": "um mapa com varios suportes para osint",
                "reddit.py": "detalhes de usuario do reddit",
                "sherlock-api.py": "sherlock modo api",
                "geolocalização.py": "olhar minha geolocalizaçao atual",
                "subdomain.py": "buscar dominios em sites",
                "validador.py": "Validador de CPF, telefone, IP, email e CEP",
                "ddd-ddi.py": "Buscador de DDD/DDI",
                "gerador.py": "Gerador de CPF, telefone, placa, cartão e IP ",
                "gerar-pessoa.py": "gera uma pessoa fake com dados",
                "name-sweep.py": "faz combinaçoes para achar redes sociais",
                "virus-total-api.py": "verificar link e apks",
                "buscar-navios.py": "olhar localização de navios, porto"
                
            },
            "malwer": {
                "c2.py": "Servidor de Comando e Controle",
                "malwer.py": "Ferramentas de malware",
                "malwer-assembly.py": "Malware em Assembly",
                "malwer-c.py": "Malware em C",
                "malwerPowerShell.py": "Malware em PowerShell",
                "mawer.go.py": "Malware em Go",
                "Pos-Exploracao.py": "Ferramentas de pós-exploração",
                "dropper.py": "Dropper para implantação de malware",
                "menu-metasplit.py": "Interface para Metasploit Framework",
                "netcat-c2.py": "Netcat como servidor C2",
                "malware-js.py": "malware feito em js",
                "malware-ruby.py": "malware feito em ruby",
                "malwer-java.py": "malware feito em java",
                "malware-bash.py": "malwares em bash",
                "malware-discord.py": "malware pra roubo de token discord",
                "malwer-troll.py": "nao execulte isso",
                "Binary-Padding.py": "depois eu explico",
                "c2-interativo.py": "c2 com comandos",
                "compilar.py": "compilar malwares",
                "web-shell.py": "c2 com interface web",
                "win-lin.py": "organizar lista de malwares linux/windows",
                "termux-lista.py": "organizar lista de malwares termux"
                
            },
            "scanner": {
                "scanner.py": "Ferramenta de varredura de portas",
                "nmap.py": "menu pra nmap",
                "scan-perigo.py": "procura portas vuneraveis como adb",
                "scan-massa.py": "faz escaners em massa",
                "scan-real.py": "scaner real",
                "nmap-script.py": "usa os scripts do nmap"
            },
            "brute": {
                "dictionary-attack.py": "Ataque de dicionário a senhas",
                "hash-cracker.c": "Quebrador de hashes em C",
                "puro.py": "Força bruta pura",
                "sites.py": "Força bruta em sites",
                "hydra.py": "Ferramenta Hydra para força bruta",
                "pin.py": "quebrar pin de celular",
                "jhon-the-ripper.py": "quebra de hashes"
            },
            "sql-inject": {
                "sqlmap.py": "Ferramenta automatizada de SQL injection",
                "sql-inject.py": "Ferramenta manual de SQL injection",
                "sql-scaner.py": "Scanner de vulnerabilidades SQL"
            },
            "span": {
                "fim-link.py": "Ferramenta de spam por links",
                "social-span.py": "Spam em redes sociais",
                "span-gmail.py": "Spam por e-mail (Gmail)",
                "span-sms.py": "Spam por SMS",
                "trolar-amigo.py": "Ferramenta para trollar amigos",
                "git.span-menu.py": "varias ferramentas de span",
                "discord-span.py": "span de discord",
                "mensagem-sms.py": "span de mensagem de sms"
            },
            "phishing": {
                "menu-phishing.py": "Menu completo de ferramentas de phishing",
                "rede-val.py": "Validador de redes de phishing",
                "site-clone.py": "Clonador de sites para phishing",
                "info-phishing.py": "Ferramenta de phishing com informações",
                "mascara.py": "Mascaramento de URLs para phishing",
                "Clickjacking.py": "Ataques de Clickjacking",
                "phishing-games.py": "phishing pra jogo",
                "phishing-social.py": "phishing pra redes sociais",
                "phishing-banco.py": "phishing pra banco",
                "phisDrive-by-social.py": "pagina com malware que cria shell",
                "phishing-discord.py": "cria pagina pra roubar token",
                "phishing-apk.py": "cria uma pagina que recomenda um malware para apk",
            },
            "xss": {
                "xss.py": "Ferramenta de ataque XSS",
                "xss-scan.py": "Scanner de vulnerabilidades XSS"
            },
            "git-exposto": {
                "git.py": "Scanner de repositórios Git expostos",
                "baixar-git.py": "abaixar git"
            },
            "dos": {
                "dos.py": "Ferramentas de Denial of Service",
                "dos-ataque.py": "Ataques DoS específicos"
            },
            "ddos": {
                "ddos.py": "Ferramentas de Distributed Denial of Service",
                "ddos-ataque.py": "Ataques DDoS específicos"
            },
            "dox": {
                "dox.py": "Ferramentas de coleta de informações pessoais",
            },
            "zero-day-leve": {
                "zero-day.py": "Exploits de dia zero",
                "zero-day-scanner.py": "Scanner de vulnerabilidades zero-day"
            },
            "testes-rede": {
                "rede.py": "Ferramentas de teste de rede",
                "my-wireshark.py": "copia do wireshark"
            },
            "linux": {
                "distro.py": "Ferramentas para distribuições Linux"
            },
            "vpn": {
                "vpn.py": "Ferramentas de VPN",
                "tor.py": "tor para anonimato"
            },
            "wi-fi": {
                "wi-fi.py": "Ferramentas de análise Wi-Fi",
                "clonar-wi_fi.py": "clonar wi-fi",
                "quebrar-senha.py": "quebrar senha de wi-fi"
            },
            "bluetooth": {
                "Bluejacking.py": "Ataques de Bluejacking",
                "Bluesnarfing.py": "Ataques de Bluesnarfing"
            },
            "extras": {
                "atualizações.py": "Atualizações do sistema",
                "install.py": "Instalar dependências",
                "definir-usuario.py": "Definir nome de usuário",
                "aleatorio.py": "gera numeros aleatorios",
                "gerador-senhas.py": "gera senhas fortes",
                "Conversor-moedas.py": "valor da sua moeda moedas",
                "verificador-links.py": "verifica seu um link e seguro",
                "jogo_lixo.py": "um jogo simples",
                "calculadora.py": "calculadora simples",
                "terminal.py": "terminal interativo do PolyTools",
                "prompet.py": "mudar prompet do terminal",
                "systema.py": "olhar dados do seu termux com termux-api"
            }
        }

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def show_main_menu(self):
        self.clear_screen()
        console.print(Panel.fit(Banners.main_menu(), style="bold red"))
        console.print("\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Opção", style="cyan", width=10)
        table.add_column("Categoria", style="green")
        table.add_column("Descrição", style="yellow")

        table.add_row("1", "OSINT", "Ferramentas de coleta de informações")
        table.add_row("2", "MALWER", "Ferramentas ofensivas")
        table.add_row("3", "SCANNER", "Ferramentas de varredura")
        table.add_row("4", "FORÇA BRUTA", "Ataques de força bruta")
        table.add_row("5", "SQL INJECTION", "Injeção de SQL em bancos de dados")
        table.add_row("6", "SPAN", "Ferramentas de envio em massa")
        table.add_row("7", "PHISHING", "Ferramentas de engenharia social")
        table.add_row("8", "XSS", "Ataques Cross-Site Scripting")
        table.add_row("9", "GIT EXPOSTO", "Busca por repositórios Git expostos")
        table.add_row("10", "DoS", "Ataques de Denial of Service")
        table.add_row("11", "DDoS", "Ataques Distribuídos de Denial of Service")
        table.add_row("12", "DOX", "Ferramentas de coleta de informações pessoais")
        table.add_row("13", "ZERO-DAY", "Exploits de dia zero")
        table.add_row("14", "TESTE-REDE", "Ferramentas de teste de rede")
        table.add_row("15", "LINUX", "Ferramentas para distribuições Linux")
        table.add_row("16", "VPN", "Ferramentas de VPN")
        table.add_row("17", "WI-FI", "Ferramentas de análise Wi-Fi")
        table.add_row("18", "BLUETOOTH", "Ferramentas de Bluetooth")
        table.add_row("19", "EXTRAS", "Ferramentas adicionais")
        table.add_row("0", "SAIR", "Sair do sistema")

        console.print(table)

        choice = console.input(f"\n[bold red]PolyTools[bold yellow]@[bold blue]{self.username}[bold yellow] >[bold blue]>[bold red]> [/bold red]")
        return choice

    def show_category_menu(self, category):
        while True:
            self.clear_screen()
            
            if category == "OSINT":
                console.print(Panel.fit(Banners.osint(), style="bold green"))
            elif category == "malwer":
                console.print(Panel.fit(Banners.malware(), style="bold red"))
            elif category == "scanner":
                console.print(Panel.fit(Banners.scanner(), style="bold blue"))
            elif category == "brute":
                console.print(Panel.fit(Banners.brute_force(), style="bold magenta"))
            elif category == "sql-inject":
                console.print(Panel.fit(Banners.sql_inject(), style="bold cyan"))
            elif category == "span":
                console.print(Panel.fit(Banners.span(), style="bold yellow"))
            elif category == "phishing":
                console.print(Panel.fit(Banners.phishing(), style="bold purple"))
            elif category == "xss":
                console.print(Panel.fit(Banners.xss(), style="bold orange3"))
            elif category == "git-exposto":
                console.print(Panel.fit(Banners.git_exposto(), style="bold dark_green"))
            elif category == "dos":
                console.print(Panel.fit(Banners.dos(), style="bold dark_red"))
            elif category == "ddos":
                console.print(Panel.fit(Banners.ddos(), style="bold dark_orange"))
            elif category == "dox":
                console.print(Panel.fit(Banners.dox(), style="bold dark_blue"))
            elif category == "zero-day-leve":
                console.print(Panel.fit(Banners.zero_day(), style="bold dark_purple"))
            elif category == "testes-rede":
                console.print(Panel.fit(Banners.teste_rede(), style="bold cyan"))
            elif category == "linux":
                console.print(Panel.fit(Banners.linux(), style="bold green"))
            elif category == "vpn":
                console.print(Panel.fit(Banners.vpn(), style="bold blue"))
            elif category == "wi-fi":
                console.print(Panel.fit(Banners.wifi(), style="bold yellow"))
            elif category == "bluetooth":
                console.print(Panel.fit(Banners.bluetooth(), style="bold blue"))
            elif category == "extras":
                console.print(Panel.fit(Banners.extras(), style="bold magenta"))
            
            console.print(f"\n[bold]{category.upper()} TOOLS[/bold]\n")
            
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Nº", style="cyan", width=5)
            table.add_column("Ferramenta", style="green")
            table.add_column("Descrição", style="yellow")
            
            tools = self.tools[category]
            for i, (tool, desc) in enumerate(tools.items(), 1):
                table.add_row(str(i), tool, desc)
            
            table.add_row("0", "VOLTAR", "Retornar ao menu principal")
            
            console.print(table)
            
            choice = console.input(f"\n[bold red]PolyTools@/{self.username}/{category} >>> [/bold red]")
            
            if choice == "0":
                return
            elif choice.isdigit() and 1 <= int(choice) <= len(tools):
                tool_name = list(tools.keys())[int(choice)-1]
                self.run_tool(category, tool_name)
            else:
                console.print("[bold red]Opção inválida![/bold red]")
                time.sleep(1)

    def compile_c_file(self, file_path):
        try:
            output_file = file_path[:-2]  
            console.print(f"[bold yellow]Compilando {file_path}...[/bold yellow]")
            
            result = subprocess.run(
                ["gcc", file_path, "-o", output_file],
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            if result.returncode != 0:
                console.print(f"[bold red]Erro na compilação:[/bold red]")
                console.print(result.stderr)
                return None
                
            console.print(f"[bold green]Compilação bem-sucedida! Arquivo gerado: {output_file}[/bold green]")
            return output_file
            
        except Exception as e:
            console.print(f"[bold red]Erro ao compilar: {str(e)}[/bold red]")
            return None

    def run_tool(self, category, tool_name):
        self.clear_screen()
        console.print(f"[bold yellow]Executando {tool_name}...[/bold yellow]\n")
        
        try:
            # Verifica se é uma ferramenta especial
            if tool_name == "definir-usuario.py":
                self.username = set_username()
                console.print(f"[bold green]Usuário definido como: {self.username}[/bold green]")
                console.input("\nPressione Enter para continuar...")
                return
                
            # Verifica se a pasta existe
            if not os.path.exists(category):
                console.print(f"[bold red]Erro: Pasta '{category}' não encontrada![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
                
            script_path = os.path.join(category, tool_name)
            if not os.path.exists(script_path):
                console.print(f"[bold red]Erro: Arquivo '{tool_name}' não encontrado em '{category}'![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
        
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            if tool_name.endswith('.c'):
                compiled_path = self.compile_c_file(script_path)
                if not compiled_path:
                    console.input("\nPressione Enter para continuar...")
                    return
                
                # Executa o arquivo compilado
                process = subprocess.Popen(
                    [f"./{compiled_path}"],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=category  # Executa na pasta da categoria
                )
            elif tool_name.endswith('.py'):
                # Executa o script Python
                process = subprocess.Popen(
                    [sys.executable, tool_name],
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=category  # Executa na pasta da categoria
                )
            else:
                console.print("[bold red]Tipo de arquivo não suportado![/bold red]")
                console.input("\nPressione Enter para continuar...")
                return
                
            process.wait()
            
            if process.returncode != 0:
                console.print(f"[bold red]Erro ao executar (código {process.returncode})[/bold red]")
        
        except Exception as e:
            console.print(f"[bold red]Erro ao executar: {str(e)}[/bold red]")
        
        console.input("\nPressione Enter para continuar...")

    def run(self):
        while True:
            choice = self.show_main_menu()
            
            if choice == "1":
                self.show_category_menu("OSINT")
            elif choice == "2":
                self.show_category_menu("malwer")
            elif choice == "3":
                self.show_category_menu("scanner")
            elif choice == "4":
                self.show_category_menu("brute")
            elif choice == "5":
                self.show_category_menu("sql-inject")
            elif choice == "6":
                self.show_category_menu("span")
            elif choice == "7":
                self.show_category_menu("phishing")
            elif choice == "8":
                self.show_category_menu("xss")
            elif choice == "9":
                self.show_category_menu("git-exposto")
            elif choice == "10":
                self.show_category_menu("dos")
            elif choice == "11":
                self.show_category_menu("ddos")
            elif choice == "12":
                self.show_category_menu("dox")
            elif choice == "13":
                self.show_category_menu("zero-day-leve")
            elif choice == "14":
                self.show_category_menu("testes-rede")
            elif choice == "15":
                self.show_category_menu("linux")
            elif choice == "16":
                self.show_category_menu("vpn")
            elif choice == "17":
                self.show_category_menu("wi-fi")
            elif choice == "18":
                self.show_category_menu("bluetooth")
            elif choice == "19":
                self.show_category_menu("extras")
            elif choice == "0":
                console.print("[bold red]Saindo do sistema...[/bold red]")
                time.sleep(1)
                sys.exit(0)
            else:
                console.print("[bold red]Opção inválida![/bold red]")
                time.sleep(1)

if __name__ == "__main__":
    try:
        menu = HackerMenu()
        menu.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrompido pelo usuário[/bold red]")
        sys.exit(0)


#Além do tempo, além do espaço,
#navego na sombra de um sonho voraz.
#A luz de um buraco, o frio do vazio,
#me chamam sem voz, me puxam pra trás.

#Giram os planetas, o destino se rompe,
#num mar de estrelas que esqueceu seu final.
#O amor é um código, um ponto no mapa,
#uma equação que não soube decifrar.

#—Espera, espera—, sussurra o eco,
#de um canto da eternidade.
#Mas eu sigo caindo na escuridão,
#entre a saudade e a gravidade.

#minha musica Habits-vitage 1930 jazz
#obgd por me molestar na infancia
