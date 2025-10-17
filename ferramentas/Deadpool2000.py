import os
import subprocess

# Verifica se a ferramenta já foi baixada
if os.path.exists("IPicker"):
    print("Ferramenta já instalada, executando...")
    os.chdir("IPicker")
    os.system("python3 ipicker.py")
else:
    print("Instalando IPicker...")
    os.system("apt-get install python3 -y")
    os.system("git clone https://github.com/Deadpool2000/IPicker.git")
    os.chdir("IPicker")
    os.system("pip install -r requirements.txt")
    os.system("python3 ipicker.py")
