import os
import subprocess

# Verifica se a ferramenta já foi baixada
if os.path.exists("brazilwings"):
    print("executando...")
    os.chdir("brazilwings")
    os.system("python brazilwings.py")
else:
    print("Instalando BrazilWings...")
    os.system("termux-setup-storage")
    os.system("pkg install python -y")
    os.system("pkg install git -y")
    os.system("git clone https://github.com/gabrielkelzer/brazilwings")
    os.chdir("brazilwings")
    os.system("chmod +x *")
    os.system("python brazilwings.py")
