import os
import subprocess

# Verifica se a ferramenta já foi baixada
if os.path.exists("Mr.Holmes"):
    print("Ferramenta já instalada, executando...")
    os.chdir("Mr.Holmes")
    os.system("./install_Termux.sh")
else:
    print("Instalando Mr.Holmes...")
    os.system("pkg install proot -y")
    os.system("git clone https://github.com/Lucksi/Mr.Holmes")
    os.chdir("Mr.Holmes")
    os.system("proot -0 chmod +x install_Termux.sh")
    os.system("./install_Termux.sh")
