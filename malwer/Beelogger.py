#!/usr/bin/env python3
import os
import subprocess
import sys

def check_installed():
    return os.path.exists(".beelogger_installed")

def mark_installed():
    with open(".beelogger_installed", "w") as f:
        f.write("1")

def main():
    if check_installed():
        print("Beelogger já instalado.")
        os.chdir("Beelogger")
        if os.path.exists("beelogger.py"):
            subprocess.run([sys.executable, "beelogger.py"])
        else:
            print("Arquivo beelogger.py não encontrado!")
            print("Execute manualmente: cd Beelogger && python3 beelogger.py")
        return
    
    print("Instalando Beelogger...")
    
    # Clonar apenas se não existir
    if not os.path.exists("Beelogger"):
        subprocess.run(["git", "clone", "https://github.com/4w4k3/Beelogger.git"])
    
    os.chdir("Beelogger")
    
    # Instalar dependências
    print("Instalando dependências...")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "colorama"])
    
    mark_installed()
    
    # Executar
    if os.path.exists("beelogger.py"):
        print("Iniciando Beelogger...")
        subprocess.run([sys.executable, "beelogger.py"])
    else:
        print("beelogger.py não encontrado!")
        print("Estrutura de arquivos:")
        subprocess.run(["ls", "-la"])

if __name__ == "__main__":
    main()
