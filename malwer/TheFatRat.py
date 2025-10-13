#!/usr/bin/env python3
"""
Script para clonar e executar o TheFatRat
Compatível com Linux e Termux
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

class TheFatRatInstaller:
    def __init__(self):
        self.repo_url = "https://github.com/screetsec/TheFatRat.git"
        self.clone_dir = "TheFatRat"
        self.installed_file = ".thefatrat_installed"
        
    def check_installation(self):
        """Verifica se já foi instalado anteriormente"""
        return os.path.exists(self.installed_file)
    
    def mark_installed(self):
        """Marca que a instalação foi concluída"""
        with open(self.installed_file, 'w') as f:
            f.write("installed")
    
    def run_command(self, command, shell=False):
        """Executa um comando e retorna o resultado"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, check=True, 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(command, check=True, 
                                      capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Erro ao executar comando: {e}")
            print(f"Stderr: {e.stderr}")
            return None
    
    def install_dependencies(self):
        """Instala as dependências necessárias"""
        print("Instalando dependências...")
        
        # Verificar se é Termux ou Linux normal
        if os.path.exists('/data/data/com.termux/files/usr/bin'):
            print("Detectado Termux")
            commands = [
                "pkg update -y",
                "pkg install -y git curl wget openjdk-17 zip unzip",
                "pkg install -y android-tools"
            ]
        else:
            print("Detectado Linux")
            # Detectar gerenciador de pacotes
            if shutil.which("apt-get"):
                commands = [
                    "sudo apt-get update",
                    "sudo apt-get install -y git curl wget openjdk-17-jdk zip unzip",
                    "sudo apt-get install -y android-sdk-build-tools"
                ]
            elif shutil.which("yum"):
                commands = [
                    "sudo yum update -y",
                    "sudo yum install -y git curl wget java-17-openjdk zip unzip",
                    "sudo yum install -y android-tools"
                ]
            elif shutil.which("pacman"):
                commands = [
                    "sudo pacman -Sy",
                    "sudo pacman -S --noconfirm git curl wget jdk17-openjdk zip unzip",
                    "sudo pacman -S --noconfirm android-tools"
                ]
            else:
                print("Gerenciador de pacotes não suportado. Instale manualmente:")
                print("- git, curl, wget, openjdk-17, zip, unzip, android-tools")
                return False
        
        for cmd in commands:
            print(f"Executando: {cmd}")
            result = self.run_command(cmd, shell=True)
            if result is None:
                print(f"Falha ao executar: {cmd}")
                return False
        
        return True
    
    def clone_repository(self):
        """Clona o repositório se não existir"""
        if os.path.exists(self.clone_dir):
            print("Repositório já existe. Usando versão existente.")
            return True
        
        print("Clonando o repositório...")
        result = self.run_command(["git", "clone", self.repo_url, self.clone_dir])
        if result is None:
            print("Falha ao clonar o repositório")
            return False
        
        print("Repositório clonado com sucesso!")
        return True
    
    def setup_fatrat(self):
        """Configura e executa o TheFatRat"""
        os.chdir(self.clone_dir)
        
        # Dar permissões de execução aos scripts
        print("Configurando permissões...")
        self.run_command("chmod +x setup.sh", shell=True)
        self.run_command("chmod +x fatrat", shell=True)
        self.run_command("chmod +x update", shell=True)
        
        # Executar setup
        print("Executando setup...")
        result = self.run_command("./setup.sh", shell=True)
        if result is None:
            print("Falha no setup. Tentando continuar...")
        
        # Voltar ao diretório anterior
        os.chdir("..")
        
        return True
    
    def run_fatrat(self):
        """Executa o TheFatRat"""
        if not os.path.exists(os.path.join(self.clone_dir, "fatrat")):
            print("TheFatRat não foi instalado corretamente")
            return False
        
        print("Iniciando TheFatRat...")
        os.chdir(self.clone_dir)
        
        # Executar o fatrat
        try:
            subprocess.run(["./fatrat"], check=True)
        except KeyboardInterrupt:
            print("\nTheFatRat fechado pelo usuário")
        except Exception as e:
            print(f"Erro ao executar TheFatRat: {e}")
        
        # Voltar ao diretório anterior
        os.chdir("..")
        return True
    
    def main(self):
        """Função principal"""
        print("=" * 50)
        print("    INSTALADOR THEFATRAT")
        print("=" * 50)
        
        # Verificar se git está instalado
        if not shutil.which("git"):
            print("Git não está instalado. Instalando...")
            if not self.install_dependencies():
                print("Falha ao instalar dependências")
                sys.exit(1)
        
        # Verificar se já foi instalado
        if self.check_installation():
            print("TheFatRat já foi instalado anteriormente.")
            choice = input("Deseja executá-lo? (s/N): ").lower()
            if choice == 's':
                self.run_fatrat()
            return
        
        # Instalar dependências
        if not self.install_dependencies():
            print("Falha na instalação das dependências")
            sys.exit(1)
        
        # Clonar repositório
        if not self.clone_repository():
            print("Falha ao clonar repositório")
            sys.exit(1)
        
        # Configurar
        if not self.setup_fatrat():
            print("Falha na configuração")
            sys.exit(1)
        
        # Marcar como instalado
        self.mark_installed()
        
        # Executar
        print("Instalação concluída com sucesso!")
        choice = input("Deseja executar o TheFatRat agora? (s/N): ").lower()
        if choice == 's':
            self.run_fatrat()

if __name__ == "__main__":
    installer = TheFatRatInstaller()
    installer.main()
