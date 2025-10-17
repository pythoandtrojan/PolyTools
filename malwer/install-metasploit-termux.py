import os
import subprocess

# Obtém o diretório atual do script
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# Clone e instalação básica
os.system('git clone https://github.com/gushmazuko/metasploit_in_termux.git')
os.chdir("metasploit_in_termux")
os.system('chmod +x metasploit.sh')
os.system('bash metasploit.sh')

# Detecta e instala gems faltantes
print("Verificando gems faltantes...")
result = subprocess.run('gem list', shell=True, capture_output=True, text=True)
gems_instaladas = result.stdout

gems_necessarias = ['bundler', 'nokogiri', 'pg', 'sqlite3', 'puma', 'rake', 'rspec', 'metasploit-framework']

for gem in gems_necessarias:
    if gem not in gems_instaladas:
        print(f"Instalando {gem}...")
        os.system(f'gem install {gem}')

print("Instalação concluída!")
