#!/data/data/com.termux/files/usr/bin/python3
import os
import random
import base64
import sys
import time
from flask import Flask, render_template_string, request, redirect, url_for

# Cores para o terminal
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Banner da Valkiria
def show_banner():
    os.system('clear')
    print(f"""{colors.RED}
    ██╗   ██╗ █████╗ ██╗     ██╗  ██╗██╗██████╗ ██╗ █████╗
    ██║   ██║██╔══██╗██║     ██║ ██╔╝██║██╔══██╗██║██╔══██╗
    ██║   ██║███████║██║     █████╔╝ ██║██████╔╝██║███████║
    ╚██╗ ██╔╝██╔══██║██║     ██╔═██╗ ██║██╔══██╗██║██╔══██║
     ╚████╔╝ ██║  ██║███████╗██║  ██╗██║██║  ██║██║██║  ██║
      ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
    {colors.RESET}""")
    print(f"{colors.YELLOW}    Ferramenta de Disfarce de URLs - Valkiria Network{colors.RESET}\n")

# Gerar URL mascarada
def mask_url(original_url):
    # Codificar a URL original em base64
    encoded = base64.b64encode(original_url.encode()).decode()
    
    # Criar um domínio falso com caracteres especiais
    domains = [
        "link-seguro", "download-ok", "atualizacao-sistema",
        "docs-online", "verificacao-contas", "central-arquivos"
    ]
    
    fake_domain = random.choice(domains)
    tlds = [".com", ".net", ".org", ".info", ".live"]
    fake_tld = random.choice(tlds)
    
    # Criar parâmetros aleatórios
    params = {
        'id': random.randint(1000, 9999),
        'ref': random.randint(100, 999),
        'token': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
    }
    
    # Construir URL mascarada
    masked_url = f"https://{fake_domain}{fake_tld}/?{encoded}&"
    masked_url += "&".join([f"{k}={v}" for k,v in params.items()])
    
    return masked_url

# Gerar site educativo sobre phishing
def generate_phishing_site():
    site_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Aprenda Sobre Phishing</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        h1 {
            color: #d9534f;
            text-align: center;
        }
        .warning {
            background-color: #fcf8e3;
            border-left: 6px solid #f0ad4e;
            padding: 10px;
            margin: 20px 0;
        }
        .tip {
            background-color: #dff0d8;
            border-left: 6px solid #5cb85c;
            padding: 10px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>Educação em Segurança Digital</h1>
    
    <div class="warning">
        <h2>O que é Phishing?</h2>
        <p>Phishing é uma técnica fraudulenta onde criminosos tentam obter informações sensíveis como logins, senhas e dados bancários, se passando por entidades confiáveis.</p>
    </div>
    
    <div class="tip">
        <h2>Como Identificar Phishing?</h2>
        <ul>
            <li>Verifique sempre o URL do site</li>
            <li>Desconfie de emails pedindo informações pessoais</li>
            <li>Observe erros gramaticais e ortográficos</li>
            <li>Não clique em links suspeitos</li>
        </ul>
    </div>
    
    <div class="warning">
        <h2>Técnicas Comuns de Phishing</h2>
        <p>Algumas técnicas que os criminosos usam:</p>
        <ol>
            <li>Links mascarados que parecem legítimos</li>
            <li>Sites falsos idênticos aos originais</li>
            <li>Urgência falsa ("sua conta será bloqueada")</li>
            <li>Ofertas boas demais para ser verdade</li>
        </ol>
    </div>
    
    <div class="tip">
        <h2>Como se Proteger?</h2>
        <ul>
            <li>Use autenticação em dois fatores</li>
            <li>Verifique o certificado SSL do site</li>
            <li>Mantenha seu antivírus atualizado</li>
            <li>Nunca reuse senhas entre sites</li>
        </ul>
    </div>
    
    <footer>
        <p>Material fornecido por Valkiria Security Research</p>
    </footer>
</body>
</html>
    """
    
    # Criar diretório se não existir
    if not os.path.exists("phishing_site"):
        os.makedirs("phishing_site")
    
    # Salvar o site
    with open("phishing_site/index.html", "w") as f:
        f.write(site_content)
    
    return os.path.abspath("phishing_site")

# Menu principal
def main_menu():
    show_banner()
    print(f"{colors.BOLD}Menu Principal:{colors.RESET}")
    print(f"{colors.GREEN}[1]{colors.RESET} Mascarar URL")
    print(f"{colors.GREEN}[2]{colors.RESET} Gerar Site Educativo sobre Phishing")
    print(f"{colors.GREEN}[3]{colors.RESET} Rodar Servidor Local")
    print(f"{colors.GREEN}[4]{colors.RESET} Sair")
    
    choice = input(f"\n{colors.BLUE}Selecione uma opção:{colors.RESET} ")
    
    if choice == "1":
        url = input(f"\n{colors.YELLOW}Digite a URL para mascarar:{colors.RESET} ")
        masked = mask_url(url)
        print(f"\n{colors.GREEN}URL Mascarada:{colors.RESET}")
        print(f"{colors.CYAN}{masked}{colors.RESET}")
        input("\nPressione Enter para continuar...")
        main_menu()
    
    elif choice == "2":
        path = generate_phishing_site()
        print(f"\n{colors.GREEN}Site educativo gerado em:{colors.RESET}")
        print(f"{colors.CYAN}{path}{colors.RESET}")
        input("\nPressione Enter para continuar...")
        main_menu()
    
    elif choice == "3":
        print(f"\n{colors.YELLOW}Iniciando servidor local...{colors.RESET}")
        print(f"{colors.WHITE}Acesse http://localhost:5000 no seu navegador{colors.RESET}")
        print(f"{colors.RED}Pressione CTRL+C para parar o servidor{colors.RESET}")
        
        app = Flask(__name__)
        
        @app.route('/')
        def home():
            with open("phishing_site/index.html", "r") as f:
                return f.read()
        
        app.run(host='0.0.0.0', port=5000)
    
    elif choice == "4":
        print(f"\n{colors.MAGENTA}Saindo...{colors.RESET}")
        sys.exit()
    
    else:
        print(f"\n{colors.RED}Opção inválida!{colors.RESET}")
        time.sleep(1)
        main_menu()

if __name__ == "__main__":
    # Verificar se o Flask está instalado
    try:
        from flask import Flask
    except ImportError:
        print(f"{colors.RED}Erro: Flask não está instalado.{colors.RESET}")
        print("Instale com: pip install flask")
        sys.exit(1)
    
    main_menu()
