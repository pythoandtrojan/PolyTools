import os
import sys
import time
from colorama import init, Fore, Style

# Inicializa o Colorama para que as cores funcionem no Termux/Windows
init()

# Cores e Estilos usando Colorama
class C:
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL

# Função para limpar a tela
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

# Função para pausar e continuar
def press_enter_to_continue():
    print(f"\n{C.YELLOW}{C.BRIGHT}[!] Pressione ENTER para continuar...{C.RESET}")
    input()
    clear_screen()

# Função para exibir o banner da lupa com 1s e 0s
def display_magnifying_glass_banner():
    print(f"{C.CYAN}{C.BRIGHT}")
    print("      000000000000000000000")
    print("    0000000000000000000000000")
    print("   000000000000000000000000000")
    print("  00000000000000000000000000000")
    print(" 0000000000000000000000000000000")
    print(" 0000000000000000000000000000000")
    print(" 0000000000000000000000000000000")
    print("  00000000000000000000000000000")
    print("   000000000000000000000000000")
    print("    0000000000000000000000000")
    print("      000000000000000000000")
    print("            00000")
    print("            00000")
    print("            00000")
    print("            00000")
    print("           0000000")
    print("          000000000")
    print("         00000000000")
    print("   " + " " * 7 + f"{C.YELLOW}{C.BRIGHT}Sherlock Automator{C.CYAN}") # Centralizando texto
    print("------------------------------------")
    print(f"{C.RESET}")

# Função para instalar o Sherlock (com opção de recusar)
def install_sherlock_if_needed():
    print(f"{C.YELLOW}{C.BRIGHT}[*] Verificando instalação do Sherlock...{C.RESET}")
    try:
        import sherlock
        print(f"{C.GREEN}[+] Sherlock já está instalado.{C.RESET}")
        return True
    except ImportError:
        print(f"{C.RED}[-] Sherlock não encontrado.{C.RESET}")
        confirm = input(f"{C.YELLOW}Deseja instalar o Sherlock agora? (s/N): {C.RESET}").lower()
        if confirm == 's':
            print(f"{C.YELLOW}[*] Iniciando instalação... Isso pode levar alguns minutos.{C.RESET}")
            os.system('pkg update -y')
            os.system('pkg install git python -y')
            
            if not os.path.exists('sherlock'):
                print(f"{C.YELLOW}[*] Clonando repositório do Sherlock...{C.RESET}")
                os.system('git clone https://github.com/sherlock-project/sherlock.git')
            else:
                print(f"{C.YELLOW}[*] Repositório do Sherlock já existe. Pulando clone.{C.RESET}")
            
            print(f"{C.YELLOW}[*] Instalando dependências do Sherlock...{C.RESET}")
            # Garante que o pip instale no ambiente correto
            os.system('pip install -r sherlock/requirements.txt') 
            
            try:
                import sherlock # Tenta importar novamente após a instalação
                print(f"{C.GREEN}[+] Sherlock instalado com sucesso!{C.RESET}")
                return True
            except ImportError:
                print(f"{C.RED}[-] Falha na instalação do Sherlock. Verifique sua conexão ou permissões.{C.RESET}")
                return False
        else:
            print(f"{C.RED}[!] Instalação do Sherlock recusada. Algumas funcionalidades podem não funcionar.{C.RESET}")
            return False
    finally:
        press_enter_to_continue()

# Função para executar comandos do Sherlock
def run_sherlock_command(username, options=""):
    if not is_sherlock_installed(): # Verifica se o Sherlock está disponível antes de tentar executar
        print(f"{C.RED}[-] Sherlock não está instalado. Por favor, instale-o para usar esta função.{C.RESET}")
        press_enter_to_continue()
        return

    command = f"python sherlock/sherlock.py {username} {options}"
    print(f"\n{C.YELLOW}{C.BRIGHT}[!] Executando comando:{C.RESET} {command}\n")
    try:
        os.system(command)
        print(f"\n{C.GREEN}[+] Comando executado com sucesso!{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}[-] Erro ao executar o comando: {e}{C.RESET}")
        print(f"{C.RED}[-] Verifique a sintaxe ou a instalação do Sherlock.{C.RESET}")
    press_enter_to_continue()

# Variável global para rastrear se o Sherlock está instalado
_sherlock_status = False

def is_sherlock_installed():
    global _sherlock_status
    try:
        import sherlock
        _sherlock_status = True
    except ImportError:
        _sherlock_status = False
    return _sherlock_status

# --- Funções de Busca (sem alterações significativas na lógica) ---

def search_specific_sites():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    sites = input(f"{C.BLUE}Digite os sites (separados por vírgula, ex: facebook,twitter): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' nos sites: {sites}...{C.RESET}")
    run_sherlock_command(username, f"--site {sites}")

def search_all_sites():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' em todos os sites...{C.RESET}")
    run_sherlock_command(username)

def search_ignore_sites():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    ignored_sites = input(f"{C.BLUE}Digite os sites a serem ignorados (separados por vírgula, ex: reddit,instagram): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' ignorando os sites: {ignored_sites}...{C.RESET}")
    run_sherlock_command(username, f"--ns {ignored_sites}")

def search_with_timeout():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    timeout = input(f"{C.BLUE}Digite o tempo limite em segundos (ex: 30): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' com tempo limite de {timeout} segundos...{C.RESET}")
    run_sherlock_command(username, f"--timeout {timeout}")

def search_with_proxy():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    proxy_address = input(f"{C.BLUE}Digite o endereço do proxy SOCKS5 (ex: socks5://127.0.0.1:9050): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' com proxy: {proxy_address}...{C.RESET}")
    run_sherlock_command(username, f"--proxy {proxy_address}")

def search_verbose():
    username = input(f"{C.BLUE}Digite o nome de usuário a ser buscado: {C.RESET}")
    print(f"\n{C.YELLOW}[*] Buscando '{username}' com resultados detalhados...{C.RESET}")
    run_sherlock_command(username, "--verbose")

# --- Funções de Download/Saída (sem alterações significativas na lógica) ---

def download_txt():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo TXT para salvar (ex: resultados.txt): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Salvando resultados para '{username}' em {filename} (formato TXT)...{C.RESET}")
    run_sherlock_command(username, f"--output {filename}")

def download_json():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo JSON para salvar (ex: resultados.json): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Salvando resultados para '{username}' em {filename} (formato JSON)...{C.RESET}")
    run_sherlock_command(username, f"--output {filename} --json")

def download_csv():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo CSV para salvar (ex: resultados.csv): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Salvando resultados para '{username}' em {filename} (formato CSV)...{C.RESET}")
    run_sherlock_command(username, f"--output {filename} --csv")

def download_html():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo HTML para salvar (ex: resultados.html): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Salvando resultados detalhados para '{username}' em {filename} (formato HTML)...{C.RESET}")
    run_sherlock_command(username, f"--output {filename} --html")

def download_pdf():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo PDF para salvar (ex: resultados.pdf): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Gerando relatório PDF para '{username}' em {filename}...{C.RESET}")
    print(f"{C.RED}[!] O Sherlock não gera PDF diretamente. Considere salvar em HTML e converter manualmente usando ferramentas como wkhtmltopdf (que precisaria ser instalada separadamente).{C.RESET}")
    press_enter_to_continue()

def download_found_only():
    username = input(f"{C.BLUE}Digite o nome de usuário que você buscou ou deseja baixar os resultados: {C.RESET}")
    filename = input(f"{C.BLUE}Digite o nome do arquivo TXT para salvar os usuários encontrados (ex: encontrados.txt): {C.RESET}")
    print(f"\n{C.YELLOW}[*] Salvando apenas usuários encontrados para '{username}' em {filename}...{C.RESET}")
    run_sherlock_command(username, f"--output {filename} --found")

# Função principal do menu
def main_menu():
    global _sherlock_status # Acessa a variável global
    while True:
        clear_screen()
        display_magnifying_glass_banner()
        print(f"{C.CYAN}{C.BRIGHT}## Menu Principal{C.RESET}")
        print("------------------------------------")
        
        # Indica o status do Sherlock
        if _sherlock_status:
            print(f"{C.GREEN}[STATUS]{C.RESET} Sherlock: {C.GREEN}INSTALADO{C.RESET}")
        else:
            print(f"{C.RED}[STATUS]{C.RESET} Sherlock: {C.RED}NÃO INSTALADO{C.RESET}")
        print("------------------------------------")

        print(f"1. {C.GREEN}Buscar Usuário em Sites Específicos{C.RESET}")
        print(f"2. {C.GREEN}Buscar Usuário em Todos os Sites (Padrão){C.RESET}")
        print(f"3. {C.GREEN}Buscar Usuário Ignorando Sites{C.RESET}")
        print(f"4. {C.GREEN}Buscar Usuário com Tempo Limite{C.RESET}")
        print(f"5. {C.GREEN}Buscar Usuário com Proxy (SOCKS5){C.RESET}")
        print(f"6. {C.GREEN}Buscar Usuário com Resultado Detalhado{C.RESET}")
        print("---")
        print(f"{C.CYAN}{C.BRIGHT}## Opções de Download/Saída{C.RESET}")
        print("------------------------------------")
        print(f"7. {C.YELLOW}Salvar Resultados em Arquivo TXT{C.RESET}")
        print(f"8. {C.YELLOW}Salvar Resultados em Arquivo JSON{C.RESET}")
        print(f"9. {C.YELLOW}Salvar Resultados em Arquivo CSV{C.RESET}")
        print(f"10. {C.YELLOW}Salvar Resultados Detalhados (HTML){C.RESET}")
        print(f"11. {C.RED}Gerar Relatório PDF (Atenção!){C.RESET}")
        print(f"12. {C.YELLOW}Salvar Apenas Usuários Encontrados{C.RESET}")
        print("---")
        
        # Opção para instalar/reinstalar o Sherlock, se necessário
        if not _sherlock_status:
            print(f"13. {C.MAGENTA}Instalar/Reinstalar Sherlock{C.RESET}")
        
        print(f"0. {C.RED}Sair{C.RESET}")
        print("------------------------------------")

        choice = input(f"{C.BLUE}Escolha uma opção: {C.RESET}")

        if choice == '1':
            search_specific_sites()
        elif choice == '2':
            search_all_sites()
        elif choice == '3':
            search_ignore_sites()
        elif choice == '4':
            search_with_timeout()
        elif choice == '5':
            search_with_proxy()
        elif choice == '6':
            search_verbose()
        elif choice == '7':
            download_txt()
        elif choice == '8':
            download_json()
        elif choice == '9':
            download_csv()
        elif choice == '10':
            download_html()
        elif choice == '11':
            download_pdf()
        elif choice == '12':
            download_found_only()
        elif choice == '13' and not _sherlock_status:
            _sherlock_status = install_sherlock_if_needed() # Tenta instalar e atualiza o status
        elif choice == '0':
            print(f"{C.GREEN}[*] Saindo... Até mais!{C.RESET}")
            sys.exit(0)
        else:
            print(f"{C.RED}[!] Opção inválida ou Sherlock não está disponível para esta ação. Tente novamente.{C.RESET}")
            press_enter_to_continue()

# --- Início do Script ---
if __name__ == "__main__":
    clear_screen()
    # Pergunta ao usuário se ele quer instalar o Sherlock no início
    _sherlock_status = install_sherlock_if_needed() 
    main_menu()
