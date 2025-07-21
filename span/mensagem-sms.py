import requests
import time
from colorama import init, Fore, Back, Style
import os
import threading

# Inicializa colorama
init(autoreset=True)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    banner = f"""
{Fore.GREEN}╔════════════════════════════════════════════════════════════╗
{Fore.GREEN}║{Fore.WHITE}{Back.GREEN}                   SMS BOMBER v2.0                        {Back.RESET}{Fore.GREEN}║
{Fore.GREEN}║{Fore.WHITE}{Back.GREEN}            Ferramenta de envio em massa via APIs          {Back.RESET}{Fore.GREEN}║
{Fore.GREEN}╚════════════════════════════════════════════════════════════╝
{Fore.RESET}
    """
    print(banner)

def get_apis():
    """Retorna APIs gratuitas para envio de SMS"""
    return [
        {
            "name": "SMS Online (Brasil)",
            "url": "https://www.smsonline.com.br/sendsms.php",
            "params": {"numero": "", "msg": ""},
            "method": "GET",
            "working": True
        },
        {
            "name": "SMS Gateway (Internacional)",
            "url": "https://smsgateway.me/api/v3/messages/send",
            "params": {"number": "", "message": ""},
            "method": "POST",
            "working": False  # Necessário cadastro
        },
        {
            "name": "Twilio (Teste Gratuito)",
            "url": "https://api.twilio.com/2010-04-01/Accounts/ACXXXX/Messages.json",
            "params": {"To": "", "From": "+15005550006", "Body": ""},
            "method": "POST",
            "working": False  # Necessário API Key
        }
    ]

def send_sms(api, number, message, results):
    try:
        params = api["params"].copy()
        
        # Preenche os parâmetros
        for key in params:
            if "num" in key.lower() or "tel" in key.lower():
                params[key] = number
            elif "msg" in key.lower() or "body" in key.lower():
                params[key] = message
        
        # Envia a requisição
        if api["method"] == "GET":
            response = requests.get(api["url"], params=params, timeout=15)
        else:
            response = requests.post(api["url"], data=params, timeout=15)
        
        # Verifica o resultado
        if response.status_code == 200:
            results.append(f"{Fore.GREEN}[✓] {api['name']}: SMS enviado para {number}{Fore.RESET}")
        else:
            results.append(f"{Fore.RED}[✗] {api['name']}: Falha (Status {response.status_code}){Fore.RESET}")
    
    except Exception as e:
        results.append(f"{Fore.RED}[✗] {api['name']}: Erro - {str(e)}{Fore.RESET}")

def mass_send(numbers, message, threads=3):
    apis = [api for api in get_apis() if api["working"]]
    if not apis:
        print(f"{Fore.RED}[!] Nenhuma API disponível no momento{Fore.RESET}")
        return
    
    results = []
    print(f"\n{Fore.CYAN}[*] Iniciando envio para {len(numbers)} números...{Fore.RESET}")
    
    for number in numbers:
        print(f"\n{Fore.YELLOW}[*] Enviando para: {number}{Fore.RESET}")
        
        # Cria threads para envio simultâneo por diferentes APIs
        threads_list = []
        for api in apis:
            t = threading.Thread(target=send_sms, args=(api, number, message, results))
            threads_list.append(t)
            t.start()
            
            # Limita o número de threads simultâneas
            while threading.active_count() > threads:
                time.sleep(0.1)
        
        # Espera todas as threads terminarem
        for t in threads_list:
            t.join()
        
        # Exibe resultados em tempo real
        for result in results[-len(apis):]:
            print(f"    {result}")
        
        time.sleep(1)  # Evitar bloqueio por flood

def main():
    clear_terminal()
    display_banner()
    
    while True:
        print(f"\n{Fore.YELLOW}╔════════════════════ MENU ═══════════════════╗")
        print(f"{Fore.YELLOW}║ {Fore.CYAN}1. Enviar SMS em massa                  {Fore.YELLOW}║")
        print(f"{Fore.YELLOW}║ {Fore.CYAN}2. Testar APIs disponíveis              {Fore.YELLOW}║")
        print(f"{Fore.YELLOW}║ {Fore.CYAN}3. Sair                                {Fore.YELLOW}║")
        print(f"{Fore.YELLOW}╚══════════════════════════════════════════╝{Fore.RESET}")
        
        choice = input(f"\n{Fore.YELLOW}[?] Selecione uma opção (1-3): {Fore.RESET}").strip()
        
        if choice == '1':
            print(f"\n{Fore.CYAN}[*] Modo de envio em massa{Fore.RESET}")
            
            # Entrada de números
            input_numbers = input(f"{Fore.YELLOW}[?] Digite os números (separados por vírgula): {Fore.RESET}").strip()
            numbers = [num.strip() for num in input_numbers.split(",") if num.strip()]
            
            # Validação
            if not numbers:
                print(f"{Fore.RED}[!] Insira pelo menos um número{Fore.RESET}")
                time.sleep(1)
                continue
                
            # Entrada da mensagem
            message = input(f"{Fore.YELLOW}[?] Digite a mensagem: {Fore.RESET}").strip()
            if not message:
                print(f"{Fore.RED}[!] A mensagem não pode estar vazia{Fore.RESET}")
                time.sleep(1)
                continue
            
            # Confirmação
            print(f"\n{Fore.RED}[!] Você está prestes a enviar:")
            print(f"{Fore.YELLOW}Números: {Fore.WHITE}{len(numbers)}")
            print(f"{Fore.YELLOW}Mensagem: {Fore.WHITE}{message[:50]}...{Fore.RESET}")
            confirm = input(f"{Fore.RED}[?] Confirmar envio? (s/n): {Fore.RESET}").lower()
            
            if confirm == 's':
                mass_send(numbers, message)
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
            clear_terminal()
            
        elif choice == '2':
            print(f"\n{Fore.CYAN}[*] Testando APIs disponíveis{Fore.RESET}\n")
            apis = get_apis()
            
            for api in apis:
                status = f"{Fore.GREEN}ATIVA" if api["working"] else f"{Fore.RED}INATIVA (requer cadastro)"
                print(f"{Fore.WHITE}[+] {api['name']:<30} {status}{Fore.RESET}")
                print(f"    {Fore.CYAN}Método: {api['method']} | URL: {api['url']}{Fore.RESET}\n")
            
            input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Fore.RESET}")
            clear_terminal()
            
        elif choice == '3':
            print(f"\n{Fore.CYAN}[*] Saindo...{Fore.RESET}")
            time.sleep(1)
            clear_terminal()
            break
            
        else:
            print(f"\n{Fore.RED}[!] Opção inválida{Fore.RESET}")
            time.sleep(1)
            clear_terminal()

if __name__ == "__main__":
    main()
