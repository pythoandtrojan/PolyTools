import os
import platform
import subprocess
import socket
import time
import sys
from datetime import datetime

def clear_screen():
    """Limpa a tela do terminal de acordo com o sistema operacional"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def display_banner():
    """Exibe um banner estilizado com símbolos de quadrados"""
    banner = """
    ██████╗ ██╗███╗   ██╗ ██████╗      ███████╗███████╗██████╗ ███████╗██████╗ 
    ██╔══██╗██║████╗  ██║██╔════╝      ██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
    ██████╔╝██║██╔██╗ ██║██║  ███╗     ███████╗█████╗  ██████╔╝█████╗  ██████╔╝
    ██╔═══╝ ██║██║╚██╗██║██║   ██║     ╚════██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
    ██║     ██║██║ ╚████║╚██████╔╝     ███████║███████╗██║  ██║███████╗██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """
    print("\033[92m" + banner + "\033[0m")
    print(" " * 20 + "\033[93mFerramentas de Rede Automatizadas v1.0\033[0m")
    print(" " * 25 + "\033[94mby Seu Nome\033[0m\n")

def menu():
    """Exibe o menu de ferramentas disponíveis"""
    print("\033[96m" + "═" * 50 + "\033[0m")
    print("\033[95mMENU PRINCIPAL - FERRAMENTAS DE REDE\033[0m")
    print("\033[96m" + "═" * 50 + "\033[0m")
    print("1. Ping")
    print("2. Traceroute")
    print("3. Teste de Velocidade")
    print("4. Verificar DNS")
    print("5. Whois")
    print("6. Verificar HTTP Headers")
    print("7. Teste de Portas TCP")
    print("8. GeoIP Lookup")
    print("9. Teste de Latência")
    print("10. Verificar Conectividade com a Internet")
    print("11. Scan de Rede Básico")
    print("0. Sair")
    print("\033[96m" + "═" * 50 + "\033[0m")

def run_ping():
    """Executa o comando ping para um host especificado"""
    try:
        host = input("Digite o endereço do host ou IP para ping: ")
        count = input("Número de pacotes (padrão 4): ") or "4"
        
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, count, host]
        
        print(f"\nExecutando ping para {host}...\n")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"\n\033[91mErro: Não foi possível alcançar {host}\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_traceroute():
    """Executa traceroute para um host especificado"""
    try:
        host = input("Digite o endereço do host ou IP para traceroute: ")
        
        if platform.system().lower() == "windows":
            command = ["tracert", host]
        else:
            command = ["traceroute", host]
        
        print(f"\nExecutando traceroute para {host}...\n")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"\n\033[91mErro: Não foi possível executar traceroute para {host}\033[0m")
    except FileNotFoundError:
        print("\n\033[91mErro: Traceroute não está instalado no seu sistema\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_speedtest():
    """Testa a velocidade da conexão com a internet"""
    try:
        print("\nPreparando teste de velocidade... (Isso pode levar alguns segundos)\n")
        import speedtest
        st = speedtest.Speedtest()
        
        print("Obtendo melhor servidor...")
        st.get_best_server()
        
        print("Testando velocidade de download...")
        download = st.download() / 1024 / 1024  # Convertendo para Mbps
        
        print("Testando velocidade de upload...")
        upload = st.upload() / 1024 / 1024  # Convertendo para Mbps
        
        print("\nResultados do Teste de Velocidade:")
        print(f"Download: {download:.2f} Mbps")
        print(f"Upload: {upload:.2f} Mbps")
        print(f"Ping: {st.results.ping:.2f} ms")
    except ImportError:
        print("\n\033[91mErro: Biblioteca speedtest-cli não instalada.")
        print("Instale com: pip install speedtest-cli\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro durante o teste de velocidade: {str(e)}\033[0m")

def run_dns_check():
    """Verifica os registros DNS de um domínio"""
    try:
        import dns.resolver
        domain = input("Digite o domínio para verificar DNS: ")
        
        print(f"\nVerificando registros DNS para {domain}...\n")
        
        # Verifica vários tipos de registros DNS
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                print(f"{record} Records:")
                for rdata in answers:
                    print(f"  {rdata.to_text()}")
                print()
            except dns.resolver.NoAnswer:
                print(f"{record} Records: Nenhum registro encontrado\n")
            except dns.resolver.NXDOMAIN:
                print(f"\n\033[91mErro: Domínio {domain} não existe\033[0m")
                return
            except Exception as e:
                print(f"Erro ao buscar {record} Records: {str(e)}\n")
                
    except ImportError:
        print("\n\033[91mErro: Biblioteca dnspython não instalada.")
        print("Instale com: pip install dnspython\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_whois():
    """Consulta informações WHOIS de um domínio"""
    try:
        import whois
        domain = input("Digite o domínio para consulta WHOIS: ")
        
        print(f"\nObtendo informações WHOIS para {domain}...\n")
        
        w = whois.whois(domain)
        
        print(f"Domínio: {w.domain_name}")
        print(f"Registrante: {w.registrar}")
        print(f"Data de criação: {w.creation_date}")
        print(f"Data de expiração: {w.expiration_date}")
        print(f"Servidores DNS: {w.name_servers}")
        print(f"Status: {w.status}")
        
    except ImportError:
        print("\n\033[91mErro: Biblioteca python-whois não instalada.")
        print("Instale com: pip install python-whois\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro durante consulta WHOIS: {str(e)}\033[0m")

def run_http_headers():
    """Obtém os cabeçalhos HTTP de um site"""
    try:
        import requests
        url = input("Digite a URL (ex: https://exemplo.com): ")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"\nObtendo cabeçalhos HTTP para {url}...\n")
        
        response = requests.head(url, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print("Cabeçalhos:")
        for header, value in response.headers.items():
            print(f"  {header}: {value}")
            
    except requests.exceptions.RequestException as e:
        print(f"\n\033[91mErro ao conectar com {url}: {str(e)}\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_port_test():
    """Testa se portas específicas estão abertas em um host"""
    try:
        host = input("Digite o endereço do host ou IP: ")
        ports_input = input("Digite as portas para testar (separadas por vírgula): ")
        ports = [int(p.strip()) for p in ports_input.split(',')]
        timeout = 2  # tempo limite em segundos
        
        print(f"\nTestando portas em {host}...\n")
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                print(f"Porta {port}: \033[92mABERTA\033[0m")
            else:
                print(f"Porta {port}: \033[91mFECHADA\033[0m")
            sock.close()
            
    except ValueError:
        print("\n\033[91mErro: Por favor, digite números válidos para as portas\033[0m")
    except socket.gaierror:
        print("\n\033[91mErro: Não foi possível resolver o nome do host\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_geoip_lookup():
    """Consulta informações de geolocalização de um IP"""
    try:
        import requests
        ip = input("Digite o endereço IP para consulta GeoIP: ")
        
        print(f"\nObtendo informações de geolocalização para {ip}...\n")
        
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data['status'] == 'success':
            print(f"País: {data['country']} ({data['countryCode']})")
            print(f"Região: {data['regionName']} ({data['region']})")
            print(f"Cidade: {data['city']}")
            print(f"CEP: {data['zip']}")
            print(f"Localização: {data['lat']}, {data['lon']}")
            print(f"Fuso Horário: {data['timezone']}")
            print(f"Provedor: {data['isp']}")
        else:
            print(f"\n\033[91mErro: {data['message']}\033[0m")
            
    except requests.exceptions.RequestException:
        print("\n\033[91mErro: Não foi possível conectar ao serviço GeoIP\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_latency_test():
    """Testa a latência para um host"""
    try:
        host = input("Digite o endereço do host ou IP para teste de latência: ")
        count = int(input("Número de tentativas (padrão 5): ") or "5")
        
        print(f"\nTestando latência para {host}...\n")
        
        total_time = 0
        successful_pings = 0
        
        for i in range(count):
            try:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                command = ["ping", param, "1", host]
                
                start_time = time.time()
                subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                end_time = time.time()
                
                latency = (end_time - start_time) * 1000  # Convertendo para ms
                total_time += latency
                successful_pings += 1
                
                print(f"Tentativa {i+1}: {latency:.2f} ms")
            except subprocess.CalledProcessError:
                print(f"Tentativa {i+1}: Falha")
        
        if successful_pings > 0:
            avg_latency = total_time / successful_pings
            print(f"\nLatência média: {avg_latency:.2f} ms")
            print(f"Taxa de sucesso: {successful_pings}/{count} ({successful_pings/count*100:.1f}%)")
        else:
            print("\n\033[91mErro: Nenhuma tentativa bem-sucedida\033[0m")
            
    except ValueError:
        print("\n\033[91mErro: Número de tentativas inválido\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_internet_connectivity():
    """Verifica a conectividade com a internet"""
    try:
        test_urls = [
            "https://www.google.com",
            "https://www.cloudflare.com",
            "https://www.amazon.com"
        ]
        
        print("\nVerificando conectividade com a internet...\n")
        
        import requests
        
        for url in test_urls:
            try:
                start_time = time.time()
                response = requests.get(url, timeout=5)
                end_time = time.time()
                
                if response.status_code == 200:
                    latency = (end_time - start_time) * 1000
                    print(f"\033[92m✓\033[0m {url} - {latency:.2f} ms")
                else:
                    print(f"\033[93m?\033[0m {url} - Status code: {response.status_code}")
            except requests.exceptions.RequestException:
                print(f"\033[91m✗\033[0m {url} - Falha na conexão")
                
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def run_network_scan():
    """Realiza um scan básico de rede local"""
    try:
        import netifaces
        
        print("\nObtendo informações de interfaces de rede...\n")
        
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            print(f"Interface: {iface}")
            
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get('addr', 'N/A')
                    netmask = addr_info.get('netmask', 'N/A')
                    print(f"  IPv4: {ip} / Máscara: {netmask}")
                    
            if netifaces.AF_INET6 in addrs:
                for addr_info in addrs[netifaces.AF_INET6]:
                    ip = addr_info.get('addr', 'N/A')
                    print(f"  IPv6: {ip}")
                    
            print()
            
    except ImportError:
        print("\n\033[91mErro: Biblioteca netifaces não instalada.")
        print("Instale com: pip install netifaces\033[0m")
    except Exception as e:
        print(f"\n\033[91mErro inesperado: {str(e)}\033[0m")

def main():
    """Função principal que executa o menu e as ferramentas"""
    clear_screen()
    display_banner()
    
    while True:
        menu()
        choice = input("\nEscolha uma ferramenta (0-11): ")
        
        try:
            choice = int(choice)
            clear_screen()
            display_banner()
            
            if choice == 0:
                print("\nObrigado por usar o Kit de Ferramentas de Rede!\n")
                break
            elif choice == 1:
                run_ping()
            elif choice == 2:
                run_traceroute()
            elif choice == 3:
                run_speedtest()
            elif choice == 4:
                run_dns_check()
            elif choice == 5:
                run_whois()
            elif choice == 6:
                run_http_headers()
            elif choice == 7:
                run_port_test()
            elif choice == 8:
                run_geoip_lookup()
            elif choice == 9:
                run_latency_test()
            elif choice == 10:
                run_internet_connectivity()
            elif choice == 11:
                run_network_scan()
            else:
                print("\n\033[91mOpção inválida! Por favor, escolha um número entre 0 e 11.\033[0m")
            
            input("\nPressione Enter para continuar...")
            clear_screen()
            display_banner()
            
        except ValueError:
            print("\n\033[91mErro: Por favor, digite um número válido.\033[0m")
            time.sleep(1)
            clear_screen()
            display_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrograma interrompido pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91mErro crítico: {str(e)}\033[0m")
        sys.exit(1)
