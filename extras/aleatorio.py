import random
import string
from datetime import datetime, timedelta

def gerar_serial_simples(comprimento=16, grupos=4, separador='-'):
    """Gera um número de serial simples no formato XXXX-XXXX-XXXX-XXXX"""
    caracteres = string.ascii_uppercase + string.digits
    grupos_serial = []
    
    for _ in range(grupos):
        grupo = ''.join(random.choice(caracteres) for _ in range(comprimento // grupos))
        grupos_serial.append(grupo)
    
    return separador.join(grupos_serial)

def gerar_serial_windows():
    """Gera um serial no estilo Windows (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"""
    return '-'.join([''.join(random.choices(string.digits + string.ascii_uppercase, k=5)) for _ in range(5)])

def gerar_serial_office():
    """Gera um serial no estilo Microsoft Office"""
    return f"{random.randint(10000, 99999)}-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}"

def gerar_serial_mac():
    """Gera um serial no estilo Apple/Mac"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

def gerar_serial_data():
    """Gera um serial baseado em data (YYMMDD-XXXXXX)"""
    data = datetime.now() - timedelta(days=random.randint(0, 365))
    data_str = data.strftime("%y%m%d")
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"{data_str}-{random_str}"

def gerar_serial_hex(comprimento=20):
    """Gera um serial em hexadecimal"""
    hex_digits = '0123456789ABCDEF'
    return ''.join(random.choice(hex_digits) for _ in range(comprimento))

def gerar_serial_com_checksum():
    """Gera um serial com dígito verificador fake"""
    base = ''.join(random.choices(string.digits, k=15))
    checksum = str(random.randint(0, 9))  # Checksum fake
    return f"{base[:5]}-{base[5:10]}-{base[10:15]}-{checksum}"

def gerar_serial_jogos():
    """Gera um serial no estilo de jogos"""
    return f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"

def mostrar_menu():
    """Exibe o menu de opções"""
    print("🔑 GERADOR DE NÚMEROS DE SÉRIE (KEYGEN FAKE)")
    print("=" * 50)
    print("[1] ➤ Serial Simples (XXXX-XXXX-XXXX-XXXX)")
    print("[2] ➤ Serial Estilo Windows")
    print("[3] ➤ Serial Estilo Microsoft Office")
    print("[4] ➤ Serial Estilo Apple/Mac")
    print("[5] ➤ Serial com Data (YYMMDD-XXXXXX)")
    print("[6] ➤ Serial Hexadecimal")
    print("[7] ➤ Serial com Checksum")
    print("[8] ➤ Serial para Jogos")
    print("[9] ➤ Gerar Todos os Tipos")
    print("[0] ➤ Sair")
    print("=" * 50)

def main():
    while True:
        mostrar_menu()
        
        try:
            opcao = input("\n📋 Escolha uma opção (0-9): ").strip()
            
            if opcao == '0':
                print("👋 Saindo do programa...")
                break
            
            elif opcao == '1':
                quantidade = int(input("Quantos seriais deseja gerar? "))
                comprimento = int(input("Comprimento total (ex: 16): ") or "16")
                grupos = int(input("Número de grupos (ex: 4): ") or "4")
                
                print("\n🔑 Seriais Gerados:")
                print("=" * 40)
                for i in range(quantidade):
                    serial = gerar_serial_simples(comprimento, grupos)
                    print(f"Serial {i + 1}: {serial}")
                
            elif opcao in ['2', '3', '4', '5', '6', '7', '8']:
                quantidade = int(input("Quantos seriais deseja gerar? "))
                
                geradores = {
                    '2': gerar_serial_windows,
                    '3': gerar_serial_office,
                    '4': gerar_serial_mac,
                    '5': gerar_serial_data,
                    '6': gerar_serial_hex,
                    '7': gerar_serial_com_checksum,
                    '8': gerar_serial_jogos
                }
                
                print(f"\n🔑 Seriais Gerados (Tipo {opcao}):")
                print("=" * 40)
                for i in range(quantidade):
                    serial = geradores[opcao]()
                    print(f"Serial {i + 1}: {serial}")
            
            elif opcao == '9':
                quantidade = int(input("Quantos seriais de cada tipo deseja gerar? "))
                
                todos_geradores = [
                    ("Simples", lambda: gerar_serial_simples()),
                    ("Windows", gerar_serial_windows),
                    ("Office", gerar_serial_office),
                    ("Mac", gerar_serial_mac),
                    ("Data", gerar_serial_data),
                    ("Hexadecimal", gerar_serial_hex),
                    ("Com Checksum", gerar_serial_com_checksum),
                    ("Jogos", gerar_serial_jogos)
                ]
                
                for nome, gerador in todos_geradores:
                    print(f"\n🔑 {nome}:")
                    print("-" * 30)
                    for i in range(quantidade):
                        serial = gerador()
                        print(f"  {i + 1}: {serial}")
            
            else:
                print("❌ Opção inválida! Escolha entre 0 e 9.")
                continue
            
            # Perguntar se quer continuar
            continuar = input("\n🔄 Deseja gerar mais seriais? (s/n): ").strip().lower()
            if continuar not in ['s', 'sim', 'y', 'yes']:
                print("👋 Saindo do programa...")
                break
                
        except ValueError:
            print("❌ Erro: Digite um número válido!")
        except KeyboardInterrupt:
            print("\n👋 Programa interrompido pelo usuário.")
            break
        except Exception as e:
            print(f"❌ Erro inesperado: {e}")

        print("\n" + "=" * 50 + "\n")

    print("\n⚠️  ATENÇÃO: Estes são números de série FICTÍCIOS para fins educacionais.")
    print("Não utilize para ativar software ilegalmente!")

if __name__ == "__main__":
    main()
