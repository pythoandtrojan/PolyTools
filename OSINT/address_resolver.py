import requests
import json
import os
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

def limpar_tela():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_banner():
    """Exibe o banner colorido"""
    print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "🗺️  SISTEMA DE BUSCA DE LOCALIZAÇÕES")
    print(Fore.CYAN + "=" * 60)
    print(Fore.GREEN + "API: OpenStreetMap Nominatim")
    print(Fore.CYAN + "=" * 60)
    print()

def buscar_localizacao(query):
    """Faz a busca na API do OpenStreetMap"""
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        'q': query,
        'format': 'json',
        'limit': 10,
        'addressdetails': 1
    }
    
    headers = {
        'User-Agent': 'SistemaBuscaLocalizacao/1.0'
    }
    
    try:
        print(Fore.YELLOW + f"🔍 Buscando: {query}")
        print(Fore.CYAN + "⏳ Conectando com a API..." + Style.RESET_ALL)
        
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        
        dados = response.json()
        
        if not dados:
            print(Fore.RED + "❌ Nenhum resultado encontrado!")
            return None
            
        return dados
        
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"❌ Erro na conexão: {e}")
        return None
    except json.JSONDecodeError:
        print(Fore.RED + "❌ Erro ao processar resposta da API")
        return None

def formatar_endereco(display_name):
    """Formata o endereço para exibição mais organizada"""
    partes = display_name.split(', ')
    if len(partes) > 3:
        return f"{partes[0]}\n📍 {', '.join(partes[1:])}"
    return display_name

def exibir_resultados(dados):
    """Exibe os resultados de forma organizada e colorida"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + f"🎯 RESULTADOS ENCONTRADOS: {len(dados)}")
    print(Fore.GREEN + "=" * 80)
    
    for i, local in enumerate(dados, 1):
        print(Fore.CYAN + f"\n📍 RESULTADO {i}:")
        print(Fore.WHITE + "─" * 50)
        
        # Nome do local
        if local.get('name'):
            print(Fore.YELLOW + f"🏛️  Nome: {local['name']}")
        
        # Tipo e classe
        tipo = local.get('type', 'N/A')
        classe = local.get('class', 'N/A')
        print(Fore.CYAN + f"📊 Tipo: {tipo} | Classe: {classe}")
        
        # Coordenadas
        lat = local.get('lat', 'N/A')
        lon = local.get('lon', 'N/A')
        print(Fore.GREEN + f"🌐 Coordenadas: Lat {lat} | Lon {lon}")
        
        # Endereço completo
        if local.get('display_name'):
            endereco_formatado = formatar_endereco(local['display_name'])
            print(Fore.WHITE + f"📫 Endereço:\n{endereco_formatado}")
        
        # Importância
        importancia = local.get('importance', 0)
        print(Fore.MAGENTA + f"⭐ Importância: {importancia:.4f}")
        
        # Bounding box se disponível
        if local.get('boundingbox'):
            bbox = local['boundingbox']
            print(Fore.BLUE + f"🗺️  Área: {bbox[0]}° a {bbox[1]}° N, {bbox[2]}° a {bbox[3]}° E")
        
        print(Fore.WHITE + "─" * 50)

def menu_principal():
    """Menu principal do sistema"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "📋 MENU PRINCIPAL")
        print(Fore.CYAN + "1. 🔍 Buscar localização")
        print(Fore.CYAN + "2. ℹ️  Sobre o sistema")
        print(Fore.RED + "3. 🚪 Sair")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-3): ").strip()
        
        if opcao == '1':
            menu_busca()
        elif opcao == '2':
            menu_sobre()
        elif opcao == '3':
            print(Fore.YELLOW + "\n👋 Obrigado por usar o sistema! Até logo!")
            break
        else:
            print(Fore.RED + "❌ Opção inválida! Tente novamente.")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_busca():
    """Menu de busca"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "🔍 MENU DE BUSCA")
    print(Fore.CYAN + "=" * 50)
    
    while True:
        print(Fore.WHITE + "\nOpções de busca:")
        print(Fore.CYAN + "1. 🔎 Buscar por nome do local")
        print(Fore.CYAN + "2. 🏠 Buscar por endereço")
        print(Fore.CYAN + "3. 🏙️  Buscar por cidade")
        print(Fore.CYAN + "4. ↩️  Voltar ao menu principal")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha o tipo de busca (1-4): ").strip()
        
        if opcao in ['1', '2', '3']:
            if opcao == '1':
                tipo = "nome do local"
            elif opcao == '2':
                tipo = "endereço completo"
            else:
                tipo = "cidade"
            
            print(Fore.YELLOW + f"\n📝 Busca por {tipo}")
            print(Fore.CYAN + "Exemplos:")
            if opcao == '1':
                print("   Torre Eiffel, Estátua da Liberdade, Cristo Redentor")
            elif opcao == '2':
                print("   Avenida Paulista, 1000, São Paulo, SP")
            else:
                print("   Paris, Rio de Janeiro, Tokyo")
            print()
            
            query = input(Fore.GREEN + f"🔍 Digite o {tipo}: ").strip()
            
            if query:
                limpar_tela()
                mostrar_banner()
                dados = buscar_localizacao(query)
                
                if dados:
                    exibir_resultados(dados)
                else:
                    print(Fore.RED + "❌ Não foi possível obter os dados.")
                
                input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
                limpar_tela()
                mostrar_banner()
                print(Fore.YELLOW + "🔍 MENU DE BUSCA")
                print(Fore.CYAN + "=" * 50)
            else:
                print(Fore.RED + "❌ Por favor, digite algo para buscar!")
                
        elif opcao == '4':
            break
        else:
            print(Fore.RED + "❌ Opção inválida! Tente novamente.")

def menu_sobre():
    """Menu sobre o sistema"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "ℹ️  SOBRE O SISTEMA")
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + """
📋 DESCRIÇÃO:
   Sistema de busca de localizações usando a API do OpenStreetMap Nominatim.
   Permite buscar por locais, endereços e cidades em todo o mundo.

🗺️  FONTE DOS DADOS:
   OpenStreetMap - Dados geográficos abertos e colaborativos

📊 INFORMAÇÕES OBTIDAS:
   • Nome do local
   • Coordenadas geográficas (Latitude/Longitude)
   • Endereço completo
   • Tipo e classificação
   • Importância do local
   • Área de abrangência

⚙️  TECNOLOGIAS:
   • Python 3
   • API Nominatim
   • Colorama para cores
   • Requests para HTTP

👨‍💻 DESENVOLVIDO PARA:
   Buscas geográficas educacionais e informativas
    """)
    
    print(Fore.CYAN + "=" * 50)
    input(Fore.YELLOW + "📝 Pressione Enter para voltar ao menu principal...")

def main():
    """Função principal"""
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n👋 Programa interrompido pelo usuário. Até logo!")
    except Exception as e:
        print(Fore.RED + f"\n❌ Erro inesperado: {e}")

if __name__ == "__main__":
    main()
