import requests
import json
import os
from datetime import datetime
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

def limpar_tela():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_banner():
    """Exibe o banner colorido"""
    print(Fore.CYAN + "=" * 70)
    print(Fore.YELLOW + "📚 SISTEMA DE BUSCA ACADÊMICA - CROSSREF")
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + "🏛️  Registro oficial de DOI - Digital Object Identifier")
    print(Fore.CYAN + "=" * 70)
    print()

def buscar_publicacoes(tipo_busca, query, rows=10):
    """Faz a busca na API Crossref"""
    base_url = "https://api.crossref.org/works"
    
    params = {
        'rows': rows
    }
    
    # Definir parâmetros baseados no tipo de busca
    if tipo_busca == 'autor':
        params['query.author'] = query
    elif tipo_busca == 'titulo':
        params['query.title'] = query
    elif tipo_busca == 'assunto':
        params['query'] = query
    elif tipo_busca == 'doi':
        # Busca direta por DOI
        url = f"{base_url}/{query}"
        params = {}
    else:
        params['query'] = query
    
    headers = {
        'User-Agent': 'SistemaAcademico/1.0 (mailto:pesquisador@universidade.edu)',
        'Accept': 'application/json'
    }
    
    try:
        print(Fore.YELLOW + f"🔍 Buscando: {query}")
        print(Fore.CYAN + f"📊 Tipo: {tipo_busca.upper()} | Resultados: {rows}")
        print(Fore.CYAN + "⏳ Conectando com a Crossref API..." + Style.RESET_ALL)
        
        if tipo_busca == 'doi':
            response = requests.get(url, headers=headers)
        else:
            response = requests.get(base_url, params=params, headers=headers)
        
        response.raise_for_status()
        dados = response.json()
        
        if tipo_busca == 'doi':
            # Formata resposta de busca por DOI
            return {'items': [dados['message']], 'total-results': 1}
        else:
            return dados['message']
        
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"❌ Erro na conexão: {e}")
        return None
    except json.JSONDecodeError:
        print(Fore.RED + "❌ Erro ao processar resposta da API")
        return None
    except KeyError as e:
        print(Fore.RED + f"❌ Erro na estrutura dos dados: {e}")
        return None

def formatar_autores(authors):
    """Formata lista de autores para exibição"""
    if not authors:
        return "N/A"
    
    nomes_autores = []
    for author in authors:
        nome = ""
        if author.get('given'):
            nome += author['given']
        if author.get('family'):
            if nome:
                nome += " "
            nome += author['family']
        if nome:
            nomes_autores.append(nome)
    
    return ", ".join(nomes_autores[:3]) + ("..." if len(nomes_autores) > 3 else "")

def formatar_data(data_string):
    """Formata data para exibição amigável"""
    if not data_string or not data_string.get('date-parts'):
        return "N/A"
    
    try:
        date_parts = data_string['date-parts'][0]
        if len(date_parts) >= 3:
            return f"{date_parts[2]:02d}/{date_parts[1]:02d}/{date_parts[0]}"
        elif len(date_parts) >= 2:
            return f"{date_parts[1]:02d}/{date_parts[0]}"
        else:
            return str(date_parts[0])
    except:
        return "N/A"

def exibir_resultados_publicacoes(dados, tipo_busca, query):
    """Exibe os resultados de publicações de forma organizada"""
    if not dados or 'items' not in dados:
        print(Fore.RED + "❌ Nenhum resultado encontrado!")
        return
    
    total = dados.get('total-results', 0)
    items = dados['items']
    
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + f"📊 RESULTADOS ENCONTRADOS: {total}")
    print(Fore.WHITE + f"🔍 Busca: {tipo_busca.upper()} - '{query}'")
    print(Fore.GREEN + "=" * 80)
    
    for i, pub in enumerate(items, 1):
        print(Fore.CYAN + f"\n📄 PUBLICAÇÃO {i}:")
        print(Fore.WHITE + "─" * 60)
        
        # Título
        titulo = pub.get('title', ['Título não disponível'])[0] if pub.get('title') else "Título não disponível"
        print(Fore.YELLOW + f"📖 Título: {titulo}")
        
        # Autores
        autores = formatar_autores(pub.get('author', []))
        print(Fore.CYAN + f"👥 Autores: {autores}")
        
        # DOI
        doi = pub.get('DOI', 'N/A')
        print(Fore.GREEN + f"🔗 DOI: {doi}")
        
        # Tipo
        tipo = pub.get('type', 'N/A').upper()
        print(Fore.MAGENTA + f"📊 Tipo: {tipo}")
        
        # Data de publicação
        data = formatar_data(pub.get('published', {}))
        print(Fore.BLUE + f"📅 Publicado: {data}")
        
        # Journal/Publisher
        if pub.get('container-title'):
            journal = pub['container-title'][0]
            print(Fore.WHITE + f"🏛️  Periódico: {journal}")
        elif pub.get('publisher'):
            print(Fore.WHITE + f"🏢 Editora: {pub.get('publisher')}")
        
        # URL
        if pub.get('URL'):
            print(Fore.CYAN + f"🌐 URL: {pub.get('URL')}")
        
        # Contagem de citações
        ref_count = pub.get('references-count', 'N/A')
        cit_count = pub.get('is-referenced-by-count', 'N/A')
        print(Fore.GREEN + f"📈 Citações: Referências: {ref_count} | Citado por: {cit_count}")
        
        # Assuntos
        if pub.get('subject'):
            assuntos = ", ".join(pub['subject'][:3])
            print(Fore.WHITE + f"🏷️  Assuntos: {assuntos}")
        
        print(Fore.WHITE + "─" * 60)

def exibir_detalhes_completos(pub):
    """Exibe detalhes completos de uma publicação"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "📋 DETALHES COMPLETOS DA PUBLICAÇÃO")
    print(Fore.GREEN + "=" * 80)
    
    # Informações básicas
    titulo = pub.get('title', ['Título não disponível'])[0] if pub.get('title') else "Título não disponível"
    print(Fore.YELLOW + f"📖 Título: {titulo}")
    
    # DOI
    doi = pub.get('DOI', 'N/A')
    print(Fore.GREEN + f"🔗 DOI: {doi}")
    
    # Autores completos
    autores = pub.get('author', [])
    if autores:
        print(Fore.CYAN + "\n👥 AUTORES:")
        for i, author in enumerate(autores, 1):
            nome = ""
            if author.get('given'):
                nome += author['given']
            if author.get('family'):
                if nome:
                    nome += " "
                nome += author['family']
            afiliacao = author.get('affiliation', [{}])[0].get('name', 'N/A')
            print(Fore.WHITE + f"   {i}. {nome} | Afiliação: {afiliacao}")
    
    # Metadados da publicação
    print(Fore.CYAN + "\n📊 METADADOS:")
    print(Fore.WHITE + f"   Tipo: {pub.get('type', 'N/A').upper()}")
    print(Fore.WHITE + f"   Publicado: {formatar_data(pub.get('published', {}))}")
    
    if pub.get('container-title'):
        journal = pub['container-title'][0]
        print(Fore.WHITE + f"   Periódico: {journal}")
    
    if pub.get('publisher'):
        print(Fore.WHITE + f"   Editora: {pub.get('publisher')}")
    
    if pub.get('volume'):
        print(Fore.WHITE + f"   Volume: {pub.get('volume')}")
    
    if pub.get('issue'):
        print(Fore.WHITE + f"   Edição: {pub.get('issue')}")
    
    if pub.get('page'):
        print(Fore.WHITE + f"   Páginas: {pub.get('page')}")
    
    # Estatísticas
    print(Fore.CYAN + "\n📈 ESTATÍSTICAS:")
    print(Fore.WHITE + f"   Contagem de referências: {pub.get('references-count', 'N/A')}")
    print(Fore.WHITE + f"   Citado por: {pub.get('is-referenced-by-count', 'N/A')}")
    
    # Assuntos
    if pub.get('subject'):
        print(Fore.CYAN + "\n🏷️  ASSUNTOS:")
        for assunto in pub['subject']:
            print(Fore.WHITE + f"   • {assunto}")
    
    # URL
    if pub.get('URL'):
        print(Fore.CYAN + f"\n🌐 URL: {pub.get('URL')}")
    
    # Abstract (se disponível)
    if pub.get('abstract'):
        abstract = pub['abstract']
        # Remover tags HTML se presentes
        import re
        abstract_limpo = re.sub('<[^<]+?>', '', abstract)
        print(Fore.CYAN + "\n📝 RESUMO:")
        print(Fore.WHITE + abstract_limpo[:300] + "..." if len(abstract_limpo) > 300 else abstract_limpo)

def menu_tipos_busca():
    """Menu para selecionar o tipo de busca"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "🔍 TIPOS DE BUSCA DISPONÍVEIS")
        print(Fore.CYAN + "=" * 50)
        print()
        
        print(Fore.GREEN + "1. 👥 Buscar por Autor")
        print(Fore.GREEN + "2. 📖 Buscar por Título")
        print(Fore.GREEN + "3. 🏷️ Buscar por Assunto/Palavra-chave")
        print(Fore.GREEN + "4. 🔗 Buscar por DOI específico")
        print(Fore.GREEN + "5. 🔄 Busca Geral")
        print(Fore.RED + "6. ↩️ Voltar ao menu principal")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha o tipo de busca (1-6): ").strip()
        
        mapeamento = {
            '1': 'autor',
            '2': 'titulo', 
            '3': 'assunto',
            '4': 'doi',
            '5': 'geral'
        }
        
        if opcao in mapeamento:
            return mapeamento[opcao]
        elif opcao == '6':
            return None
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_busca_publicacoes():
    """Menu principal de busca de publicações"""
    tipo_busca = menu_tipos_busca()
    
    if not tipo_busca:
        return
    
    limpar_tela()
    mostrar_banner()
    
    # Definir prompt baseado no tipo de busca
    prompts = {
        'autor': "👥 Digite o nome do autor (ex: 'John Doe', 'Marie Curie'): ",
        'titulo': "📖 Digite o título ou palavras do título (ex: 'machine learning', 'quantum physics'): ",
        'assunto': "🏷️ Digite o assunto ou palavras-chave (ex: 'artificial intelligence', 'climate change'): ",
        'doi': "🔗 Digite o DOI completo (ex: '10.1038/s41586-023-06466-x'): ",
        'geral': "🔄 Digite termos para busca geral: "
    }
    
    query = input(Fore.GREEN + prompts[tipo_busca]).strip()
    
    if not query:
        print(Fore.RED + "❌ Por favor, digite algo para buscar!")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    # Selecionar número de resultados
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "📊 NÚMERO DE RESULTADOS")
    print(Fore.CYAN + "=" * 50)
    print()
    
    print(Fore.GREEN + "1. 🎯 5 resultados (rápido)")
    print(Fore.GREEN + "2. 📊 10 resultados (padrão)")
    print(Fore.GREEN + "3. 📈 25 resultados (abrangente)")
    print(Fore.GREEN + "4. 🔢 Personalizado")
    print()
    
    opcao_rows = input(Fore.GREEN + "👉 Escolha o número de resultados (1-4): ").strip()
    
    rows_map = {'1': 5, '2': 10, '3': 25}
    
    if opcao_rows in rows_map:
        rows = rows_map[opcao_rows]
    elif opcao_rows == '4':
        try:
            rows = int(input(Fore.GREEN + "🔢 Digite o número de resultados (1-100): "))
            rows = max(1, min(100, rows))  # Limitar entre 1 e 100
        except ValueError:
            rows = 10
            print(Fore.RED + "❌ Valor inválido, usando padrão (10)")
    else:
        rows = 10
    
    # Fazer a busca
    limpar_tela()
    mostrar_banner()
    
    dados = buscar_publicacoes(tipo_busca, query, rows)
    
    if not dados:
        print(Fore.RED + "❌ Não foi possível obter os dados.")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    items = dados.get('items', [])
    if not items:
        print(Fore.RED + "❌ Nenhuma publicação encontrada!")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    # Menu de resultados
    while True:
        limpar_tela()
        mostrar_banner()
        
        exibir_resultados_publicacoes(dados, tipo_busca, query)
        
        print(Fore.YELLOW + "\n📋 OPÇÕES:")
        print(Fore.CYAN + "1. 📖 Ver detalhes de uma publicação")
        print(Fore.CYAN + "2. 🔄 Nova busca")
        print(Fore.CYAN + "3. 💾 Salvar resultados (JSON)")
        print(Fore.RED + "4. ↩️ Voltar ao menu principal")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-4): ").strip()
        
        if opcao == '1':
            try:
                num_pub = int(input(Fore.GREEN + "📖 Digite o número da publicação: "))
                if 1 <= num_pub <= len(items):
                    limpar_tela()
                    mostrar_banner()
                    exibir_detalhes_completos(items[num_pub - 1])
                    input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
                else:
                    print(Fore.RED + "❌ Número inválido!")
                    input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
            except ValueError:
                print(Fore.RED + "❌ Por favor, digite um número válido!")
                input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
                
        elif opcao == '2':
            menu_busca_publicacoes()
            break
        elif opcao == '3':
            salvar_resultados(dados, query)
        elif opcao == '4':
            break
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def salvar_resultados(dados, query):
    """Salva os resultados em arquivo JSON"""
    try:
        filename = f"crossref_results_{query.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        
        print(Fore.GREEN + f"✅ Resultados salvos em: {filename}")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        
    except Exception as e:
        print(Fore.RED + f"❌ Erro ao salvar arquivo: {e}")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_principal():
    """Menu principal do sistema"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "📋 MENU PRINCIPAL")
        print(Fore.CYAN + "1. 🔍 Buscar publicações acadêmicas")
        print(Fore.CYAN + "2. ℹ️  Sobre o sistema")
        print(Fore.RED + "3. 🚪 Sair")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-3): ").strip()
        
        if opcao == '1':
            menu_busca_publicacoes()
        elif opcao == '2':
            menu_sobre()
        elif opcao == '3':
            print(Fore.YELLOW + "\n👋 Obrigado por usar o sistema! Boas pesquisas! 📚")
            break
        else:
            print(Fore.RED + "❌ Opção inválida! Tente novamente.")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_sobre():
    """Menu sobre o sistema"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "ℹ️  SOBRE O SISTEMA")
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + """
📋 DESCRIÇÃO:
   Sistema de busca acadêmica baseado na API Crossref.
   Acesso ao registro oficial de DOI (Digital Object Identifier).

🏛️  FONTE DOS DADOS:
   Crossref - Registro oficial de DOI
   Base global de publicações acadêmicas

🔗 SISTEMA DOI:
   • Identificador único para publicações
   • Ligação permanente entre citações
   • Cooperativa sem fins lucrativos
   +6.000 organizações membros

📊 TIPOS DE BUSCA:
   • Por autor 👥
   • Por título 📖  
   • Por assunto 🏷️
   • Por DOI específico 🔗
   • Busca geral 🔄

⚙️  TECNOLOGIAS:
   • Python 3
   • Crossref API
   • Colorama para cores
   • Requests para HTTP

👨‍🎓 DESENVOLVIDO PARA:
   Pesquisadores, estudantes e profissionais acadêmicos
    """)
    
    print(Fore.CYAN + "=" * 50)
    input(Fore.YELLOW + "📝 Pressione Enter para voltar ao menu principal...")

def main():
    """Função principal"""
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n👋 Programa interrompido pelo usuário. Até logo! 📚")
    except Exception as e:
        print(Fore.RED + f"\n❌ Erro inesperado: {e}")

if __name__ == "__main__":
    main()
