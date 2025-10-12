import requests
import json
import os
from datetime import datetime, timedelta
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

def limpar_tela():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_banner():
    """Exibe o banner colorido"""
    print(Fore.CYAN + "=" * 80)
    print(Fore.YELLOW + "🌍 SISTEMA DE MONITORAMENTO DE NOTÍCIAS GLOBALS - GDELT PROJECT")
    print(Fore.CYAN + "=" * 80)
    print(Fore.GREEN + "📰 Monitoramento em tempo real de +100.000 fontes em 100 idiomas")
    print(Fore.CYAN + "=" * 80)
    print()

def buscar_noticias_gdelt(query, modo="artlist", max_results=50, idioma=None, periodo=None):
    """Faz a busca na API GDELT Project"""
    base_url = "https://api.gdeltproject.org/api/v2/doc/doc"
    
    params = {
        'query': query,
        'mode': modo,
        'format': 'json',
        'maxrecords': max_results
    }
    
    # Adicionar filtros opcionais
    if idioma and idioma != "todos":
        params['lang'] = idioma
    
    if periodo:
        data_fim = datetime.now()
        if periodo == "24h":
            data_inicio = data_fim - timedelta(days=1)
        elif periodo == "7d":
            data_inicio = data_fim - timedelta(days=7)
        elif periodo == "30d":
            data_inicio = data_fim - timedelta(days=30)
        
        params['startdatetime'] = data_inicio.strftime('%Y%m%d')
        params['enddatetime'] = data_fim.strftime('%Y%m%d')
    
    headers = {
        'User-Agent': 'SistemaNoticiasGDELT/1.0 (pesquisa@midia.com)',
        'Accept': 'application/json'
    }
    
    try:
        print(Fore.YELLOW + f"🔍 Buscando: '{query}'")
        print(Fore.CYAN + f"📊 Modo: {modo.upper()} | Resultados: {max_results}")
        if idioma and idioma != "todos":
            print(Fore.CYAN + f"🌐 Idioma: {idioma.capitalize()}")
        if periodo:
            print(Fore.CYAN + f"📅 Período: {periodo}")
        print(Fore.CYAN + "⏳ Conectando com a GDELT API..." + Style.RESET_ALL)
        
        response = requests.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        
        dados = response.json()
        return dados
        
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"❌ Erro na conexão: {e}")
        return None
    except json.JSONDecodeError:
        print(Fore.RED + "❌ Erro ao processar resposta da API")
        return None
    except Exception as e:
        print(Fore.RED + f"❌ Erro inesperado: {e}")
        return None

def formatar_data_gdelt(data_string):
    """Formata data do GDELT para exibição amigável"""
    try:
        # Formato GDELT: 20240115T120000Z
        if 'T' in data_string:
            data_obj = datetime.strptime(data_string, '%Y%m%dT%H%M%SZ')
            return data_obj.strftime('%d/%m/%Y %H:%M UTC')
        else:
            return data_string
    except:
        return data_string

def analisar_sentimento(tone, positive_score, negative_score):
    """Analisa e classifica o sentimento do artigo"""
    if tone > 5:
        return Fore.GREEN + "😊 Positivo", tone
    elif tone < -5:
        return Fore.RED + "😠 Negativo", tone
    elif tone > 0:
        return Fore.CYAN + "🙂 Levemente Positivo", tone
    elif tone < 0:
        return Fore.YELLOW + "😐 Levemente Negativo", tone
    else:
        return Fore.WHITE + "😐 Neutro", tone

def exibir_resultados_artigos(dados, query):
    """Exibe os resultados de artigos de forma organizada"""
    if not dados or 'articles' not in dados:
        print(Fore.RED + "❌ Nenhum artigo encontrado!")
        return 0
    
    articles = dados['articles']
    total = len(articles)
    
    print(Fore.GREEN + "\n" + "=" * 90)
    print(Fore.YELLOW + f"📰 ARTIGOS ENCONTRADOS: {total}")
    print(Fore.WHITE + f"🔍 Busca: '{query}'")
    print(Fore.GREEN + "=" * 90)
    
    for i, artigo in enumerate(articles, 1):
        print(Fore.CYAN + f"\n📄 NOTÍCIA {i}:")
        print(Fore.WHITE + "─" * 70)
        
        # Título e URL
        titulo = artigo.get('title', 'Título não disponível')
        print(Fore.YELLOW + f"📖 {titulo}")
        
        # Fonte e domínio
        fonte = artigo.get('source', 'N/A')
        dominio = artigo.get('domain', 'N/A')
        print(Fore.CYAN + f"🏛️  Fonte: {fonte} | 🌐 Domínio: {dominio}")
        
        # Data
        data = formatar_data_gdelt(artigo.get('seendate', 'N/A'))
        print(Fore.BLUE + f"📅 Publicado: {data}")
        
        # Idioma e país da fonte
        idioma = artigo.get('language', 'N/A').capitalize()
        pais_fonte = artigo.get('sourcecountry', 'N/A')
        print(Fore.MAGENTA + f"🗣️  Idioma: {idioma} | 🇺🇳 País da Fonte: {pais_fonte}")
        
        # Análise de Sentimento
        tone = artigo.get('tone', 0)
        positive = artigo.get('positive_score', 0)
        negative = artigo.get('negative_score', 0)
        
        sentimento, valor_tone = analisar_sentimento(tone, positive, negative)
        print(Fore.WHITE + f"😊 Sentimento: {sentimento} ({valor_tone:.2f})")
        print(Fore.GREEN + f"   👍 Positivo: {positive:.3f} | 👎 Negativo: {negative:.3f}")
        
        # Estatísticas
        wordcount = artigo.get('wordcount', 0)
        print(Fore.CYAN + f"📊 Palavras: {wordcount}")
        
        # Entidades mencionadas
        if artigo.get('persons'):
            pessoas = ", ".join(artigo['persons'][:3])
            print(Fore.WHITE + f"👥 Pessoas: {pessoas}" + ("..." if len(artigo['persons']) > 3 else ""))
        
        if artigo.get('organizations'):
            orgs = ", ".join(artigo['organizations'][:3])
            print(Fore.WHITE + f"🏢 Organizações: {orgs}" + ("..." if len(artigo['organizations']) > 3 else ""))
        
        if artigo.get('locations'):
            locs = ", ".join(artigo['locations'][:3])
            print(Fore.WHITE + f"📍 Localizações: {locs}" + ("..." if len(artigo['locations']) > 3 else ""))
        
        # URL
        url = artigo.get('url', 'N/A')
        print(Fore.BLUE + f"🔗 URL: {url}")
        
        print(Fore.WHITE + "─" * 70)
    
    return total

def exibir_timeline(dados, query):
    """Exibe dados de timeline (volume de notícias)"""
    if not dados or 'timeline' not in dados:
        print(Fore.RED + "❌ Nenhum dado de timeline disponível!")
        return
    
    timeline = dados['timeline']
    
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + f"📈 TIMELINE DE MENÇÕES: '{query}'")
    print(Fore.GREEN + "=" * 80)
    
    print(Fore.CYAN + "\n📊 Volume de Notícias por Período:")
    print(Fore.WHITE + "─" * 50)
    
    for item in timeline:
        data = item.get('date', 'N/A')
        count = item.get('value', 0)
        
        # Formatar data
        try:
            if len(data) == 8:  # YYYYMMDD
                data_formatada = f"{data[6:8]}/{data[4:6]}/{data[:4]}"
            else:
                data_formatada = data
        except:
            data_formatada = data
        
        barra = "█" * min(count // 5, 20)  # Normalizar para máximo 20 caracteres
        print(Fore.WHITE + f"📅 {data_formatada}: {count:3d} menções {Fore.CYAN}{barra}")

def exibir_analise_sentimento(dados, query):
    """Exibe análise de sentimento"""
    if not dados or 'tonechart' not in dados:
        print(Fore.RED + "❌ Nenhum dado de análise de sentimento disponível!")
        return
    
    tonechart = dados['tonechart']
    
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + f"😊 ANÁLISE DE SENTIMENTO: '{query}'")
    print(Fore.GREEN + "=" * 80)
    
    print(Fore.CYAN + "\n📊 Distribuição de Sentimento:")
    print(Fore.WHITE + "─" * 50)
    
    for item in tonechart:
        tone_bin = item.get('bin', 0)
        count = item.get('count', 0)
        
        if tone_bin > 5:
            cor = Fore.GREEN
            classificacao = "Muito Positivo"
        elif tone_bin > 0:
            cor = Fore.CYAN
            classificacao = "Positivo"
        elif tone_bin == 0:
            cor = Fore.WHITE
            classificacao = "Neutro"
        elif tone_bin > -5:
            cor = Fore.YELLOW
            classificacao = "Negativo"
        else:
            cor = Fore.RED
            classificacao = "Muito Negativo"
        
        barra = "█" * min(count // 2, 30)
        print(f"{cor}📊 {classificacao:15} ({tone_bin:3.0f}): {count:3d} artigos {barra}")

def menu_modos_busca():
    """Menu para selecionar o modo de busca"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "🔍 MODOS DE ANÁLISE GDELT")
        print(Fore.CYAN + "=" * 50)
        print()
        
        print(Fore.GREEN + "1. 📰 Lista de Artigos (artlist)")
        print(Fore.GREEN + "2. 📈 Timeline de Volume (timeline)")
        print(Fore.GREEN + "3. 😊 Análise de Sentimento (tonechart)")
        print(Fore.GREEN + "4. ☁️  Nuvem de Palavras (wordcloud)")
        print(Fore.RED + "5. ↩️ Voltar ao menu principal")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha o modo de análise (1-5): ").strip()
        
        modos = {
            '1': 'artlist',
            '2': 'timeline', 
            '3': 'tonechart',
            '4': 'wordcloud'
        }
        
        if opcao in modos:
            return modos[opcao]
        elif opcao == '5':
            return None
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_filtros():
    """Menu para selecionar filtros de busca"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "🎛️  FILTROS DE BUSCA")
    print(Fore.CYAN + "=" * 50)
    print()
    
    # Idioma
    print(Fore.GREEN + "🌐 IDIOMA:")
    print(Fore.CYAN + "1. Todos os idiomas")
    print(Fore.CYAN + "2. Português")
    print(Fore.CYAN + "3. Inglês")
    print(Fore.CYAN + "4. Espanhol")
    print(Fore.CYAN + "5. Francês")
    
    op_idioma = input(Fore.GREEN + "👉 Escolha o idioma (1-5): ").strip()
    idiomas = {'1': 'todos', '2': 'portuguese', '3': 'english', '4': 'spanish', '5': 'french'}
    idioma = idiomas.get(op_idioma, 'todos')
    
    # Período
    print(Fore.GREEN + "\n📅 PERÍODO:")
    print(Fore.CYAN + "1. Todo o período")
    print(Fore.CYAN + "2. Últimas 24 horas")
    print(Fore.CYAN + "3. Últimos 7 dias")
    print(Fore.CYAN + "4. Últimos 30 dias")
    
    op_periodo = input(Fore.GREEN + "👉 Escolha o período (1-4): ").strip()
    periodos = {'1': None, '2': '24h', '3': '7d', '4': '30d'}
    periodo = periodos.get(op_periodo, None)
    
    # Número de resultados
    print(Fore.GREEN + "\n📊 NÚMERO DE RESULTADOS:")
    print(Fore.CYAN + "1. 10 (rápido)")
    print(Fore.CYAN + "2. 25 (padrão)")
    print(Fore.CYAN + "3. 50 (abrangente)")
    print(Fore.CYAN + "4. 100 (completo)")
    
    op_results = input(Fore.GREEN + "👉 Número de resultados (1-4): ").strip()
    results_map = {'1': 10, '2': 25, '3': 50, '4': 100}
    max_results = results_map.get(op_results, 25)
    
    return idioma, periodo, max_results

def menu_busca_noticias():
    """Menu principal de busca de notícias"""
    modo = menu_modos_busca()
    
    if not modo:
        return
    
    # Obter filtros
    idioma, periodo, max_results = menu_filtros()
    
    limpar_tela()
    mostrar_banner()
    
    # Obter query do usuário
    print(Fore.YELLOW + "🔍 TERMO DE BUSCA")
    print(Fore.CYAN + "=" * 50)
    print()
    
    print(Fore.GREEN + "💡 Exemplos:")
    print(Fore.CYAN + "  • Brazil")
    print(Fore.CYAN + "  • Petrobras")
    print(Fore.CYAN + "  • 'climate change'")
    print(Fore.CYAN + "  • location:'São Paulo'")
    print(Fore.CYAN + "  • 'artificial intelligence'")
    print()
    
    query = input(Fore.GREEN + "👉 Digite o termo de busca: ").strip()
    
    if not query:
        print(Fore.RED + "❌ Por favor, digite algo para buscar!")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    # Fazer a busca
    limpar_tela()
    mostrar_banner()
    
    dados = buscar_noticias_gdelt(query, modo, max_results, idioma, periodo)
    
    if not dados:
        print(Fore.RED + "❌ Não foi possível obter os dados.")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    # Exibir resultados baseado no modo
    if modo == 'artlist':
        total = exibir_resultados_artigos(dados, query)
        if total > 0:
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
    elif modo == 'timeline':
        exibir_timeline(dados, query)
        input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
    elif modo == 'tonechart':
        exibir_analise_sentimento(dados, query)
        input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
    elif modo == 'wordcloud':
        print(Fore.YELLOW + "\n☁️  Dados de nuvem de palavras recebidos!")
        print(Fore.CYAN + "💡 Use os dados para gerar visualizações externas")
        input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")

def menu_exemplos_predefinidos():
    """Menu com exemplos predefinidos de busca"""
    exemplos = {
        '1': {'query': 'Brazil', 'desc': 'Notícias sobre o Brasil'},
        '2': {'query': 'Petrobras', 'desc': 'Empresa Petrobras'},
        '3': {'query': 'location:"São Paulo"', 'desc': 'Notícias sobre São Paulo'},
        '4': {'query': 'climate change', 'desc': 'Mudanças climáticas'},
        '5': {'query': 'artificial intelligence', 'desc': 'Inteligência artificial'},
        '6': {'query': 'elections', 'desc': 'Eleições globais'},
        '7': {'query': 'Ukraine Russia', 'desc': 'Conflito Ucrânia-Rússia'},
        '8': {'query': 'Microsoft', 'desc': 'Empresa Microsoft'}
    }
    
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "🎯 EXEMPLOS PREDEFINIDOS")
        print(Fore.CYAN + "=" * 50)
        print()
        
        for key, ex in exemplos.items():
            print(Fore.GREEN + f"{key}. {ex['query']}")
            print(Fore.CYAN + f"   📝 {ex['desc']}")
            print()
        
        print(Fore.RED + "9. ↩️ Voltar ao menu anterior")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha um exemplo (1-9): ").strip()
        
        if opcao in exemplos:
            return exemplos[opcao]['query']
        elif opcao == '9':
            return None
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_principal():
    """Menu principal do sistema"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "📋 MENU PRINCIPAL")
        print(Fore.CYAN + "1. 🔍 Busca personalizada")
        print(Fore.CYAN + "2. 🎯 Exemplos predefinidos")
        print(Fore.CYAN + "3. ℹ️  Sobre o GDELT")
        print(Fore.RED + "4. 🚪 Sair")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-4): ").strip()
        
        if opcao == '1':
            menu_busca_noticias()
        elif opcao == '2':
            query = menu_exemplos_predefinidos()
            if query:
                # Usar busca padrão com exemplo
                dados = buscar_noticias_gdelt(query, "artlist", 25)
                if dados:
                    limpar_tela()
                    mostrar_banner()
                    exibir_resultados_artigos(dados, query)
                    input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '3':
            menu_sobre_gdelt()
        elif opcao == '4':
            print(Fore.YELLOW + "\n👋 Obrigado por usar o sistema! Até logo! 🌍")
            break
        else:
            print(Fore.RED + "❌ Opção inválida! Tente novamente.")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_sobre_gdelt():
    """Menu sobre o GDELT Project"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "ℹ️  SOBRE O GDELT PROJECT")
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + """
🌍 GLOBAL DATABASE OF EVENTS, LANGUAGE, AND TONE

📊 O MAIOR BANCO DE DADOS DE NOTÍCIAS DO MUNDO:
   • +100,000 fontes de notícias
   • 100 idiomas diferentes
   • Monitoramento em tempo real
   • Dados desde 1979

🔍 O QUE É MONITORADO:
   • Eventos globais e locais
   • Análise de sentimento
   • Menções de pessoas/organizações
   • Localizações geográficas
   • Temas e tendências

📈 MODOS DE ANÁLISE:
   • 📰 Lista de Artigos - Notícias completas
   • 📈 Timeline - Volume temporal
   • 😊 Tone Chart - Análise de sentimento  
   • ☁️  Word Cloud - Palavras mais usadas

🎯 APLICAÇÕES:
   • OSINT e inteligência competitiva
   • Monitoramento de marca
   • Análise de crise
   • Pesquisa acadêmica
   • Jornalismo de dados

⚙️  TECNOLOGIAS:
   • Processamento de linguagem natural
   • Análise de sentimento
   • Geocodificação automática
   • Reconhecimento de entidades
    """)
    
    print(Fore.CYAN + "=" * 50)
    input(Fore.YELLOW + "📝 Pressione Enter para voltar ao menu principal...")

def main():
    """Função principal"""
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n👋 Programa interrompido pelo usuário. Até logo! 🌍")
    except Exception as e:
        print(Fore.RED + f"\n❌ Erro inesperado: {e}")

if __name__ == "__main__":
    main()
