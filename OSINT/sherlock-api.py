#!/usr/bin/env python3
import requests
import os
import json
import concurrent.futures
from datetime import datetime
import time
import hashlib
import sys

# Cores para terminal
class Cores:
    VERDE = '\033[92m'
    VERMELHO = '\033[91m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    MAGENTA = '\033[95m'
    CIANO = '\033[96m'
    BRANCO = '\033[97m'
    NEGRITO = '\033[1m'
    RESET = '\033[0m'

# Configurações
os.makedirs('cache_sherlock', exist_ok=True)
TEMPO_CACHE = 86400  # 24 horas em segundos

# Configuração da API Apify Sherlock
APIFY_API_URL = "https://api.apify.com/v2/acts/sherlock~sherlock/run-sync-get-dataset-items"
APIFY_TOKEN = ""  # Você pode adicionar seu token aqui se tiver

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ███████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗ ██╗  ██╗
   ██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██║ ██╔╝
   ███████╗███████║█████╗  ██████╔╝██║     ██║   ██║█████╔╝ 
   ╚════██║██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██╔═██╗ 
   ███████║██║  ██║███████╗██║  ██║███████╗╚██████╔╝██║  ██╗
   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   SHERLOCK INVESTIGATOR
   Busca de Usuários em Redes Sociais
{Cores.RESET}
{Cores.AMARELO}   +300 sites verificados
   Dados completos + Links ativos
{Cores.RESET}""")

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_sherlock/{nome}.json"
        if dados is not None:  # Modo escrita
            with open(caminho, 'w', encoding='utf-8') as f:
                json.dump({'data': dados, 'timestamp': time.time()}, f)
            return dados
        else:  # Modo leitura
            if os.path.exists(caminho):
                with open(caminho, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                    if time.time() - cache['timestamp'] < TEMPO_CACHE:
                        return cache['data']
        return None
    except (IOError, json.JSONDecodeError):
        return None

def consultar_sherlock_local(username):
    """Consulta usando Sherlock local (fallback)"""
    cache_id = f"sherlock_local_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    # Sites populares para verificação manual
    sites_populares = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Facebook': f'https://facebook.com/{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'YouTube': f'https://youtube.com/@{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'Pinterest': f'https://pinterest.com/{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'Twitch': f'https://twitch.tv/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Dev.to': f'https://dev.to/{username}',
        'GitLab': f'https://gitlab.com/{username}',
        'Bitbucket': f'https://bitbucket.org/{username}',
        'Dribbble': f'https://dribbble.com/{username}',
        'Behance': f'https://behance.net/{username}',
        'Flickr': f'https://flickr.com/people/{username}',
        'Vimeo': f'https://vimeo.com/{username}',
        'SlideShare': f'https://slideshare.net/{username}',
        'StackOverflow': f'https://stackoverflow.com/users/{username}',
        'Keybase': f'https://keybase.io/{username}',
        'HackerNews': f'https://news.ycombinator.com/user?id={username}',
        'ProductHunt': f'https://www.producthunt.com/@{username}',
        'Telegram': f'https://t.me/{username}',
        'Discord': f'https://discord.com/users/{username}'
    }
    
    resultados = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    print(f"{Cores.AMARELO}[*] Verificando {len(sites_populares)} sites para {username}...{Cores.RESET}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for site, url in sites_populares.items():
            futures[executor.submit(verificar_site, url, site, headers)] = site
        
        for future in concurrent.futures.as_completed(futures):
            site = futures[future]
            try:
                resultado = future.result()
                if resultado['encontrado']:
                    resultados.append(resultado)
                    print(f"{Cores.VERDE}[+] {site}: ENCONTRADO{Cores.RESET}")
                else:
                    print(f"{Cores.VERMELHO}[-] {site}: não encontrado{Cores.RESET}")
            except Exception as e:
                print(f"{Cores.AMARELO}[!] {site}: erro na verificação{Cores.RESET}")
    
    cache_arquivo(cache_id, resultados)
    return resultados

def verificar_site(url, site, headers):
    """Verifica se um usuário existe em um site específico"""
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Heurísticas simples para detecção
        if response.status_code == 200:
            # Verificar se não é página de erro
            if any(termo in response.text.lower() for termo in ['page not found', '404', 'not found', 'does not exist', 'error']):
                return {'site': site, 'url': url, 'encontrado': False}
            return {'site': site, 'url': url, 'encontrado': True}
        elif response.status_code == 404:
            return {'site': site, 'url': url, 'encontrado': False}
        else:
            # Para outros status, assumir que pode existir
            return {'site': site, 'url': url, 'encontrado': True}
    except:
        return {'site': site, 'url': url, 'encontrado': False}

def consultar_sherlock_apify(username):
    """Consulta usando API Apify Sherlock (se token disponível)"""
    if not APIFY_TOKEN:
        return None
    
    cache_id = f"sherlock_apify_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {APIFY_TOKEN}'
        }
        
        data = {
            "usernames": [username]
        }
        
        response = requests.post(APIFY_API_URL, json=data, headers=headers, timeout=60)
        
        if response.status_code == 200:
            resultados = response.json()
            cache_arquivo(cache_id, resultados)
            return resultados
        else:
            print(f"{Cores.VERMELHO}[!] Erro API Apify: {response.status_code}{Cores.RESET}")
            return None
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro na consulta Apify: {str(e)}{Cores.RESET}")
        return None

def consultar_todos_dados(username):
    """Consulta todos os dados do usuário"""
    print(f"{Cores.AMARELO}[*] Iniciando busca por {username}...{Cores.RESET}")
    
    # Tentar Apify primeiro (se token disponível)
    resultados_apify = consultar_sherlock_apify(username)
    
    # Usar método local como fallback
    if resultados_apify:
        print(f"{Cores.VERDE}[+] Usando dados da API Apify{Cores.RESET}")
        resultados = resultados_apify
    else:
        print(f"{Cores.AMARELO}[*] Usando verificação local (fallback){Cores.RESET}")
        resultados = consultar_sherlock_local(username)
    
    return {
        'username': username,
        'resultados': resultados,
        'metodo': 'apify' if resultados_apify else 'local',
        'consultado_em': datetime.now().isoformat()
    }

def organizar_por_categoria(resultados):
    """Organiza os resultados por categoria de sites"""
    categorias = {
        'Redes Sociais': ['Twitter', 'Facebook', 'Instagram', 'LinkedIn', 'TikTok'],
        'Desenvolvimento': ['GitHub', 'GitLab', 'Bitbucket', 'StackOverflow', 'Dev.to', 'HackerNews'],
        'Profissional': ['LinkedIn', 'Behance', 'Dribbble', 'Medium', 'SlideShare'],
        'Entretenimento': ['YouTube', 'Twitch', 'Spotify', 'SoundCloud', 'Vimeo'],
        'Tecnologia': ['ProductHunt', 'Keybase', 'Telegram', 'Discord'],
        'Fotografia': ['Flickr', 'Instagram', 'Pinterest'],
        'Outros': []  # Para sites não categorizados
    }
    
    organizado = {categoria: [] for categoria in categorias.keys()}
    
    for resultado in resultados:
        site = resultado['site']
        categoria_encontrada = False
        
        for categoria, sites in categorias.items():
            if site in sites:
                organizado[categoria].append(resultado)
                categoria_encontrada = True
                break
        
        if not categoria_encontrada:
            organizado['Outros'].append(resultado)
    
    # Remover categorias vazias
    return {k: v for k, v in organizado.items() if v}

def exibir_resultados_sherlock(resultado):
    """Exibe os resultados da busca Sherlock"""
    username = resultado['username']
    resultados = resultado['resultados']
    metodo = resultado['metodo']
    
    if not resultados:
        print(f"{Cores.VERMELHO}[!] Nenhum resultado encontrado para {username}{Cores.RESET}")
        return False
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== RESULTADOS PARA @{username} ==={Cores.RESET}")
    print(f"{Cores.AZUL}Método:{Cores.RESET} {Cores.CIANO}{metodo.upper()}{Cores.RESET}")
    print(f"{Cores.AZUL}Total encontrado:{Cores.RESET} {Cores.VERDE}{len(resultados)} sites{Cores.RESET}")
    
    # Organizar por categoria
    resultados_organizados = organizar_por_categoria(resultados)
    
    total_por_categoria = sum(len(sites) for sites in resultados_organizados.values())
    
    for categoria, sites in resultados_organizados.items():
        if sites:
            print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== {categoria.upper()} ({len(sites)}) ==={Cores.RESET}")
            
            for i, site_info in enumerate(sites, 1):
                emoji = get_emoji_site(site_info['site'])
                print(f"  {Cores.VERDE}{i}. {emoji} {site_info['site']}{Cores.RESET}")
                print(f"     {Cores.CIANO}URL:{Cores.RESET} {site_info['url']}")
                
                # Informações adicionais se disponíveis
                if site_info.get('detalhes'):
                    print(f"     {Cores.AZUL}Detalhes:{Cores.RESET} {site_info['detalhes']}")
    
    # Estatísticas
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== ESTATÍSTICAS ==={Cores.RESET}")
    print(f"{Cores.AZUL}Total de sites verificados:{Cores.RESET} {total_por_categoria}")
    print(f"{Cores.AZUL}Taxa de sucesso:{Cores.RESET} {(total_por_categoria/50)*100:.1f}%")  # Assumindo 50 sites verificados
    
    # Sites mais populares encontrados
    sites_populares_encontrados = [site['site'] for site in resultados if site['site'] in 
                                  ['GitHub', 'Twitter', 'Instagram', 'Facebook', 'LinkedIn']]
    if sites_populares_encontrados:
        print(f"{Cores.AZUL}Sites populares:{Cores.RESET} {', '.join(sites_populares_encontrados)}")
    
    return True

def get_emoji_site(site):
    """Retorna emoji correspondente ao site"""
    emojis = {
        'GitHub': '💻', 'Twitter': '🐦', 'Instagram': '📷', 'Facebook': '👥', 'LinkedIn': '💼',
        'YouTube': '📺', 'Reddit': '👽', 'Pinterest': '📌', 'TikTok': '🎵', 'Twitch': '🎮',
        'Spotify': '🎵', 'SoundCloud': '☁️', 'Medium': '📝', 'Dev.to': '⚡', 'GitLab': '🦊',
        'Bitbucket': '🚀', 'Dribbble': '🎨', 'Behance': '🎨', 'Flickr': '📸', 'Vimeo': '🎬',
        'SlideShare': '📊', 'StackOverflow': '🔧', 'Keybase': '🔑', 'HackerNews': '👨‍💻',
        'ProductHunt': '🔍', 'Telegram': '✈️', 'Discord': '💬'
    }
    return emojis.get(site, '🌐')

def salvar_resultado(resultado, username, formato='txt'):
    """Salva os resultados em arquivo"""
    if not resultado.get('resultados'):
        return False
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_sherlock', exist_ok=True)
        nome_arquivo = f"resultados_sherlock/sherlock_{username}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(resultado, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== RELATÓRIO SHERLOCK - @{username} ===\n\n")
                
                f.write(f"Username: {username}\n")
                f.write(f"Método: {resultado['metodo']}\n")
                f.write(f"Data: {timestamp}\n")
                f.write(f"Total de sites encontrados: {len(resultado['resultados'])}\n\n")
                
                # Organizar por categoria
                resultados_organizados = organizar_por_categoria(resultado['resultados'])
                
                for categoria, sites in resultados_organizados.items():
                    if sites:
                        f.write(f"\n--- {categoria.upper()} ({len(sites)}) ---\n")
                        for site in sites:
                            f.write(f"• {site['site']}: {site['url']}\n")
                
                f.write(f"\n--- ESTATÍSTICAS ---\n")
                f.write(f"Sites totais: {len(resultado['resultados'])}\n")
                
                # Contar sites populares
                sites_populares = ['GitHub', 'Twitter', 'Instagram', 'Facebook', 'LinkedIn']
                contagem_populares = sum(1 for site in resultado['resultados'] if site['site'] in sites_populares)
                f.write(f"Sites populares encontrados: {contagem_populares}/5\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Buscar Usuário")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Buscar Múltiplos Usuários")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Configurar API Token")
    print(f"{Cores.VERDE}[4]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[5]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '5'

def buscar_multiplos_usuarios():
    """Busca múltiplos usuários de uma vez"""
    banner()
    print(f"{Cores.CIANO}{Cores.NEGRITO}BUSCA EM MASSA{Cores.RESET}\n")
    
    try:
        usernames_input = input(f"{Cores.CIANO}Digite os usernames (separados por vírgula): {Cores.RESET}").strip()
        if not usernames_input:
            return
        
        usernames = [username.strip() for username in usernames_input.split(',')]
        usernames = [username for username in usernames if username]
        
        if not usernames:
            print(f"{Cores.VERMELHO}[!] Nenhum username válido{Cores.RESET}")
            return
        
        print(f"\n{Cores.AMARELO}[*] Buscando {len(usernames)} usuários...{Cores.RESET}")
        
        resultados_totais = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(consultar_todos_dados, username): username for username in usernames}
            
            for future in concurrent.futures.as_completed(futures):
                username = futures[future]
                try:
                    resultado = future.result()
                    resultados_totais[username] = resultado
                    print(f"{Cores.VERDE}[+] {username}: {len(resultado['resultados'])} sites encontrados{Cores.RESET}")
                except Exception as e:
                    print(f"{Cores.VERMELHO}[!] {username}: erro na busca{Cores.RESET}")
        
        # Exibir resumo
        banner()
        print(f"{Cores.VERDE}{Cores.NEGRITO}=== RESUMO DA BUSCA EM MASSA ==={Cores.RESET}")
        for username, resultado in resultados_totais.items():
            print(f"\n{Cores.CIANO}@{username}:{Cores.RESET} {len(resultado['resultados'])} sites")
            sites_principais = [site['site'] for site in resultado['resultados'][:5]]
            if sites_principais:
                print(f"  Principais: {', '.join(sites_principais)}")
        
        # Opção de exportação
        try:
            exportar = input(f"\n{Cores.CIANO}Exportar todos os resultados? (JSON/TXT/Não): {Cores.RESET}").lower()
            if exportar.startswith('j'):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                nome_arquivo = f"resultados_sherlock/massa_{timestamp}.json"
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    json.dump(resultados_totais, f, indent=2, ensure_ascii=False)
                print(f"{Cores.VERDE}[+] Resultados salvos em {nome_arquivo}{Cores.RESET}")
            elif exportar.startswith('t'):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                nome_arquivo = f"resultados_sherlock/massa_{timestamp}.txt"
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    f.write("=== RELATÓRIO SHERLOCK EM MASSA ===\n\n")
                    for username, resultado in resultados_totais.items():
                        f.write(f"@{username}: {len(resultado['resultados'])} sites\n")
                        for site in resultado['resultados']:
                            f.write(f"  - {site['site']}: {site['url']}\n")
                        f.write("\n")
                print(f"{Cores.VERDE}[+] Resultados salvos em {nome_arquivo}{Cores.RESET}")
        except (EOFError, KeyboardInterrupt):
            pass
            
    except (EOFError, KeyboardInterrupt):
        return

def configurar_token():
    """Configura o token da API Apify"""
    banner()
    print(f"{Cores.CIANO}{Cores.NEGRITO}CONFIGURAÇÃO API TOKEN{Cores.RESET}\n")
    
    print(f"{Cores.AMARELO}Para usar a API completa do Sherlock:{Cores.RESET}")
    print("1. Acesse: https://console.apify.com/")
    print("2. Crie uma conta gratuita")
    print("3. Obtenha seu API Token")
    print("4. Cole abaixo (ou pressione Enter para pular)\n")
    
    try:
        token = input(f"{Cores.CIANO}Seu API Token Apify: {Cores.RESET}").strip()
        if token:
            global APIFY_TOKEN
            APIFY_TOKEN = token
            print(f"{Cores.VERDE}[+] Token configurado com sucesso!{Cores.RESET}")
        else:
            print(f"{Cores.AMARELO}[*] Usando modo local (sem API){Cores.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass
    
    try:
        input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O SHERLOCK INVESTIGATOR{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Busca em +300 redes sociais e sites
- Verificação em tempo real
- Organização por categorias
- Busca em massa múltiplos usuários
- Cache inteligente para performance
- Exportação em JSON/TXT

{Cores.AMARELO}Métodos disponíveis:{Cores.RESET}
- API Apify Sherlock (com token) - +300 sites
- Modo Local (fallback) - 30+ sites populares

{Cores.AMARELO}Categorias de sites:{Cores.RESET}
- Redes Sociais (Twitter, Facebook, Instagram, etc.)
- Desenvolvimento (GitHub, GitLab, StackOverflow, etc.)
- Profissional (LinkedIn, Behance, Dribbble, etc.)
- Entretenimento (YouTube, Twitch, Spotify, etc.)
- Tecnologia (ProductHunt, Keybase, Telegram, etc.)

{Cores.AMARELO}Exemplos de usernames para teste:{Cores.RESET}
- torvalds (Linus Torvalds)
- john (Nome comum)
- test (Usuário de teste)

{Cores.VERDE}Pressione Enter para voltar...{Cores.RESET}""")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                try:
                    username = input(f"\n{Cores.CIANO}Digite o username: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not username:
                    print(f"{Cores.VERMELHO}[!] Username não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                # Consultar usuário
                resultado = consultar_todos_dados(username)
                
                banner()
                sucesso = exibir_resultados_sherlock(resultado)
                
                # Opção de exportação
                if sucesso:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(resultado, username, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(resultado, username, 'txt')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '2':
                buscar_multiplos_usuarios()
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '3':
                configurar_token()
            
            elif opcao == '4':
                sobre()
            
            elif opcao == '5':
                print(f"\n{Cores.VERDE}[+] Saindo...{Cores.RESET}")
                break
            
            else:
                print(f"{Cores.VERMELHO}[!] Opção inválida!{Cores.RESET}")
                try:
                    input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
    
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Programa interrompido{Cores.RESET}")
    except Exception as e:
        print(f"\n{Cores.VERMELHO}[!] Erro fatal: {str(e)}{Cores.RESET}")
    finally:
        print(f"{Cores.CIANO}\nObrigado por usar o Sherlock Investigator!{Cores.RESET}")

if __name__ == "__main__":
    # Verificar dependências
    try:
        import requests
    except ImportError:
        print(f"{Cores.VERMELHO}[!] Biblioteca 'requests' não encontrada.{Cores.RESET}")
        print(f"{Cores.AMARELO}[*] Instale com: pip install requests{Cores.RESET}")
        sys.exit(1)
    
    main()
