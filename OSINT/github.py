#!/usr/bin/env python3
import requests
import os
import json
import concurrent.futures
from datetime import datetime
import time
import hashlib

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
os.makedirs('cache_github', exist_ok=True)
TEMPO_CACHE = 3600  # 1 hora em segundos

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗ 
   ██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗
   ██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝
   ██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗
   ╚██████╔╝██║   ██║   ██║  ██║╚██████╔║██████╔╝
    ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ 
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   INVESTIGADOR GITHUB
   OSINT de Usuários GitHub
{Cores.RESET}
{Cores.AMARELO}   Dados completos + Repositórios + Seguidores
   Análise detalhada de perfil
{Cores.RESET}""")

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_github/{nome}.json"
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

def consultar_usuario_github(username):
    """Consulta dados básicos do usuário"""
    cache_id = f"usuario_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.github.com/users/{username}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados:
                # Processar dados do usuário
                usuario = {
                    'login': dados.get('login', ''),
                    'id': dados.get('id', ''),
                    'nome': dados.get('name', ''),
                    'empresa': dados.get('company', ''),
                    'blog': dados.get('blog', ''),
                    'localizacao': dados.get('location', ''),
                    'email': dados.get('email', ''),
                    'bio': dados.get('bio', ''),
                    'twitter': dados.get('twitter_username', ''),
                    'repos_publicos': dados.get('public_repos', 0),
                    'seguidores': dados.get('followers', 0),
                    'seguindo': dados.get('following', 0),
                    'gists_publicos': dados.get('public_gists', 0),
                    'criado_em': dados.get('created_at', ''),
                    'atualizado_em': dados.get('updated_at', ''),
                    'avatar_url': dados.get('avatar_url', ''),
                    'html_url': dados.get('html_url', ''),
                    'tipo': dados.get('type', ''),
                    'site_admin': dados.get('site_admin', False),
                    'url_perfil': f"https://github.com/{username}"
                }
                cache_arquivo(cache_id, usuario)
                return usuario
        elif response.status_code == 404:
            return {'erro': 'Usuário não encontrado'}
    except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
        return {'erro': f'Erro na consulta: {str(e)}'}
    
    return {'erro': 'Erro desconhecido'}

def consultar_repositorios(username):
    """Consulta repositórios do usuário"""
    cache_id = f"repos_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            repos = response.json()
            repositorios = []
            
            for repo in repos[:5]:  # Limitar aos 5 mais recentes
                repositorios.append({
                    'nome': repo.get('name', ''),
                    'descricao': repo.get('description', ''),
                    'linguagem': repo.get('language', ''),
                    'stars': repo.get('stargazers_count', 0),
                    'forks': repo.get('forks_count', 0),
                    'watchers': repo.get('watchers_count', 0),
                    'tamanho': repo.get('size', 0),
                    'url': repo.get('html_url', ''),
                    'criado_em': repo.get('created_at', ''),
                    'atualizado_em': repo.get('updated_at', ''),
                    'privado': repo.get('private', False),
                    'fork': repo.get('fork', False)
                })
            
            cache_arquivo(cache_id, repositorios)
            return repositorios
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_seguidores(username):
    """Consulta seguidores do usuário"""
    cache_id = f"seguidores_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.github.com/users/{username}/followers?per_page=5"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            seguidores = response.json()
            lista_seguidores = []
            
            for seguidor in seguidores:
                lista_seguidores.append({
                    'login': seguidor.get('login', ''),
                    'url': seguidor.get('html_url', ''),
                    'avatar': seguidor.get('avatar_url', '')
                })
            
            cache_arquivo(cache_id, lista_seguidores)
            return lista_seguidores
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_seguindo(username):
    """Consulta quem o usuário está seguindo"""
    cache_id = f"seguindo_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.github.com/users/{username}/following?per_page=5"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            seguindo = response.json()
            lista_seguindo = []
            
            for user in seguindo:
                lista_seguindo.append({
                    'login': user.get('login', ''),
                    'url': user.get('html_url', ''),
                    'avatar': user.get('avatar_url', '')
                })
            
            cache_arquivo(cache_id, lista_seguindo)
            return lista_seguindo
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_organizacoes(username):
    """Consulta organizações do usuário"""
    cache_id = f"orgs_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://api.github.com/users/{username}/orgs"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            orgs = response.json()
            organizacoes = []
            
            for org in orgs:
                organizacoes.append({
                    'login': org.get('login', ''),
                    'url': org.get('html_url', ''),
                    'avatar': org.get('avatar_url', ''),
                    'descricao': org.get('description', '')
                })
            
            cache_arquivo(cache_id, organizacoes)
            return organizacoes
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_todos_dados(username):
    """Consulta todos os dados do usuário em paralelo"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            'usuario': executor.submit(consultar_usuario_github, username),
            'repositorios': executor.submit(consultar_repositorios, username),
            'seguidores': executor.submit(consultar_seguidores, username),
            'seguindo': executor.submit(consultar_seguindo, username),
            'organizacoes': executor.submit(consultar_organizacoes, username)
        }
        
        resultados = {}
        for nome, future in futures.items():
            try:
                resultados[nome] = future.result(timeout=30)
            except concurrent.futures.TimeoutError:
                resultados[nome] = {'erro': 'Timeout'}
            except Exception:
                resultados[nome] = {'erro': 'Erro desconhecido'}
        
        return resultados

def formatar_data(data_iso):
    """Formata data ISO para formato legível"""
    try:
        if data_iso:
            data = datetime.fromisoformat(data_iso.replace('Z', '+00:00'))
            return data.strftime("%d/%m/%Y %H:%M:%S")
    except:
        pass
    return data_iso

def calcular_idade_conta(data_criacao):
    """Calcula a idade da conta em anos"""
    try:
        if data_criacao:
            criacao = datetime.fromisoformat(data_criacao.replace('Z', '+00:00'))
            agora = datetime.now()
            idade = agora.year - criacao.year
            if agora.month < criacao.month or (agora.month == criacao.month and agora.day < criacao.day):
                idade -= 1
            return idade
    except:
        pass
    return None

def exibir_dados_usuario(usuario):
    """Exibe dados principais do usuário"""
    if 'erro' in usuario:
        print(f"{Cores.VERMELHO}[!] {usuario['erro']}{Cores.RESET}")
        return False
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== DADOS DO USUÁRIO ==={Cores.RESET}")
    print(f"{Cores.AZUL}Usuário:{Cores.RESET} {Cores.VERDE}{usuario['login']}{Cores.RESET} (ID: {usuario['id']})")
    
    if usuario['nome']:
        print(f"{Cores.AZUL}Nome:{Cores.RESET} {usuario['nome']}")
    
    if usuario['bio']:
        print(f"{Cores.AZUL}Bio:{Cores.RESET} {usuario['bio']}")
    
    if usuario['empresa']:
        print(f"{Cores.AZUL}Empresa:{Cores.RESET} {usuario['empresa']}")
    
    if usuario['localizacao']:
        print(f"{Cores.AZUL}Localização:{Cores.RESET} {usuario['localizacao']}")
    
    if usuario['email']:
        print(f"{Cores.AZUL}Email:{Cores.RESET} {usuario['email']}")
    
    if usuario['blog']:
        print(f"{Cores.AZUL}Blog/Website:{Cores.RESET} {usuario['blog']}")
    
    if usuario['twitter']:
        print(f"{Cores.AZUL}Twitter:{Cores.RESET} @{usuario['twitter']}")
    
    print(f"\n{Cores.AZUL}Estatísticas:{Cores.RESET}")
    print(f"  {Cores.CIANO}Repositórios:{Cores.RESET} {usuario['repos_publicos']} públicos")
    print(f"  {Cores.CIANO}Seguidores:{Cores.RESET} {usuario['seguidores']}")
    print(f"  {Cores.CIANO}Seguindo:{Cores.RESET} {usuario['seguindo']}")
    print(f"  {Cores.CIANO}Gists:{Cores.RESET} {usuario['gists_publicos']} públicos")
    
    idade_conta = calcular_idade_conta(usuario['criado_em'])
    if idade_conta:
        print(f"  {Cores.CIANO}Idade da conta:{Cores.RESET} {idade_conta} anos")
    
    print(f"\n{Cores.AZUL}Datas:{Cores.RESET}")
    print(f"  {Cores.CIANO}Criado em:{Cores.RESET} {formatar_data(usuario['criado_em'])}")
    print(f"  {Cores.CIANO}Atualizado em:{Cores.RESET} {formatar_data(usuario['atualizado_em'])}")
    
    print(f"\n{Cores.AZUL}Links:{Cores.RESET}")
    print(f"  {Cores.CIANO}Perfil GitHub:{Cores.RESET} {usuario['url_perfil']}")
    print(f"  {Cores.CIANO}Avatar:{Cores.RESET} {usuario['avatar_url']}")
    
    return True

def exibir_repositorios(repositorios):
    """Exibe repositórios do usuário"""
    if not repositorios:
        print(f"{Cores.AMARELO}[!] Nenhum repositório encontrado{Cores.RESET}")
        return
    
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== REPOSITÓRIOS RECENTES ({len(repositorios)}) ==={Cores.RESET}")
    
    for i, repo in enumerate(repositorios, 1):
        print(f"\n{Cores.VERDE}{i}. {repo['nome']}{Cores.RESET}")
        
        if repo['descricao']:
            print(f"   {Cores.AZUL}Descrição:{Cores.RESET} {repo['descricao']}")
        
        if repo['linguagem']:
            print(f"   {Cores.AZUL}Linguagem:{Cores.RESET} {repo['linguagem']}")
        
        print(f"   {Cores.AZUL}Estatísticas:{Cores.RESET} ⭐ {repo['stars']} | 🍴 {repo['forks']} | 👀 {repo['watchers']}")
        
        if repo['tamanho']:
            tamanho_kb = repo['tamanho']
            if tamanho_kb > 1024:
                tamanho_mb = tamanho_kb / 1024
                print(f"   {Cores.AZUL}Tamanho:{Cores.RESET} {tamanho_mb:.1f} MB")
            else:
                print(f"   {Cores.AZUL}Tamanho:{Cores.RESET} {tamanho_kb} KB")
        
        print(f"   {Cores.AZUL}URL:{Cores.RESET} {repo['url']}")
        print(f"   {Cores.AZUL}Atualizado:{Cores.RESET} {formatar_data(repo['atualizado_em'])}")

def exibir_seguidores(seguidores):
    """Exibe seguidores do usuário"""
    if not seguidores:
        print(f"{Cores.AMARELO}[!] Nenhum seguidor encontrado{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== PRINCIPAIS SEGUIDORES ({len(seguidores)}) ==={Cores.RESET}")
    
    for seguidor in seguidores:
        print(f"  {Cores.VERDE}@{seguidor['login']}{Cores.RESET} - {seguidor['url']}")

def exibir_seguindo(seguindo):
    """Exibe quem o usuário está seguindo"""
    if not seguindo:
        print(f"{Cores.AMARELO}[!] Não segue ninguém{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== SEGUINDO ({len(seguindo)}) ==={Cores.RESET}")
    
    for user in seguindo:
        print(f"  {Cores.VERDE}@{user['login']}{Cores.RESET} - {user['url']}")

def exibir_organizacoes(organizacoes):
    """Exibe organizações do usuário"""
    if not organizacoes:
        print(f"{Cores.AMARELO}[!] Nenhuma organização encontrada{Cores.RESET}")
        return
    
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== ORGANIZAÇÕES ({len(organizacoes)}) ==={Cores.RESET}")
    
    for org in organizacoes:
        print(f"  {Cores.VERDE}@{org['login']}{Cores.RESET}")
        if org['descricao']:
            print(f"    {Cores.AZUL}Descrição:{Cores.RESET} {org['descricao']}")
        print(f"    {Cores.AZUL}URL:{Cores.RESET} {org['url']}")

def salvar_resultado(dados, username, formato='txt'):
    """Salva os resultados em arquivo"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_github', exist_ok=True)
        nome_arquivo = f"resultados_github/github_{username}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== INVESTIGAÇÃO GITHUB - @{username} ===\n\n")
                
                if 'usuario' in dados and 'erro' not in dados['usuario']:
                    usuario = dados['usuario']
                    f.write("DADOS DO USUÁRIO:\n")
                    f.write(f"Usuário: {usuario['login']} (ID: {usuario['id']})\n")
                    if usuario['nome']: f.write(f"Nome: {usuario['nome']}\n")
                    if usuario['bio']: f.write(f"Bio: {usuario['bio']}\n")
                    if usuario['empresa']: f.write(f"Empresa: {usuario['empresa']}\n")
                    if usuario['localizacao']: f.write(f"Localização: {usuario['localizacao']}\n")
                    if usuario['email']: f.write(f"Email: {usuario['email']}\n")
                    if usuario['blog']: f.write(f"Blog: {usuario['blog']}\n")
                    if usuario['twitter']: f.write(f"Twitter: @{usuario['twitter']}\n")
                    f.write(f"\nEstatísticas:\n")
                    f.write(f"- Repositórios: {usuario['repos_publicos']}\n")
                    f.write(f"- Seguidores: {usuario['seguidores']}\n")
                    f.write(f"- Seguindo: {usuario['seguindo']}\n")
                    f.write(f"- Gists: {usuario['gists_publicos']}\n")
                    f.write(f"- Criado em: {formatar_data(usuario['criado_em'])}\n")
                    f.write(f"- Atualizado em: {formatar_data(usuario['atualizado_em'])}\n")
                    f.write(f"- Perfil: {usuario['url_perfil']}\n\n")
                
                if 'repositorios' in dados and dados['repositorios']:
                    f.write("REPOSITÓRIOS RECENTES:\n")
                    for repo in dados['repositorios']:
                        f.write(f"- {repo['nome']}: {repo['url']}\n")
                        if repo['descricao']: f.write(f"  Descrição: {repo['descricao']}\n")
                        if repo['linguagem']: f.write(f"  Linguagem: {repo['linguagem']}\n")
                        f.write(f"  Stars: {repo['stars']} | Forks: {repo['forks']}\n\n")
                
                if 'organizacoes' in dados and dados['organizacoes']:
                    f.write("ORGANIZAÇÕES:\n")
                    for org in dados['organizacoes']:
                        f.write(f"- {org['login']}: {org['url']}\n")
                        if org['descricao']: f.write(f"  Descrição: {org['descricao']}\n\n")
                
                f.write(f"Data da consulta: {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Investigar Usuário GitHub")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O INVESTIGADOR GITHUB{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Dados completos do perfil GitHub
- Repositórios mais recentes
- Lista de seguidores e seguindo
- Organizações do usuário
- Análise de atividade e estatísticas
- Cache inteligente para performance

{Cores.AMARELO}Informações obtidas:{Cores.RESET}
- Dados pessoais (nome, bio, localização)
- Informações profissionais (empresa, blog)
- Estatísticas (repositórios, seguidores, stars)
- Datas de criação e atualização
- Links para perfil, repositórios e avatar
- Rede social (Twitter)

{Cores.AMARELO}Exemplos de usuários para teste:{Cores.RESET}
- torvalds (Linus Torvalds - Criador do Linux)
- gust (Gustavo Guanabara - Curso em Vídeo)
- microsoft (Microsoft Corporation)
- facebook (Meta Platforms)

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
                    username = input(f"\n{Cores.CIANO}Digite o username do GitHub: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not username:
                    print(f"{Cores.VERMELHO}[!] Username não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"\n{Cores.AMARELO}[*] Investigando usuário @{username}...{Cores.RESET}")
                
                # Consultar todos os dados em paralelo
                resultados = consultar_todos_dados(username)
                
                banner()
                print(f"{Cores.VERDE}{Cores.NEGRITO}RESULTADOS PARA @{username}{Cores.RESET}")
                
                # Exibir dados
                if 'usuario' in resultados:
                    sucesso = exibir_dados_usuario(resultados['usuario'])
                    
                    if sucesso:
                        if 'repositorios' in resultados:
                            exibir_repositorios(resultados['repositorios'])
                        
                        if 'organizacoes' in resultados:
                            exibir_organizacoes(resultados['organizacoes'])
                        
                        if 'seguidores' in resultados:
                            exibir_seguidores(resultados['seguidores'])
                        
                        if 'seguindo' in resultados:
                            exibir_seguindo(resultados['seguindo'])
                
                # Opção de exportação
                if resultados.get('usuario') and 'erro' not in resultados['usuario']:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(resultados, username, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(resultados, username, 'txt')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '2':
                sobre()
            
            elif opcao == '3':
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
        print(f"{Cores.CIANO}\nObrigado por usar o Investigador GitHub!{Cores.RESET}")

if __name__ == "__main__":
    main()
