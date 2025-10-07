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
os.makedirs('cache_reddit', exist_ok=True)
TEMPO_CACHE = 3600  # 1 hora em segundos

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ██████╗ ███████╗██████╗ ██████╗ ██╗████████╗
   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║╚══██╔══╝
   ██████╔╝█████╗  ██║  ██║██║  ██║██║   ██║   
   ██╔══██╗██╔══╝  ██║  ██║██║  ██║██║   ██║   
   ██║  ██║███████╗██████╔╝██████╔╝██║   ██║   
   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   INVESTIGADOR REDDIT
   OSINT de Usuários Reddit
{Cores.RESET}
{Cores.AMARELO}   Dados completos + Estatísticas + Atividade
   Análise detalhada de perfil
{Cores.RESET}""")

def gerar_hash(texto):
    if not texto:
        return ""
    return hashlib.md5(texto.encode()).hexdigest()

def cache_arquivo(nome, dados=None):
    try:
        caminho = f"cache_reddit/{nome}.json"
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

def consultar_usuario_reddit(username):
    """Consulta dados básicos do usuário Reddit"""
    cache_id = f"reddit_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://www.reddit.com/user/{username}/about.json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Reddit Investigator v1.0)',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            if dados and 'data' in dados:
                user_data = dados['data']
                
                # Processar dados do usuário
                usuario = {
                    'username': user_data.get('name', ''),
                    'id': user_data.get('id', ''),
                    'tipo': dados.get('kind', ''),
                    'criado_em': user_data.get('created_utc', ''),
                    'karma_total': user_data.get('total_karma', 0),
                    'karma_links': user_data.get('link_karma', 0),
                    'karma_comentarios': user_data.get('comment_karma', 0),
                    'karma_premiador': user_data.get('awarder_karma', 0),
                    'karma_premiado': user_data.get('awardee_karma', 0),
                    'verificado': user_data.get('verified', False),
                    'ouro': user_data.get('is_gold', False),
                    'moderador': user_data.get('is_mod', False),
                    'funcionario': user_data.get('is_employee', False),
                    'email_verificado': user_data.get('has_verified_email', False),
                    'icone_img': user_data.get('icon_img', ''),
                    'aceita_seguidores': user_data.get('accept_followers', False),
                    'aceita_mensagens': user_data.get('accept_pms', True),
                    'aceita_chats': user_data.get('accept_chats', True),
                    'escondido_robos': user_data.get('hide_from_robots', False),
                    'inscrito': user_data.get('has_subscribed', True),
                    'bloqueado': user_data.get('is_blocked', False),
                    'amigo': user_data.get('is_friend', False),
                    'url_perfil': f"https://www.reddit.com/user/{username}",
                    'snoovatar_img': user_data.get('snoovatar_img', ''),
                    'snoovatar_size': user_data.get('snoovatar_size', ''),
                    'mostrar_snoovatar': user_data.get('pref_show_snoovatar', False)
                }
                
                # Dados do subreddit personalizado
                if 'subreddit' in user_data:
                    sub_data = user_data['subreddit']
                    usuario.update({
                        'titulo_subreddit': sub_data.get('title', ''),
                        'descricao_publica': sub_data.get('public_description', ''),
                        'descricao': sub_data.get('description', ''),
                        'icone_subreddit': sub_data.get('icon_img', ''),
                        'banner_img': sub_data.get('banner_img', ''),
                        'header_img': sub_data.get('header_img', ''),
                        'cor_icone': sub_data.get('icon_color', ''),
                        'cor_primaria': sub_data.get('primary_color', ''),
                        'cor_chave': sub_data.get('key_color', ''),
                        'adulto': sub_data.get('over_18', False),
                        'quarentena': sub_data.get('quarantine', False),
                        'tipo_subreddit': sub_data.get('subreddit_type', ''),
                        'inscritos': sub_data.get('subscribers', 0),
                        'url_subreddit': f"https://www.reddit.com{sub_data.get('url', '')}",
                        'nome_exibicao': sub_data.get('display_name', ''),
                        'nome_exibicao_prefixo': sub_data.get('display_name_prefixed', '')
                    })
                
                cache_arquivo(cache_id, usuario)
                return usuario
        elif response.status_code == 404:
            return {'erro': 'Usuário não encontrado'}
        elif response.status_code == 429:
            return {'erro': 'Limite de requisições excedido. Tente novamente mais tarde.'}
    except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
        return {'erro': f'Erro na consulta: {str(e)}'}
    
    return {'erro': 'Erro desconhecido'}

def consultar_posts_recentes(username):
    """Consulta posts recentes do usuário"""
    cache_id = f"posts_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://www.reddit.com/user/{username}/submitted.json?limit=5"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Reddit Investigator v1.0)',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            posts = []
            
            if 'data' in dados and 'children' in dados['data']:
                for post in dados['data']['children'][:3]:  # Limitar a 3 posts
                    post_data = post['data']
                    posts.append({
                        'titulo': post_data.get('title', ''),
                        'subreddit': post_data.get('subreddit', ''),
                        'upvotes': post_data.get('ups', 0),
                        'downvotes': post_data.get('downs', 0),
                        'score': post_data.get('score', 0),
                        'comentarios': post_data.get('num_comments', 0),
                        'criado_em': post_data.get('created_utc', ''),
                        'url': f"https://reddit.com{post_data.get('permalink', '')}",
                        'tipo': post_data.get('post_hint', 'text'),
                        'texto': post_data.get('selftext', '')[:200] + '...' if post_data.get('selftext') else '',
                        'nsfw': post_data.get('over_18', False),
                        'spoiler': post_data.get('spoiler', False)
                    })
            
            cache_arquivo(cache_id, posts)
            return posts
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_comentarios_recentes(username):
    """Consulta comentários recentes do usuário"""
    cache_id = f"comentarios_{username}"
    cached = cache_arquivo(cache_id)
    if cached:
        return cached
    
    try:
        url = f"https://www.reddit.com/user/{username}/comments.json?limit=5"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Reddit Investigator v1.0)',
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            dados = response.json()
            comentarios = []
            
            if 'data' in dados and 'children' in dados['data']:
                for comment in dados['data']['children'][:3]:  # Limitar a 3 comentários
                    comment_data = comment['data']
                    comentarios.append({
                        'subreddit': comment_data.get('subreddit', ''),
                        'post_pai': comment_data.get('link_title', '')[:100],
                        'texto': comment_data.get('body', '')[:150] + '...',
                        'upvotes': comment_data.get('ups', 0),
                        'score': comment_data.get('score', 0),
                        'criado_em': comment_data.get('created_utc', ''),
                        'url': f"https://reddit.com{comment_data.get('permalink', '')}",
                        'controversialidade': comment_data.get('controversiality', 0)
                    })
            
            cache_arquivo(cache_id, comentarios)
            return comentarios
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        pass
    
    return []

def consultar_todos_dados(username):
    """Consulta todos os dados do usuário em paralelo"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            'usuario': executor.submit(consultar_usuario_reddit, username),
            'posts': executor.submit(consultar_posts_recentes, username),
            'comentarios': executor.submit(consultar_comentarios_recentes, username)
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

def formatar_data(timestamp):
    """Formata timestamp Unix para formato legível"""
    try:
        if timestamp:
            data = datetime.fromtimestamp(float(timestamp))
            return data.strftime("%d/%m/%Y %H:%M:%S")
    except:
        pass
    return timestamp

def calcular_idade_conta(timestamp):
    """Calcula a idade da conta em anos"""
    try:
        if timestamp:
            criacao = datetime.fromtimestamp(float(timestamp))
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
    print(f"{Cores.AZUL}Usuário:{Cores.RESET} {Cores.VERDE}u/{usuario['username']}{Cores.RESET} (ID: {usuario['id']})")
    
    if usuario.get('titulo_subreddit'):
        print(f"{Cores.AZUL}Título:{Cores.RESET} {usuario['titulo_subreddit']}")
    
    if usuario.get('descricao_publica'):
        print(f"{Cores.AZUL}Descrição:{Cores.RESET} {usuario['descricao_publica']}")
    
    print(f"\n{Cores.AZUL}Status da Conta:{Cores.RESET}")
    print(f"  {Cores.CIANO}Verificado:{Cores.RESET} {'Sim' if usuario['verificado'] else 'Não'}")
    print(f"  {Cores.CIANO}Email Verificado:{Cores.RESET} {'Sim' if usuario['email_verificado'] else 'Não'}")
    print(f"  {Cores.CIANO}Reddit Gold:{Cores.RESET} {'Sim' if usuario['ouro'] else 'Não'}")
    print(f"  {Cores.CIANO}Moderador:{Cores.RESET} {'Sim' if usuario['moderador'] else 'Não'}")
    print(f"  {Cores.CIANO}Funcionário:{Cores.RESET} {'Sim' if usuario['funcionario'] else 'Não'}")
    print(f"  {Cores.CIANO}Conteúdo Adulto:{Cores.RESET} {'Sim' if usuario.get('adulto', False) else 'Não'}")
    
    print(f"\n{Cores.AZUL}Estatísticas de Karma:{Cores.RESET}")
    print(f"  {Cores.CIANO}Total:{Cores.RESET} {usuario['karma_total']:,}")
    print(f"  {Cores.CIANO}Posts:{Cores.RESET} {usuario['karma_links']:,}")
    print(f"  {Cores.CIANO}Comentários:{Cores.RESET} {usuario['karma_comentarios']:,}")
    print(f"  {Cores.CIANO}Premiador:{Cores.RESET} {usuario['karma_premiador']:,}")
    print(f"  {Cores.CIANO}Premiado:{Cores.RESET} {usuario['karma_premiado']:,}")
    
    idade_conta = calcular_idade_conta(usuario['criado_em'])
    if idade_conta:
        print(f"\n{Cores.AZUL}Idade da Conta:{Cores.RESET} {idade_conta} anos")
    
    print(f"\n{Cores.AZUL}Datas:{Cores.RESET}")
    print(f"  {Cores.CIANO}Criado em:{Cores.RESET} {formatar_data(usuario['criado_em'])}")
    
    print(f"\n{Cores.AZUL}Configurações de Privacidade:{Cores.RESET}")
    print(f"  {Cores.CIANO}Aceita Seguidores:{Cores.RESET} {'Sim' if usuario['aceita_seguidores'] else 'Não'}")
    print(f"  {Cores.CIANO}Aceita Mensagens:{Cores.RESET} {'Sim' if usuario['aceita_mensagens'] else 'Não'}")
    print(f"  {Cores.CIANO}Aceita Chats:{Cores.RESET} {'Sim' if usuario['aceita_chats'] else 'Não'}")
    print(f"  {Cores.CIANO}Escondido de Robôs:{Cores.RESET} {'Sim' if usuario['escondido_robos'] else 'Não'}")
    
    print(f"\n{Cores.AZUL}Links:{Cores.RESET}")
    print(f"  {Cores.CIANO}Perfil:{Cores.RESET} {usuario['url_perfil']}")
    if usuario.get('url_subreddit'):
        print(f"  {Cores.CIANO}Subreddit:{Cores.RESET} {usuario['url_subreddit']}")
    if usuario['icone_img']:
        print(f"  {Cores.CIANO}Ícone:{Cores.RESET} {usuario['icone_img']}")
    
    return True

def exibir_posts_recentes(posts):
    """Exibe posts recentes do usuário"""
    if not posts:
        print(f"{Cores.AMARELO}[!] Nenhum post recente encontrado{Cores.RESET}")
        return
    
    print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}=== POSTS RECENTES ({len(posts)}) ==={Cores.RESET}")
    
    for i, post in enumerate(posts, 1):
        print(f"\n{Cores.VERDE}{i}. {post['titulo'][:80]}{'...' if len(post['titulo']) > 80 else ''}{Cores.RESET}")
        print(f"   {Cores.AZUL}Subreddit:{Cores.RESET} r/{post['subreddit']}")
        print(f"   {Cores.AZUL}Score:{Cores.RESET} ⬆️ {post['upvotes']} | ⬇️ {post['downvotes']} | 💬 {post['comentarios']}")
        
        if post['texto']:
            print(f"   {Cores.AZUL}Conteúdo:{Cores.RESET} {post['texto']}")
        
        if post['nsfw']:
            print(f"   {Cores.VERMELHO}🚫 NSFW{Cores.RESET}")
        if post['spoiler']:
            print(f"   {Cores.AMARELO}⚠️  SPOILER{Cores.RESET}")
        
        print(f"   {Cores.AZUL}Postado:{Cores.RESET} {formatar_data(post['criado_em'])}")
        print(f"   {Cores.AZUL}URL:{Cores.RESET} {post['url']}")

def exibir_comentarios_recentes(comentarios):
    """Exibe comentários recentes do usuário"""
    if not comentarios:
        print(f"{Cores.AMARELO}[!] Nenhum comentário recente encontrado{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== COMENTÁRIOS RECENTES ({len(comentarios)}) ==={Cores.RESET}")
    
    for i, comentario in enumerate(comentarios, 1):
        print(f"\n{Cores.VERDE}{i}. r/{comentario['subreddit']}{Cores.RESET}")
        print(f"   {Cores.AZUL}Post:{Cores.RESET} {comentario['post_pai']}")
        print(f"   {Cores.AZUL}Comentário:{Cores.RESET} {comentario['texto']}")
        print(f"   {Cores.AZUL}Score:{Cores.RESET} ⬆️ {comentario['upvotes']}")
        print(f"   {Cores.AZUL}Postado:{Cores.RESET} {formatar_data(comentario['criado_em'])}")
        print(f"   {Cores.AZUL}URL:{Cores.RESET} {comentario['url']}")

def salvar_resultado(dados, username, formato='txt'):
    """Salva os resultados em arquivo"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_reddit', exist_ok=True)
        nome_arquivo = f"resultados_reddit/reddit_{username}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(dados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== INVESTIGAÇÃO REDDIT - u/{username} ===\n\n")
                
                if 'usuario' in dados and 'erro' not in dados['usuario']:
                    usuario = dados['usuario']
                    f.write("DADOS DO USUÁRIO:\n")
                    f.write(f"Usuário: u/{usuario['username']} (ID: {usuario['id']})\n")
                    if usuario.get('titulo_subreddit'): f.write(f"Título: {usuario['titulo_subreddit']}\n")
                    if usuario.get('descricao_publica'): f.write(f"Descrição: {usuario['descricao_publica']}\n")
                    
                    f.write(f"\nSTATUS DA CONTA:\n")
                    f.write(f"- Verificado: {'Sim' if usuario['verificado'] else 'Não'}\n")
                    f.write(f"- Email Verificado: {'Sim' if usuario['email_verificado'] else 'Não'}\n")
                    f.write(f"- Reddit Gold: {'Sim' if usuario['ouro'] else 'Não'}\n")
                    f.write(f"- Moderador: {'Sim' if usuario['moderador'] else 'Não'}\n")
                    f.write(f"- Funcionário: {'Sim' if usuario['funcionario'] else 'Não'}\n")
                    f.write(f"- Conteúdo Adulto: {'Sim' if usuario.get('adulto', False) else 'Não'}\n")
                    
                    f.write(f"\nESTATÍSTICAS DE KARMA:\n")
                    f.write(f"- Total: {usuario['karma_total']:,}\n")
                    f.write(f"- Posts: {usuario['karma_links']:,}\n")
                    f.write(f"- Comentários: {usuario['karma_comentarios']:,}\n")
                    f.write(f"- Premiador: {usuario['karma_premiador']:,}\n")
                    f.write(f"- Premiado: {usuario['karma_premiado']:,}\n")
                    
                    idade_conta = calcular_idade_conta(usuario['criado_em'])
                    if idade_conta:
                        f.write(f"- Idade da Conta: {idade_conta} anos\n")
                    
                    f.write(f"\nDATAS:\n")
                    f.write(f"- Criado em: {formatar_data(usuario['criado_em'])}\n")
                    
                    f.write(f"\nLINKS:\n")
                    f.write(f"- Perfil: {usuario['url_perfil']}\n")
                    if usuario.get('url_subreddit'):
                        f.write(f"- Subreddit: {usuario['url_subreddit']}\n")
                    f.write(f"\n")
                
                if 'posts' in dados and dados['posts']:
                    f.write("POSTS RECENTES:\n")
                    for post in dados['posts']:
                        f.write(f"- {post['titulo']}\n")
                        f.write(f"  Subreddit: r/{post['subreddit']}\n")
                        f.write(f"  Score: {post['score']} | Comentários: {post['comentarios']}\n")
                        f.write(f"  URL: {post['url']}\n\n")
                
                if 'comentarios' in dados and dados['comentarios']:
                    f.write("COMENTÁRIOS RECENTES:\n")
                    for comentario in dados['comentarios']:
                        f.write(f"- r/{comentario['subreddit']}\n")
                        f.write(f"  Post: {comentario['post_pai']}\n")
                        f.write(f"  Comentário: {comentario['texto']}\n")
                        f.write(f"  URL: {comentario['url']}\n\n")
                
                f.write(f"Data da consulta: {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Investigar Usuário Reddit")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O INVESTIGADOR REDDIT{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Dados completos do perfil Reddit
- Estatísticas detalhadas de karma
- Posts e comentários recentes
- Informações de privacidade e configurações
- Análise de atividade e histórico
- Cache inteligente para performance

{Cores.AMARELO}Informações obtidas:{Cores.RESET}
- Dados básicos (username, ID, datas)
- Status da conta (verificado, gold, moderador)
- Estatísticas de karma (total, posts, comentários)
- Configurações de privacidade
- Posts e comentários recentes
- Links para perfil e conteúdo

{Cores.AMARELO}Exemplos de usuários para teste:{Cores.RESET}
- spez (CEO do Reddit)
- awkwardtheturtle (Moderador famoso)
- GallowBoob (Power user)
- _vargas_ (Usuário popular)

{Cores.AMARELO}Limitações:{Cores.RESET}
- Usuários privados/bloqueados não são acessíveis
- Limite de requisições da API
- Alguns dados podem estar indisponíveis

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
                    username = input(f"\n{Cores.CIANO}Digite o username do Reddit (sem u/): {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not username:
                    print(f"{Cores.VERMELHO}[!] Username não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                # Remover u/ se o usuário incluiu
                username = username.replace('u/', '').strip()
                
                print(f"\n{Cores.AMARELO}[*] Investigando usuário u/{username}...{Cores.RESET}")
                
                # Consultar todos os dados em paralelo
                resultados = consultar_todos_dados(username)
                
                banner()
                print(f"{Cores.VERDE}{Cores.NEGRITO}RESULTADOS PARA u/{username}{Cores.RESET}")
                
                # Exibir dados
                if 'usuario' in resultados:
                    sucesso = exibir_dados_usuario(resultados['usuario'])
                    
                    if sucesso:
                        if 'posts' in resultados:
                            exibir_posts_recentes(resultados['posts'])
                        
                        if 'comentarios' in resultados:
                            exibir_comentarios_recentes(resultados['comentarios'])
                
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
        print(f"{Cores.CIANO}\nObrigado por usar o Investigador Reddit!{Cores.RESET}")

if __name__ == "__main__":
    main()
