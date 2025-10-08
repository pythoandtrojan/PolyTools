#!/usr/bin/env python3
import instaloader
import requests
import json
import re
import os
import time
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init
import mimetypes

init(autoreset=True)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

class InstagramScraperPremium:
    def __init__(self):
        self.L = instaloader.Instaloader()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def fazer_login(self, username, password):
        """Tenta fazer login no Instagram com tratamento melhorado"""
        try:
            print(f"{AMARELO}[*] Tentando login...{RESET}")
            self.L.login(username, password)
            print(f"{VERDE}[✓] Login realizado com sucesso{RESET}")
            return True
        except instaloader.exceptions.BadCredentialsException:
            print(f"{VERMELHO}[!] Credenciais inválidas{RESET}")
            return False
        except instaloader.exceptions.ConnectionException:
            print(f"{VERMELHO}[!] Erro de conexão{RESET}")
            return False
        except Exception as e:
            print(f"{VERMELHO}[!] Erro no login: {e}{RESET}")
            return False

    def baixar_foto_perfil(self, profile, username):
        """Baixa a foto de perfil em alta qualidade"""
        try:
            if not profile.profile_pic_url:
                print(f"{VERMELHO}[!] URL da foto de perfil não disponível{RESET}")
                return None
                
            print(f"{AMARELO}[*] Baixando foto de perfil...{RESET}")
            
            # Criar diretório para fotos
            foto_dir = f"instagram_{username}_fotos"
            os.makedirs(foto_dir, exist_ok=True)
            
            # Baixar imagem
            response = self.session.get(profile.profile_pic_url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Determinar extensão do arquivo
            content_type = response.headers.get('content-type', '')
            extension = mimetypes.guess_extension(content_type) or '.jpg'
            
            filename = f"{foto_dir}/foto_perfil_{username}{extension}"
            
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Obter metadados da imagem
            file_size = os.path.getsize(filename)
            file_size_mb = file_size / (1024 * 1024)
            
            foto_info = {
                'caminho': filename,
                'tamanho_bytes': file_size,
                'tamanho_mb': round(file_size_mb, 2),
                'url_original': profile.profile_pic_url,
                'resolucao': 'Variável (HD)',
                'formato': extension.replace('.', '').upper()
            }
            
            print(f"{VERDE}[✓] Foto baixada: {filename} ({file_size_mb:.2f} MB){RESET}")
            return foto_info
            
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao baixar foto: {e}{RESET}")
            return None

    def analisar_biografia_avancada(self, biography):
        """Análise avançada da biografia para extrair múltiplos dados"""
        dados = {
            'emails': [],
            'telefones': [],
            'links': [],
            'hashtags': [],
            'mencoes': [],
            'palavras_chave': []
        }
        
        if not biography:
            return dados
        
        # Extrair emails
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', biography)
        dados['emails'] = list(set(emails))  # Remove duplicatas
        
        # Extrair telefones (padrões brasileiros e internacionais)
        padroes_telefone = [
            r'(\+55\s?)?(\(?\d{2}\)?[\s-]?)?\d{4,5}[\s-]?\d{4}',  # Brasil
            r'\(\d{2}\)\s?\d{4,5}-\d{4}',  # (11) 99999-9999
            r'\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{4}',  # Internacional
            r'\d{4,5}[\s-]?\d{4}'  # 99999-9999
        ]
        
        telefones_encontrados = []
        for padrao in padroes_telefone:
            matches = re.findall(padrao, biography)
            for match in matches:
                if isinstance(match, tuple):
                    telefone = ''.join(match).strip()
                else:
                    telefone = match.strip()
                if len(telefone) >= 8:  # Número mínimo de dígitos
                    telefones_encontrados.append(telefone)
        
        dados['telefones'] = list(set(telefones_encontrados))
        
        # Extrair links
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        links = re.findall(url_pattern, biography)
        dados['links'] = list(set(links))
        
        # Extrair hashtags
        hashtags = re.findall(r'#\w+', biography)
        dados['hashtags'] = list(set(hashtags))
        
        # Extrair menções
        mencoes = re.findall(r'@\w+', biography)
        dados['mencoes'] = list(set(mencoes))
        
        # Palavras-chave importantes
        palavras_chave = re.findall(r'\b(?:contato|email|e-mail|telefone|tel|whatsapp|zap|instagram|fb|facebook|twitter|tiktok|youtube|linkedin|site|web|blog|loja|vendas|comercial)\b', biography, re.IGNORECASE)
        dados['palavras_chave'] = list(set(palavras_chave))
        
        return dados

    def scrape_perfil_completo(self, username):
        """Coleta dados completos do perfil do Instagram"""
        print(f"{AMARELO}[*] Coletando dados completos do perfil: @{username}{RESET}")
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            # Dados básicos do perfil
            dados_perfil = {
                'username': profile.username,
                'user_id': profile.userid,
                'nome_completo': profile.full_name,
                'biografia': profile.biography,
                'biografia_completa': self.analisar_biografia_avancada(profile.biography),
                'seguidores': profile.followers,
                'seguindo': profile.followees,
                'posts': profile.mediacount,
                'verificado': profile.is_verified,
                'privado': profile.is_private,
                'negocio': profile.is_business_account,
                'categoria_negocio': profile.business_category_name if profile.is_business_account else None,
                'url_perfil': f"https://instagram.com/{profile.username}",
                'url_foto_perfil': profile.profile_pic_url,
                'data_coleta': datetime.now().isoformat(),
                'detalhes_foto_perfil': None,
                'estatisticas': {
                    'ratio_seguidores_seguindo': round(profile.followers / max(profile.followees, 1), 2),
                    'engajamento_estimado': 'Baixo' if profile.followers > 10000 else 'Médio' if profile.followers > 1000 else 'Alto',
                    'posts_por_mes': 'Desconhecido'  # Poderia ser calculado com análise de posts
                }
            }
            
            # Baixar foto de perfil se solicitado
            baixar_foto = input(f"{CIANO}Deseja baixar a foto de perfil? (S/N): {RESET}").lower()
            if baixar_foto in ['s', 'sim']:
                foto_info = self.baixar_foto_perfil(profile, username)
                dados_perfil['detalhes_foto_perfil'] = foto_info
            
            print(f"{VERDE}[✓] Dados básicos coletados com sucesso{RESET}")
            return dados_perfil
            
        except instaloader.exceptions.ProfileNotExistsException:
            print(f"{VERMELHO}[!] Perfil @{username} não encontrado{RESET}")
            return None
        except instaloader.exceptions.PrivateProfileNotFollowedException:
            print(f"{VERMELHO}[!] Perfil privado - necessário seguir o perfil{RESET}")
            return None
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao coletar perfil: {e}{RESET}")
            return None

    def get_seguidores_detalhados(self, username, max_seguidores=500):
        """Obtém lista detalhada de seguidores"""
        print(f"{AMARELO}[*] Coletando seguidores detalhados...{RESET}")
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            if profile.is_private:
                print(f"{VERMELHO}[!] Perfil privado - não é possível obter seguidores{RESET}")
                return []
            
            seguidores_detalhados = []
            count = 0
            
            for follower in profile.get_followers():
                seguidor_info = {
                    'username': follower.username,
                    'user_id': follower.userid,
                    'nome_completo': follower.full_name,
                    'verificado': follower.is_verified,
                    'privado': follower.is_private,
                    'seguidores': follower.followers,
                    'seguindo': follower.followees,
                    'posts': follower.mediacount,
                    'biografia': follower.biography,
                    'url_perfil': f"https://instagram.com/{follower.username}",
                    'url_foto_perfil': follower.profile_pic_url
                }
                
                seguidores_detalhados.append(seguidor_info)
                count += 1
                
                if count % 50 == 0:
                    print(f"{AZUL}[*] Coletados {count} seguidores...{RESET}")
                
                if count >= max_seguidores:
                    break
                    
                # Delay para evitar bloqueio
                time.sleep(0.3)
            
            print(f"{VERDE}[✓] Total de seguidores coletados: {len(seguidores_detalhados)}{RESET}")
            return seguidores_detalhados
            
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao coletar seguidores: {e}{RESET}")
            return []

    def analisar_posts_recentes(self, username, max_posts=10):
        """Analisa os posts mais recentes do perfil"""
        print(f"{AMARELO}[*] Analisando posts recentes...{RESET}")
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            posts_analisados = []
            count = 0
            
            for post in profile.get_posts():
                post_info = {
                    'post_id': post.shortcode,
                    'legenda': post.caption,
                    'data_postagem': post.date_utc.isoformat(),
                    'likes': post.likes,
                    'comentarios': post.comments,
                    'url_post': f"https://instagram.com/p/{post.shortcode}",
                    'tipo': 'Video' if post.is_video else 'Imagem',
                    'url_midia': post.url,
                    'hashtags': re.findall(r'#\w+', post.caption) if post.caption else [],
                    'mencoes': re.findall(r'@\w+', post.caption) if post.caption else []
                }
                
                posts_analisados.append(post_info)
                count += 1
                
                if count >= max_posts:
                    break
            
            print(f"{VERDE}[✓] {len(posts_analisados)} posts analisados{RESET}")
            return posts_analisados
            
        except Exception as e:
            print(f"{VERMELHO}[!] Erro ao analisar posts: {e}{RESET}")
            return []

    def salvar_dados_completos(self, dados_perfil, seguidores, posts, username):
        """Salva todos os dados coletados de forma organizada"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = f"instagram_{username}_{timestamp}"
        os.makedirs(base_dir, exist_ok=True)
        
        # 1. Salvar dados principais do perfil
        perfil_filename = f"{base_dir}/01_perfil_principal.json"
        with open(perfil_filename, 'w', encoding='utf-8') as f:
            json.dump(dados_perfil, f, indent=2, ensure_ascii=False)
        
        # 2. Salvar seguidores ordenados
        if seguidores:
            # Ordenar por username (alfabeticamente)
            seguidores_ordenados = sorted(seguidores, key=lambda x: x['username'].lower())
            
            # JSON detalhado
            seguidores_json = f"{base_dir}/02_seguidores_detalhados.json"
            with open(seguidores_json, 'w', encoding='utf-8') as f:
                json.dump(seguidores_ordenados, f, indent=2, ensure_ascii=False)
            
            # TXT simplificado (apenas usernames)
            seguidores_txt = f"{base_dir}/03_seguidores_ordenados.txt"
            with open(seguidores_txt, 'w', encoding='utf-8') as f:
                f.write(f"SEGUIDORES DE @{username}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Total: {len(seguidores_ordenados)} seguidores | Coletado em: {datetime.now()}\n\n")
                
                for i, seg in enumerate(seguidores_ordenados, 1):
                    verificado = " ✓" if seg['verificado'] else ""
                    f.write(f"{i:4d}. @{seg['username']}{verificado} | {seg['nome_completo']}\n")
                    f.write(f"     Seguidores: {seg['seguidores']:,} | Seguindo: {seg['seguindo']:,} | Posts: {seg['posts']}\n")
                    if seg['biografia']:
                        f.write(f"     Bio: {seg['biografia'][:100]}{'...' if len(seg['biografia']) > 100 else ''}\n")
                    f.write("\n")
        
        # 3. Salvar análise de posts
        if posts:
            posts_filename = f"{base_dir}/04_posts_recentes.json"
            with open(posts_filename, 'w', encoding='utf-8') as f:
                json.dump(posts, f, indent=2, ensure_ascii=False)
        
        # 4. Salvar relatório resumido
        relatorio_filename = f"{base_dir}/00_RELATORIO_RESUMIDO.txt"
        with open(relatorio_filename, 'w', encoding='utf-8') as f:
            f.write("RELATÓRIO COMPLETO - INSTAGRAM SCRAPER\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"PERFIL ANALISADO: @{dados_perfil['username']}\n")
            f.write(f"Nome: {dados_perfil['nome_completo']}\n")
            f.write(f"Seguidores: {dados_perfil['seguidores']:,}\n")
            f.write(f"Seguindo: {dados_perfil['seguindo']:,}\n")
            f.write(f"Posts: {dados_perfil['posts']:,}\n")
            f.write(f"Verificado: {'Sim' if dados_perfil['verificado'] else 'Não'}\n")
            f.write(f"Privado: {'Sim' if dados_perfil['privado'] else 'Não'}\n\n")
            
            # Contatos encontrados
            bio_data = dados_perfil['biografia_completa']
            if bio_data['emails']:
                f.write("EMAILS ENCONTRADOS:\n")
                for email in bio_data['emails']:
                    f.write(f"  ✉️  {email}\n")
                f.write("\n")
            
            if bio_data['telefones']:
                f.write("TELEFONES ENCONTRADOS:\n")
                for tel in bio_data['telefones']:
                    f.write(f"  📞 {tel}\n")
                f.write("\n")
            
            if seguidores:
                f.write(f"SEGUIDORES COLETADOS: {len(seguidores)}\n")
                f.write("(Lista completa nos arquivos separados)\n\n")
            
            f.write(f"DATA DA COLETA: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        
        print(f"{VERDE}[✓] Todos os dados salvos em: {base_dir}/{RESET}")
        return base_dir

    def mostrar_resumo_premium(self, dados_perfil, seguidores, posts):
        """Exibe resumo completo e bem formatado dos dados coletados"""
        if not dados_perfil:
            return
            
        print(f"\n{CIANO}{NEGRITO}🎯 RELATÓRIO COMPLETO DO PERFIL{RESET}")
        print("=" * 60)
        
        # Informações básicas
        print(f"\n{AZUL}{NEGRITO}📊 INFORMAÇÕES BÁSICAS:{RESET}")
        print(f"  {BRANCO}👤 Usuário:{RESET} @{dados_perfil['username']}")
        print(f"  {BRANCO}🆔 ID:{RESET} {dados_perfil['user_id']}")
        print(f"  {BRANCO}📛 Nome:{RESET} {dados_perfil['nome_completo']}")
        print(f"  {BRANCO}👥 Seguidores:{RESET} {dados_perfil['seguidores']:,}")
        print(f"  {BRANCO}🔁 Seguindo:{RESET} {dados_perfil['seguindo']:,}")
        print(f"  {BRANCO}📸 Posts:{RESET} {dados_perfil['posts']:,}")
        print(f"  {BRANCO}✅ Verificado:{RESET} {'Sim' if dados_perfil['verificado'] else 'Não'}")
        print(f"  {BRANCO}🔒 Privado:{RESET} {'Sim' if dados_perfil['privado'] else 'Não'}")
        print(f"  {BRANCO}💼 Negócio:{RESET} {'Sim' if dados_perfil['negocio'] else 'Não'}")
        
        # Análise de contatos
        bio_data = dados_perfil['biografia_completa']
        
        if bio_data['emails']:
            print(f"\n{AZUL}{NEGRITO}📧 EMAILS ENCONTRADOS:{RESET}")
            for email in bio_data['emails']:
                print(f"  {VERDE}✉️  {email}{RESET}")
        
        if bio_data['telefones']:
            print(f"\n{AZUL}{NEGRITO}📞 TELEFONES ENCONTRADOS:{RESET}")
            for tel in bio_data['telefones']:
                print(f"  {VERDE}📱 {tel}{RESET}")
        
        if bio_data['links']:
            print(f"\n{AZUL}{NEGRITO}🔗 LINKS NA BIO:{RESET}")
            for link in bio_data['links'][:5]:  # Mostrar apenas os 5 primeiros
                print(f"  {CIANO}🌐 {link}{RESET}")
        
        # Estatísticas de seguidores
        if seguidores:
            print(f"\n{AZUL}{NEGRITO}👥 ANÁLISE DE SEGUIDORES:{RESET}")
            print(f"  {BRANCO}Total coletados:{RESET} {len(seguidores)}")
            
            # Top 5 seguidores com mais seguidores
            top_seguidores = sorted(seguidores, key=lambda x: x['seguidores'], reverse=True)[:5]
            print(f"  {BRANCO}Top 5 influenciadores:{RESET}")
            for i, seg in enumerate(top_seguidores, 1):
                print(f"    {i}. @{seg['username']} ({seg['seguidores']:,} seguidores)")
        
        # Informações da foto
        if dados_perfil['detalhes_foto_perfil']:
            foto_info = dados_perfil['detalhes_foto_perfil']
            print(f"\n{AZUL}{NEGRITO}🖼️  FOTO DE PERFIL:{RESET}")
            print(f"  {BRANCO}Arquivo:{RESET} {foto_info['caminho']}")
            print(f"  {BRANCO}Tamanho:{RESET} {foto_info['tamanho_mb']} MB")
            print(f"  {BRANCO}Formato:{RESET} {foto_info['formato']}")

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{MAGENTA}{NEGRITO}
██╗███╗   ██╗███████╗████████╗ █████╗  ██████╗ ██████╗  █████╗ ███╗   ███╗
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝ ██╔══██╗██╔══██╗████╗ ████║
██║██╔██╗ ██║███████╗   ██║   ███████║██║  ███╗██████╔╝███████║██╔████╔██║
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║
██║██║ ╚████║███████║   ██║   ██║  ██║╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
                                                                          
{RESET}
{CIANO}{NEGRITO}   INSTAGRAM SCRAPER PREMIUM v3.0
   Coletor Avançado de Dados de Perfis
{RESET}
{AMARELO}   ✓ Perfil completo + Foto + Biografia detalhada
   ✓ Seguidores ordenados + Análise
   ✓ Posts recentes + Metadados
   ✓ Emails, telefones, links da bio
   ✓ Relatórios organizados em pastas
{RESET}""")

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}🎪 MENU PRINCIPAL - SCRAPER PREMIUM{RESET}")
    print(f"{VERDE}[1]{RESET} 🚀 Scraping Completo Premium (Recomendado)")
    print(f"{VERDE}[2]{RESET} 📊 Scraping Básico (Sem login)")
    print(f"{VERDE}[3]{RESET} 📋 Apenas Seguidores (Com login)")
    print(f"{VERDE}[4]{RESET} ℹ️  Sobre o Scraper")
    print(f"{VERDE}[5]{RESET} 🚪 Sair")
    return input(f"\n{CIANO}🎯 Selecione uma opção: {RESET}")

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}📖 SOBRE O INSTAGRAM SCRAPER PREMIUM{RESET}

{AMARELO}🚀 FUNCIONALIDADES AVANÇADAS:{RESET}
• 📸 Download de foto de perfil em HD
• 📊 Análise completa da biografia
• 👥 Coleta detalhada de seguidores
• 📝 Análise de posts recentes
• 📧 Extração avançada de emails/telefones
• 📁 Organização automática em pastas

{AMARELO}🎯 DADOS COLETADOS:{RESET}
✓ Informações completas do perfil
✓ Metadados da foto de perfil
✓ Lista de seguidores ordenada alfabeticamente
✓ Estatísticas de engajamento
✓ Contatos (emails, telefones, links)
✓ Hashtags e menções da bio
✓ Posts recentes com análises

{AMARELO}⚠️  AVISOS IMPORTANTES:{RESET}
• Use apenas para fins educacionais
• Respeite os termos de serviço do Instagram
• Não faça scraping em massa
• Mantenha intervalos entre requisições
• Dados são apenas para análise legítima

{VERDE}📞 Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        scraper = InstagramScraperPremium()
        
        while True:
            opcao = menu_principal()
            
            if opcao in ['1', '2', '3']:
                banner()
                username = input(f"\n{CIANO}🎯 Digite o username do Instagram: {RESET}").strip().lower()
                
                if not username:
                    print(f"{VERMELHO}[!] Username não pode estar vazio{RESET}")
                    input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
                    continue
                
                # Login para modos que precisam
                if opcao in ['1', '3']:
                    print(f"\n{AMARELO}[*] 🔐 Login necessário{RESET}")
                    user = input(f"{CIANO}👤 Seu username Instagram: {RESET}").strip()
                    password = input(f"{CIANO}🔒 Sua senha: {RESET}").strip()
                    
                    if not user or not password:
                        print(f"{VERMELHO}[!] Credenciais necessárias{RESET}")
                        input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
                        continue
                    
                    if not scraper.fazer_login(user, password):
                        input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
                        continue
                
                # Coleta de dados baseada no modo selecionado
                print(f"\n{AMARELO}[*] 🚀 Iniciando coleta de dados...{RESET}")
                
                dados_perfil = None
                seguidores = []
                posts = []
                
                if opcao in ['1', '2']:  # Modos com perfil
                    dados_perfil = scraper.scrape_perfil_completo(username)
                    if not dados_perfil:
                        input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
                        continue
                
                if opcao in ['1', '3']:  # Modos com seguidores
                    max_seg = input(f"{CIANO}👥 Máximo de seguidores (padrão 500): {RESET}").strip()
                    max_seg = int(max_seg) if max_seg.isdigit() else 500
                    seguidores = scraper.get_seguidores_detalhados(username, max_seg)
                
                if opcao == '1':  # Apenas modo completo tem posts
                    posts = scraper.analisar_posts_recentes(username, 5)
                
                # Mostrar resumo
                scraper.mostrar_resumo_premium(dados_perfil, seguidores, posts)
                
                # Salvar dados
                if dados_perfil or seguidores:
                    salvar = input(f"\n{CIANO}💾 Salvar todos os dados? (S/N): {RESET}").lower()
                    if salvar in ['s', 'sim']:
                        scraper.salvar_dados_completos(dados_perfil, seguidores, posts, username)
                        print(f"{VERDE}[✓] ✅ Todos os dados foram salvos e organizados{RESET}")
                
                input(f"\n{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':  # Sobre
                sobre()
            
            elif opcao == '5':  # Sair
                print(f"\n{VERDE}[+] 👋 Saindo... Obrigado por usar o Scraper Premium!{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] ❌ Opção inválida!{RESET}")
                input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] 🚫 Programa interrompido{RESET}")
        exit()
    except Exception as e:
        print(f"{VERMELHO}[!] 💥 Erro inesperado: {e}{RESET}")
        exit()

if __name__ == "__main__":
    main()
