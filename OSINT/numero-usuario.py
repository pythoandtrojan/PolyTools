#!/usr/bin/env python3
import os
import requests
import time
import sys
import re
from colorama import init, Fore, Back, Style

# Inicializar colorama
init(autoreset=True)

# Configurações
PASTA_RESULTADOS = "TheLurker_Phone"
os.makedirs(PASTA_RESULTADOS, exist_ok=True)

# Banner THE LURKER
BANNER = f"""
{Fore.RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{Fore.RED}▓                                                                        ▓
{Fore.RED}▓  {Fore.WHITE}████████╗██╗  ██╗███████╗    {Fore.RED}██╗     ██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}╚══██╔══╝██║  ██║██╔════╝    {Fore.RED}██║     ██║   ██║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ███████║█████╗      {Fore.RED}██║     ██║   ██║██████╔╝█████╔╝ █████╗  ██████╔╝ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ██╔══██║██╔══╝      {Fore.RED}██║     ██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══██╗ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ██║   ██║  ██║███████╗    {Fore.RED}███████╗╚██████╔╝██║  ██║██║  ██╗███████╗██║  ██║ {Fore.RED}▓
{Fore.RED}▓  {Fore.WHITE}   ╚═╝   ╚═╝  ╚═╝╚══════╝    {Fore.RED}╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ {Fore.RED}▓
{Fore.RED}▓                                                                        ▓
{Fore.RED}▓  {Fore.YELLOW}📱 THE LURKER - Busca por Telefone v2.0                  {Fore.RED}▓
{Fore.RED}▓  {Fore.CYAN}Developed by Erik 16y - Linux & Termux Expert              {Fore.RED}▓
{Fore.RED}▓  {Fore.MAGENTA}Made in Brazil with ❤️                                   {Fore.RED}▓
{Fore.RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{Style.RESET_ALL}"""

def animar_texto(texto, delay=0.03):
    """Animação de digitação"""
    for char in texto:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_loading(texto="Escaneando", duracao=2):
    """Animação de loading"""
    animacao = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    fim_tempo = time.time() + duracao
    i = 0
    
    while time.time() < fim_tempo:
        print(f"\r{Fore.CYAN}{animacao[i % len(animacao)]} {texto}...{Style.RESET_ALL}", end="")
        time.sleep(0.1)
        i += 1
    print("\r" + " " * 60 + "\r", end="")

def formatar_numero_telefone(numero):
    """Formata número para padrão internacional"""
    # Remove caracteres não numéricos
    numero_limpo = re.sub(r'\D', '', numero)
    
    # Adiciona código do Brasil se necessário
    if numero_limpo.startswith('55'):
        return numero_limpo
    elif len(numero_limpo) == 11:  # DDD + número (11 99999-9999)
        return '55' + numero_limpo
    elif len(numero_limpo) == 10:  # DDD + número sem 9 (11 9999-9999)
        return '55' + numero_limpo
    elif len(numero_limpo) == 9:   # Apenas número com 9 (99999-9999)
        return '5511' + numero_limpo  # Assume SP como DDD padrão
    elif len(numero_limpo) == 8:   # Apenas número sem 9 (9999-9999)
        return '5511' + numero_limpo  # Assume SP como DDD padrão
    else:
        return numero_limpo

def fazer_requisicao(url, method="GET"):
    """Faz requisição HTTP com headers personalizados"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    try:
        if method == "HEAD":
            resposta = requests.head(url, headers=headers, timeout=15, allow_redirects=True)
            if resposta.status_code == 405:  # HEAD não suportado
                resposta = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        else:
            resposta = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        
        return resposta
    except Exception as e:
        return None

def verificar_whatsapp_business(numero):
    """Verifica se o número tem WhatsApp Business"""
    url = f"https://wa.me/{numero}"
    
    try:
        resposta = fazer_requisicao(url)
        if resposta:
            # WhatsApp Business geralmente redireciona ou tem conteúdo específico
            if resposta.status_code == 200:
                # Verifica se é conta business por conteúdo da página
                if "business" in resposta.text.lower() or "comercial" in resposta.text.lower():
                    return {
                        'encontrado': True,
                        'tipo': 'WhatsApp Business',
                        'url': url,
                        'detalhes': 'Conta comercial encontrada',
                        'status': '🟢 ATIVO'
                    }
                else:
                    return {
                        'encontrado': True,
                        'tipo': 'WhatsApp Pessoal',
                        'url': url,
                        'detalhes': 'Conta pessoal encontrada',
                        'status': '🟡 PESSOAL'
                    }
        return {
            'encontrado': False,
            'tipo': 'WhatsApp',
            'url': url,
            'detalhes': 'Número não encontrado no WhatsApp',
            'status': '🔴 NÃO ENCONTRADO'
        }
    except:
        return {
            'encontrado': False,
            'tipo': 'WhatsApp',
            'url': url,
            'detalhes': 'Erro na verificação',
            'status': '⚫ ERRO'
        }

def verificar_telegram(numero):
    """Verifica se o número está no Telegram"""
    url = f"https://t.me/+{numero}"
    
    try:
        resposta = fazer_requisicao(url)
        if resposta:
            if resposta.status_code == 200:
                # Telegram mostra página de perfil se o número estiver registrado
                if "tgme_page" in resposta.text or "tgme_username" in resposta.text:
                    return {
                        'encontrado': True,
                        'tipo': 'Telegram',
                        'url': url,
                        'detalhes': 'Usuário encontrado no Telegram',
                        'status': '🟢 ENCONTRADO'
                    }
        return {
            'encontrado': False,
            'tipo': 'Telegram',
            'url': url,
            'detalhes': 'Número não registrado no Telegram',
            'status': '🔴 NÃO ENCONTRADO'
        }
    except:
        return {
            'encontrado': False,
            'tipo': 'Telegram',
            'url': url,
            'detalhes': 'Erro na verificação',
            'status': '⚫ ERRO'
        }

def verificar_truecaller(numero):
    """Verifica informações no Truecaller"""
    url = f"https://www.truecaller.com/search/br/{numero}"
    
    try:
        resposta = fazer_requisicao(url)
        if resposta:
            if resposta.status_code == 200:
                # Truecaller mostra informações se o número estiver no banco de dados
                if "profileName" in resposta.text or "truecaller" in resposta.text:
                    return {
                        'encontrado': True,
                        'tipo': 'Truecaller',
                        'url': url,
                        'detalhes': 'Informações disponíveis no Truecaller',
                        'status': '🟢 DADOS ENCONTRADOS'
                    }
        return {
            'encontrado': False,
            'tipo': 'Truecaller',
            'url': url,
            'detalhes': 'Número não encontrado no Truecaller',
            'status': '🔴 NÃO ENCONTRADO'
        }
    except:
        return {
            'encontrado': False,
            'tipo': 'Truecaller',
            'url': url,
            'detalhes': 'Erro na verificação',
            'status': '⚫ ERRO'
        }

def verificar_listas_telefonicas(numero):
    """Verifica em listas telefônicas brasileiras"""
    sites = {
        "Telelistas": f"https://www.telelistas.net/busca/{numero}",
        "Apontador": f"https://www.apontador.com.br/telefones/{numero}",
        "Listão": f"https://www.listao.com.br/telefone/{numero}"
    }
    
    resultados = []
    
    for nome, url in sites.items():
        try:
            resposta = fazer_requisicao(url)
            if resposta and resposta.status_code == 200:
                resultados.append({
                    'encontrado': True,
                    'tipo': f'Lista Telefônica - {nome}',
                    'url': url,
                    'detalhes': 'Possível listing encontrado',
                    'status': '🟢 POSSÍVEL LISTAGEM'
                })
            else:
                resultados.append({
                    'encontrado': False,
                    'tipo': f'Lista Telefônica - {nome}',
                    'url': url,
                    'detalhes': 'Número não listado',
                    'status': '🔴 NÃO LISTADO'
                })
        except:
            resultados.append({
                'encontrado': False,
                'tipo': f'Lista Telefônica - {nome}',
                'url': url,
                'detalhes': 'Erro na verificação',
                'status': '⚫ ERRO'
            })
    
    return resultados

def verificar_redes_sociais_vinculadas(numero):
    """Verifica redes sociais que podem estar vinculadas ao número"""
    # Estas verificações são indiretas, baseadas em padrões
    resultados = []
    
    # Facebook (busca indireta)
    try:
        url_facebook = f"https://www.facebook.com/search/top/?q={numero}"
        resposta = fazer_requisicao(url_facebook)
        if resposta and resposta.status_code == 200:
            resultados.append({
                'encontrado': True,
                'tipo': 'Facebook (Busca)',
                'url': url_facebook,
                'detalhes': 'Possível vinculação encontrada',
                'status': '🟡 POSSÍVEL VINCULO'
            })
    except:
        pass
    
    # Instagram (busca indireta)
    try:
        url_instagram = f"https://www.instagram.com/web/search/topsearch/?query={numero}"
        resposta = fazer_requisicao(url_instagram)
        if resposta and resposta.status_code == 200:
            resultados.append({
                'encontrado': True,
                'tipo': 'Instagram (Busca)',
                'url': 'https://www.instagram.com',
                'detalhes': 'Busca por número realizada',
                'status': '🟡 BUSCA REALIZADA'
            })
    except:
        pass
    
    return resultados if resultados else [{
        'encontrado': False,
        'tipo': 'Redes Sociais',
        'url': '',
        'detalhes': 'Nenhum vínculo direto encontrado',
        'status': '🔴 SEM VÍNCULOS'
    }]

def analisar_numero(numero):
    """Análise completa do número de telefone"""
    print(f"\n{Fore.YELLOW}🔍 Iniciando análise do número: {numero}{Style.RESET_ALL}")
    
    # Formatar número
    numero_formatado = formatar_numero_telefone(numero)
    print(f"{Fore.CYAN}📞 Número formatado: +{numero_formatado}{Style.RESET_ALL}")
    
    resultados = []
    
    # WhatsApp Business
    mostrar_loading("Verificando WhatsApp")
    resultados.append(verificar_whatsapp_business(numero_formatado))
    
    # Telegram
    mostrar_loading("Verificando Telegram")
    resultados.append(verificar_telegram(numero_formatado))
    
    # Truecaller
    mostrar_loading("Verificando Truecaller")
    resultados.append(verificar_truecaller(numero_formatado))
    
    # Listas Telefônicas
    mostrar_loading("Verificando listas telefônicas")
    resultados.extend(verificar_listas_telefonicas(numero))
    
    # Redes Sociais
    mostrar_loading("Buscando vínculos em redes sociais")
    resultados.extend(verificar_redes_sociais_vinculadas(numero))
    
    return resultados

def mostrar_resultados(resultados, numero):
    """Exibe os resultados de forma organizada"""
    print(f"\n{Fore.GREEN}═" * 70)
    print(f"📊 RESULTADOS DA BUSCA: {numero}")
    print("═" * 70 + f"{Style.RESET_ALL}\n")
    
    encontrados = [r for r in resultados if r['encontrado']]
    nao_encontrados = [r for r in resultados if not r['encontrado'] and 'ERRO' not in r['status']]
    erros = [r for r in resultados if 'ERRO' in r['status']]
    
    # Mostrar encontrados primeiro
    if encontrados:
        print(f"{Fore.GREEN}🎯 INFORMAÇÕES ENCONTRADAS:{Style.RESET_ALL}\n")
        for resultado in encontrados:
            print(f"  {resultado['status']} {Fore.CYAN}{resultado['tipo']}{Style.RESET_ALL}")
            print(f"     📋 {resultado['detalhes']}")
            if resultado['url']:
                print(f"     🌐 {resultado['url']}")
            print()
    
    # Mostrar não encontrados
    if nao_encontrados:
        print(f"{Fore.YELLOW}⚠️  NÃO ENCONTRADOS:{Style.RESET_ALL}\n")
        for resultado in nao_encontrados:
            print(f"  {resultado['status']} {Fore.YELLOW}{resultado['tipo']}{Style.RESET_ALL}")
            print(f"     📋 {resultado['detalhes']}")
            print()
    
    # Mostrar erros
    if erros:
        print(f"{Fore.RED}❌ ERROS NA VERIFICAÇÃO:{Style.RESET_ALL}\n")
        for resultado in erros:
            print(f"  {resultado['status']} {Fore.RED}{resultado['tipo']}{Style.RESET_ALL}")
            print(f"     📋 {resultado['detalhes']}")
            print()
    
    # Resumo
    print(f"{Fore.MAGENTA}📈 RESUMO DA BUSCA:{Style.RESET_ALL}")
    print(f"   ✅ Encontrados: {len(encontrados)}")
    print(f"   ❌ Não encontrados: {len(nao_encontrados)}")
    print(f"   ⚫ Erros: {len(erros)}")
    print(f"   📊 Total de verificações: {len(resultados)}")

def salvar_resultados(resultados, numero):
    """Salva os resultados em arquivo"""
    nome_arquivo = f"resultado_{numero}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    caminho_arquivo = os.path.join(PASTA_RESULTADOS, nome_arquivo)
    
    with open(caminho_arquivo, 'w', encoding='utf-8') as f:
        f.write(f"THE LURKER - Resultados para {numero}\n")
        f.write(f"Data da busca: {time.strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        
        for resultado in resultados:
            f.write(f"Tipo: {resultado['tipo']}\n")
            f.write(f"Status: {resultado['status']}\n")
            f.write(f"Detalhes: {resultado['detalhes']}\n")
            if resultado['url']:
                f.write(f"URL: {resultado['url']}\n")
            f.write("-" * 30 + "\n")
    
    return caminho_arquivo

def menu_principal():
    """Menu principal do programa"""
    limpar_tela()
    print(BANNER)
    print(f"\n{Fore.GREEN}[{time.strftime('%d/%m/%Y %H:%M:%S')}]{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}📱 BUSCA POR NÚMERO DE TELEFONE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}═" * 50 + f"{Style.RESET_ALL}")
    
    print("\n1. 🔍 Buscar por número de telefone")
    print("2. 📖 Ver arquivos de resultados salvos")
    print("3. 🚪 Sair")
    
    try:
        opcao = input(f"\n{Fore.YELLOW}🎯 Escolha uma opção (1-3): {Style.RESET_ALL}").strip()
        return int(opcao) if opcao.isdigit() else 0
    except:
        return 0

def listar_arquivos_resultados():
    """Lista arquivos de resultados salvos"""
    arquivos = [f for f in os.listdir(PASTA_RESULTADOS) if f.endswith('.txt')]
    
    if not arquivos:
        print(f"\n{Fore.YELLOW}📁 Nenhum arquivo de resultado encontrado.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}📂 ARQUIVOS DE RESULTADOS:{Style.RESET_ALL}\n")
    for i, arquivo in enumerate(arquivos, 1):
        print(f"  {i}. {arquivo}")
    
    try:
        escolha = input(f"\n{Fore.YELLOW}📖 Digite o número do arquivo para ver (0 para voltar): {Style.RESET_ALL}")
        if escolha.isdigit() and int(escolha) > 0:
            indice = int(escolha) - 1
            if 0 <= indice < len(arquivos):
                caminho_arquivo = os.path.join(PASTA_RESULTADOS, arquivos[indice])
                with open(caminho_arquivo, 'r', encoding='utf-8') as f:
                    print(f"\n{Fore.CYAN}📄 CONTEÚDO DO ARQUIVO:{Style.RESET_ALL}\n")
                    print(f.read())
    except:
        print(f"\n{Fore.RED}❌ Erro ao ler arquivo.{Style.RESET_ALL}")

def main():
    """Função principal"""
    try:
        while True:
            opcao = menu_principal()
            
            if opcao == 1:
                numero = input(f"\n{Fore.YELLOW}📞 Digite o número de telefone (com DDD): {Style.RESET_ALL}").strip()
                
                if numero:
                    print(f"\n{Fore.CYAN}🚀 Iniciando busca avançada...{Style.RESET_ALL}")
                    
                    # Validar número
                    if len(re.sub(r'\D', '', numero)) < 8:
                        print(f"{Fore.RED}❌ Número inválido! Digite um número com pelo menos 8 dígitos.{Style.RESET_ALL}")
                        time.sleep(2)
                        continue
                    
                    # Realizar busca
                    resultados = analisar_numero(numero)
                    
                    # Mostrar resultados
                    mostrar_resultados(resultados, numero)
                    
                    # Salvar resultados
                    arquivo_salvo = salvar_resultados(resultados, numero)
                    print(f"\n{Fore.GREEN}💾 Resultados salvos em: {arquivo_salvo}{Style.RESET_ALL}")
                    
                else:
                    print(f"{Fore.RED}❌ Por favor, insira um número válido!{Style.RESET_ALL}")
                    
            elif opcao == 2:
                listar_arquivos_resultados()
                
            elif opcao == 3:
                print(f"\n{Fore.GREEN}👋 Saindo do THE LURKER...{Style.RESET_ALL}")
                break
                
            else:
                print(f"\n{Fore.RED}❌ Opção inválida! Tente novamente.{Style.RESET_ALL}")
                time.sleep(1)
            
            if opcao != 3:
                input(f"\n{Fore.YELLOW}⏎ Pressione Enter para continuar...{Style.RESET_ALL}")
                
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}❌ THE LURKER interrompido pelo usuário!{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}💥 ERRO CRÍTICO: {str(e)}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.GREEN}🛡️  Obrigado por usar o THE LURKER! Use com responsabilidade.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
