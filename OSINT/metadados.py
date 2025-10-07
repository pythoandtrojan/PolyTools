#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime
import hashlib
from pathlib import Path
import requests
from urllib.parse import urlparse, unquote

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
EXTENSOES_SUPORTADAS = {
    '.pdf': 'PDF Document',
    '.doc': 'Word Document',
    '.docx': 'Word Document',
    '.xls': 'Excel Spreadsheet',
    '.xlsx': 'Excel Spreadsheet',
    '.ppt': 'PowerPoint Presentation',
    '.pptx': 'PowerPoint Presentation',
    '.odt': 'OpenDocument Text',
    '.ods': 'OpenDocument Spreadsheet',
    '.odp': 'OpenDocument Presentation',
    '.txt': 'Text File',
    '.rtf': 'Rich Text Format',
    '.csv': 'Comma Separated Values',
    '.xml': 'XML Document',
    '.html': 'HTML Document',
    '.htm': 'HTML Document',
    '.epub': 'eBook',
    '.mp3': 'Audio MP3',
    '.mp4': 'Video MP4',
    '.avi': 'Video AVI',
    '.mov': 'Video MOV',
    '.wav': 'Audio WAV',
    '.zip': 'ZIP Archive',
    '.rar': 'RAR Archive',
    '.7z': '7-Zip Archive',
    '.tar': 'TAR Archive',
    '.gz': 'GZIP Archive'
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.CIANO}{Cores.NEGRITO}
   ███╗   ███╗███████╗████████╗ █████╗ ██████╗  █████╗ ████████╗ █████╗ 
   ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
   ██╔████╔██║█████╗     ██║   ███████║██║  ██║███████║   ██║   ███████║
   ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██║  ██║██╔══██║   ██║   ██╔══██║
   ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██████╔╝██║  ██║   ██║   ██║  ██║
   ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
{Cores.RESET}
{Cores.MAGENTA}{Cores.NEGRITO}   ANALISADOR DE METADADOS
   PDFs + Documentos + Arquivos
{Cores.RESET}
{Cores.AMARELO}   Extração completa + Links + URLs
   Análise forense digital
{Cores.RESET}""")

def calcular_hash_arquivo(caminho_arquivo):
    """Calcula hash MD5 e SHA256 do arquivo"""
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(caminho_arquivo, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    except Exception as e:
        return {'erro': str(e)}

def extrair_metadados_pdf(caminho_arquivo):
    """Extrai metadados de arquivos PDF"""
    try:
        import PyPDF2
        
        metadados = {
            'tipo': 'PDF',
            'metadados_pdf': {},
            'links': [],
            'texto_amostra': ''
        }
        
        with open(caminho_arquivo, 'rb') as arquivo:
            leitor_pdf = PyPDF2.PdfReader(arquivo)
            
            # Metadados do PDF
            if leitor_pdf.metadata:
                for chave, valor in leitor_pdf.metadata.items():
                    metadados['metadados_pdf'][chave.replace('/', '')] = str(valor)
            
            # Extrair texto e links das primeiras páginas
            texto_completo = ""
            for i, pagina in enumerate(leitor_pdf.pages[:5]):  # Limitar às 5 primeiras páginas
                try:
                    texto = pagina.extract_text()
                    if texto:
                        texto_completo += texto + "\n"
                except:
                    pass
            
            # Amostra de texto (primeiros 500 caracteres)
            if texto_completo:
                metadados['texto_amostra'] = texto_completo[:500] + "..." if len(texto_completo) > 500 else texto_completo
            
            # Tentar extrair links (método básico)
            import re
            links = re.findall(r'https?://[^\s\)]+', texto_completo)
            metadados['links'] = list(set(links))  # Remover duplicatas
            
            # Informações da estrutura
            metadados['num_paginas'] = len(leitor_pdf.pages)
            metadados['criptografado'] = leitor_pdf.is_encrypted
            
        return metadados
        
    except ImportError:
        return {'erro': 'PyPDF2 não instalado. Use: pip install pypdf2'}
    except Exception as e:
        return {'erro': f'Erro ao processar PDF: {str(e)}'}

def extrair_metadados_office(caminho_arquivo, extensao):
    """Extrai metadados de arquivos Office"""
    try:
        if extensao in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            import olefile
            
            metadados = {
                'tipo': 'Documento Office',
                'metadados_office': {}
            }
            
            if olefile.isOleFile(caminho_arquivo):
                with olefile.OleFileIO(caminho_arquivo) as ole:
                    # Metadados padrão do OLE
                    metadados_ole = ole.get_metadata()
                    
                    for attr in ['author', 'title', 'subject', 'keywords', 'comments', 
                               'last_saved_by', 'revision_number', 'total_edit_time',
                               'last_printed', 'created', 'modified']:
                        valor = getattr(metadados_ole, attr, None)
                        if valor:
                            metadados['metadados_office'][attr] = str(valor)
            
            return metadados
        else:
            return {'tipo': 'Documento Office', 'metadados_office': {}}
            
    except ImportError:
        return {'erro': 'olefile não instalado. Use: pip install olefile'}
    except Exception as e:
        return {'tipo': 'Documento Office', 'erro': f'Erro Office: {str(e)}'}

def extrair_metadados_audio_video(caminho_arquivo):
    """Extrai metadados de arquivos de áudio e vídeo"""
    try:
        import mutagen
        
        metadados = {
            'tipo': 'Áudio/Video',
            'metadados_midia': {}
        }
        
        arquivo = mutagen.File(caminho_arquivo)
        if arquivo is not None:
            for chave, valor in arquivo.items():
                metadados['metadados_midia'][chave] = str(valar)
            
            # Informações básicas
            if hasattr(arquivo, 'info'):
                info = arquivo.info
                if hasattr(info, 'length'):
                    metadados['duracao'] = f"{info.length:.2f} segundos"
                if hasattr(info, 'bitrate'):
                    metadados['bitrate'] = f"{info.bitrate} kbps"
        
        return metadados
        
    except ImportError:
        return {'erro': 'mutagen não instalado. Use: pip install mutagen'}
    except Exception as e:
        return {'tipo': 'Áudio/Video', 'erro': f'Erro mídia: {str(e)}'}

def extrair_metadados_zip(caminho_arquivo):
    """Extrai metadados de arquivos compactados"""
    try:
        import zipfile
        
        metadados = {
            'tipo': 'Arquivo Compactado',
            'conteudo_zip': [],
            'metadados_zip': {}
        }
        
        with zipfile.ZipFile(caminho_arquivo, 'r') as zip_ref:
            # Listar conteúdo
            metadados['conteudo_zip'] = zip_ref.namelist()
            
            # Informações do arquivo
            for info in zip_ref.infolist():
                if info.filename == info.filename.split('/')[-1]:  # Arquivo raiz
                    metadados['metadados_zip'] = {
                        'nome_arquivo': info.filename,
                        'tamanho_comprimido': info.compress_size,
                        'tamanho_original': info.file_size,
                        'data_modificacao': f"{info.date_time[2]}/{info.date_time[1]}/{info.date_time[0]} {info.date_time[3]}:{info.date_time[4]}:{info.date_time[5]}"
                    }
                    break
        
        return metadados
        
    except ImportError:
        return {'erro': 'zipfile não disponível'}
    except Exception as e:
        return {'tipo': 'Arquivo Compactado', 'erro': f'Erro ZIP: {str(e)}'}

def analisar_arquivo(caminho_arquivo):
    """Analisa um arquivo e extrai todos os metadados disponíveis"""
    if not os.path.exists(caminho_arquivo):
        return {'erro': 'Arquivo não encontrado'}
    
    try:
        # Informações básicas do arquivo
        stat_info = os.stat(caminho_arquivo)
        extensao = Path(caminho_arquivo).suffix.lower()
        
        metadados = {
            'arquivo': caminho_arquivo,
            'nome': os.path.basename(caminho_arquivo),
            'extensao': extensao,
            'tipo_arquivo': EXTENSOES_SUPORTADAS.get(extensao, 'Desconhecido'),
            'tamanho_bytes': stat_info.st_size,
            'tamanho_humano': formatar_tamanho(stat_info.st_size),
            'data_criacao': datetime.fromtimestamp(stat_info.st_ctime).strftime('%d/%m/%Y %H:%M:%S'),
            'data_modificacao': datetime.fromtimestamp(stat_info.st_mtime).strftime('%d/%m/%Y %H:%M:%S'),
            'data_acesso': datetime.fromtimestamp(stat_info.st_atime).strftime('%d/%m/%Y %H:%M:%S'),
            'hashs': calcular_hash_arquivo(caminho_arquivo)
        }
        
        # Metadados específicos por tipo de arquivo
        if extensao == '.pdf':
            metadados_pdf = extrair_metadados_pdf(caminho_arquivo)
            metadados.update(metadados_pdf)
        
        elif extensao in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            metadados_office = extrair_metadados_office(caminho_arquivo, extensao)
            metadados.update(metadados_office)
        
        elif extensao in ['.mp3', '.mp4', '.avi', '.mov', '.wav']:
            metadados_midia = extrair_metadados_audio_video(caminho_arquivo)
            metadados.update(metadados_midia)
        
        elif extensao in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            metadados_zip = extrair_metadados_zip(caminho_arquivo)
            metadados.update(metadados_zip)
        
        # Análise de strings para encontrar URLs/emails em qualquer arquivo
        urls_encontradas = extrair_urls_do_arquivo(caminho_arquivo)
        if urls_encontradas:
            metadados['urls_encontradas'] = urls_encontradas
        
        return metadados
        
    except Exception as e:
        return {'erro': f'Erro na análise: {str(e)}'}

def extrair_urls_do_arquivo(caminho_arquivo):
    """Extrai URLs e emails de qualquer arquivo"""
    try:
        import re
        
        urls = []
        emails = []
        
        # Padrões regex
        url_pattern = r'https?://[^\s\)\]\>]+'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Ler arquivo como binário e decodificar como texto
        with open(caminho_arquivo, 'rb') as f:
            conteudo = f.read()
            
            # Tentar diferentes codificações
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    texto = conteudo.decode(encoding, errors='ignore')
                    
                    # Encontrar URLs
                    urls_encontradas = re.findall(url_pattern, texto)
                    urls.extend(urls_encontradas)
                    
                    # Encontrar emails
                    emails_encontrados = re.findall(email_pattern, texto)
                    emails.extend(emails_encontrados)
                    
                    break
                except UnicodeDecodeError:
                    continue
        
        resultado = {}
        if urls:
            resultado['urls'] = list(set(urls))  # Remover duplicatas
        if emails:
            resultado['emails'] = list(set(emails))  # Remover duplicatas
        
        return resultado if resultado else None
        
    except Exception as e:
        return None

def formatar_tamanho(tamanho_bytes):
    """Formata o tamanho em bytes para formato humano"""
    for unidade in ['B', 'KB', 'MB', 'GB']:
        if tamanho_bytes < 1024.0:
            return f"{tamanho_bytes:.2f} {unidade}"
        tamanho_bytes /= 1024.0
    return f"{tamanho_bytes:.2f} TB"

def baixar_arquivo_url(url, pasta_download='downloads'):
    """Baixa um arquivo de uma URL"""
    try:
        os.makedirs(pasta_download, exist_ok=True)
        
        # Extrair nome do arquivo da URL
        parsed_url = urlparse(url)
        nome_arquivo = unquote(parsed_url.path.split('/')[-1])
        
        if not nome_arquivo or '.' not in nome_arquivo:
            nome_arquivo = f"arquivo_{hashlib.md5(url.encode()).hexdigest()[:8]}.bin"
        
        caminho_arquivo = os.path.join(pasta_download, nome_arquivo)
        
        print(f"{Cores.AMARELO}[*] Baixando: {url}{Cores.RESET}")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(caminho_arquivo, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"{Cores.VERDE}[+] Arquivo salvo: {caminho_arquivo}{Cores.RESET}")
        return caminho_arquivo
        
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao baixar: {str(e)}{Cores.RESET}")
        return None

def exibir_metadados(metadados):
    """Exibe os metadados de forma organizada"""
    if 'erro' in metadados:
        print(f"{Cores.VERMELHO}[!] {metadados['erro']}{Cores.RESET}")
        return False
    
    print(f"\n{Cores.VERDE}{Cores.NEGRITO}=== METADADOS: {metadados['nome']} ==={Cores.RESET}")
    
    # Informações básicas
    print(f"\n{Cores.AZUL}📁 INFORMAÇÕES BÁSICAS:{Cores.RESET}")
    print(f"  {Cores.CIANO}Arquivo:{Cores.RESET} {metadados['arquivo']}")
    print(f"  {Cores.CIANO}Tipo:{Cores.RESET} {metadados['tipo_arquivo']}")
    print(f"  {Cores.CIANO}Tamanho:{Cores.RESET} {metadados['tamanho_humano']} ({metadados['tamanho_bytes']} bytes)")
    print(f"  {Cores.CIANO}Criado:{Cores.RESET} {metadados['data_criacao']}")
    print(f"  {Cores.CIANO}Modificado:{Cores.RESET} {metadados['data_modificacao']}")
    
    # Hashes
    if 'hashs' in metadados and 'erro' not in metadados['hashs']:
        print(f"\n  {Cores.CIANO}MD5:{Cores.RESET} {metadados['hashs']['md5']}")
        print(f"  {Cores.CIANO}SHA256:{Cores.RESET} {metadados['hashs']['sha256']}")
    
    # Metadados específicos do PDF
    if metadados.get('tipo') == 'PDF':
        print(f"\n{Cores.MAGENTA}📄 METADADOS PDF:{Cores.RESET}")
        
        if 'metadados_pdf' in metadados:
            for chave, valor in metadados['metadados_pdf'].items():
                print(f"  {Cores.CIANO}{chave}:{Cores.RESET} {valor}")
        
        if 'num_paginas' in metadados:
            print(f"  {Cores.CIANo}Páginas:{Cores.RESET} {metadados['num_paginas']}")
        
        if metadados.get('criptografado'):
            print(f"  {Cores.VERMELHO}Criptografado: SIM{Cores.RESET}")
        else:
            print(f"  {Cores.VERDE}Criptografado: NÃO{Cores.RESET}")
    
    # Metadados do Office
    if 'metadados_office' in metadados:
        print(f"\n{Cores.MAGENTA}📊 METADADOS OFFICE:{Cores.RESET}")
        for chave, valor in metadados['metadados_office'].items():
            print(f"  {Cores.CIANO}{chave}:{Cores.RESET} {valor}")
    
    # Links e URLs
    if metadados.get('links'):
        print(f"\n{Cores.CIANO}🔗 LINKS ENCONTRADOS:{Cores.RESET}")
        for i, link in enumerate(metadados['links'][:10], 1):  # Limitar a 10 links
            print(f"  {Cores.VERDE}{i}.{Cores.RESET} {link}")
        if len(metadados['links']) > 10:
            print(f"  {Cores.AMARELO}... e mais {len(metadados['links']) - 10} links{Cores.RESET}")
    
    if metadados.get('urls_encontradas'):
        urls_data = metadados['urls_encontradas']
        if 'urls' in urls_data:
            print(f"\n{Cores.CIANO}🌐 URLs NO ARQUIVO:{Cores.RESET}")
            for i, url in enumerate(urls_data['urls'][:5], 1):
                print(f"  {Cores.VERDE}{i}.{Cores.RESET} {url}")
        
        if 'emails' in urls_data:
            print(f"\n{Cores.CIANO}📧 EMAILS ENCONTRADOS:{Cores.RESET}")
            for i, email in enumerate(urls_data['emails'][:5], 1):
                print(f"  {Cores.VERDE}{i}.{Cores.RESET} {email}")
    
    # Conteúdo de arquivos ZIP
    if metadados.get('conteudo_zip'):
        print(f"\n{Cores.MAGENTA}📦 CONTEÚDO DO ZIP:{Cores.RESET}")
        for i, item in enumerate(metadados['conteudo_zip'][:10], 1):
            print(f"  {Cores.VERDE}{i}.{Cores.RESET} {item}")
        if len(metadados['conteudo_zip']) > 10:
            print(f"  {Cores.AMARELO}... e mais {len(metadados['conteudo_zip']) - 10} itens{Cores.RESET}")
    
    # Amostra de texto
    if metadados.get('texto_amostra'):
        print(f"\n{Cores.AZUL}📝 AMOSTRA DE TEXTO:{Cores.RESET}")
        print(f"  {metadados['texto_amostra']}")
    
    return True

def scan_pasta(pasta):
    """Escaneia uma pasta por arquivos suportados"""
    if not os.path.exists(pasta):
        return []
    
    arquivos_suportados = []
    for root, dirs, files in os.walk(pasta):
        for file in files:
            extensao = Path(file).suffix.lower()
            if extensao in EXTENSOES_SUPORTADAS:
                caminho_completo = os.path.join(root, file)
                arquivos_suportados.append(caminho_completo)
    
    return arquivos_suportados

def salvar_resultado(metadados, formato='txt'):
    """Salva os metadados em arquivo"""
    try:
        nome_base = Path(metadados['arquivo']).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('resultados_metadados', exist_ok=True)
        nome_arquivo = f"resultados_metadados/metadados_{nome_base}_{timestamp}.{formato.lower()}"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(metadados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== METADADOS: {metadados['nome']} ===\n\n")
                
                f.write("INFORMAÇÕES BÁSICAS:\n")
                f.write(f"Arquivo: {metadados['arquivo']}\n")
                f.write(f"Tipo: {metadados['tipo_arquivo']}\n")
                f.write(f"Tamanho: {metadados['tamanho_humano']}\n")
                f.write(f"Criado: {metadados['data_criacao']}\n")
                f.write(f"Modificado: {metadados['data_modificacao']}\n")
                
                if 'hashs' in metadados and 'erro' not in metadados['hashs']:
                    f.write(f"MD5: {metadados['hashs']['md5']}\n")
                    f.write(f"SHA256: {metadados['hashs']['sha256']}\n")
                
                # Metadados específicos
                if metadados.get('metadados_pdf'):
                    f.write("\nMETADADOS PDF:\n")
                    for chave, valor in metadados['metadados_pdf'].items():
                        f.write(f"{chave}: {valor}\n")
                
                if metadados.get('urls_encontradas'):
                    f.write("\nURLS E EMAILS:\n")
                    urls_data = metadados['urls_encontradas']
                    if 'urls' in urls_data:
                        f.write("URLs:\n")
                        for url in urls_data['urls']:
                            f.write(f"- {url}\n")
                    if 'emails' in urls_data:
                        f.write("Emails:\n")
                        for email in urls_data['emails']:
                            f.write(f"- {email}\n")
                
                f.write(f"\nData da análise: {timestamp}\n")
        
        print(f"{Cores.VERDE}[+] Resultado salvo em {nome_arquivo}{Cores.RESET}")
        return True
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar: {str(e)}{Cores.RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Analisar arquivo local")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Baixar e analisar URL")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Escanear pasta")
    print(f"{Cores.VERDE}[4]{Cores.RESET} Formatos suportados")
    print(f"{Cores.VERDE}[5]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '5'

def mostrar_formatos_suportados():
    """Mostra os formatos de arquivo suportados"""
    banner()
    print(f"{Cores.CIANO}{Cores.NEGRITO}FORMATOS SUPORTADOS{Cores.RESET}\n")
    
    categorias = {
        'Documentos': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
        'Planilhas': ['.xls', '.xlsx', '.csv', '.ods'],
        'Apresentações': ['.ppt', '.pptx', '.odp'],
        'Arquivos Web': ['.html', '.htm', '.xml'],
        'Áudio/Video': ['.mp3', '.mp4', '.avi', '.mov', '.wav'],
        'Compactados': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'eBooks': ['.epub']
    }
    
    for categoria, formatos in categorias.items():
        print(f"{Cores.MAGENTA}{categoria}:{Cores.RESET}")
        for formato in formatos:
            print(f"  {Cores.VERDE}{formato}{Cores.RESET} - {EXTENSOES_SUPORTADAS.get(formato, '')}")
        print()
    
    try:
        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    try:
        # Verificar dependências
        try:
            import PyPDF2
        except ImportError:
            print(f"{Cores.AMARELO}[!] PyPDF2 não instalado. Algumas funcionalidades limitadas.{Cores.RESET}")
            print(f"{Cores.AMARELO}[*] Instale com: pip install pypdf2{Cores.RESET}")
        
        while True:
            opcao = menu_principal()
            
            if opcao == '1':
                banner()
                try:
                    caminho = input(f"\n{Cores.CIANO}Caminho do arquivo: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not caminho:
                    print(f"{Cores.VERMELHO}[!] Caminho não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                if not os.path.exists(caminho):
                    print(f"{Cores.VERMELHO}[!] Arquivo não encontrado{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                extensao = Path(caminho).suffix.lower()
                if extensao not in EXTENSOES_SUPORTADAS:
                    print(f"{Cores.VERMELHO}[!] Formato não suportado: {extensao}{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"{Cores.AMARELO}[*] Analisando arquivo...{Cores.RESET}")
                metadados = analisar_arquivo(caminho)
                
                banner()
                sucesso = exibir_metadados(metadados)
                
                if sucesso:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_resultado(metadados, 'json')
                        elif exportar.startswith('t'):
                            salvar_resultado(metadados, 'txt')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '2':
                banner()
                try:
                    url = input(f"\n{Cores.CIANO}URL do arquivo: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not url:
                    print(f"{Cores.VERMELHO}[!] URL não pode estar vazio{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                arquivo_baixado = baixar_arquivo_url(url)
                if arquivo_baixado:
                    print(f"{Cores.AMARELO}[*] Analisando arquivo baixado...{Cores.RESET}")
                    metadados = analisar_arquivo(arquivo_baixado)
                    
                    banner()
                    sucesso = exibir_metadados(metadados)
                    
                    if sucesso:
                        try:
                            exportar = input(f"\n{Cores.CIANO}Exportar resultado? (JSON/TXT/Não): {Cores.RESET}").lower()
                            if exportar.startswith('j'):
                                salvar_resultado(metadados, 'json')
                            elif exportar.startswith('t'):
                                salvar_resultado(metadados, 'txt')
                        except (EOFError, KeyboardInterrupt):
                            pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '3':
                banner()
                try:
                    pasta = input(f"\n{Cores.CIANO}Caminho da pasta: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not pasta:
                    print(f"{Cores.VERMELHO}[!] Pasta não pode estar vazia{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                if not os.path.exists(pasta):
                    print(f"{Cores.VERMELHO}[!] Pasta não encontrada{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"{Cores.AMARELO}[*] Escaneando pasta...{Cores.RESET}")
                arquivos = scan_pasta(pasta)
                
                if not arquivos:
                    print(f"{Cores.VERMELHO}[!] Nenhum arquivo suportado encontrado{Cores.RESET}")
                else:
                    print(f"{Cores.VERDE}[+] Encontrados {len(arquivos)} arquivos suportados{Cores.RESET}")
                    
                    for i, arquivo in enumerate(arquivos[:5], 1):  # Mostrar apenas 5
                        print(f"  {Cores.CIANO}{i}.{Cores.RESET} {arquivo}")
                    
                    if len(arquivos) > 5:
                        print(f"  {Cores.AMARELO}... e mais {len(arquivos) - 5} arquivos{Cores.RESET}")
                    
                    try:
                        analisar_todos = input(f"\n{Cores.CIANO}Analisar todos os arquivos? (s/N): {Cores.RESET}").lower()
                        if analisar_todos in ['s', 'sim', 'y', 'yes']:
                            for arquivo in arquivos:
                                print(f"\n{Cores.AMARELO}[*] Analisando: {arquivo}{Cores.RESET}")
                                metadados = analisar_arquivo(arquivo)
                                exibir_metadados(metadados)
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                try:
                    input(f"\n{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                except (EOFError, KeyboardInterrupt):
                    continue
            
            elif opcao == '4':
                mostrar_formatos_suportados()
            
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
        print(f"{Cores.CIANO}\nObrigado por usar o Analisador de Metadados!{Cores.RESET}")

if __name__ == "__main__":
    main()
