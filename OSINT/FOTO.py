#!/usr/bin/env python3
import os
import sys
import json
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import piexif
import hashlib
from datetime import datetime
import webbrowser
import folium
import subprocess

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

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    limpar_tela()
    print(f"""{Cores.MAGENTA}{Cores.NEGRITO}
   ███████╗ ██████╗ ████████╗ ██████╗ 
   ██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗
   █████╗  ██║   ██║   ██║   ██║   ██║
   ██╔══╝  ██║   ██║   ██║   ██║   ██║
   ██║     ╚██████╔╝   ██║   ╚██████╔╝
   ╚═╝      ╚═════╝    ╚═╝    ╚═════╝ 
{Cores.RESET}
{Cores.CIANO}{Cores.NEGRITO}   ANALISADOR DE METADADOS DE FOTOS
   Versão Termux - Extração Completa
{Cores.RESET}
{Cores.AMARELO}   Exif, GPS, Câmera, Thumbnails e Forense
   Visualização em Mapa e Relatórios
{Cores.RESET}""")

def extrair_metadados(imagem_path):
    try:
        imagem = Image.open(imagem_path)
        metadados = {}
        
        # Informações básicas da imagem
        metadados['Informacoes_Basicas'] = {
            'Formato': imagem.format,
            'Modo': imagem.mode,
            'Tamanho': f"{imagem.width}x{imagem.height} px",
            'Tamanho_Arquivo': f"{os.path.getsize(imagem_path) / 1024:.2f} KB"
        }
        
        # EXIF Data
        exif_data = {}
        if hasattr(imagem, '_getexif') and imagem._getexif() is not None:
            for tag, valor in imagem._getexif().items():
                tag_nome = TAGS.get(tag, tag)
                exif_data[tag_nome] = valor
        
        # Processar EXIF
        if exif_data:
            metadados['EXIF'] = processar_exif(exif_data)
        
        # Extrair dados GPS
        gps_info = extrair_gps(exif_data)
        if gps_info:
            metadados['GPS'] = gps_info
        
        # Extrair dados XMP (se existirem)
        xmp_data = extrair_xmp(imagem_path)
        if xmp_data:
            metadados['XMP'] = xmp_data
        
        # Extrair dados IPTC (se existirem)
        iptc_data = extrair_iptc(imagem_path)
        if iptc_data:
            metadados['IPTC'] = iptc_data
        
        # Informações do arquivo
        metadados['Arquivo'] = {
            'Nome': os.path.basename(imagem_path),
            'Caminho': os.path.abspath(imagem_path),
            'Data_Criacao': datetime.fromtimestamp(os.path.getctime(imagem_path)).strftime('%Y-%m-%d %H:%M:%S'),
            'Data_Modificacao': datetime.fromtimestamp(os.path.getmtime(imagem_path)).strftime('%Y-%m-%d %H:%M:%S'),
            'Hash_MD5': calcular_hash(imagem_path)
        }
        
        return metadados
    
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao extrair metadados: {str(e)}{Cores.RESET}")
        return None

def processar_exif(exif_data):
    processed = {}
    for tag, valor in exif_data.items():
        # Processar tags conhecidas
        if tag == 'DateTimeOriginal':
            processed['Data_Hora'] = valor
        elif tag == 'Make':
            processed['Fabricante'] = valor
        elif tag == 'Model':
            processed['Modelo_Camera'] = valor
        elif tag == 'Software':
            processed['Software'] = valor
        elif tag == 'ExposureTime':
            processed['Tempo_Exposicao'] = f"{valor[0]}/{valor[1]} s" if isinstance(valor, tuple) else valor
        elif tag == 'FNumber':
            processed['Abertura'] = f"f/{valor[0]/valor[1]:.1f}" if isinstance(valor, tuple) else f"f/{valor:.1f}"
        elif tag == 'ISOSpeedRatings':
            processed['ISO'] = valor
        elif tag == 'FocalLength':
            processed['Distancia_Focal'] = f"{valor[0]/valor[1]} mm" if isinstance(valor, tuple) else f"{valor} mm"
        elif tag == 'Flash':
            processed['Flash'] = "Sim" if valor else "Não"
        else:
            processed[tag] = valor
    return processed

def extrair_gps(exif_data):
    if 'GPSInfo' not in exif_data:
        return None
    
    gps_info = {}
    for tag in exif_data['GPSInfo'].keys():
        tag_nome = GPSTAGS.get(tag, tag)
        gps_info[tag_nome] = exif_data['GPSInfo'][tag]
    
    # Converter coordenadas GPS para graus decimais
    if 'GPSLatitude' in gps_info and 'GPSLatitudeRef' in gps_info:
        gps_info['Latitude'] = converter_para_graus(gps_info['GPSLatitude'], gps_info['GPSLatitudeRef'])
    
    if 'GPSLongitude' in gps_info and 'GPSLongitudeRef' in gps_info:
        gps_info['Longitude'] = converter_para_graus(gps_info['GPSLongitude'], gps_info['GPSLongitudeRef'])
    
    return gps_info

def converter_para_graus(coords, ref):
    graus = coords[0][0] / coords[0][1] if isinstance(coords[0], tuple) else coords[0]
    minutos = coords[1][0] / coords[1][1] if isinstance(coords[1], tuple) else coords[1]
    segundos = coords[2][0] / coords[2][1] if isinstance(coords[2], tuple) else coords[2]
    
    decimal = graus + (minutos / 60.0) + (segundos / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    
    return decimal

def extrair_xmp(imagem_path):
    try:
        with open(imagem_path, 'rb') as f:
            conteudo = f.read().decode('latin-1')
        
        xmp_start = conteudo.find('<x:xmpmeta')
        xmp_end = conteudo.find('</x:xmpmeta>')
        
        if xmp_start != -1 and xmp_end != -1:
            xmp_str = conteudo[xmp_start:xmp_end+12]
            return {'XMP_Raw': xmp_str}
        return None
    except:
        return None

def extrair_iptc(imagem_path):
    try:
        iptc_data = {}
        with open(imagem_path, 'rb') as f:
            conteudo = f.read()
        
        # Procurar marcadores IPTC
        iptc_start = conteudo.find(b'\x1c\x02', 0)
        if iptc_start == -1:
            return None
        
        # Processar dados IPTC (simplificado)
        while iptc_start != -1:
            marker = conteudo[iptc_start:iptc_start+2]
            length = conteudo[iptc_start+2]
            data = conteudo[iptc_start+3:iptc_start+3+length]
            
            # Mapear tags IPTC conhecidas
            if marker == b'\x1c\x02':
                iptc_data['Titulo'] = data.decode('utf-8', errors='ignore')
            elif marker == b'\x1c\x05':
                iptc_data['Palavras_Chave'] = data.decode('utf-8', errors='ignore')
            elif marker == b'\x1c\x0f':
                iptc_data['Categoria'] = data.decode('utf-8', errors='ignore')
            
            iptc_start = conteudo.find(b'\x1c', iptc_start+1)
        
        return iptc_data if iptc_data else None
    except:
        return None

def calcular_hash(arquivo_path):
    try:
        hasher = hashlib.md5()
        with open(arquivo_path, 'rb') as f:
            for bloco in iter(lambda: f.read(4096), b''):
                hasher.update(bloco)
        return hasher.hexdigest()
    except:
        return "Erro ao calcular hash"

def exibir_metadados(metadados):
    if not metadados:
        print(f"{Cores.VERMELHO}[!] Nenhum metadado encontrado{Cores.RESET}")
        return
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES BÁSICAS ==={Cores.RESET}")
    for chave, valor in metadados['Informacoes_Basicas'].items():
        print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor}")
    
    if 'EXIF' in metadados and metadados['EXIF']:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== METADADOS EXIF ==={Cores.RESET}")
        for chave, valor in metadados['EXIF'].items():
            print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor}")
    
    if 'GPS' in metadados and metadados['GPS']:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== DADOS GPS ==={Cores.RESET}")
        for chave, valor in metadados['GPS'].items():
            if chave in ['Latitude', 'Longitude']:
                print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor:.6f}")
            else:
                print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor}")
        
        if 'Latitude' in metadados['GPS'] and 'Longitude' in metadados['GPS']:
            print(f"\n{Cores.AZUL}Link Google Maps:{Cores.RESET} https://www.google.com/maps?q={metadados['GPS']['Latitude']},{metadados['GPS']['Longitude']}")
    
    if 'XMP' in metadados and metadados['XMP']:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== METADADOS XMP (resumo) ==={Cores.RESET}")
        xmp = metadados['XMP'].get('XMP_Raw', '')[:200] + '...' if len(metadados['XMP'].get('XMP_Raw', '')) > 200 else metadados['XMP'].get('XMP_Raw', '')
        print(f"{Cores.AZUL}XMP Data:{Cores.RESET} {xmp}")
    
    if 'IPTC' in metadados and metadados['IPTC']:
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== METADADOS IPTC ==={Cores.RESET}")
        for chave, valor in metadados['IPTC'].items():
            print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor}")
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}=== INFORMAÇÕES DO ARQUIVO ==={Cores.RESET}")
    for chave, valor in metadados['Arquivo'].items():
        print(f"{Cores.AZUL}{chave}:{Cores.RESET} {valor}")

def salvar_relatorio(metadados, formato='txt'):
    if not metadados:
        return False
    
    try:
        nome_arquivo = os.path.basename(metadados['Arquivo']['Nome'])
        nome_sem_ext = os.path.splitext(nome_arquivo)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('relatorios', exist_ok=True)
        caminho_relatorio = f"relatorios/{nome_sem_ext}_{timestamp}.{formato.lower()}"
        
        with open(caminho_relatorio, 'w', encoding='utf-8') as f:
            if formato.lower() == 'json':
                json.dump(metadados, f, indent=2, ensure_ascii=False)
            else:
                f.write(f"=== RELATÓRIO DE METADADOS ===\n")
                f.write(f"Arquivo: {metadados['Arquivo']['Nome']}\n")
                f.write(f"Gerado em: {timestamp}\n\n")
                
                f.write("=== INFORMAÇÕES BÁSICAS ===\n")
                for chave, valor in metadados['Informacoes_Basicas'].items():
                    f.write(f"{chave}: {valor}\n")
                
                if 'EXIF' in metadados and metadados['EXIF']:
                    f.write("\n=== METADADOS EXIF ===\n")
                    for chave, valor in metadados['EXIF'].items():
                        f.write(f"{chave}: {valor}\n")
                
                if 'GPS' in metadados and metadados['GPS']:
                    f.write("\n=== DADOS GPS ===\n")
                    for chave, valor in metadados['GPS'].items():
                        f.write(f"{chave}: {valor}\n")
                
                if 'XMP' in metadados and metadados['XMP']:
                    f.write("\n=== METADADOS XMP ===\n")
                    f.write(f"XMP Data: {metadados['XMP'].get('XMP_Raw', '')}\n")
                
                if 'IPTC' in metadados and metadados['IPTC']:
                    f.write("\n=== METADADOS IPTC ===\n")
                    for chave, valor in metadados['IPTC'].items():
                        f.write(f"{chave}: {valor}\n")
                
                f.write("\n=== INFORMAÇÕES DO ARQUIVO ===\n")
                for chave, valor in metadados['Arquivo'].items():
                    f.write(f"{chave}: {valor}\n")
        
        print(f"{Cores.VERDE}[+] Relatório salvo em {caminho_relatorio}{Cores.RESET}")
        return True
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao salvar relatório: {str(e)}{Cores.RESET}")
        return False

def criar_mapa_gps(latitude, longitude, nome_arquivo):
    try:
        os.makedirs('mapas', exist_ok=True)
        mapa = folium.Map(location=[latitude, longitude], zoom_start=15)
        folium.Marker([latitude, longitude], popup="Local da Foto").add_to(mapa)
        caminho_mapa = f"mapas/{nome_arquivo}_mapa.html"
        mapa.save(caminho_mapa)
        return caminho_mapa
    except Exception as e:
        print(f"{Cores.VERMELHO}[!] Erro ao criar mapa: {str(e)}{Cores.RESET}")
        return None

def menu_principal():
    banner()
    print(f"\n{Cores.AMARELO}{Cores.NEGRITO}MENU PRINCIPAL{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} Analisar Foto")
    print(f"{Cores.VERDE}[2]{Cores.RESET} Sobre")
    print(f"{Cores.VERDE}[3]{Cores.RESET} Sair")
    
    try:
        return input(f"\n{Cores.CIANO}Selecione uma opção: {Cores.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return '3'

def sobre():
    banner()
    print(f"""
{Cores.CIANO}{Cores.NEGRITO}SOBRE O ANALISADOR DE METADADOS DE FOTOS{Cores.RESET}

{Cores.AMARELO}Recursos principais:{Cores.RESET}
- Extração completa de metadados EXIF, GPS, XMP e IPTC
- Informações detalhadas da câmera e configurações
- Visualização de coordenadas GPS em mapas
- Análise forense básica (hashes)
- Geração de relatórios em TXT e JSON

{Cores.AMARELO}Metadados extraídos:{Cores.RESET}
- Dados da câmera (fabricante, modelo)
- Configurações (ISO, abertura, velocidade do obturador)
- Data e hora da captura
- Coordenadas GPS (quando disponíveis)
- Informações de edição e software usado
- Thumbnails embutidos
- Hashes forenses (MD5)

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
                    caminho_imagem = input(f"\n{Cores.CIANO}Digite o caminho da imagem: {Cores.RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
                
                if not os.path.isfile(caminho_imagem):
                    print(f"{Cores.VERMELHO}[!] Arquivo não encontrado!{Cores.RESET}")
                    try:
                        input(f"{Cores.AMARELO}Pressione Enter para continuar...{Cores.RESET}")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    continue
                
                print(f"\n{Cores.AMARELO}[*] Analisando imagem...{Cores.RESET}")
                metadados = extrair_metadados(caminho_imagem)
                
                banner()
                exibir_metadados(metadados)
                
                if metadados and 'GPS' in metadados and 'Latitude' in metadados['GPS'] and 'Longitude' in metadados['GPS']:
                    try:
                        resposta = input(f"\n{Cores.CIANO}Mostrar localização no mapa? (s/n): {Cores.RESET}").lower()
                        if resposta == 's':
                            nome_arquivo = os.path.splitext(os.path.basename(caminho_imagem))[0]
                            mapa = criar_mapa_gps(metadados['GPS']['Latitude'], metadados['GPS']['Longitude'], nome_arquivo)
                            if mapa:
                                webbrowser.open(f'file://{os.path.abspath(mapa)}')
                    except (EOFError, KeyboardInterrupt):
                        pass
                
                if metadados:
                    try:
                        exportar = input(f"\n{Cores.CIANO}Exportar relatório? (JSON/TXT/Não): {Cores.RESET}").lower()
                        if exportar.startswith('j'):
                            salvar_relatorio(metadados, 'json')
                        elif exportar.startswith('t'):
                            salvar_relatorio(metadados, 'txt')
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
        print(f"{Cores.CIANO}\nObrigado por usar o Analisador de Metadados!{Cores.RESET}")

if __name__ == "__main__":
    # Verificar dependências
    try:
        from PIL import Image
    except ImportError:
        print(f"{Cores.VERMELHO}[!] Necessário instalar a biblioteca Pillow:{Cores.RESET}")
        print("Execute: pip install pillow")
        sys.exit(1)
    
    try:
        import folium
    except ImportError:
        print(f"{Cores.AMARELO}[!] Folium não instalado. Mapas GPS não estarão disponíveis.{Cores.RESET}")
        print("Para instalar: pip install folium")
    
    main()
