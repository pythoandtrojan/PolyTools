#!/usr/bin/env python3
"""
🔍 BUSCADOR INTELIGENTE - MODO MENU
Script avançado com múltiplos métodos de busca e interface amigável
"""

import os
import re
import argparse
from pathlib import Path
from datetime import datetime
import fnmatch
import mimetypes
from typing import List, Dict, Tuple
import threading
import time

class BuscadorInteligente:
    def __init__(self, diretorio_base: str = "."):
        self.diretorio_base = Path(diretorio_base).resolve()
        self.resultados = []
        self.estatisticas = {
            'arquivos_analisados': 0,
            'resultados_encontrados': 0,
            'tempo_execucao': 0,
            'inicio': None,
            'fim': None
        }
        self.buscando = False
        
        self.setup_cores()
        self.setup_mimes()

    def setup_cores(self):
        """Configura cores para terminal"""
        self.cores = {
            'VERDE': '\033[92m',
            'AMARELO': '\033[93m',
            'AZUL': '\033[94m',
            'VERMELHO': '\033[91m',
            'ROXO': '\033[95m',
            'CIANO': '\033[96m',
            'NEGRITO': '\033[1m',
            'FIM': '\033[0m'
        }

    def setup_mimes(self):
        """Configura tipos MIME comuns"""
        self.tipos_arquivo = {
            '📷 Imagens': ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/svg+xml', 'image/webp'],
            '🎵 Áudio': ['audio/mpeg', 'audio/wav', 'audio/flac', 'audio/aac', 'audio/ogg'],
            '🎬 Vídeo': ['video/mp4', 'video/avi', 'video/x-matroska', 'video/quicktime', 'video/x-ms-wmv'],
            '📄 Documentos': ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain'],
            '📊 Planilhas': ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/csv'],
            '💻 Código': ['text/x-python', 'application/javascript', 'text/html', 'text/css', 'text/x-java', 'text/x-c', 'text/x-c++', 'application/json'],
            '📦 Compactados': ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/x-tar', 'application/gzip']
        }

    def colorir(self, texto: str, cor: str) -> str:
        """Aplica cor ao texto"""
        return f"{self.cores.get(cor, '')}{texto}{self.cores['FIM']}"

    def limpar_tela(self):
        """Limpa a tela do terminal"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def mostrar_cabecalho(self, titulo: str = "BUSCADOR INTELIGENTE"):
        """Mostra cabeçalho bonito"""
        self.limpar_tela()
        print(f"{self.colorir('╔══════════════════════════════════════════════════╗', 'AZUL')}")
        print(f"{self.colorir('║               🔍 BUSCADOR INTELIGENTE            ║', 'AZUL')}")
        print(f"{self.colorir('║                 🚀 Modo Menu Interativo          ║', 'AZUL')}")
        print(f"{self.colorir('╚══════════════════════════════════════════════════╝', 'AZUL')}")
        print(f"📂 {self.colorir('Diretório base:', 'NEGRITO')} {self.diretorio_base}")
        print(f"📊 {self.colorir('Última busca:', 'NEGRITO')} {self.estatisticas['resultados_encontrados']} resultados")
        print()

    def pausar(self, mensagem: str = "Pressione Enter para continuar..."):
        """Pausa e espera Enter"""
        input(f"\n⏸️  {mensagem}")

    def mostrar_menu_principal(self):
        """Menu principal"""
        self.mostrar_cabecalho()
        
        print(f"{self.colorir('🎯 MENU PRINCIPAL', 'NEGRITO')}")
        print("=" * 50)
        print(f"1. {self.colorir('🔎 Buscar por Nome/Extensão', 'VERDE')}")
        print(f"2. {self.colorir('📝 Buscar por Conteúdo', 'AZUL')}")
        print(f"3. {self.colorir('📏 Buscar por Tamanho', 'ROXO')}")
        print(f"4. {self.colorir('📅 Buscar por Data', 'AMARELO')}")
        print(f"5. {self.colorir('🎯 Buscar por Tipo', 'CIANO')}")
        print(f"6. {self.colorir('⚡ Busca Avançada', 'VERMELHO')}")
        print(f"7. {self.colorir('📊 Estatísticas/Histórico', 'AZUL')}")
        print(f"8. {self.colorir('⚙️ Configurações', 'ROXO')}")
        print(f"0. {self.colorir('🚪 Sair', 'VERMELHO')}")
        print("=" * 50)
        
        return input(f"\n🎯 {self.colorir('Selecione uma opção', 'NEGRITO')} (0-8): ").strip()

    def animacao_busca(self):
        """Mostra animação durante a busca"""
        animacao = ["🔍 Buscando...", "🔎 Buscando..", "🔍 Buscando.", "🔎 Buscando"]
        i = 0
        while self.buscando:
            print(f"\r{animacao[i % len(animacao)]} ({self.estatisticas['arquivos_analisados']} arquivos analisados)", end="", flush=True)
            i += 1
            time.sleep(0.3)

    def buscar_por_nome(self, padrao: str, case_sensitive: bool = False) -> List[Path]:
        """Busca arquivos por nome ou extensão"""
        resultados = []
        padrao_regex = fnmatch.translate(padrao)
        
        if not case_sensitive:
            padrao_regex = padrao_regex.lower()
        
        regex = re.compile(padrao_regex)
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file():
                self.estatisticas['arquivos_analisados'] += 1
                nome_arquivo = arquivo.name if case_sensitive else arquivo.name.lower()
                
                if regex.match(nome_arquivo):
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
        
        return resultados

    def buscar_por_conteudo(self, texto: str, case_sensitive: bool = False) -> List[Tuple[Path, int]]:
        """Busca arquivos que contenham determinado texto"""
        resultados = []
        padrao = texto if case_sensitive else texto.lower()
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file() and arquivo.stat().st_size < 10 * 1024 * 1024:  # Limite 10MB
                self.estatisticas['arquivos_analisados'] += 1
                
                try:
                    with open(arquivo, 'r', encoding='utf-8', errors='ignore') as f:
                        for num_linha, linha in enumerate(f, 1):
                            linha_busca = linha if case_sensitive else linha.lower()
                            if padrao in linha_busca:
                                resultados.append((arquivo, num_linha))
                                self.estatisticas['resultados_encontrados'] += 1
                                break
                except:
                    continue
        
        return resultados

    def buscar_por_tamanho(self, operador: str, tamanho: int, unidade: str = 'MB') -> List[Path]:
        """Busca arquivos por tamanho"""
        resultados = []
        
        # Converter para bytes
        multiplicador = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024
        }.get(unidade.upper(), 1024 * 1024)
        
        tamanho_bytes = tamanho * multiplicador
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file():
                self.estatisticas['arquivos_analisados'] += 1
                tamanho_arquivo = arquivo.stat().st_size
                
                if operador == '>' and tamanho_arquivo > tamanho_bytes:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
                elif operador == '<' and tamanho_arquivo < tamanho_bytes:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
                elif operador == '=' and tamanho_arquivo == tamanho_bytes:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
        
        return resultados

    def buscar_por_data(self, dias: int, operador: str = 'after') -> List[Path]:
        """Busca arquivos por data de modificação"""
        resultados = []
        tempo_limite = time.time() - (dias * 24 * 60 * 60)
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file():
                self.estatisticas['arquivos_analisados'] += 1
                tempo_arquivo = arquivo.stat().st_mtime
                
                if operador == 'after' and tempo_arquivo > tempo_limite:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
                elif operador == 'before' and tempo_arquivo < tempo_limite:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
        
        return resultados

    def buscar_por_tipo(self, tipo: str) -> List[Path]:
        """Busca arquivos por tipo MIME"""
        resultados = []
        extensoes = self.obter_extensoes_por_tipo(tipo)
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file():
                self.estatisticas['arquivos_analisados'] += 1
                
                # Verifica por extensão
                if arquivo.suffix.lower().lstrip('.') in extensoes:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
                    continue
                
                # Verifica por MIME type
                try:
                    mime_type, _ = mimetypes.guess_type(arquivo)
                    if mime_type in self.tipos_arquivo.get(tipo, []):
                        resultados.append(arquivo)
                        self.estatisticas['resultados_encontrados'] += 1
                except:
                    continue
        
        return resultados

    def obter_extensoes_por_tipo(self, tipo: str) -> List[str]:
        """Obtém extensões comuns para um tipo"""
        map_extensoes = {
            '📷 Imagens': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'],
            '🎵 Áudio': ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a'],
            '🎬 Vídeo': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
            '📄 Documentos': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'],
            '📊 Planilhas': ['xls', 'xlsx', 'csv', 'ods'],
            '💻 Código': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'php', 'json', 'xml'],
            '📦 Compactados': ['zip', 'rar', '7z', 'tar', 'gz', 'bz2']
        }
        return map_extensoes.get(tipo, [])

    def buscar_avancada(self, criterios: Dict) -> List[Path]:
        """Busca avançada com múltiplos critérios"""
        resultados = []
        
        for arquivo in self.diretorio_base.rglob('*'):
            if arquivo.is_file():
                self.estatisticas['arquivos_analisados'] += 1
                corresponde = True
                
                # Verifica cada critério
                if 'nome' in criterios:
                    padrao = criterios['nome']
                    if not fnmatch.fnmatch(arquivo.name.lower(), f"*{padrao.lower()}*"):
                        corresponde = False
                
                if 'tamanho_min' in criterios and corresponde:
                    if arquivo.stat().st_size < criterios['tamanho_min']:
                        corresponde = False
                
                if 'tamanho_max' in criterios and corresponde:
                    if arquivo.stat().st_size > criterios['tamanho_max']:
                        corresponde = False
                
                if 'dias' in criterios and corresponde:
                    tempo_limite = time.time() - (criterios['dias'] * 24 * 60 * 60)
                    if arquivo.stat().st_mtime < tempo_limite:
                        corresponde = False
                
                if corresponde:
                    resultados.append(arquivo)
                    self.estatisticas['resultados_encontrados'] += 1
        
        return resultados

    def formatar_tamanho(self, tamanho_bytes: int) -> str:
        """Formata tamanho em bytes para string legível"""
        for unidade in ['B', 'KB', 'MB', 'GB']:
            if tamanho_bytes < 1024.0:
                return f"{tamanho_bytes:.2f} {unidade}"
            tamanho_bytes /= 1024.0
        return f"{tamanho_bytes:.2f} TB"

    def formatar_data(self, timestamp: float) -> str:
        """Formata timestamp para data legível"""
        return datetime.fromtimestamp(timestamp).strftime('%d/%m/%Y %H:%M')

    def mostrar_resultados(self, resultados: List, tipo_busca: str = ""):
        """Mostra resultados de forma organizada"""
        if not resultados:
            print(f"\n❌ {self.colorir('Nenhum resultado encontrado!', 'VERMELHO')}")
            return
        
        print(f"\n✅ {self.colorir(f'Encontrados {len(resultados)} resultados:', 'VERDE')}")
        print("=" * 80)
        
        for i, resultado in enumerate(resultados[:50], 1):  # Mostra até 50 resultados
            if isinstance(resultado, tuple):  # Resultado com número de linha
                arquivo, linha = resultado
                tamanho = self.formatar_tamanho(arquivo.stat().st_size)
                data = self.formatar_data(arquivo.stat().st_mtime)
                print(f"{i:2d}. 📄 {self.colorir(arquivo.name, 'AZUL')}")
                print(f"    📍 {arquivo}")
                print(f"    📏 {tamanho} | 📅 {data} | 🎯 Linha: {linha}")
            else:  # Resultado normal
                arquivo = resultado
                tamanho = self.formatar_tamanho(arquivo.stat().st_size)
                data = self.formatar_data(arquivo.stat().st_mtime)
                print(f"{i:2d}. 📄 {self.colorir(arquivo.name, 'AZUL')}")
                print(f"    📍 {arquivo}")
                print(f"    📏 {tamanho} | 📅 {data}")
            
            if i < len(resultados[:50]):
                print("    " + "-" * 60)
        
        if len(resultados) > 50:
            print(f"\n📋 {self.colorir(f'... e mais {len(resultados) - 50} resultados (mostrando 50 primeiros)', 'AMARELO')}")

    def executar_busca(self, funcao_busca, *args, **kwargs):
        """Executa uma busca com animação e estatísticas"""
        self.estatisticas['arquivos_analisados'] = 0
        self.estatisticas['resultados_encontrados'] = 0
        self.estatisticas['inicio'] = time.time()
        self.buscando = True
        
        # Inicia animação em thread separada
        animacao_thread = threading.Thread(target=self.animacao_busca)
        animacao_thread.daemon = True
        animacao_thread.start()
        
        try:
            resultados = funcao_busca(*args, **kwargs)
        finally:
            self.buscando = False
            self.estatisticas['fim'] = time.time()
            self.estatisticas['tempo_execucao'] = self.estatisticas['fim'] - self.estatisticas['inicio']
        
        print("\r" + " " * 60 + "\r", end="")  # Limpa linha da animação
        return resultados

    def menu_busca_nome(self):
        """Menu de busca por nome"""
        self.mostrar_cabecalho("BUSCA POR NOME")
        
        print(f"{self.colorir('🔎 BUSCAR POR NOME/EXTENSÃO', 'NEGRITO')}")
        print("=" * 50)
        
        padrao = input(f"\n📝 {self.colorir('Digite o nome ou padrão', 'AZUL')} (ex: *.txt, relatorio*): ").strip()
        case_sensitive = input("🔠 Case sensitive? (s/N): ").strip().lower() == 's'
        
        if not padrao:
            print("❌ Padrão não pode estar vazio!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_por_nome, padrao, case_sensitive)
        self.mostrar_resultados(resultados, "nome")
        self.pausar()

    def menu_busca_conteudo(self):
        """Menu de busca por conteúdo"""
        self.mostrar_cabecalho("BUSCA POR CONTEÚDO")
        
        print(f"{self.colorir('📝 BUSCAR POR CONTEÚDO', 'NEGRITO')}")
        print("=" * 50)
        
        texto = input(f"\n📝 {self.colorir('Digite o texto a buscar', 'AZUL')}: ").strip()
        case_sensitive = input("🔠 Case sensitive? (s/N): ").strip().lower() == 's'
        
        if not texto:
            print("❌ Texto não pode estar vazio!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_por_conteudo, texto, case_sensitive)
        self.mostrar_resultados(resultados, "conteúdo")
        self.pausar()

    def menu_busca_tamanho(self):
        """Menu de busca por tamanho"""
        self.mostrar_cabecalho("BUSCA POR TAMANHO")
        
        print(f"{self.colorir('📏 BUSCAR POR TAMANHO', 'NEGRITO')}")
        print("=" * 50)
        
        print("\n🎯 Selecione o operador:")
        print("1. Maior que (>)")
        print("2. Menor que (<)")
        print("3. Igual a (=)")
        
        op_choice = input(f"\n🔢 {self.colorir('Operador', 'AZUL')} (1-3): ").strip()
        operadores = {'1': '>', '2': '<', '3': '='}
        operador = operadores.get(op_choice, '>')
        
        try:
            tamanho = float(input(f"📏 {self.colorir('Tamanho', 'AZUL')}: ").strip())
            unidade = input(f"📊 {self.colorir('Unidade', 'AZUL')} (B/KB/MB/GB - padrão: MB): ").strip() or 'MB'
        except ValueError:
            print("❌ Tamanho inválido!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_por_tamanho, operador, tamanho, unidade)
        self.mostrar_resultados(resultados, "tamanho")
        self.pausar()

    def menu_busca_data(self):
        """Menu de busca por data"""
        self.mostrar_cabecalho("BUSCA POR DATA")
        
        print(f"{self.colorir('📅 BUSCAR POR DATA', 'NEGRITO')}")
        print("=" * 50)
        
        print("\n🎯 Selecione o tipo:")
        print("1. Modificados nos últimos X dias")
        print("2. Modificados há mais de X dias")
        
        op_choice = input(f"\n🔢 {self.colorir('Tipo', 'AZUL')} (1-2): ").strip()
        operador = 'after' if op_choice == '1' else 'before'
        
        try:
            dias = int(input(f"📅 {self.colorir('Número de dias', 'AZUL')}: ").strip())
        except ValueError:
            print("❌ Número de dias inválido!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_por_data, dias, operador)
        self.mostrar_resultados(resultados, "data")
        self.pausar()

    def menu_busca_tipo(self):
        """Menu de busca por tipo"""
        self.mostrar_cabecalho("BUSCA POR TIPO")
        
        print(f"{self.colorir('🎯 BUSCAR POR TIPO', 'NEGRITO')}")
        print("=" * 50)
        
        print("\n🎯 Selecione o tipo de arquivo:")
        tipos = list(self.tipos_arquivo.keys())
        for i, tipo in enumerate(tipos, 1):
            print(f"{i}. {tipo}")
        
        try:
            escolha = int(input(f"\n🔢 {self.colorir('Tipo', 'AZUL')} (1-{len(tipos)}): ").strip())
            tipo_selecionado = tipos[escolha - 1]
        except (ValueError, IndexError):
            print("❌ Escolha inválida!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_por_tipo, tipo_selecionado)
        self.mostrar_resultados(resultados, f"tipo: {tipo_selecionado}")
        self.pausar()

    def menu_busca_avancada(self):
        """Menu de busca avançada"""
        self.mostrar_cabecalho("BUSCA AVANÇADA")
        
        print(f"{self.colorir('⚡ BUSCA AVANÇADA', 'NEGRITO')}")
        print("=" * 50)
        
        criterios = {}
        
        nome = input(f"\n🔎 {self.colorir('Nome (opcional)', 'AZUL')}: ").strip()
        if nome:
            criterios['nome'] = nome
        
        try:
            tamanho_min = input(f"📏 {self.colorir('Tamanho mínimo em MB (opcional)', 'AZUL')}: ").strip()
            if tamanho_min:
                criterios['tamanho_min'] = float(tamanho_min) * 1024 * 1024
            
            tamanho_max = input(f"📏 {self.colorir('Tamanho máximo em MB (opcional)', 'AZUL')}: ").strip()
            if tamanho_max:
                criterios['tamanho_max'] = float(tamanho_max) * 1024 * 1024
            
            dias = input(f"📅 {self.colorir('Modificados nos últimos X dias (opcional)', 'AZUL')}: ").strip()
            if dias:
                criterios['dias'] = int(dias)
        except ValueError:
            print("❌ Valores numéricos inválidos!")
            self.pausar()
            return
        
        if not criterios:
            print("❌ Pelo menos um critério deve ser especificado!")
            self.pausar()
            return
        
        resultados = self.executar_busca(self.buscar_avancada, criterios)
        self.mostrar_resultados(resultados, "avançada")
        self.pausar()

    def menu_estatisticas(self):
        """Menu de estatísticas"""
        self.mostrar_cabecalho("ESTATÍSTICAS")
        
        print(f"{self.colorir('📊 ESTATÍSTICAS DA ÚLTIMA BUSCA', 'NEGRITO')}")
        print("=" * 50)
        
        if self.estatisticas['inicio']:
            print(f"🔍 {self.colorir('Arquivos analisados:', 'AZUL')} {self.estatisticas['arquivos_analisados']:,}")
            print(f"✅ {self.colorir('Resultados encontrados:', 'VERDE')} {self.estatisticas['resultados_encontrados']:,}")
            print(f"⏱️  {self.colorir('Tempo de execução:', 'CIANO')} {self.estatisticas['tempo_execucao']:.2f} segundos")
            print(f"📈 {self.colorir('Eficiência:', 'ROXO')} {self.estatisticas['resultados_encontrados']/max(1, self.estatisticas['arquivos_analisados'])*100:.2f}%")
        else:
            print("ℹ️  Nenhuma busca realizada ainda.")
        
        self.pausar()

    def menu_configuracoes(self):
        """Menu de configurações"""
        self.mostrar_cabecalho("CONFIGURAÇÕES")
        
        print(f"{self.colorir('⚙️ CONFIGURAÇÕES', 'NEGRITO')}")
        print("=" * 50)
        
        novo_dir = input(f"\n📂 {self.colorir('Novo diretório base', 'AZUL')} (atual: {self.diretorio_base}): ").strip()
        
        if novo_dir:
            novo_path = Path(novo_dir).expanduser().resolve()
            if novo_path.exists() and novo_path.is_dir():
                self.diretorio_base = novo_path
                print(f"✅ {self.colorir('Diretório alterado com sucesso!', 'VERDE')}")
            else:
                print(f"❌ {self.colorir('Diretório não existe!', 'VERMELHO')}")
        
        self.pausar()

    def executar(self):
        """Loop principal do menu"""
        while True:
            opcao = self.mostrar_menu_principal()
            
            if opcao == '0':
                print(f"\n👋 {self.colorir('Saindo do Buscador. Até mais!', 'AZUL')}")
                break
            
            elif opcao == '1':
                self.menu_busca_nome()
            
            elif opcao == '2':
                self.menu_busca_conteudo()
            
            elif opcao == '3':
                self.menu_busca_tamanho()
            
            elif opcao == '4':
                self.menu_busca_data()
            
            elif opcao == '5':
                self.menu_busca_tipo()
            
            elif opcao == '6':
                self.menu_busca_avancada()
            
            elif opcao == '7':
                self.menu_estatisticas()
            
            elif opcao == '8':
                self.menu_configuracoes()
            
            else:
                print(f"❌ {self.colorir('Opção inválida!', 'VERMELHO')}")
                self.pausar()

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Buscador Inteligente - Modo Menu')
    parser.add_argument('diretorio', nargs='?', default='.', help='Diretório base para busca')
    
    args = parser.parse_args()
    
    try:
        buscador = BuscadorInteligente(args.diretorio)
        buscador.executar()
    except KeyboardInterrupt:
        print(f"\n\n👋 {buscador.colorir('Programa interrompido pelo usuário.', 'AMARELO')}")
    except Exception as e:
        print(f"\n❌ {buscador.colorir(f'Erro fatal: {e}', 'VERMELHO')}")

if __name__ == "__main__":
    main()
