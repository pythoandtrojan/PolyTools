#!/usr/bin/env python3
"""
📁 ORGANIZADOR INTELIGENTE DE ARQUIVOS - MODO MENU
Script avançado com menu interativo para organizar arquivos
"""

import os
import shutil
import argparse
from pathlib import Path
from datetime import datetime
import json
from typing import Dict, List
import sys

class OrganizadorMenu:
    def __init__(self, diretorio: str = "."):
        self.diretorio = Path(diretorio).resolve()
        self.modo_seguro = True
        self.estatisticas = {
            'arquivos_movidos': 0,
            'pastas_criadas': 0,
            'erros': 0,
            'inicio': None,
            'fim': None
        }
        
        # Mapeamento extensão → pasta
        self.categorias = {
            '📷 Imagens': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico', 'raw', 'cr2'],
            '🎵 Audio': ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma'],
            '🎬 Videos': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v'],
            '📄 Documentos': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'],
            '📊 Planilhas': ['xls', 'xlsx', 'csv', 'ods'],
            '🎯 Apresentacoes': ['ppt', 'pptx', 'odp'],
            '📦 Compactados': ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'],
            '💻 Codigo': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'php', 'json', 'xml'],
            '⚙️ Executaveis': ['exe', 'msi', 'deb', 'rpm', 'appimage', 'sh', 'bat'],
            '🔐 Seguranca': ['pem', 'key', 'crt', 'cer', 'pfx', 'p12'],
        }
        
        self.setup_cores()

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

    def colorir(self, texto: str, cor: str) -> str:
        """Aplica cor ao texto"""
        return f"{self.cores.get(cor, '')}{texto}{self.cores['FIM']}"

    def limpar_tela(self):
        """Limpa a tela do terminal"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def mostrar_cabecalho(self):
        """Mostra cabeçalho bonito"""
        self.limpar_tela()
        print(f"{self.colorir('╔══════════════════════════════════════════════════╗', 'AZUL')}")
        print(f"{self.colorir('║               🗂️  ORGANIZADOR DE ARQUIVOS         ║', 'AZUL')}")
        print(f"{self.colorir('║                 🚀 Modo Menu Interativo          ║', 'AZUL')}")
        print(f"{self.colorir('╚══════════════════════════════════════════════════╝', 'AZUL')}")
        print(f"📂 {self.colorir('Diretório:', 'NEGRITO')} {self.diretorio}")
        print(f"🛡️  {self.colorir('Modo seguro:', 'NEGRITO')} {self.colorir('ATIVADO', 'VERDE') if self.modo_seguro else self.colorir('DESATIVADO', 'VERMELHO')}")
        print()

    def pausar(self, mensagem: str = "Pressione Enter para continuar..."):
        """Pausa e espera Enter"""
        input(f"\n⏸️  {mensagem}")

    def mostrar_menu_principal(self):
        """Menu principal"""
        self.mostrar_cabecalho()
        
        print(f"{self.colorir('🎯 MENU PRINCIPAL', 'NEGRITO')}")
        print("=" * 40)
        print(f"1. {self.colorir('📊 Analisar Diretório', 'CIANO')}")
        print(f"2. {self.colorir('🗂️ Organizar por Tipo', 'VERDE')}")
        print(f"3. {self.colorir('📅 Organizar por Data', 'AMARELO')}")
        print(f"4. {self.colorir('📏 Organizar por Tamanho', 'ROXO')}")
        print(f"5. {self.colorir('⚙️  Configurações', 'AZUL')}")
        print(f"6. {self.colorir('📈 Estatísticas', 'CIANO')}")
        print(f"0. {self.colorir('🚪 Sair', 'VERMELHO')}")
        print("=" * 40)
        
        return input(f"\n🎯 {self.colorir('Selecione uma opção', 'NEGRITO')} (0-6): ").strip()

    def mostrar_menu_tipo(self):
        """Menu de organização por tipo"""
        self.mostrar_cabecalho()
        
        print(f"{self.colorir('🗂️ ORGANIZAR POR TIPO', 'NEGRITO')}")
        print("=" * 40)
        print(f"1. {self.colorir('Organização Básica', 'VERDE')}")
        print(f"2. {self.colorir('Com Subpastas por Extensão', 'AZUL')}")
        print(f"3. {self.colorir('Personalizar Categorias', 'ROXO')}")
        print(f"0. {self.colorir('↩️ Voltar', 'AMARELO')}")
        print("=" * 40)
        
        return input(f"\n🎯 {self.colorir('Selecione uma opção', 'NEGRITO')} (0-3): ").strip()

    def mostrar_menu_data(self):
        """Menu de organização por data"""
        self.mostrar_cabecalho()
        
        print(f"{self.colorir('📅 ORGANIZAR POR DATA', 'NEGRITO')}")
        print("=" * 40)
        print(f"1. {self.colorir('Por Ano', 'VERDE')} (2024)")
        print(f"2. {self.colorir('Por Ano-Mês', 'AZUL')} (2024-01)")
        print(f"3. {self.colorir('Por Data Completa', 'ROXO')} (2024-01-15)")
        print(f"0. {self.colorir('↩️ Voltar', 'AMARELO')}")
        print("=" * 40)
        
        return input(f"\n🎯 {self.colorir('Selecione uma opção', 'NEGRITO')} (0-3): ").strip()

    def mostrar_menu_config(self):
        """Menu de configurações"""
        self.mostrar_cabecalho()
        
        print(f"{self.colorir('⚙️ CONFIGURAÇÕES', 'NEGRITO')}")
        print("=" * 40)
        print(f"1. {self.colorir('Mudar Diretório', 'CIANO')}")
        print(f"2. {self.colorir('Modo Seguro: ', 'VERDE')}{'🔴 DESATIVAR' if self.modo_seguro else '🟢 ATIVAR'}")
        print(f"3. {self.colorir('Ver Categorias', 'AZUL')}")
        print(f"0. {self.colorir('↩️ Voltar', 'AMARELO')}")
        print("=" * 40)
        
        return input(f"\n🎯 {self.colorir('Selecione uma opção', 'NEGRITO')} (0-3): ").strip()

    def detectar_categoria(self, arquivo: Path) -> str:
        """Detecta a categoria do arquivo"""
        extensao = arquivo.suffix.lower().lstrip('.')
        
        for categoria, extensoes in self.categorias.items():
            if extensao in extensoes:
                # Remove emoji para nome da pasta
                return categoria.split(' ', 1)[1] if ' ' in categoria else categoria
        
        return "Outros"

    def criar_pasta_segura(self, pasta: Path) -> bool:
        """Cria pasta se não existir"""
        try:
            if not pasta.exists():
                pasta.mkdir(parents=True, exist_ok=True)
                self.estatisticas['pastas_criadas'] += 1
                print(f"📁 {self.colorir('Pasta criada:', 'AZUL')} {pasta.name}")
            return True
        except Exception as e:
            print(f"❌ {self.colorir(f'Erro criando pasta: {e}', 'VERMELHO')}")
            self.estatisticas['erros'] += 1
            return False

    def mover_arquivo_seguro(self, origem: Path, destino: Path) -> bool:
        """Move arquivo com verificações de segurança"""
        try:
            if not origem.exists():
                return False
            
            if destino.exists() and self.modo_seguro:
                # Cria nome único
                contador = 1
                nome_base = destino.stem
                extensao = destino.suffix
                
                while destino.exists():
                    novo_nome = f"{nome_base}_{contador}{extensao}"
                    destino = destino.parent / novo_nome
                    contador += 1
            
            shutil.move(str(origem), str(destino))
            self.estatisticas['arquivos_movidos'] += 1
            return True
            
        except Exception as e:
            print(f"❌ {self.colorir(f'Erro movendo {origem.name}: {e}', 'VERMELHO')}")
            self.estatisticas['erros'] += 1
            return False

    def analisar_diretorio(self):
        """Analisa o diretório detalhadamente"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('🔍 ANALISANDO DIRETÓRIO...', 'NEGRITO')}\n")
        
        arquivos_por_tipo = {}
        total_arquivos = 0
        total_tamanho = 0
        
        try:
            itens = list(self.diretorio.iterdir())
        except Exception as e:
            print(f"❌ {self.colorir(f'Erro acessando diretório: {e}', 'VERMELHO')}")
            self.pausar()
            return
        
        for item in itens:
            if item.is_file():
                total_arquivos += 1
                total_tamanho += item.stat().st_size
                
                categoria = self.detectar_categoria(item)
                arquivos_por_tipo[categoria] = arquivos_por_tipo.get(categoria, 0) + 1
        
        # Mostrar resultados
        print(f"📄 {self.colorir('Total de arquivos:', 'AZUL')} {total_arquivos}")
        print(f"💾 {self.colorir('Espaço total:', 'AZUL')} {total_tamanho / (1024*1024):.2f} MB")
        print(f"📂 {self.colorir('Itens no diretório:', 'AZUL')} {len(itens)}")
        
        if total_arquivos > 0:
            print(f"\n📊 {self.colorir('DISTRIBUIÇÃO POR TIPO:', 'NEGRITO')}")
            print("-" * 30)
            
            for categoria, quantidade in sorted(arquivos_por_tipo.items(), key=lambda x: x[1], reverse=True):
                percentual = (quantidade / total_arquivos) * 100
                barra = "█" * int(percentual / 5)  # Barra de progresso
                print(f"  {categoria:<15} {quantidade:>3} {barra:<20} ({percentual:.1f}%)")
        
        self.pausar()

    def organizar_por_tipo(self, criar_subpastas: bool = False):
        """Organiza arquivos por tipo"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('🗂️ ORGANIZANDO POR TIPO...', 'NEGRITO')}\n")
        
        self.estatisticas['inicio'] = datetime.now()
        arquivos_processados = 0
        
        for item in self.diretorio.iterdir():
            if item.is_file():
                categoria = self.detectar_categoria(item)
                pasta_destino = self.diretorio / categoria
                
                if criar_subpastas:
                    extensao = item.suffix.lower().lstrip('.') or 'sem_extensao'
                    pasta_destino = pasta_destino / extensao
                
                if self.criar_pasta_segura(pasta_destino):
                    destino_arquivo = pasta_destino / item.name
                    if self.mover_arquivo_seguro(item, destino_arquivo):
                        print(f"✅ {self.colorir('Movido:', 'VERDE')} {item.name} → {categoria}/")
                        arquivos_processados += 1
        
        self.estatisticas['fim'] = datetime.now()
        self.mostrar_resumo_operacao(arquivos_processados)

    def organizar_por_data(self, formato: str = "ano-mes"):
        """Organiza arquivos por data"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('📅 ORGANIZANDO POR DATA...', 'NEGRITO')}\n")
        
        self.estatisticas['inicio'] = datetime.now()
        arquivos_processados = 0
        
        for item in self.diretorio.iterdir():
            if item.is_file():
                timestamp = item.stat().st_mtime
                data = datetime.fromtimestamp(timestamp)
                
                if formato == "ano":
                    pasta_data = f"{data.year}"
                elif formato == "ano-mes-dia":
                    pasta_data = f"{data.year}-{data.month:02d}-{data.day:02d}"
                else:  # ano-mes
                    pasta_data = f"{data.year}-{data.month:02d}"
                
                pasta_destino = self.diretorio / "PorData" / pasta_data
                
                if self.criar_pasta_segura(pasta_destino):
                    destino_arquivo = pasta_destino / item.name
                    if self.mover_arquivo_seguro(item, destino_arquivo):
                        print(f"✅ {self.colorir('Movido:', 'VERDE')} {item.name} → PorData/{pasta_data}/")
                        arquivos_processados += 1
        
        self.estatisticas['fim'] = datetime.now()
        self.mostrar_resumo_operacao(arquivos_processados)

    def organizar_por_tamanho(self):
        """Organiza arquivos por tamanho"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('📏 ORGANIZANDO POR TAMANHO...', 'NEGRITO')}\n")
        
        self.estatisticas['inicio'] = datetime.now()
        arquivos_processados = 0
        
        faixas = {
            'Pequenos': (0, 1024 * 1024),
            'Medios': (1024 * 1024, 10 * 1024 * 1024),
            'Grandes': (10 * 1024 * 1024, 100 * 1024 * 1024),
            'Enormes': (100 * 1024 * 1024, float('inf'))
        }
        
        for item in self.diretorio.iterdir():
            if item.is_file():
                tamanho = item.stat().st_size
                
                for faixa, (minimo, maximo) in faixas.items():
                    if minimo <= tamanho < maximo:
                        pasta_destino = self.diretorio / "PorTamanho" / faixa
                        
                        if self.criar_pasta_segura(pasta_destino):
                            destino_arquivo = pasta_destino / item.name
                            if self.mover_arquivo_seguro(item, destino_arquivo):
                                tamanho_mb = tamanho / (1024 * 1024)
                                print(f"✅ {self.colorir('Movido:', 'VERDE')} {item.name} ({tamanho_mb:.1f}MB) → PorTamanho/{faixa}/")
                                arquivos_processados += 1
                        break
        
        self.estatisticas['fim'] = datetime.now()
        self.mostrar_resumo_operacao(arquivos_processados)

    def mostrar_resumo_operacao(self, arquivos_processados: int):
        """Mostra resumo da operação"""
        duracao = self.estatisticas['fim'] - self.estatisticas['inicio']
        
        print(f"\n{'='*50}")
        print(f"📊 {self.colorir('RESUMO DA OPERAÇÃO', 'NEGRITO')}")
        print(f"{'='*50}")
        print(f"✅ {self.colorir('Arquivos processados:', 'VERDE')} {arquivos_processados}")
        print(f"📁 {self.colorir('Pastas criadas:', 'AZUL')} {self.estatisticas['pastas_criadas']}")
        print(f"❌ {self.colorir('Erros:', 'VERMELHO')} {self.estatisticas['erros']}")
        print(f"⏱️  {self.colorir('Duração:', 'CIANO')} {duracao.total_seconds():.2f} segundos")
        print(f"{'='*50}")
        
        self.pausar()

    def mudar_diretorio(self):
        """Permite mudar o diretório de trabalho"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('📂 MUDAR DIRETÓRIO', 'NEGRITO')}\n")
        
        novo_dir = input(f"📁 {self.colorir('Digite o caminho do diretório', 'AZUL')} (atual: {self.diretorio}): ").strip()
        
        if not novo_dir:
            print("⚠️  Operação cancelada.")
            self.pausar()
            return
        
        novo_path = Path(novo_dir).expanduser().resolve()
        
        try:
            if novo_path.exists() and novo_path.is_dir():
                self.diretorio = novo_path
                print(f"✅ {self.colorir('Diretório alterado para:', 'VERDE')} {self.diretorio}")
            else:
                print(f"❌ {self.colorir('Diretório não existe ou não é válido!', 'VERMELHO')}")
        except Exception as e:
            print(f"❌ {self.colorir(f'Erro: {e}', 'VERMELHO')}")
        
        self.pausar()

    def toggle_modo_seguro(self):
        """Alterna o modo seguro"""
        self.modo_seguro = not self.modo_seguro
        status = "ATIVADO" if self.modo_seguro else "DESATIVADO"
        cor = "VERDE" if self.modo_seguro else "VERMELHO"
        
        print(f"🛡️  {self.colorir('Modo seguro:', 'NEGRITO')} {self.colorir(status, cor)}")
        self.pausar()

    def ver_categorias(self):
        """Mostra todas as categorias configuradas"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('📋 CATEGORIAS CONFIGURADAS', 'NEGRITO')}\n")
        
        for categoria, extensoes in self.categorias.items():
            print(f"{categoria}:")
            print(f"  📄 {', '.join(extensoes)}")
            print()
        
        self.pausar()

    def mostrar_estatisticas_gerais(self):
        """Mostra estatísticas gerais"""
        self.mostrar_cabecalho()
        print(f"{self.colorir('📈 ESTATÍSTICAS GERAIS', 'NEGRITO')}\n")
        
        print(f"📂 {self.colorir('Diretório atual:', 'AZUL')} {self.diretorio}")
        print(f"🛡️  {self.colorir('Modo seguro:', 'AZUL')} {'ATIVADO' if self.modo_seguro else 'DESATIVADO'}")
        print(f"📊 {self.colorir('Total de categorias:', 'AZUL')} {len(self.categorias)}")
        
        if self.estatisticas['inicio']:
            print(f"\n{self.colorir('📅 ÚLTIMA OPERAÇÃO:', 'NEGRITO')}")
            print(f"✅ Arquivos movidos: {self.estatisticas['arquivos_movidos']}")
            print(f"📁 Pastas criadas: {self.estatisticas['pastas_criadas']}")
            print(f"❌ Erros: {self.estatisticas['erros']}")
        
        self.pausar()

    def executar(self):
        """Loop principal do menu"""
        while True:
            opcao = self.mostrar_menu_principal()
            
            if opcao == '0':
                print(f"\n👋 {self.colorir('Saindo do Organizador. Até mais!', 'AZUL')}")
                break
            
            elif opcao == '1':
                self.analisar_diretorio()
            
            elif opcao == '2':
                self.processar_menu_tipo()
            
            elif opcao == '3':
                self.processar_menu_data()
            
            elif opcao == '4':
                self.organizar_por_tamanho()
            
            elif opcao == '5':
                self.processar_menu_config()
            
            elif opcao == '6':
                self.mostrar_estatisticas_gerais()
            
            else:
                print(f"❌ {self.colorir('Opção inválida!', 'VERMELHO')}")
                self.pausar()

    def processar_menu_tipo(self):
        """Processa o menu de organização por tipo"""
        while True:
            opcao = self.mostrar_menu_tipo()
            
            if opcao == '0':
                break
            elif opcao == '1':
                self.organizar_por_tipo()
                break
            elif opcao == '2':
                self.organizar_por_tipo(criar_subpastas=True)
                break
            elif opcao == '3':
                self.ver_categorias()
            else:
                print(f"❌ {self.colorir('Opção inválida!', 'VERMELHO')}")
                self.pausar()

    def processar_menu_data(self):
        """Processa o menu de organização por data"""
        while True:
            opcao = self.mostrar_menu_data()
            
            if opcao == '0':
                break
            elif opcao == '1':
                self.organizar_por_data("ano")
                break
            elif opcao == '2':
                self.organizar_por_data("ano-mes")
                break
            elif opcao == '3':
                self.organizar_por_data("ano-mes-dia")
                break
            else:
                print(f"❌ {self.colorir('Opção inválida!', 'VERMELHO')}")
                self.pausar()

    def processar_menu_config(self):
        """Processa o menu de configurações"""
        while True:
            opcao = self.mostrar_menu_config()
            
            if opcao == '0':
                break
            elif opcao == '1':
                self.mudar_diretorio()
            elif opcao == '2':
                self.toggle_modo_seguro()
            elif opcao == '3':
                self.ver_categorias()
            else:
                print(f"❌ {self.colorir('Opção inválida!', 'VERMELHO')}")
                self.pausar()

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Organizador de Arquivos - Modo Menu')
    parser.add_argument('diretorio', nargs='?', default='.', help='Diretório inicial')
    
    args = parser.parse_args()
    
    try:
        organizador = OrganizadorMenu(args.diretorio)
        organizador.executar()
    except KeyboardInterrupt:
        print(f"\n\n👋 {organizador.colorir('Programa interrompido pelo usuário.', 'AMARELO')}")
    except Exception as e:
        print(f"\n❌ {organizador.colorir(f'Erro fatal: {e}', 'VERMELHO')}")

if __name__ == "__main__":
    main()
