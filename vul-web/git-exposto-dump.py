#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import time
import random
import requests
import subprocess
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Interface colorida no terminal
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.tree import Tree
from rich.syntax import Syntax

console = Console()

class GitExposedScanner:
    def __init__(self):
        self.common_paths = [
            '.git/',
            '.git/HEAD',
            '.git/config',
            '.git/description',
            '.git/hooks/',
            '.git/index',
            '.git/info/',
            '.git/logs/',
            '.git/objects/',
            '.git/refs/',
            '.git-rewrite/',
            '.gitignore',
            'README.md'
        ]
        
        self.signature_patterns = [
            r'refs/heads/master',
            r'\[core\]',
            r'repositoryformatversion',
            r'ref: refs/heads/',
            r'object\.*'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'git/2.30.0',
            'curl/7.68.0'
        ]
        
        self.found_repos = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
    def mostrar_banner(self):
        banner = """
[bold red]
 ██████╗ ██╗████████╗    ███████╗██╗  ██╗██████╗  ██████╗ ████████╗███████╗██████╗ 
██╔════╝ ██║╚══██╔══╝    ██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔══██╗
██║  ███╗██║   ██║       █████╗   ╚███╔╝ ██████╔╝██║   ██║   ██║   █████╗  ██║  ██║
██║   ██║██║   ██║       ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║   ██║   ██╔══╗  ██║  ██║
╚██████╔╝██║   ██║       ███████╗██╔╝ ██╗██║     ╚██████╔╝   ██║   ███████╗██████╔╝
 ╚═════╝ ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝    ╚═╝   ╚══════╝╚═════╝ 
[/bold red]
[bold white on red]        SCANNER DE REPOSITÓRIOS GIT EXPOSTOS - USE COM RESPONSABILIDADE[/bold white on red]
"""
        console.print(banner)
        console.print(Panel.fit(
            "[blink yellow]⚠️  FERRAMENTA DE SEGURANÇA - USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink yellow]\n"
            "Este scanner identifica e baixa repositórios Git expostos acidentalmente\n"
            "em servidores web. Use apenas em sistemas que você possui ou tem permissão para testar.",
            style="yellow on black"
        ))
    
    def verificar_url(self, url: str) -> bool:
        """Verifica se uma URL parece válida"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False
    
    def normalizar_url(self, url: str) -> str:
        """Normaliza a URL para garantir que termine com /"""
        if not url.endswith('/'):
            url += '/'
        return url
    
    def testar_path(self, base_url: str, path: str) -> Tuple[str, bool, int]:
        """Testa um caminho específico na URL base"""
        full_url = urljoin(base_url, path)
        try:
            response = self.session.get(
                full_url, 
                timeout=10, 
                allow_redirects=True,
                headers={'User-Agent': random.choice(self.user_agents)}
            )
            
            # Verificar se é um diretório Git válido
            is_git = False
            if response.status_code == 200:
                content = response.text.lower()
                # Verificar padrões específicos do Git
                for pattern in self.signature_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        is_git = True
                        break
            
            return (full_url, is_git, response.status_code)
            
        except requests.RequestException:
            return (full_url, False, 0)
    
    def escanear_url(self, url: str) -> Dict[str, any]:
        """Escaneia uma URL em busca de repositórios Git expostos"""
        console.print(f"[cyan]Escaneando: {url}[/cyan]")
        
        resultados = {
            'url': url,
            'vulneravel': False,
            'paths_encontrados': [],
            'detalhes': {}
        }
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("[yellow]Testando caminhos...", total=len(self.common_paths))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self.testar_path, url, path): path 
                    for path in self.common_paths
                }
                
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        full_url, is_git, status_code = future.result()
                        if status_code == 200:
                            resultados['paths_encontrados'].append({
                                'path': path,
                                'url': full_url,
                                'is_git': is_git,
                                'status': status_code
                            })
                            if is_git:
                                resultados['vulneravel'] = True
                    except Exception as e:
                        pass
                    progress.update(task, advance=1)
        
        return resultados
    
    def confirmar_vulnerabilidade(self, resultados: Dict[str, any]) -> bool:
        """Confirma se a URL é realmente vulnerável"""
        if not resultados['vulneravel']:
            return False
        
        # Testar caminhos adicionais para confirmação
        paths_confirmacao = ['.git/logs/HEAD', '.git/refs/heads/master']
        
        for path in paths_confirmacao:
            full_url = urljoin(resultados['url'], path)
            try:
                response = self.session.get(full_url, timeout=8)
                if response.status_code == 200:
                    return True
            except:
                continue
        
        return False
    
    def baixar_repositorio(self, url: str, output_dir: str) -> bool:
        """Baixa um repositório Git exposto"""
        console.print(f"[green]Baixando repositório de: {url}[/green]")
        
        # Criar diretório de saída
        domain = urlparse(url).netloc
        timestamp = int(time.time())
        repo_dir = os.path.join(output_dir, f"git_{domain}_{timestamp}")
        os.makedirs(repo_dir, exist_ok=True)
        
        try:
            # Baixar arquivos principais do Git
            arquivos_principais = [
                'HEAD', 'config', 'description', 'index',
                'logs/HEAD', 'info/exclude', 'packed-refs'
            ]
            
            # Baixar objetos (isso pode ser extenso)
            objetos_dir = os.path.join(repo_dir, 'objects')
            os.makedirs(objetos_dir, exist_ok=True)
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Baixando arquivos...", total=len(arquivos_principais) + 10)
                
                # Baixar arquivos principais
                for arquivo in arquivos_principais:
                    file_url = urljoin(url, f'.git/{arquivo}')
                    try:
                        response = self.session.get(file_url, timeout=10)
                        if response.status_code == 200:
                            file_path = os.path.join(repo_dir, '.git', arquivo)
                            os.makedirs(os.path.dirname(file_path), exist_ok=True)
                            with open(file_path, 'wb') as f:
                                f.write(response.content)
                    except:
                        pass
                    progress.update(task, advance=1)
                
                # Tentar baixar alguns objetos (limitar para não sobrecarregar)
                for i in range(10):
                    obj_dir = f"{i:02x}"
                    obj_url = urljoin(url, f'.git/objects/{obj_dir}/')
                    
                    try:
                        response = self.session.get(obj_url, timeout=5)
                        if response.status_code == 200:
                            # É um diretório, tentar listar objetos
                            os.makedirs(os.path.join(objetos_dir, obj_dir), exist_ok=True)
                            
                            # Padrão para encontrar arquivos de objeto
                            objetos = re.findall(r'href="([a-f0-9]+)"', response.text)
                            for obj in objetos[:5]:  # Limitar a 5 objetos por diretório
                                obj_url_full = urljoin(obj_url, obj)
                                obj_response = self.session.get(obj_url_full, timeout=5)
                                if obj_response.status_code == 200:
                                    obj_path = os.path.join(objetos_dir, obj_dir, obj)
                                    with open(obj_path, 'wb') as f:
                                        f.write(obj_response.content)
                    except:
                        pass
                    progress.update(task, advance=1)
            
            # Verificar se conseguimos baixar o suficiente para análise
            head_path = os.path.join(repo_dir, '.git', 'HEAD')
            if os.path.exists(head_path):
                console.print(f"[green]✓ Repositório baixado em: {repo_dir}[/green]")
                return True
            else:
                console.print("[red]✗ Falha ao baixar repositório completo[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Erro ao baixar: {str(e)}[/red]")
            return False
    
    def analisar_repositorio(self, repo_dir: str):
        """Analisa um repositório baixado em busca de informações sensíveis"""
        console.print(f"[yellow]Analisando repositório: {repo_dir}[/yellow]")
        
        informacoes_sensiveis = {
            'chaves_ssh': [],
            'tokens_api': [],
            'senhas': [],
            'emails': [],
            'arquivos_config': []
        }
        
        padroes_sensiveis = {
            'ssh_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'api_token': r'(?i)(api[_-]?key|token|secret)[\s:=]["\']([a-zA-Z0-9_\-]{20,})["\']',
            'password': r'(?i)(password|passwd|pwd)[\s:=]["\']([^"\']+)["\']',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'google_key': r'AIza[0-9A-Za-z\\-_]{35}'
        }
        
        try:
            for root, dirs, files in os.walk(repo_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Verificar padrões sensíveis
                            for tipo, pattern in padroes_sensiveis.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    informacoes_sensiveis[tipo + 's'].extend(matches)
                    
                    except (UnicodeDecodeError, IOError):
                        # Pular arquivos binários ou inacessíveis
                        continue
            
            # Exibir resultados da análise
            if any(informacoes_sensiveis.values()):
                console.print(Panel.fit(
                    "[bold red]INFORMAÇÕES SENSÍVEIS ENCONTRADAS![/bold red]",
                    border_style="red"
                ))
                
                for tipo, dados in informacoes_sensiveis.items():
                    if dados:
                        console.print(f"[yellow]{tipo.upper()}:[/yellow] {len(dados)} encontrados")
                        for i, dado in enumerate(dados[:3]):  # Mostrar apenas os 3 primeiros
                            if isinstance(dado, tuple):
                                dado = str(dado)
                            console.print(f"  {i+1}. {dado[:100]}{'...' if len(dado) > 100 else ''}")
            
            else:
                console.print("[green]✓ Nenhuma informação sensível encontrada[/green]")
                
        except Exception as e:
            console.print(f"[red]✗ Erro na análise: {str(e)}[/red]")
    
    def gerar_relatorio(self, resultados: List[Dict[str, any]], output_file: str):
        """Gera um relatório JSON com os resultados do scan"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': time.time(),
                    'scan_results': resultados,
                    'metadata': {
                        'scanner': 'GitExposedScanner',
                        'version': '1.0'
                    }
                }, f, indent=2, ensure_ascii=False)
            
            console.print(f"[green]✓ Relatório salvo em: {output_file}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Erro ao salvar relatório: {str(e)}[/red]")
    
    def menu_principal(self):
        """Menu principal interativo"""
        self.mostrar_banner()
        
        while True:
            console.print("\n[bold cyan]MENU PRINCIPAL[/bold cyan]")
            console.print("1. Escanear URL única")
            console.print("2. Escanear múltiplas URLs (arquivo)")
            console.print("3. Configurações")
            console.print("4. Sair")
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione uma opção",
                choices=["1", "2", "3", "4"],
                show_choices=False
            )
            
            if escolha == "1":
                self.escanear_url_unica()
            elif escolha == "2":
                self.escanear_multiplas_urls()
            elif escolha == "3":
                self.menu_configuracoes()
            elif escolha == "4":
                console.print("[cyan]Saindo...[/cyan]")
                break
    
    def escanear_url_unica(self):
        """Escaneia uma única URL"""
        url = Prompt.ask("[yellow]?[/yellow] Digite a URL para escanear")
        
        if not self.verificar_url(url):
            console.print("[red]✗ URL inválida![/red]")
            return
        
        url = self.normalizar_url(url)
        resultados = self.escanear_url(url)
        
        # Exibir resultados
        console.print("\n[bold]RESULTADOS DO SCAN:[/bold]")
        if resultados['vulneravel'] and self.confirmar_vulnerabilidade(resultados):
            console.print(Panel.fit(
                "[blink bold red]⚠️  VULNERABILIDADE ENCONTRADA! ⚠️[/blink bold red]\n"
                f"Repositório Git exposto em: {url}",
                border_style="red"
            ))
            
            # Mostrar paths encontrados
            tabela = Table(title="Arquivos/Diretórios Encontrados", show_header=True)
            tabela.add_column("Path")
            tabela.add_column("Status")
            tabela.add_column("Git")
            
            for item in resultados['paths_encontrados']:
                status_emoji = "🟢" if item['status'] == 200 else "🔴"
                git_emoji = "✅" if item['is_git'] else "❌"
                tabela.add_row(item['path'], status_emoji, git_emoji)
            
            console.print(tabela)
            
            # Oferecer para baixar
            if Confirm.ask("[yellow]?[/yellow] Deseja baixar o repositório?"):
                output_dir = Prompt.ask(
                    "[yellow]?[/yellow] Diretório de saída", 
                    default="./git_repos"
                )
                sucesso = self.baixar_repositorio(url, output_dir)
                if sucesso:
                    if Confirm.ask("[yellow]?[/yellow] Deseja analisar o repositório em busca de informações sensíveis?"):
                        repo_dir = os.path.join(output_dir, f"git_{urlparse(url).netloc}_*")
                        matching_dirs = [d for d in os.listdir(output_dir) if d.startswith(f"git_{urlparse(url).netloc}_")]
                        if matching_dirs:
                            latest_dir = max(matching_dirs, key=lambda d: os.path.getctime(os.path.join(output_dir, d)))
                            self.analisar_repositorio(os.path.join(output_dir, latest_dir))
        
        else:
            console.print("[green]✓ Nenhuma vulnerabilidade encontrada[/green]")
        
        input("\nPressione Enter para continuar...")
    
    def escanear_multiplas_urls(self):
        """Escaneia múltiplas URLs de um arquivo"""
        arquivo = Prompt.ask("[yellow]?[/yellow] Caminho do arquivo com URLs")
        
        if not os.path.exists(arquivo):
            console.print("[red]✗ Arquivo não encontrado![/red]")
            return
        
        try:
            with open(arquivo, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and self.verificar_url(line.strip())]
            
            if not urls:
                console.print("[red]✗ Nenhuma URL válida encontrada no arquivo![/red]")
                return
            
            console.print(f"[cyan]Encontradas {len(urls)} URLs válidas[/cyan]")
            
            resultados = []
            vulneraveis = []
            
            with Progress() as progress:
                task = progress.add_task("[yellow]Escaneando URLs...", total=len(urls))
                
                for url in urls:
                    url = self.normalizar_url(url)
                    resultado = self.escanear_url(url)
                    resultados.append(resultado)
                    
                    if resultado['vulneravel'] and self.confirmar_vulnerabilidade(resultado):
                        vulneraveis.append(url)
                        console.print(f"[red]✓ Vulnerabilidade encontrada em: {url}[/red]")
                    
                    progress.update(task, advance=1)
            
            # Relatório final
            console.print(Panel.fit(
                f"[bold]RELATÓRIO FINAL[/bold]\n"
                f"Total de URLs escaneadas: {len(urls)}\n"
                f"Vulnerabilidades encontradas: {len(vulneraveis)}\n"
                f"Taxa de sucesso: {(len(vulneraveis)/len(urls))*100:.2f}%",
                border_style="green" if not vulneraveis else "red"
            ))
            
            if vulneraveis:
                console.print("[bold]URLs vulneráveis:[/bold]")
                for url in vulneraveis:
                    console.print(f"  • {url}")
                
                if Confirm.ask("[yellow]?[/yellow] Deseja gerar um relatório?"):
                    output_file = Prompt.ask(
                        "[yellow]?[/yellow] Nome do arquivo de relatório", 
                        default="git_scan_report.json"
                    )
                    self.gerar_relatorio(resultados, output_file)
        
        except Exception as e:
            console.print(f"[red]✗ Erro ao processar arquivo: {str(e)}[/red]")
        
        input("\nPressione Enter para continuar...")
    
    def menu_configuracoes(self):
        """Menu de configurações"""
        console.print(Panel.fit(
            "[bold cyan]CONFIGURAÇÕES[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print(f"User Agents: {len(self.user_agents)} disponíveis")
        console.print(f"Paths comuns: {len(self.common_paths)} configurados")
        console.print(f"Padrões de detecção: {len(self.signature_patterns)} ativos")
        
        input("\nPressione Enter para voltar...")

def main():
    try:
        scanner = GitExposedScanner()
        scanner.menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Scan cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro inesperado: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
