#!/data/data/com.termux/files/usr/bin/python3

import os
import sys
import subprocess
import platform
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text
import shutil

console = Console()

class UniversalCompiler:
    def __init__(self):
        self.supported_languages = {
            "cpp": {
                "extensions": [".cpp", ".cxx", ".cc", ".c++"],
                "compiler": "g++",
                "description": "C++"
            },
            "c": {
                "extensions": [".c"],
                "compiler": "gcc", 
                "description": "C"
            },
            "java": {
                "extensions": [".java"],
                "compiler": "javac",
                "description": "Java"
            }
        }
        self.setup_environment()
    
    def setup_environment(self):
        """Configura o ambiente de compilação"""
        self.system = platform.system().lower()
        self.arch = platform.machine()
        
        # Verifica compiladores disponíveis
        self.available_compilers = {}
        for lang, info in self.supported_languages.items():
            if self.check_compiler_available(info['compiler']):
                self.available_compilers[lang] = info
    
    def check_compiler_available(self, compiler):
        """Verifica se um compilador está disponível no sistema"""
        try:
            result = subprocess.run(
                [compiler, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def detect_language(self, file_path):
        """Detecta a linguagem do arquivo baseado na extensão"""
        file_ext = Path(file_path).suffix.lower()
        
        for lang, info in self.supported_languages.items():
            if file_ext in info['extensions']:
                return lang
        return None
    
    def compile_cpp(self, file_path, output_name=None, optimize=False, debug=False):
        """Compila arquivo C++"""
        if not output_name:
            output_name = Path(file_path).stem
            
        # Ajusta extensão do executável baseado no SO
        if self.system == "windows":
            output_name += ".exe"
        
        compile_cmd = ["g++", file_path, "-o", output_name]
        
        # Flags de otimização
        if optimize:
            compile_cmd.extend(["-O2", "-march=native"])
        
        # Flags de debug
        if debug:
            compile_cmd.extend(["-g", "-DDEBUG"])
        
        # Flags padrão
        compile_cmd.extend(["-std=c++17", "-Wall", "-Wextra"])
        
        return self.run_compilation(compile_cmd, output_name)
    
    def compile_c(self, file_path, output_name=None, optimize=False, debug=False):
        """Compila arquivo C"""
        if not output_name:
            output_name = Path(file_path).stem
            
        if self.system == "windows":
            output_name += ".exe"
        
        compile_cmd = ["gcc", file_path, "-o", output_name]
        
        if optimize:
            compile_cmd.extend(["-O2", "-march=native"])
        
        if debug:
            compile_cmd.extend(["-g", "-DDEBUG"])
        
        compile_cmd.extend(["-std=c11", "-Wall", "-Wextra"])
        
        return self.run_compilation(compile_cmd, output_name)
    
    def compile_java(self, file_path, output_name=None):
        """Compila arquivo Java"""
        compile_cmd = ["javac", file_path]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Compilando Java...", total=None)
            
            try:
                result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    class_file = Path(file_path).with_suffix('.class')
                    return True, f"Compilado com sucesso: {class_file}", class_file
                else:
                    return False, f"Erro na compilação:\n{result.stderr}", None
                    
            except subprocess.TimeoutExpired:
                return False, "Timeout na compilação", None
            except Exception as e:
                return False, f"Erro: {str(e)}", None
    
    def run_compilation(self, compile_cmd, output_name):
        """Executa o processo de compilação"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task(description="Compilando...", total=100)
            
            try:
                result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Simula progresso
                for i in range(100):
                    progress.update(task, advance=1)
                
                if result.returncode == 0:
                    # Verifica se o executável foi criado
                    if Path(output_name).exists():
                        file_size = Path(output_name).stat().st_size
                        return True, f"Compilado com sucesso: {output_name} ({file_size} bytes)", output_name
                    else:
                        return False, "Compilação aparentemente bem-sucedida, mas executável não encontrado", None
                else:
                    return False, f"Erro na compilação:\n{result.stderr}", None
                    
            except subprocess.TimeoutExpired:
                return False, "Timeout na compilação", None
            except Exception as e:
                return False, f"Erro: {str(e)}", None
    
    def create_executable_wrapper(self, java_class_path):
        """Cria um wrapper executável para Java"""
        if self.system == "windows":
            wrapper_content = f'''@echo off
java -cp . {java_class_path}
pause
'''
            wrapper_name = f"run_{java_class_path}.bat"
        else:
            wrapper_content = f'''#!/bin/bash
java -cp . {java_class_path}
'''
            wrapper_name = f"run_{java_class_path}.sh"
            # Torna executável
            Path(wrapper_name).write_text(wrapper_content)
            os.chmod(wrapper_name, 0o755)
            return wrapper_name
        
        Path(wrapper_name).write_text(wrapper_content)
        return wrapper_name
    
    def clean_project(self):
        """Limpa arquivos de compilação"""
        patterns = ["*.exe", "*.class", "*.o", "*.out", "run_*", "*.bat", "*.sh"]
        cleaned = []
        
        for pattern in patterns:
            for file in Path('.').glob(pattern):
                try:
                    file.unlink()
                    cleaned.append(file.name)
                except:
                    pass
        
        return cleaned

class CompilerInterface:
    def __init__(self):
        self.compiler = UniversalCompiler()
        self.show_banner()
    
    def show_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                   🛠️ COMPILADOR UNIVERSAL 🛠️                 ║
║                 C++ • C • Java • Executáveis                ║
╚══════════════════════════════════════════════════════════════╝
"""
        console.print(Panel(banner, style="bold blue"))
    
    def show_status(self):
        """Mostra status dos compiladores disponíveis"""
        table = Table(title="🛠️ Compiladores Disponíveis", show_header=True)
        table.add_column("Linguagem", style="cyan")
        table.add_column("Compilador", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Descrição", style="white")
        
        for lang, info in self.compiler.supported_languages.items():
            status = "✅ Disponível" if lang in self.compiler.available_compilers else "❌ Não encontrado"
            table.add_row(
                lang.upper(),
                info['compiler'],
                status,
                info['description']
            )
        
        console.print(table)
        console.print()
    
    def select_file(self):
        """Interface para seleção de arquivo"""
        current_dir = Path('.')
        source_files = []
        
        # Encontra todos os arquivos fonte suportados
        for lang_info in self.compiler.supported_languages.values():
            for ext in lang_info['extensions']:
                source_files.extend(list(current_dir.glob(f"*{ext}")))
        
        if not source_files:
            console.print("[red]❌ Nenhum arquivo fonte encontrado no diretório atual.[/red]")
            console.print("\nExtensões suportadas:")
            for lang, info in self.compiler.supported_languages.items():
                console.print(f"  [cyan]{lang.upper()}:[/cyan] {', '.join(info['extensions'])}")
            return None
        
        # Mostra arquivos disponíveis
        table = Table(title="📁 Arquivos Fonte Encontrados", show_header=True)
        table.add_column("#", style="cyan", width=5)
        table.add_column("Arquivo", style="green")
        table.add_column("Tipo", style="yellow")
        table.add_column("Tamanho", style="white")
        
        for i, file in enumerate(source_files, 1):
            file_type = self.compiler.detect_language(file).upper()
            size = file.stat().st_size
            table.add_row(str(i), file.name, file_type, f"{size} bytes")
        
        console.print(table)
        
        try:
            choice = Prompt.ask(
                "\n🎯 Selecione o arquivo para compilar",
                choices=[str(i) for i in range(1, len(source_files) + 1)],
                default="1"
            )
            return source_files[int(choice) - 1]
        except KeyboardInterrupt:
            return None
    
    def get_compilation_options(self, file_path):
        """Obtém opções de compilação do usuário"""
        lang = self.compiler.detect_language(file_path)
        options = {}
        
        console.print(f"\n[bold]⚙️ Opções de Compilação para {file_path.name}[/bold]")
        
        # Nome do output
        default_name = file_path.stem
        options['output_name'] = Prompt.ask(
            "📝 Nome do executável",
            default=default_name
        )
        
        # Opções específicas por linguagem
        if lang in ['cpp', 'c']:
            options['optimize'] = Confirm.ask("🚀 Otimização agressiva?")
            options['debug'] = Confirm.ask("🐛 Incluir informações de debug?")
        
        return options
    
    def compile_file(self, file_path, options):
        """Executa a compilação"""
        lang = self.compiler.detect_language(file_path)
        
        if lang not in self.compiler.available_compilers:
            console.print(f"[red]❌ Compilador para {lang.upper()} não disponível![/red]")
            return False
        
        console.print(f"\n[bold]🔨 Compilando {file_path.name}...[/bold]")
        
        try:
            if lang == 'cpp':
                success, message, output_file = self.compiler.compile_cpp(
                    str(file_path),
                    options['output_name'],
                    options.get('optimize', False),
                    options.get('debug', False)
                )
            elif lang == 'c':
                success, message, output_file = self.compiler.compile_c(
                    str(file_path),
                    options['output_name'],
                    options.get('optimize', False),
                    options.get('debug', False)
                )
            elif lang == 'java':
                success, message, output_file = self.compiler.compile_java(
                    str(file_path),
                    options['output_name']
                )
                # Cria wrapper executável para Java
                if success and output_file:
                    wrapper = self.compiler.create_executable_wrapper(file_path.stem)
                    message += f"\n📦 Wrapper criado: {wrapper}"
            
            # Mostra resultado
            if success:
                console.print(Panel(f"✅ {message}", style="green", title="Sucesso!"))
                
                # Mostra informações do executável
                if output_file and Path(output_file).exists():
                    exe_path = Path(output_file)
                    console.print(f"📊 [cyan]Tamanho:[/cyan] {exe_path.stat().st_size} bytes")
                    console.print(f"📁 [cyan]Local:[/cyan] {exe_path.absolute()}")
                    
                    # Oferece para executar
                    if Confirm.ask("\n🎯 Executar o programa agora?"):
                        self.run_executable(output_file, lang)
                        
                return True
            else:
                console.print(Panel(f"❌ {message}", style="red", title="Erro"))
                return False
                
        except Exception as e:
            console.print(Panel(f"💥 Erro inesperado: {str(e)}", style="red"))
            return False
    
    def run_executable(self, exec_path, lang):
        """Executa o programa compilado"""
        console.print(f"\n[bold]🚀 Executando {exec_path}...[/bold]")
        
        try:
            if lang == 'java':
                # Para Java, executa a classe
                class_name = Path(exec_path).stem
                subprocess.run(['java', '-cp', '.', class_name])
            else:
                # Para C/C++, executa o binário diretamente
                if self.compiler.system == "windows":
                    subprocess.run([exec_path])
                else:
                    subprocess.run(['./' + exec_path])
                    
        except Exception as e:
            console.print(f"[red]❌ Erro ao executar: {str(e)}[/red]")
    
    def show_quick_compile(self):
        """Modo compilação rápida"""
        current_dir = Path('.')
        
        # Procura por arquivos comuns
        common_patterns = ['main.cpp', 'main.c', 'app.java', 'program.cpp', 'test.java']
        
        for pattern in common_patterns:
            if Path(pattern).exists():
                file_path = Path(pattern)
                lang = self.compiler.detect_language(file_path)
                
                if lang in self.compiler.available_compilers:
                    console.print(f"🔍 [yellow]Arquivo encontrado: {file_path.name}[/yellow]")
                    
                    if Confirm.ask(f"Compilar {file_path.name} com configurações padrão?"):
                        options = {'output_name': file_path.stem}
                        if lang in ['cpp', 'c']:
                            options.update({'optimize': False, 'debug': True})
                        
                        return self.compile_file(file_path, options)
        return False
    
    def cleanup_menu(self):
        """Menu de limpeza"""
        cleaned = self.compiler.clean_project()
        
        if cleaned:
            console.print(Panel(
                "🧹 Arquivos removidos:\n" + "\n".join(f"• {f}" for f in cleaned),
                style="yellow",
                title="Limpeza Concluída"
            ))
        else:
            console.print("[green]✅ Nenhum arquivo de compilação para limpar.[/green]")
    
    def main_menu(self):
        """Menu principal"""
        while True:
            self.show_banner()
            self.show_status()
            
            menu_table = Table(show_header=False, box=None)
            menu_table.add_column("Opção", style="cyan", width=3)
            menu_table.add_column("Descrição", style="white")
            
            menu_table.add_row("1", "📁 Selecionar arquivo para compilar")
            menu_table.add_row("2", "⚡ Compilação rápida (auto-detect)")
            menu_table.add_row("3", "🧹 Limpar arquivos de compilação")
            menu_table.add_row("4", "📊 Informações do sistema")
            menu_table.add_row("0", "🚪 Sair")
            
            console.print(Panel(menu_table, title="📋 Menu Principal"))
            
            choice = Prompt.ask(
                "🎯 Selecione uma opção",
                choices=["1", "2", "3", "4", "0"],
                default="1"
            )
            
            if choice == "1":
                file_path = self.select_file()
                if file_path:
                    options = self.get_compilation_options(file_path)
                    self.compile_file(file_path, options)
                    
            elif choice == "2":
                if not self.show_quick_compile():
                    console.print("[yellow]⚠️ Nenhum arquivo comum encontrado para compilação rápida.[/yellow]")
                    
            elif choice == "3":
                self.cleanup_menu()
                
            elif choice == "4":
                self.show_system_info()
                
            elif choice == "0":
                console.print("[blue]👋 Até logo![/blue]")
                break
            
            if choice != "0":
                Prompt.ask("\n⏎ Pressione Enter para continuar")
    
    def show_system_info(self):
        """Mostra informações do sistema"""
        info_table = Table(title="📊 Informações do Sistema", show_header=False)
        info_table.add_column("Item", style="cyan")
        info_table.add_column("Valor", style="white")
        
        info_table.add_row("Sistema", f"{platform.system()} {platform.release()}")
        info_table.add_row("Arquitetura", self.compiler.arch)
        info_table.add_row("Python", platform.python_version())
        info_table.add_row("Diretório", str(Path('.').absolute()))
        
        console.print(info_table)

def main():
    try:
        compiler_ui = CompilerInterface()
        compiler_ui.main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]❌ Interrompido pelo usuário[/red]")
    except Exception as e:
        console.print(f"\n[red]💥 Erro crítico: {str(e)}[/red]")

if __name__ == "__main__":
    main()
