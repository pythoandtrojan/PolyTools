#!/usr/bin/env python3
import os
import sys
import time
import random
import json
import logging
import subprocess
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style
from logging.handlers import RotatingFileHandler

# Configurações globais
DIRETORIO_SAIDA = os.path.expanduser("~/sqlmap_output")
ALVO_PADRAO = "http://testphp.vulnweb.com"
CONFIG_FILE = os.path.expanduser("~/.sqlmap_interface.conf")
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
LOG_BACKUP_COUNT = 3
API_TIMEOUT = 30  # segundos

class SQLMapInterface:
    def __init__(self):
        self.alvo_atual = ALVO_PADRAO
        self.modo_api = False
        self.tarefa_id = None
        self.api_disponivel = False
        self.cli_disponivel = False
        self.sqlmap_api = None  # Referência para o módulo API
        self._configurar_logging()
        self.carregar_config()
        self.verificar_ambiente()
        
    def _configurar_logging(self):
        """Configura o sistema de logging com rotação"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    'sqlmap_interface.log',
                    maxBytes=MAX_LOG_SIZE,
                    backupCount=LOG_BACKUP_COUNT
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def carregar_config(self):
        """Carrega configurações do arquivo com verificação de segurança"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    if isinstance(config, dict) and 'alvo' in config:
                        self.alvo_atual = config['alvo'][:500]  
        except Exception as e:
            self.logger.error(f"Erro ao carregar config: {str(e)}")
            self.alvo_atual = ALVO_PADRAO

    def salvar_config(self):
        """Salva configurações no arquivo com tratamento de erro"""
        try:
            config = {'alvo': self.alvo_atual[:500]} 
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            return True
        except Exception as e:
            self.logger.error(f"Erro ao salvar config: {str(e)}")
            return False

    def verificar_ambiente(self):
        """Verifica o ambiente de forma mais robusta"""
        # Primeiro verifica se a API está disponível
        self.api_disponivel = self._verificar_api()
        
        # Se API não está disponível, verifica CLI
        self.cli_disponivel = self._verificar_cli()
        
        if not self.api_disponivel and not self.cli_disponivel:
            print(f"{Fore.RED}[ERRO] SQLMap não encontrado!")
            print(f"{Fore.YELLOW}Instale com:")
            print(f"pip install sqlmap-py (para modo API)")
            print(f"ou baixe de https://github.com/sqlmapproject/sqlmap (para modo CLI)")
            return False
        
        # Prioriza o modo API se disponível
        self.modo_api = self.api_disponivel
        return True

    def _verificar_api(self):
        """Verifica se a API está disponível"""
        try:
            # Tenta importar o módulo da API
            import sqlmap
            if hasattr(sqlmap, 'api'):
                self.sqlmap_api = sqlmap.api
                # Testa a funcionalidade básica
                test_task = self.sqlmap_api.new_task()
                if 'taskid' in test_task:
                    self.sqlmap_api.delete_task(test_task['taskid'])
                    return True
        except Exception as e:
            self.logger.warning(f"API SQLMap não disponível: {str(e)}")
        return False

    def _verificar_cli(self):
        """Verifica se o CLI está disponível"""
        try:
            result = subprocess.run(
                ["sqlmap", "--version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def mostrar_banner(self):
        """Exibe banner com verificação de tamanho"""
        try:
            banners = [
                f"""{Fore.GREEN}
  ██████╗ ███████╗██╗     ███╗   ███╗ █████╗ ██████╗ 
  ██╔══██╗██╔════╝██║     ████╗ ████║██╔══██╗██╔══██╗
  ██████╔╝███████╗██║     ██╔████╔██║███████║██████╔╝
  ██╔═══╝ ╚════██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝ 
  ██║     ███████║███████╗██║ ╚═╝ ██║██║  ██║██║     
  ╚═╝     ╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Style.RESET_ALL}""",
                f"""{Fore.BLUE}
   _____ _______       _____ _____  _____  _______       _____   ___  
  / ____|__   __|/\   |  __ \_   _|/ ____|/ ____\ \    / /__ \ / _ \ 
 | (___    | |  /  \  | |__) || | | |  __| |     \ \  / /   ) | | | |
  \___ \   | | / /\ \ |  ___/ | | | | |_ | |      \ \/ /   / /| | | |
  ____) |  | |/ ____ \| |    _| |_| |__| | |____   \  /   / /_| |_| |
 |_____/   |_/_/    \_\_|   |_____|\_____|\_____|   \/   |____|\___/ 
{Style.RESET_ALL}"""
            ]
            print(random.choice(banners))
            print(f"{Fore.CYAN}[*] Modo: {'API' if self.modo_api else 'CLI'} | Alvo: {self.alvo_atual[:100]}\n")
        except Exception as e:
            self.logger.error(f"Erro ao mostrar banner: {str(e)}")

    def iniciar_sessao(self):
        """Inicia nova sessão com verificação de estado"""
        if not self.modo_api:
            return True
            
        try:
            # Encerra sessão existente
            if self.tarefa_id:
                self._encerrar_sessao()
                
            # Tenta iniciar nova sessão com timeout
            start_time = time.time()
            while time.time() - start_time < API_TIMEOUT:
                try:
                    nova_tarefa = self.sqlmap_api.new_task()
                    if 'taskid' in nova_tarefa:
                        self.tarefa_id = nova_tarefa['taskid']
                        self.logger.info(f"Nova sessão iniciada - TaskID: {self.tarefa_id}")
                        return True
                except Exception as e:
                    self.logger.warning(f"Tentativa de conexão com API falhou: {str(e)}")
                    time.sleep(2)
            
            self.logger.error("Timeout ao iniciar sessão com API")
            return False
            
        except Exception as e:
            self.logger.error(f"Erro crítico ao iniciar sessão: {str(e)}")
            self.tarefa_id = None
            return False

    def _encerrar_sessao(self):
        """Encerra sessão de forma segura"""
        if self.modo_api and self.tarefa_id and self.sqlmap_api:
            try:
                self.sqlmap_api.delete_task(self.tarefa_id)
                self.logger.info(f"Sessão encerrada - TaskID: {self.tarefa_id}")
            except Exception as e:
                self.logger.error(f"Erro ao encerrar sessão: {str(e)}")
            finally:
                self.tarefa_id = None

    def validar_url(self, url):
        """Validação robusta de URL"""
        if not url or len(url) > 500:
            return False
            
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
                
            # Verifica esquema válido
            if result.scheme not in ('http', 'https'):
                return False
                
            # Verifica domínio básico
            if not '.' in result.netloc:
                return False
                
            return True
        except:
            return False

    def executar_via_api(self, comando):
        """Execução com API com tratamento completo"""
        if not self._verificar_sessao_valida():
            return False
            
        try:
            # Converte o comando para opções da API
            options = self._converter_comando_para_opcoes(comando)
            if not options:
                return False
                
            # Inicia a tarefa
            start_time = time.time()
            self.sqlmap_api.start_task(self.tarefa_id, options)
            
            # Monitora o progresso
            while time.time() - start_time < API_TIMEOUT:
                status = self.sqlmap_api.get_task_status(self.tarefa_id).get("status")
                if status == "terminated":
                    break
                time.sleep(2)
            else:
                raise TimeoutError("Timeout ao aguardar término da tarefa")
      
            return self._processar_resultados()
            
        except TimeoutError as te:
            self.logger.error(f"Timeout na execução: {str(te)}")
            return False
        except Exception as e:
            self.logger.error(f"Erro na API: {str(e)}")
            return False

    def _verificar_sessao_valida(self):
        """Verifica se a sessão API é válida"""
        if not self.modo_api or not self.tarefa_id or not self.sqlmap_api:
            return False
            
        try:
            status = self.sqlmap_api.get_task_status(self.tarefa_id)
            return status.get("status") != "not found"
        except:
            return False

    def _converter_comando_para_opcoes(self, comando):
        """Converte comandos CLI para opções da API"""
        try:
            options = {"url": self.alvo_atual, "batch": True}
            
            # Técnicas de injeção
            if "--technique" in comando:
                tech_index = comando.index("--technique")
                if tech_index + 1 < len(comando):
                    options["technique"] = comando[tech_index + 1]
            
            # Nível de risco
            if "--risk" in comando:
                risk_index = comando.index("--risk")
                if risk_index + 1 < len(comando):
                    options["risk"] = comando[risk_index + 1]
            
            return options
        except Exception as e:
            self.logger.error(f"Erro na conversão de comando: {str(e)}")
            return None

    def _processar_resultados(self):
        """Processa resultados da API de forma segura"""
        try:
            data = self.sqlmap_api.get_task_data(self.tarefa_id).get("data", [])
            if not data:
                print(f"{Fore.YELLOW}[!] Nenhum dado retornado")
                return False
                
            print(f"\n{Fore.GREEN}[+] Resultados:")
            for item in data[:50]:  # Limita a exibição
                if isinstance(item, str):
                    print(f" - {item[:500]}")  # Limita o tamanho
                else:
                    print(f" - {str(item)[:500]}")
                    
            return True
        except Exception as e:
            self.logger.error(f"Erro ao processar resultados: {str(e)}")
            return False

    def executar_via_cli(self, comando):
        """Execução CLI com tratamento completo"""
        try:
            # Verifica comandos perigosos
            if any(cmd in ' '.join(comando) for cmd in [";", "&&", "||", "`"]):
                raise ValueError("Comando potencialmente perigoso detectado")
                
            # Executa o processo
            processo = subprocess.Popen(
                comando,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Monitora com timeout
            start_time = time.time()
            while processo.poll() is None:
                if time.time() - start_time > API_TIMEOUT:
                    processo.terminate()
                    raise TimeoutError("Timeout ao executar comando")
                time.sleep(1)
                
            # Captura saída
            saida, erro = processo.communicate()
            
            if saida:
                print(saida[:10000])  # Limita a saída
                
            if erro:
                print(f"{Fore.RED}[!] Erros encontrados:")
                print(erro[:1000]) 
                
            return processo.returncode == 0
            
        except TimeoutError as te:
            self.logger.error(f"Timeout na execução CLI: {str(te)}")
            return False
        except Exception as e:
            self.logger.error(f"Erro na execução CLI: {str(e)}")
            return False

    def definir_novo_alvo(self):
        """Define novo alvo com validação"""
        print(f"\n{Fore.CYAN}[*] Alvo atual: {self.alvo_atual}")
        
        try:
            novo_alvo = input(f"{Fore.YELLOW}[?] Novo URL alvo: ").strip()
            if not novo_alvo:
                return False
                
            # Verifica tamanho
            if len(novo_alvo) > 500:
                print(f"{Fore.RED}[!] URL muito longa (máx. 500 caracteres)")
                return False
                
            # Adiciona esquema se necessário
            if not novo_alvo.startswith(('http://', 'https://')):
                novo_alvo = f"http://{novo_alvo}"
                
            # Valida URL
            if not self.validar_url(novo_alvo):
                print(f"{Fore.RED}[!] URL inválida!")
                return False
                
            # Verifica acessibilidade opcional
            if input(f"{Fore.YELLOW}[?] Verificar acessibilidade? (s/N): ").lower() == 's':
                if not self._verificar_url_acessivel(novo_alvo):
                    print(f"{Fore.RED}[!] URL não acessível!")
                    return False
                    
            # Atualiza alvo
            self.alvo_atual = novo_alvo
            self.salvar_config()
            self.iniciar_sessao()
            print(f"{Fore.GREEN}[+] Alvo atualizado para: {novo_alvo}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao definir novo alvo: {str(e)}")
            return False

    def _verificar_url_acessivel(self, url):
        """Verifica se a URL está acessível"""
        try:
            # Usa curl para verificar
            result = subprocess.run(
                ["curl", "-Is", "--connect-timeout", "5", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except:
            return False

    def limpar_sessao(self):
        """Limpeza segura da sessão"""
        try:
            self._encerrar_sessao()
            print(f"{Fore.GREEN}[+] Sessão limpa com sucesso")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao limpar sessão: {str(e)}")
            return False

    def mostrar_menu(self):
        """Exibe o menu de opções"""
        menu = f"""
{Fore.CYAN}Menu Principal:
{Fore.YELLOW}[1]{Style.RESET_ALL} Varredura básica
{Fore.YELLOW}[2]{Style.RESET_ALL} Detecção de vulnerabilidades
{Fore.YELLOW}[3]{Style.RESET_ALL} Extrair informações do banco
{Fore.YELLOW}[4]{Style.RESET_ALL} Teste de injeção avançado
{Fore.YELLOW}[5]{Style.RESET_ALL} Teste de WAF bypass

{Fore.YELLOW}[N]{Style.RESET_ALL} Definir novo alvo
{Fore.YELLOW}[S]{Style.RESET_ALL} Salvar configuração
{Fore.YELLOW}[L]{Style.RESET_ALL} Limpar sessão
{Fore.YELLOW}[T]{Style.RESET_ALL} Alterar tema
{Fore.YELLOW}[X]{Style.RESET_ALL} Sair
"""
        print(menu)

    def executar_comando(self, opcao):
        """Executa o comando selecionado"""
        try:
            if self.modo_api:
                return self._executar_comando_api(opcao)
            else:
                return self._executar_comando_cli(opcao)
        except Exception as e:
            self.logger.error(f"Erro ao executar comando: {str(e)}")
            return False

    def _executar_comando_api(self, opcao):
        """Executa comando no modo API"""
        comandos = {
            1: ["--batch", "--crawl=2"],
            2: ["--batch", "--risk=3", "--level=5"],
            3: ["--batch", "--dbs"],
            4: ["--batch", "--technique=BEUST"],
            5: ["--batch", "--tamper=between,randomcase"]
        }
        
        if opcao not in comandos:
            print(f"{Fore.RED}[!] Opção inválida!")
            return False
            
        return self.executar_via_api(comandos[opcao])

    def _executar_comando_cli(self, opcao):
        """Executa comando no modo CLI"""
        base_cmd = ["sqlmap", "-u", self.alvo_atual, "--batch"]
        
        comandos = {
            1: base_cmd + ["--crawl=2"],
            2: base_cmd + ["--risk=3", "--level=5"],
            3: base_cmd + ["--dbs"],
            4: base_cmd + ["--technique=BEUST"],
            5: base_cmd + ["--tamper=between,randomcase"]
        }
        
        if opcao not in comandos:
            print(f"{Fore.RED}[!] Opção inválida!")
            return False
            
        return self.executar_via_cli(comandos[opcao])

    def main(self):
        """Loop principal com tratamento de erro completo"""
        try:
            if not self.verificar_ambiente():
                sys.exit(1)
                
            if not self.iniciar_sessao():
                print(f"{Fore.RED}[!] Falha ao iniciar sessão")
                sys.exit(1)
                
            while True:
                try:
                    self.mostrar_banner()
                    self.mostrar_menu()
                    
                    escolha = input(f"\n{Fore.YELLOW}[?] Selecione uma opção: ").strip().upper()
                    
                    # Opções do menu
                    if escolha == 'X':
                        print(f"\n{Fore.CYAN}[*] Saindo...")
                        self.limpar_sessao()
                        sys.exit(0)
                    
                    elif escolha == 'N':
                        self.definir_novo_alvo()
                    
                    elif escolha == 'S':
                        if self.salvar_config():
                            print(f"{Fore.GREEN}[+] Configuração salva!")
                    
                    elif escolha == 'L':
                        if input(f"{Fore.RED}[?] Confirmar limpeza? (s/N): ").upper() == 'S':
                            self.limpar_sessao()
                            self.iniciar_sessao()
                    
                    elif escolha == 'T':
                        print(f"\n{Fore.CYAN}Temas disponíveis: 1. Padrão 2. Escuro")
                        tema = input(f"{Fore.YELLOW}[?] Escolha o tema: ")
                        print(f"{Fore.GREEN}[+] Tema alterado!")
                    
                    # Opções numéricas
                    elif escolha.isdigit():
                        opcao = int(escolha)
                        if 1 <= opcao <= 5:
                            if self.executar_comando(opcao):
                                input(f"\n{Fore.YELLOW}[*] Pressione Enter para continuar...")
                        else:
                            print(f"{Fore.RED}[!] Opção inválida!")
                    
                    else:
                        print(f"{Fore.RED}[!] Opção inválida!")
                    
                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] Operação cancelada")
                    self.limpar_sessao()
                    sys.exit(1)
                except Exception as e:
                    self.logger.error(f"Erro no loop principal: {str(e)}", exc_info=True)
                    print(f"{Fore.RED}[!] Erro: {str(e)}")
                    time.sleep(2)
                    
        except Exception as e:
            self.logger.critical(f"Erro crítico: {str(e)}", exc_info=True)
            print(f"{Fore.RED}[ERRO CRÍTICO] {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    init(autoreset=True)
    interface = SQLMapInterface()
    interface.main()
