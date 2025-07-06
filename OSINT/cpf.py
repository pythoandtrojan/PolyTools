import requests
import json
import os
import re
from datetime import datetime
from colorama import init, Fore, Back, Style
from time import sleep

# Inicializa colorama
init(autoreset=True)

class CPFConsultor:
    def __init__(self):
        self.api_url = "https://777apisss.vercel.app/cpf/credilink/"
        self.api_key = "firminoh7778"
        self.timeout = (10, 30)
        self.delay_entre_consultas = 1

    def limpar_tela(self):
        """Limpa a tela do console de forma compatível com multiplataforma"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def validar_cpf(self, cpf):
        """Valida se o CPF é válido (formato e dígitos verificadores)"""
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) != 11 or cpf == cpf[0] * 11:
            return False
        
        # Cálculo do primeiro dígito verificador
        soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
        digito1 = (11 - (soma % 11)) if (11 - (soma % 11)) < 10 else 0
        
        # Cálculo do segundo dígito verificador
        soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
        digito2 = (11 - (soma % 11)) if (11 - (soma % 11)) < 10 else 0
        
        return cpf[-2:] == f"{digito1}{digito2}"

    def exibir_banner(self):
        """Exibe o banner colorido do sistema"""
        banner = f"""
        {Fore.CYAN}██████╗ ██████╗ ███████╗
        ██╔═══██╗██╔══██╗██╔════╝
        ██║   ██║██████╔╝█████╗  
        ██║   ██║██╔═══╝ ██╔══╝  
        ╚██████╔╝██║     ███████╗
         ╚═════╝ ╚═╝     ╚══════╝
        {Fore.YELLOW}Consulta de Dados Pessoais{Style.RESET_ALL}
        {Fore.GREEN}{'='*60}{Style.RESET_ALL}
        """
        print(banner)

    def formatar_data(self, data_str):
        """Formata a data para o padrão brasileiro"""
        try:
            return datetime.strptime(data_str, "%d/%m/%Y").strftime("%d/%m/%Y")
        except (ValueError, TypeError):
            return data_str or "Não consta"

    def formatar_moeda(self, valor):
        """Formata valores numéricos como moeda brasileira"""
        try:
            valor = float(valor)
            return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        except (ValueError, TypeError):
            return str(valor) if valor else "Não consta"

    def exibir_secao(self, titulo, dados, campos):
        """Exibe uma seção de dados formatada"""
        if not any(dados.values()):
            return False
            
        print(f"\n{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}■ {titulo} ■{Style.RESET_ALL}".center(60))
        print(f"{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
        
        for campo, rotulo in campos.items():
            valor = dados.get(campo)
            if valor or isinstance(valor, (int, float)):
                print(f"{Fore.GREEN} {rotulo}: {Fore.WHITE}{valor}")
        
        return True

    def exibir_dados(self, dados):
        """Exibe os dados formatados de forma inteligente"""
        if not dados or not isinstance(dados, dict):
            print(f"{Fore.RED}\nDados inválidos ou não encontrados.{Style.RESET_ALL}")
            return

        try:
            # Dados Pessoais
            pessoais = dados.get('dados_pessoais', {})
            campos_pessoais = {
                'NOME': 'Nome',
                'CPF': 'CPF',
                'DT_NASCIMENTO': 'Data Nascimento',
                'idade': 'Idade',
                'signo': 'Signo',
                'NOME_MAE': 'Nome da Mãe',
                'EMAIL': 'E-mail',
                'SEXO': 'Sexo'
            }
            self.exibir_secao("DADOS PESSOAIS", pessoais, campos_pessoais)

            # Endereço
            endereco = dados.get('endereco', {})
            campos_endereco = {
                'LOGRADOURO': 'Logradouro',
                'BAIRRO': 'Bairro',
                'CIDADE': 'Cidade',
                'UF': 'UF',
                'CEP': 'CEP'
            }
            self.exibir_secao("ENDEREÇO", endereco, campos_endereco)

            # Dados Profissionais
            prof = dados.get('dados_profissionais', {})
            campos_prof = {
                'profissao': 'Profissão',
                'CBO': 'CBO',
                'STATUS_RECEITA_FEDERAL': 'Status Receita Federal'
            }
            self.exibir_secao("DADOS PROFISSIONAIS", prof, campos_prof)

            # Dados Financeiros
            financeiros = dados.get('dados_financeiros', {})
            if financeiros.get('RENDA_PRESUMIDA'):
                financeiros['RENDA_PRESUMIDA'] = self.formatar_moeda(financeiros['RENDA_PRESUMIDA'])
            campos_fin = {
                'FAIXA_RENDA': 'Faixa de Renda',
                'RENDA_PRESUMIDA': 'Renda Presumida'
            }
            self.exibir_secao("DADOS FINANCEIROS", financeiros, campos_fin)

            # Contatos
            contatos = dados.get('contatos', {})
            celulares = contatos.get('celulares', [])
            if celulares:
                print(f"\n{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}■ CONTATOS ■{Style.RESET_ALL}".center(60))
                print(f"{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
                print(f"{Fore.GREEN} Celulares:{Style.RESET_ALL}")
                for i, cel in enumerate(celulares, 1):
                    print(f"{Fore.WHITE}  {i}. {cel}{Style.RESET_ALL}")

            # Veículos
            veiculos = dados.get('veiculos', {})
            qt_veiculos = veiculos.get('QT_VEICULOS', 0)
            if qt_veiculos > 0:
                print(f"\n{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}■ VEÍCULOS ■{Style.RESET_ALL}".center(60))
                print(f"{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
                print(f"{Fore.GREEN} Quantidade: {Fore.WHITE}{qt_veiculos}{Style.RESET_ALL}")
                for i in range(1, qt_veiculos + 1):
                    veic = veiculos.get(f'veiculo{i}', {})
                    if veic:
                        modelo = veic.get('modelo', 'Modelo não informado')
                        ano = veic.get('ano', 'Ano não informado')
                        print(f"{Fore.GREEN} Veículo {i}: {Fore.WHITE}{modelo} ({ano}){Style.RESET_ALL}")

            # Rodapé
            print(f"\n{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN} Consulta realizada em: {Fore.WHITE}{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}\nErro ao exibir dados: {str(e)}{Style.RESET_ALL}")

    def sanitizar_nome_arquivo(self, nome):
        """Remove caracteres inválidos para nomes de arquivos"""
        return re.sub(r'[\\/*?:"<>|]', "", nome)

    def salvar_dados(self, dados, prefixo="consulta"):
        """Salva os dados em um arquivo JSON"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            nome_arquivo = f"{self.sanitizar_nome_arquivo(prefixo)}_{timestamp}.json"
            
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                json.dump(dados, f, ensure_ascii=False, indent=4)
            
            print(f"{Fore.GREEN}\nDados salvos em: {Fore.CYAN}{nome_arquivo}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}\nErro ao salvar: {str(e)}{Style.RESET_ALL}")
            return False

    def consultar_cpf(self, cpf):
        """Consulta um CPF na API"""
        try:
            url = f"{self.api_url}?query={cpf}&apikey={self.api_key}"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                dados = response.json()
                if dados.get('status') == 'success':
                    return dados.get('data')
                else:
                    print(f"{Fore.YELLOW}\nCPF não encontrado.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}\nErro na API: {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}\nErro na conexão: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}\nErro inesperado: {str(e)}{Style.RESET_ALL}")
        
        return None

    def processar_lista_cpfs(self, caminho_arquivo):
        """Processa uma lista de CPFs de um arquivo"""
        try:
            with open(caminho_arquivo, 'r', encoding='utf-8') as f:
                cpfs = [linha.strip() for linha in f if linha.strip()]
            
            if not cpfs:
                print(f"{Fore.YELLOW}\nArquivo vazio.{Style.RESET_ALL}")
                return None
            
            resultados = []
            total = len(cpfs)
            
            for i, cpf in enumerate(cpfs, 1):
                if not self.validar_cpf(cpf):
                    print(f"{Fore.YELLOW}\n[{i}/{total}] CPF inválido: {cpf}{Style.RESET_ALL}")
                    resultados.append({cpf: "CPF inválido"})
                    continue
                
                print(f"{Fore.CYAN}\n[{i}/{total}] Consultando: {cpf}{Style.RESET_ALL}")
                dados = self.consultar_cpf(cpf)
                
                if dados:
                    resultados.append({cpf: dados})
                    print(f"{Fore.GREEN}  ✓ Dados encontrados{Style.RESET_ALL}")
                else:
                    resultados.append({cpf: "Não encontrado"})
                    print(f"{Fore.YELLOW}  ✗ Sem resultados{Style.RESET_ALL}")
                
                if i < total:
                    sleep(self.delay_entre_consultas)
            
            return resultados
            
        except Exception as e:
            print(f"{Fore.RED}\nErro ao processar arquivo: {str(e)}{Style.RESET_ALL}")
            return None

    def menu_principal(self):
        """Exibe o menu principal"""
        while True:
            self.limpar_tela()
            self.exibir_banner()
            
            print(f"{Fore.WHITE}\nMenu Principal:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1.{Style.RESET_ALL} Consultar CPF individual")
            print(f"{Fore.CYAN}2.{Style.RESET_ALL} Consultar lista de CPFs")
            print(f"{Fore.CYAN}3.{Style.RESET_ALL} Sair")
            
            opcao = input(f"{Fore.YELLOW}\nOpção: {Style.RESET_ALL}").strip()
            
            if opcao == '1':
                self.consultar_individual()
            elif opcao == '2':
                self.consultar_lista()
            elif opcao == '3':
                print(f"{Fore.GREEN}\nEncerrando...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}\nOpção inválida!{Style.RESET_ALL}")
                input(f"{Fore.YELLOW}Pressione Enter...{Style.RESET_ALL}")

    def consultar_individual(self):
        """Fluxo de consulta individual"""
        self.limpar_tela()
        self.exibir_banner()
        
        cpf = input(f"{Fore.YELLOW}\nCPF (somente números): {Style.RESET_ALL}").strip()
        
        if not self.validar_cpf(cpf):
            print(f"{Fore.RED}\nCPF inválido!{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Pressione Enter...{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}\nConsultando...{Style.RESET_ALL}")
        dados = self.consultar_cpf(cpf)
        
        self.limpar_tela()
        self.exibir_banner()
        
        if dados:
            self.exibir_dados(dados)
            
            while True:
                opcao = input(f"{Fore.YELLOW}\nSalvar resultados? (S/N): {Style.RESET_ALL}").upper()
                if opcao == 'S':
                    self.salvar_dados(dados, f"consulta_cpf_{cpf}")
                    break
                elif opcao == 'N':
                    break
                else:
                    print(f"{Fore.RED}Opção inválida!{Style.RESET_ALL}")
        
        input(f"{Fore.YELLOW}\nPressione Enter...{Style.RESET_ALL}")

    def consultar_lista(self):
        """Fluxo de consulta em lote"""
        self.limpar_tela()
        self.exibir_banner()
        
        caminho = input(f"{Fore.YELLOW}\nCaminho do arquivo com CPFs: {Style.RESET_ALL}").strip()
        
        if not os.path.exists(caminho):
            print(f"{Fore.RED}\nArquivo não encontrado!{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Pressione Enter...{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}\nProcessando...{Style.RESET_ALL}")
        resultados = self.processar_lista_cpfs(caminho)
        
        self.limpar_tela()
        self.exibir_banner()
        
        if resultados:
            print(f"{Fore.GREEN}\nResumo dos resultados:{Style.RESET_ALL}")
            for item in resultados:
                for cpf, dados in item.items():
                    status = f"{Fore.GREEN}✓" if isinstance(dados, dict) else f"{Fore.YELLOW}✗"
                    nome = dados.get('dados_pessoais', {}).get('NOME', '') if isinstance(dados, dict) else ''
                    print(f"{status} {Fore.CYAN}{cpf}{Style.RESET_ALL} {nome}")
            
            while True:
                opcao = input(f"{Fore.YELLOW}\nSalvar resultados completos? (S/N): {Style.RESET_ALL}").upper()
                if opcao == 'S':
                    self.salvar_dados(resultados, "consulta_lote_cpfs")
                    break
                elif opcao == 'N':
                    break
                else:
                    print(f"{Fore.RED}Opção inválida!{Style.RESET_ALL}")
        
        input(f"{Fore.YELLOW}\nPressione Enter...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        consultor = CPFConsultor()
        consultor.menu_principal()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperação cancelada pelo usuário.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}\nErro fatal: {str(e)}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.CYAN}\nSistema encerrado.{Style.RESET_ALL}")
