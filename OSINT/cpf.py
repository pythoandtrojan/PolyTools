import requests
import json
import os
import re
from datetime import datetime
from colorama import init, Fore, Back, Style
from time import sleep

# Inicializa colorama
init(autoreset=True)

def limpar_tela():
    """Limpa a tela do console de forma compatível com multiplataforma"""
    os.system('cls' if os.name == 'nt' else 'clear')

def validar_cpf(cpf):
    """Valida se o CPF é válido (formato e dígitos verificadores)"""
    # Remove caracteres não numéricos
    cpf = re.sub(r'[^0-9]', '', cpf)
    
    # Verifica se tem 11 dígitos e não é uma sequência repetida
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    
    # Calcula o primeiro dígito verificador
    soma = 0
    for i in range(9):
        soma += int(cpf[i]) * (10 - i)
    resto = 11 - (soma % 11)
    digito1 = resto if resto < 10 else 0
    
    # Calcula o segundo dígito verificador
    soma = 0
    for i in range(10):
        soma += int(cpf[i]) * (11 - i)
    resto = 11 - (soma % 11)
    digito2 = resto if resto < 10 else 0
    
    # Verifica se os dígitos calculados conferem com os informados
    return cpf[-2:] == f"{digito1}{digito2}"

def exibir_banner():
    """Exibe o banner colorido do sistema"""
    print(Fore.CYAN + """
    ██████╗ ██████╗ ███████╗
    ██╔═══██╗██╔══██╗██╔════╝
    ██║   ██║██████╔╝█████╗  
    ██║   ██║██╔═══╝ ██╔══╝  
    ╚██████╔╝██║     ███████╗
     ╚═════╝ ╚═╝     ╚══════╝
    """ + Fore.YELLOW + "Consulta de Dados Pessoais" + Style.RESET_ALL)
    print(Fore.GREEN + "="*60 + Style.RESET_ALL)

def formatar_data(data_str):
    """Formata a data para o padrão brasileiro"""
    try:
        data = datetime.strptime(data_str, "%d/%m/%Y")
        return data.strftime("%d/%m/%Y")
    except (ValueError, TypeError):
        return data_str

def formatar_moeda(valor):
    """Formata valores numéricos como moeda brasileira"""
    try:
        valor = float(valor)
        return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except (ValueError, TypeError):
        return valor

def exibir_dados(dados):
    """Exibe os dados formatados e coloridos"""
    if not dados:
        print(Fore.RED + "\nNenhum dado encontrado para exibição." + Style.RESET_ALL)
        return
    
    try:
        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ DADOS PESSOAIS ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        pessoais = dados.get('dados_pessoais', {})
        print(Fore.GREEN + f" Nome: " + Fore.WHITE + f"{pessoais.get('NOME', 'Não informado')}")
        print(Fore.GREEN + f" CPF: " + Fore.WHITE + f"{pessoais.get('CPF', 'Não informado')}")
        print(Fore.GREEN + f" Data de Nascimento: " + Fore.WHITE + f"{formatar_data(pessoais.get('DT_NASCIMENTO', 'Não informado'))}")
        print(Fore.GREEN + f" Idade: " + Fore.WHITE + f"{pessoais.get('idade', 'Não informado')}" + 
              Fore.GREEN + " | Signo: " + Fore.WHITE + f"{pessoais.get('signo', 'Não informado')}")
        print(Fore.GREEN + f" Nome da Mãe: " + Fore.WHITE + f"{pessoais.get('NOME_MAE', 'Não informado')}")
        print(Fore.GREEN + f" E-mail: " + Fore.WHITE + f"{pessoais.get('EMAIL', 'Não informado')}")
        print(Fore.GREEN + f" Sexo: " + Fore.WHITE + f"{pessoais.get('SEXO', 'Não informado')}")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ ENDEREÇO ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        endereco = dados.get('endereco', {})
        print(Fore.GREEN + f" Logradouro: " + Fore.WHITE + f"{endereco.get('LOGRADOURO', 'Não informado')}")
        print(Fore.GREEN + f" Bairro: " + Fore.WHITE + f"{endereco.get('BAIRRO', 'Não informado')}")
        print(Fore.GREEN + f" Cidade: " + Fore.WHITE + f"{endereco.get('CIDADE', 'Não informado')} - {endereco.get('UF', 'Não informado')}")
        print(Fore.GREEN + f" CEP: " + Fore.WHITE + f"{endereco.get('CEP', 'Não informado')}")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ DADOS PROFISSIONAIS ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        prof = dados.get('dados_profissionais', {})
        print(Fore.GREEN + f" Profissão: " + Fore.WHITE + f"{prof.get('profissao', 'Não informado')}")
        print(Fore.GREEN + f" CBO: " + Fore.WHITE + f"{prof.get('CBO', 'Não informado')}")
        print(Fore.GREEN + f" Status Receita Federal: " + Fore.WHITE + f"{prof.get('STATUS_RECEITA_FEDERAL', 'Não informado')}")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ DADOS FINANCEIROS ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        financeiros = dados.get('dados_financeiros', {})
        print(Fore.GREEN + f" Faixa de Renda: " + Fore.WHITE + f"{financeiros.get('FAIXA_RENDA', 'Não informado')}")
        print(Fore.GREEN + f" Renda Presumida: " + Fore.WHITE + f"{formatar_moeda(financeiros.get('RENDA_PRESUMIDA', 'Não informado'))}")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ CONTATOS ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        contatos = dados.get('contatos', {})
        celulares = contatos.get('celulares', [])
        print(Fore.GREEN + " Celulares:")
        if celulares:
            for i, cel in enumerate(celulares, 1):
                print(Fore.WHITE + f"  {i}. {cel}")
        else:
            print(Fore.WHITE + "  Nenhum celular cadastrado")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.YELLOW + "■ VEÍCULOS ■".center(60) + Style.RESET_ALL)
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
        
        veiculos = dados.get('veiculos', {})
        qt_veiculos = veiculos.get('QT_VEICULOS', 0)
        print(Fore.GREEN + f" Quantidade de Veículos: " + Fore.WHITE + f"{qt_veiculos}")
        
        if qt_veiculos > 0:
            for i in range(1, qt_veiculos + 1):
                veic = veiculos.get(f'veiculo{i}', {})
                print(Fore.GREEN + f" Veículo {i}: " + Fore.WHITE + 
                      f"{veic.get('modelo', 'Modelo não informado')} ({veic.get('ano', 'Ano não informado')})")

        print("\n" + Fore.BLUE + "═"*60 + Style.RESET_ALL)
        print(Fore.GREEN + f" Consulta realizada em: " + Fore.WHITE + f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(Fore.BLUE + "═"*60 + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"\nErro ao exibir dados: {str(e)}" + Style.RESET_ALL)

def sanitizar_nome_arquivo(nome):
    """Remove caracteres inválidos para nomes de arquivos"""
    return re.sub(r'[\\/*?:"<>|]', "", nome)

def salvar_dados(dados, cpf):
    """Salva os dados em um arquivo JSON com tratamento de erros"""
    try:
        nome_base = sanitizar_nome_arquivo(f"consulta_cpf_{cpf}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        nome_arquivo = f"{nome_base}.json"
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)
        
        print(Fore.GREEN + f"\nDados salvos com sucesso no arquivo: " + Fore.CYAN + f"{nome_arquivo}" + Style.RESET_ALL)
        return True
    except PermissionError:
        print(Fore.RED + "\nErro: Permissão negada para salvar o arquivo." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nErro ao salvar arquivo: {str(e)}" + Style.RESET_ALL)
    return False

def consultar_cpf(cpf):
    """Consulta a API com tratamento robusto de erros"""
    url = f"https://777apisss.vercel.app/cpf/credilink/?query={cpf}&apikey=firminoh7778"
    
    try:
        # Adiciona timeout para a requisição (10 segundos para conexão, 30 para leitura)
        response = requests.get(url, timeout=(10, 30))
        
        if response.status_code == 200:
            dados = response.json()
            
            if dados.get('status') == 'success':
                return dados.get('data')
            else:
                print(Fore.YELLOW + "\nAviso: CPF não encontrado ou dados indisponíveis." + Style.RESET_ALL)
                return None
        else:
            print(Fore.RED + f"\nErro na API: HTTP {response.status_code} - {response.reason}" + Style.RESET_ALL)
            return None
            
    except requests.exceptions.Timeout:
        print(Fore.RED + "\nErro: Tempo de conexão com a API expirado." + Style.RESET_ALL)
    except requests.exceptions.ConnectionError:
        print(Fore.RED + "\nErro: Não foi possível conectar à API. Verifique sua internet." + Style.RESET_ALL)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"\nErro na requisição: {str(e)}" + Style.RESET_ALL)
    except json.JSONDecodeError:
        print(Fore.RED + "\nErro: Resposta inválida da API." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nErro inesperado: {str(e)}" + Style.RESET_ALL)
    
    return None

def consultar_lista_cpfs(caminho_lista):
    """Processa uma lista de CPFs com tratamento de erros"""
    resultados = []
    
    try:
        # Verifica se o arquivo existe
        if not os.path.exists(caminho_lista):
            print(Fore.RED + "\nErro: Arquivo não encontrado." + Style.RESET_ALL)
            return None
        
        # Verifica se é um arquivo (não diretório)
        if not os.path.isfile(caminho_lista):
            print(Fore.RED + "\nErro: O caminho especificado não é um arquivo." + Style.RESET_ALL)
            return None
        
        # Lê o arquivo
        with open(caminho_lista, 'r', encoding='utf-8') as f:
            cpfs = [linha.strip() for linha in f if linha.strip()]
        
        if not cpfs:
            print(Fore.YELLOW + "\nAviso: O arquivo está vazio ou não contém CPFs válidos." + Style.RESET_ALL)
            return None
        
        total_cpfs = len(cpfs)
        print(Fore.GREEN + f"\nIniciando consulta de {total_cpfs} CPF(s)..." + Style.RESET_ALL)
        
        for i, cpf in enumerate(cpfs, 1):
            # Valida o CPF antes de consultar
            if not validar_cpf(cpf):
                print(Fore.YELLOW + f"\n[{i}/{total_cpfs}] CPF inválido: {cpf}" + Style.RESET_ALL)
                resultados.append({cpf: "CPF inválido"})
                continue
            
            print(Fore.CYAN + f"\n[{i}/{total_cpfs}] Consultando CPF: {cpf}" + Style.RESET_ALL)
            
            # Consulta o CPF com delay para evitar rate limiting
            dados = consultar_cpf(cpf)
            
            if dados:
                resultados.append({cpf: dados})
                print(Fore.GREEN + "  ✓ Dados encontrados" + Style.RESET_ALL)
            else:
                resultados.append({cpf: "Não encontrado"})
                print(Fore.YELLOW + "  ✗ Dados não encontrados" + Style.RESET_ALL)
            
            # Delay entre consultas (1 segundo)
            if i < total_cpfs:
                sleep(1)
        
        return resultados
    
    except UnicodeDecodeError:
        print(Fore.RED + "\nErro: O arquivo não está em um formato de texto válido." + Style.RESET_ALL)
    except PermissionError:
        print(Fore.RED + "\nErro: Permissão negada para ler o arquivo." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nErro ao processar arquivo: {str(e)}" + Style.RESET_ALL)
    
    return None

def main():
    """Função principal do programa"""
    while True:
        limpar_tela()
        exibir_banner()
        
        print(Fore.WHITE + "\nOpções disponíveis:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. " + Fore.WHITE + "Consultar um CPF")
        print(Fore.CYAN + "2. " + Fore.WHITE + "Consultar lista de CPFs")
        print(Fore.CYAN + "3. " + Fore.WHITE + "Sair")
        
        opcao = input(Fore.YELLOW + "\nEscolha uma opção (1-3): " + Style.RESET_ALL).strip()
        
        if opcao == '1':
            limpar_tela()
            exibir_banner()
            
            cpf = input(Fore.YELLOW + "\nDigite o CPF (apenas números): " + Style.RESET_ALL).strip()
            
            # Validação robusta do CPF
            if not validar_cpf(cpf):
                print(Fore.RED + "\nCPF inválido. Verifique o número digitado." + Style.RESET_ALL)
                input(Fore.YELLOW + "\nPressione Enter para continuar..." + Style.RESET_ALL)
                continue
            
            print(Fore.GREEN + "\nConsultando CPF..." + Style.RESET_ALL)
            dados = consultar_cpf(cpf)
            
            limpar_tela()
            exibir_banner()
            
            if dados:
                exibir_dados(dados)
                
                while True:
                    salvar = input(Fore.YELLOW + "\nDeseja salvar os dados? (S/N): " + Style.RESET_ALL).upper()
                    
                    if salvar == 'S':
                        if salvar_dados(dados, cpf):
                            break
                    elif salvar == 'N':
                        break
                    else:
                        print(Fore.RED + "Opção inválida. Digite S ou N." + Style.RESET_ALL)
            
            input(Fore.YELLOW + "\nPressione Enter para continuar..." + Style.RESET_ALL)
            
        elif opcao == '2':
            limpar_tela()
            exibir_banner()
            
            caminho_lista = input(Fore.YELLOW + "\nDigite o caminho do arquivo com a lista de CPFs: " + Style.RESET_ALL).strip()
            
            resultados = consultar_lista_cpfs(caminho_lista)
            
            if resultados:
                limpar_tela()
                exibir_banner()
                
                print(Fore.GREEN + "\nResultados da consulta em lote:" + Style.RESET_ALL)
                
                for resultado in resultados:
                    for cpf, dados in resultado.items():
                        print(Fore.CYAN + f"\nCPF: {cpf}" + Style.RESET_ALL)
                        
                        if isinstance(dados, dict):
                            print(Fore.GREEN + " ✓ Dados encontrados:" + Style.RESET_ALL)
                            # Exibe apenas um resumo para listas grandes
                            print(Fore.WHITE + f"  Nome: {dados.get('dados_pessoais', {}).get('NOME', 'Não informado')}")
                            print(f"  Cidade: {dados.get('endereco', {}).get('CIDADE', 'Não informado')}")
                        else:
                            print(Fore.YELLOW + f" {dados}" + Style.RESET_ALL)
                
                while True:
                    salvar = input(Fore.YELLOW + "\nDeseja salvar os resultados completos? (S/N): " + Style.RESET_ALL).upper()
                    
                    if salvar == 'S':
                        nome_base = sanitizar_nome_arquivo(f"consulta_lote_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                        nome_arquivo = f"{nome_base}.json"
                        
                        try:
                            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                                json.dump(resultados, f, ensure_ascii=False, indent=4)
                            
                            print(Fore.GREEN + f"\nResultados salvos com sucesso no arquivo: " + 
                                  Fore.CYAN + f"{nome_arquivo}" + Style.RESET_ALL)
                            break
                        except Exception as e:
                            print(Fore.RED + f"\nErro ao salvar arquivo: {str(e)}" + Style.RESET_ALL)
                    elif salvar == 'N':
                        break
                    else:
                        print(Fore.RED + "Opção inválida. Digite S ou N." + Style.RESET_ALL)
            
            input(Fore.YELLOW + "\nPressione Enter para continuar..." + Style.RESET_ALL)
            
        elif opcao == '3':
            print(Fore.GREEN + "\nSaindo do sistema..." + Style.RESET_ALL)
            break
            
        else:
            print(Fore.RED + "\nOpção inválida. Por favor, escolha uma opção de 1 a 3." + Style.RESET_ALL)
            input(Fore.YELLOW + "\nPressione Enter para continuar..." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nOperação cancelada pelo usuário." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nErro fatal: {str(e)}" + Style.RESET_ALL)
    finally:
        print(Fore.CYAN + "\nPrograma encerrado." + Style.RESET_ALL)
