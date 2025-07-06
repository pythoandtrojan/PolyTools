import requests
import json
import os
from datetime import datetime

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def exibir_banner():
    print("""
    ██████╗ ██████╗ ███████╗
    ██╔═══██╗██╔══██╗██╔════╝
    ██║   ██║██████╔╝█████╗  
    ██║   ██║██╔═══╝ ██╔══╝  
    ╚██████╔╝██║     ███████╗
     ╚═════╝ ╚═╝     ╚══════╝
    Consulta de Dados Pessoais
    """)

def formatar_data(data_str):
    try:
        data = datetime.strptime(data_str, "%d/%m/%Y")
        return data.strftime("%d/%m/%Y")
    except:
        return data_str

def exibir_dados(dados):
    print("\n" + "═"*50)
    print("■ DADOS PESSOAIS ■".center(50))
    print("═"*50)
    pessoais = dados['dados_pessoais']
    print(f" Nome: {pessoais['NOME']}")
    print(f" CPF: {pessoais['CPF']}")
    print(f" Data de Nascimento: {formatar_data(pessoais['DT_NASCIMENTO'])}")
    print(f" Idade: {pessoais['idade']} | Signo: {pessoais['signo']}")
    print(f" Nome da Mãe: {pessoais['NOME_MAE']}")
    print(f" E-mail: {pessoais['EMAIL']}")
    print(f" Sexo: {pessoais['SEXO']}")

    print("\n" + "═"*50)
    print("■ ENDEREÇO ■".center(50))
    print("═"*50)
    endereco = dados['endereco']
    print(f" Logradouro: {endereco['LOGRADOURO']}")
    print(f" Bairro: {endereco['BAIRRO']}")
    print(f" Cidade: {endereco['CIDADE']} - {endereco['UF']}")
    print(f" CEP: {endereco['CEP']}")

    print("\n" + "═"*50)
    print("■ DADOS PROFISSIONAIS ■".center(50))
    print("═"*50)
    prof = dados['dados_profissionais']
    print(f" Profissão: {prof['profissao']}")
    print(f" CBO: {prof['CBO']}")
    print(f" Status Receita Federal: {prof['STATUS_RECEITA_FEDERAL']}")

    print("\n" + "═"*50)
    print("■ DADOS FINANCEIROS ■".center(50))
    print("═"*50)
    financeiros = dados['dados_financeiros']
    print(f" Faixa de Renda: {financeiros['FAIXA_RENDA']}")
    print(f" Renda Presumida: R$ {financeiros['RENDA_PRESUMIDA']}")

    print("\n" + "═"*50)
    print("■ CONTATOS ■".center(50))
    print("═"*50)
    contatos = dados['contatos']
    print(" Celulares:")
    for i, cel in enumerate(contatos['celulares'], 1):
        print(f"  {i}. {cel}")
    
    print("\n" + "═"*50)
    print("■ VEÍCULOS ■".center(50))
    print("═"*50)
    veiculos = dados['veiculos']
    print(f" Quantidade de Veículos: {veiculos['QT_VEICULOS']}")
    for i in range(1, veiculos['QT_VEICULOS'] + 1):
        veic = veiculos[f'veiculo{i}']
        print(f" Veículo {i}: {veic['modelo']} ({veic['ano']})")

    print("\n" + "═"*50)
    print(f" Consulta realizada em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("═"*50)

def salvar_dados(dados, cpf):
    nome_arquivo = f"consulta_cpf_{cpf}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)
    print(f"\nDados salvos no arquivo: {nome_arquivo}")

def consultar_cpf(cpf):
    url = f"https://777apisss.vercel.app/cpf/credilink/?query={cpf}&apikey=firminoh7778"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            dados = response.json()
            if dados.get('status') == 'success':
                return dados['data']
            else:
                print("Erro na consulta: CPF não encontrado ou dados indisponíveis.")
                return None
        else:
            print(f"Erro na API: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erro na conexão: {str(e)}")
        return None

def main():
    while True:
        limpar_tela()
        exibir_banner()
        
        print("\nOpções:")
        print("1. Consultar um CPF")
        print("2. Consultar lista de CPFs")
        print("3. Sair")
        
        opcao = input("\nEscolha uma opção: ")
        
        if opcao == '1':
            cpf = input("\nDigite o CPF (apenas números): ").strip()
            if len(cpf) != 11 or not cpf.isdigit():
                print("CPF inválido. Deve conter 11 dígitos numéricos.")
                input("\nPressione Enter para continuar...")
                continue
                
            dados = consultar_cpf(cpf)
            if dados:
                limpar_tela()
                exibir_banner()
                exibir_dados(dados)
                
                salvar = input("\nDeseja salvar os dados? (S/N): ").upper()
                if salvar == 'S':
                    salvar_dados(dados, cpf)
                
                input("\nPressione Enter para continuar...")
                
        elif opcao == '2':
            caminho_lista = input("\nDigite o caminho do arquivo com a lista de CPFs: ").strip()
            try:
                with open(caminho_lista, 'r') as f:
                    cpfs = [linha.strip() for linha in f if linha.strip()]
                
                resultados = []
                for cpf in cpfs:
                    if len(cpf) == 11 and cpf.isdigit():
                        print(f"\nConsultando CPF: {cpf}")
                        dados = consultar_cpf(cpf)
                        if dados:
                            resultados.append({cpf: dados})
                        else:
                            resultados.append({cpf: "Não encontrado"})
                    else:
                        resultados.append({cpf: "Formato inválido"})
                
                limpar_tela()
                exibir_banner()
                print("\nResultados da consulta em lote:")
                for resultado in resultados:
                    for cpf, dados in resultado.items():
                        print(f"\nCPF: {cpf}")
                        if isinstance(dados, dict):
                            print(" Dados encontrados")
                        else:
                            print(f" {dados}")
                
                salvar = input("\nDeseja salvar os resultados? (S/N): ").upper()
                if salvar == 'S':
                    nome_arquivo = f"consulta_lote_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(nome_arquivo, 'w', encoding='utf-8') as f:
                        json.dump(resultados, f, ensure_ascii=False, indent=4)
                    print(f"\nResultados salvos no arquivo: {nome_arquivo}")
                
                input("\nPressione Enter para continuar...")
                
            except Exception as e:
                print(f"Erro ao processar arquivo: {str(e)}")
                input("\nPressione Enter para continuar...")
                
        elif opcao == '3':
            print("\nSaindo do sistema...")
            break
            
        else:
            print("\nOpção inválida. Tente novamente.")
            input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    main()
