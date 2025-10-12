import requests
import json
import os
from datetime import datetime
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

def limpar_tela():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_banner():
    """Exibe o banner colorido"""
    print(Fore.CYAN + "=" * 70)
    print(Fore.YELLOW + "🏢 SISTEMA DE INFORMAÇÕES FINANCEIRAS - SEC EDGAR")
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + "📊 Dados da U.S. Securities and Exchange Commission")
    print(Fore.CYAN + "=" * 70)
    print()

def buscar_dados_empresa(cik):
    """Faz a busca na API da SEC"""
    # Formatar CIK com zeros à esquerda
    cik_formatado = str(cik).zfill(10)
    url = f"https://data.sec.gov/submissions/CIK{cik_formatado}.json"
    
    headers = {
        'User-Agent': 'SistemaFinanceiro/1.0 contact@empresa.com',
        'Accept': 'application/json'
    }
    
    try:
        print(Fore.YELLOW + f"🔍 Buscando dados para CIK: {cik}")
        print(Fore.CYAN + "⏳ Conectando com a SEC API..." + Style.RESET_ALL)
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        dados = response.json()
        return dados
        
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"❌ Erro na conexão: {e}")
        return None
    except json.JSONDecodeError:
        print(Fore.RED + "❌ Erro ao processar resposta da API")
        return None

def exibir_informacoes_empresa(dados):
    """Exibe informações básicas da empresa"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "🏢 INFORMAÇÕES DA EMPRESA")
    print(Fore.GREEN + "=" * 80)
    
    # Informações básicas
    print(Fore.CYAN + f"📋 CIK: {dados.get('cik', 'N/A')}")
    print(Fore.WHITE + f"🏛️  Nome: {dados.get('name', 'N/A')}")
    print(Fore.CYAN + f"📊 Tipo de Entidade: {dados.get('entityType', 'N/A')}")
    
    # Tickers e exchanges
    tickers = dados.get('tickers', [])
    exchanges = dados.get('exchanges', [])
    print(Fore.GREEN + f"💼 Tickers: {', '.join(tickers) if tickers else 'N/A'}")
    print(Fore.WHITE + f"🏪 Exchanges: {', '.join(exchanges) if exchanges else 'N/A'}")
    
    # Informações SIC
    sic = dados.get('sic', 'N/A')
    sic_desc = dados.get('sicDescription', 'N/A')
    print(Fore.CYAN + f"📈 Código SIC: {sic} - {sic_desc}")
    
    # Categoria e ano fiscal
    print(Fore.WHITE + f"📂 Categoria: {dados.get('category', 'N/A')}")
    print(Fore.CYAN + f"📅 Fim do Ano Fiscal: {dados.get('fiscalYearEnd', 'N/A')}")
    
    # Estado de incorporação
    state_inc = dados.get('stateOfIncorporation', 'N/A')
    state_inc_desc = dados.get('stateOfIncorporationDescription', 'N/A')
    print(Fore.GREEN + f"🗺️  Estado de Incorporação: {state_inc} - {state_inc_desc}")

def exibir_endereco_contato(dados):
    """Exibe endereços e informações de contato"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "📫 ENDEREÇOS E CONTATOS")
    print(Fore.GREEN + "=" * 80)
    
    addresses = dados.get('addresses', {})
    phones = dados.get('phones', {})
    
    # Endereço comercial
    business = addresses.get('business', {})
    if business:
        print(Fore.CYAN + "🏢 Endereço Comercial:")
        print(Fore.WHITE + f"   Rua: {business.get('street1', 'N/A')}")
        if business.get('street2'):
            print(Fore.WHITE + f"   Complemento: {business.get('street2')}")
        print(Fore.WHITE + f"   Cidade: {business.get('city', 'N/A')}")
        print(Fore.WHITE + f"   Estado: {business.get('state', 'N/A')}")
        print(Fore.WHITE + f"   CEP: {business.get('zip', 'N/A')}")
    
    # Endereço postal
    mailing = addresses.get('mailing', {})
    if mailing:
        print(Fore.CYAN + "\n📮 Endereço Postal:")
        print(Fore.WHITE + f"   Rua: {mailing.get('street1', 'N/A')}")
        if mailing.get('street2'):
            print(Fore.WHITE + f"   Complemento: {mailing.get('street2')}")
        print(Fore.WHITE + f"   Cidade: {mailing.get('city', 'N/A')}")
        print(Fore.WHITE + f"   Estado: {mailing.get('state', 'N/A')}")
        print(Fore.WHITE + f"   CEP: {mailing.get('zip', 'N/A')}")
        if mailing.get('phone'):
            print(Fore.WHITE + f"   Telefone: {mailing.get('phone')}")
    
    # Telefones
    if phones:
        print(Fore.CYAN + "\n📞 Contatos:")
        for tipo, numero in phones.items():
            print(Fore.WHITE + f"   {tipo.capitalize()}: {numero}")
    
    # Website
    website = dados.get('website', 'N/A')
    investor_website = dados.get('investorWebsite', 'N/A')
    print(Fore.CYAN + "\n🌐 Websites:")
    print(Fore.WHITE + f"   Corporativo: {website}")
    print(Fore.WHITE + f"   Investidores: {investor_website}")

def exibir_historicos_arquivamentos(dados):
    """Exibe histórico de arquivamentos"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "📈 HISTÓRICO DE ARQUIVAMENTOS")
    print(Fore.GREEN + "=" * 80)
    
    filings = dados.get('filings', {})
    recent = filings.get('recent', {})
    
    if not recent:
        print(Fore.RED + "❌ Nenhum dado de arquivamento disponível")
        return
    
    # Mapeamento de tipos de arquivamento
    tipo_arquivamento = {
        '10-K': 'Relatório Anual',
        '10-Q': 'Relatório Trimestral', 
        '8-K': 'Relatório de Evento Corrente',
        'DEF 14A': 'Proxy Statement',
        '4': 'Declaração de Mudança de Propriedade',
        '3': 'Declaração Inicial de Propriedade',
        'S-1': 'Registro de Oferta'
    }
    
    acessos = recent.get('accessionNumber', [])
    tipos = recent.get('form', [])
    datas = recent.get('filingDate', [])
    arquivos = recent.get('primaryDocument', [])
    
    print(Fore.CYAN + f"📊 Total de arquivamentos recentes: {len(acessos)}")
    print()
    
    # Mostrar últimos 10 arquivamentos
    for i in range(min(10, len(acessos))):
        tipo = tipos[i]
        descricao = tipo_arquivamento.get(tipo, tipo)
        data = datas[i]
        arquivo = arquivos[i]
        
        print(Fore.YELLOW + f"📄 Arquivo {i+1}:")
        print(Fore.WHITE + f"   Tipo: {tipo} - {descricao}")
        print(Fore.CYAN + f"   Data: {data}")
        print(Fore.GREEN + f"   Documento: {arquivo}")
        print(Fore.WHITE + "   ──────────────────────────")

def exibir_executivos_diretores(dados):
    """Exibe informações sobre executivos e diretores"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "👥 EXECUTIVOS E DIRETORES")
    print(Fore.GREEN + "=" * 80)
    
    # Nota: Esta informação pode estar em endpoints diferentes
    # Vamos mostrar informações disponíveis na resposta principal
    
    former_names = dados.get('formerNames', [])
    if former_names:
        print(Fore.CYAN + "📝 Nomes Anteriores da Empresa:")
        for former in former_names:
            nome = former.get('name', 'N/A')
            de = former.get('from', 'N/A')
            ate = former.get('to', 'N/A')
            print(Fore.WHITE + f"   • {nome} ({de} a {ate})")
    
    # Informações sobre transações de insiders
    insider_owner = dados.get('insiderTransactionForOwnerExists', 0)
    insider_issuer = dados.get('insiderTransactionForIssuerExists', 0)
    
    print(Fore.CYAN + "\n💼 Transações de Insiders:")
    print(Fore.WHITE + f"   Transações para Proprietários: {'Sim' if insider_owner else 'Não'}")
    print(Fore.WHITE + f"   Transações para Emissor: {'Sim' if insider_issuer else 'Não'}")

def exibir_descricao_negocios(dados):
    """Exibe descrição dos negócios da empresa"""
    print(Fore.GREEN + "\n" + "=" * 80)
    print(Fore.YELLOW + "💼 DESCRIÇÃO DOS NEGÓCIOS")
    print(Fore.GREEN + "=" * 80)
    
    description = dados.get('description', 'N/A')
    ein = dados.get('ein', 'N/A')
    
    if ein != 'N/A':
        print(Fore.CYAN + f"📊 EIN: {ein}")
    
    print(Fore.WHITE + f"\n📋 Descrição:\n{description}")

def menu_empresas_predefinidas():
    """Menu com empresas predefinidas para busca"""
    empresas = {
        '1': {'nome': 'APPLE INC', 'cik': '0000320193'},
        '2': {'nome': 'MICROSOFT CORP', 'cik': '0000789019'},
        '3': {'nome': 'AMAZON COM INC', 'cik': '0001018724'},
        '4': {'nome': 'ALPHABET INC (GOOGLE)', 'cik': '0001652044'},
        '5': {'nome': 'TESLA INC', 'cik': '0001318605'},
        '6': {'nome': 'META PLATFORMS INC (FACEBOOK)', 'cik': '0001326801'},
        '7': {'nome': 'NETFLIX INC', 'cik': '0001065280'},
        '8': {'nome': 'NIKE INC', 'cik': '0000320187'}
    }
    
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "🏢 EMPRESAS PREDEFINIDAS")
        print(Fore.CYAN + "=" * 50)
        print()
        
        for key, emp in empresas.items():
            print(Fore.GREEN + f"{key}. {emp['nome']}")
        
        print(Fore.CYAN + "9. 🔍 Buscar por CIK personalizado")
        print(Fore.RED + "0. ↩️ Voltar ao menu principal")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma empresa (0-9): ").strip()
        
        if opcao == '0':
            return None
        elif opcao in empresas:
            return empresas[opcao]['cik']
        elif opcao == '9':
            cik_personalizado = input(Fore.GREEN + "🔍 Digite o CIK (apenas números): ").strip()
            if cik_personalizado.isdigit():
                return cik_personalizado
            else:
                print(Fore.RED + "❌ CIK deve conter apenas números!")
                input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def exibir_relatorio_completo(dados):
    """Exibe relatório completo da empresa"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + f"📊 RELATÓRIO COMPLETO - {dados.get('name', 'EMPRESA')}")
    print(Fore.CYAN + "=" * 80)
    
    exibir_informacoes_empresa(dados)
    exibir_endereco_contato(dados)
    exibir_descricao_negocios(dados)
    exibir_historicos_arquivamentos(dados)
    exibir_executivos_diretores(dados)

def menu_principal():
    """Menu principal do sistema"""
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + "📋 MENU PRINCIPAL")
        print(Fore.CYAN + "1. 🏢 Buscar dados de empresa")
        print(Fore.CYAN + "2. ℹ️  Sobre o sistema")
        print(Fore.RED + "3. 🚪 Sair")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-3): ").strip()
        
        if opcao == '1':
            menu_busca_empresa()
        elif opcao == '2':
            menu_sobre()
        elif opcao == '3':
            print(Fore.YELLOW + "\n👋 Obrigado por usar o sistema! Até logo!")
            break
        else:
            print(Fore.RED + "❌ Opção inválida! Tente novamente.")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_busca_empresa():
    """Menu de busca de empresa"""
    cik = menu_empresas_predefinidas()
    
    if not cik:
        return
    
    limpar_tela()
    mostrar_banner()
    
    dados = buscar_dados_empresa(cik)
    
    if not dados:
        print(Fore.RED + "❌ Não foi possível obter os dados da empresa.")
        input(Fore.YELLOW + "📝 Pressione Enter para continuar...")
        return
    
    while True:
        limpar_tela()
        mostrar_banner()
        
        print(Fore.YELLOW + f"🏢 DETALHES DA EMPRESA: {dados.get('name', 'N/A')}")
        print(Fore.CYAN + "=" * 50)
        print()
        
        print(Fore.GREEN + "1. 📊 Informações Básicas")
        print(Fore.GREEN + "2. 📫 Endereços e Contatos")
        print(Fore.GREEN + "3. 📈 Histórico de Arquivamentos")
        print(Fore.GREEN + "4. 👥 Executivos e Diretores")
        print(Fore.GREEN + "5. 💼 Descrição dos Negócios")
        print(Fore.GREEN + "6. 📄 Relatório Completo")
        print(Fore.RED + "7. ↩️ Voltar ao menu anterior")
        print()
        
        opcao = input(Fore.GREEN + "👉 Escolha uma opção (1-7): ").strip()
        
        if opcao == '1':
            limpar_tela()
            mostrar_banner()
            exibir_informacoes_empresa(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '2':
            limpar_tela()
            mostrar_banner()
            exibir_endereco_contato(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '3':
            limpar_tela()
            mostrar_banner()
            exibir_historicos_arquivamentos(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '4':
            limpar_tela()
            mostrar_banner()
            exibir_executivos_diretores(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '5':
            limpar_tela()
            mostrar_banner()
            exibir_descricao_negocios(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '6':
            exibir_relatorio_completo(dados)
            input(Fore.YELLOW + "\n📝 Pressione Enter para continuar...")
        elif opcao == '7':
            break
        else:
            print(Fore.RED + "❌ Opção inválida!")
            input(Fore.YELLOW + "📝 Pressione Enter para continuar...")

def menu_sobre():
    """Menu sobre o sistema"""
    limpar_tela()
    mostrar_banner()
    
    print(Fore.YELLOW + "ℹ️  SOBRE O SISTEMA")
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + """
📋 DESCRIÇÃO:
   Sistema de informações financeiras baseado na API da SEC EDGAR.
   Fornece dados corporativos, arquivamentos e informações regulatórias.

🏛️  FONTE DOS DADOS:
   U.S. Securities and Exchange Commission (SEC)
   EDGAR Database - Electronic Data Gathering, Analysis, and Retrieval

📊 INFORMAÇÕES OBTIDAS:
   • Dados corporativos básicos
   • Endereços e contatos
   • Histórico de arquivamentos (10-K, 10-Q, 8-K)
   • Informações de executivos
   • Descrição dos negócios

⚙️  TECNOLOGIAS:
   • Python 3
   • SEC EDGAR API
   • Colorama para cores
   • Requests para HTTP

👨‍💻 DESENVOLVIDO PARA:
   Análise financeira e pesquisa corporativa
    """)
    
    print(Fore.CYAN + "=" * 50)
    input(Fore.YELLOW + "📝 Pressione Enter para voltar ao menu principal...")

def main():
    """Função principal"""
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n👋 Programa interrompido pelo usuário. Até logo!")
    except Exception as e:
        print(Fore.RED + f"\n❌ Erro inesperado: {e}")

if __name__ == "__main__":
    main()
