import requests
import json
from colorama import Fore, Style, init
import os
import webbrowser
from urllib.parse import quote

# Inicializar colorama
init(autoreset=True)

class DataGovExplorer:
    def __init__(self):
        self.base_url = "https://catalog.data.gov/api/3/action/package_search"
        self.categories = {
            "climate": "Mudanças climáticas e meio ambiente",
            "economy": "Economia e finanças",
            "health": "Saúde pública",
            "education": "Educação",
            "transportation": "Transportes",
            "energy": "Energia",
            "employment": "Emprego e trabalho",
            "housing": "Habitação e urbanismo",
            "public_safety": "Segurança pública",
            "technology": "Tecnologia e inovação",
            "agriculture": "Agricultura",
            "finance": "Finanças e bancos"
        }
        
    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Exibe o banner"""
        banner = f"""
{Fore.GREEN}
 ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ███╗   ██╗ ██████╗       ███████╗██╗   ██╗ █████╗ 
██╔════╝ ██╔═══██╗██║   ██║██╔════╝██╔══██╗████╗  ██║██╔═══██╗      ██╔════╝██║   ██║██╔══██╗
██║  ███╗██║   ██║██║   ██║█████╗  ██████╔╝██╔██╗ ██║██║   ██║█████╗█████╗  ██║   ██║███████║
██║   ██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚════╝██╔══╝  ██║   ██║██╔══██║
╚██████╔╝╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║ ╚████║╚██████╔╝      ███████╗╚██████╔╝██║  ██║
 ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝       ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                                                             
                  EXPLORADOR DE DADOS GOVERNAMENTAIS             
                        Data.gov API v3                         
   
{Fore.CYAN}
    Acesso a mais de 200.000 conjuntos de dados governamentais
{Style.RESET_ALL}
        """
        print(banner)
    
    def wait_enter(self):
        """Aguarda Enter para continuar"""
        input(f"\n{Fore.YELLOW}[!] Pressione Enter para continuar...{Style.RESET_ALL}")
    
    def make_api_request(self, query, rows=20, start=0):
        """Faz requisição para a API do Data.gov"""
        try:
            params = {
                'q': query,
                'rows': rows,
                'start': start
            }
            
            print(f"{Fore.CYAN}[*] Buscando: '{query}'...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] URL da API: {self.base_url}?q={quote(query)}&rows={rows}{Style.RESET_ALL}")
            
            response = requests.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Erro na requisição: {e}{Style.RESET_ALL}")
            return None
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}[!] Erro ao decodificar JSON: {e}{Style.RESET_ALL}")
            return None
    
    def display_categories(self):
        """Exibe categorias disponíveis"""
        print(f"\n{Fore.GREEN}📊 CATEGORIAS DISPONÍVEIS:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┌{'─' * 40}┐{Style.RESET_ALL}")
        
        for i, (key, value) in enumerate(self.categories.items(), 1):
            print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.YELLOW}{i:2d}.{Style.RESET_ALL} {value:<35} {Fore.CYAN}│{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}└{'─' * 40}┘{Style.RESET_ALL}")
    
    def search_by_category(self, category_key):
        """Busca dados por categoria"""
        category_name = self.categories.get(category_key, category_key)
        print(f"\n{Fore.GREEN}🔍 BUSCANDO NA CATEGORIA: {category_name.upper()}{Style.RESET_ALL}")
        
        result = self.make_api_request(category_key, rows=15)
        if result and result.get('success'):
            self.display_results(result, f"Categoria: {category_name}")
        else:
            print(f"{Fore.RED}[!] Nenhum resultado encontrado.{Style.RESET_ALL}")
    
    def custom_search(self):
        """Busca personalizada"""
        self.clear_screen()
        self.display_banner()
        
        print(f"\n{Fore.GREEN}🎯 BUSCA PERSONALIZADA{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Você pode buscar por:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Tópicos específicos (ex: 'public employees', 'climate change'){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Nomes de agências (ex: 'NASA', 'EPA'){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Tipos de dados (ex: 'budget', 'salaries'){Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Localizações (ex: 'California', 'New York'){Style.RESET_ALL}")
        
        query = input(f"\n{Fore.CYAN}[?] Digite sua busca: {Style.RESET_ALL}").strip()
        
        if query:
            result = self.make_api_request(query, rows=20)
            if result and result.get('success'):
                self.display_results(result, f"Busca: '{query}'")
            else:
                print(f"{Fore.RED}[!] Nenhum resultado encontrado para '{query}'.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Digite um termo para buscar.{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def display_results(self, data, search_title):
        """Exibe os resultados da busca"""
        if not data or not data.get('success'):
            print(f"{Fore.RED}[!] Dados inválidos retornados pela API.{Style.RESET_ALL}")
            return
        
        result = data['result']
        count = result.get('count', 0)
        results = result.get('results', [])
        
        print(f"\n{Fore.GREEN}📈 RESULTADOS DA BUSCA: {search_title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Total de conjuntos de dados encontrados: {count}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📄 Mostrando: {len(results)} resultados{Style.RESET_ALL}")
        print(f"{Fore.GREEN}┌{'─' * 80}┐{Style.RESET_ALL}")
        
        for i, dataset in enumerate(results, 1):
            title = dataset.get('title', 'Sem título')
            org = dataset.get('organization', {}).get('title', 'N/A')
            metadata_created = dataset.get('metadata_created', '')[:10]
            resources_count = len(dataset.get('resources', []))
            
            print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}{i:2d}.{Style.RESET_ALL} {title[:70]}...")
            print(f"{Fore.GREEN}│{Style.RESET_ALL}    {Fore.CYAN}🏢 {org}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}│{Style.RESET_ALL}    {Fore.CYAN}📅 {metadata_created} | 📁 {resources_count} recursos{Style.RESET_ALL}")
            
            # Mostrar tags
            tags = [tag['display_name'] for tag in dataset.get('tags', [])[:5]]
            if tags:
                print(f"{Fore.GREEN}│{Style.RESET_ALL}    {Fore.CYAN}🏷️  {', '.join(tags)}{Style.RESET_ALL}")
            
            if i < len(results):
                print(f"{Fore.GREEN}│{Style.RESET_ALL}    {Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}└{'─' * 80}┘{Style.RESET_ALL}")
        
        # Opção para ver detalhes
        if results:
            self.show_dataset_details(results)
    
    def show_dataset_details(self, datasets):
        """Mostra detalhes de um dataset específico"""
        try:
            choice = input(f"\n{Fore.CYAN}[?] Ver detalhes de um dataset (número) ou Enter para voltar: {Style.RESET_ALL}").strip()
            if choice and choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(datasets):
                    self.display_dataset_full(datasets[idx])
        except ValueError:
            pass
    
    def display_dataset_full(self, dataset):
        """Exibe todos os dados de um dataset em JSON formatado"""
        self.clear_screen()
        self.display_banner()
        
        print(f"\n{Fore.GREEN}📋 DETALHES COMPLETOS DO DATASET{Style.RESET_ALL}")
        print(f"{Fore.GREEN}┌{'─' * 80}┐{Style.RESET_ALL}")
        
        # Informações principais
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}📖 TÍTULO:{Style.RESET_ALL} {dataset.get('title', 'N/A')}")
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}🏢 ORGANIZAÇÃO:{Style.RESET_ALL} {dataset.get('organization', {}).get('title', 'N/A')}")
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}📅 CRIADO EM:{Style.RESET_ALL} {dataset.get('metadata_created', 'N/A')}")
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}🔄 ATUALIZADO EM:{Style.RESET_ALL} {dataset.get('metadata_modified', 'N/A')}")
        
        # Descrição
        notes = dataset.get('notes', 'Sem descrição')
        if len(notes) > 200:
            notes = notes[:200] + "..."
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}📝 DESCRIÇÃO:{Style.RESET_ALL} {notes}")
        
        # Tags
        tags = [tag['display_name'] for tag in dataset.get('tags', [])]
        if tags:
            print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}🏷️  TAGS:{Style.RESET_ALL} {', '.join(tags)}")
        
        # Recursos (arquivos)
        resources = dataset.get('resources', [])
        print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.YELLOW}📁 RECURSOS ({len(resources)}):{Style.RESET_ALL}")
        
        for i, resource in enumerate(resources, 1):
            name = resource.get('name', resource.get('url', 'Recurso sem nome'))
            fmt = resource.get('format', 'N/A').upper()
            print(f"{Fore.GREEN}│{Style.RESET_ALL}    {Fore.CYAN}{i}. {name[:50]} [{fmt}]{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}└{'─' * 80}┘{Style.RESET_ALL}")
        
        # Mostrar JSON completo se solicitado
        show_json = input(f"\n{Fore.CYAN}[?] Mostrar dados completos em JSON? (s/N): {Style.RESET_ALL}").lower()
        if show_json == 's':
            print(f"\n{Fore.GREEN}📄 DADOS COMPLETOS EM JSON:{Style.RESET_ALL}")
            print(json.dumps(dataset, indent=2, ensure_ascii=False))
        
        # Opção para abrir no navegador
        open_browser = input(f"\n{Fore.CYAN}[?] Abrir no Data.gov? (s/N): {Style.RESET_ALL}").lower()
        if open_browser == 's':
            webbrowser.open(f"https://catalog.data.gov/dataset/{dataset.get('name', '')}")
        
        self.wait_enter()
    
    def popular_searches(self):
        """Buscas populares pré-definidas"""
        searches = {
            "1": {"query": "public employees", "name": "Funcionários Públicos"},
            "2": {"query": "federal budget", "name": "Orçamento Federal"},
            "3": {"query": "climate change", "name": "Mudanças Climáticas"},
            "4": {"query": "COVID-19", "name": "Dados COVID-19"},
            "5": {"query": "education statistics", "name": "Estatísticas Educacionais"},
            "6": {"query": "health care", "name": "Cuidados de Saúde"},
            "7": {"query": "transportation safety", "name": "Segurança no Transporte"},
            "8": {"query": "energy consumption", "name": "Consumo de Energia"},
            "9": {"query": "housing prices", "name": "Preços de Habitação"},
            "10": {"query": "unemployment rate", "name": "Taxa de Desemprego"}
        }
        
        self.clear_screen()
        self.display_banner()
        
        print(f"\n{Fore.GREEN}🔥 BUSCAS POPULARES{Style.RESET_ALL}")
        for key, search in searches.items():
            print(f"{Fore.YELLOW}[{key}] {search['name']}{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.CYAN}[?] Selecione uma busca (1-10): {Style.RESET_ALL}").strip()
        
        if choice in searches:
            search_data = searches[choice]
            result = self.make_api_request(search_data['query'], rows=15)
            if result and result.get('success'):
                self.display_results(result, f"Busca Popular: {search_data['name']}")
            else:
                print(f"{Fore.RED}[!] Nenhum resultado encontrado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Opção inválida.{Style.RESET_ALL}")
        
        self.wait_enter()
    
    def main_menu(self):
        """Menu principal"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"{Fore.YELLOW}[1] 🔍 Busca por Categoria")
            print(f"[2] 🎯 Busca Personalizada")
            print(f"[3] 🔥 Buscas Populares")
            print(f"[4] 📊 Sobre o Data.gov")
            print(f"[5] 🚪 Sair{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.menu_categories()
            elif choice == '2':
                self.custom_search()
            elif choice == '3':
                self.popular_searches()
            elif choice == '4':
                self.about_data_gov()
            elif choice == '5':
                print(f"{Fore.GREEN}[+] Obrigado por usar o Explorador de Dados Governamentais!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def menu_categories(self):
        """Menu de categorias"""
        while True:
            self.clear_screen()
            self.display_banner()
            
            print(f"\n{Fore.GREEN}📂 BUSCAR POR CATEGORIA{Style.RESET_ALL}")
            self.display_categories()
            print(f"\n{Fore.YELLOW}[0] Voltar ao Menu Principal{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}[?] Selecione uma categoria (1-{len(self.categories)}): {Style.RESET_ALL}").strip()
            
            if choice == '0':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(self.categories):
                category_key = list(self.categories.keys())[int(choice) - 1]
                self.search_by_category(category_key)
                self.wait_enter()
            else:
                print(f"{Fore.RED}[!] Opção inválida!{Style.RESET_ALL}")
                self.wait_enter()
    
    def about_data_gov(self):
        """Informações sobre o Data.gov"""
        self.clear_screen()
        self.display_banner()
        
        print(f"""
{Fore.GREEN}📊 SOBRE O DATA.GOV{Style.RESET_ALL}

{Fore.CYAN}O Data.gov é o catálogo de dados abertos do governo dos Estados Unidos,
fornecendo acesso a mais de 200.000 conjuntos de dados de diversas agências.{Style.RESET_ALL}

{Fore.YELLOW}🎯 O QUE VOCÊ PODE ENCONTRAR:{Style.RESET_ALL}
{Fore.CYAN}• Dados climáticos e ambientais
• Estatísticas econômicas e financeiras
• Dados de saúde pública
• Informações educacionais
• Dados de transporte e infraestrutura
• Estatísticas de emprego e trabalho
• E muito mais...{Style.RESET_ALL}

{Fore.YELLOW}🏛️  AGÊNCIAS ENVOLVIDAS:{Style.RESET_ALL}
{Fore.CYAN}• NASA, EPA, NOAA, USDA
• Departamento de Saúde
• Departamento de Educação
• Departamento de Transportes
• E centenas de outras{Style.RESET_ALL}

{Fore.YELLOW}🔗 SITE OFICIAL: {Fore.WHITE}https://data.gov{Style.RESET_ALL}
{Fore.YELLOW}📚 DOCUMENTAÇÃO DA API: {Fore.WHITE}https://catalog.data.gov/api/3{Style.RESET_ALL}
        """)
        
        self.wait_enter()

def main():
    """Função principal"""
    try:
        explorer = DataGovExplorer()
        explorer.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Programa interrompido pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
