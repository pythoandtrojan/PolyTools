import requests
import re
import socket
import whois
from urllib.parse import urlparse, quote
import datetime
import time

class VerificadorLinks:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.listas_negra = self.carregar_listas_negra()

    def carregar_listas_negra(self):
        """Carrega listas de domínios maliciosos conhecidos"""
        return {
            'phishing': ['paypa1', 'facebok', 'whatsapp', 'instagram', 'linkedin'],
            'suspicious': ['.tk', '.ml', '.ga', '.cf', '.gq'],
            'shorteners': ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        }

    def mostrar_menu(self):
        """Exibe o menu principal"""
        print("🔗 VERIFICADOR DE LINKS - ANÁLISE DE SEGURANÇA")
        print("=" * 60)
        print("[1] ➤ Verificar link único")
        print("[2] ➤ Verificar múltiplos links")
        print("[3] ➤ Analisar arquivo com links")
        print("[4] ➤ Verificar lista de domínios suspeitos")
        print("[5] ➤ Informações WHOIS do domínio")
        print("[6] ➤ Testar conexão do site")
        print("[0] ➤ Sair")
        print("=" * 60)

    def normalizar_url(self, url):
        """Normaliza a URL para análise"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        dominio = parsed.netloc.lower()
        caminho = parsed.path
        
        return url, dominio, caminho

    def verificar_dominio_suspeito(self, dominio):
        """Verifica se o domínio possui características suspeitas"""
        alertas = []
        
        # Verificar lista negra
        for tipo, lista in self.listas_negra.items():
            for item in lista:
                if item in dominio:
                    alertas.append(f"⚠️  Domínio contém termo suspeito: {item}")
        
        # Verificar IP como domínio (pode ser suspeito)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', dominio):
            alertas.append("⚠️  Domínio é um endereço IP (pode ser suspeito)")
        
        # Verificar domínios muito longos
        if len(dominio) > 50:
            alertas.append("⚠️  Domínio muito longo (pode ser phishing)")
        
        # Verificar caracteres especiais
        if re.search(r'[^\w\.\-]', dominio):
            alertas.append("⚠️  Domínio contém caracteres especiais")
        
        return alertas

    def verificar_https(self, url):
        """Verifica se o site usa HTTPS"""
        try:
            if url.startswith('https://'):
                return "✅ HTTPS ativo (conexão segura)"
            else:
                return "⚠️  Site não usa HTTPS (conexão não criptografada)"
        except:
            return "❌ Não foi possível verificar HTTPS"

    def verificar_redirecionamentos(self, url):
        """Verifica se a URL faz redirecionamentos"""
        try:
            response = requests.head(url, headers=self.headers, timeout=10, allow_redirects=True)
            redirecionamentos = len(response.history)
            
            if redirecionamentos > 0:
                destino_final = response.url
                return f"⚠️  {redirecionamentos} redirecionamento(s) detectado(s)\n   Final: {destino_final}"
            else:
                return "✅ Sem redirecionamentos detectados"
                
        except requests.RequestException:
            return "❌ Não foi possível verificar redirecionamentos"

    def obter_info_whois(self, dominio):
        """Obtém informações WHOIS do domínio"""
        try:
            info = whois.whois(dominio)
            
            resultados = []
            if info.domain_name:
                resultados.append(f"📛 Domínio: {info.domain_name}")
            if info.creation_date:
                if isinstance(info.creation_date, list):
                    data_criacao = info.creation_date[0]
                else:
                    data_criacao = info.creation_date
                idade = (datetime.datetime.now() - data_criacao).days
                resultados.append(f"📅 Criado em: {data_criacao.strftime('%d/%m/%Y')} ({idade} dias)")
            if info.registrar:
                resultados.append(f"🏢 Registrar: {info.registrar}")
            if info.country:
                resultados.append(f"🌍 País: {info.country}")
            
            return "\n".join(resultados) if resultados else "❌ Informações WHOIS não disponíveis"
            
        except Exception as e:
            return f"❌ Erro ao obter WHOIS: {e}"

    def testar_conexao(self, url):
        """Testa a conexão com o site"""
        try:
            start_time = time.time()
            response = requests.get(url, headers=self.headers, timeout=10)
            tempo_resposta = round((time.time() - start_time) * 1000, 2)
            
            info = [
                f"📡 Status: {response.status_code}",
                f"⏱️  Tempo de resposta: {tempo_resposta}ms",
                f"📊 Tamanho: {len(response.content)} bytes"
            ]
            
            return "\n".join(info)
            
        except requests.exceptions.Timeout:
            return "❌ Timeout - Site não respondeu"
        except requests.exceptions.ConnectionError:
            return "❌ Erro de conexão - Site pode estar offline"
        except Exception as e:
            return f"❌ Erro: {e}"

    def analisar_url(self, url):
        """Analisa uma URL completa"""
        print(f"\n🔍 Analisando: {url}")
        print("─" * 50)
        
        try:
            url_normalizada, dominio, caminho = self.normalizar_url(url)
            
            # Informações básicas
            print(f"🌐 Domínio: {dominio}")
            print(f"📁 Caminho: {caminho}")
            
            # Verificações de segurança
            print(f"\n🛡️  VERIFICAÇÕES DE SEGURANÇA:")
            print("├─ " + self.verificar_https(url_normalizada))
            
            alertas_dominio = self.verificar_dominio_suspeito(dominio)
            if alertas_dominio:
                for alerta in alertas_dominio:
                    print("├─ " + alerta)
            else:
                print("├─ ✅ Domínio parece legítimo")
            
            print("├─ " + self.verificar_redirecionamentos(url_normalizada))
            
            # Teste de conexão
            print(f"\n📡 TESTE DE CONEXÃO:")
            print("├─ " + self.testar_conexao(url_normalizada))
            
            # Score de segurança
            score = 100
            if alertas_dominio:
                score -= len(alertas_dominio) * 10
            if not url_normalizada.startswith('https://'):
                score -= 20
            
            print(f"\n📊 SCORE DE SEGURANÇA: {score}/100")
            if score >= 80:
                print("✅ LINK PROVAVELMENTE SEGURO")
            elif score >= 60:
                print("⚠️  LINK COM ALGUNS ALERTAS")
            else:
                print("❌ LINK POTENCIALMENTE PERIGOSO")
                
        except Exception as e:
            print(f"❌ Erro na análise: {e}")

    def verificar_link_unico(self):
        """Verifica um único link"""
        url = input("\n🔗 Digite a URL para verificar: ").strip()
        if url:
            self.analisar_url(url)
        else:
            print("❌ URL inválida!")

    def verificar_multiplos_links(self):
        """Verifica múltiplos links"""
        print("\n🔗 Digite os links (um por linha). Digite 'fim' para terminar:")
        links = []
        
        while True:
            link = input().strip()
            if link.lower() == 'fim':
                break
            if link:
                links.append(link)
        
        for i, link in enumerate(links, 1):
            self.analisar_url(link)
            if i < len(links):
                print("\n" + "═" * 60 + "\n")

    def verificar_arquivo(self):
        """Verifica links de um arquivo"""
        caminho = input("\n📁 Digite o caminho do arquivo: ").strip()
        try:
            with open(caminho, 'r', encoding='utf-8') as file:
                links = [linha.strip() for linha in file if linha.strip()]
            
            for i, link in enumerate(links, 1):
                print(f"\n📄 Link {i}/{len(links)}:")
                self.analisar_url(link)
                if i < len(links):
                    print("\n" + "═" * 60 + "\n")
                    
        except FileNotFoundError:
            print("❌ Arquivo não encontrado!")
        except Exception as e:
            print(f"❌ Erro ao ler arquivo: {e}")

    def executar(self):
        """Loop principal do programa"""
        while True:
            try:
                self.mostrar_menu()
                opcao = input("\n📋 Escolha uma opção (0-6): ").strip()
                
                if opcao == '0':
                    print("👋 Saindo do verificador de links...")
                    break
                elif opcao == '1':
                    self.verificar_link_unico()
                elif opcao == '2':
                    self.verificar_multiplos_links()
                elif opcao == '3':
                    self.verificar_arquivo()
                elif opcao == '4':
                    dominio = input("\n🌐 Digite o domínio para verificar: ").strip()
                    alertas = self.verificar_dominio_suspeito(dominio)
                    if alertas:
                        for alerta in alertas:
                            print(f"⚠️  {alerta}")
                    else:
                        print("✅ Domínio não está na lista de suspeitos")
                elif opcao == '5':
                    dominio = input("\n🌐 Digite o domínio para WHOIS: ").strip()
                    print(f"\n📋 Informações WHOIS para {dominio}:")
                    print("─" * 40)
                    print(self.obter_info_whois(dominio))
                elif opcao == '6':
                    url = input("\n🔗 Digite a URL para testar conexão: ").strip()
                    if url:
                        url_norm, _, _ = self.normalizar_url(url)
                        print(self.testar_conexao(url_norm))
                else:
                    print("❌ Opção inválida!")
                
                input("\n⏎ Pressione Enter para continuar...")
                print("\n" + "=" * 60 + "\n")
                
            except KeyboardInterrupt:
                print("\n👋 Programa interrompido pelo usuário.")
                break
            except Exception as e:
                print(f"❌ Erro inesperado: {e}")

# Instalar dependências se necessário
def verificar_dependencias():
    try:
        import whois
        import requests
    except ImportError:
        print("📦 Instalando dependências...")
        import subprocess
        subprocess.run(['pip', 'install', 'python-whois', 'requests'])
        print("✅ Dependências instaladas!")

if __name__ == "__main__":
    verificar_dependencias()
    verificador = VerificadorLinks()
    verificador.executar()
