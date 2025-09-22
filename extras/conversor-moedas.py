import requests
import json
from datetime import datetime
import time

class ConversorMoedas:
    def __init__(self):
        self.moedas = {
            '1': {'codigo': 'USD', 'nome': 'Dólar Americano', 'simbolo': 'US$'},
            '2': {'codigo': 'EUR', 'nome': 'Euro', 'simbolo': '€'},
            '3': {'codigo': 'GBP', 'nome': 'Libra Esterlina', 'simbolo': '£'},
            '4': {'codigo': 'JPY', 'nome': 'Iene Japonês', 'simbolo': '¥'},
            '5': {'codigo': 'BRL', 'nome': 'Real Brasileiro', 'simbolo': 'R$'},
            '6': {'codigo': 'CAD', 'nome': 'Dólar Canadense', 'simbolo': 'C$'},
            '7': {'codigo': 'AUD', 'nome': 'Dólar Australiano', 'simbolo': 'A$'},
            '8': {'codigo': 'CHF', 'nome': 'Franco Suíço', 'simbolo': 'CHF'},
            '9': {'codigo': 'CNY', 'nome': 'Yuan Chinês', 'simbolo': '¥'},
            '10': {'codigo': 'ARS', 'nome': 'Peso Argentino', 'simbolo': '$'},
            '11': {'codigo': 'BTC', 'nome': 'Bitcoin', 'simbolo': '₿'},
            '12': {'codigo': 'ETH', 'nome': 'Ethereum', 'simbolo': 'Ξ'}
        }
        self.taxas = {}
        self.ultima_atualizacao = None

    def obter_taxas(self):
        """Obtém as taxas de câmbio atualizadas"""
        try:
            print("🔄 Conectando à API...")
            url = "https://api.exchangerate-api.com/v4/latest/USD"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                dados = response.json()
                self.taxas = dados['rates']
                self.ultima_atualizacao = datetime.fromtimestamp(dados['time_last_updated'])
                print("✅ Taxas atualizadas com sucesso!")
                return True
            else:
                print("❌ Erro ao conectar com a API. Usando taxas offline...")
                return self.usar_taxas_offline()
                
        except requests.exceptions.RequestException:
            print("❌ Sem conexão. Usando taxas offline...")
            return self.usar_taxas_offline()

    def usar_taxas_offline(self):
        """Usa taxas offline caso não consiga conectar"""
        # Taxas aproximadas (devem ser atualizadas periodicamente)
        self.taxas = {
            'USD': 1.0,
            'EUR': 0.92,
            'GBP': 0.79,
            'JPY': 148.50,
            'BRL': 5.20,
            'CAD': 1.35,
            'AUD': 1.52,
            'CHF': 0.88,
            'CNY': 7.18,
            'ARS': 850.0,
            'BTC': 0.000025,
            'ETH': 0.00042
        }
        self.ultima_atualizacao = datetime.now()
        return True

    def converter_moeda(self, valor, de_moeda, para_moeda):
        """Converte um valor entre duas moedas"""
        try:
            # Primeiro converter para USD (moeda base)
            valor_em_usd = valor / self.taxas[de_moeda]
            # Depois converter para a moeda destino
            valor_convertido = valor_em_usd * self.taxas[para_moeda]
            return round(valor_convertido, 4)
        except KeyError:
            return None

    def mostrar_menu_principal(self):
        """Exibe o menu principal"""
        print("💱 CONVERSOR DE MOEDAS INTERNACIONAL")
        print("=" * 55)
        print("[1] ➤ Converter moeda")
        print("[2] ➤ Ver todas as taxas")
        print("[3] ➤ Atualizar taxas")
        print("[4] ➤ Listar moedas disponíveis")
        print("[5] ➤ Conversão múltipla")
        print("[0] ➤ Sair")
        print("=" * 55)

    def mostrar_moedas(self):
        """Mostra todas as moedas disponíveis"""
        print("\n📊 MOEDAS DISPONÍVEIS:")
        print("─" * 40)
        for key, moeda in self.moedas.items():
            print(f"[{key}] {moeda['codigo']} - {moeda['nome']} ({moeda['simbolo']})")

    def selecionar_moeda(self, mensagem):
        """Permite ao usuário selecionar uma moeda"""
        self.mostrar_moedas()
        while True:
            try:
                opcao = input(f"\n{mensagem} (1-12): ").strip()
                if opcao in self.moedas:
                    return self.moedas[opcao]['codigo']
                else:
                    print("❌ Opção inválida! Escolha entre 1 e 12.")
            except KeyboardInterrupt:
                return None

    def converter(self):
        """Realiza uma conversão única"""
        print("\n💵 CONVERSÃO DE MOEDA")
        print("─" * 30)
        
        de_moeda = self.selecionar_moeda("Converter DE")
        if not de_moeda:
            return
            
        para_moeda = self.selecionar_moeda("Converter PARA")
        if not para_moeda:
            return
        
        try:
            valor = float(input(f"\n💰 Valor em {de_moeda} para converter: ").replace(',', '.'))
            
            resultado = self.converter_moeda(valor, de_moeda, para_moeda)
            if resultado is not None:
                simbolo_de = self.moedas[[k for k, v in self.moedas.items() if v['codigo'] == de_moeda][0]]['simbolo']
                simbolo_para = self.moedas[[k for k, v in self.moedas.items() if v['codigo'] == para_moeda][0]]['simbolo']
                
                print(f"\n✅ RESULTADO:")
                print("═" * 40)
                print(f"{simbolo_de} {valor:,.2f} {de_moeda} = {simbolo_para} {resultado:,.2f} {para_moeda}")
                
                # Mostrar taxa de câmbio
                taxa = self.converter_moeda(1, de_moeda, para_moeda)
                print(f"💱 Taxa: 1 {de_moeda} = {taxa:,.4f} {para_moeda}")
            else:
                print("❌ Erro na conversão!")
                
        except ValueError:
            print("❌ Valor inválido! Use números.")
        except Exception as e:
            print(f"❌ Erro: {e}")

    def ver_todas_taxas(self):
        """Mostra todas as taxas em relação ao USD"""
        print(f"\n📈 TAXAS DE CÂMBIO (USD → outras)")
        print(f"🕒 Última atualização: {self.ultima_atualizacao.strftime('%d/%m/%Y %H:%M')}")
        print("─" * 50)
        
        for key, moeda in self.moedas.items():
            if moeda['codigo'] != 'USD':
                taxa = self.taxas.get(moeda['codigo'], 'N/A')
                print(f"USD → {moeda['codigo']}: {taxa:,.4f}")

    def conversao_multipla(self):
        """Converte um valor para várias moedas"""
        print("\n🌍 CONVERSÃO MÚLTIPLA")
        print("─" * 25)
        
        de_moeda = self.selecionar_moeda("Converter DE")
        if not de_moeda:
            return
            
        try:
            valor = float(input(f"\n💰 Valor em {de_moeda} para converter: ").replace(',', '.'))
            
            print(f"\n📊 {valor:,.2f} {de_moeda} equivale a:")
            print("═" * 50)
            
            simbolo_de = self.moedas[[k for k, v in self.moedas.items() if v['codigo'] == de_moeda][0]]['simbolo']
            
            for key, moeda in self.moedas.items():
                if moeda['codigo'] != de_moeda:
                    resultado = self.converter_moeda(valor, de_moeda, moeda['codigo'])
                    if resultado is not None:
                        print(f"{moeda['simbolo']} {resultado:>12,.2f} {moeda['codigo']}")
            
        except ValueError:
            print("❌ Valor inválido!")

    def executar(self):
        """Loop principal do programa"""
        print("💱 Inicializando Conversor de Moedas...")
        self.obter_taxas()
        
        while True:
            try:
                self.mostrar_menu_principal()
                opcao = input("\n📋 Escolha uma opção (0-5): ").strip()
                
                if opcao == '0':
                    print("👋 Obrigado por usar o Conversor de Moedas!")
                    break
                elif opcao == '1':
                    self.converter()
                elif opcao == '2':
                    self.ver_todas_taxas()
                elif opcao == '3':
                    if self.obter_taxas():
                        time.sleep(1)
                elif opcao == '4':
                    self.mostrar_moedas()
                elif opcao == '5':
                    self.conversao_multipla()
                else:
                    print("❌ Opção inválida! Escolha entre 0 e 5.")
                
                input("\n⏎ Pressione Enter para continuar...")
                print("\n" + "=" * 55 + "\n")
                
            except KeyboardInterrupt:
                print("\n👋 Programa interrompido pelo usuário.")
                break
            except Exception as e:
                print(f"❌ Erro inesperado: {e}")

# Executar o programa
if __name__ == "__main__":
    conversor = ConversorMoedas()
    conversor.executar()
