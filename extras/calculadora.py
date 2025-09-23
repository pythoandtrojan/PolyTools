import math
import os
import sys
from datetime import datetime

class Calculadora:
    def __init__(self):
        self.historico = []
        self.memoria = 0
        self.ultimo_resultado = 0
        self.ligada = True
        
    def limpar_tela(self):
        """Limpa a tela do terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def exibir_cabecalho(self):
        """Exibe o cabeçalho da calculadora"""
        print("=" * 60)
        print("            🧮 CALCULADORA AVANÇADA v2.0 🧮")
        print("=" * 60)
        print(f"Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"Memória: {self.memoria}")
        print(f"Último resultado: {self.ultimo_resultado}")
        print("-" * 60)
    
    def exibir_menu(self):
        """Exibe o menu de operações disponíveis"""
        print("\n📋 OPERAÇÕES DISPONÍVEIS:")
        print("1.  Adição (+)")
        print("2.  Subtração (-)")
        print("3.  Multiplicação (×)")
        print("4.  Divisão (÷)")
        print("5.  Potência (^)")
        print("6.  Raiz Quadrada (√)")
        print("7.  Porcentagem (%)")
        print("8.  Logaritmo (log)")
        print("9.  Seno (sin)")
        print("10. Cosseno (cos)")
        print("11. Tangente (tan)")
        print("12. Fatorial (!)")
        print("13. Memória (M+)")
        print("14. Limpar Memória (MC)")
        print("15. Ver Histórico")
        print("16. Limpar Histórico")
        print("17. Desligar")
        print("-" * 60)
    
    def validar_numero(self, mensagem):
        """Valida a entrada de números"""
        while True:
            try:
                valor = input(mensagem)
                if valor.upper() == 'M':  # Usar valor da memória
                    return self.memoria
                elif valor.upper() == 'ANS':  # Usar último resultado
                    return self.ultimo_resultado
                else:
                    return float(valor)
            except ValueError:
                print("❌ Erro: Por favor, digite um número válido!")
    
    def adicionar_historico(self, operacao, resultado):
        """Adiciona operação ao histórico"""
        entrada = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'operacao': operacao,
            'resultado': resultado
        }
        self.historico.append(entrada)
        self.ultimo_resultado = resultado
    
    def exibir_historico(self):
        """Exibe o histórico de operações"""
        self.limpar_tela()
        self.exibir_cabecalho()
        print("\n📜 HISTÓRICO DE OPERAÇÕES:")
        if not self.historico:
            print("Nenhuma operação realizada ainda.")
        else:
            for i, entrada in enumerate(self.historico[-10:], 1):  # Mostra últimas 10
                print(f"{i}. [{entrada['timestamp']}] {entrada['operacao']} = {entrada['resultado']}")
        
        input("\nPressione Enter para continuar...")
    
    def adicao(self):
        """Operação de adição"""
        print("\n➕ ADIÇÃO")
        num1 = self.validar_numero("Digite o primeiro número (ou 'M' para memória, 'ANS' para último resultado): ")
        num2 = self.validar_numero("Digite o segundo número: ")
        resultado = num1 + num2
        operacao = f"{num1} + {num2}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def subtracao(self):
        """Operação de subtração"""
        print("\n➖ SUBTRAÇÃO")
        num1 = self.validar_numero("Digite o primeiro número (ou 'M' para memória, 'ANS' para último resultado): ")
        num2 = self.validar_numero("Digite o segundo número: ")
        resultado = num1 - num2
        operacao = f"{num1} - {num2}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def multiplicacao(self):
        """Operação de multiplicação"""
        print("\n✖️ MULTIPLICAÇÃO")
        num1 = self.validar_numero("Digite o primeiro número (ou 'M' para memória, 'ANS' para último resultado): ")
        num2 = self.validar_numero("Digite o segundo número: ")
        resultado = num1 * num2
        operacao = f"{num1} × {num2}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def divisao(self):
        """Operação de divisão"""
        print("\n➗ DIVISÃO")
        num1 = self.validar_numero("Digite o primeiro número (ou 'M' para memória, 'ANS' para último resultado): ")
        
        while True:
            num2 = self.validar_numero("Digite o segundo número (não pode ser zero): ")
            if num2 != 0:
                break
            print("❌ Erro: Divisão por zero não é permitida!")
        
        resultado = num1 / num2
        operacao = f"{num1} ÷ {num2}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def potencia(self):
        """Operação de potência"""
        print("\n🔺 POTÊNCIA")
        base = self.validar_numero("Digite a base (ou 'M' para memória, 'ANS' para último resultado): ")
        expoente = self.validar_numero("Digite o expoente: ")
        resultado = base ** expoente
        operacao = f"{base} ^ {expoente}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def raiz_quadrada(self):
        """Operação de raiz quadrada"""
        print("\n√ RAIZ QUADRADA")
        
        while True:
            numero = self.validar_numero("Digite o número (deve ser positivo): ")
            if numero >= 0:
                break
            print("❌ Erro: Não é possível calcular raiz de número negativo!")
        
        resultado = math.sqrt(numero)
        operacao = f"√{numero}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def porcentagem(self):
        """Operação de porcentagem"""
        print("\n% PORCENTAGEM")
        numero = self.validar_numero("Digite o número: ")
        percentual = self.validar_numero("Digite a porcentagem: ")
        resultado = (numero * percentual) / 100
        operacao = f"{percentual}% de {numero}"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def logaritmo(self):
        """Operação de logaritmo"""
        print("\n📊 LOGARITMO")
        
        while True:
            numero = self.validar_numero("Digite o número (deve ser positivo): ")
            if numero > 0:
                break
            print("❌ Erro: Número deve ser maior que zero!")
        
        while True:
            base = self.validar_numero("Digite a base do logaritmo (deve ser positiva e diferente de 1): ")
            if base > 0 and base != 1:
                break
            print("❌ Erro: Base deve ser positiva e diferente de 1!")
        
        resultado = math.log(numero, base)
        operacao = f"log{base}({numero})"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def seno(self):
        """Operação de seno"""
        print("\n📐 SENO")
        angulo = self.validar_numero("Digite o ângulo em graus: ")
        resultado = math.sin(math.radians(angulo))
        operacao = f"sin({angulo}°)"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def cosseno(self):
        """Operação de cosseno"""
        print("\n📐 COSSENO")
        angulo = self.validar_numero("Digite o ângulo em graus: ")
        resultado = math.cos(math.radians(angulo))
        operacao = f"cos({angulo}°)"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def tangente(self):
        """Operação de tangente"""
        print("\n📐 TANGENTE")
        angulo = self.validar_numero("Digite o ângulo em graus: ")
        
        # Verificar se o ângulo não é 90° + k*180°
        if (angulo % 180) == 90:
            print("❌ Erro: Tangente não definida para este ângulo!")
            return None
        
        resultado = math.tan(math.radians(angulo))
        operacao = f"tan({angulo}°)"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def fatorial(self):
        """Operação de fatorial"""
        print("\n❗ FATORIAL")
        
        while True:
            numero = self.validar_numero("Digite um número inteiro não negativo: ")
            if numero >= 0 and numero == int(numero):
                break
            print("❌ Erro: Número deve ser inteiro não negativo!")
        
        resultado = math.factorial(int(numero))
        operacao = f"{int(numero)}!"
        self.adicionar_historico(operacao, resultado)
        return resultado
    
    def adicionar_memoria(self, valor):
        """Adiciona valor à memória"""
        self.memoria += valor
        print(f"✅ Valor {valor} adicionado à memória. Memória atual: {self.memoria}")
    
    def limpar_memoria(self):
        """Limpa a memória"""
        self.memoria = 0
        print("✅ Memória limpa!")
    
    def executar_operacao(self, opcao):
        """Executa a operação selecionada"""
        operacoes = {
            1: self.adicao,
            2: self.subtracao,
            3: self.multiplicacao,
            4: self.divisao,
            5: self.potencia,
            6: self.raiz_quadrada,
            7: self.porcentagem,
            8: self.logaritmo,
            9: self.seno,
            10: self.cosseno,
            11: self.tangente,
            12: self.fatorial
        }
        
        if opcao in operacoes:
            try:
                resultado = operacoes[opcao]()
                if resultado is not None:
                    print(f"\n🎯 RESULTADO: {resultado}")
                    
                    # Perguntar se deseja armazenar na memória
                    if input("\nDeseja adicionar este valor à memória? (s/n): ").lower() == 's':
                        self.adicionar_memoria(resultado)
                
                input("\nPressione Enter para continuar...")
                
            except Exception as e:
                print(f"❌ Erro durante a operação: {e}")
                input("\nPressione Enter para continuar...")
        
        elif opcao == 13:
            valor = self.validar_numero("Digite o valor para adicionar à memória: ")
            self.adicionar_memoria(valor)
            input("\nPressione Enter para continuar...")
        
        elif opcao == 14:
            self.limpar_memoria()
            input("\nPressione Enter para continuar...")
        
        elif opcao == 15:
            self.exibir_historico()
        
        elif opcao == 16:
            self.historico.clear()
            print("✅ Histórico limpo!")
            input("\nPressione Enter para continuar...")
        
        elif opcao == 17:
            print("\n👋 Obrigado por usar a calculadora! Até logo!")
            self.ligada = False
        
        else:
            print("❌ Opção inválida! Tente novamente.")
            input("\nPressione Enter para continuar...")
    
    def iniciar(self):
        """Inicia a calculadora"""
        while self.ligada:
            self.limpar_tela()
            self.exibir_cabecalho()
            self.exibir_menu()
            
            try:
                opcao = int(input("\n📝 Digite o número da operação desejada: "))
                self.executar_operacao(opcao)
            except ValueError:
                print("❌ Erro: Por favor, digite um número válido!")
                input("\nPressione Enter para continuar...")
            except KeyboardInterrupt:
                print("\n\n👋 Calculadora encerrada pelo usuário!")
                break

# Executar a calculadora
if __name__ == "__main__":
    calculadora = Calculadora()
    calculadora.iniciar()
