#!/usr/bin/env python3
import random
import json
import os
from datetime import datetime, timedelta
from colorama import Fore, Style, init

init(autoreset=True)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

class GeradorPersonaOSINT:
    def __init__(self):
        # Bancos de dados para geração
        self.nomes_masculinos = [
            'João Silva', 'Pedro Santos', 'Carlos Oliveira', 'Lucas Pereira', 'Miguel Costa',
            'Antônio Rodrigues', 'Francisco Almeida', 'Paulo Souza', 'Marcos Lima', 'Rafael Ferreira',
            'Daniel Barbosa', 'Bruno Carvalho', 'Eduardo Rocha', 'Felipe Martins', 'André Ribeiro'
        ]
        
        self.nomes_femininos = [
            'Maria Silva', 'Ana Santos', 'Juliana Oliveira', 'Fernanda Pereira', 'Patrícia Costa',
            'Mariana Rodrigues', 'Amanda Almeida', 'Bruna Souza', 'Carla Lima', 'Letícia Ferreira',
            'Tatiane Barbosa', 'Vanessa Carvalho', 'Camila Rocha', 'Isabela Martins', 'Laura Ribeiro'
        ]
        
        self.sobrenomes = [
            'Silva', 'Santos', 'Oliveira', 'Souza', 'Rodrigues', 'Ferreira', 'Alves', 'Lima',
            'Pereira', 'Costa', 'Ribeiro', 'Martins', 'Jesus', 'Barbosa', 'Rocha'
        ]
        
        self.empregos = {
            'estudante': ['Ensino Médio', 'Faculdade', 'Pós-graduação', 'Curso Técnico'],
            'trabalhador': [
                'Analista de Sistemas', 'Desenvolvedor', 'Designer', 'Professor', 'Médico',
                'Engenheiro', 'Advogado', 'Vendedor', 'Gerente', 'Assistente Administrativo',
                'Jornalista', 'Marketing Digital', 'Contador', 'Arquiteto', 'Chef de Cozinha'
            ],
            'autonomo': ['Uber', 'Freelancer', 'Consultor', 'Youtuber', 'Entregador']
        }
        
        self.hobbies = [
            'Futebol', 'Video Game', 'Leitura', 'Música', 'Cinema', 'Culinária', 'Academia',
            'Natação', 'Corrida', 'Pintura', 'Fotografia', 'Viagens', 'Dança', 'Teatro'
        ]
        
        self.animais = [
            'Cachorro', 'Gato', 'Pássaro', 'Peixe', 'Coelho', 'Tartaruga', 'Hamster'
        ]
        
        self.nomes_animais = [
            'Rex', 'Luna', 'Thor', 'Mel', 'Bob', 'Luna', 'Mike', 'Bela', 'Tobby', 'Nina'
        ]
        
        self.cidades_estados = [
            ('São Paulo', 'SP'), ('Rio de Janeiro', 'RJ'), ('Belo Horizonte', 'MG'),
            ('Porto Alegre', 'RS'), ('Curitiba', 'PR'), ('Salvador', 'BA'),
            ('Fortaleza', 'CE'), ('Recife', 'PE'), ('Brasília', 'DF'), ('Manaus', 'AM')
        ]
        
        self.redes_sociais = [
            'Facebook', 'Instagram', 'Twitter', 'LinkedIn', 'TikTok', 'WhatsApp'
        ]

    def gerar_cpf(self):
        """Gera CPF válido"""
        def calcular_digito(dados, pesos):
            soma = sum(int(dados[i]) * pesos[i] for i in range(len(pesos)))
            resto = soma % 11
            return 0 if resto < 2 else 11 - resto
        
        numeros = [random.randint(0, 9) for _ in range(9)]
        
        pesos1 = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito1 = calcular_digito(''.join(map(str, numeros)), pesos1)
        numeros.append(digito1)
        
        pesos2 = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]
        digito2 = calcular_digito(''.join(map(str, numeros)), pesos2)
        numeros.append(digito2)
        
        cpf = ''.join(map(str, numeros))
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"

    def gerar_email(self, nome, sobrenome):
        """Gera email realista"""
        provedores = ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com']
        formatos = [
            f"{nome.lower()}.{sobrenome.lower()}",
            f"{nome.lower()}{sobrenome.lower()}",
            f"{nome.lower()}_{sobrenome.lower()}",
            f"{nome[0].lower()}.{sobrenome.lower()}"
        ]
        
        formato = random.choice(formatos)
        ano = random.randint(85, 2000)
        if random.random() > 0.7:  # 30% de chance de ter número
            formato += str(random.randint(1, 99))
        
        provedor = random.choice(provedores)
        return f"{formato}@{provedor}"

    def gerar_telefone(self):
        """Gera telefone brasileiro"""
        ddd = random.randint(11, 99)
        if random.choice([True, False]):
            # Celular
            numero = f"9{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
            return f"({ddd}) {numero[:5]}-{numero[5:]}"
        else:
            # Fixo
            numero = f"{random.randint(2, 5)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
            return f"({ddd}) {numero[:4]}-{numero[4:]}"

    def gerar_data_nascimento(self, idade):
        """Gera data de nascimento baseada na idade"""
        ano_atual = datetime.now().year
        ano_nascimento = ano_atual - idade
        mes = random.randint(1, 12)
        dia = random.randint(1, 28)
        return f"{dia:02d}/{mes:02d}/{ano_nascimento}"

    def determinar_estudo_trabalho(self, idade):
        """Determina situação de estudo/trabalho baseada na idade"""
        if idade <= 18:
            return "estudante", "Ensino Médio"
        elif idade <= 24:
            if random.random() > 0.3:  # 70% chance de estudar
                return "estudante", "Faculdade"
            else:
                return "trabalhador", random.choice(self.empregos['trabalhador'])
        elif idade <= 30:
            if random.random() > 0.7:  # 30% chance de estudar
                return "estudante", "Pós-graduação"
            else:
                return "trabalhador", random.choice(self.empregos['trabalhador'])
        else:
            if random.random() > 0.8:  # 20% chance de ser autônomo
                return "autonomo", random.choice(self.empregos['autonomo'])
            else:
                return "trabalhador", random.choice(self.empregos['trabalhador'])

    def gerar_endereco(self):
        """Gera endereço fictício"""
        cidade, estado = random.choice(self.cidades_estados)
        ruas = ['Rua das Flores', 'Avenida Brasil', 'Rua São Paulo', 'Alameda Santos',
                'Rua Rio de Janeiro', 'Avenida Paulista', 'Rua Augusta', 'Alameda Campinas']
        
        return {
            'rua': f"{random.choice(ruas)}, {random.randint(100, 2000)}",
            'cidade': cidade,
            'estado': estado,
            'cep': f"{random.randint(10000, 99999)}-{random.randint(100, 999)}"
        }

    def criar_historia_vida(self, persona):
        """Cria uma história de vida coerente para a persona"""
        idade = persona['idade']
        situacao = persona['situacao']
        emprego_estudo = persona['emprego_estudo']
        cidade = persona['endereco']['cidade']
        
        historia = f"{persona['nome_completo']} é uma pessoa de {idade} anos "
        
        if situacao == "estudante":
            if emprego_estudo == "Ensino Médio":
                historia += f"que está cursando o Ensino Médio em {cidade}. "
                historia += f"Sonha em ingressar na faculdade no próximo ano. "
            elif emprego_estudo == "Faculdade":
                faculdades = ['USP', 'UNICAMP', 'UFMG', 'UFRJ', 'PUC']
                historia += f"que está cursando {random.choice(faculdades)}. "
                historia += f"Está no {random.randint(1, 5)}º ano do curso. "
            else:
                historia += f"que está fazendo {emprego_estudo.lower()}. "
        else:
            historia += f"que trabalha como {emprego_estudo.lower()} em {cidade}. "
            historia += f"Tem {random.randint(1, 10)} anos de experiência na área. "
        
        # Adicionar hobbies
        hobbies = random.sample(self.hobbies, random.randint(1, 3))
        historia += f"Nos tempos livres, gosta de {', '.join(hobbies[:-1])} e {hobbies[-1]}. "
        
        # Adicionar vida familiar
        if idade > 25 and random.random() > 0.6:
            historia += f"Mora com {persona['nome_mae']} e {persona['nome_pai']}. "
        
        # Adicionar animais
        if persona['animais']:
            animais_str = ', '.join([f"{animal['nome']} ({animal['tipo']})" for animal in persona['animais']])
            historia += f"Tem {len(persona['animais'])} animais de estimação: {animais_str}. "
        
        # Finalização
        historia += f"É uma pessoa {random.choice(['comunicativa', 'reservada', 'alegre', 'determinada'])} "
        historia += f"e {random.choice(['gosta de ajudar os outros', 'valoriza sua família', 'busca sempre aprender coisas novas', 'é muito dedicada ao trabalho'])}."
        
        return historia

    def gerar_persona_completa(self, idade=None):
        """Gera uma persona completa e coerente"""
        if idade is None:
            idade = random.randint(18, 65)
        
        # Gênero
        genero = random.choice(['masculino', 'feminino'])
        
        # Nome completo
        if genero == 'masculino':
            nome_completo = random.choice(self.nomes_masculinos)
        else:
            nome_completo = random.choice(self.nomes_femininos)
        
        nome, sobrenome = nome_completo.split(' ', 1)
        
        # Situação de estudo/trabalho
        situacao, emprego_estudo = self.determinar_estudo_trabalho(idade)
        
        # Dados pessoais
        persona = {
            'nome_completo': nome_completo,
            'idade': idade,
            'genero': genero,
            'data_nascimento': self.gerar_data_nascimento(idade),
            'cpf': self.gerar_cpf(),
            'rg': f"{random.randint(10, 50)}.{random.randint(100, 999)}.{random.randint(100, 999)}-{random.randint(1, 9)}",
            'email': self.gerar_email(nome, sobrenome),
            'telefone': self.gerar_telefone(),
            'situacao': situacao,
            'emprego_estudo': emprego_estudo,
            'endereco': self.gerar_endereco(),
            'nome_mae': f"{random.choice(self.nomes_femininos)} {random.choice(self.sobrenomes)}",
            'nome_pai': f"{random.choice(self.nomes_masculinos)} {random.choice(self.sobrenomes)}",
            'animais': [],
            'redes_sociais': [],
            'hobbies': random.sample(self.hobbies, random.randint(2, 4)),
            'historia_vida': ""
        }
        
        # Animais de estimação
        if random.random() > 0.4:  # 60% de chance de ter animal
            num_animais = random.randint(1, 2)
            for _ in range(num_animais):
                persona['animais'].append({
                    'tipo': random.choice(self.animais),
                    'nome': random.choice(self.nomes_animais),
                    'idade': random.randint(1, 15)
                })
        
        # Redes sociais
        num_redes = random.randint(2, 4)
        redes = random.sample(self.redes_sociais, num_redes)
        for rede in redes:
            persona['redes_sociais'].append({
                'rede': rede,
                'usuario': f"{nome.lower()}{sobrenome.lower()}{random.randint(1, 99) if random.random() > 0.5 else ''}"
            })
        
        # História de vida
        persona['historia_vida'] = self.criar_historia_vida(persona)
        
        return persona

    def mostrar_persona(self, persona):
        """Exibe a persona de forma organizada e colorida"""
        print(f"\n{CIANO}{NEGRITO}🎭 PERSONA FICTÍCIA GERADA{RESET}")
        print("=" * 60)
        
        print(f"\n{AZUL}{NEGRITO}👤 IDENTIFICAÇÃO{RESET}")
        print(f"  {BRANCO}Nome:{RESET} {VERDE}{persona['nome_completo']}{RESET}")
        print(f"  {BRANCO}Idade:{RESET} {persona['idade']} anos")
        print(f"  {BRANCO}Gênero:{RESET} {persona['genero'].title()}")
        print(f"  {BRANCO}Data Nasc:{RESET} {persona['data_nascimento']}")
        print(f"  {BRANCO}CPF:{RESET} {persona['cpf']}")
        print(f"  {BRANCO}RG:{RESET} {persona['rg']}")
        
        print(f"\n{AZUL}{NEGRITO}📞 CONTATOS{RESET}")
        print(f"  {BRANCO}Email:{RESET} {VERDE}{persona['email']}{RESET}")
        print(f"  {BRANCO}Telefone:{RESET} {persona['telefone']}")
        
        print(f"\n{AZUL}{NEGRITO}🏠 ENDEREÇO{RESET}")
        end = persona['endereco']
        print(f"  {BRANCO}Endereço:{RESET} {end['rua']}")
        print(f"  {BRANCO}Cidade/UF:{RESET} {end['cidade']}/{end['estado']}")
        print(f"  {BRANCO}CEP:{RESET} {end['cep']}")
        
        print(f"\n{AZUL}{NEGRITO}💼 SITUAÇÃO{RESET}")
        print(f"  {BRANCO}Status:{RESET} {persona['situacao'].title()}")
        print(f"  {BRANCO}Emprego/Estudo:{RESET} {persona['emprego_estudo']}")
        
        print(f"\n{AZUL}{NEGRITO}👪 FAMÍLIA{RESET}")
        print(f"  {BRANCO}Mãe:{RESET} {persona['nome_mae']}")
        print(f"  {BRANCO}Pai:{RESET} {persona['nome_pai']}")
        
        if persona['animais']:
            print(f"\n{AZUL}{NEGRITO}🐾 ANIMAIS DE ESTIMAÇÃO{RESET}")
            for animal in persona['animais']:
                print(f"  {BRANCO}•{RESET} {animal['nome']} ({animal['tipo']}) - {animal['idade']} anos")
        
        print(f"\n{AZUL}{NEGRITO}🎯 HOBBIES{RESET}")
        for hobby in persona['hobbies']:
            print(f"  {BRANCO}•{RESET} {hobby}")
        
        print(f"\n{AZUL}{NEGRITO}📱 REDES SOCIAIS{RESET}")
        for rede in persona['redes_sociais']:
            print(f"  {BRANCO}•{RESET} {rede['rede']}: {rede['usuario']}")
        
        print(f"\n{AZUL}{NEGRITO}📖 HISTÓRIA DE VIDA{RESET}")
        print(f"  {BRANCO}{persona['historia_vida']}{RESET}")

    def salvar_persona(self, persona):
        """Salva a persona em arquivo JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"persona_{persona['nome_completo'].replace(' ', '_')}_{timestamp}.json"
        
        # Criar diretório se não existir
        os.makedirs("personas_geradas", exist_ok=True)
        filepath = f"personas_geradas/{filename}"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(persona, f, indent=2, ensure_ascii=False)
        
        print(f"{VERDE}[✓] Persona salva em: {filepath}{RESET}")
        return filepath

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{CIANO}{NEGRITO}
   ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗ 
   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗
   ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║███████║██████╔╝
   ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗
   ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║██║  ██║██║  ██║
   ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
{RESET}
{MAGENTA}{NEGRITO}   GERADOR DE PERSONAS FICTÍCIAS v2.0
   Ferramenta para OSINT e Engenharia Social
{RESET}
{AMARELO}   Gera identidades completas e coerentes com:
   • Dados pessoais realistas • Histórias de vida • Redes sociais
   • Situação profissional • Hobbies • Animais de estimação
{RESET}""")

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}🎪 MENU PRINCIPAL{RESET}")
    print(f"{VERDE}[1]{RESET} 🎭 Gerar Persona Aleatória")
    print(f"{VERDE}[2]{RESET} 👶 Gerar Persona por Idade")
    print(f"{VERDE}[3]{RESET} 📊 Gerar Múltiplas Personas")
    print(f"{VERDE}[4]{RESET} 📖 Sobre a Ferramenta")
    print(f"{VERDE}[5]{RESET} 🚪 Sair")
    return input(f"\n{CIANO}🎯 Selecione uma opção: {RESET}")

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}📖 SOBRE O GERADOR DE PERSONAS{RESET}

{AMARELO}🎯 OBJETIVO:{RESET}
Criar identidades fictícias realistas para uso em:
• Testes de OSINT (Open Source Intelligence)
• Exercícios de engenharia social
• Desenvolvimento de sistemas
• Pesquisas acadêmicas

{AMARELO}🚀 CARACTERÍSTICAS:{RESET}
• Dados pessoais coerentes (CPF, RG, email, telefone)
• Situação profissional/estudo baseada na idade
• Histórias de vida realistas e consistentes
• Redes sociais e hobbies variados
• Animais de estimação (opcional)
• Família e endereço fictícios

{AMARELO}⚠️  USO ÉTICO:{RESET}
• Apenas para fins educacionais e legais
• Não usar para fraudes ou atividades ilegais
• Respeitar a privacidade e leis locais
• Manter o caráter fictício das personas

{VERDE}📞 Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        gerador = GeradorPersonaOSINT()
        
        while True:
            opcao = menu_principal()
            
            if opcao == '1':  # Persona aleatória
                banner()
                print(f"\n{AMARELO}[*] 🎭 Gerando persona aleatória...{RESET}")
                persona = gerador.gerar_persona_completa()
                gerador.mostrar_persona(persona)
                
                salvar = input(f"\n{CIANO}💾 Salvar persona? (S/N): {RESET}").lower()
                if salvar in ['s', 'sim']:
                    gerador.salvar_persona(persona)
                
                input(f"\n{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':  # Persona por idade
                banner()
                try:
                    idade = int(input(f"\n{CIANO}🎯 Digite a idade desejada (18-65): {RESET}"))
                    if 18 <= idade <= 65:
                        print(f"\n{AMARELO}[*] 👶 Gerando persona de {idade} anos...{RESET}")
                        persona = gerador.gerar_persona_completa(idade)
                        gerador.mostrar_persona(persona)
                        
                        salvar = input(f"\n{CIANO}💾 Salvar persona? (S/N): {RESET}").lower()
                        if salvar in ['s', 'sim']:
                            gerador.salvar_persona(persona)
                    else:
                        print(f"{VERMELHO}[!] Idade deve ser entre 18 e 65 anos{RESET}")
                except ValueError:
                    print(f"{VERMELHO}[!] Idade inválida{RESET}")
                
                input(f"\n{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':  # Múltiplas personas
                banner()
                try:
                    quantidade = int(input(f"\n{CIANO}🎯 Quantas personas gerar? (1-10): {RESET}"))
                    if 1 <= quantidade <= 10:
                        print(f"\n{AMARELO}[*] 📊 Gerando {quantidade} personas...{RESET}")
                        
                        for i in range(quantidade):
                            print(f"\n{CIANO}{NEGRITO}--- Persona {i+1} ---{RESET}")
                            persona = gerador.gerar_persona_completa()
                            gerador.mostrar_persona(persona)
                            
                            salvar = input(f"\n{CIANO}💾 Salvar esta persona? (S/N): {RESET}").lower()
                            if salvar in ['s', 'sim']:
                                gerador.salvar_persona(persona)
                            
                            if i < quantidade - 1:
                                input(f"\n{AMARELO}⏎ Próxima persona...{RESET}")
                    else:
                        print(f"{VERMELHO}[!] Quantidade deve ser entre 1 e 10{RESET}")
                except ValueError:
                    print(f"{VERMELHO}[!] Quantidade inválida{RESET}")
                
                input(f"\n{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':  # Sobre
                sobre()
            
            elif opcao == '5':  # Sair
                print(f"\n{VERDE}[+] 👋 Obrigado por usar o Gerador de Personas!{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] ❌ Opção inválida!{RESET}")
                input(f"{AMARELO}⏎ Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] 🚫 Programa interrompido{RESET}")
        exit()
    except Exception as e:
        print(f"{VERMELHO}[!] 💥 Erro inesperado: {e}{RESET}")
        exit()

if __name__ == "__main__":
    main()
