import time
import random
import sys
import textwrap
from datetime import datetime, timedelta

# Cores para o terminal
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    DARK_RED = '\033[31m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BACKGROUND_BLACK = '\033[40m'
    BACKGROUND_RED = '\033[41m'

# Animação de digitação
def type_effect(text, color=colors.WHITE, delay=0.03, new_line=True):
    print(color, end="")
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print(colors.RESET, end="\n" if new_line else "")
    time.sleep(0.3)

# Animação de loading
def loading_animation(seconds, message="Carregando"):
    print(f"{colors.GRAY}{message}", end="")
    for _ in range(seconds * 2):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print(colors.RESET)

# Limpar tela
def clear_screen():
    print("\033c", end="")

# Exibir citação filosófica
def citacao_filosofica():
    citacoes = [
        "Nietzsche: Aquele que tem um porquê para viver pode suportar quase qualquer como.",
        "Camus: No meio do inverno, descobri dentro de mim um verão invencível.",
        "Schopenhauer: A vida é um pêndulo que oscila entre a dor e o tédio.",
        "Sartre: O inferno são os outros.",
        "Kafka: O trabalho é uma prisão onde se esquece até mesmo dos próprios desejos.",
        "Dostoiévski: Sofrer e chorar significa viver.",
        "Cioran: Não é worth being born, mas uma vez que você está aqui, é melhor viver.",
        "Nietzsche: E aqueles que foram vistos dançando foram julgados insanos por aqueles que não podiam ouvir a música.",
        "Camus: Há apenas um problema filosófico verdadeiramente sério: o suicídio.",
        "Schopenhauer: A solidão é a sorte de todos os espíritos excepcionais.",
        "Kierkegaard: A vida só pode ser entendida olhando-se para trás; mas deve ser vivida para frente.",
        "Sêneca: Às vezes, mesmo viver é um ato de coragem.",
        "Platão: Uma vida não examinada não vale a pena ser vivida.",
        "Aristóteles: A excelência não é um ato, mas um hábito.",
        "Epicuro: Não estrague o que tem desejando o que não tem.",
    ]
    citacao = random.choice(citacoes)
    type_effect(f"\n{colors.GRAY}«{citacao}»{colors.RESET}", colors.GRAY)

# Diálogos internos e memórias
def dialogo_interno():
    dialogos = [
        "Por que continuar? Talvez a resposta esteja na própria pergunta.",
        "As cicatrizes não doem mais, mas a lembrança da dor permanece.",
        "Às vezes, sinto que estou apenas interpretando o papel de mim mesmo.",
        "O vazio dentro de mim parece ecoar mais alto nos dias silenciosos.",
        "Será que alguém notaria se eu simplesmente desaparecesse?",
        "As memórias são como fantasmas que se recusam a descansar.",
        "Aprendi a sorrir quando quero chorar, e isso me assusta.",
        "Cada pessoa carrega consigo um universo de dor invisível.",
        "As palavras não ditas doem mais do que as pronunciadas.",
        "Às vezes, a solidão é a única companhia que compreende.",
    ]
    dialogo = random.choice(dialogos)
    type_effect(f"\n{colors.PURPLE}«{dialogo}»{colors.RESET}", colors.PURPLE)

# Memórias traumáticas
def memoria_traumatica():
    memorias = [
        "Lembro-me de ter sete anos e me esconder no armário enquanto meus pais brigavam.",
        "O som de garrafas quebrando ainda me faz estremecer involuntariamente.",
        "Na escola, eles riam de minhas roupas velhas e de meu silêncio constante.",
        "Meu aniversário de dez anos: meus pais se esqueceram completamente.",
        "O primeiro soco que levei do meu pai: não doeu tanto quanto seu olhar de desprezo.",
        "Aprendi a andar silenciosamente pela casa para não ser notado.",
        "As promessas quebradas do meu pai ainda ecoam em minha mente.",
        "Minha mãe me chamando de 'fracasso' antes mesmo de eu ter chance de tentar.",
        "O vazio no estômago quando não havia comida em casa novamente.",
        "O médico perguntando como eu havia machucado o braço, e eu inventando uma história.",
    ]
    memoria = random.choice(memorias)
    type_effect(f"\n{colors.DARK_RED}✸ {memoria}{colors.RESET}", colors.DARK_RED)

# Pensamentos sobre Ju
def pensamento_ju():
    pensamentos = [
        "O sorriso de Ju era como um raio de sol em um dia nublado.",
        "Lembro-me de como ela franzia a testa quando se concentrava.",
        "Ela era a única que conseguia ver além da minha fachada fria.",
        "Seus olhos refletiam uma compreensão que palavras não podiam expressar.",
        "Às vezes, sinto seu perfume no ar, mesmo sabendo que é apenas minha memória.",
        "Ela me fez acreditar, mesmo que por um momento, que eu poderia ser amado.",
        "O som de sua risada ainda ecoa nos cantos mais silenciosos da minha mente.",
        "Por que ela se importou com alguém tão quebrado como eu?",
        "Se eu pudesse ter apenas mais cinco minutos com ela...",
        "Talvez eu não merecesse seu amor, mas isso não impediu que eu o desejasse.",
    ]
    pensamento = random.choice(pensamentos)
    type_effect(f"\n{colors.BLUE}♫ {pensamento}{colors.RESET}", colors.BLUE)

# Classe principal do jogo
class JogoDaVida:
    def __init__(self):
        self.dinheiro = 50
        self.prestigio = 0
        self.forca = 10
        self.saude_mental = 30
        self.dias = 0
        self.dia_final = 90  # 3 meses
        self.ju_amor = 0
        self.habilidades = {
            "boxe": 0,
            "muay_thai": 0,
            "musica": 0,
            "resistencia_mental": 0
        }
        self.nome_jogador = ""
        self.final_alcancado = False
        self.traumas_revelados = []
        self.eventos_especiais = {
            "encontro_inesperado": False,
            "revelacao_familia": False,
            "performance_publica": False,
            "crise_existencial": False
        }
        self.diario = []
        
    def mostrar_status(self):
        print(f"\n{colors.CYAN}╔══════════════════════════════════════╗")
        print(f"║              STATUS                ║")
        print(f"╚══════════════════════════════════════╝{colors.RESET}")
        print(f"{colors.YELLOW}📅 Dia: {self.dias}/{self.dia_final}{colors.RESET}")
        print(f"{colors.GREEN}💰 Dinheiro: R${self.dinheiro}{colors.RESET}")
        print(f"{colors.BLUE}⭐ Prestígio: {self.prestigio}/100{colors.RESET}")
        print(f"{colors.PURPLE}💪 Força: {self.forca}/100{colors.RESET}")
        print(f"{colors.RED}🧠 Saúde Mental: {self.saude_mental}/100{colors.RESET}")
        print(f"{colors.PURPLE}❤️  Amor da Ju: {self.ju_amor}/100{colors.RESET}")
        print(f"{colors.YELLOW}🥊 Boxe: {self.habilidades['boxe']}/10")
        print(f"🥋 Muay Thai: {self.habilidades['muay_thai']}/10")
        print(f"🎵 Música: {self.habilidades['musica']}/10")
        print(f"🧘 Resistência Mental: {self.habilidades['resistencia_mental']}/10{colors.RESET}")
        
    def adicionar_entrada_diario(self, texto):
        self.diario.append(f"Dia {self.dias}: {texto}")
        if len(self.diario) > 10:
            self.diario.pop(0)
            
    def ler_diario(self):
        clear_screen()
        type_effect(f"{colors.PURPLE}╔══════════════════════════════════════╗", colors.PURPLE)
        type_effect(f"║               DIÁRIO               ║", colors.PURPLE)
        type_effect(f"╚══════════════════════════════════════╝", colors.PURPLE)
        
        if not self.diario:
            type_effect("O diário está vazio...", colors.GRAY)
        else:
            for entrada in self.diario:
                type_effect(f"{entrada}", colors.PURPLE)
                
        input(f"\n{colors.GRAY}Pressione Enter para continuar...{colors.RESET}")
        
    def evento_aleatorio(self):
        eventos = [
            self.evento_pai_alcoolatra,
            self.evento_mae_toxica,
            self.evento_lembranca_ju,
            self.evento_depressao,
            self.evento_inspiracao,
            self.evento_memoria_traumatica,
            self.evento_encontro_inesperado,
            self.evento_crise_existencial
        ]
        random.choice(eventos)()
        
    def evento_pai_alcoolatra(self):
        type_effect(f"\n{colors.RED}╔══════════════════════════════════════╗", colors.RED)
        type_effect(f"║          EVENTO: Pai Alcoólatra         ║", colors.RED)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.RED)
        
        type_effect("Seu pai chegou bêbado em casa novamente...", colors.RED)
        type_effect("O cheiro de álcool preenche a casa antes mesmo dele abrir a porta.", colors.RED)
        type_effect("Ele começa a gritar e quebrar coisas.", colors.RED)
        type_effect("Você tenta se esconder, mas ele te encontra.", colors.RED)
        
        if self.habilidades["boxe"] + self.habilidades["muay_thai"] > 5:
            type_effect("Com suas habilidades de luta, você consegue se defender.", colors.GREEN)
            type_effect("Mas a situação drena sua energia mental.", colors.YELLOW)
            self.saude_mental -= 5
            self.forca += 2
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        else:
            type_effect("Você não consegue se defender adequadamente.", colors.RED)
            type_effect("Leva alguns golpes e fica com hematomas.", colors.RED)
            self.saude_mental -= 15
            self.forca -= 5
            
        type_effect("\n'Você não presta para nada! Um fracasso como eu!'", colors.RED)
        type_effect("— Ele grita antes de desmaiar embriagado.", colors.RED)
        
        memoria_traumatica()
        self.adicionar_entrada_diario("Pai chegou bêbado again. Por que não posso ter uma família normal?")
        
    def evento_mae_toxica(self):
        type_effect(f"\n{colors.PURPLE}╔══════════════════════════════════════╗", colors.PURPLE)
        type_effect(f"║           EVENTO: Mãe Tóxica          ║", colors.PURPLE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.PURPLE)
        
        type_effect("Sua mãe começa a comparar você com outros jovens...", colors.PURPLE)
        type_effect("'O filho da Maria passou em medicina...'", colors.PURPLE)
        type_effect("'O primo do seu amigo já tem carro...'", colors.PURPLE)
        type_effect("'Por que você não pode ser normal?'", colors.PURPLE)
        
        if self.saude_mental > 40 or self.habilidades["resistencia_mental"] > 3:
            type_effect("Você ignora os comentários, focando em seus objetivos.", colors.GREEN)
            type_effect("Isso te fortalece mentalmente.", colors.GREEN)
            self.saude_mental += 3
            self.prestigio += 2
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        else:
            type_effect("As palavras entram na sua mente como facas.", colors.RED)
            type_effect("Você questiona se realmente é capaz.", colors.RED)
            self.saude_mental -= 10
            
        type_effect("\n'Por que você não é normal? Por que não é como os outros?'", colors.PURPLE)
        type_effect("— Ela diz com desprezo antes de sair.", colors.PURPLE)
        
        dialogo_interno()
        self.adicionar_entrada_diario("Mãe comparing me to others again. Will I ever be enough?")
        
    def evento_lembranca_ju(self):
        type_effect(f"\n{colors.BLUE}╔══════════════════════════════════════╗", colors.BLUE)
        type_effect(f"║         EVENTO: Lembrança da Ju        ║", colors.BLUE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.BLUE)
        
        type_effect("Você se lembra do dia em que Ju terminou com você...", colors.BLUE)
        type_effect("'Eu preciso de alguém que pode estar comigo'", colors.BLUE)
        type_effect("'Você nunca pode sair, nunca pode me acompanhar...'", colors.BLUE)
        type_effect("'É muito difícil amar alguém que não se deixa amar'", colors.BLUE)
        
        if random.random() > 0.5 or self.habilidades["resistencia_mental"] > 4:
            type_effect("A lembrança te motiva a seguir em frente.", colors.GREEN)
            type_effect("Você se torna mais determinado.", colors.GREEN)
            self.ju_amor += 3
            self.prestigio += 5
        else:
            type_effect("A saudade dói profundamente.", colors.RED)
            type_effect("Você se questiona se vale a pena continuar.", colors.RED)
            self.saude_mental -= 8
            self.ju_amor += 5  # A dor aumenta o amor paradoxalmente
            
        type_effect("\n'Mas eu te amo...' — você sussurra para o vazio.", colors.BLUE)
        
        pensamento_ju()
        self.adicionar_entrada_diario("Lembrei de Ju hoje. Ainda dói. Será que ela pensa em mim?")
        
    def evento_depressao(self):
        type_effect(f"\n{colors.GRAY}╔══════════════════════════════════════╗", colors.GRAY)
        type_effect(f"║           EVENTO: Depressão           ║", colors.GRAY)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.GRAY)
        
        type_effect("Os demônios internos voltam a assombrar você...", colors.GRAY)
        type_effect("Qual o sentido de tudo isso?", colors.GRAY)
        type_effect("Por que continuar lutando?", colors.GRAY)
        type_effect("O vazio dentro de você parece expandir.", colors.GRAY)
        
        if self.saude_mental > 50 or self.habilidades["resistencia_mental"] > 5:
            type_effect("Você encontra força na raiva e na determinação.", colors.GREEN)
            type_effect("A escuridão te fortalece.", colors.GREEN)
            self.saude_mental -= 5
            self.forca += 5
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        else:
            type_effect("A vontade de desistir é quase irresistível.", colors.RED)
            type_effect("Você perde um dia inteiro na cama.", colors.RED)
            self.saude_mental -= 15
            self.dias += 1  # Perde um dia
            
        type_effect("\nNietzsche: Aquele que tem um porquê para viver pode suportar quase qualquer como.", colors.GRAY)
        type_effect("Mas você ainda não encontrou seu porquê...", colors.GRAY)
        
        dialogo_interno()
        self.adicionar_entrada_diario("Os dark thoughts estão voltando. É tão difícil levantar da cama.")
        
    def evento_inspiracao(self):
        type_effect(f"\n{colors.GREEN}╔══════════════════════════════════════╗", colors.GREEN)
        type_effect(f"║          EVENTO: Inspiração          ║", colors.GREEN)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.GREEN)
        
        type_effect("De repente, você tem um insight...", colors.GREEN)
        type_effect("Uma centelha de clareza mental.", colors.GREEN)
        type_effect("Por um momento, tudo faz sentido.", colors.GREEN)
        
        type_effect("\nCamus: No meio do inverno, descobri dentro de mim um verão invencível.", colors.GREEN)
        
        if random.random() > 0.3:
            type_effect("Você encontra forças para continuar.", colors.GREEN)
            self.saude_mental += 10
            self.prestigio += 5
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        else:
            type_effect("A inspiração é passageira, mas ajuda um pouco.", colors.YELLOW)
            self.saude_mental += 5
            
        citacao_filosofica()
        self.adicionar_entrada_diario("Tive um momento de clareza today. Talvez haja esperança.")
        
    def evento_memoria_traumatica(self):
        type_effect(f"\n{colors.DARK_RED}╔══════════════════════════════════════╗", colors.DARK_RED)
        type_effect(f"║       EVENTO: Memória Traumática      ║", colors.DARK_RED)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.DARK_RED)
        
        type_effect("Uma memória dolorosa volta à tona...", colors.DARK_RED)
        type_effect("Algo que você tentou enterrar no passado.", colors.DARK_RED)
        type_effect("As emoções são tão intensas quanto naquele dia.", colors.DARK_RED)
        
        memoria_traumatica()
        
        if self.habilidades["resistencia_mental"] > 4:
            type_effect("Você consegue processar a memória sem se despedaçar.", colors.GREEN)
            type_effect("Isso te fortalece emocionalmente.", colors.GREEN)
            self.saude_mental += 5
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 2)
        else:
            type_effect("A memória é avassaladora.", colors.RED)
            type_effect("Você precisa de tempo para se recuperar.", colors.RED)
            self.saude_mental -= 10
            
        dialogo_interno()
        self.adicionar_entrada_diario("Uma bad memory voltou today. Thought I had buried it forever.")
        
    def evento_encontro_inesperado(self):
        if self.eventos_especiais["encontro_inesperado"]:
            return
            
        type_effect(f"\n{colors.CYAN}╔══════════════════════════════════════╗", colors.CYAN)
        type_effect(f"║       EVENTO: Encontro Inesperado     ║", colors.CYAN)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.CYAN)
        
        type_effect("Você encontra Ju inesperadamente na rua...", colors.CYAN)
        type_effect("Ela parece diferente, mas ainda a mesma.", colors.CYAN)
        type_effect("Por um momento, seus olhos se encontram.", colors.CYAN)
        
        if self.prestigio < 30:
            type_effect("Ela desvia o olhar rapidamente e segue seu caminho.", colors.RED)
            type_effect("A rejeição dói mais do que você esperava.", colors.RED)
            self.saude_mental -= 10
            self.ju_amor += 5
        elif self.prestigio < 70:
            type_effect("Ela hesita, então dá um pequeno aceno antes de seguir.", colors.YELLOW)
            type_effect("Um pequeno sinal, mas significa tudo para você.", colors.YELLOW)
            self.saude_mental += 5
            self.ju_amor += 10
        else:
            type_effect("Ela para e conversa com você brevemente.", colors.GREEN)
            type_effect("'Você mudou...' - ela diz com um sorriso tímido.", colors.GREEN)
            self.saude_mental += 10
            self.ju_amor += 15
            self.prestigio += 10
            
        self.eventos_especiais["encontro_inesperado"] = True
        pensamento_ju()
        self.adicionar_entrada_diario("Vi Ju today. My heart still races when I see her.")
        
    def evento_crise_existencial(self):
        type_effect(f"\n{colors.PURPLE}╔══════════════════════════════════════╗", colors.PURPLE)
        type_effect(f"║       EVENTO: Crise Existencial      ║", colors.PURPLE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.PURPLE)
        
        type_effect("Questionamentos profundos assolam sua mente...", colors.PURPLE)
        type_effect("Qual o significado da existência?", colors.PURPLE)
        type_effect("Por que nascemos apenas para sofrer?", colors.PURPLE)
        type_effect("Há algum propósito em continuar?", colors.PURPLE)
        
        if self.habilidades["resistencia_mental"] > 6:
            type_effect("Você encontra conforto na aceitação do absurdo.", colors.GREEN)
            type_effect("A falta de sentido se torna sua liberdade.", colors.GREEN)
            self.saude_mental += 10
            self.prestigio += 8
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 2)
        else:
            type_effect("As questões são esmagadoras.", colors.RED)
            type_effect("Você se sente perdido em um universo indiferente.", colors.RED)
            self.saude_mental -= 15
            
        citacao_filosofica()
        dialogo_interno()
        self.adicionar_entrada_diario("Questioning everything today. What's the point of it all?")
        
    def treinar_boxe(self):
        type_effect(f"\n{colors.YELLOW}╔══════════════════════════════════════╗", colors.YELLOW)
        type_effect(f"║           Treino de Boxe            ║", colors.YELLOW)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.YELLOW)
        
        if self.dinheiro >= 20:
            type_effect("Você vai à academia de boxe e treina intensamente.", colors.YELLOW)
            type_effect("Cada soco no saco de pancadas é uma memória dolorosa.", colors.YELLOW)
            type_effect("Cada golpe é um pensamento tóxico sendo expulso.", colors.YELLOW)
            
            self.dinheiro -= 20
            self.habilidades["boxe"] = min(10, self.habilidades["boxe"] + 1)
            self.forca += 5
            self.prestigio += 3
            self.saude_mental -= 2
            
            if random.random() > 0.7:
                type_effect("Você tem um breakthrough técnico durante o treino!", colors.GREEN)
                self.habilidades["boxe"] = min(10, self.habilidades["boxe"] + 1)
                self.prestigio += 5
                
        else:
            type_effect("Você não tem dinheiro suficiente para treinar boxe.", colors.RED)
            type_effect("A frustração corrói um pouco sua determinação.", colors.RED)
            self.saude_mental -= 3
            
        self.adicionar_entrada_diario("Treino de boxe today. Hitting things helps with the anger.")
        
    def treinar_muay_thai(self):
        type_effect(f"\n{colors.RED}╔══════════════════════════════════════╗", colors.RED)
        type_effect(f"║          Treino de Muay Thai         ║", colors.RED)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.RED)
        
        if self.dinheiro >= 25:
            type_effect("Você vai ao dojo de Muay Thai e treina com intensidade.", colors.RED)
            type_effect("Os chutes e joelhadas liberam a raiva acumulada.", colors.RED)
            type_effect("A dor física substitui temporariamente a dor emocional.", colors.RED)
            
            self.dinheiro -= 25
            self.habilidades["muay_thai"] = min(10, self.habilidades["muay_thai"] + 1)
            self.forca += 7
            self.prestigio += 4
            self.saude_mental -= 3
            
            if random.random() > 0.7:
                type_effect("Você domina uma nova técnica complexa!", colors.GREEN)
                self.habilidades["muay_thai"] = min(10, self.habilidades["muay_thai"] + 1)
                self.prestigio += 5
                
        else:
            type_effect("Você não tem dinheiro suficiente para treinar Muay Thai.", colors.RED)
            type_effect("A impotência financeira aumenta sua raiva.", colors.RED)
            self.saude_mental -= 4
            
        self.adicionar_entrada_diario("Muay Thai session. The pain reminds me I'm still alive.")
        
    def praticar_musica(self):
        type_effect(f"\n{colors.BLUE}╔══════════════════════════════════════╗", colors.BLUE)
        type_effect(f"║          Prática de Música          ║", colors.BLUE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.BLUE)
        
        if self.dinheiro >= 15:
            type_effect("Você pega seu instrumento e compõe músicas angustiadas.", colors.BLUE)
            type_effect("As notas ecoam sua dor existencial.", colors.BLUE)
            type_effect("A melodia expressa o que palavras não podem dizer.", colors.BLUE)
            
            self.dinheiro -= 15
            self.habilidades["musica"] = min(10, self.habilidades["musica"] + 1)
            self.prestigio += 5
            self.saude_mental += 5
            
            if random.random() > 0.7:
                type_effect("Você compõe uma peça profundamente emocional!", colors.GREEN)
                self.habilidades["musica"] = min(10, self.habilidades["musica"] + 1)
                self.prestigio += 8
                self.saude_mental += 5
                
        else:
            type_effect("Você não tem dinheiro suficiente para praticar música.", colors.RED)
            type_effect("A criatividade parece murchar sem recursos.", colors.RED)
            self.saude_mental -= 2
            
        self.adicionar_entrada_diario("Played music today. It's the only language that understands me.")
        
    def trabalhar(self):
        type_effect(f"\n{colors.GREEN}╔══════════════════════════════════════╗", colors.GREEN)
        type_effect(f"║               Trabalho              ║", colors.GREEN)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.GREEN)
        
        type_effect("Você trabalha em um emprego cansativo e mal pago.", colors.GREEN)
        type_effect("Horas intermináveis de esforço monótono.", colors.GREEN)
        
        ganho = random.randint(30, 50)
        self.dinheiro += ganho
        self.saude_mental -= 5
        
        type_effect(f"Você ganhou R${ganho}, mas perdeu um pouco de sanidade.", colors.GREEN)
        
        if random.random() > 0.8:
            type_effect("Um cliente especialmente rude testa sua paciência.", colors.RED)
            self.saude_mental -= 5
            type_effect("Você respira fundo e mantém a compostura.", colors.YELLOW)
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
            
        citacao_filosofica()
        self.adicionar_entrada_diario("Another day at work. Selling my time for scraps.")
        
    def descansar(self):
        type_effect(f"\n{colors.PURPLE}╔══════════════════════════════════════╗", colors.PURPLE)
        type_effect(f"║               Descanso              ║", colors.PURPLE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.PURPLE)
        
        type_effect("Você tenta descansar e recuperar energias.", colors.PURPLE)
        type_effect("O silêncio permite que seus pensamentos ecoem.", colors.PURPLE)
        
        recuperacao = random.randint(5, 15)
        self.saude_mental += recuperacao
        
        type_effect(f"Você recuperou {recuperacao} de saúde mental.", colors.PURPLE)
        
        if random.random() > 0.6:
            dialogo_interno()
            
        if random.random() > 0.8:
            memoria_traumatica()
            type_effect("O descanso trouxe memórias não convidadas.", colors.RED)
            self.saude_mental -= 5
            
        citacao_filosofica()
        self.adicionar_entrada_diario("Tried to rest today. Even silence is loud sometimes.")
        
    def meditar(self):
        type_effect(f"\n{colors.CYAN}╔══════════════════════════════════════╗", colors.CYAN)
        type_effect(f"║               Meditar               ║", colors.CYAN)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.CYAN)
        
        type_effect("Você tenta encontrar paz através da meditação.", colors.CYAN)
        type_effect("Observar os pensamentos sem se apegar a eles.", colors.CYAN)
        
        if self.habilidades["resistencia_mental"] < 3:
            type_effect("É difícil acalmar a mente agitada.", colors.YELLOW)
            recuperacao = random.randint(3, 8)
            self.saude_mental += recuperacao
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        else:
            type_effect("Você encontra um momento de paz interior.", colors.GREEN)
            recuperacao = random.randint(10, 20)
            self.saude_mental += recuperacao
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 2)
            
        type_effect(f"Você recuperou {recuperacao} de saúde mental.", colors.CYAN)
        
        if random.random() > 0.7:
            type_effect("Um insight profundo surge durante a meditação.", colors.GREEN)
            self.prestigio += 5
            
        dialogo_interno()
        self.adicionar_entrada_diario("Meditated today. For a moment, the chaos inside quieted down.")
        
    def escrever(self):
        type_effect(f"\n{colors.BLUE}╔══════════════════════════════════════╗", colors.BLUE)
        type_effect(f"║               Escrever              ║", colors.BLUE)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.BLUE)
        
        type_effect("Você coloca suas emoções no papel.", colors.BLUE)
        type_effect("As palavras fluem como sangue de feridas abertas.", colors.BLUE)
        
        self.saude_mental += 8
        self.prestigio += 3
        self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 1)
        
        if random.random() > 0.6:
            type_effect("Você produz um texto profundamente comovente.", colors.GREEN)
            self.prestigio += 7
            self.habilidades["musica"] = min(10, self.habilidades["musica"] + 1)
            
        dialogo_interno()
        citacao_filosofica()
        self.adicionar_entrada_diario("Wrote today. Putting pain into words makes it more bearable.")
        
    def procurar_ju(self):
        type_effect(f"\n{colors.CYAN}╔══════════════════════════════════════╗", colors.CYAN)
        type_effect(f"║          Procurando por Ju          ║", colors.CYAN)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.CYAN)
        
        type_effect("Você procura por Ju, esperando um sinal de reconciliação.", colors.CYAN)
        
        if self.prestigio < 30:
            type_effect("Você tenta encontrar Ju, mas ela evita contato.", colors.RED)
            type_effect("'Por favor, me deixe em paz' — ela diz rapidamente.", colors.RED)
            self.ju_amor -= 5
            self.saude_mental -= 10
        elif self.prestigio < 70:
            type_effect("Você encontra Ju, mas ela ainda está hesitante.", colors.YELLOW)
            type_effect("'Você mudou... mas ainda preciso de tempo' — ela diz.", colors.YELLOW)
            self.ju_amor += 5
            self.saude_mental += 3
        else:
            type_effect("Ju parece impressionada com sua transformação.", colors.GREEN)
            type_effect("'Você realmente mudou...' — ela diz com um sorriso tímido.", colors.GREEN)
            self.ju_amor += 10
            self.saude_mental += 8
            self.prestigio += 5
            
        pensamento_ju()
        self.adicionar_entrada_diario("Tried to see Ju today. My heart can't decide between hope and fear.")
        
    def passar_dia(self):
        self.dias += 1
        self.saude_mental -= 2  # Desgaste diário
        
        # Evento aleatório a cada 3 dias
        if self.dias % 3 == 0:
            self.evento_aleatorio()
            
        # Eventos especiais em dias específicos
        if self.dias == 30 and not self.eventos_especiais["revelacao_familia"]:
            self.evento_revelacao_familia()
            
        if self.dias == 60 and not self.eventos_especiais["performance_publica"]:
            self.evento_performance_publica()
            
    def evento_revelacao_familia(self):
        self.eventos_especiais["revelacao_familia"] = True
        
        type_effect(f"\n{colors.DARK_RED}╔══════════════════════════════════════╗", colors.DARK_RED)
        type_effect(f"║       EVENTO: Revelação Familiar     ║", colors.DARK_RED)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.DARK_RED)
        
        type_effect("Você descobre um segredo de família perturbador...", colors.DARK_RED)
        type_effect("Cartas escondidas revelam verdades dolorosas.", colors.DARK_RED)
        type_effect("O alcoolismo do seu pai tem raízes mais profundas.", colors.DARK_RED)
        type_effect("A toxicidade da sua mãe vem de sua própria infância roubada.", colors.DARK_RED)
        
        type_effect("\n'Às vezes, as pessoas machucam outras porque estão machucadas.'", colors.DARK_RED)
        type_effect("— Você reflete, com uma mistura de raiva e compreensão.", colors.DARK_RED)
        
        if self.habilidades["resistencia_mental"] > 5:
            type_effect("Você consegue processar a revelação com maturidade.", colors.GREEN)
            type_effect("A compreensão traz uma paz amarga.", colors.GREEN)
            self.saude_mental += 5
            self.habilidades["resistencia_mental"] = min(10, self.habilidades["resistencia_mental"] + 2)
            self.prestigio += 10
        else:
            type_effect("A revelação é esmagadora.", colors.RED)
            type_effect("Novas perguntas surgem sem respostas.", colors.RED)
            self.saude_mental -= 15
            
        memoria_traumatica()
        dialogo_interno()
        self.adicionar_entrada_diario("Discovered family secrets today. The roots of our pain run deep.")
        
    def evento_performance_publica(self):
        self.eventos_especiais["performance_publica"] = True
        
        type_effect(f"\n{colors.YELLOW}╔══════════════════════════════════════╗", colors.YELLOW)
        type_effect(f"║       EVENTO: Performance Pública     ║", colors.YELLOW)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.YELLOW)
        
        type_effect("Você tem a oportunidade de se apresentar publicamente.", colors.YELLOW)
        type_effect("Uma chance de mostrar sua música ou habilidades marciais.", colors.YELLOW)
        
        if self.habilidades["musica"] > 5 or (self.habilidades["boxe"] + self.habilidades["muay_thai"]) > 8:
            type_effect("Sua performance é impressionante.", colors.GREEN)
            type_effect("Pessoas começam a notar sua dedicação e talento.", colors.GREEN)
            self.prestigio += 20
            self.saude_mental += 10
            self.dinheiro += 50
            
            if random.random() > 0.5:
                type_effect("Ju está na plateia e parece impressionada.", colors.BLUE)
                self.ju_amor += 15
        else:
            type_effect("Você não está preparado o suficiente.", colors.RED)
            type_effect("A performance é medíocre e embaraçosa.", colors.RED)
            self.prestigio -= 10
            self.saude_mental -= 15
            
        citacao_filosofica()
        self.adicionar_entrada_diario("Public performance today. Felt exposed but alive.")
        
    def verificar_fim_de_jogo(self):
        if self.saude_mental <= 0:
            self.final_suicidio()
            return True
            
        if self.dias >= self.dia_final:
            if self.prestigio >= 100:
                self.final_sucesso_tragico()
            else:
                self.final_fracasso()
            return True
            
        return False
        
    def final_suicidio(self):
        clear_screen()
        type_effect(f"{colors.RED}╔══════════════════════════════════════╗", colors.RED, 0.05)
        type_effect(f"║       FINAL: O Silêncio Eterno       ║", colors.RED, 0.05)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.RED, 0.05)
        
        type_effect("A dor se tornou insuportável.", colors.RED, 0.05)
        type_effect("Os demônios internos venceram a batalha.", colors.RED, 0.05)
        type_effect("Você não encontrou forças para continuar.", colors.RED, 0.05)
        type_effect("O peso de existir superou o medo de não existir.", colors.RED, 0.05)
        
        type_effect("\nCamus: Há apenas um problema filosófico verdadeiramente sério: o suicídio.", colors.GRAY, 0.05)
        type_effect("Julgar se a vida vale ou não vale a pena ser vivida é responder à pergunta fundamental da filosofia.", colors.GRAY, 0.05)
        
        type_effect("\nVocê encontrou sua resposta.", colors.RED, 0.05)
        type_effect("Nas suas notas, uma última mensagem:", colors.RED, 0.05)
        type_effect("\n'Ju, não foi o suficiente. Nada é.'", colors.RED, 0.05)
        type_effect("'O vazio consome tudo.'", colors.RED, 0.05)
        type_effect("'Perdoem-me por não ser forte o bastante.'", colors.RED, 0.05)
        
        type_effect(f"\n{self.nome_jogador} (17 anos) - Causa da morte: suicídio", colors.RED, 0.05)
        type_effect("A vida não tem sentido inerente. Às vezes, a única saída é a saída final.", colors.GRAY, 0.05)
        
        type_effect("\nJogo criado por Erik", colors.WHITE, 0.05)
        self.final_alcancado = True
        
    def final_fracasso(self):
        clear_screen()
        type_effect(f"{colors.RED}╔══════════════════════════════════════╗", colors.RED, 0.05)
        type_effect(f"║     FINAL: O Fracasso Inevitável     ║", colors.RED, 0.05)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.RED, 0.05)
        
        type_effect("O tempo se esgotou.", colors.RED, 0.05)
        type_effect("Você não conseguiu alcançar o prestígio necessário.", colors.RED, 0.05)
        type_effect("Ju segue sua vida sem você.", colors.RED, 0.05)
        type_effect("As oportunidades se perderam no mar do tempo.", colors.RED, 0.05)
        
        type_effect("\nNietzsche: O que não me destrói me fortalece.", colors.GRAY, 0.05)
        type_effect("Mas algumas coisas nos destroem por dentro, lentamente.", colors.GRAY, 0.05)
        type_effect("Sem nos matar completamente, nos deixam meio vivos.", colors.GRAY, 0.05)
        
        type_effect("\nVocê se torna como seu pai: um homem amargurado e derrotado.", colors.RED, 0.05)
        type_effect("A cada dia, um gole de álcool para afogar as memórias.", colors.RED, 0.05)
        type_effect("A cada noite, o fantasma do que poderia ter sido.", colors.RED, 0.05)
        
        type_effect("\n'Ju me mostrou que poderia ser diferente...'", colors.RED, 0.05)
        type_effect("'...mas no fim, eu era apenas mais um fracassado.'", colors.RED, 0.05)
        
        type_effect("\nA vida é absurda e indiferente ao nosso sofrimento.", colors.GRAY, 0.05)
        type_effect("Jogo criado por Erik", colors.WHITE, 0.05)
        self.final_alcancado = True
        
    def final_sucesso_tragico(self):
        clear_screen()
        type_effect(f"{colors.BLUE}╔══════════════════════════════════════╗", colors.BLUE, 0.05)
        type_effect(f"║        FINAL: A Vitória Amarga       ║", colors.BLUE, 0.05)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.BLUE, 0.05)
        
        type_effect("Você conseguiu.", colors.BLUE, 0.05)
        type_effect("Transformou-se em alguém forte, respeitado.", colors.BLUE, 0.05)
        type_effect("Alcançou prestígio, domina artes marciais, compõe músicas.", colors.BLUE, 0.05)
        type_effect("Superou muitos dos demônios que o assombravam.", colors.BLUE, 0.05)
        
        type_effect("\nVocê encontra Ju, finalmente.", colors.BLUE, 0.05)
        type_effect("Ela está com outro.", colors.RED, 0.05)
        type_effect("'Você mudou muito...'", colors.RED, 0.05)
        type_effect("'...mas eu segui em frente.'", colors.RED, 0.05)
        type_effect("'Algumas coisas não podem ser consertadas.'", colors.RED, 0.05)
        
        type_effect("\nSartre: O inferno são os outros.", colors.GRAY, 0.05)
        type_effect("Mas o inferno também é estar sozinho consigo mesmo.", colors.GRAY, 0.05)
        type_effect("É carregar o peso de transformações que chegaram tarde demais.", colors.GRAY, 0.05)
        
        type_effect("\nVocê conquistou tudo o que precisava.", colors.BLUE, 0.05)
        type_effect("Exceto a única coisa que realmente queria.", colors.BLUE, 0.05)
        
        type_effect("\nA ironia cruel da existência:", colors.GRAY, 0.05)
        type_effect("Às vezes, chegamos ao topo da montanha apenas para descobrir", colors.GRAY, 0.05)
        type_effect("que o que procurávamos estava no vale que deixamos para trás.", colors.GRAY, 0.05)
        
        type_effect("\nJogo criado por Erik", colors.WHITE, 0.05)
        self.final_alcancado = True
        
    def jogar(self):
        clear_screen()
        
        # Introdução
        type_effect(f"{colors.RED}╔══════════════════════════════════════╗", colors.RED, 0.05)
        type_effect(f"║           SOMBRAS E ACORDES           ║", colors.RED, 0.05)
        type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.RED, 0.05)
        type_effect("Um jogo sobre dor, amor e existência", colors.GRAY, 0.05)
        type_effect("Criado por Erik", colors.WHITE, 0.05)
        
        loading_animation(3, "Iniciando")
        
        clear_screen()
        type_effect("Você tem 17 anos.", colors.YELLOW)
        type_effect("Odeia pessoas. Odeia falsidade. Odeia a si mesmo.", colors.YELLOW)
        type_effect("Seu pai é um alcoólatra violento.", colors.RED)
        type_effect("Sua mãe é tóxica e manipuladora.", colors.PURPLE)
        type_effect("Ju era sua única luz...", colors.BLUE)
        type_effect("...até terminar com você porque não podia sair.", colors.BLUE)
        type_effect("Agora, você tem 90 dias para mudar.", colors.GREEN)
        type_effect("Para conseguir prestígio, para torná-la orgulhosa.", colors.GREEN)
        type_effect("Para tentar reconquistá-la.", colors.GREEN)
        type_effect("Mas lembre-se: mesmo as histórias de amor", colors.GRAY)
        type_effect("podem terminar em tragédia.", colors.GRAY)
        
        type_effect("\nSchopenhauer: A vida é um pêndulo que oscila entre a dor e o tédio.", colors.GRAY)
        
        self.nome_jogador = input(f"\n{colors.CYAN}Qual seu nome? {colors.RESET}")
        
        # Loop principal do jogo
        while not self.final_alcancado:
            clear_screen()
            
            # Mostrar dias restantes
            dias_restantes = self.dia_final - self.dias
            type_effect(f"{colors.YELLOW}╔══════════════════════════════════════╗", colors.YELLOW)
            type_effect(f"║         Dia {self.dias + 1} | Dias restantes: {dias_restantes}        ║", colors.YELLOW)
            type_effect(f"╚══════════════════════════════════════╝{colors.RESET}", colors.YELLOW)
            
            self.mostrar_status()
            
            # Menu de ações
            type_effect(f"\n{colors.CYAN}O que você faz hoje?{colors.RESET}")
            type_effect("1. Treinar Boxe (R$20)")
            type_effect("2. Treinar Muay Thai (R$25)")
            type_effect("3. Praticar Música (R$15)")
            type_effect("4. Trabalhar")
            type_effect("5. Descansar")
            type_effect("6. Meditar")
            type_effect("7. Escrever")
            type_effect("8. Procurar Ju")
            type_effect("9. Ler Diário")
            type_effect("0. Reflexão Existencial")
            
            escolha = input(f"\n{colors.CYAN}Sua escolha (0-9): {colors.RESET}")
            
            if escolha == "1":
                self.treinar_boxe()
            elif escolha == "2":
                self.treinar_muay_thai()
            elif escolha == "3":
                self.praticar_musica()
            elif escolha == "4":
                self.trabalhar()
            elif escolha == "5":
                self.descansar()
            elif escolha == "6":
                self.meditar()
            elif escolha == "7":
                self.escrever()
            elif escolha == "8":
                self.procurar_ju()
            elif escolha == "9":
                self.ler_diario()
                continue
            elif escolha == "0":
                self.evento_depressao()
            else:
                type_effect("Você perde o dia em indecisão existencial.", colors.RED)
                self.saude_mental -= 3
                self.adicionar_entrada_diario("Wasted day paralyzed by indecision.")
                
            self.passar_dia()
            
            # Verificar fim de jogo
            if self.verificar_fim_de_jogo():
                break
                
            input(f"\n{colors.GRAY}Pressione Enter para continuar...{colors.RESET}")

# Executar o jogo
if __name__ == "__main__":
    jogo = JogoDaVida()
    jogo.jogar()
