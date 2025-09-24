#!/usr/bin/env python3
"""
PolyTools - Créditos Finais
Script de pós-créditos com animações estilo Marvel
"""

import os
import sys
import time
import random
from datetime import datetime

try:
    import curses
except ImportError:
    print("Instalando dependência necessária...")
    os.system("pip install windows-curses" if os.name == 'nt' else "pip install curses")
    import curses

class Creditos:
    def __init__(self):
        self.largura = 80
        self.altura = 24
        self.delay_base = 0.05
        self.delay_rapido = 0.02
        self.delay_lento = 0.1
        
    def inicializar_tela(self):
        """Inicializa a tela do curses"""
        self.tela = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.curs_set(0)
        self.tela.keypad(1)
        self.tela.timeout(100)
        
        # Configurar cores
        curses.init_pair(1, curses.COLOR_RED, -1)      # Vermelho - Destaque
        curses.init_pair(2, curses.COLOR_YELLOW, -1)   # Amarelo - Títulos
        curses.init_pair(3, curses.COLOR_CYAN, -1)     # Ciano - Nomes
        curses.init_pair(4, curses.COLOR_GREEN, -1)    # Verde - Sucesso
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Magenta - Especial
        curses.init_pair(6, curses.COLOR_WHITE, -1)    # Branco - Texto normal
        
    def finalizar_tela(self):
        """Finaliza a tela do curses"""
        curses.endwin()
        
    def centralizar_texto(self, texto, linha=None):
        """Centraliza texto na tela"""
        if linha is None:
            linha = self.altura // 2
        coluna = (self.largura - len(texto)) // 2
        return linha, coluna
        
    def digitar_texto(self, texto, linha, coluna, delay=None, cor=6):
        """Efeito de digitação"""
        if delay is None:
            delay = self.delay_base
            
        self.tela.attron(curses.color_pair(cor))
        for i, char in enumerate(texto):
            try:
                self.tela.addstr(linha, coluna + i, char)
                self.tela.refresh()
                time.sleep(delay)
                
                # Verificar se usuário quer pular
                if self.tela.getch() == ord(' '):
                    self.tela.addstr(linha, coluna, texto)
                    self.tela.refresh()
                    break
            except:
                pass
        self.tela.attroff(curses.color_pair(cor))
        
    def efeito_estrelas(self, quantidade=50):
        """Efeito de estrelas caindo"""
        estrelas = []
        for _ in range(quantidade):
            x = random.randint(0, self.largura - 1)
            y = random.randint(0, self.altura - 1)
            velocidade = random.uniform(0.01, 0.05)
            estrelas.append((x, y, velocidade))
            
        for _ in range(20):
            for i, (x, y, vel) in enumerate(estrelas):
                try:
                    self.tela.addch(int(y), int(x), '*', curses.A_BOLD)
                    estrelas[i] = (x, (y + vel) % self.altura, vel)
                except:
                    pass
            self.tela.refresh()
            time.sleep(0.1)
            self.tela.clear()
            
    def mostrar_logo_polytools(self):
        """Mostra logo do PolyTools"""
        logo = [
            "╔══════════════════════════════════════════════════════════════════════════╗",
            "║                                                                          ║",
            "║    ██████╗  ██████╗ ██╗  ██╗   ██╗████████╗ ██████╗  ██████╗ ███████╗   ║",
            "║    ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██╔════╝   ║",
            "║    ██████╔╝██║   ██║██║   ╚████╔╝    ██║   ██║   ██║██║   ██║███████╗   ║",
            "║    ██╔═══╝ ██║   ██║██║    ╚██╔╝     ██║   ██║   ██║██║   ██║╚════██║   ║",
            "║    ██║     ╚██████╔╝███████╗██║      ██║   ╚██████╔╝╚██████╔╝███████║   ║",
            "║    ╚═╝      ╚═════╝ ╚══════╝╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝   ║",
            "║                                                                          ║",
            "║                            🐺 WOLFPACK EDITION 🐺                       ║",
            "║                                                                          ║",
            "╚══════════════════════════════════════════════════════════════════════════╝"
        ]
        
        self.tela.clear()
        for i, linha in enumerate(logo):
            try:
                linha_centro = (self.altura - len(logo)) // 2 + i
                coluna_centro = (self.largura - len(linha)) // 2
                self.tela.addstr(linha_centro, coluna_centro, linha, curses.color_pair(1))
            except:
                pass
        self.tela.refresh()
        time.sleep(2)
        
    def animacao_lobo(self):
        """Animação do lobo solitário"""
        frames = [
            [
                "    ████████████████    ",
                "  ██                ██  ",
                " ██    ██      ██    ██ ",
                "██    ████████████    ██",
                "██    ██  ████  ██    ██",
                "██    ██  ████  ██    ██",
                " ██    ████████████  ██ ",
                "  ██              ████  ",
                "    ████████████████    "
            ],
            [
                "    ████████████████    ",
                "  ██                ██  ",
                " ██    ██      ██    ██ ",
                "██    ████████████    ██",
                "██    ██  ████  ██    ██",
                "██    ██  ████  ██    ██",
                " ██    ████████████  ██ ",
                "  ██                ██  ",
                "    ████████████████    "
            ]
        ]
        
        for frame in frames * 3:  # Repetir animação 3 vezes
            self.tela.clear()
            for i, linha in enumerate(frame):
                try:
                    linha_centro = (self.altura - len(frame)) // 2 + i
                    coluna_centro = (self.largura - len(linha)) // 2
                    self.tela.addstr(linha_centro, coluna_centro, linha, curses.color_pair(3))
                except:
                    pass
            self.tela.refresh()
            time.sleep(0.3)
            
    def mostrar_creditos(self):
        """Mostra os créditos principais"""
        creditos = [
            ("POLYTOOLS - WOLFPACK ANALYZER", 2),
            (" ", 6),
            ("DESENVOLVIMENTO E LIDERANÇA", 2),
            ("Erik lagosta", 3),
            (" ", 6),
            ("CONTRIBUIÇÕES ESPECIAIS", 2),
            ("Comunidade PolyTools", 3),
            ("Testadores Beta", 3),
            ("Contribuidores Open Source", 3),
            (" ", 6),
            ("AGRADECIMENTOS ESPECIAIS", 2),
            ("Você - Por usar nossa ferramenta!", 4),
            ("Comunidade de Segurança Digital", 3),
            ("Desenvolvedores Python", 3),
        ]
        
        self.tela.clear()
        
        # Efeito de estrelas inicial
        self.efeito_estrelas(30)
        
        # Rolagem dos créditos
        posicao_inicial = self.altura
        for texto, cor in creditos:
            linha, coluna = self.centralizar_texto(texto, posicao_inicial)
            self.digitar_texto(texto, linha, coluna, self.delay_lento, cor)
            posicao_inicial += 2
            
            # Verificar se usuário quer pular
            if self.tela.getch() == ord(' '):
                break
                
        time.sleep(2)
        
    def historia_erik(self):
        """Conta a história do Erik e sua jornada"""
        historia = [
            "EM 2025...",
            " ",
            "Um desenvolvedor apaixonado por tecnologia,",
            "Erik Ferreira, começou uma jornada...",
            " ",
            "Com pouca experiência em segurança digital,",
            "mas muita determinação e curiosidade,",
            "ele decidiu criar algo que fizesse diferença.",
            " ",
            "Assim nasceu o PolyTools - WolfPack Analyzer,",
            "uma ferramenta para democratizar o acesso",
            "à análise de redes e segurança.",
            " ",
            "Mesmo 'não sendo nada na área' inicialmente,",
            "qualquer um pode fazer a diferença."
        ]
        
        self.tela.clear()
        self.tela.addstr(0, 0, "🎮 A JORNADA DO ERIK 🎮", curses.color_pair(2) | curses.A_BOLD)
        
        for i, linha in enumerate(historia, 2):
            try:
                self.digitar_texto(linha, i, (self.largura - len(linha)) // 2, self.delay_base, 6)
            except:
                pass
            time.sleep(0.5)
            
        time.sleep(3)
        
    def redes_sociais(self):
        """Mostra redes sociais e contatos"""
        redes = [
            "🌐 REDES SOCIAIS E CONTATOS 🌐",
            " ",
            "📷 Instagram: @erikmxp",
            "📹 YouTube: PolyTools Oficial",
            "💻 GitHub: github.com/pythoandtrojan",
            "📧 Email: eeu31471@gmail.com",
            " ",
            "🔗 Nos acompanhe para mais atualizações!",
            "⭐ Deixe uma estrela no repositório!",
            "🐛 Reporte bugs e sugira melhorias!"
        ]
        
        self.tela.clear()
        
        for i, linha in enumerate(redes):
            try:
                linha_pos = (self.altura - len(redes)) // 2 + i
                coluna_pos = (self.largura - len(linha)) // 2
                cor = 2 if i == 0 else (3 if i in [3, 4, 5] else 6)
                self.digitar_texto(linha, linha_pos, coluna_pos, self.delay_base, cor)
            except:
                pass
            time.sleep(0.3)
            
        time.sleep(3)
        
    def mensagem_inspiradora(self):
        """Mensagem final inspiradora"""
        mensagens = [
            "A jornada de mil milhas começa com um único passo...",
            " ",
            "Não importa de onde você vem,",
            "mas para onde você quer chegar.",
            " ",
            "A segurança digital é um direito de todos,",
            "não um privilégio de poucos.",
            " ",
            "Continue aprendendo, continue explorando,",
            "continue fazendo a diferença!",
            " ",
            "🐺 O lobo solitário caça, mas a alcateia prospera! 🐺"
        ]
        
        self.tela.clear()
        
        for i, linha in enumerate(mensagens):
            try:
                linha_pos = (self.altura - len(mensagens)) // 2 + i
                coluna_pos = (self.largura - len(linha)) // 2
                cor = 1 if "lobo" in linha else (2 if i == 0 else 6)
                self.digitar_texto(linha, linha_pos, coluna_pos, self.delay_lento, cor)
            except:
                pass
            time.sleep(0.5)
            
    def cena_pos_creditos(self):
        """Cena especial pós-créditos (como nos filmes da Marvel)"""
        self.tela.clear()
        
        # Mistério...
        self.digitar_texto("ALGUM TEMPO DEPOIS...", 5, self.centralizar_texto("ALGUM TEMPO DEPOIS...")[1], self.delay_base, 1)
        time.sleep(2)
        
        self.digitar_texto("Em um servidor distante...", 7, self.centralizar_texto("Em um servidor distante...")[1], self.delay_base, 6)
        time.sleep(2)
        
        # Revelação
        revelacao = [
            "NOVAS FERRAMENTAS ESTÃO A CAMINHO!",
            " ",
            "🐺 WolfPack Suite - Em desenvolvimento",
            "🔒 CryptoShield - vale a pena?",
            "🌐 WebSentinel - Em planejamento",
            " ",
            "A revolução PolyTools apenas começou..."
        ]
        
        for i, linha in enumerate(revelacao):
            try:
                self.digitar_texto(linha, 10 + i, self.centralizar_texto(linha)[1], self.delay_base, 5 if i == 0 else 3)
            except:
                pass
            time.sleep(0.5)
            
        time.sleep(3)
        
    def executar(self):
        """Executa a sequência completa de créditos"""
        try:
            self.inicializar_tela()
            
            # Sequência de animações
            self.mostrar_logo_polytools()
            self.animacao_lobo()
            self.mostrar_creditos()
            self.historia_erik()
            self.redes_sociais()
            self.mensagem_inspiradora()
            self.cena_pos_creditos()
            
            # Mensagem final
            self.tela.clear()
            linha_final = "OBRIGADO POR USAR POLYTOOLS! 🐺"
            linha, coluna = self.centralizar_texto(linha_final)
            self.digitar_texto(linha_final, linha, coluna, self.delay_base, 1)
            
            time.sleep(2)
            
            # Instrução para sair
            sair_msg = "Pressione qualquer tecla para sair..."
            linha, coluna = self.centralizar_texto(sair_msg, self.altura - 2)
            self.tela.addstr(linha, coluna, sair_msg, curses.color_pair(4))
            self.tela.refresh()
            
            self.tela.getch()
            
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Erro durante os créditos: {e}")
        finally:
            self.finalizar_tela()

def main():
    """Função principal"""
    print("🐺 Iniciando Créditos do PolyTools...")
    print("Pressione ESPAÇO durante a animação para pular partes")
    time.sleep(2)
    
    creditos = Creditos()
    creditos.executar()
    
    print("\n🎉 Créditos finalizados!")
    print("Siga-nos nas redes sociais:")
    print("📷 Instagram: @erikmxp")
    print("📹 YouTube: PolyTools Oficial")
    print("💻 Continue usando o WolfPack Analyzer!")

if __name__ == "__main__":
    main()
