#!/usr/bin/env python3
import requests
import json
import time
from datetime import datetime
import os
import sys
import re
from functools import lru_cache
import websocket
from threading import Thread
from tqdm import tqdm
import dotenv
import logging

dotenv.load_dotenv()  
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 10
CACHE_TTL_MINUTES = 5


BLOCKCHAIN_API = "https://blockchain.info"
COINMARKETCAP_API = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price"
BINANCE_API = "https://api.binance.com/api/v3/ticker/price"
BLOCKCHAIN_WS = "wss://ws.blockchain.info/inv"


CMC_API_KEY = os.getenv("CMC_API_KEY", "")  

def limpar_tela():
    """Limpa a tela do terminal de forma multiplataforma"""
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    """Exibe o banner do programa"""
    print("""
\033[1;33m
██████╗ ██╗████████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗███╗   ██╗
██╔══██╗██║╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝ ██║████╗  ██║
██████╔╝██║   ██║   ██║   ██║█████╔╝ ██║  ███╗██║██╔██╗ ██║
██╔══██╗██║   ██║   ██║   ██║██╔═██╗ ██║   ██║██║██║╚██╗██║
██████╔╝██║   ██║   ╚██████╔╝██║  ██╗╚██████╔╝██║██║ ╚████║
╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
\033[0m
\033[1;36m
 BITRACK - Rastreador Avançado de Bitcoin (Termux Edition)
\033[0m
\033[1;35m
 v2.1 | Monitoramento em Tempo Real | Suporte a Múltiplas APIs
\033[0m
""")

def verificar_conectividade():
    """Verifica se há conexão com a internet"""
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        logger.error("Sem conexão com a internet")
        return False

def menu_principal():
    """Exibe o menu principal e retorna a escolha do usuário"""
    print("\n\033[1;35mMENU PRINCIPAL:\033[0m")
    print("1. 📊 Ver preço atual do Bitcoin")
    print("2. 🔍 Rastrear transação Bitcoin")
    print("3. 🏦 Monitorar carteira Bitcoin")
    print("4. ⚡ Monitorar transação em tempo real")
    print("5. 💰 Ver taxas de mineração atuais")
    print("6. 🚪 Sair")
    
    while True:
        escolha = input("\n\033[1;32m[?] Escolha uma opção (1-6): \033[0m").strip()
        if escolha in ("1", "2", "3", "4", "5", "6"):
            return escolha
        print("\033[1;31m[!] Opção inválida. Por favor, escolha de 1 a 6.\033[0m")

def is_valid_bitcoin_address(address):
    """Valida um endereço Bitcoin de forma robusta"""

    if not re.match(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$', address):
        return False
    
    
    if address.startswith('1') or address.startswith('3'):
        
        pass
        
    return True

def is_valid_tx_hash(tx_hash):
    """Valida um hash de transação Bitcoin"""
    return re.match(r'^[a-fA-F0-9]{64}$', tx_hash) is not None

def get_bitcoin_price_with_cache(api="all"):
    """Obtém o preço do Bitcoin com cache TTL"""
    current_time = time.time() // (60 * CACHE_TTL_MINUTES)  
    return get_bitcoin_price(api, _cache_time=current_time)

@lru_cache(maxsize=100)
def get_bitcoin_price(api="all", _cache_time=None):
    """
    Obtém o preço do Bitcoin de várias APIs com cache
    Args:
        api: Qual API usar ('all', 'cmc', 'cg', 'bn')
        _cache_time: Parâmetro interno para controle de cache
    """
    resultados = {}
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    if not verificar_conectividade():
        logger.warning("Sem conexão com a internet - usando cache")
        return resultados
    
    
    if api in ("all", "cmc") and CMC_API_KEY:
        try:
            headers = {'X-CMC_PRO_API_KEY': CMC_API_KEY}
            params = {'symbol': 'BTC', 'convert': 'BRL'}
            response = requests.get(COINMARKETCAP_API, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            resultados['cmc'] = {
                'preco': data['data']['BTC']['quote']['BRL']['price'],
                'variacao_24h': data['data']['BTC']['quote']['BRL']['percent_change_24h'],
                'atualizado': timestamp
            }
        except Exception as e:
            logger.error(f"Erro CoinMarketCap: {str(e)}")

    
    if api in ("all", "cg"):
        try:
            params = {'ids': 'bitcoin', 'vs_currencies': 'brl', 'include_24hr_change': 'true'}
            response = requests.get(COINGECKO_API, params=params, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            resultados['cg'] = {
                'preco': data['bitcoin']['brl'],
                'variacao_24h': data['bitcoin']['brl_24h_change'],
                'atualizado': timestamp
            }
        except Exception as e:
            logger.error(f"Erro CoinGecko: {str(e)}")

  
    if api in ("all", "bn"):
        try:
            params = {'symbol': 'BTCBRL'}
            response = requests.get(BINANCE_API, params=params, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            resultados['bn'] = {
                'preco': float(data['price']),
                'atualizado': timestamp
            }
        except Exception as e:
            logger.error(f"Erro Binance: {str(e)}")
    
    return resultados

def formatar_moeda(valor, moeda="BRL"):
    """Formata valores monetários de forma consistente"""
    try:
        valor = float(valor)
    except (TypeError, ValueError):
        return "N/A"
    
    if moeda == "BRL":
        return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"${valor:,.2f}"

def converter_btc_para_fiat(amount_btc, currency="BRL"):
    """Converte BTC para moeda fiduciária com tratamento de erros"""
    if not isinstance(amount_btc, (int, float)) or amount_btc <= 0:
        return 0.0
    
    price_data = get_bitcoin_price_with_cache()
    if not price_data or 'cmc' not in price_data:
        return 0.0
    
    btc_price = price_data['cmc']['preco']
    return amount_btc * btc_price

def mostrar_precos():
    """Mostra os preços de todas as APIs com feedback visual"""
    limpar_tela()
    banner()
    
    print("\n\033[1;34m[+] Obtendo preços do Bitcoin...\033[0m")
    
    with tqdm(total=3, desc="Consultando APIs", unit="API") as pbar:
        precos = get_bitcoin_price_with_cache()
        pbar.update(1)
        
        
        time.sleep(0.5)
        pbar.update(1)
        time.sleep(0.5)
        pbar.update(1)
    
    print("\n\033[1;32m=== PREÇOS ATUAIS ===\033[0m")
    
    if 'cmc' in precos:
        variacao = precos['cmc']['variacao_24h']
        cor = "\033[1;32m↑" if variacao >= 0 else "\033[1;31m↓"
        print(f"\n\033[1;36mCoinMarketCap:\033[0m")
        print(f"💰 Preço: {formatar_moeda(precos['cmc']['preco'])}")
        print(f"📈 Variação 24h: {cor} {abs(variacao):.2f}%\033[0m")
        print(f"🕒 Atualizado: {precos['cmc']['atualizado']}")
    
    if 'cg' in precos:
        variacao = precos['cg']['variacao_24h']
        cor = "\033[1;32m↑" if variacao >= 0 else "\033[1;31m↓"
        print(f"\n\033[1;36mCoinGecko:\033[0m")
        print(f"💰 Preço: {formatar_moeda(precos['cg']['preco'])}")
        print(f"📈 Variação 24h: {cor} {abs(variacao):.2f}%\033[0m")
        print(f"🕒 Atualizado: {precos['cg']['atualizado']}")
    
    if 'bn' in precos:
        print(f"\n\033[1;36mBinance:\033[0m")
        print(f"💰 Preço: {formatar_moeda(precos['bn']['preco'])}")
        print(f"🕒 Atualizado: {precos['bn']['atualizado']}")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def rastrear_transacao():
    """Rastreia uma transação Bitcoin específica com validação robusta"""
    limpar_tela()
    banner()
    
    while True:
        tx_hash = input("\n\033[1;32m[?] Digite o hash da transação Bitcoin: \033[0m").strip()
        if is_valid_tx_hash(tx_hash):
            break
        print("\033[1;31m[!] Hash de transação inválido. Deve ter 64 caracteres hexadecimais.\033[0m")
    
    print("\n\033[1;34m[+] Rastreando transação...\033[0m")
    
    try:
        with tqdm(desc="Buscando dados", unit="req") as pbar:
            response = requests.get(f"{BLOCKCHAIN_API}/rawtx/{tx_hash}", timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            pbar.update(1)
            
            data = response.json()
            pbar.update(1)
        
        print("\n\033[1;32m=== DETALHES DA TRANSAÇÃO ===\033[0m")
        print(f"\n🔗 Hash: {data['hash']}")
        print(f"📅 Data: {datetime.fromtimestamp(data['time']).strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"📦 Tamanho: {data['size']} bytes")
        print(f"💸 Taxa: {data['fee'] / 100000000:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(data['fee'] / 100000000))})")
        
        # Entradas
        print("\n\033[1;36mENTRADAS:\033[0m")
        for inp in data['inputs']:
            if 'prev_out' in inp:
                btc_value = inp['prev_out']['value'] / 100000000
                print(f"- {inp['prev_out']['addr']} ({btc_value:.8f} BTC ~ {formatar_moeda(converter_btc_para_fiat(btc_value))})")
        
        # Saídas
        print("\n\033[1;36mSAÍDAS:\033[0m")
        for out in data['out']:
            if 'addr' in out:
                btc_value = out['value'] / 100000000
                print(f"- {out['addr']} ({btc_value:.8f} BTC ~ {formatar_moeda(converter_btc_para_fiat(btc_value))})")
        
        
        valor_total = sum(out['value'] for out in data['out']) / 100000000
        print(f"\n💰 Valor total: {valor_total:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(valor_total))}")
        
    except requests.exceptions.RequestException as e:
        print(f"\n\033[1;31m[!] Erro na requisição: {str(e)}\033[0m")
    except json.JSONDecodeError:
        print("\n\033[1;31m[!] Resposta inválida da API\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao rastrear transação: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def monitorar_carteira():
    """Monitora uma carteira Bitcoin específica com tratamento completo"""
    limpar_tela()
    banner()
    
    while True:
        endereco = input("\n\033[1;32m[?] Digite o endereço da carteira Bitcoin: \033[0m").strip()
        if is_valid_bitcoin_address(endereco):
            break
        print("\033[1;31m[!] Endereço Bitcoin inválido. Deve começar com 1, 3 ou bc1.\033[0m")
    
    print("\n\033[1;34m[+] Monitorando carteira...\033[0m")
    
    try:
        with tqdm(desc="Carregando dados", unit="req") as pbar:
            response = requests.get(f"{BLOCKCHAIN_API}/rawaddr/{endereco}", timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            pbar.update(1)
            
            data = response.json()
            pbar.update(1)
        
        print("\n\033[1;32m=== DETALHES DA CARTEIRA ===\033[0m")
        print(f"\n📌 Endereço: {data['address']}")
        
        
        saldo_btc = data['final_balance'] / 100000000
        recebido_btc = data['total_received'] / 100000000
        enviado_btc = data['total_sent'] / 100000000
        
        print(f"💰 Saldo total: {saldo_btc:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(saldo_btc))}")
        print(f"📥 Total recebido: {recebido_btc:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(recebido_btc))}")
        print(f"📤 Total enviado: {enviado_btc:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(enviado_btc))}")
        print(f"🔢 Número de transações: {data['n_tx']}")
        print("\n\033[1;36mÚLTIMAS TRANSAÇÕES:\033[0m")
        for tx in data['txs'][:5]:
            valor_btc = tx['result'] / 100000000
            print(f"\n🔗 {tx['hash']}")
            print(f"📅 {datetime.fromtimestamp(tx['time']).strftime('%d/%m/%Y %H:%M:%S')}")
            print(f"💸 {valor_btc:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(valor_btc))}")
            
    except requests.exceptions.RequestException as e:
        print(f"\n\033[1;31m[!] Erro na requisição: {str(e)}\033[0m")
    except json.JSONDecodeError:
        print("\n\033[1;31m[!] Resposta inválida da API\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao monitorar carteira: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def monitorar_transacao_tempo_real():
    """Monitora uma transação em tempo real usando WebSocket com gerenciamento adequado"""
    limpar_tela()
    banner()
    
    while True:
        tx_hash = input("\n\033[1;32m[?] Digite o hash da transação Bitcoin: \033[0m").strip()
        if is_valid_tx_hash(tx_hash):
            break
        print("\033[1;31m[!] Hash de transação inválido. Deve ter 64 caracteres hexadecimais.\033[0m")
    
    print("\n\033[1;34m[+] Iniciando monitoramento em tempo real...\033[0m")
    print("\033[1;33mPressione Ctrl+C para parar o monitoramento\033[0m")
    
    def on_message(ws, message):
        """Callback para mensagens WebSocket"""
        try:
            data = json.loads(message)
            if data.get('op') == 'utx':
                status = data['x'].get('block_idx', 'pendente')
                confirmacoes = data['x'].get('block_height', 0)
                
                print(f"\n\033[1;32mNovo status: {status}")
                print(f"Hash: {data['x']['hash']}")
                print(f"Confirmações: {confirmacoes}")
        except json.JSONDecodeError:
            logger.error("Mensagem WebSocket inválida")
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {str(e)}")

    def on_error(ws, error):
        """Callback para erros WebSocket"""
        logger.error(f"Erro WebSocket: {str(error)}")

    def on_close(ws, close_status_code, close_msg):
        """Callback para fechamento WebSocket"""
        logger.info("Conexão WebSocket fechada")

  
    ws = websocket.WebSocketApp(
        f"{BLOCKCHAIN_WS}?event=tx&hash={tx_hash}",
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    
    
    wst = Thread(target=ws.run_forever)
    wst.daemon = True
    wst.start()
    
    try:
        while wst.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Encerrando monitoramento...")
        ws.close()
        wst.join(timeout=2)
        if wst.is_alive():
            logger.warning("Thread WebSocket não encerrou corretamente")
    
    print("\n\033[1;33m[+] Monitoramento encerrado\033[0m")
    time.sleep(1)

def mostrar_taxas_mineracao():
    """Mostra as taxas atuais de mineração com tratamento completo"""
    limpar_tela()
    banner()
    
    print("\n\033[1;34m[+] Obtendo taxas de mineração...\033[0m")
    
    try:
        with tqdm(desc="Consultando taxas", unit="req") as pbar:
            response = requests.get(f"{BLOCKCHAIN_API}/mempool/fees", timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            pbar.update(1)
            
            data = response.json()
            pbar.update(1)
        
        print("\n\033[1;32m=== TAXAS ATUAIS (satoshis/byte) ===\033[0m")
        print(f"\n🐢 Prioridade baixa: {data['hourFee']:.1f}")
        print(f"🐢 Tempo estimado: ~1-2 horas")
        print(f"\n🚗 Prioridade média: {data['halfHourFee']:.1f}")
        print(f"🚗 Tempo estimado: ~10-30 minutos")
        print(f"\n🚀 Prioridade alta: {data['fastestFee']:.1f}")
        print(f"🚀 Tempo estimado: ~1-2 blocos")
        
      
        preco_data = get_bitcoin_price_with_cache()
        if preco_data and 'cmc' in preco_data:
            preco_btc = preco_data['cmc']['preco']
            taxa_alta_brl = (data['fastestFee'] * 250 * preco_btc) / 100000000
            taxa_media_brl = (data['halfHourFee'] * 250 * preco_btc) / 100000000
            
            print(f"\n💸 Taxa alta estimada para transação média: ~{formatar_moeda(taxa_alta_brl)}")
            print(f"💸 Taxa média estimada para transação média: ~{formatar_moeda(taxa_media_brl)}")
        
    except requests.exceptions.RequestException as e:
        print(f"\n\033[1;31m[!] Erro na requisição: {str(e)}\033[0m")
    except json.JSONDecodeError:
        print("\n\033[1;31m[!] Resposta inválida da API\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao obter taxas: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def main():
    """Função principal do programa"""
    try:
        while True:
            limpar_tela()
            banner()
            
            if not verificar_conectividade():
                print("\n\033[1;31m[!] Sem conexão com a internet. Algumas funcionalidades podem não funcionar.\033[0m")
                time.sleep(2)
            
            opcao = menu_principal()
            
            if opcao == "1":
                mostrar_precos()
            elif opcao == "2":
                rastrear_transacao()
            elif opcao == "3":
                monitorar_carteira()
            elif opcao == "4":
                monitorar_transacao_tempo_real()
            elif opcao == "5":
                mostrar_taxas_mineracao()
            elif opcao == "6":
                print("\n\033[1;33m[*] Saindo...\033[0m")
                break
            else:
                print("\n\033[1;31m[!] Opção inválida\033[0m")
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\n\033[1;33m[+] Programa encerrado pelo usuário\033[0m")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
