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

BLOCKCHAIN_API = "https://blockchain.info"
COINMARKETCAP_API = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price"
BINANCE_API = "https://api.binance.com/api/v3/ticker/price"
BLOCKCHAIN_WS = "wss://ws.blockchain.info/inv"

CMC_API_KEY = "sua_chave_aqui"  

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
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
 v2.0 | Monitoramento em Tempo Real | Suporte a Múltiplas APIs
\033[0m
""")

def menu_principal():
    print("\n\033[1;35mMENU PRINCIPAL:\033[0m")
    print("1. 📊 Ver preço atual do Bitcoin")
    print("2. 🔍 Rastrear transação Bitcoin")
    print("3. 🏦 Monitorar carteira Bitcoin")
    print("4. ⚡ Monitorar transação em tempo real")
    print("5. 💰 Ver taxas de mineração atuais")
    print("6. 🚪 Sair")
    return input("\n\033[1;32m[?] Escolha uma opção: \033[0m").strip()

def is_valid_bitcoin_address(address):
    """Valida um endereço Bitcoin"""
    return re.match(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$', address)

def is_valid_tx_hash(tx_hash):
    """Valida um hash de transação Bitcoin"""
    return re.match(r'^[a-fA-F0-9]{64}$', tx_hash)

@lru_cache(maxsize=100)
def get_bitcoin_price(api="all"):
    """Obtém o preço do Bitcoin de várias APIs com cache"""
    resultados = {}
    
    # CoinMarketCap
    if api in ["all", "cmc"]:
        headers = {'X-CMC_PRO_API_KEY': CMC_API_KEY}
        params = {'symbol': 'BTC', 'convert': 'BRL'}
        try:
            response = requests.get(COINMARKETCAP_API, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            resultados['cmc'] = {
                'preco': data['data']['BTC']['quote']['BRL']['price'],
                'variacao_24h': data['data']['BTC']['quote']['BRL']['percent_change_24h'],
                'atualizado': datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            }
        except Exception as e:
            print(f"\033[1;31m[!] Erro CoinMarketCap: {str(e)}\033[0m")
    
    
    if api in ["all", "cg"]:
        params = {'ids': 'bitcoin', 'vs_currencies': 'brl', 'include_24hr_change': 'true'}
        try:
            response = requests.get(COINGECKO_API, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            resultados['cg'] = {
                'preco': data['bitcoin']['brl'],
                'variacao_24h': data['bitcoin']['brl_24h_change'],
                'atualizado': datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            }
        except Exception as e:
            print(f"\033[1;31m[!] Erro CoinGecko: {str(e)}\033[0m")
    
    
    if api in ["all", "bn"]:
        params = {'symbol': 'BTCBRL'}
        try:
            response = requests.get(BINANCE_API, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            resultados['bn'] = {
                'preco': float(data['price']),
                'atualizado': datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            }
        except Exception as e:
            print(f"\033[1;31m[!] Erro Binance: {str(e)}\033[0m")
    
    return resultados

def formatar_moeda(valor, moeda="BRL"):
    """Formata valores monetários"""
    if moeda == "BRL":
        return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"${valor:,.2f}"

def converter_btc_para_fiat(amount_btc, currency="BRL"):
    """Converte BTC para moeda fiduciária"""
    price_data = get_bitcoin_price()
    if not price_data or 'cmc' not in price_data:
        return None
    btc_price = price_data['cmc']['preco']  
    return amount_btc * btc_price

def mostrar_precos():
    """Mostra os preços de todas as APIs"""
    limpar_tela()
    banner()
    
    print("\n\033[1;34m[+] Obtendo preços do Bitcoin...\033[0m")
    precos = get_bitcoin_price()
    
    print("\n\033[1;32m=== PREÇOS ATUAIS ===\033[0m")
    
    if 'cmc' in precos:
        variacao = precos['cmc']['variacao_24h']
        cor = "\033[1;32m↑" if variacao >= 0 else "\033[1;31m↓"
        print(f"\n\033[1;36mCoinMarketCap:\033[0m")
        print(f"💰 Preço: {formatar_moeda(precos['cmc']['preco']}")
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
    """Rastreia uma transação Bitcoin específica"""
    limpar_tela()
    banner()
    
    while True:
        tx_hash = input("\n\033[1;32m[?] Digite o hash da transação Bitcoin: \033[0m").strip()
        if is_valid_tx_hash(tx_hash):
            break
        print("\033[1;31m[!] Hash de transação inválido. Tente novamente.\033[0m")
    
    print("\n\033[1;34m[+] Rastreando transação...\033[0m")
    
    try:
        response = requests.get(f"{BLOCKCHAIN_API}/rawtx/{tx_hash}", timeout=10)
        response.raise_for_status()
        data = response.json()
        
        print("\n\033[1;32m=== DETALHES DA TRANSAÇÃO ===\033[0m")
        print(f"\n🔗 Hash: {data['hash']}")
        print(f"📅 Data: {datetime.fromtimestamp(data['time']).strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"📦 Tamanho: {data['size']} bytes")
        print(f"💸 Taxa: {data['fee'] / 100000000:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(data['fee'] / 100000000))})")
        
        print("\n\033[1;36mENTRADAS:\033[0m")
        for inp in data['inputs']:
            if 'prev_out' in inp:
                btc_value = inp['prev_out']['value'] / 100000000
                print(f"- {inp['prev_out']['addr']} ({btc_value:.8f} BTC ~ {formatar_moeda(converter_btc_para_fiat(btc_value))})")
        
        print("\n\033[1;36mSAÍDAS:\033[0m")
        for out in data['out']:
            if 'addr' in out:
                btc_value = out['value'] / 100000000
                print(f"- {out['addr']} ({btc_value:.8f} BTC ~ {formatar_moeda(converter_btc_para_fiat(btc_value))})")
        
        valor_total = sum(out['value'] for out in data['out']) / 100000000
        print(f"\n💰 Valor total: {valor_total:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(valor_total))})")
        
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao rastrear transação: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def monitorar_carteira():
    """Monitora uma carteira Bitcoin específica"""
    limpar_tela()
    banner()
    
    while True:
        endereco = input("\n\033[1;32m[?] Digite o endereço da carteira Bitcoin: \033[0m").strip()
        if is_valid_bitcoin_address(endereco):
            break
        print("\033[1;31m[!] Endereço Bitcoin inválido. Tente novamente.\033[0m")
    
    print("\n\033[1;34m[+] Monitorando carteira...\033[0m")
    
    try:
        response = requests.get(f"{BLOCKCHAIN_API}/rawaddr/{endereco}", timeout=10)
        response.raise_for_status()
        data = response.json()
        
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
        for tx in data['txs'][:5]:  # Mostra apenas as 5 últimas transações
            valor_btc = tx['result'] / 100000000
            print(f"\n🔗 {tx['hash']}")
            print(f"📅 {datetime.fromtimestamp(tx['time']).strftime('%d/%m/%Y %H:%M:%S')}")
            print(f"💸 {valor_btc:.8f} BTC (~{formatar_moeda(converter_btc_para_fiat(valor_btc))}")
        
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao monitorar carteira: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def monitorar_transacao_tempo_real():
    """Monitora uma transação em tempo real usando WebSocket"""
    limpar_tela()
    banner()
    
    while True:
        tx_hash = input("\n\033[1;32m[?] Digite o hash da transação Bitcoin: \033[0m").strip()
        if is_valid_tx_hash(tx_hash):
            break
        print("\033[1;31m[!] Hash de transação inválido. Tente novamente.\033[0m")
    
    print("\n\033[1;34m[+] Iniciando monitoramento em tempo real...\033[0m")
    print("\033[1;33mPressione Ctrl+C para parar o monitoramento\033[0m")
    
    def on_message(ws, message):
        data = json.loads(message)
        if data['op'] == 'utx':
            print(f"\n\033[1;32mNovo status: {data['x']['block_idx'] if 'block_idx' in data['x'] else 'pendente'}")
            print(f"Hash: {data['x']['hash']}")
            print(f"Confirmacoes: {data['x'].get('block_height', 0)}")
    
    def on_error(ws, error):
        print(f"\033[1;31m[!] Erro WebSocket: {str(error)}\033[0m")
    
    def on_close(ws):
        print("\n\033[1;33m[+] Conexão WebSocket fechada\033[0m")
    
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
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ws.close()
        print("\n\033[1;33m[+] Monitoramento encerrado\033[0m")
        time.sleep(2)

def mostrar_taxas_mineracao():
    """Mostra as taxas atuais de mineração"""
    limpar_tela()
    banner()
    
    print("\n\033[1;34m[+] Obtendo taxas de mineração...\033[0m")
    
    try:
        response = requests.get(f"{BLOCKCHAIN_API}/fees?cors=true", timeout=10)
        response.raise_for_status()
        data = response.json()
        
        print("\n\033[1;32m=== TAXAS ATUAIS (satoshis/byte) ===\033[0m")
        print(f"\n🐢 Prioridade baixa: {data['low_fee_per_kb'] / 1000:.1f}")
        print(f"🐢 Tempo estimado: ~1-2 horas")
        print(f"\n🚗 Prioridade média: {data['medium_fee_per_kb'] / 1000:.1f}")
        print(f"🚗 Tempo estimado: ~10-20 minutos")
        print(f"\n🚀 Prioridade alta: {data['high_fee_per_kb'] / 1000:.1f}")
        print(f"🚀 Tempo estimado: ~1-2 blocos")
        
        # Converter para BRL
        preco_btc = get_bitcoin_price().get('cmc', {}).get('preco', 0)
        if preco_btc:
            taxa_alta_brl = (data['high_fee_per_kb'] / 1000) * 250 * preco_btc / 100000000
            print(f"\n💸 Taxa alta estimada para transação média: ~{formatar_moeda(taxa_alta_brl)}")
        
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao obter taxas: {str(e)}\033[0m")
    
    input("\n\033[1;34mPressione Enter para continuar...\033[0m")

def main():
    while True:
        limpar_tela()
        banner()
        
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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[+] Programa encerrado pelo usuário\033[0m")
        sys.exit(0)
