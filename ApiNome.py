#!/usr/bin/env python3
import requests
import json
from datetime import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor


APIS_CONSULTA = {
    "IBGE Nomes": {
        "url": "https://servicodados.ibge.gov.br/api/v2/censos/nomes/{}",
        "type": "demografia",
        "params": {}
    },
    "TSE (Candidatos)": {
        "url": "https://divulgacandcontas.tse.jus.br/divulga/rest/v1/candidatura/listar/2022/BR/2040602022/1/candidatos",
        "type": "politica",
        "params": {"nome": "{}"}
    },
    "CEP Aberto": {
        "url": "https://viacep.com.br/ws/{}/json/",
        "type": "localidade",
        "params": {}
    },
    "Receita WS (CPF)": {
        "url": "https://receitaws.com.br/v1/cpf/{}",
        "type": "fiscal",
        "params": {"timeout": "5"}
    },
    "Dados Abertos Brasil": {
        "url": "https://api.dadosabertosbrasil.org/v1/ibge/populacao/{}",
        "type": "demografia",
        "params": {}
    },
    "CNPJ WS": {
        "url": "https://publica.cnpj.ws/cnpj/{}",
        "type": "fiscal",
        "params": {}
    }
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    print("""
\033[1;36m
   ___   _____   _____   _____   _____   _____   _____ 
  / _ \ |  _  \ |  _  \ |_   _| |  _  \ /  ___| /  ___|
 / /_\ \| | | | | | | |   | |   | | | | | |     | |    
 |  _  || | | | | | | |   | |   | | | | | |     | |    
 | | | || |/ /  | |/ /    | |   | |/ /  | |___  | |___ 
 \_| |_/|___/   |___/     \_/   |___/   \_____/ \_____/
\033[0m
\033[1;33m
 Consulta de Nomes Completos - Dados Públicos v2.0
\033[0m
\033[1;35m
 Fontes oficiais: IBGE, TSE, Receita Federal e mais
\033[0m
""")

def validar_nome(nome):
    """Validação rigorosa de nome completo"""
    nome = nome.strip()
    if len(nome.split()) < 2:
        return False, "Digite nome e sobrenome completos"
    if not all(palavra.isalpha() or any(c in "ãâáàéêíóôõúüç" for c in palavra) for palavra in nome.split()):
        return False, "Use apenas letras e acentos válidos"
    if len(nome) < 6 or len(nome) > 100:
        return False, "Nome deve ter entre 6 e 100 caracteres"
    return True, ""

def consultar_ibge(nome):
    """Consulta dados demográficos oficiais do IBGE"""
    try:
        primeiro_nome = nome.split()[0]
        url = APIS_CONSULTA["IBGE Nomes"]["url"].format(primeiro_nome)
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if isinstance(data, list) and len(data) > 0:
            return {
                "nome": primeiro_nome,
                "frequencia_total": sum(decada["frequencia"] for decada in data[0]["res"]),
                "decada_mais_popular": max(data[0]["res"], key=lambda x: x["frequencia"])["periodo"],
                "ranking": data[0].get("ranking", "Não disponível"),
                "detalhes_decadas": [{"decada": d["periodo"], "frequencia": d["frequencia"]} for d in data[0]["res"][:5]]
            }
        return {"erro": "Nome não consta no censo"}
    except Exception as e:
        return {"erro": f"IBGE: {str(e)}"}

def consultar_tse(nome_completo):
    """Consulta dados de candidaturas no TSE"""
    try:
        url = APIS_CONSULTA["TSE (Candidatos)"]["url"]
        params = {"nome": nome_completo}
        response = requests.get(url, params=params, headers=HEADERS, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if data.get("candidatos"):
            candidatos = []
            for cand in data["candidatos"][:3]:  
                candidatos.append({
                    "nome_urna": cand.get("nomeUrna"),
                    "partido": cand.get("partido", {}).get("sigla"),
                    "cargo": cand.get("cargo", {}).get("nome"),
                    "estado": cand.get("unidadeEleitoral", {}).get("sigla")
                })
            return {
                "total_candidaturas": len(data["candidatos"]),
                "principais_candidatos": candidatos
            }
        return {"erro": "Nenhuma candidatura encontrada"}
    except Exception as e:
        return {"erro": f"TSE: {str(e)}"}

def consultar_cep(cep):
    """Consulta dados de localização por CEP"""
    try:
        url = APIS_CONSULTA["CEP Aberto"]["url"].format(cep)
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if not data.get("erro"):
            return {
                "logradouro": data.get("logradouro", "Desconhecido"),
                "bairro": data.get("bairro", "Desconhecido"),
                "cidade": data.get("localidade", "Desconhecido"),
                "estado": data.get("uf", "Desconhecido")
            }
        return {"erro": "CEP não encontrado"}
    except Exception as e:
        return {"erro": f"CEP: {str(e)}"}

def consultar_apis_paralelas(nome, cep=None):
    """Executa consultas em paralelo para melhor performance"""
    resultados = {}
    
    with ThreadPoolExecutor(max_workers=4) as executor:
    
        futures = {
            executor.submit(consultar_ibge, nome): "ibge",
            executor.submit(consultar_tse, nome): "tse"
        }
        
        if cep:
            futures[executor.submit(consultar_cep, cep)] = "cep"
        
      
        for future in futures:
            api = futures[future]
            try:
                resultados[api] = future.result()
            except Exception as e:
                resultados[api] = {"erro": str(e)}
    
    return resultados

def formatar_relatorio(dados):
    """Formata os dados para exibição amigável"""
    relatorio = []
    
    # Seção IBGE
    if "ibge" in dados and "erro" not in dados["ibge"]:
        ibge = dados["ibge"]
        relatorio.append("\n\033[1;34mDADOS DEMOGRÁFICOS (IBGE):\033[0m")
        relatorio.append(f"📊 Nome pesquisado: {ibge['nome']}")
        relatorio.append(f"👥 Total de pessoas: {ibge['frequencia_total']:,}")
        relatorio.append(f"🏆 Década mais popular: {ibge['decada_mais_popular']}")
        relatorio.append(f"🥇 Ranking: {ibge['ranking']}")
        relatorio.append("\n📅 Distribuição por década:")
        for decada in ibge.get("detalhes_decadas", []):
            relatorio.append(f"  - {decada['decada']}: {decada['frequencia']:,} pessoas")
  
    
    if "tse" in dados and "erro" not in dados["tse"]:
        tse = dados["tse"]
        relatorio.append("\n\033[1;34mHISTÓRICO POLÍTICO (TSE):\033[0m")
        relatorio.append(f"🗳️ Total de candidaturas: {tse['total_candidaturas']}")
        if tse.get("principais_candidatos"):
            relatorio.append("\n👤 Principais candidatos:")
            for cand in tse["principais_candidatos"]:
                relatorio.append(f"  - {cand['nome_urna']} ({cand['partido']})")
                relatorio.append(f"    Cargo: {cand['cargo']} - {cand['estado']}")
    
  
    if "cep" in dados and "erro" not in dados["cep"]:
        cep = dados["cep"]
        relatorio.append("\n\033[1;34mDADOS GEOGRÁFICOS (CEP):\033[0m")
        relatorio.append(f"🏠 Endereço: {cep['logradouro']}")
        relatorio.append(f"🏘️ Bairro: {cep['bairro']}")
        relatorio.append(f"🏙️ Cidade/UF: {cep['cidade']}/{cep['estado']}")
    
    
    for api in dados:
        if "erro" in dados[api]:
            relatorio.append(f"\n\033[1;33m⚠ {api.upper()}: {dados[api]['erro']}\033[0m")
    
    return "\n".join(relatorio)

def salvar_resultados(nome, dados, formato='json'):
    """Salva os resultados em arquivo"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"consulta_nome_{nome.replace(' ', '_')}_{timestamp}"
    
    if formato == 'json':
        filename += ".json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                "nome": nome,
                "data_consulta": timestamp,
                "resultados": dados
            }, f, indent=4, ensure_ascii=False)
    else:
        filename += ".txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(formatar_relatorio(dados))
    
    return filename

def main():
    limpar_tela()
    banner()
    
  
    while True:
        nome = input("\n\033[1;32m[?] Digite o nome completo para consulta: \033[0m").strip()
        valido, msg = validar_nome(nome)
        if valido:
            break
        print(f"\033[1;31m[!] {msg}\033[0m")
    
    cep = None
    if input("\n\033[1;36m[?] Deseja incluir consulta por CEP? (s/n): \033[0m").lower() == 's':
        while True:
            cep = input("\033[1;32m[?] Digite o CEP (apenas números): \033[0m").strip()
            if cep.isdigit() and len(cep) == 8:
                break
            print("\033[1;31m[!] CEP deve ter 8 dígitos numéricos\033[0m")
    
    print("\n\033[1;34m[+] Consultando fontes oficiais...\033[0m")
    

    dados = consultar_apis_paralelas(nome, cep)
    
    
    limpar_tela()
    banner()
    print(formatar_relatorio(dados))
    
    
    arquivo = salvar_resultados(nome, dados)
    print(f"\n\033[1;32m[+] Relatório salvo como: {arquivo}\033[0m")
    
    input("\n\033[1;34mPressione Enter para sair...\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[+] Consulta cancelada pelo usuário\033[0m")
        sys.exit(0)
