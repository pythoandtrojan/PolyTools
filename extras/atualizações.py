import requests
import os
import json
from typing import Optional

def verificar_updates(repo: str, arquivo_cache: str = "ultimo_commit.json") -> Optional[bool]:
    """
    Verifica se há atualizações disponíveis no repositório GitHub
    
    Args:
        repo: Nome do repositório no formato "usuário/repositório"
        arquivo_cache: Arquivo para armazenar o último commit conhecido
    
    Returns:
        bool: True se há atualizações, False se está atualizado, None em caso de erro
    """
    
    # Headers para evitar limites de rate limiting
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Python-Update-Checker'
    }
    
    url = f"https://api.github.com/repos/{repo}/commits/main"
    
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            dados_commit = resp.json()
            commit_atual = dados_commit["sha"]
            
            commit_local = None
            if os.path.exists(arquivo_cache):
                try:
                    with open(arquivo_cache, "r") as f:
                        dados_cache = json.load(f)
                        commit_local = dados_cache.get("commit")
                except json.JSONDecodeError:
                    print("⚠️ Arquivo de cache corrompido, recriando...")
            
            # Salvar o commit atual independentemente
            with open(arquivo_cache, "w") as f:
                json.dump({"commit": commit_atual, "repo": repo}, f)
            
            if commit_local and commit_atual == commit_local:
                print("✅ Já está atualizado.")
                return False
            else:
                if commit_local:
                    print("🔄 Novo update disponível no GitHub!")
                    return True
                else:
                    print("ℹ️ Commit atual salvo para verificação futura.")
                    return False
                
        elif resp.status_code == 404:
            print("❌ Repositório não encontrado.")
        elif resp.status_code == 403:
            print("⏳ Limite de requisições excedido. Tente mais tarde.")
        else:
            print(f"⚠️ Erro HTTP {resp.status_code} ao acessar API")
            
        return None
            
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        return None

# Uso correto:
if __name__ == "__main__":
    resultado = verificar_updates("pythoandtrojan/PolyTools")
    if resultado is True:
        print("É necessário atualizar o software!")
