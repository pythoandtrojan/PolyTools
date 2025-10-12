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
        # Primeiro, ler o commit local ANTES de fazer a requisição
        commit_local = None
        if os.path.exists(arquivo_cache):
            try:
                with open(arquivo_cache, "r") as f:
                    dados_cache = json.load(f)
                    # Verificar se o cache é do mesmo repositório
                    if dados_cache.get("repo") == repo:
                        commit_local = dados_cache.get("commit")
            except (json.JSONDecodeError, KeyError):
                print("⚠️ Arquivo de cache corrompido, recriando...")
        
        # Fazer requisição para obter commit atual
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            dados_commit = resp.json()
            commit_atual = dados_commit["sha"]
            
            # Comparar commits
            if commit_local is None:
                # Primeira execução - salvar e considerar como atualizado
                with open(arquivo_cache, "w") as f:
                    json.dump({"commit": commit_atual, "repo": repo}, f)
                print("ℹ️ Commit atual salvo para verificação futura.")
                return False
            elif commit_atual == commit_local:
                print("✅ Já está atualizado.")
                return False
            else:
                print("🔄 Novo update disponível no GitHub!")
                # NÃO salvar automaticamente - deixar para o usuário atualizar
                return True
                
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

def marcar_como_atualizado(repo: str, arquivo_cache: str = "ultimo_commit.json"):
    """
    Marca a versão atual como atualizada (após o usuário fazer update)
    """
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
            
            with open(arquivo_cache, "w") as f:
                json.dump({"commit": commit_atual, "repo": repo}, f)
            print("✅ Cache atualizado com a versão mais recente.")
        else:
            print("❌ Não foi possível obter o commit atual para atualizar o cache.")
    except Exception as e:
        print(f"❌ Erro ao atualizar cache: {e}")

# Uso correto:
if __name__ == "__main__":
    resultado = verificar_updates("pythoandtrojan/PolyTools")
    
    if resultado is True:
        print("É necessário atualizar o software!")
        # Aqui você pode adicionar a lógica de atualização
        
        # Após atualizar, chamar esta função para marcar como atualizado:
        # marcar_como_atualizado("pythoandtrojan/PolyTools")
        
    elif resultado is False:
        print("Software está atualizado!")
    else:
        print("Não foi possível verificar atualizações.")
