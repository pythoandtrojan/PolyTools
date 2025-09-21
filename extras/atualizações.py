import requests
import os
import json

def verificar_updates(repo, arquivo_cache="ultimo_commit.json"):
    url = f"https://api.github.com/repos/https://github.com/pythoandtrojan/PolyTools/commits/main"
    resp = requests.get(url)

    if resp.status_code == 200:
        commit_atual = resp.json()["sha"]

        if os.path.exists(arquivo_cache):
            with open(arquivo_cache, "r") as f:
                commit_local = json.load(f).get("commit")

            if commit_atual == commit_local:
                print("✅ Já está atualizado.")
            else:
                print("🔄 Novo update disponível no GitHub!")
        else:
            print("ℹ️ Primeiro uso: salvando commit atual.")

        with open(arquivo_cache, "w") as f:
            json.dump({"commit": commit_atual}, f)

    else:
        print("⚠️ Erro ao acessar API:", resp.status_code)

# Exemplo de uso
verificar_updates("pythoandtrojan/varios-investiga")
