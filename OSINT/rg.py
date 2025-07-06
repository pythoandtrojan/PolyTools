import requests
import json
import os
import sys
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import webbrowser

# Configurações
API_URL = "https://777apisss.vercel.app/consulta/rg/"
API_KEY = "firminoh7778"
OUTPUT_DIR = "rg_data"
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Consulta de RG - Valkyria Network</title>
    <meta charset="UTF-8">
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background-color: #121212; 
            color: #e0e0e0; 
            max-width: 900px; 
            margin: 0 auto; 
            padding: 20px;
        }
        .banner { 
            background-color: #1e1e1e; 
            border: 1px solid #333; 
            padding: 20px; 
            margin-bottom: 20px;
            white-space: pre;
            overflow-x: auto;
        }
        .data-container { 
            background-color: #1e1e1e; 
            border: 1px solid #333; 
            padding: 20px; 
            margin-bottom: 20px;
        }
        h1 { 
            color: #8a2be2; 
            text-align: center;
            border-bottom: 1px solid #8a2be2;
            padding-bottom: 10px;
        }
        .photo { 
            max-width: 300px; 
            display: block; 
            margin: 20px auto;
            border: 1px solid #8a2be2;
        }
        .footer { 
            text-align: center; 
            margin-top: 30px; 
            color: #666; 
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <h1>Consulta de RG - Valkyria Network</h1>
    <div class="banner">{banner}</div>
    <div class="data-container">
        <h2>Dados Pessoais</h2>
        <p><strong>Nome:</strong> {nome}</p>
        <p><strong>Nome da Mãe:</strong> {nome_mae}</p>
        <p><strong>Nome do Pai:</strong> {nome_pai if nome_pai else 'Não informado'}</p>
        <p><strong>Data de Nascimento:</strong> {nasc}</p>
        <p><strong>CPF:</strong> {cpf}</p>
        <p><strong>RG:</strong> {rg}</p>
        <p><strong>Órgão Emissor:</strong> {orgao_emissor}</p>
        <p><strong>UF Emissão:</strong> {uf_emissao}</p>
        <p><strong>Sexo:</strong> {sexo}</p>
        <p><strong>Estado Civil:</strong> {estciv}</p>
        
        <h2>Informações Adicionais</h2>
        <p><strong>CBO:</strong> {cbo}</p>
        <p><strong>Mosaic:</strong> {cd_mosaic} (Novo: {cd_mosaic_novo}, Secundário: {cd_mosaic_secundario})</p>
        <p><strong>Situação Cadastral:</strong> {cd_sit_cad}</p>
        <p><strong>Data da Situação:</strong> {dt_sit_cad}</p>
        <p><strong>Data da Informação:</strong> {dt_informacao}</p>
        
        {photo_html}
    </div>
    <div class="footer">
        Consulta realizada em {data_consulta} | API by {criador}
    </div>
</body>
</html>
"""

def create_banner(text):
    """Cria um banner ASCII com bordas de quadrados"""
    lines = text.split('\n')
    max_len = max(len(line) for line in lines)
    border = '█' * (max_len + 4)
    
    banner = []
    banner.append('█' + border + '█')
    for line in lines:
        banner.append('█  ' + line.ljust(max_len) + '  █')
    banner.append('█' + border + '█')
    
    return '\n'.join(banner)

def consulta_rg(rg_number):
    """Consulta a API de RG e retorna os dados"""
    try:
        response = requests.get(f"{API_URL}?query={rg_number}&apikey={API_KEY}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro ao consultar a API: {e}")
        return None

def save_photo(photo_url, output_dir, rg_number):
    """Salva a foto do RG se existir"""
    if not photo_url:
        return None
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        photo_response = requests.get(photo_url)
        photo_response.raise_for_status()
        
        photo_path = os.path.join(output_dir, f"photo_{rg_number}.jpg")
        with open(photo_path, 'wb') as f:
            f.write(photo_response.content)
        return photo_path
    except Exception as e:
        print(f"Erro ao salvar foto: {e}")
        return None

def display_data(data):
    """Exibe os dados formatados no terminal"""
    if not data or data.get('status') != 1:
        print("Nenhum dado encontrado ou erro na consulta.")
        return
    
    dados = data['dados'][0]
    
    # Criar banner
    banner_text = f"""
    ████████  Valkyria Network  ████████
    Consulta de RG - Dados completos
    RG: {data['rg']}
    Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    print(create_banner(banner_text))
    
    # Exibir dados
    print("\nDADOS PESSOAIS:")
    print(f"Nome: {dados['NOME']}")
    print(f"Nome da Mãe: {dados['NOME_MAE']}")
    print(f"Nome do Pai: {dados['NOME_PAI'] if dados['NOME_PAI'] else 'Não informado'}")
    print(f"Data de Nascimento: {dados['NASC']}")
    print(f"CPF: {dados['CPF']}")
    print(f"RG: {dados['RG']}")
    print(f"Órgão Emissor: {dados['ORGAO_EMISSOR']}")
    print(f"UF Emissão: {dados['UF_EMISSAO']}")
    print(f"Sexo: {dados['SEXO']}")
    print(f"Estado Civil: {dados['ESTCIV']}")
    
    print("\nINFORMAÇÕES ADICIONAIS:")
    print(f"CBO: {dados['CBO']}")
    print(f"Mosaic: {dados['CD_MOSAIC']} (Novo: {dados['CD_MOSAIC_NOVO']}, Secundário: {dados['CD_MOSAIC_SECUNDARIO']})")
    print(f"Situação Cadastral: {dados['CD_SIT_CAD']}")
    print(f"Data da Situação: {dados['DT_SIT_CAD']}")
    print(f"Data da Informação: {dados['DT_INFORMACAO']}")
    
    print(f"\nCriador: {data['criador']}")
    print(f"Quantidade de registros: {data['qnt']}")

def generate_html(data, photo_path=None):
    """Gera uma página HTML com os dados"""
    if not data or data.get('status') != 1:
        return None
    
    dados = data['dados'][0]
    
    # Criar banner para HTML
    banner_text = f"""
    ████████  Valkyria Network  ████████
    Consulta de RG - Dados completos
    RG: {data['rg']}
    Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    banner_html = create_banner(banner_text).replace('█', '■')
    
    # Foto HTML
    if photo_path and os.path.exists(photo_path):
        photo_html = f'<img src="{os.path.basename(photo_path)}" class="photo" alt="Foto do RG">'
    else:
        photo_html = '<p>Foto não disponível</p>'
    
    # Substituir valores no template
    html_content = HTML_TEMPLATE.format(
        banner=banner_html,
        nome=dados['NOME'],
        nome_mae=dados['NOME_MAE'],
        nome_pai=dados['NOME_PAI'] if dados['NOME_PAI'] else 'Não informado',
        nasc=dados['NASC'],
        cpf=dados['CPF'],
        rg=dados['RG'],
        orgao_emissor=dados['ORGAO_EMISSOR'],
        uf_emissao=dados['UF_EMISSAO'],
        sexo=dados['SEXO'],
        estciv=dados['ESTCIV'],
        cbo=dados['CBO'],
        cd_mosaic=dados['CD_MOSAIC'],
        cd_mosaic_novo=dados['CD_MOSAIC_NOVO'],
        cd_mosaic_secundario=dados['CD_MOSAIC_SECUNDARIO'],
        cd_sit_cad=dados['CD_SIT_CAD'],
        dt_sit_cad=dados['DT_SIT_CAD'],
        dt_informacao=dados['DT_INFORMACAO'],
        photo_html=photo_html,
        data_consulta=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        criador=data['criador']
    )
    
    return html_content

def run_web_server(port=8000):
    """Inicia um servidor web simples"""
    os.chdir(OUTPUT_DIR)
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Servidor web rodando em http://localhost:{port}")
    httpd.serve_forever()

def main():
    # Verificar e criar diretório de saída
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print(create_banner("Consulta de RG - Valkyria Network"))
    
    while True:
        try:
            rg_number = input("\nDigite o número do RG (ou 'sair' para encerrar): ").strip()
            if rg_number.lower() in ('sair', 'exit'):
                break
                
            if not rg_number.isdigit():
                print("Por favor, digite apenas números para o RG.")
                continue
                
            # Consultar API
            print("\nConsultando dados...")
            data = consulta_rg(rg_number)
            
            if not data or data.get('status') != 1:
                print("Nenhum dado encontrado para este RG.")
                continue
                
            # Exibir dados no terminal
            display_data(data)
            
            # Perguntar se deseja salvar os dados
            save_option = input("\nDeseja salvar os dados e foto (se disponível)? (s/n): ").strip().lower()
            if save_option == 's':
                # Salvar dados como JSON
                json_path = os.path.join(OUTPUT_DIR, f"rg_{rg_number}.json")
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                # Tentar salvar foto (URL precisa ser implementada conforme API)
                photo_url = None  # Substituir pela URL real da foto se a API fornecer
                photo_path = save_photo(photo_url, OUTPUT_DIR, rg_number)
                
                # Gerar HTML
                html_content = generate_html(data, photo_path)
                if html_content:
                    html_path = os.path.join(OUTPUT_DIR, f"rg_{rg_number}.html")
                    with open(html_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    
                    print(f"\nDados salvos em: {json_path}")
                    print(f"HTML gerado em: {html_path}")
                    if photo_path:
                        print(f"Foto salva em: {photo_path}")
                    
                    # Perguntar se deseja iniciar servidor web
                    web_option = input("\nDeseja iniciar um servidor web para visualização? (s/n): ").strip().lower()
                    if web_option == 's':
                        print("\nIniciando servidor web...")
                        threading.Thread(target=run_web_server, daemon=True).start()
                        webbrowser.open(f"http://localhost:8000/rg_{rg_number}.html")
                        input("Pressione Enter para encerrar o servidor...\n")
                else:
                    print("Erro ao gerar HTML.")
            
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            break
        except Exception as e:
            print(f"\nOcorreu um erro: {e}")
            
    print("\nConsulta encerrada. Valkyria Network - Segurança da Informação")

if __name__ == "__main__":
    main()
