#!/usr/bin/env python3
import instaloader
import os
import re
from datetime import datetime
import webbrowser
import json
from collections import defaultdict

BR_CITIES = [
    "São Paulo", "Rio de Janeiro", "Belo Horizonte", "Brasília", "Salvador",
    "Fortaleza", "Curitiba", "Recife", "Porto Alegre", "Manaus", "Belém",
    "Goiânia", "Florianópolis", "Vitória", "Natal", "João Pessoa", "Maceió",
    "Aracaju", "Campo Grande", "Cuiabá", "São Luís", "Teresina", "Porto Velho",
    "Rio Branco", "Macapá", "Boa Vista",
    "Anápolis", "Aparecida de Goiânia", "Rio Verde", "Luziânia", "Águas Lindas de Goiás",
    "Valparaíso de Goiás", "Senador Canedo", "Trindade", "Formosa", "Itumbiara",
    "Catalão", "Novo Gama", "Jataí", "Planaltina", "Caldas Novas", "Cidade Ocidental",
    "Santo Antônio do Descoberto", "Inhumas", "Goianésia", "Jaraguá", "Quirinópolis",
    "Mineiros", "Cristalina", "Porangatu", "Morrinhos", "Itaberaí", "Uruaçu",
    "Ipameri", "São Luís de Montes Belos", "Niquelândia", "Minaçu", "Pires do Rio",
    "Santa Helena de Goiás", "Itapaci", "Iporá", "Pontalina", "Morrinhos",
    "Campos Belos", "Goianira", "Catalão", "Palmeiras de Goiás", "Orizona",
    "Corumbá de Goiás", "São Miguel do Araguaia", "Piranhas", "Itapuranga", 
    "Mambaí", "Guarani de Goiás", "Hidrolândia", "Alexânia", "Silvânia",
    "Ceres", "Abadiânia", "Posse", "Cocalzinho de Goiás", "Bonfinópolis",
    "Nova Crixás", "Campo Alegre de Goiás", "Acreúna", "Edéia", "Turvânia",
    "Rubiataba", "Água Fria de Goiás", "Petrolina de Goiás", "Alvorada do Norte",
    "Cavalcante", "Buriti Alegre", "Campinorte", "Itarumã", "Jussara",
    "Aruanã", "Montividiu", "Maurilândia", "Itajá", "Cachoeira Alta",
    "Arenópolis", "Vianópolis", "São Simão", "Mozarlândia", "Nova Veneza",
    "Montes Claros de Goiás", "Caçu", "Aurilândia", "Nova Roma", "Alto Paraíso de Goiás",
    "Damianópolis", "São Domingos", "Crixás", "Flores de Goiás", "Campos Verdes",
    "Serranópolis", "Cachoeira de Goiás", "Divinópolis de Goiás", "Gameleira de Goiás",
    "Guapó", "Heitoraí", "Indiara", "Itauçu", "Jandaia", "Jesúpolis", "Joviânia",
    "Leopoldo de Bulhões", "Matrinchã", "Moiporá", "Mutunópolis", "Nazário",
    "Nova América", "Nova Aurora", "Nova Glória", "Novo Brasil"
]

def limpar_tela():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    print("""
\033[1;36m
  ____ _____ _   _ _____ ____ _____   _____ _   _ _______ ______ _____  
 / ___|_   _| \ | | ____/ ___|_ _\ \ / /_ _| \ | | ____|  _ \_   _| 
 \___ \ | | |  \| |  _|| |  _ | | \ V / | ||  \| |  _| | |_) || |   
  ___) || | | |\  | |__| |_| || |  | |  | || |\  | |___|  _ < | |   
 |____/ |_| |_| \_|_____\____|___| |_| |___|_| \_|_____|_| \_\|_|   
\033[0m
\033[1;33m
 OSINT Tool - Geolocalização Avançada no Instagram (Termux)
\033[0m
""")

def extract_locations(text):
    """Extrai possíveis localizações do texto usando regex aprimorado"""
    if not text:
        return []
    
    locations = []
    
    for city in BR_CITIES:
        if re.search(r'\b' + re.escape(city) + r'\b', text, re.IGNORECASE):
            locations.append(city)
    
    
    address_matches = re.findall(r'\b(Rua|Avenida|Av\.|Praça|Travessa)\s[\w\s]+,\s*\d+\b', text, re.IGNORECASE)
    locations.extend(address_matches)
    
    return list(set(locations))  

def extract_contacts(text):
    """Extrai contatos da biografia"""
    phones = re.findall(r'\(\d{2}\)\s?\d{4,5}-\d{4}', text) or []
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', text) or []
    whatsapp = re.findall(r'(whatsapp|wa\.me)[:\s]?[\d\s-]+', text, re.IGNORECASE) or []
    return {"phones": phones, "emails": emails, "whatsapp": whatsapp}

def save_report(username, data):
    """Salva o relatório em JSON com timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ig_report_{username}_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"\n\033[1;32m[+] Relatório salvo como: {filename}\033[0m")
    return filename

def analyze_user_activity(posts):
    """Analisa padrões de horário e frequência de posts"""
    if not posts:
        return None, None, None
    
    post_times = [post.date_local.hour for post in posts if post.date_local]
    post_weekdays = [post.date_local.weekday() for post in posts if post.date_local]
    
    if post_times:
        active_hour = max(set(post_times), key=post_times.count)
        timezone_guess = (active_hour - 12) % 24 - 12
        active_weekday = max(set(post_weekdays), key=post_weekdays.count)
        weekday_names = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
        return active_hour, timezone_guess, weekday_names[active_weekday]
    
    return None, None, None

def get_old_posts_with_locations(profile, max_posts=30):
    """Busca posts antigos com localização"""
    locations = []
    for i, post in enumerate(profile.get_posts()):
        if i >= max_posts:
            break
        if post.location:
            loc_data = {
                "date": str(post.date_local),
                "location": post.location.name,
                "post_url": f"https://instagram.com/p/{post.shortcode}",
                "likes": post.likes
            }
            try:
                if hasattr(post.location, 'lat') and post.location.lat:
                    loc_data["coords"] = (post.location.lat, post.location.lng)
                    loc_data["maps_url"] = f"https://maps.google.com/?q={post.location.lat},{post.location.lng}"
            except:
                pass
            locations.append(loc_data)
    return locations

def get_liked_posts_locations(profile, max_posts=20):
    """Busca localizações em posts curtidos"""
    locations = []
    try:
        for i, post in enumerate(profile.get_liked_posts()):
            if i >= max_posts:
                break
            if post.location:
                loc_data = {
                    "date": str(post.date_local),
                    "location": post.location.name,
                    "post_url": f"https://instagram.com/p/{post.shortcode}",
                    "owner": post.owner_username
                }
                locations.append(loc_data)
    except Exception as e:
        print(f"\n\033[1;31m[!] Erro ao buscar posts curtidos: {str(e)}\033[0m")
    return locations

def generate_heatmap(locations):
    """Gera URL para mapa de calor no Google Maps"""
    if not locations or not any('coords' in loc for loc in locations):
        return None
    
    base_url = "https://maps.googleapis.com/maps/api/staticmap?"
    size = "size=800x400"
    maptype = "maptype=roadmap"
    markers = []
    
    for i, loc in enumerate(locations):
        if 'coords' in loc:
            color = "red" if i == 0 else "blue"  
            markers.append(f"markers=color:{color}%7C{loc['coords'][0]},{loc['coords'][1]}")
    
    markers_str = "&".join(markers)
    return f"{base_url}{size}&{maptype}&{markers_str}"

def show_ascii_map(locations):
    """Mostra um mapa ASCII simplificado"""
    if not locations:
        return
    
    print("\n\033[1;36m🌎 Mapa aproximado:\033[0m")
    print("""
        +-------------------+
        |       • SP        |
        |   • RJ     • BH   |
        | • DF             |
        +-------------------+
    """)
    print("\033[1;33mLegenda:\033[0m")
    for i, loc in enumerate(locations[:3]):  
        print(f"\033[1;34m{i+1}. {loc['location']}\033[0m ({loc['date'].split()[0]})")

def analyze_seasonal_patterns(posts):
    """Analisa padrões sazonais de postagem"""
    monthly_locations = defaultdict(list)
    for post in posts:
        if post.location:
            month = post.date_local.strftime("%Y-%m")
            monthly_locations[month].append(post.location.name)
    
    
    result = []
    for month, locs in sorted(monthly_locations.items()):
        unique_locs = list(set(locs))
        result.append({
            "month": month,
            "locations": unique_locs,
            "count": len(locs)
        })
    
    return result

def detect_trips(locations):
    """Detecta possíveis viagens entre cidades"""
    trips = []
    prev_loc = None
    prev_date = None
    
    for loc in sorted(locations, key=lambda x: x['date']):
        current_loc = loc['location']
        current_date = datetime.strptime(loc['date'], '%Y-%m-%d %H:%M:%S').date()
        
        if prev_loc and current_loc != prev_loc:
            days_diff = (current_date - prev_date).days if prev_date else 0
            trips.append({
                "from": prev_loc,
                "to": current_loc,
                "date": str(current_date),
                "days_since_last": days_diff
            })
        
        prev_loc = current_loc
        prev_date = current_date
    
    return trips

def get_top_locations(locations, by='likes', top_n=3):
    """Retorna os locais mais relevantes por curtidas ou frequência"""
    if not locations:
        return []
    
    if by == 'likes' and all('likes' in loc for loc in locations):
        return sorted(locations, key=lambda x: x.get('likes', 0), reverse=True)[:top_n]
    else:
        
        freq = defaultdict(int)
        for loc in locations:
            freq[loc['location']] += 1
        return sorted(locations, key=lambda x: freq[x['location']], reverse=True)[:top_n]

def investigar_perfil():
    L = instaloader.Instaloader()
    report_data = {}
    
    try:
        username = input("\033[1;32m[?] Digite o nome de usuário do Instagram: \033[0m").strip()
        profile = instaloader.Profile.from_username(L.context, username)
        
        print("\n\033[1;33m[*] Coletando e analisando dados... Isso pode levar alguns minutos\033[0m")
        
      
        report_data['basic_info'] = {
            'username': profile.username,
            'full_name': profile.full_name,
            'bio': profile.biography,
            'external_url': profile.external_url,
            'is_private': profile.is_private,
            'is_verified': profile.is_verified,
            'followers': profile.followers,
            'following': profile.followees,
            'posts_count': profile.mediacount,
            'profile_pic_url': profile.profile_pic_url,
            'last_seen': str(datetime.now())
        }
        
      
        contacts = extract_contacts(profile.biography)
        if any(contacts.values()):
            report_data['contacts'] = contacts
        
        limpar_tela()
        banner()
        
        print("\n\033[1;32m[+] Informações Básicas:\033[0m")
        for key, value in report_data['basic_info'].items():
            if key == 'profile_pic_url':
                print(f"\033[1;34m{key.replace('_', ' ').title()}:\033[0m \033[4;34m{value}\033[0m")
            else:
                print(f"\033[1;34m{key.replace('_', ' ').title()}:\033[0m {value}")
        
      
        if 'contacts' in report_data:
            print("\n\033[1;33m[+] Contatos encontrados na biografia:\033[0m")
            for contact_type, values in report_data['contacts'].items():
                if values:
                    print(f"- {contact_type.title()}: {', '.join(values)}")
        
        
        bio_locations = extract_locations(profile.biography)
        if bio_locations:
            print("\n\033[1;33m[+] Possíveis localizações na biografia:\033[0m")
            for loc in bio_locations:
                print(f"- {loc}")
            report_data['bio_locations'] = bio_locations
        
        
        print("\n\033[1;33m[*] Analisando posts com localização...\033[0m")
        locations = get_old_posts_with_locations(profile)
        report_data['locations'] = locations
        
        if locations:
            
            top_locations = get_top_locations(locations, by='likes')
            print("\n\033[1;32m[+] Locais mais relevantes:\033[0m")
            for i, loc in enumerate(top_locations[:3]):
                print(f"\n{i+1}. 📍 {loc['location']}")
                print(f"   📅 {loc['date']}")
                if 'coords' in loc:
                    print(f"   🌐 Coordenadas: {loc['coords'][0]}, {loc['coords'][1]}")
                    print(f"   🔗 Mapa: {loc['maps_url']}")
                print(f"   👍 Curtidas: {loc.get('likes', 'N/A')}")
                print(f"   📎 Post: {loc['post_url']}")
            
        
            heatmap_url = generate_heatmap(locations)
            if heatmap_url:
                report_data['heatmap_url'] = heatmap_url
                print(f"\n\033[1;32m🗺️ Mapa de calor dos locais:\033[0m \033[4;34m{heatmap_url}\033[0m")
                show_ascii_map(locations)
            
          
            trips = detect_trips(locations)
            if trips:
                print("\n\033[1;33m[+] Possíveis viagens detectadas:\033[0m")
                for trip in trips[:3]:  # Mostra apenas as 3 mais recentes
                    print(f"- De {trip['from']} para {trip['to']} em {trip['date']} "
                          f"(após {trip['days_since_last']} dias)")
                report_data['trips'] = trips
            
        
            seasonal = analyze_seasonal_patterns(profile.get_posts())
            if seasonal:
                print("\n\033[1;33m[+] Padrões sazonais:\033[0m")
                for month_data in seasonal[:6]:  # Mostra os últimos 6 meses
                    print(f"- {month_data['month']}: {', '.join(month_data['locations'][:3])} "
                          f"({month_data['count']} posts)")
                report_data['seasonal_patterns'] = seasonal
        
      
        active_hour, timezone_guess, active_weekday = analyze_user_activity(list(profile.get_posts()))
        if active_hour:
            print(f"\n\033[1;33m⏰ Padrão de atividade:\033[0m")
            print(f"- Horário mais ativo: {active_hour}h")
            print(f"- Dia mais ativo: {active_weekday}")
            print(f"- Estimativa de fuso horário: UTC{timezone_guess:+}")
            report_data['activity_patterns'] = {
                'most_active_hour': active_hour,
                'most_active_weekday': active_weekday,
                'estimated_timezone': f"UTC{timezone_guess:+}"
            }
        
      
        try:
            if profile.has_public_story:
                print("\n\033[1;33m📱 Stories públicos disponíveis (pode conter localização)\033[0m")
                report_data['has_public_story'] = True
        except:
            pass
        
        
        try:
            print("\n\033[1;33m[*] Verificando fotos onde o usuário foi marcado...\033[0m")
            tagged_posts = []
            for post in profile.get_tagged_posts():
                if post.location:
                    tagged_posts.append({
                        "date": str(post.date_local),
                        "location": post.location.name,
                        "post_url": f"https://instagram.com/p/{post.shortcode}",
                        "owner": post.owner_username
                    })
            
            if tagged_posts:
                print("\n\033[1;32m[+] Localizações em fotos onde foi marcado:\033[0m")
                for post in tagged_posts[:3]:  # Mostra apenas as 3 mais recentes
                    print(f"- {post['date']}: {post['location']} (por @{post['owner']})")
                report_data['tagged_posts'] = tagged_posts
        except Exception as e:
            print("\n\033[1;31m[!] Erro ao verificar fotos marcadas\033[0m")
            report_data['tagged_posts_error'] = str(e)
        
      
        print("\n\033[1;33m[*] Analisando posts curtidos...\033[0m")
        liked_locations = get_liked_posts_locations(profile)
        if liked_locations:
            print("\n\033[1;32m[+] Locais em posts curtidos:\033[0m")
            for loc in liked_locations[:3]:  
                print(f"- {loc['location']} (post de @{loc['owner']})")
            report_data['liked_posts_locations'] = liked_locations
        
        
        report_file = save_report(username, report_data)
        
        
        while True:
            print("\n\033[1;35mOpções Adicionais:\033[0m")
            print("1. Abrir mapa de calor no navegador")
            print("2. Ver relatório completo")
            print("3. Voltar ao menu principal")
            
            opcao = input("\n\033[1;32m[?] Escolha uma opção: \033[0m").strip()
            
            if opcao == "1" and 'heatmap_url' in report_data:
                webbrowser.open(report_data['heatmap_url'])
            elif opcao == "2":
                print(f"\n\033[1;33m[*] Relatório salvo em: {report_file}\033[0m")
                print("\033[1;33m[*] Use 'cat' ou um editor para visualizar o arquivo JSON\033[0m")
            elif opcao == "3":
                break
            else:
                print("\n\033[1;31m[!] Opção inválida\033[0m")
        
    except instaloader.exceptions.ProfileNotExistsException:
        print("\n\033[1;31m[!] Perfil não encontrado\033[0m")
    except instaloader.exceptions.ConnectionException:
        print("\n\033[1;31m[!] Erro de conexão. Verifique sua internet\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m[!] Ocorreu um erro: {str(e)}\033[0m")

def main():
    limpar_tela()
    banner()
    
    while True:
        print("\n\033[1;35mMenu Principal:\033[0m")
        print("1. Investigar perfil do Instagram")
        print("2. Sair")
        
        opcao = input("\n\033[1;32m[?] Escolha uma opção: \033[0m").strip()
        
        if opcao == "1":
            investigar_perfil()
        elif opcao == "2":
            print("\n\033[1;33m[*] Saindo...\033[0m")
            break
        else:
            print("\n\033[1;31m[!] Opção inválida\033[0m")
        
        input("\n\033[1;34mPressione Enter para continuar...\033[0m")
        limpar_tela()
        banner()

if __name__ == "__main__":
    main()
