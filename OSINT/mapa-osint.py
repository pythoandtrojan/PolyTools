#!/usr/bin/env python3
"""
PolyTools OSINT - Sistema Completo de Inteligência de Fontes Abertas
Autor: [Seu Nome]
Versão: 1.0
"""

import os
import json
import sqlite3
import requests
import folium
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
import pandas as pd
from PIL import Image, ExifTags
import reverse_geocoder as rg
from datetime import datetime, timedelta
import threading
import time
from io import BytesIO
import base64
import math

# Inicialização do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'osint_secret_key_2024'
socketio = SocketIO(app)

# Banco de dados SQLite
def init_db():
    conn = sqlite3.connect('osint_data.db')
    c = conn.cursor()
    
    # Tabela de pesquisas
    c.execute('''CREATE TABLE IF NOT EXISTS searches
                 (id INTEGER PRIMARY KEY, query TEXT, module TEXT, 
                  results TEXT, timestamp DATETIME, user_id INTEGER)''')
    
    # Tabela de localizações
    c.execute('''CREATE TABLE IF NOT EXISTS locations
                 (id INTEGER PRIMARY KEY, lat REAL, lng REAL, 
                  address TEXT, source TEXT, confidence REAL,
                  timestamp DATETIME)''')
    
    # Tabela de dispositivos
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (id INTEGER PRIMARY KEY, ip TEXT, lat REAL, lng REAL,
                  type TEXT, vendor TEXT, port INTEGER, 
                  timestamp DATETIME)''')
    
    conn.commit()
    conn.close()

init_db()

class OSINTEngine:
    """Motor principal de análise OSINT"""
    
    def __init__(self):
        self.cache = {}
        
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calcula distância entre dois pontos usando fórmula de Haversine"""
        R = 6371  # Raio da Terra em km
        
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        
        a = (math.sin(dlat/2) * math.sin(dlat/2) + 
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * 
             math.sin(dlon/2) * math.sin(dlon/2))
        
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c

    def triangulate_cellular(self, tower_data):
        """Triangulação por torres de celular"""
        if len(tower_data) < 3:
            return None
            
        # Média ponderada baseada na intensidade do sinal
        total_weight = 0
        weighted_lat = 0
        weighted_lng = 0
        
        for tower in tower_data:
            weight = tower.get('signal_strength', 1)
            weighted_lat += tower['lat'] * weight
            weighted_lng += tower['lng'] * weight
            total_weight += weight
            
        return {
            'lat': weighted_lat / total_weight,
            'lng': weighted_lng / total_weight,
            'accuracy': total_weight / len(tower_data),
            'method': 'cellular_triangulation'
        }

    def triangulate_visual(self, reference_points, user_location=None):
        """Triangulação visual baseada em pontos de referência"""
        points = []
        
        for point in reference_points:
            if 'bearing' in point and user_location:
                # Calcula ponto baseado em bearing e distância estimada
                bearing = math.radians(point['bearing'])
                distance = point.get('distance', 1)  # km
                
                lat1 = math.radians(user_location[0])
                lon1 = math.radians(user_location[1])
                
                lat2 = math.asin(math.sin(lat1) * math.cos(distance/6371) + 
                               math.cos(lat1) * math.sin(distance/6371) * math.cos(bearing))
                
                lon2 = lon1 + math.atan2(math.sin(bearing) * math.sin(distance/6371) * math.cos(lat1),
                                       math.cos(distance/6371) - math.sin(lat1) * math.sin(lat2))
                
                points.append({
                    'lat': math.degrees(lat2),
                    'lng': math.degrees(lon2),
                    'confidence': point.get('confidence', 0.5)
                })
            else:
                points.append(point)
        
        if not points:
            return None
            
        # Média simples das coordenadas
        avg_lat = sum(p['lat'] for p in points) / len(points)
        avg_lng = sum(p['lng'] for p in points) / len(points)
        
        return {
            'lat': avg_lat,
            'lng': avg_lng,
            'accuracy': sum(p.get('confidence', 0.5) for p in points) / len(points),
            'method': 'visual_triangulation',
            'points_used': len(points)
        }

    def create_voronoi_diagram(self, points):
        """Cria diagrama de Voronoi para áreas de influência"""
        # Implementação simplificada do diagrama de Voronoi
        voronoi_cells = []
        
        for i, point in enumerate(points):
            cell = {
                'id': i,
                'center': {'lat': point['lat'], 'lng': point['lng']},
                'bounds': self._calculate_voronoi_cell(points, point),
                'influence_radius': point.get('influence_radius', 5)
            }
            voronoi_cells.append(cell)
            
        return voronoi_cells
    
    def _calculate_voronoi_cell(self, all_points, center_point):
        """Calcula célula de Voronoi para um ponto"""
        # Algoritmo simplificado - em produção usar biblioteca especializada
        bounds = []
        for angle in range(0, 360, 45):
            rad_angle = math.radians(angle)
            max_dist = 10  # km
            
            for dist in [1, 2, 5, 10]:
                lat = center_point['lat'] + (dist * math.cos(rad_angle) / 111)
                lng = center_point['lng'] + (dist * math.sin(rad_angle) / (111 * math.cos(math.radians(center_point['lat']))))
                
                # Verifica se este ponto está mais próximo do centro atual
                closest_point = min(all_points, 
                                  key=lambda p: self.calculate_distance(lat, lng, p['lat'], p['lng']))
                
                if closest_point == center_point:
                    bounds.append({'lat': lat, 'lng': lng})
                    break
                    
        return bounds

    def viewshed_analysis(self, center_point, radius_km=5, resolution=100):
        """Análise de área visível a partir de um ponto"""
        visible_points = []
        
        for angle in range(0, 360, 10):
            for dist in range(1, radius_km + 1):
                rad_angle = math.radians(angle)
                
                lat = center_point['lat'] + (dist * math.cos(rad_angle) / 111)
                lng = center_point['lng'] + (dist * math.sin(rad_angle) / 
                                           (111 * math.cos(math.radians(center_point['lat']))))
                
                # Simulação simplificada - em produção integrar com dados de elevação
                is_visible = True  # Placeholder
                
                if is_visible:
                    visible_points.append({
                        'lat': lat,
                        'lng': lng,
                        'distance': dist,
                        'bearing': angle
                    })
                    
        return visible_points

class InstagramModule:
    """Módulo de análise do Instagram"""
    
    def __init__(self):
        self.base_url = "https://www.instagram.com/api/v1"
        
    def search_locations(self, query):
        """Busca localizações no Instagram"""
        # Simulação - em produção usar API oficial ou web scraping
        mock_locations = [
            {
                'name': f'Local {query} 1',
                'lat': -23.5505 + (0.01 * (hash(query) % 10)),
                'lng': -46.6333 + (0.01 * (hash(query) % 10)),
                'posts_count': 150,
                'recent_activity': '2 hours ago'
            },
            {
                'name': f'Local {query} 2', 
                'lat': -23.5605 + (0.01 * (hash(query) % 10)),
                'lng': -46.6433 + (0.01 * (hash(query) % 10)),
                'posts_count': 89,
                'recent_activity': '5 hours ago'
            }
        ]
        return mock_locations

class TwitterModule:
    """Módulo de análise do Twitter"""
    
    def search_geotagged_tweets(self, lat, lng, radius_km=10):
        """Busca tweets geolocalizados"""
        # Simulação - em produção usar Twitter API v2
        mock_tweets = [
            {
                'text': f'Tweet próximo a {lat},{lng}',
                'user': 'user1',
                'timestamp': datetime.now().isoformat(),
                'lat': lat + (0.001 * (hash(str(lat+lng)) % 10)),
                'lng': lng + (0.001 * (hash(str(lat+lng)) % 10)),
                'sentiment': 'positive'
            }
        ]
        return mock_tweets

class EXIFAnalyzer:
    """Analisador de metadados EXIF"""
    
    def __init__(self):
        self.supported_formats = ['JPEG', 'PNG', 'TIFF']
    
    def extract_metadata(self, image_path):
        """Extrai metadados EXIF de imagem"""
        try:
            with Image.open(image_path) as img:
                exif_data = {}
                
                if hasattr(img, '_getexif') and img._getexif():
                    for tag, value in img._getexif().items():
                        tag_name = ExifTags.TAGS.get(tag, tag)
                        exif_data[tag_name] = str(value)
                
                # Informações básicas da imagem
                exif_data['format'] = img.format
                exif_data['size'] = img.size
                exif_data['mode'] = img.mode
                
                return self._parse_gps_data(exif_data)
                
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_gps_data(self, exif_data):
        """Parse dados GPS do EXIF"""
        gps_info = {}
        
        if 'GPSInfo' in exif_data:
            # Processa coordenadas GPS
            gps_data = exif_data['GPSInfo']
            # Implementar conversão de coordenadas GPS
            pass
            
        exif_data['gps'] = gps_info
        return exif_data

# Instâncias globais
osint_engine = OSINTEngine()
instagram_module = InstagramModule()
twitter_module = TwitterModule()
exif_analyzer = EXIFAnalyzer()

# Templates HTML como strings
INDEX_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools OSINT</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .sidebar { background: #2c3e50; color: white; height: 100vh; position: fixed; }
        .module-card { cursor: pointer; transition: transform 0.2s; margin-bottom: 20px; }
        .module-card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
        .dashboard-stats { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .main-content { margin-left: 16.666667%; }
        .navbar { background: #34495e !important; }
        @media (max-width: 768px) {
            .sidebar { position: relative; height: auto; }
            .main-content { margin-left: 0; }
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#"><i class="fas fa-search"></i> PolyTools OSINT</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="/map"><i class="fas fa-map"></i> Mapa</a></li>
                    <li class="nav-item"><a class="nav-link" href="#" onclick="showModal('aboutModal')"><i class="fas fa-info-circle"></i> Sobre</a></li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar p-3">
                <h4 class="text-center mb-4"><i class="fas fa-search-location"></i> Módulos</h4>
                <div class="list-group">
                    <a href="/" class="list-group-item list-group-item-action active">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                    <a href="/map" class="list-group-item list-group-item-action">
                        <i class="fas fa-map-marked-alt"></i> Mapa Interativo
                    </a>
                    <a href="#" class="list-group-item list-group-item-action" onclick="showModal('instagramModal')">
                        <i class="fab fa-instagram"></i> Instagram OSINT
                    </a>
                    <a href="#" class="list-group-item list-group-item-action" onclick="showModal('twitterModal')">
                        <i class="fab fa-twitter"></i> Twitter Analysis
                    </a>
                    <a href="#" class="list-group-item list-group-item-action" onclick="showModal('exifModal')">
                        <i class="fas fa-camera"></i> EXIF Analysis
                    </a>
                    <a href="#" class="list-group-item list-group-item-action" onclick="showModal('triangulationModal')">
                        <i class="fas fa-satellite-dish"></i> Triangulação
                    </a>
                    <a href="#" class="list-group-item list-group-item-action" onclick="showModal('analysisModal')">
                        <i class="fas fa-chart-line"></i> Análise Avançada
                    </a>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 main-content">
                <div class="container-fluid mt-4">
                    <div class="row">
                        <div class="col-12">
                            <h2><i class="fas fa-tachometer-alt"></i> Dashboard OSINT</h2>
                            <p class="text-muted">Sistema completo de inteligência de fontes abertas</p>
                        </div>
                    </div>

                    <!-- Stats Cards -->
                    <div class="row mt-4">
                        <div class="col-xl-3 col-md-6 mb-4">
                            <div class="card dashboard-stats text-white shadow">
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col">
                                            <div class="h5 font-weight-bold">Localizações</div>
                                            <div class="h3">1,248</div>
                                        </div>
                                        <div class="col-auto">
                                            <i class="fas fa-map-marker-alt fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-xl-3 col-md-6 mb-4">
                            <div class="card bg-success text-white shadow">
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col">
                                            <div class="h5 font-weight-bold">Imagens Analisadas</div>
                                            <div class="h3">892</div>
                                        </div>
                                        <div class="col-auto">
                                            <i class="fas fa-camera fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-xl-3 col-md-6 mb-4">
                            <div class="card bg-warning text-white shadow">
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col">
                                            <div class="h5 font-weight-bold">Posts Sociais</div>
                                            <div class="h3">5,672</div>
                                        </div>
                                        <div class="col-auto">
                                            <i class="fas fa-share-alt fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-xl-3 col-md-6 mb-4">
                            <div class="card bg-danger text-white shadow">
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col">
                                            <div class="h5 font-weight-bold">Triangulações</div>
                                            <div class="h3">156</div>
                                        </div>
                                        <div class="col-auto">
                                            <i class="fas fa-satellite-dish fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Modules Grid -->
                    <div class="row mt-4">
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="location.href='/map'">
                                <div class="card-body text-center">
                                    <i class="fas fa-map-marked-alt fa-3x text-primary mb-3"></i>
                                    <h5 class="card-title">Mapa Interativo</h5>
                                    <p class="card-text">Visualização avançada com camadas e ferramentas de análise</p>
                                    <span class="badge bg-primary">Online</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="showModal('instagramModal')">
                                <div class="card-body text-center">
                                    <i class="fab fa-instagram fa-3x text-danger mb-3"></i>
                                    <h5 class="card-title">Instagram OSINT</h5>
                                    <p class="card-text">Análise de localizações, posts e redes sociais</p>
                                    <span class="badge bg-success">Ativo</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="showModal('twitterModal')">
                                <div class="card-body text-center">
                                    <i class="fab fa-twitter fa-3x text-info mb-3"></i>
                                    <h5 class="card-title">Twitter Analysis</h5>
                                    <p class="card-text">Geolocalização de tweets e análise de sentimentos</p>
                                    <span class="badge bg-success">Ativo</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="showModal('exifModal')">
                                <div class="card-body text-center">
                                    <i class="fas fa-camera-retro fa-3x text-success mb-3"></i>
                                    <h5 class="card-title">EXIF Analysis</h5>
                                    <p class="card-text">Extrai metadados e coordenadas de imagens</p>
                                    <span class="badge bg-warning">Beta</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="showModal('triangulationModal')">
                                <div class="card-body text-center">
                                    <i class="fas fa-satellite fa-3x text-warning mb-3"></i>
                                    <h5 class="card-title">Triangulação</h5>
                                    <p class="card-text">Celular, visual e temporal</p>
                                    <span class="badge bg-info">Nova</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4 mb-4">
                            <div class="card module-card shadow" onclick="showModal('analysisModal')">
                                <div class="card-body text-center">
                                    <i class="fas fa-chart-network fa-3x text-purple mb-3"></i>
                                    <h5 class="card-title">Análise Avançada</h5>
                                    <p class="card-text">Voronoi, Viewshed, Buffer Analysis</p>
                                    <span class="badge bg-danger">Premium</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity -->
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="card">
                                <div class="card-header">
                                    <h5><i class="fas fa-history"></i> Atividade Recente</h5>
                                </div>
                                <div class="card-body">
                                    <div class="list-group">
                                        <div class="list-group-item">
                                            <div class="d-flex w-100 justify-content-between">
                                                <h6 class="mb-1">Busca no Instagram: "São Paulo"</h6>
                                                <small>2 minutos atrás</small>
                                            </div>
                                            <p class="mb-1">15 localizações encontradas</p>
                                        </div>
                                        <div class="list-group-item">
                                            <div class="d-flex w-100 justify-content-between">
                                                <h6 class="mb-1">Análise EXIF concluída</h6>
                                                <small>5 minutos atrás</small>
                                            </div>
                                            <p class="mb-1">Imagem: photo123.jpg - Dados GPS extraídos</p>
                                        </div>
                                        <div class="list-group-item">
                                            <div class="d-flex w-100 justify-content-between">
                                                <h6 class="mb-1">Triangulação celular</h6>
                                                <small>10 minutos atrás</small>
                                            </div>
                                            <p class="mb-1">3 torres processadas - Precisão: 85%</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal fade" id="aboutModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Sobre o PolyTools OSINT</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p><strong>Versão:</strong> 1.0</p>
                    <p><strong>Descrição:</strong> Sistema completo de inteligência de fontes abertas</p>
                    <p><strong>Desenvolvido para:</strong> Pesquisa e análise de dados públicos</p>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Este sistema é para fins educacionais e de pesquisa.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="instagramModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fab fa-instagram"></i> Instagram OSINT</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="instagramQuery" class="form-label">Buscar Localizações:</label>
                        <input type="text" class="form-control" id="instagramQuery" placeholder="Digite localização...">
                    </div>
                    <button class="btn btn-danger" onclick="searchInstagram()">
                        <i class="fas fa-search"></i> Buscar
                    </button>
                    <hr>
                    <div id="instagramResults"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="twitterModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fab fa-twitter"></i> Twitter Analysis</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Latitude:</label>
                                <input type="number" class="form-control" id="twitterLat" value="-23.5505" step="0.0001">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Longitude:</label>
                                <input type="number" class="form-control" id="twitterLng" value="-46.6333" step="0.0001">
                            </div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Raio (km):</label>
                        <input type="number" class="form-control" id="twitterRadius" value="10">
                    </div>
                    <button class="btn btn-info" onclick="searchTwitter()">
                        <i class="fas fa-search"></i> Buscar Tweets
                    </button>
                    <hr>
                    <div id="twitterResults"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    <script>
        function showModal(modalId) {
            var modal = new bootstrap.Modal(document.getElementById(modalId));
            modal.show();
        }

        function searchInstagram() {
            const query = document.getElementById('instagramQuery').value;
            if (!query) {
                alert('Digite um termo para buscar');
                return;
            }

            fetch(`/api/search/instagram?query=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => {
                    const resultsDiv = document.getElementById('instagramResults');
                    resultsDiv.innerHTML = '<h6>Resultados:</h6>';
                    
                    data.forEach(location => {
                        resultsDiv.innerHTML += `
                            <div class="card mb-2">
                                <div class="card-body">
                                    <h6>${location.name}</h6>
                                    <p>Coordenadas: ${location.lat.toFixed(4)}, ${location.lng.toFixed(4)}</p>
                                    <p>Posts: ${location.posts_count} | ${location.recent_activity}</p>
                                </div>
                            </div>
                        `;
                    });
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro na busca');
                });
        }

        function searchTwitter() {
            const lat = document.getElementById('twitterLat').value;
            const lng = document.getElementById('twitterLng').value;
            const radius = document.getElementById('twitterRadius').value;

            fetch(`/api/search/twitter?lat=${lat}&lng=${lng}&radius=${radius}`)
                .then(response => response.json())
                .then(data => {
                    const resultsDiv = document.getElementById('twitterResults');
                    resultsDiv.innerHTML = '<h6>Tweets Encontrados:</h6>';
                    
                    data.forEach(tweet => {
                        resultsDiv.innerHTML += `
                            <div class="card mb-2">
                                <div class="card-body">
                                    <p>${tweet.text}</p>
                                    <small>Por: ${tweet.user} | ${new Date(tweet.timestamp).toLocaleString()}</small>
                                    <br>
                                    <small>Local: ${tweet.lat.toFixed(4)}, ${tweet.lng.toFixed(4)}</small>
                                    <span class="badge bg-${tweet.sentiment === 'positive' ? 'success' : 'warning'}">${tweet.sentiment}</span>
                                </div>
                            </div>
                        `;
                    });
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro na busca');
                });
        }

        // Inicialização
        document.addEventListener('DOMContentLoaded', function() {
            console.log('PolyTools OSINT carregado!');
        });
    </script>
</body>
</html>
'''

MAP_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mapa Interativo - PolyTools OSINT</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        #map { 
            height: 100vh; 
            width: 100%;
        }
        .map-controls { 
            position: absolute; 
            top: 10px; 
            right: 10px; 
            z-index: 1000; 
            background: white; 
            padding: 15px; 
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            max-width: 300px;
        }
        .sidebar-map { 
            position: absolute; 
            left: 10px; 
            top: 10px; 
            z-index: 1000; 
            background: white; 
            padding: 15px; 
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            width: 300px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .nav-tabs .nav-link.active {
            background: #007bff;
            color: white;
            border: none;
        }
        .analysis-panel {
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin-top: 10px;
            display: none;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><i class="fas fa-arrow-left"></i> Voltar ao Dashboard</a>
            <span class="navbar-text">Mapa Interativo OSINT</span>
        </div>
    </nav>

    <div id="map"></div>
    
    <div class="sidebar-map">
        <h5><i class="fas fa-tools"></i> Ferramentas OSINT</h5>
        
        <ul class="nav nav-tabs" id="toolsTab">
            <li class="nav-item">
                <a class="nav-link active" href="#basic">Básico</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#advanced">Avançado</a>
            </li>
        </ul>

        <div class="tab-content mt-2">
            <div class="tab-pane active" id="basic">
                <div class="btn-group-vertical w-100">
                    <button class="btn btn-primary mb-2" onclick="searchLocation()">
                        <i class="fas fa-search"></i> Buscar Localização
                    </button>
                    <button class="btn btn-info mb-2" onclick="addMarker()">
                        <i class="fas fa-map-marker-alt"></i> Adicionar Marcador
                    </button>
                    <button class="btn btn-warning mb-2" onclick="drawCircle()">
                        <i class="fas fa-circle"></i> Círculo de Distância
                    </button>
                    <button class="btn btn-success mb-2" onclick="showAnalysisPanel()">
                        <i class="fas fa-chart-area"></i> Análise de Área
                    </button>
                </div>

                <div class="mt-3">
                    <h6>Camadas:</h6>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="layerInstagram" checked onchange="toggleLayer('instagram')">
                        <label class="form-check-label" for="layerInstagram">Instagram</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="layerTwitter" checked onchange="toggleLayer('twitter')">
                        <label class="form-check-label" for="layerTwitter">Twitter</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="layerDevices" onchange="toggleLayer('devices')">
                        <label class="form-check-label" for="layerDevices">Dispositivos</label>
                    </div>
                </div>
            </div>

            <div class="tab-pane" id="advanced">
                <div class="btn-group-vertical w-100">
                    <button class="btn btn-danger mb-2" onclick="startTriangulation()">
                        <i class="fas fa-satellite-dish"></i> Triangulação
                    </button>
                    <button class="btn btn-purple mb-2" onclick="createVoronoi()" style="background: #6f42c1; color: white;">
                        <i class="fas fa-project-diagram"></i> Voronoi
                    </button>
                    <button class="btn btn-teal mb-2" onclick="analyzeViewshed()" style="background: #20c997; color: white;">
                        <i class="fas fa-binoculars"></i> Viewshed
                    </button>
                    <button class="btn btn-orange mb-2" onclick="exportData()" style="background: #fd7e14; color: white;">
                        <i class="fas fa-download"></i> Exportar
                    </button>
                </div>
            </div>
        </div>

        <!-- Painel de Análise -->
        <div class="analysis-panel" id="analysisPanel">
            <h6>Análise de Área</h6>
            <div class="mb-2">
                <label>Raio (km):</label>
                <input type="number" id="analysisRadius" class="form-control" value="5" min="1" max="50">
            </div>
            <div class="mb-2">
                <label>Tipo de Análise:</label>
                <select id="analysisType" class="form-select">
                    <option value="buffer">Buffer Analysis</option>
                    <option value="coverage">Cobertura</option>
                    <option value="density">Densidade</option>
                </select>
            </div>
            <button class="btn btn-primary btn-sm w-100" onclick="performAnalysis()">Executar</button>
            <button class="btn btn-secondary btn-sm w-100 mt-1" onclick="hideAnalysisPanel()">Fechar</button>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    <script>
        // Inicialização do mapa
        var map = L.map('map').setView([-23.5505, -46.6333], 12);
        var markers = L.layerGroup().addTo(map);
        var circles = L.layerGroup().addTo(map);
        var currentTool = null;
        
        // Camadas base
        var osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);
        
        var satelliteLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            attribution: '© Esri'
        });

        // Controle de layers
        var baseLayers = {
            "Mapa": osmLayer,
            "Satélite": satelliteLayer
        };
        
        var overlayLayers = {
            "Marcadores": markers,
            "Círculos": circles
        };
        
        L.control.layers(baseLayers, overlayLayers).addTo(map);

        // Inicializa tabs
        var triggerTabList = [].slice.call(document.querySelectorAll('#toolsTab a'))
        triggerTabList.forEach(function (triggerEl) {
            var tabTrigger = new bootstrap.Tab(triggerEl)
            triggerEl.addEventListener('click', function (event) {
                event.preventDefault()
                tabTrigger.show()
            })
        });

        // Funções das ferramentas
        function searchLocation() {
            var query = prompt("Digite endereço ou coordenadas (lat,lng):");
            if (query) {
                // Simulação de geocoding - em produção integrar com API
                if (query.includes(',')) {
                    var coords = query.split(',').map(coord => parseFloat(coord.trim()));
                    if (coords.length === 2) {
                        map.setView(coords, 15);
                        L.marker(coords).addTo(markers)
                            .bindPopup("Localização: " + query)
                            .openPopup();
                    }
                } else {
                    alert("Buscando: " + query + " (simulação)");
                    // Aqui integraria com API de geocoding real
                }
            }
        }
        
        function addMarker() {
            alert("Clique no mapa para adicionar marcador");
            currentTool = 'marker';
            map.once('click', function(e) {
                var marker = L.marker(e.latlng).addTo(markers);
                marker.bindPopup(`
                    <b>Marcador Personalizado</b><br>
                    Coord: ${e.latlng.lat.toFixed(4)}, ${e.latlng.lng.toFixed(4)}<br>
                    <button onclick="removeMarker(${marker._leaflet_id})" class="btn btn-sm btn-danger">Remover</button>
                `).openPopup();
                currentTool = null;
            });
        }
        
        function removeMarker(markerId) {
            map.eachLayer(function(layer) {
                if (layer._leaflet_id === markerId) {
                    map.removeLayer(layer);
                }
            });
        }
        
        function drawCircle() {
            var radius = prompt("Raio do círculo (km):", "1");
            if (radius && !isNaN(radius)) {
                alert("Clique no centro do círculo");
                currentTool = 'circle';
                map.once('click', function(e) {
                    var circle = L.circle(e.latlng, {
                        radius: radius * 1000,
                        color: 'blue',
                        fillColor: '#00f',
                        fillOpacity: 0.1
                    }).addTo(circles);
                    
                    circle.bindPopup(`
                        <b>Círculo de Análise</b><br>
                        Raio: ${radius}km<br>
                        Centro: ${e.latlng.lat.toFixed(4)}, ${e.latlng.lng.toFixed(4)}<br>
                        <button onclick="removeCircle(${circle._leaflet_id})" class="btn btn-sm btn-danger">Remover</button>
                    `).openPopup();
                    currentTool = null;
                });
            }
        }
        
        function removeCircle(circleId) {
            map.eachLayer(function(layer) {
                if (layer._leaflet_id === circleId) {
                    map.removeLayer(layer);
                }
            });
        }
        
        function showAnalysisPanel() {
            document.getElementById('analysisPanel').style.display = 'block';
        }
        
        function hideAnalysisPanel() {
            document.getElementById('analysisPanel').style.display = 'none';
        }
        
        function performAnalysis() {
            var radius = document.getElementById('analysisRadius').value;
            var type = document.getElementById('analysisType').value;
            alert(`Executando análise ${type} com raio de ${radius}km - Em desenvolvimento`);
        }
        
        function startTriangulation() {
            alert("Módulo de Triangulação - Em desenvolvimento");
        }
        
        function createVoronoi() {
            alert("Diagramas de Voronoi - Em desenvolvimento");
        }
        
        function analyzeViewshed() {
            alert("Análise Viewshed - Em desenvolvimento");
        }
        
        function exportData() {
            alert("Exportando dados...");
            window.open('/api/export/kml', '_blank');
        }
        
        function toggleLayer(layerType) {
            alert("Camada " + layerType + " alterada - Em desenvolvimento");
        }

        // Adiciona alguns marcadores de exemplo
        L.marker([-23.5505, -46.6333]).addTo(markers)
            .bindPopup("<b>São Paulo</b><br>Localização exemplo<br><small>Fonte: OpenStreetMap</small>")
            .openPopup();
            
        L.marker([-23.5605, -46.6433]).addTo(markers)
            .bindPopup("<b>Ponto de Interesse</b><br>Instagram location<br><small>15 posts recentes</small>");

        // Adiciona círculo de exemplo
        L.circle([-23.5505, -46.6333], {
            radius: 2000,
            color: 'red',
            fillColor: '#f03',
            fillOpacity: 0.1
        }).addTo(circles).bindPopup("Área de cobertura exemplo - 2km");

        console.log("Mapa OSINT carregado com sucesso!");
    </script>
</body>
</html>
'''

# Rotas da aplicação
@app.route('/')
def index():
    """Página principal do dashboard"""
    return INDEX_HTML

@app.route('/map')
def map_view():
    """Visualização do mapa interativo"""
    return MAP_HTML

@app.route('/api/search/instagram')
def search_instagram():
    """API para busca no Instagram"""
    query = request.args.get('query', '')
    results = instagram_module.search_locations(query)
    return jsonify(results)

@app.route('/api/search/twitter')
def search_twitter():
    """API para busca no Twitter"""
    lat = float(request.args.get('lat', -23.5505))
    lng = float(request.args.get('lng', -46.6333))
    radius = float(request.args.get('radius', 10))
    
    results = twitter_module.search_geotagged_tweets(lat, lng, radius)
    return jsonify(results)

@app.route('/api/triangulate/cellular', methods=['POST'])
def triangulate_cellular():
    """API para triangulação por celular"""
    tower_data = request.json.get('towers', [])
    result = osint_engine.triangulate_cellular(tower_data)
    return jsonify(result or {'error': 'Dados insuficientes'})

@app.route('/api/triangulate/visual', methods=['POST'])
def triangulate_visual():
    """API para triangulação visual"""
    reference_points = request.json.get('points', [])
    user_location = request.json.get('user_location')
    
    result = osint_engine.triangulate_visual(reference_points, user_location)
    return jsonify(result or {'error': 'Dados insuficientes'})

@app.route('/api/analysis/voronoi', methods=['POST'])
def create_voronoi():
    """API para criação de diagramas de Voronoi"""
    points = request.json.get('points', [])
    result = osint_engine.create_voronoi_diagram(points)
    return jsonify(result)

@app.route('/api/analysis/viewshed', methods=['POST'])
def analyze_viewshed():
    """API para análise de área visível"""
    center_point = request.json.get('center')
    radius = request.json.get('radius', 5)
    
    if not center_point:
        return jsonify({'error': 'Ponto central não especificado'})
        
    result = osint_engine.viewshed_analysis(center_point, radius)
    return jsonify(result)

@app.route('/api/upload/image', methods=['POST'])
def upload_image():
    """API para upload e análise de imagem"""
    if 'image' not in request.files:
        return jsonify({'error': 'Nenhuma imagem enviada'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo vazio'})
    
    # Salva arquivo temporariamente
    temp_path = f"temp_{datetime.now().timestamp()}.jpg"
    file.save(temp_path)
    
    # Analisa metadados
    metadata = exif_analyzer.extract_metadata(temp_path)
    
    # Limpa arquivo temporário
    os.remove(temp_path)
    
    return jsonify(metadata)

@app.route('/api/analysis/buffer', methods=['POST'])
def create_buffer():
    """Cria buffer analysis (círculos de distância)"""
    center = request.json.get('center')
    distances = request.json.get('distances', [1, 2, 5, 10])  # em km
    
    if not center:
        return jsonify({'error': 'Ponto central não especificado'})
    
    buffers = []
    for distance in distances:
        buffer_points = []
        for angle in range(0, 360, 10):
            rad_angle = math.radians(angle)
            lat = center['lat'] + (distance * math.cos(rad_angle) / 111)
            lng = center['lng'] + (distance * math.sin(rad_angle) / 
                                 (111 * math.cos(math.radians(center['lat']))))
            buffer_points.append({'lat': lat, 'lng': lng})
        
        buffers.append({
            'distance': distance,
            'points': buffer_points
        })
    
    return jsonify(buffers)

@app.route('/api/export/kml')
def export_kml():
    """Exporta dados para KML"""
    kml_content = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<name>PolyTools OSINT Export</name>
<description>Exportação de dados OSINT - PolyTools</description>
<Placemark>
<name>Ponto de Exemplo</name>
<description>Localização exportada do sistema OSINT</description>
<Point>
<coordinates>-46.6333,-23.5505,0</coordinates>
</Point>
</Placemark>
</Document>
</kml>"""
    
    return send_file(
        BytesIO(kml_content.encode()),
        mimetype='application/vnd.google-earth.kml+xml',
        as_attachment=True,
        download_name='osint_export.kml'
    )

@app.route('/api/health')
def health_check():
    """Endpoint de saúde da aplicação"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0',
        'modules': {
            'instagram': 'active',
            'twitter': 'active', 
            'exif': 'active',
            'triangulation': 'active'
        }
    })

if __name__ == '__main__':
    print("""
    🚀 PolyTools OSINT System Iniciando...
    
    📍 Dashboard: http://localhost:5000
    🗺️  Mapa: http://localhost:5000/map
    ❤️  Saúde: http://localhost:5000/api/health
    
    ⚠️  Este é um sistema demonstrativo para fins educacionais
    
    Módulos Disponíveis:
    ✅ Instagram OSINT
    ✅ Twitter Analysis  
    ✅ EXIF Analysis
    ✅ Triangulação Avançada
    ✅ Mapa Interativo
    ✅ Análise de Área
    ✅ Export KML
    """)
    
    # Criar diretório para uploads se não existir
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
