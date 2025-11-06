#!/usr/bin/env python3
"""
PolyTools - WolfPack Network Analyzer
WireShark-like tool for Termux with web interface
Symbol: Lone Wolf
"""

import os
import sys
import json
import time
import threading
import math
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from flask import Flask, render_template_string, request, jsonify
import netifaces as ni
import psutil
import subprocess
import signal
import socket
import struct
import random
from collections import deque, defaultdict

app = Flask(__name__)

# Configurações
CONFIG = {
    'capture_file': '/data/data/com.termux/files/home/capture.pcap',
    'update_interval': 2,
    'max_packets': 2000,
    'interfaces': [],
    'target_ports': '1-1000',
    'history_size': 50
}

# Dados globais
captured_packets = []
packet_history = deque(maxlen=CONFIG['history_size'])
bandwidth_history = deque(maxlen=CONFIG['history_size'])
security_alerts = []

# Estatísticas de segurança
PORT_SECURITY = {
    21: {'risk': 'Médio', 'service': 'FTP', 'description': 'Transferência de arquivos - senhas em texto claro'},
    22: {'risk': 'Baixo', 'service': 'SSH', 'description': 'Conexão segura - geralmente seguro'},
    23: {'risk': 'Alto', 'service': 'Telnet', 'description': 'Não criptografado - muito perigoso'},
    25: {'risk': 'Médio', 'service': 'SMTP', 'description': 'Email - pode ser explorado'},
    53: {'risk': 'Baixo', 'service': 'DNS', 'description': 'Resolução de nomes - geralmente seguro'},
    80: {'risk': 'Baixo', 'service': 'HTTP', 'description': 'Web - tráfego não criptografado'},
    110: {'risk': 'Médio', 'service': 'POP3', 'description': 'Email - senhas em texto claro'},
    135: {'risk': 'Alto', 'service': 'RPC', 'description': 'Remote Procedure Call - vulnerável'},
    139: {'risk': 'Alto', 'service': 'NetBIOS', 'description': 'Compartilhamento de arquivos - vulnerável'},
    143: {'risk': 'Médio', 'service': 'IMAP', 'description': 'Email - pode ser explorado'},
    443: {'risk': 'Baixo', 'service': 'HTTPS', 'description': 'Web seguro - geralmente seguro'},
    445: {'risk': 'Alto', 'service': 'SMB', 'description': 'Compartilhamento Windows - muito vulnerável'},
    993: {'risk': 'Baixo', 'service': 'IMAPS', 'description': 'IMAP seguro - geralmente seguro'},
    995: {'risk': 'Baixo', 'service': 'POP3S', 'description': 'POP3 seguro - geralmente seguro'},
    1433: {'risk': 'Alto', 'service': 'MSSQL', 'description': 'SQL Server - frequentemente atacado'},
    3306: {'risk': 'Médio', 'service': 'MySQL', 'description': 'Database - pode ser explorado'},
    3389: {'risk': 'Médio', 'service': 'RDP', 'description': 'Área de trabalho remota - vulnerável'},
    5432: {'risk': 'Médio', 'service': 'PostgreSQL', 'description': 'Database - pode ser explorado'},
    5900: {'risk': 'Médio', 'service': 'VNC', 'description': 'Controle remoto - pode ser inseguro'},
    8080: {'risk': 'Baixo', 'service': 'HTTP-Alt', 'description': 'Web alternativo - depende da configuração'}
}

capture_stats = {
    'total_packets': 0,
    'tcp_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'other_packets': 0,
    'start_time': None,
    'bandwidth_usage': 0,
    'packets_per_second': 0,
    'suspicious_activity': 0
}

# Thread de captura
capture_thread = None
capture_running = False
last_update_time = time.time()
packet_count_since_update = 0

def get_interfaces():
    """Obtém interfaces de rede disponíveis"""
    interfaces = []
    try:
        for interface in ni.interfaces():
            try:
                addrs = ni.ifaddresses(interface)
                if ni.AF_INET in addrs:
                    ip = addrs[ni.AF_INET][0]['addr']
                    netmask = addrs[ni.AF_INET][0].get('netmask', 'N/A')
                    interfaces.append({
                        'name': interface,
                        'ip': ip,
                        'netmask': netmask,
                        'status': 'up'
                    })
                else:
                    interfaces.append({
                        'name': interface,
                        'ip': 'N/A',
                        'netmask': 'N/A',
                        'status': 'down'
                    })
            except:
                interfaces.append({
                    'name': interface,
                    'ip': 'N/A',
                    'netmask': 'N/A',
                    'status': 'error'
                })
    except Exception as e:
        print(f"Erro ao obter interfaces: {e}")
        interfaces = [{'name': 'any', 'ip': 'N/A', 'netmask': 'N/A', 'status': 'up'}]
    
    return interfaces

def analyze_packet_security(packet):
    """Analisa a segurança do pacote"""
    alerts = []
    
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Verifica portas conhecidas
            if TCP in packet:
                dst_port = packet[TCP].dport
                if dst_port in PORT_SECURITY:
                    risk_info = PORT_SECURITY[dst_port]
                    if risk_info['risk'] in ['Alto', 'Médio']:
                        alerts.append({
                            'type': 'PORT_RISK',
                            'risk': risk_info['risk'],
                            'message': f"Porta {dst_port} ({risk_info['service']}) - {risk_info['description']}",
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'port': dst_port,
                            'timestamp': datetime.now().strftime('%H:%M:%S')
                        })
            
            # Verifica padrões suspeitos
            if TCP in packet and packet[TCP].flags == 2:  # SYN apenas
                alerts.append({
                    'type': 'SYN_SCAN',
                    'risk': 'Médio',
                    'message': f"Possível scan SYN de {src_ip} para {dst_ip}",
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })
                
    except Exception as e:
        pass
    
    return alerts

def packet_handler(packet):
    """Manipula pacotes capturados"""
    global captured_packets, capture_stats, packet_count_since_update, security_alerts
    
    if len(captured_packets) >= CONFIG['max_packets']:
        captured_packets.pop(0)
    
    packet_info = {
        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'protocol': 'Unknown',
        'length': len(packet),
        'info': str(packet.summary()),
        'risk': 'Baixo'
    }
    
    try:
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                capture_stats['tcp_packets'] += 1
                
                # Análise de segurança
                security_analysis = analyze_packet_security(packet)
                security_alerts.extend(security_analysis)
                if security_analysis:
                    packet_info['risk'] = security_analysis[0]['risk']
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                capture_stats['udp_packets'] += 1
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                capture_stats['icmp_packets'] += 1
            else:
                capture_stats['other_packets'] += 1
                
        capture_stats['total_packets'] += 1
        packet_count_since_update += 1
        captured_packets.append(packet_info)
        
        # Atualiza histórico
        current_time = time.time()
        packet_history.append({
            'time': current_time,
            'count': 1,
            'size': len(packet)
        })
        
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")

def calculate_bandwidth():
    """Calcula a largura de banda em tempo real"""
    global bandwidth_history
    
    try:
        net_io = psutil.net_io_counters()
        current_bandwidth = (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024  # MB
        
        bandwidth_history.append({
            'time': time.time(),
            'bandwidth': current_bandwidth
        })
        
        return current_bandwidth
    except:
        return 0

def calculate_pps():
    """Calcula pacotes por segundo"""
    global last_update_time, packet_count_since_update
    
    current_time = time.time()
    time_diff = current_time - last_update_time
    
    if time_diff > 0:
        pps = packet_count_since_update / time_diff
        packet_count_since_update = 0
        last_update_time = current_time
        return round(pps, 2)
    
    return 0

def start_capture(interface):
    """Inicia captura de pacotes"""
    global capture_running, capture_stats, security_alerts
    capture_running = True
    security_alerts = []
    capture_stats = {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'start_time': datetime.now().strftime('%H:%M:%S'),
        'bandwidth_usage': 0,
        'packets_per_second': 0,
        'suspicious_activity': 0
    }
    
    try:
        print(f"Iniciando captura na interface: {interface}")
        if interface == 'any':
            sniff(prn=packet_handler, store=0, stop_filter=lambda x: not capture_running)
        else:
            sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: not capture_running)
    except Exception as e:
        print(f"Erro na captura: {e}")
    finally:
        capture_running = False

def get_network_info():
    """Obtém informações de rede"""
    try:
        # Estatísticas de rede
        bandwidth = calculate_bandwidth()
        pps = calculate_pps()
        
        # Conexões ativas
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr:
                status = conn.status
                if status == 'ESTABLISHED':
                    risk = 'Baixo'
                elif status == 'LISTEN':
                    risk = 'Médio'
                else:
                    risk = 'Alto'
                    
                connections.append({
                    'protocol': conn.type,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'status': status,
                    'risk': risk
                })
        
        return {
            'bandwidth_mb': round(bandwidth, 2),
            'active_connections': len(connections),
            'packets_per_second': pps,
            'connections': connections[:15]
        }
    except Exception as e:
        print(f"Erro ao obter info de rede: {e}")
        return {'bandwidth_mb': 0, 'active_connections': 0, 'packets_per_second': 0, 'connections': []}

def prepare_chart_data():
    """Prepara dados para gráficos - CORRIGIDO"""
    global packet_history, bandwidth_history
    
    # Dados para gráfico de pacotes (últimos 20 pontos)
    recent_packets = list(packet_history)[-20:]
    packet_times = [entry['time'] for entry in recent_packets]
    packet_counts = [entry['count'] for entry in recent_packets]
    
    # Dados para gráfico de banda (últimos 20 pontos)
    recent_bandwidth = list(bandwidth_history)[-20:]
    bw_times = [entry['time'] for entry in recent_bandwidth]
    bw_values = [entry['bandwidth'] for entry in recent_bandwidth]
    
    return {
        'packet_times': packet_times,
        'packet_counts': packet_counts,
        'bw_times': bw_times,
        'bw_values': [round(bw, 2) for bw in bw_values]
    }

def validate_ports(ports_str):
    """Valida e formata a string de portas"""
    if not ports_str:
        return "1-1000"
    
    ports_str = ports_str.replace(" ", "")
    
    if not all(c in '0123456789,-' for c in ports_str):
        return "1-1000"
    
    return ports_str

def simple_port_scan(target, ports):
    """Scanner de portas simples integrado"""
    try:
        open_ports = []
        ports_list = []
        
        # Parse port ranges
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports_list.extend(range(start, end + 1))
            else:
                ports_list.append(int(part))
        
        # Remove duplicates and sort
        ports_list = sorted(set(ports_list))
        
        results = []
        for port in ports_list[:100]:  # Limita a 100 portas para performance
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                is_open = result == 0
                risk_info = PORT_SECURITY.get(port, {'risk': 'Desconhecido', 'service': 'Unknown', 'description': 'Porta não catalogada'})
                
                results.append({
                    'port': port,
                    'status': 'Aberta' if is_open else 'Fechada',
                    'risk': risk_info['risk'],
                    'service': risk_info['service'],
                    'description': risk_info['description']
                })
                
                if is_open:
                    open_ports.append(port)
                    
            except:
                pass
        
        return {
            'open_ports': open_ports,
            'results': results,
            'total_scanned': len(ports_list),
            'open_count': len(open_ports)
        }
        
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    """Página principal"""
    interfaces = get_interfaces()
    
    html_template = """
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🐺 WolfPack - Network Analyzer</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            :root {
                --primary: #1a202c;
                --secondary: #2d3748;
                --accent: #e53e3e;
                --success: #38a169;
                --warning: #d69e2e;
                --danger: #e53e3e;
                --text: #e2e8f0;
                --background: #0f1419;
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--background) 0%, #1a202c 100%);
                color: var(--text);
                line-height: 1.6;
                min-height: 100vh;
            }
            
            .header {
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                padding: 1.5rem;
                text-align: center;
                border-bottom: 3px solid var(--accent);
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            
            .logo {
                font-size: 2.5rem;
                font-weight: bold;
                background: linear-gradient(45deg, #e53e3e, #ed8936);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 0.5rem;
            }
            
            .subtitle {
                font-size: 1rem;
                opacity: 0.8;
                color: #a0aec0;
            }
            
            .container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 1rem;
            }
            
            .dashboard {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 1.5rem;
                margin-bottom: 1.5rem;
            }
            
            .card {
                background: rgba(45, 55, 72, 0.8);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 1.5rem;
                border-left: 4px solid var(--accent);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                transition: transform 0.3s, box-shadow 0.3s;
            }
            
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
            }
            
            .card h3 {
                margin-bottom: 1rem;
                color: #edf2f7;
                border-bottom: 2px solid var(--accent);
                padding-bottom: 0.5rem;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 1rem;
                margin-bottom: 1rem;
            }
            
            .stat-card {
                background: rgba(26, 32, 44, 0.6);
                padding: 1rem;
                border-radius: 8px;
                text-align: center;
                border: 1px solid #4a5568;
            }
            
            .stat-number {
                font-size: 1.8rem;
                font-weight: bold;
                margin-bottom: 0.5rem;
            }
            
            .stat-tcp { color: #68d391; }
            .stat-udp { color: #63b3ed; }
            .stat-icmp { color: #fbb6ce; }
            .stat-total { color: #e53e3e; }
            .stat-bandwidth { color: #ed8936; }
            .stat-pps { color: #9f7aea; }
            
            .controls {
                display: flex;
                gap: 0.8rem;
                margin-bottom: 1rem;
                flex-wrap: wrap;
            }
            
            .btn {
                padding: 0.7rem 1.2rem;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-family: inherit;
                font-weight: 600;
                transition: all 0.3s;
                font-size: 0.9rem;
            }
            
            .btn-primary {
                background: linear-gradient(45deg, #e53e3e, #ed8936);
                color: white;
            }
            
            .btn-secondary {
                background: #4a5568;
                color: var(--text);
                border: 1px solid #718096;
            }
            
            .btn-success {
                background: linear-gradient(45deg, #38a169, #48bb78);
                color: white;
            }
            
            .btn-danger {
                background: linear-gradient(45deg, #e53e3e, #c53030);
                color: white;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            }
            
            select, input {
                padding: 0.7rem;
                border-radius: 6px;
                border: 1px solid #4a5568;
                background: #2d3748;
                color: var(--text);
                font-family: inherit;
                flex: 1;
            }
            
            .chart-container {
                height: 200px;
                margin-top: 1rem;
            }
            
            .packet-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
                font-size: 0.85rem;
            }
            
            .packet-table th {
                background: #2d3748;
                padding: 0.8rem;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid var(--accent);
            }
            
            .packet-table td {
                padding: 0.6rem;
                border-bottom: 1px solid #4a5568;
            }
            
            .packet-row:hover {
                background: rgba(66, 153, 225, 0.1);
            }
            
            .risk-low { color: #68d391; border-left: 3px solid #68d391; }
            .risk-medium { color: #ed8936; border-left: 3px solid #ed8936; }
            .risk-high { color: #e53e3e; border-left: 3px solid #e53e3e; }
            
            .terminal {
                background: #1a202c;
                color: #68d391;
                padding: 1rem;
                border-radius: 6px;
                font-family: 'Courier New', monospace;
                height: 300px;
                overflow-y: auto;
                font-size: 0.85rem;
                white-space: pre-wrap;
                border: 1px solid #4a5568;
            }
            
            .alert-box {
                background: rgba(229, 62, 62, 0.1);
                border: 1px solid #e53e3e;
                border-radius: 6px;
                padding: 1rem;
                margin: 1rem 0;
            }
            
            .security-alerts {
                max-height: 200px;
                overflow-y: auto;
            }
            
            .alert-item {
                padding: 0.5rem;
                margin: 0.3rem 0;
                border-radius: 4px;
                background: rgba(229, 62, 62, 0.1);
                border-left: 3px solid #e53e3e;
            }
            
            .tab-container {
                margin: 1rem 0;
            }
            
            .tabs {
                display: flex;
                background: #2d3748;
                border-radius: 6px 6px 0 0;
                overflow: hidden;
            }
            
            .tab {
                padding: 1rem;
                flex: 1;
                text-align: center;
                cursor: pointer;
                transition: background 0.3s;
            }
            
            .tab.active {
                background: var(--accent);
                font-weight: bold;
            }
            
            .tab-content {
                display: none;
                background: #2d3748;
                padding: 1rem;
                border-radius: 0 0 6px 6px;
            }
            
            .tab-content.active {
                display: block;
            }
            
            @media (max-width: 768px) {
                .dashboard {
                    grid-template-columns: 1fr;
                }
                
                .controls {
                    flex-direction: column;
                }
                
                .stats-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">🐺 WolfPack Analyzer</div>
            <div class="subtitle">Professional Network Security Analysis Tool</div>
        </div>
        
        <div class="container">
            <!-- Dashboard de Estatísticas -->
            <div class="dashboard">
                <div class="card">
                    <h3>📊 Status do Sistema</h3>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number stat-total" id="totalPackets">0</div>
                            <div>Total Packets</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number stat-tcp" id="tcpPackets">0</div>
                            <div>TCP</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number stat-udp" id="udpPackets">0</div>
                            <div>UDP</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number stat-bandwidth" id="bandwidth">0</div>
                            <div>MB</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number stat-pps" id="pps">0</div>
                            <div>PPS</div>
                        </div>
                    </div>
                    <div id="statusIndicator" class="alert-box">
                        <strong>Status:</strong> <span id="statusText">Parado</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>📈 Tráfego em Tempo Real</h3>
                    <div class="chart-container">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🚨 Alertas de Segurança</h3>
                    <div class="security-alerts" id="securityAlerts">
                        <!-- Alertas serão inseridos aqui -->
                    </div>
                </div>
            </div>
            
            <!-- Controles Principais -->
            <div class="card">
                <h3>🎮 Controles de Captura</h3>
                <div class="controls">
                    <select id="interfaceSelect" class="btn btn-secondary">
                        <option value="any">🌐 Qualquer Interface</option>
                    </select>
                    <button class="btn btn-primary" onclick="startCapture()">▶️ Iniciar Captura</button>
                    <button class="btn btn-danger" onclick="stopCapture()">⏹️ Parar Captura</button>
                    <button class="btn btn-secondary" onclick="clearPackets()">🗑️ Limpar</button>
                </div>
            </div>
            
            <!-- Abas Principais -->
            <div class="tab-container">
                <div class="tabs">
                    <div class="tab active" onclick="switchTab('packets')">📦 Pacotes</div>
                    <div class="tab" onclick="switchTab('scanner')">🔍 Scanner</div>
                    <div class="tab" onclick="switchTab('tools')">🛠️ Ferramentas</div>
                    <div class="tab" onclick="switchTab('security')">🛡️ Segurança</div>
                </div>
                
                <!-- Aba de Pacotes -->
                <div id="packets" class="tab-content active">
                    <div class="card">
                        <h3>📋 Pacotes Capturados (Últimos 100)</h3>
                        <div style="max-height: 400px; overflow-y: auto;">
                            <table class="packet-table">
                                <thead>
                                    <tr>
                                        <th>Hora</th>
                                        <th>Origem</th>
                                        <th>Destino</th>
                                        <th>Protocolo</th>
                                        <th>Tamanho</th>
                                        <th>Risco</th>
                                        <th>Info</th>
                                    </tr>
                                </thead>
                                <tbody id="packetTableBody">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Aba do Scanner -->
                <div id="scanner" class="tab-content">
                    <div class="card">
                        <h3>🎯 Scanner de Portas Avançado</h3>
                        <div class="controls">
                            <input type="text" id="scanTarget" placeholder="🎯 IP ou Hostname (ex: 192.168.1.1)" 
                                   class="btn btn-secondary">
                            <input type="text" id="portRange" placeholder="🔢 Portas (ex: 1-1000,80,443)" 
                                   value="1-1000" class="btn btn-secondary">
                            <button class="btn btn-success" onclick="startPortScan()">🚀 Iniciar Scan</button>
                            <button class="btn btn-primary" onclick="quickScan()">⚡ Scan Rápido</button>
                        </div>
                        
                        <div class="terminal" id="scanResult">
                            👆 Configure o alvo e as portas para iniciar o scan
                        </div>
                        
                        <div id="scanResults" style="margin-top: 1rem;">
                            <!-- Resultados do scan serão inseridos aqui -->
                        </div>
                    </div>
                </div>
                
                <!-- Aba de Ferramentas -->
                <div id="tools" class="tab-content">
                    <div class="card">
                        <h3>🔧 Ferramentas de Rede</h3>
                        <div class="controls">
                            <input type="text" id="toolTarget" placeholder="🌐 IP ou Hostname" 
                                   class="btn btn-secondary" style="flex: 2;">
                            <button class="btn btn-secondary" onclick="pingTest()">📡 Ping</button>
                            <button class="btn btn-secondary" onclick="dnsLookup()">🔍 DNS</button>
                            <button class="btn btn-secondary" onclick="traceroute()">🛣️ Traceroute</button>
                            <button class="btn btn-secondary" onclick="whoisLookup()">👤 WHOIS</button>
                        </div>
                        <div class="terminal" id="toolResult">
                            Selecione uma ferramenta para começar
                        </div>
                    </div>
                </div>
                
                <!-- Aba de Segurança -->
                <div id="security" class="tab-content">
                    <div class="card">
                        <h3>📚 Catálogo de Portas e Riscos</h3>
                        <div style="max-height: 400px; overflow-y: auto;">
                            <table class="packet-table">
                                <thead>
                                    <tr>
                                        <th>Porta</th>
                                        <th>Serviço</th>
                                        <th>Risco</th>
                                        <th>Descrição</th>
                                    </tr>
                                </thead>
                                <tbody id="portCatalog">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let updateInterval;
            let trafficChart;
            let currentPorts = "1-1000";
            
            // Gráfico de tráfego
            function initCharts() {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Pacotes/s',
                            data: [],
                            borderColor: '#e53e3e',
                            backgroundColor: 'rgba(229, 62, 62, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255,255,255,0.1)'
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                }
                            }
                        }
                    }
                });
            }
            
            // Alternar abas
            function switchTab(tabName) {
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                
                event.target.classList.add('active');
                document.getElementById(tabName).classList.add('active');
            }
            
            // Carregar interfaces
            function loadInterfaces() {
                fetch('/get_interfaces')
                    .then(r => r.json())
                    .then(interfaces => {
                        const select = document.getElementById('interfaceSelect');
                        select.innerHTML = '<option value="any">🌐 Qualquer Interface</option>';
                        
                        interfaces.forEach(iface => {
                            const option = document.createElement('option');
                            option.value = iface.name;
                            option.textContent = `📡 ${iface.name} (${iface.ip}) - ${iface.status}`;
                            select.appendChild(option);
                        });
                    });
            }
            
            // Atualizar dados
            function updateData() {
                fetch('/get_packets')
                    .then(r => r.json())
                    .then(data => {
                        // Status
                        const statusBox = document.getElementById('statusIndicator');
                        const statusText = document.getElementById('statusText');
                        
                        if (data.is_running) {
                            statusBox.style.background = 'rgba(56, 161, 105, 0.1)';
                            statusBox.style.borderColor = '#38a169';
                            statusText.textContent = '🟢 Capturando...';
                        } else {
                            statusBox.style.background = 'rgba(229, 62, 62, 0.1)';
                            statusBox.style.borderColor = '#e53e3e';
                            statusText.textContent = '🔴 Parado';
                        }
                        
                        // Estatísticas
                        document.getElementById('totalPackets').textContent = data.stats.total_packets;
                        document.getElementById('tcpPackets').textContent = data.stats.tcp_packets;
                        document.getElementById('udpPackets').textContent = data.stats.udp_packets;
                        document.getElementById('pps').textContent = data.stats.packets_per_second;
                        
                        // Tabela de pacotes
                        const tbody = document.getElementById('packetTableBody');
                        tbody.innerHTML = '';
                        
                        data.packets.forEach(packet => {
                            const row = document.createElement('tr');
                            row.className = `packet-row risk-${packet.risk.toLowerCase()}`;
                            row.innerHTML = `
                                <td>${packet.timestamp}</td>
                                <td>${packet.src_ip}${packet.src_port ? ':' + packet.src_port : ''}</td>
                                <td>${packet.dst_ip}${packet.dst_port ? ':' + packet.dst_port : ''}</td>
                                <td>${packet.protocol}</td>
                                <td>${packet.length}</td>
                                <td><span class="risk-${packet.risk.toLowerCase()}">${packet.risk}</span></td>
                                <td>${packet.info}</td>
                            `;
                            tbody.appendChild(row);
                        });
                    })
                    .catch(err => {
                        console.error('Erro ao atualizar pacotes:', err);
                    });
                
                fetch('/get_network_stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('bandwidth').textContent = data.bandwidth_mb;
                    })
                    .catch(err => {
                        console.error('Erro ao atualizar stats:', err);
                    });
                
                fetch('/get_security_alerts')
                    .then(r => r.json())
                    .then(alerts => {
                        updateSecurityAlerts(alerts);
                    })
                    .catch(err => {
                        console.error('Erro ao atualizar alertas:', err);
                    });
                
                // Atualizar gráficos
                updateCharts();
            }
            
            // Atualizar gráficos
            function updateCharts() {
                fetch('/get_chart_data')
                    .then(r => r.json())
                    .then(chartData => {
                        if (trafficChart && chartData.packet_times.length > 0) {
                            const labels = chartData.packet_times.map(t => {
                                const date = new Date(t * 1000);
                                return date.getMinutes() + ':' + date.getSeconds();
                            });
                            
                            trafficChart.data.labels = labels;
                            trafficChart.data.datasets[0].data = chartData.packet_counts;
                            trafficChart.update('none');
                        }
                    })
                    .catch(err => {
                        console.error('Erro ao atualizar gráficos:', err);
                    });
            }
            
            // Alertas de segurança
            function updateSecurityAlerts(alerts) {
                const container = document.getElementById('securityAlerts');
                if (!alerts || alerts.length === 0) {
                    container.innerHTML = '<div style="text-align: center; padding: 2rem; color: #68d391;">✅ Nenhum alerta de segurança detectado</div>';
                    return;
                }
                
                container.innerHTML = alerts.slice(0, 5).map(alert => `
                    <div class="alert-item">
                        <strong>🚨 ${alert.type} (${alert.risk})</strong><br>
                        ${alert.message}<br>
                        <small>⏰ ${alert.timestamp} | 📡 ${alert.src_ip} → ${alert.dst_ip}</small>
                    </div>
                `).join('');
            }
            
            // Controles de captura
            function startCapture() {
                const interface = document.getElementById('interfaceSelect').value;
                fetch('/start_capture', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({interface: interface})
                }).then(r => r.json()).then(data => {
                    alert(data.message);
                    if(data.status === 'success') {
                        if (updateInterval) {
                            clearInterval(updateInterval);
                        }
                        updateInterval = setInterval(updateData, 1000);
                    }
                }).catch(err => {
                    alert('Erro: ' + err);
                });
            }
            
            function stopCapture() {
                fetch('/stop_capture', {method: 'POST'})
                    .then(r => r.json())
                    .then(data => {
                        alert(data.message);
                        if (updateInterval) {
                            clearInterval(updateInterval);
                        }
                        updateData();
                    })
                    .catch(err => {
                        alert('Erro: ' + err);
                    });
            }
            
            function clearPackets() {
                if (confirm('Tem certeza que deseja limpar todos os pacotes?')) {
                    fetch('/clear_packets', {method: 'POST'})
                        .then(r => r.json())
                        .then(data => {
                            alert(data.message);
                            updateData();
                        })
                        .catch(err => {
                            alert('Erro: ' + err);
                        });
                }
            }
            
            // Scanner de portas
            function startPortScan() {
                const target = document.getElementById('scanTarget').value;
                const ports = document.getElementById('portRange').value;
                const result = document.getElementById('scanResult');
                
                if (!target) {
                    alert('Por favor, informe o alvo!');
                    return;
                }
                
                result.innerHTML = '🚀 Iniciando scan...\\n';
                
                fetch('/port_scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, ports: ports})
                }).then(r => r.json()).then(data => {
                    if (data.status === 'success') {
                        displayScanResults(data);
                    } else {
                        result.innerHTML = '❌ Erro: ' + data.message;
                    }
                }).catch(err => {
                    result.innerHTML = '❌ Erro: ' + err;
                });
            }
            
            function quickScan() {
                document.getElementById('portRange').value = '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080';
                startPortScan();
            }
            
            function displayScanResults(data) {
                const resultsDiv = document.getElementById('scanResults');
                const resultTerminal = document.getElementById('scanResult');
                
                resultTerminal.innerHTML = `Scan concluído! ${data.open_count} portas abertas de ${data.total_scanned} verificadas.`;
                
                resultsDiv.innerHTML = `
                    <h4>📊 Resultados do Scan</h4>
                    <p>🎯 Alvo: ${data.target} | 🔢 Portas: ${data.ports}</p>
                    <p>✅ Portas abertas: ${data.open_count}/${data.total_scanned}</p>
                    <div style="max-height: 300px; overflow-y: auto;">
                        <table class="packet-table">
                            <thead>
                                <tr>
                                    <th>Porta</th>
                                    <th>Status</th>
                                    <th>Risco</th>
                                    <th>Serviço</th>
                                    <th>Descrição</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.results.map(result => `
                                    <tr class="risk-${result.risk.toLowerCase()}">
                                        <td>${result.port}</td>
                                        <td>${result.status}</td>
                                        <td>${result.risk}</td>
                                        <td>${result.service}</td>
                                        <td>${result.description}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            // Ferramentas
            function pingTest() {
                const target = document.getElementById('toolTarget').value;
                const result = document.getElementById('toolResult');
                
                if (!target) {
                    alert('Por favor, informe o alvo!');
                    return;
                }
                
                result.innerHTML = '📡 Testando ping...\\n';
                
                fetch('/ping_test', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                }).then(r => r.json()).then(data => {
                    result.innerHTML = data.status === 'success' ? data.result : 'Erro: ' + data.message;
                }).catch(err => {
                    result.innerHTML = 'Erro: ' + err;
                });
            }
            
            function dnsLookup() {
                const target = document.getElementById('toolTarget').value;
                const result = document.getElementById('toolResult');
                
                if (!target) {
                    alert('Por favor, informe o alvo!');
                    return;
                }
                
                result.innerHTML = '🔍 Consultando DNS...\\n';
                
                fetch('/dns_lookup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                }).then(r => r.json()).then(data => {
                    result.innerHTML = data.status === 'success' ? data.result : 'Erro: ' + data.message;
                }).catch(err => {
                    result.innerHTML = 'Erro: ' + err;
                });
            }
            
            function traceroute() {
                const target = document.getElementById('toolTarget').value;
                const result = document.getElementById('toolResult');
                
                if (!target) {
                    alert('Por favor, informe o alvo!');
                    return;
                }
                
                result.innerHTML = '🛣️ Executando traceroute...\\n';
                
                fetch('/traceroute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                }).then(r => r.json()).then(data => {
                    result.innerHTML = data.status === 'success' ? data.result : 'Erro: ' + data.message;
                }).catch(err => {
                    result.innerHTML = 'Erro: ' + err;
                });
            }
            
            function whoisLookup() {
                const target = document.getElementById('toolTarget').value;
                const result = document.getElementById('toolResult');
                
                if (!target) {
                    alert('Por favor, informe o alvo!');
                    return;
                }
                
                result.innerHTML = '👤 Consultando WHOIS...\\n';
                
                fetch('/whois_lookup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                }).then(r => r.json()).then(data => {
                    result.innerHTML = data.status === 'success' ? data.result : 'Erro: ' + data.message;
                }).catch(err => {
                    result.innerHTML = 'Erro: ' + err;
                });
            }
            
            // Inicialização
            document.addEventListener('DOMContentLoaded', function() {
                initCharts();
                loadInterfaces();
                updateData();
                setInterval(updateData, 2000);
                loadPortCatalog();
            });
            
            function loadPortCatalog() {
                const tbody = document.getElementById('portCatalog');
                const ports = [
                    [21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'], [53, 'DNS'], 
                    [80, 'HTTP'], [110, 'POP3'], [135, 'RPC'], [139, 'NetBIOS'], [143, 'IMAP'],
                    [443, 'HTTPS'], [445, 'SMB'], [993, 'IMAPS'], [995, 'POP3S'], [1433, 'MSSQL'],
                    [3306, 'MySQL'], [3389, 'RDP'], [5432, 'PostgreSQL'], [5900, 'VNC'], [8080, 'HTTP-Alt']
                ];
                
                tbody.innerHTML = ports.map(([port, service]) => {
                    const riskInfo = PORT_SECURITY[port] || {'risk': 'Desconhecido', 'description': 'N/A'};
                    return `
                        <tr class="risk-${riskInfo.risk.toLowerCase()}">
                            <td>${port}</td>
                            <td>${service}</td>
                            <td>${riskInfo.risk}</td>
                            <td>${riskInfo.description}</td>
                        </tr>
                    `;
                }).join('');
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_template)

@app.route('/get_interfaces')
def get_interfaces_route():
    """Retorna interfaces disponíveis"""
    return jsonify(get_interfaces())

@app.route('/start_capture', methods=['POST'])
def start_capture_route():
    """Inicia captura"""
    global capture_thread, capture_running
    
    if capture_running:
        return jsonify({'status': 'error', 'message': 'Captura já está rodando'})
    
    interface = request.json.get('interface', 'any')
    
    capture_thread = threading.Thread(target=start_capture, args=(interface,))
    capture_thread.daemon = True
    capture_thread.start()
    
    time.sleep(1)
    
    if capture_running:
        return jsonify({'status': 'success', 'message': f'Captura iniciada na interface {interface}'})
    else:
        return jsonify({'status': 'error', 'message': 'Falha ao iniciar captura'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture_route():
    """Para captura"""
    global capture_running
    
    capture_running = False
    time.sleep(1)
    
    return jsonify({'status': 'success', 'message': 'Captura parada'})

@app.route('/get_packets')
def get_packets():
    """Retorna pacotes capturados"""
    return jsonify({
        'packets': captured_packets[-100:],
        'stats': capture_stats,
        'is_running': capture_running,
        'security_alerts': security_alerts[-10:]
    })

@app.route('/get_network_stats')
def get_network_stats():
    """Retorna estatísticas de rede"""
    network_info = get_network_info()
    network_info['is_running'] = capture_running
    return jsonify(network_info)

@app.route('/get_security_alerts')
def get_security_alerts_route():
    """Retorna alertas de segurança"""
    return jsonify(security_alerts[-10:])

@app.route('/get_chart_data')
def get_chart_data_route():
    """Retorna dados para gráficos - CORRIGIDO"""
    return jsonify(prepare_chart_data())

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    """Limpa pacotes capturados"""
    global captured_packets, capture_stats, security_alerts
    captured_packets = []
    security_alerts = []
    capture_stats = {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'start_time': None,
        'bandwidth_usage': 0,
        'packets_per_second': 0,
        'suspicious_activity': 0
    }
    return jsonify({'status': 'success', 'message': 'Pacotes limpos'})

@app.route('/update_ports', methods=['POST'])
def update_ports():
    """Atualiza as portas para scan"""
    try:
        ports = request.json.get('ports', '')
        CONFIG['target_ports'] = validate_ports(ports)
        return jsonify({'status': 'success', 'message': f'Portas atualizadas: {CONFIG["target_ports"]}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/port_scan', methods=['POST'])
def port_scan():
    """Realiza scan de portas"""
    try:
        target = request.json.get('target', '127.0.0.1')
        ports = request.json.get('ports', CONFIG['target_ports'])
        
        # Valida as portas
        ports = validate_ports(ports)
        
        # Usa scanner integrado
        scan_result = simple_port_scan(target, ports)
        
        if 'error' in scan_result:
            return jsonify({'status': 'error', 'message': scan_result['error']})
        
        return jsonify({
            'status': 'success',
            'result': f"Scan concluído: {scan_result['open_count']} portas abertas",
            'target': target,
            'ports': ports,
            'open_count': scan_result['open_count'],
            'total_scanned': scan_result['total_scanned'],
            'results': scan_result['results']
        })
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/ping_test', methods=['POST'])
def ping_test():
    """Testa conectividade com ping"""
    try:
        target = request.json.get('target', '127.0.0.1')
        
        # Executa ping
        result = subprocess.run(['ping', '-c', '4', target], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'result': result.stdout
            })
        else:
            return jsonify({'status': 'error', 'message': result.stderr})
            
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Ping expirado (timeout)'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    """Faz lookup DNS"""
    try:
        target = request.json.get('target', '')
        result = subprocess.run(['nslookup', target], 
                              capture_output=True, text=True, timeout=10)
        return jsonify({'status': 'success', 'result': result.stdout})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/traceroute', methods=['POST'])
def traceroute_route():
    """Executa traceroute"""
    try:
        target = request.json.get('target', '')
        result = subprocess.run(['traceroute', target], 
                              capture_output=True, text=True, timeout=30)
        return jsonify({'status': 'success', 'result': result.stdout})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/whois_lookup', methods=['POST'])
def whois_lookup():
    """Faz consulta WHOIS"""
    try:
        target = request.json.get('target', '')
        result = subprocess.run(['whois', target], 
                              capture_output=True, text=True, timeout=10)
        return jsonify({'status': 'success', 'result': result.stdout})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def signal_handler(sig, frame):
    """Manipula sinal de interrupção"""
    global capture_running
    print("\nParando captura...")
    capture_running = False
    sys.exit(0)

def main():
    """Função principal"""
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🐺 PolyTools WolfPack Network Analyzer PRO")
    print("==========================================")
    print("Symbol: Lone Wolf")
    print("")
    print("🚀 Recursos Avançados:")
    print("📊 Gráficos em tempo real")
    print("🛡️ Análise de segurança automatizada")
    print("🔍 Scanner de portas integrado")
    print("📈 Monitoramento de desempenho")
    print("🚨 Sistema de alertas")
    print("")
    print("🌐 Interface Web: http://localhost:5000")
    print("⏹️  Pressione Ctrl+C para parar")
    print("")
    
    # Verificar dependências
    try:
        import scapy
        import flask
        import netifaces
        import psutil
    except ImportError as e:
        print(f"❌ Erro: Dependência não encontrada: {e}")
        print("Instale as dependências com:")
        print("pip install scapy flask netifaces psutil")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("⚠️  Aviso: Execute como root para melhor funcionalidade")
        print("Use: sudo python3 wolfpack_pro.py")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"❌ Erro ao iniciar servidor: {e}")

if __name__ == '__main__':
    main()
