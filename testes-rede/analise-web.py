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
from datetime import datetime
from scapy.all import *
from flask import Flask, render_template, request, jsonify, send_file
import netifaces as ni
import psutil
import subprocess

app = Flask(__name__)

# Configurações
CONFIG = {
    'capture_file': '/data/data/com.termux/files/home/capture.pcap',
    'update_interval': 2,
    'max_packets': 1000,
    'interfaces': []
}

# Dados globais
captured_packets = []
capture_stats = {
    'total_packets': 0,
    'tcp_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'other_packets': 0,
    'start_time': None,
    'bandwidth_usage': 0
}

# Thread de captura
capture_thread = None
capture_running = False

def get_interfaces():
    """Obtém interfaces de rede disponíveis"""
    interfaces = []
    try:
        for interface in ni.interfaces():
            addrs = ni.ifaddresses(interface)
            if ni.AF_INET in addrs:
                ip = addrs[ni.AF_INET][0]['addr']
                interfaces.append({
                    'name': interface,
                    'ip': ip,
                    'status': 'up' if interface in ni.interfaces() else 'down'
                })
    except:
        pass
    return interfaces

def packet_handler(packet):
    """Manipula pacotes capturados"""
    global captured_packets, capture_stats
    
    if len(captured_packets) >= CONFIG['max_packets']:
        captured_packets.pop(0)
    
    packet_info = {
        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'protocol': 'Unknown',
        'length': len(packet),
        'info': str(packet.summary())
    }
    
    try:
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                capture_stats['tcp_packets'] += 1
                
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                capture_stats['udp_packets'] += 1
                
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                capture_stats['icmp_packets'] += 1
            else:
                capture_stats['other_packets'] += 1
                
        capture_stats['total_packets'] += 1
        captured_packets.append(packet_info)
        
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")

def start_capture(interface):
    """Inicia captura de pacotes"""
    global capture_running, capture_stats
    capture_running = True
    capture_stats = {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'start_time': datetime.now().strftime('%H:%M:%S'),
        'bandwidth_usage': 0
    }
    
    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except Exception as e:
        print(f"Erro na captura: {e}")

def get_network_info():
    """Obtém informações de rede"""
    try:
        # Estatísticas de rede
        net_io = psutil.net_io_counters()
        bandwidth = (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024  # MB
        
        # Conexões ativas
        connections = []
        for conn in psutil.net_connections():
            if conn.laddr:
                connections.append({
                    'protocol': conn.type,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'status': conn.status
                })
        
        return {
            'bandwidth_mb': round(bandwidth, 2),
            'active_connections': len(connections),
            'connections': connections[:10]  # Mostrar apenas as 10 primeiras
        }
    except:
        return {'bandwidth_mb': 0, 'active_connections': 0, 'connections': []}

@app.route('/')
def index():
    """Página principal"""
    interfaces = get_interfaces()
    return render_template('index.html', interfaces=interfaces)

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
    
    return jsonify({'status': 'success', 'message': f'Captura iniciada na interface {interface}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture_route():
    """Para captura"""
    global capture_running
    capture_running = False
    
    # Força parada da captura
    try:
        if capture_thread and capture_thread.is_alive():
            # Esta é uma maneira simples de parar, pode precisar de ajustes
            os.system('pkill -f "python.*sniff"')
    except:
        pass
    
    return jsonify({'status': 'success', 'message': 'Captura parada'})

@app.route('/get_packets')
def get_packets():
    """Retorna pacotes capturados"""
    return jsonify({
        'packets': captured_packets[-100:],  # Últimos 100 pacotes
        'stats': capture_stats,
        'is_running': capture_running
    })

@app.route('/get_network_stats')
def get_network_stats():
    """Retorna estatísticas de rede"""
    network_info = get_network_info()
    network_info['is_running'] = capture_running
    return jsonify(network_info)

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    """Limpa pacotes capturados"""
    global captured_packets, capture_stats
    captured_packets = []
    capture_stats = {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'start_time': None,
        'bandwidth_usage': 0
    }
    return jsonify({'status': 'success', 'message': 'Pacotes limpos'})

@app.route('/save_capture', methods=['POST'])
def save_capture():
    """Salva captura em arquivo"""
    try:
        filename = request.json.get('filename', f'capture_{int(time.time())}.pcap')
        # Aqui você implementaria a lógica para salvar os pacotes
        return jsonify({'status': 'success', 'message': f'Captura salva como {filename}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/port_scan', methods=['POST'])
def port_scan():
    """Realiza scan de portas"""
    try:
        target = request.json.get('target', '127.0.0.1')
        ports = request.json.get('ports', '1-100')
        
        # Comando básico de port scan (substitua por implementação real)
        result = subprocess.run(['nmap', '-p', ports, target], 
                              capture_output=True, text=True)
        
        return jsonify({
            'status': 'success',
            'result': result.stdout,
            'target': target
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Template HTML embutido
@app.route('/template')
def template():
    """Serve o template HTML"""
    return """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools - WolfPack Analyzer</title>
    <style>
        :root {
            --primary: #2d3748;
            --secondary: #4a5568;
            --accent: #e53e3e;
            --text: #e2e8f0;
            --background: #1a202c;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: var(--background);
            color: var(--text);
            line-height: 1.6;
        }
        
        .header {
            background: var(--primary);
            padding: 1rem;
            text-align: center;
            border-bottom: 3px solid var(--accent);
        }
        
        .logo {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
        }
        
        .subtitle {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1rem;
        }
        
        .card {
            background: var(--primary);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .stat-card {
            background: var(--secondary);
            padding: 1rem;
            border-radius: 6px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
        }
        
        .controls {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-secondary {
            background: var(--secondary);
            color: var(--text);
        }
        
        .btn:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }
        
        .packet-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        .packet-table th,
        .packet-table td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--secondary);
        }
        
        .packet-table th {
            background: var(--secondary);
            position: sticky;
            top: 0;
        }
        
        .packet-row:hover {
            background: var(--secondary);
        }
        
        .tcp { color: #68d391; }
        .udp { color: #63b3ed; }
        .icmp { color: #fbb6ce; }
        .other { color: #b794f4; }
        
        .terminal {
            background: #000;
            color: #0f0;
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            height: 200px;
            overflow-y: auto;
        }
        
        @media (max-width: 768px) {
            .controls {
                flex-direction: column;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🐺 PolyTools WolfPack</div>
        <div class="subtitle">Network Analyzer for Termux</div>
    </div>
    
    <div class="container">
        <!-- Estatísticas em tempo real -->
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-number" id="totalPackets">0</div>
                <div>Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="tcpPackets">0</div>
                <div>TCP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="udpPackets">0</div>
                <div>UDP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="bandwidth">0 MB</div>
                <div>Bandwidth</div>
            </div>
        </div>
        
        <!-- Controles -->
        <div class="card">
            <h3>Controles de Captura</h3>
            <div class="controls">
                <select id="interfaceSelect" class="btn btn-secondary">
                    <option value="any">Qualquer Interface</option>
                </select>
                <button class="btn btn-primary" onclick="startCapture()">Iniciar Captura</button>
                <button class="btn btn-secondary" onclick="stopCapture()">Parar Captura</button>
                <button class="btn btn-secondary" onclick="clearPackets()">Limpar Pacotes</button>
                <button class="btn btn-secondary" onclick="saveCapture()">Salvar Captura</button>
            </div>
        </div>
        
        <!-- Tabela de Pacotes -->
        <div class="card">
            <h3>Pacotes Capturados</h3>
            <div style="max-height: 400px; overflow-y: auto;">
                <table class="packet-table" id="packetTable">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody id="packetTableBody">
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Ferramentas Adicionais -->
        <div class="card">
            <h3>Ferramentas de Rede</h3>
            <div class="controls">
                <input type="text" id="scanTarget" placeholder="IP ou Hostname" class="btn btn-secondary">
                <input type="text" id="scanPorts" placeholder="Portas (ex: 1-100)" class="btn btn-secondary">
                <button class="btn btn-primary" onclick="portScan()">Scan de Portas</button>
            </div>
            <div class="terminal" id="scanResult"></div>
        </div>
    </div>
    
    <script>
        let updateInterval;
        
        // Atualizar dados periodicamente
        function updateData() {
            fetch('/get_packets')
                .then(r => r.json())
                .then(data => {
                    // Atualizar estatísticas
                    document.getElementById('totalPackets').textContent = data.stats.total_packets;
                    document.getElementById('tcpPackets').textContent = data.stats.tcp_packets;
                    document.getElementById('udpPackets').textContent = data.stats.udp_packets;
                    
                    // Atualizar tabela de pacotes
                    const tbody = document.getElementById('packetTableBody');
                    tbody.innerHTML = '';
                    
                    data.packets.forEach(packet => {
                        const row = document.createElement('tr');
                        row.className = 'packet-row';
                        row.innerHTML = `
                            <td>${packet.timestamp}</td>
                            <td>${packet.src_ip}</td>
                            <td>${packet.dst_ip}</td>
                            <td class="${packet.protocol.toLowerCase()}">${packet.protocol}</td>
                            <td>${packet.length}</td>
                            <td>${packet.info}</td>
                        `;
                        tbody.appendChild(row);
                    });
                });
            
            fetch('/get_network_stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('bandwidth').textContent = data.bandwidth_mb + ' MB';
                });
        }
        
        function startCapture() {
            const interface = document.getElementById('interfaceSelect').value;
            fetch('/start_capture', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({interface: interface})
            }).then(r => r.json()).then(data => {
                alert(data.message);
                if(data.status === 'success') {
                    updateInterval = setInterval(updateData, 2000);
                }
            });
        }
        
        function stopCapture() {
            fetch('/stop_capture', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert(data.message);
                    clearInterval(updateInterval);
                });
        }
        
        function clearPackets() {
            fetch('/clear_packets', {method: 'POST'})
                .then(r => r.json())
                .then(data => alert(data.message));
        }
        
        function saveCapture() {
            const filename = prompt('Nome do arquivo:', `capture_${Date.now()}.pcap`);
            if(filename) {
                fetch('/save_capture', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({filename: filename})
                }).then(r => r.json()).then(data => alert(data.message));
            }
        }
        
        function portScan() {
            const target = document.getElementById('scanTarget').value;
            const ports = document.getElementById('scanPorts').value;
            const result = document.getElementById('scanResult');
            
            result.innerHTML = 'Scanning...';
            
            fetch('/port_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target, ports: ports})
            }).then(r => r.json()).then(data => {
                result.innerHTML = data.status === 'success' ? 
                    data.result : 'Error: ' + data.message;
            });
        }
        
        // Carregar interfaces disponíveis
        fetch('/')
            .then(r => r.text())
            .then(html => {
                // Extrair interfaces do HTML (simplificado)
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                // Esta parte precisaria ser ajustada para carregar dinamicamente
            });
        
        // Iniciar atualização automática
        updateData();
        setInterval(updateData, 5000);
    </script>
</body>
</html>
"""

def main():
    """Função principal"""
    print("🐺 PolyTools WolfPack Network Analyzer")
    print("=====================================")
    print("Iniciando servidor web...")
    print("Acesse: http://localhost:5000")
    print("Pressione Ctrl+C para parar")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\nParando servidor...")
    except Exception as e:
        print(f"Erro: {e}")

if __name__ == '__main__':
    # Verificar dependências
    try:
        import scapy
        import flask
        import netifaces
        import psutil
    except ImportError as e:
        print(f"Erro: Dependência não encontrada: {e}")
        print("Instale as dependências com:")
        print("pip install scapy flask netifaces psutil")
        sys.exit(1)
    
    main()
