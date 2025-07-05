#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
import argparse
import socket
import json
import os

class VulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
        })
        self.vulnerabilities = []

    def check_sql_injection(self):
        test_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            '" OR "1"="1',
            '1 AND 1=1',
            '1 AND 1=2'
        ]
        
        forms = self._get_forms()
        for form in forms:
            for payload in test_payloads:
                data = {}
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    input_value = input_tag.get('value', '')
                    if input_type == 'text' or input_type == 'password':
                        data[input_name] = payload
                    else:
                        data[input_name] = input_value
                
                form_action = form.get('action')
                form_method = form.get('method', 'get').lower()
                target_url = urljoin(self.target_url, form_action)
                
                try:
                    if form_method == 'post':
                        response = self.session.post(target_url, data=data)
                    else:
                        response = self.session.get(target_url, params=data)
                    
                    errors = [
                        'SQL syntax',
                        'MySQL server',
                        'ORA-',
                        'syntax error',
                        'unclosed quotation mark',
                        'PostgreSQL',
                        'Microsoft Access',
                        'ODBC'
                    ]
                    
                    for error in errors:
                        if error in response.text:
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': target_url,
                                'payload': payload,
                                'form': str(form)
                            })
                            return True
                except Exception as e:
                    continue
        return False

    def check_xss(self):
        test_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '" onfocus=alert(1) autofocus="',
            "'><script>alert(1)</script>"
        ]
        
        forms = self._get_forms()
        for form in forms:
            for payload in test_payloads:
                data = {}
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    input_value = input_tag.get('value', '')
                    if input_type == 'text' or input_type == 'search' or input_type == 'password':
                        data[input_name] = payload
                    else:
                        data[input_name] = input_value
                
                form_action = form.get('action')
                form_method = form.get('method', 'get').lower()
                target_url = urljoin(self.target_url, form_action)
                
                try:
                    if form_method == 'post':
                        response = self.session.post(target_url, data=data)
                    else:
                        response = self.session.get(target_url, params=data)
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'url': target_url,
                            'payload': payload,
                            'form': str(form)
                        })
                        return True
                except Exception as e:
                    continue
        return False

    def check_exposed_git(self):
        git_urls = [
            '/.git/HEAD',
            '/.git/config',
            '/.git/index',
            '/.git/logs/HEAD'
        ]
        
        for git_url in git_urls:
            target_url = urljoin(self.target_url, git_url)
            try:
                response = self.session.get(target_url, timeout=5)
                if response.status_code == 200:
                    if 'ref:' in response.text or '[core]' in response.text:
                        self.vulnerabilities.append({
                            'type': 'Exposed Git Repository',
                            'url': target_url,
                            'details': 'Git repository is accessible publicly'
                        })
                        return True
            except Exception as e:
                continue
        return False

    def check_directory_listing(self):
        test_dirs = [
            '/images/',
            '/assets/',
            '/files/',
            '/uploads/',
            '/backup/'
        ]
        
        for test_dir in test_dirs:
            target_url = urljoin(self.target_url, test_dir)
            try:
                response = self.session.get(target_url, timeout=5)
                if response.status_code == 200:
                    if '<title>Index of' in response.text or '<a href="..">..</a>' in response.text:
                        self.vulnerabilities.append({
                            'type': 'Directory Listing',
                            'url': target_url,
                            'details': 'Directory listing is enabled'
                        })
                        return True
            except Exception as e:
                continue
        return False

    def check_sensitive_files(self):
        common_files = [
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/phpinfo.php',
            '/.htaccess',
            '/robots.txt',
            '/backup.zip',
            '/database.sql'
        ]
        
        for file_path in common_files:
            target_url = urljoin(self.target_url, file_path)
            try:
                response = self.session.get(target_url, timeout=5)
                if response.status_code == 200:
                    sensitive_keywords = ['password', 'secret', 'database', 'API_KEY']
                    for keyword in sensitive_keywords:
                        if keyword in response.text:
                            self.vulnerabilities.append({
                                'type': 'Sensitive File Exposure',
                                'url': target_url,
                                'details': f'Sensitive file exposed containing "{keyword}"'
                            })
                            return True
            except Exception as e:
                continue
        return False

    def check_cors_misconfig(self):
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET'
        }
        
        try:
            response = self.session.get(self.target_url, headers=headers)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' or (acao == 'https://evil.com' and acac.lower() == 'true'):
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'url': self.target_url,
                    'details': f'CORS misconfiguration - ACAO: {acao}, ACAC: {acac}'
                })
                return True
        except Exception as e:
            pass
        return False

    def check_clickjacking(self):
        try:
            response = self.session.get(self.target_url)
            xfo = response.headers.get('X-Frame-Options', '').lower()
            csp = response.headers.get('Content-Security-Policy', '').lower()
            
            if not xfo and 'frame-ancestors' not in csp:
                self.vulnerabilities.append({
                    'type': 'Clickjacking',
                    'url': self.target_url,
                    'details': 'Missing X-Frame-Options or CSP frame-ancestors'
                })
                return True
        except Exception as e:
            pass
        return False

    def check_http_methods(self):
        try:
            response = self.session.request('OPTIONS', self.target_url)
            allowed_methods = response.headers.get('Allow', '')
            if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                self.vulnerabilities.append({
                    'type': 'Dangerous HTTP Methods',
                    'url': self.target_url,
                    'details': f'Dangerous methods allowed: {allowed_methods}'
                })
                return True
        except Exception as e:
            pass
        return False

    def check_server_info(self):
        try:
            response = self.session.get(self.target_url)
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            if server or powered_by:
                self.vulnerabilities.append({
                    'type': 'Server Information Disclosure',
                    'url': self.target_url,
                    'details': f'Server: {server}, X-Powered-By: {powered_by}'
                })
                return True
        except Exception as e:
            pass
        return False

    def _get_forms(self):
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            return []

    def scan_all(self):
        checks = [
            ('SQL Injection', self.check_sql_injection),
            ('XSS', self.check_xss),
            ('Exposed Git', self.check_exposed_git),
            ('Directory Listing', self.check_directory_listing),
            ('Sensitive Files', self.check_sensitive_files),
            ('CORS Misconfig', self.check_cors_misconfig),
            ('Clickjacking', self.check_clickjacking),
            ('HTTP Methods', self.check_http_methods),
            ('Server Info', self.check_server_info)
        ]
        
        for name, check_func in checks:
            print(f'[+] Checking {name}...')
            check_func()
        
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Lightweight Vulnerability Scanner')
    parser.add_argument('target', help='Target URL or IP to scan')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    args = parser.parse_args()
    
    scanner = VulnScanner(args.target)
    vulnerabilities = scanner.scan_all()
    
    print('\n[+] Scan Results:')
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"\n[!] {vuln['type']} found!")
            print(f"    URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"    Payload: {vuln['payload']}")
            print(f"    Details: {vuln.get('details', 'N/A')}")
    else:
        print("[-] No vulnerabilities found.")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == '__main__':
    main()
