#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import re
import dns.resolver
import socket
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
import hashlib
from functools import lru_cache
import smtplib
from email.mime.text import MIMEText

init(autoreset=True)

class Config:
    """Configurações robustas da ferramenta com validação"""
    TIMEOUT = 15
    MAX_RETRIES = 3
    RATE_LIMIT_DELAY = 2
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
    ]
    
    @classmethod
    def get_hibp_key(cls) -> str:
        key = os.getenv('HIBP_API_KEY')
        if not key or key == 'sua_chave_aqui':
            raise ValueError("Chave API HIBP não configurada. Defina HIBP_API_KEY")
        return key

class DomainIntel:
    """Inteligência avançada de domínios com cache"""
    
    @staticmethod
    @lru_cache(maxsize=128)
    def get_full_whois(domain: str) -> Dict:
        """Consulta WHOIS com parser e histórico"""
        try:
            import whois
            from whois.parser import WhoisEntry
            w = whois.whois(domain)
            
            if isinstance(w.creation_date, list):
                created = w.creation_date[0]
                updated = w.updated_date[-1] if w.updated_date else None
            else:
                created = w.creation_date
                updated = w.updated_date
                
            return {
                'created': created,
                'updated': updated,
                'expires': w.expiration_date,
                'registrar': w.registrar,
                'name_servers': sorted(list(set(w.name_servers))),
                'status': list(set(w.status)),
                'emails': getattr(w, 'emails', [])
            }
        except Exception as e:
            print(f"{Fore.RED}[WHOIS Error] {e}{Style.RESET_ALL}")
            return None

    @staticmethod
    def check_email_security(domain: str) -> Dict:
        """Verificação completa de segurança de email"""
        results = {
            'spf': DomainIntel._check_spf(domain),
            'dmarc': DomainIntel._check_dmarc(domain),
            'mx': DomainIntel._analyze_mx(domain),
            'blacklists': DomainIntel._check_blacklists(domain)
        }
        return results

    @staticmethod
    def _check_spf(domain: str) -> bool:
        """Verifica registros SPF"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return any('v=spf1' in str(rdata) for rdata in answers)
        except:
            return False

    @staticmethod
    def _check_dmarc(domain: str) -> bool:
        """Verifica política DMARC"""
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            return any('DMARC1' in str(rdata) for rdata in answers)
        except:
            return False

    @staticmethod
    def _analyze_mx(domain: str) -> List[Dict]:
        """Análise profissional de servidores MX"""
        try:
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_host = str(rdata.exchange)
                try:
                    ip = socket.gethostbyname(mx_host)
                    mx_records.append({
                        'host': mx_host,
                        'ip': ip,
                        'priority': rdata.preference
                    })
                except socket.gaierror:
                    continue
            return sorted(mx_records, key=lambda x: x['priority'])
        except Exception as e:
            print(f"{Fore.RED}[MX Error] {e}{Style.RESET_ALL}")
            return []

    @staticmethod
    def _check_blacklists(domain: str) -> Dict:
        """Verifica listas de spam"""
        blacklists = {
            'spamhaus': '.zen.spamhaus.org',
            'sorbs': '.dnsbl.sorbs.net',
            'barracuda': '.b.barracudacentral.org'
        }
        
        results = {}
        try:
            ip = socket.gethostbyname(domain)
            reversed_ip = '.'.join(reversed(ip.split('.')))
            
            for name, bl in blacklists.items():
                try:
                    query = f"{reversed_ip}{bl}"
                    dns.resolver.resolve(query, 'A')
                    results[name] = True
                except:
                    results[name] = False
                    
        except Exception as e:
            print(f"{Fore.RED}[Blacklist Error] {e}{Style.RESET_ALL}")
            
        return results

class BreachIntel:
    """Inteligência de vazamentos com múltiplas fontes"""
    
    @staticmethod
    def get_breach_details(email: str) -> Tuple[List[Dict], Dict]:
        """Obtém detalhes completos de vazamentos"""
        try:
            hibp_data = BreachIntel._get_hibp_breaches(email)
            risk = RiskAnalyzer.calculate_risk(hibp_data)
            return hibp_data, risk
        except Exception as e:
            print(f"{Fore.RED}[Breach Error] {e}{Style.RESET_ALL}")
            return [], {}

    @staticmethod
    def _get_hibp_breaches(email: str) -> List[Dict]:
        """Consulta HIBP API com tratamento profissional"""
        session = requests.Session()
        retry = Retry(
            total=Config.MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount('https://', HTTPAdapter(max_retries=retry))
        
        try:
            headers = {
                'hibp-api-key': Config.get_hibp_key(),
                'User-Agent': Config.USER_AGENTS[0]
            }
            response = session.get(
                f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                headers=headers,
                timeout=Config.TIMEOUT
            )
            
            if response.status_code == 200:
                return sorted(response.json(), key=lambda x: x['AddedDate'], reverse=True)
            elif response.status_code == 404:
                return []
                
            response.raise_for_status()
            return []
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"HIBP API Error: {str(e)}")

class RiskAnalyzer:
    """Análise avançada de riscos"""
    
    @staticmethod
    def calculate_risk(breaches: List[Dict]) -> Dict:
        """Calcula risco com base em múltiplos fatores"""
        if not breaches:
            return {'score': 0, 'level': 'None', 'details': {}}
        
        risk_weights = {
            'Passwords': 4,
            'CreditCards': 5,
            'BankAccounts': 6,
            'PersonalInfo': 3,
            'SecurityQuestions': 2
        }
        
        score = 0
        compromised = set()
        recent_breaches = 0
        sensitive_services = set()
        
        for breach in breaches:
            # Conta brechas nos últimos 2 anos
            if (datetime.now() - datetime.strptime(breach['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days < 730:
                recent_breaches += 1
                
            # Marca serviços sensíveis
            if breach['Domain'] in ['facebook.com', 'google.com', 'apple.com']:
                sensitive_services.add(breach['Domain'])
                
            # Calcula score
            for data_class in breach['DataClasses']:
                compromised.add(data_class)
                score += risk_weights.get(data_class, 1)
        
        # Ajustes baseados em fatores adicionais
        if recent_breaches > 3:
            score += 3
        elif recent_breaches > 1:
            score += 1
            
        if sensitive_services:
            score += len(sensitive_services) * 2
            
        # Determina nível de risco
        level = 'Low'
        if score > 20: level = 'Critical'
        elif score > 15: level = 'High'
        elif score > 8: level = 'Medium'
        
        return {
            'score': score,
            'level': level,
            'compromised': sorted(compromised),
            'recent_breaches': recent_breaches,
            'sensitive_services': sorted(sensitive_services)
        }

class ReportEngine:
    """Motor de relatórios profissionais"""
    
    @staticmethod
    def generate_full_report(email: str) -> Dict:
        """Gera relatório completo"""
        domain = email.split('@')[-1]
        
        # Coleta de dados
        breaches, risk = BreachIntel.get_breach_details(email)
        whois = DomainIntel.get_full_whois(domain)
        email_security = DomainIntel.check_email_security(domain)
        
        # Estrutura do relatório
        return {
            'metadata': {
                'email': email,
                'generated_at': datetime.now().isoformat(),
                'tool_version': 'OSINT Pro 6.0'
            },
            'breaches': breaches,
            'risk_assessment': risk,
            'domain_analysis': {
                'whois': whois,
                'email_security': email_security
            }
        }
    
    @staticmethod
    def print_human_report(report: Dict):
        """Exibe relatório formatado para humanos"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== OSINT PROFESSIONAL REPORT ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Email:{Style.RESET_ALL} {report['metadata']['email']}")
        print(f"{Fore.YELLOW}Date:{Style.RESET_ALL} {report['metadata']['generated_at']}")
        
        # Seção de vazamentos
        if report['breaches']:
            print(f"\n{Fore.RED}{Style.BRIGHT}● DATA BREACHES ({len(report['breaches']}):{Style.RESET_ALL}")
            for breach in report['breaches']:
                print(f"  {Fore.MAGENTA}↳ {breach['Name']} ({breach['BreachDate']}){Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Domain: {breach['Domain']}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Compromised: {', '.join(breach['DataClasses'])}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}✓ No known breaches found{Style.RESET_ALL}")
        
        # Seção de risco
        if report['risk_assessment']:
            risk = report['risk_assessment']
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}● RISK ASSESSMENT:{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Score: {risk['score']} ({risk['level']}){Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Compromised Data: {', '.join(risk['compromised'])}{Style.RESET_ALL}")
            if risk['recent_breaches']:
                print(f"  {Fore.WHITE}Recent breaches (last 2 years): {risk['recent_breaches']}{Style.RESET_ALL}")
            if risk['sensitive_services']:
                print(f"  {Fore.WHITE}Sensitive services affected: {', '.join(risk['sensitive_services'])}{Style.RESET_ALL}")
        
        # Seção de domínio
        if report['domain_analysis']:
            print(f"\n{Fore.BLUE}{Style.BRIGHT}● DOMAIN ANALYSIS:{Style.RESET_ALL}")
            
            if report['domain_analysis']['whois']:
                whois = report['domain_analysis']['whois']
                print(f"  {Fore.CYAN}↳ WHOIS RECORDS:{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Created: {whois.get('created', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Registrar: {whois.get('registrar', 'Unknown')}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Name Servers: {', '.join(whois.get('name_servers', []))}{Style.RESET_ALL}")
            
            if report['domain_analysis']['email_security']:
                sec = report['domain_analysis']['email_security']
                print(f"  {Fore.CYAN}↳ EMAIL SECURITY:{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}SPF: {'✓' if sec['spf'] else '✗'}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}DMARC: {'✓' if sec['dmarc'] else '✗'}{Style.RESET_ALL}")
                
                if sec['mx']:
                    print(f"    {Fore.WHITE}Mail Servers:{Style.RESET_ALL}")
                    for mx in sec['mx']:
                        print(f"      {mx['priority']} {mx['host']} ({mx['ip']})")
                
                if sec['blacklists']:
                    print(f"    {Fore.WHITE}Blacklists:{Style.RESET_ALL}")
                    for bl, listed in sec['blacklists'].items():
                        print(f"      {bl}: {'🔴 Listed' if listed else '🟢 Clean'}")

class OutputManager:
    """Gerenciamento de saída e exportação"""
    
    @staticmethod
    def save_report(report: Dict, format: str = 'json'):
        """Salva relatório em múltiplos formatos"""
        email = report['metadata']['email']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            filename = f"osint_report_{email.replace('@', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            return filename
        
        # Implementar outros formatos (HTML, PDF) aqui
        raise ValueError("Formato não suportado")

def main():
    try:
        # Verificação de dependências
        try:
            import dns.resolver
            import whois
        except ImportError:
            print(f"{Fore.RED}[!] Installing required packages...{Style.RESET_ALL}")
            os.system("pip install dnspython python-whois requests")
            print(f"{Fore.GREEN}[✓] Dependencies installed{Style.RESET_ALL}")
        
        # Obter email alvo
        if len(sys.argv) > 1:
            email = sys.argv[1]
        else:
            email = input(f"{Fore.YELLOW}[*] Target email: {Style.RESET_ALL}").strip()

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")

        print(f"\n{Fore.CYAN}[*] Starting professional OSINT analysis...{Style.RESET_ALL}")
        
        # Gerar relatório
        report = ReportEngine.generate_full_report(email)
        ReportEngine.print_human_report(report)
        
        # Opção de salvamento
        if input(f"\n{Fore.YELLOW}[?] Save full report? (y/n): {Style.RESET_ALL}").lower() == 'y':
            filename = OutputManager.save_report(report)
            print(f"{Fore.GREEN}[✓] Report saved as {filename}{Style.RESET_ALL}")
            
    except ValueError as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Analysis interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
