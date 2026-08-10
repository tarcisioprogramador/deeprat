import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.sql_payloads = ["'", "1' OR '1'='1", "1' OR '1'='1'--", "' OR ''='"]
        self.xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
        self.lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"]
        self.cmd_payloads = ["; ls", "| ls", "`ls`", "$(ls)"]
        
        self.vulns_found = []
    
    def scan(self, url):
        self.vulns_found = []
        
        if not url.startswith('http'):
            url = 'http://' + url
        
        print(f"Escaneando: {url}")
        
        self._check_headers(url)
        self._check_forms(url)
        self._check_parameters(url)
        self._check_directory_listing(url)
        self._check_common_files(url)
        self._check_sql_injection(url)
        self._check_xss(url)
        self._check_lfi(url)
        self._check_command_injection(url)
        self._check_ssl(url)
        
        return {
            "url": url,
            "total_vulns": len(self.vulns_found),
            "vulnerabilities": self.vulns_found,
            "summary": self._generate_summary()
        }
    
    def _check_headers(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            headers = resp.headers
            
            if 'X-Frame-Options' not in headers:
                self.vulns_found.append({
                    "type": "Missing Header",
                    "severity": "MÉDIA",
                    "title": "X-Frame-Options ausente",
                    "description": "Possível clickjacking",
                    "fix": "Adicione header X-Frame-Options: DENY"
                })
            
            if 'X-Content-Type-Options' not in headers:
                self.vulns_found.append({
                    "type": "Missing Header",
                    "severity": "BAIXA",
                    "title": "X-Content-Type-Options ausente",
                    "description": "Possível MIME sniffing",
                    "fix": "Adicione header X-Content-Type-Options: nosniff"
                })
            
            if 'Strict-Transport-Security' not in headers:
                self.vulns_found.append({
                    "type": "Missing Header",
                    "severity": "MÉDIA",
                    "title": "HSTS ausente",
                    "description": "Sem HTTP Strict Transport Security",
                    "fix": "Adicione header Strict-Transport-Security"
                })
            
            if 'Content-Security-Policy' not in headers:
                self.vulns_found.append({
                    "type": "Missing Header",
                    "severity": "MÉDIA",
                    "title": "CSP ausente",
                    "description": "Sem Content Security Policy",
                    "fix": "Adicione header Content-Security-Policy"
                })
            
            server = headers.get('Server', '')
            if server:
                self.vulns_found.append({
                    "type": "Info Disclosure",
                    "severity": "BAIXA",
                    "title": "Server header exposto",
                    "description": f"Servidor: {server}",
                    "fix": "Remova ou oculte o header Server"
                })
                
        except Exception as e:
            pass
    
    def _check_forms(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                if 'method="post"' in form.lower() or "method='post'" in form.lower():
                    if 'csrf' not in form.lower() and 'token' not in form.lower():
                        self.vulns_found.append({
                            "type": "CSRF",
                            "severity": "MÉDIA",
                            "title": "Formulário sem token CSRF",
                            "description": "Formulário POST sem proteção CSRF",
                            "fix": "Adicione token CSRF em todos os formulários"
                        })
                        break
            
            inputs = re.findall(r'<input[^>]*>', resp.text, re.IGNORECASE)
            for inp in inputs:
                if 'type="file"' in inp.lower():
                    if 'enctype="multipart/form-data"' not in resp.text.lower():
                        self.vulns_found.append({
                            "type": "Config",
                            "severity": "BAIXA",
                            "title": "Upload de arquivo",
                            "description": "Formulário com upload de arquivo encontrado",
                            "fix": "Valide tipos de arquivo e tamanhos"
                        })
                        break
                        
        except Exception as e:
            pass
    
    def _check_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for payload in self.xss_payloads:
                try:
                    test_params = {k: v[0] if v else '' for k, v in params.items()}
                    test_params[param] = payload
                    
                    resp = self.session.get(test_url, params=test_params, timeout=10)
                    
                    if payload in resp.text:
                        self.vulns_found.append({
                            "type": "XSS",
                            "severity": "ALTA",
                            "title": f"XSS Refletido no parâmetro {param}",
                            "description": f"Payload XSS refletido na resposta",
                            "evidence": f"Parâmetro: {param}, Payload: {payload}",
                            "fix": "Sanitize entrada e use output encoding"
                        })
                        break
                except:
                    pass
            
            for payload in self.sql_payloads:
                try:
                    test_params = {k: v[0] if v else '' for k, v in params.items()}
                    test_params[param] = payload
                    
                    resp = self.session.get(test_url, params=test_params, timeout=10)
                    
                    sql_errors = ['sql', 'mysql', 'syntax', 'error', 'warning', 'query']
                    if any(err in resp.text.lower() for err in sql_errors):
                        self.vulns_found.append({
                            "type": "SQL Injection",
                            "severity": "CRÍTICA",
                            "title": f"SQL Injection no parâmetro {param}",
                            "description": "Possível SQL Injection detectado",
                            "evidence": f"Parâmetro: {param}, Payload: {payload}",
                            "fix": "Use prepared statements e parameterized queries"
                        })
                        break
                except:
                    pass
    
    def _check_directory_listing(self, url):
        dirs = ['/admin/', '/backup/', '/config/', '/test/', '/debug/', '/.git/']
        
        for d in dirs:
            try:
                resp = self.session.get(urljoin(url, d), timeout=5)
                if resp.status_code == 200 and 'index of' in resp.text.lower():
                    self.vulns_found.append({
                        "type": "Directory Listing",
                        "severity": "ALTA",
                        "title": f"Directory Listing em {d}",
                        "description": "Listagem de diretórios habilitada",
                        "fix": "Desabilite directory listing no servidor"
                    })
            except:
                pass
    
    def _check_common_files(self, url):
        files = [
            '/.env', '/config.php', '/wp-config.php', '/web.config',
            '/.htaccess', '/phpinfo.php', '/server-status',
            '/robots.txt', '/sitemap.xml', '/.git/config'
        ]
        
        for f in files:
            try:
                resp = self.session.get(urljoin(url, f), timeout=5)
                if resp.status_code == 200:
                    self.vulns_found.append({
                        "type": "Sensitive File",
                        "severity": "MÉDIA" if f not in ['/.env', '/.git/config'] else "ALTA",
                        "title": f"Arquivo sensível exposto: {f}",
                        "description": f"Arquivo {f} acessível publicamente",
                        "fix": f"Restrija acesso ao arquivo {f}"
                    })
            except:
                pass
    
    def _check_sql_injection(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        for param in params:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for payload in ["' OR 1=1--", "1' OR '1'='1'--"]:
                try:
                    test_params = {k: v[0] if v else '' for k, v in params.items()}
                    test_params[param] = payload
                    
                    normal_resp = self.session.get(test_url, params={k: v[0] if v else '' for k, v in params.items()}, timeout=10)
                    attack_resp = self.session.get(test_url, params=test_params, timeout=10)
                    
                    if len(attack_resp.text) > len(normal_resp.text) * 1.5:
                        self.vulns_found.append({
                            "type": "SQL Injection",
                            "severity": "CRÍTICA",
                            "title": f"SQL Injection confirmado no parâmetro {param}",
                            "description": "Resposta maior com payload sugere SQL Injection",
                            "fix": "Use prepared statements"
                        })
                        break
                except:
                    pass
    
    def _check_xss(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        for param in params:
            payload = '<xss>alert(1)</xss>'
            try:
                test_params = {k: v[0] if v else '' for k, v in params.items()}
                test_params[param] = payload
                
                resp = self.session.get(url, params=test_params, timeout=10)
                
                if payload in resp.text:
                    self.vulns_found.append({
                        "type": "XSS",
                        "severity": "ALTA",
                        "title": f"XSS Refletido no parâmetro {param}",
                        "description": "Payload XSS refletido sem sanitização",
                        "fix": "Encode output e use CSP"
                    })
            except:
                pass
    
    def _check_lfi(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        for param in params:
            payload = "../../../etc/passwd"
            try:
                test_params = {k: v[0] if v else '' for k, v in params.items()}
                test_params[param] = payload
                
                resp = self.session.get(url, params=test_params, timeout=10)
                
                if 'root:' in resp.text or '/bin/bash' in resp.text:
                    self.vulns_found.append({
                        "type": "LFI",
                        "severity": "CRÍTICA",
                        "title": f"Local File Injection no parâmetro {param}",
                        "description": "Possível leitura de arquivos do sistema",
                        "fix": "Valide e sanitize caminhos de arquivo"
                    })
            except:
                pass
    
    def _check_command_injection(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        for param in params:
            payload = "; echo test12345"
            try:
                test_params = {k: v[0] if v else '' for k, v in params.items()}
                test_params[param] = payload
                
                resp = self.session.get(url, params=test_params, timeout=10)
                
                if 'test12345' in resp.text:
                    self.vulns_found.append({
                        "type": "Command Injection",
                        "severity": "CRÍTICA",
                        "title": f"Command Injection no parâmetro {param}",
                        "description": "Execução de comandos do sistema detectada",
                        "fix": "Nunca passe input do usuário para comandos do sistema"
                    })
            except:
                pass
    
    def _check_ssl(self, url):
        if not url.startswith('https'):
            self.vulns_found.append({
                "type": "SSL/TLS",
                "severity": "MÉDIA",
                "title": "Sem HTTPS",
                "description": "Site não usa HTTPS",
                "fix": "Implemente HTTPS com certificado válido"
            })
    
    def _generate_summary(self):
        critical = sum(1 for v in self.vulns_found if v['severity'] == 'CRÍTICA')
        high = sum(1 for v in self.vulns_found if v['severity'] == 'ALTA')
        medium = sum(1 for v in self.vulns_found if v['severity'] == 'MÉDIA')
        low = sum(1 for v in self.vulns_found if v['severity'] == 'BAIXA')
        
        if critical > 0:
            risk = "CRÍTICO"
        elif high > 0:
            risk = "ALTO"
        elif medium > 0:
            risk = "MÉDIO"
        else:
            risk = "BAIXO"
        
        return {
            "risk_level": risk,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }
