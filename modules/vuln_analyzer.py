class VulnerabilityAnalyzer:
    def __init__(self):
        self.vuln_database = {
            "sql_injection": {
                "name": "SQL Injection",
                "severity": "CRÍTICA",
                "owasp": "A03:2021",
                "description": "Inserção de código SQL malicioso em queries",
                "indicators": ["parâmetros de URL", "formulários", "cookies", "headers"],
                "tools": ["sqlmap", "Burp Suite", "SQLNinja"],
                "prevention": [
                    "Usar prepared statements",
                    "Validar e sanitizar inputs",
                    "Princípio do menor privilege no banco",
                    "WAF (Web Application Firewall)"
                ]
            },
            "xss": {
                "name": "Cross-Site Scripting",
                "severity": "ALTA",
                "owasp": "A03:2021",
                "description": "Injeção de scripts maliciosos em páginas web",
                "indicators": ["parâmetros refletidos", "formulários", "anchors"],
                "tools": ["XSStrike", "Burp Suite", "BruteXSS"],
                "prevention": [
                    "Escape de output",
                    "Content Security Policy (CSP)",
                    "Validação de input",
                    "HttpOnly cookies"
                ]
            },
            "csrf": {
                "name": "Cross-Site Request Forgery",
                "severity": "MÉDIA",
                "owasp": "A01:2021",
                "description": "Forging de requisições não autorizadas",
                "indicators": ["formulários sem token", "ações sensíveis sem verificação"],
                "tools": ["Burp Suite", "CSRF Tester"],
                "prevention": [
                    "Tokens CSRF",
                    "SameSite cookies",
                    "Verificação de Origin/Referer"
                ]
            },
            "lfi": {
                "name": "Local File Inclusion",
                "severity": "ALTA",
                "owasp": "A01:2021",
                "description": "Inclusão de arquivos locais via parâmetros",
                "indicators": ["path traversal", "parâmetros de arquivo", "include"],
                "tools": ["LFi Scanner", "Burp Suite"],
                "prevention": [
                    "Whitelist de arquivos permitidos",
                    "Sanitização de path",
                    "Chroot/jail"
                ]
            },
            "rfi": {
                "name": "Remote File Inclusion",
                "severity": "CRÍTICA",
                "owasp": "A01:2021",
                "description": "Inclusão de arquivos remotos via URL",
                "indicators": ["URLs em parâmetros", "include/require com URLs"],
                "tools": ["RFI Scanner", "Burp Suite"],
                "prevention": [
                    "Desabilitar allow_url_include",
                    "Whitelist de URLs",
                    "Firewall de saída"
                ]
            },
            "command_injection": {
                "name": "Command Injection",
                "severity": "CRÍTICA",
                "owasp": "A03:2021",
                "description": "Execução de comandos do sistema via input",
                "indicators": ["comandos em parâmetros", "pipe operators", "backticks"],
                "tools": ["Commix", "Burp Suite"],
                "prevention": [
                    "Evitar chamadas a shell",
                    "Shell parameterization",
                    "Input validation"
                ]
            },
            "ssrf": {
                "name": "Server-Side Request Forgery",
                "severity": "ALTA",
                "owasp": "A10:2021",
                "description": "Induzir servidor a fazer requisições internas",
                "indicators": ["URLs em parâmetros", "webhooks", "file handlers"],
                "tools": ["SSRFmap", "Burp Suite"],
                "prevention": [
                    "Whitelist de domínios",
                    "Desabilitar HTTP redirects",
                    "Segmentação de rede"
                ]
            },
            "idor": {
                "name": "Insecure Direct Object References",
                "severity": "MÉDIA",
                "owasp": "A01:2021",
                "description": "Acesso não autorizado a objetos diretos",
                "indicators": ["IDs sequenciais em URLs", "parâmetros de objeto"],
                "tools": ["Burp Suite", "Autorize"],
                "prevention": [
                    "Verificação de autorização",
                    "IDs indiretos/UUIDs",
                    "Access control checks"
                ]
            }
        }
        
        self.port_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPCBind",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
    
    def analyze_service(self, port, service, version=None):
        vulnerabilities = []
        
        common_vulns = {
            21: ["anonymous_login", "weak_credentials", "clear_text"],
            22: ["weak_credentials", "ssh_version_disclosure"],
            23: ["telnet_clear_text", "weak_credentials"],
            80: ["xss", "sql_injection", "csrf", "lfi", "rfi", "command_injection"],
            443: ["ssl_vulnerabilities", "certificate_issues"],
            445: ["smb_signing", "eternal_blue", "null_session"],
            3306: ["weak_credentials", "mysql_udf"],
            3389: ["bluekeep", "weak_credentials"],
            5432: ["weak_credentials", "command_execution"]
        }
        
        if port in common_vulns:
            for vuln in common_vulns[port]:
                if vuln in self.vuln_database:
                    vulnerabilities.append(self.vuln_database[vuln])
        
        return {
            "port": port,
            "service": service,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "risk_level": self._calculate_risk(vulnerabilities),
            "recommendations": self._get_recommendations(port, service)
        }
    
    def analyze_target(self, target_info):
        results = {
            "target": target_info.get("ip", "unknown"),
            "services": [],
            "overall_risk": "BAIXO",
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "recommendations": []
        }
        
        for service in target_info.get("services", []):
            analysis = self.analyze_service(
                service.get("port"),
                service.get("service"),
                service.get("version")
            )
            results["services"].append(analysis)
            
            if analysis["risk_level"] == "CRÍTICO":
                results["critical_vulns"] += 1
            elif analysis["risk_level"] == "ALTO":
                results["high_vulns"] += 1
            elif analysis["risk_level"] == "MÉDIO":
                results["medium_vulns"] += 1
        
        if results["critical_vulns"] > 0:
            results["overall_risk"] = "CRÍTICO"
        elif results["high_vulns"] > 0:
            results["overall_risk"] = "ALTO"
        elif results["medium_vulns"] > 0:
            results["overall_risk"] = "MÉDIO"
        
        return results
    
    def get_vulnerability_info(self, vuln_name):
        for key, vuln in self.vuln_database.items():
            if vuln_name.lower() in key.lower() or vuln_name.lower() in vuln["name"].lower():
                return vuln
        return {"error": f"Vulnerabilidade não encontrada: {vuln_name}"}
    
    def list_vulnerabilities(self):
        return [
            {"id": k, "name": v["name"], "severity": v["severity"]}
            for k, v in self.vuln_database.items()
        ]
    
    def _calculate_risk(self, vulnerabilities):
        if not vulnerabilities:
            return "BAIXO"
        
        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRÍTICA")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "ALTA")
        
        if critical_count > 0:
            return "CRÍTICO"
        elif high_count > 0:
            return "ALTO"
        else:
            return "MÉDIO"
    
    def _get_recommendations(self, port, service):
        recommendations = []
        
        if port in [21, 23]:
            recommendations.append("Evitar serviços em texto claro")
            recommendations.append("Usar alternativas criptografadas (SSH, SFTP)")
        
        if port in [22, 3389]:
            recommendations.append("Usar chaves SSH em vez de senhas")
            recommendations.append("Implementar fail2ban")
            recommendations.append("Limitar acesso por IP")
        
        if port in [80, 443, 8080, 8443]:
            recommendations.append("Manter framework atualizado")
            recommendations.append("Implementar WAF")
            recommendations.append("Usar HTTPS em todos os endpoints")
        
        if port in [445, 139]:
            recommendations.append("Desabilitar SMB se não necessário")
            recommendations.append("Implementar assinatura SMB")
            recommendations.append("Limitar acesso por rede")
        
        if port in [3306, 5432, 1433]:
            recommendations.append("Restringir acesso ao banco de dados")
            recommendations.append("Usar credenciais fortes")
            recommendations.append("Manter banco atualizado")
        
        return recommendations
